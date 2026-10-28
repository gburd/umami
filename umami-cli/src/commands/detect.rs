//! `umami pipeline`, `sim` and `ingest`: stream log lines through the
//! detector. The three differ only in how they print what it finds.

use clap::Args as ClapArgs;
use std::collections::BTreeMap;
use std::error::Error;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use umami::{
    time::event_time, Anomaly, AnomalyKind, Detector, DetectorConfig, ProfileStore, Tokenizer,
};

/// How often, in seconds of event time, to look for silent events and systems.
const SWEEP_EVERY: i64 = 60;

/// Bump when a change to tokenizing or hashing makes saved profiles invalid.
const STATE_FORMAT: u64 = 1;

/// Options shared by `pipeline`, `sim` and `ingest`.
#[derive(ClapArgs)]
pub struct Args {
    /// System name for untagged lines.
    #[arg(long, default_value = "stdin")]
    system: String,

    /// Read each line as `system<TAB>line`, to multiplex several systems on
    /// one stream. Lines without a tab use `--system`.
    #[arg(long)]
    tagged: bool,

    /// Tokenizer to use.
    #[arg(long, default_value = "structure", value_parser = super::tokenizer_arg())]
    tokenizer: Tokenizer,

    /// Also report parameter changes (new values on known structures).
    #[arg(long)]
    parameters: bool,

    /// Load learned profiles from FILE if it exists, and save them back at
    /// the end of input (and every minute or so while input is idle).
    #[arg(long, value_name = "FILE")]
    state: Option<PathBuf>,
}

/// `pipeline` options.
#[derive(ClapArgs)]
pub struct PipelineArgs {
    #[command(flatten)]
    common: Args,

    /// Print every line, prefixed with its classification (or `ok`).
    #[arg(long)]
    show_all: bool,
}

/// How results are printed.
#[derive(Clone, Copy)]
pub enum Format {
    /// `pipeline`: the kind, then the line.
    Text {
        /// Also print normal lines, as `ok`.
        show_all: bool,
    },
    /// `ingest`: one JSON object per anomaly.
    Json,
    /// `sim`: counts by kind, at the end.
    Summary,
}

/// Runs `pipeline`.
pub fn run_pipeline(args: PipelineArgs) -> Result<(), Box<dyn Error>> {
    let show_all = args.show_all;
    run(args.common, Format::Text { show_all })
}

/// Runs a detection subcommand over stdin.
///
/// Each line is observed at its own timestamp (see [`umami::time`]); a line
/// without one is observed at the latest timestamp seen, or the wall clock
/// before any. Every [`SWEEP_EVERY`] seconds of that clock the detector is
/// swept for stopped events and silent systems.
//
// shortcut: sweeps only run when a line arrives, so a stream that goes fully
// idle reports system_away when it resumes, not while idle. Read stdin on a
// thread and sweep on a timer if live idle alerts are needed.
// shortcut: when replaying old logs, lines before the first timestamp are
// stamped with the wall clock, which hides system_away for that system for
// the rest of the replay. Buffer them until the first timestamp if it matters.
pub fn run(args: Args, format: Format) -> Result<(), Box<dyn Error>> {
    let mut cfg = DetectorConfig::default();
    cfg.tokenizer = args.tokenizer;
    cfg.detect_parameter_changes = args.parameters;
    let store = match &args.state {
        Some(path) if path.exists() => load_state(path, cfg.tokenizer)?,
        _ => ProfileStore::new(),
    };
    let mut det = Detector::with_store(cfg, store);
    let mut saved_at = Instant::now();

    let mut out = io::BufWriter::new(io::stdout().lock());
    let mut counts: BTreeMap<&'static str, u64> = BTreeMap::new();
    let (mut events, mut flagged) = (0u64, 0u64);
    let mut clock: Option<i64> = None;
    let mut next_sweep = i64::MIN;

    super::for_each_line(io::stdin().lock(), |raw, more| {
        let (system, line) = match raw.split_once('\t') {
            Some((s, l)) if args.tagged => (s, l),
            _ => (args.system.as_str(), raw),
        };
        let tokens = cfg.tokenizer.tokenize(line);
        // Only parsed timestamps move the clock; a line without one is seen at
        // the latest time so far, or the wall clock if there has been none.
        let parsed = event_time(&tokens, clock.unwrap_or_else(wall_clock));
        if let Some(t) = parsed {
            if clock.is_none() {
                next_sweep = i64::MIN; // switching from the wall clock to event time
            }
            clock = Some(clock.map_or(t, |c| c.max(t)));
        }
        let latest = clock.unwrap_or_else(wall_clock);
        let now = parsed.unwrap_or(latest);

        if latest >= next_sweep {
            for a in det.sweep(latest) {
                *counts.entry(a.kind.as_str()).or_default() += 1;
                print(&mut out, format, &a)?;
            }
            next_sweep = latest + SWEEP_EVERY;
        }

        events += 1;
        match det.observe_tokens(system, line, &tokens, now) {
            Some(a) => {
                flagged += 1;
                *counts.entry(a.kind.as_str()).or_default() += 1;
                print(&mut out, format, &a)?;
            }
            None if matches!(format, Format::Text { show_all: true }) => {
                writeln!(out, "{:<18} {line}", "ok")?;
            }
            None => {}
        }
        if !more {
            out.flush()?;
            if let Some(path) = &args.state {
                if saved_at.elapsed().as_secs() >= 60 {
                    save_state(path, &det)?;
                    saved_at = Instant::now();
                }
            }
        }
        Ok(())
    })?;

    if let Some(path) = &args.state {
        save_state(path, &det)?;
    }

    if let Format::Summary = format {
        writeln!(out, "events:    {events}")?;
        writeln!(out, "anomalies: {flagged}")?;
        let reduction = if events > 0 {
            100.0 * (1.0 - flagged as f64 / events as f64)
        } else {
            0.0
        };
        writeln!(out, "reduction: {reduction:.1}%")?;
        writeln!(out, "profiles:  {}", det.store().profile_count())?;
        for (kind, n) in counts {
            writeln!(out, "  {kind:<18} {n}")?;
        }
    }
    out.flush()?;
    Ok(())
}

fn wall_clock() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}

fn load_state(path: &Path, tokenizer: Tokenizer) -> Result<ProfileStore, Box<dyn Error>> {
    let fail = |why: String| format!("{}: {why}", path.display());
    let mut v: serde_json::Value =
        serde_json::from_reader(io::BufReader::new(std::fs::File::open(path)?))
            .map_err(|e| fail(e.to_string()))?;
    if v["format"] != STATE_FORMAT {
        return Err(fail(format!(
            "state format {} is not {STATE_FORMAT}",
            v["format"]
        ))
        .into());
    }
    if v["tokenizer"] != tokenizer.name() {
        let msg = format!(
            "saved with --tokenizer {}, not {}",
            v["tokenizer"],
            tokenizer.name()
        );
        return Err(fail(msg).into());
    }
    Ok(serde_json::from_value(v["store"].take()).map_err(|e| fail(e.to_string()))?)
}

/// Writes the state next to `path` and renames it into place, so a crash
/// mid-write never leaves a truncated file.
fn save_state(path: &Path, det: &Detector) -> io::Result<()> {
    let tmp = path.with_extension("tmp");
    let mut w = io::BufWriter::new(std::fs::File::create(&tmp)?);
    serde_json::to_writer(
        &mut w,
        &serde_json::json!({
            "format": STATE_FORMAT,
            "tokenizer": det.config().tokenizer.name(),
            "store": det.store(),
        }),
    )?;
    w.into_inner()?.sync_all()?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

fn print(out: &mut impl Write, format: Format, a: &Anomaly) -> io::Result<()> {
    let kind = a.kind.as_str();
    match format {
        // found by a sweep: there is no line, so say which system and structure
        Format::Text { .. } if matches!(a.kind, AnomalyKind::EventStop | AnomalyKind::SystemAway) => {
            let msg = format!("{kind:<18} [{}] {}", a.system, a.signature);
            writeln!(out, "{}", msg.trim_end())
        }
        Format::Text { .. } => writeln!(out, "{kind:<18} {}", a.line),
        Format::Json => writeln!(
            out,
            "{{\"system\":{},\"kind\":\"{kind}\",\"score\":{:.2},\"hash\":{},\"signature\":{},\"line\":{}}}",
            json_str(&a.system),
            a.score,
            a.hash.map_or("null".to_string(), |h| format!("\"{h}\"")),
            json_str(&a.signature),
            json_str(&a.line),
        ),
        Format::Summary => Ok(()),
    }
}

/// Minimal JSON string escaping (no external dependency).
fn json_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}
