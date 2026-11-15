//! `umami pipeline`, `sim` and `ingest`: stream log lines through the
//! detector. The three differ only in how they print what it finds.

use clap::Args as ClapArgs;
use std::collections::BTreeMap;
use std::error::Error;
use std::io::{self, Write};
use std::path::PathBuf;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use umami::{
    time::{continuing_event_time, event_time},
    Anomaly, AnomalyKind, Detector, DetectorConfig, ProfileStore, Tokenizer,
};

/// How often, in seconds of event time, to look for silent events and systems.
const SWEEP_EVERY: i64 = 60;

mod input;
mod output;
mod state;
mod timestamp;

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

    /// Join indented continuation lines (1 MiB limit, one-second idle flush).
    #[arg(long, conflicts_with = "tagged")]
    multiline: bool,

    /// Parse a leading strftime timestamp with an explicit year (zone defaults to UTC).
    #[arg(long, value_name = "FORMAT")]
    time_format: Option<String>,

    /// Tokenizer to use.
    #[arg(long, default_value = "structure", value_parser = super::tokenizer_arg())]
    tokenizer: Tokenizer,

    /// Also report parameter changes (new values on known structures).
    #[arg(long)]
    parameters: bool,

    /// Lock and resume FILE; checkpoint every minute, on EOF, and on SIGINT/SIGTERM.
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

/// Runs detection with bounded IO and main-thread checkpoint ownership.
///
/// A signal saves accepted learning and exits even if stdout cannot drain.
/// Queued output may then be lost.  Idle input does not advance event time.
pub fn run(args: Args, format: Format) -> Result<(), Box<dyn Error>> {
    let parsed_format = args
        .time_format
        .as_deref()
        .map(timestamp::TimestampFormat::new)
        .transpose()?;
    let shutdown = Arc::new(AtomicBool::new(false));
    for signal in [signal_hook::consts::SIGINT, signal_hook::consts::SIGTERM] {
        signal_hook::flag::register(signal, shutdown.clone())?;
    }
    let mut cfg = DetectorConfig::default();
    cfg.tokenizer = args.tokenizer;
    cfg.detect_parameter_changes = args.parameters;
    let settings = state::Settings {
        tokenizer: args.tokenizer.name().into(),
        multiline: args.multiline,
        time_format: args.time_format.clone(),
        tagged: args.tagged,
        system: args.system.clone(),
        parameters: args.parameters,
    };
    let state = args
        .state
        .as_ref()
        .map(|path| state::State::open(path, settings))
        .transpose()?;
    let (store, anchors) = match &state {
        Some(state) => state.load()?,
        None => (ProfileStore::new(), BTreeMap::new()),
    };
    let mut session = Session {
        det: Detector::with_store(cfg, store),
        anchors,
        state,
        dirty: false,
        saved_at: Instant::now(),
        shutdown,
        next_sweep: i64::MIN,
        counts: BTreeMap::new(),
        events: 0,
        flagged: 0,
    };
    let mut input = input::Input::stdin(args.multiline);
    let output = output::Output::stdout();
    let result = (|| -> Result<(), Box<dyn Error>> {
        loop {
            output.check()?;
            if session.tick()? {
                break;
            }
            match input.next()? {
                input::InputEvent::Event(line) => {
                    let bytes = session.observe(&args, format, parsed_format.as_ref(), &line)?;
                    output.send(bytes, || session.tick())?;
                }
                input::InputEvent::Wake => {}
                input::InputEvent::Eof => break,
            }
        }
        if matches!(format, Format::Summary) {
            output.send(session.summary()?, || session.tick())?;
        }
        Ok(())
    })();
    let saved = session.save();
    let drained = output.finish(|| session.tick());
    saved?;
    result?;
    drained?;
    Ok(())
}

struct Session {
    det: Detector,
    anchors: BTreeMap<String, i64>,
    state: Option<state::State>,
    dirty: bool,
    saved_at: Instant,
    shutdown: Arc<AtomicBool>,
    next_sweep: i64,
    counts: BTreeMap<&'static str, u64>,
    events: u64,
    flagged: u64,
}

impl Session {
    /// Validates time before either sweeping or observing can mutate learning.
    fn observe(
        &mut self,
        args: &Args,
        format: Format,
        parsed_format: Option<&timestamp::TimestampFormat>,
        raw: &str,
    ) -> Result<Vec<u8>, Box<dyn Error>> {
        let (system, line) = match raw.split_once('\t') {
            Some((s, l)) if args.tagged => (s, l),
            _ => (args.system.as_str(), raw),
        };
        let (tokens, parsed) = if let Some(parser) = parsed_format {
            let (tokens, time) = parser.tokenize(line, args.tokenizer)?;
            (tokens, Some(time))
        } else {
            let tokens = args.tokenizer.tokenize(line);
            let header = args
                .tokenizer
                .tokenize(line.split('\n').next().unwrap_or(line));
            let parsed = match self.anchors.get(system) {
                Some(&previous) => continuing_event_time(&header, previous),
                None => event_time(&header, wall_clock()),
            };
            (tokens, parsed)
        };
        if parsed.is_some_and(|t| !umami::time::is_supported_timestamp(t)) {
            return Err(
                "event time outside supported timestamp range (UTC years 0 through 9999)".into(),
            );
        }
        if parsed.is_some_and(|t| t > wall_clock().saturating_add(86_400)) {
            return Err("future timestamp exceeds wall clock plus one day".into());
        }
        if let Some(time) = parsed {
            if self.anchors.is_empty() {
                self.next_sweep = i64::MIN;
            }
            self.anchors
                .entry(system.to_string())
                .and_modify(|t| *t = (*t).max(time))
                .or_insert(time);
        }
        let latest = self
            .anchors
            .values()
            .copied()
            .max()
            .unwrap_or_else(wall_clock);
        let now = parsed.unwrap_or(latest);
        let mut out = Vec::new();
        self.dirty = true;
        if latest >= self.next_sweep {
            for anomaly in self.det.sweep(latest) {
                self.report(&mut out, format, &anomaly)?;
            }
            self.next_sweep = latest.saturating_add(SWEEP_EVERY);
        }
        self.events += 1;
        match self.det.observe_tokens(system, line, &tokens, now) {
            Some(anomaly) => self.report(&mut out, format, &anomaly)?,
            None if matches!(format, Format::Text { show_all: true }) => {
                writeln!(out, "{:<18} {line}", "ok")?;
            }
            None => {}
        }
        Ok(out)
    }

    fn report(&mut self, out: &mut Vec<u8>, format: Format, anomaly: &Anomaly) -> io::Result<()> {
        self.flagged += 1;
        *self.counts.entry(anomaly.kind.as_str()).or_default() += 1;
        print(out, format, anomaly)
    }

    /// Uses monotonic deadlines and runs even under continuous input or blocked output.
    fn tick(&mut self) -> io::Result<bool> {
        let stop = self.shutdown.load(Ordering::Relaxed);
        if stop || self.saved_at.elapsed().as_secs() >= 60 {
            self.save()?;
        }
        Ok(stop)
    }

    fn save(&mut self) -> io::Result<()> {
        if self.dirty {
            if let Some(state) = &self.state {
                state.save(&self.det, &self.anchors)?;
            }
            self.dirty = false;
        }
        self.saved_at = Instant::now();
        Ok(())
    }

    fn summary(&self) -> io::Result<Vec<u8>> {
        let mut out = Vec::new();
        writeln!(out, "events:    {}", self.events)?;
        writeln!(out, "anomalies: {}", self.flagged)?;
        let flagged_lines = self.flagged - counts_of_sweeps(&self.counts);
        let reduction = if self.events > 0 {
            100.0 * (1.0 - flagged_lines as f64 / self.events as f64)
        } else {
            0.0
        };
        writeln!(out, "reduction: {reduction:.1}%")?;
        writeln!(out, "profiles:  {}", self.det.store().profile_count())?;
        for (kind, n) in &self.counts {
            writeln!(out, "  {kind:<18} {n}")?;
        }
        Ok(out)
    }
}

fn wall_clock() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}

fn counts_of_sweeps(counts: &BTreeMap<&'static str, u64>) -> u64 {
    [AnomalyKind::EventStop, AnomalyKind::SystemAway]
        .iter()
        .map(|k| counts.get(k.as_str()).copied().unwrap_or(0))
        .sum()
}

fn print(out: &mut impl Write, format: Format, a: &Anomaly) -> io::Result<()> {
    let kind = a.kind.as_str();
    match format {
        // found by a sweep: there is no line, so say which system and structure
        Format::Text { .. } if matches!(a.kind, AnomalyKind::EventStop | AnomalyKind::SystemAway) => {
            let msg = format!("{kind:<18} [{}] {}", a.system, a.signature);
            writeln!(out, "{}", msg.trim_end())
        }
        Format::Text { .. } if a.kind == AnomalyKind::ParameterChange => {
            let slots = a.changed_params.iter().map(usize::to_string).collect::<Vec<_>>().join(", ");
            writeln!(out, "{kind:<18} [changed_params: {slots}] {}", a.line)
        }
        Format::Text { .. } => writeln!(out, "{kind:<18} {}", a.line),
        Format::Json => writeln!(
            out,
            "{{\"system\":{},\"kind\":\"{kind}\",\"score\":{:.2},\"hash\":{},\"signature\":{},\"line\":{},\"changed_params\":{:?}}}",
            json_str(&a.system),
            a.score,
            a.hash.map_or("null".to_string(), |h| format!("\"{h}\"")),
            json_str(&a.signature),
            json_str(&a.line),
            a.changed_params,
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
