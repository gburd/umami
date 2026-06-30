//! `umami ingest` — emit per-line anomaly events as JSON lines.
//!
//! Each input line is expected to be either a raw log line (attributed to the
//! `--system` value) or, with `--tagged`, a `system\tline` pair so multiple
//! systems can be multiplexed on one stream.

use clap::Args as ClapArgs;
use std::error::Error;
use std::io::Write;
use umami::{Detector, DetectorConfig, Tokenizer};

/// Arguments for the `ingest` subcommand.
#[derive(ClapArgs)]
pub struct Args {
    /// Default system name when input is not tagged.
    #[arg(long, default_value = "stdin")]
    system: String,

    /// Interpret each input line as `system<TAB>line`.
    #[arg(long)]
    tagged: bool,

    /// Tokenizer to use: `structure` or `legacy`.
    #[arg(long, default_value = "structure")]
    tokenizer: String,

    /// Report parameter-change anomalies as well.
    #[arg(long)]
    parameters: bool,
}

/// Runs the `ingest` subcommand.
pub fn run(args: Args) -> Result<(), Box<dyn Error>> {
    let tokenizer = Tokenizer::from_name(&args.tokenizer)
        .ok_or_else(|| format!("unknown tokenizer: {}", args.tokenizer))?;
    let mut cfg = DetectorConfig {
        tokenizer,
        ..Default::default()
    };
    cfg.detect_parameter_changes = args.parameters;
    let mut detector = Detector::with_config(cfg);

    let stdout = std::io::stdout();
    let mut out = std::io::BufWriter::new(stdout.lock());

    let mut t: i64 = 0;
    for raw in super::read_stdin_lines()? {
        let (system, line) = if args.tagged {
            match raw.split_once('\t') {
                Some((s, l)) => (s.to_string(), l.to_string()),
                None => (args.system.clone(), raw.clone()),
            }
        } else {
            (args.system.clone(), raw.clone())
        };
        if let Some(a) = detector.observe(&system, &line, t) {
            writeln!(
                out,
                "{{\"system\":{},\"kind\":\"{}\",\"score\":{:.2},\"signature\":{},\"line\":{}}}",
                json_str(&a.system),
                a.kind.as_str(),
                a.score,
                json_str(&a.signature),
                json_str(&a.line),
            )?;
        }
        t += 1;
    }
    out.flush()?;
    Ok(())
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
