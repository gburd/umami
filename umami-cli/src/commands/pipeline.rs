//! `umami pipeline` — run log lines through the detector and print anomalies.

use clap::Args as ClapArgs;
use std::error::Error;
use std::io::Write;
use umami::{Detector, DetectorConfig, Tokenizer};

/// Arguments for the `pipeline` subcommand.
#[derive(ClapArgs)]
pub struct Args {
    /// System (source) name to attribute the events to.
    #[arg(long, default_value = "stdin")]
    system: String,

    /// Tokenizer to use: `structure` or `legacy`.
    #[arg(long, default_value = "structure")]
    tokenizer: String,

    /// Also report parameter-change anomalies (new values on known structures).
    #[arg(long)]
    parameters: bool,

    /// Only print anomalous lines (the default). With `--show-all`, every line
    /// is printed and prefixed with its classification (or `ok`).
    #[arg(long)]
    show_all: bool,
}

/// Runs the `pipeline` subcommand.
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
    let lines = super::read_stdin_lines()?;
    for line in lines {
        let anomaly = detector.observe(&args.system, &line, t);
        t += 1;
        match anomaly {
            Some(a) => writeln!(out, "{:<18} {}", a.kind.as_str(), a.line)?,
            None if args.show_all => writeln!(out, "{:<18} {}", "ok", line)?,
            None => {}
        }
    }
    out.flush()?;
    Ok(())
}
