//! `umami sim` — summarize anomalies by type over an input stream.

use clap::Args as ClapArgs;
use std::collections::BTreeMap;
use std::error::Error;
use umami::{Detector, DetectorConfig, Tokenizer};

/// Arguments for the `sim` subcommand.
#[derive(ClapArgs)]
pub struct Args {
    /// System (source) name to attribute the events to.
    #[arg(long, default_value = "stdin")]
    system: String,

    /// Tokenizer to use: `structure` or `legacy`.
    #[arg(long, default_value = "structure")]
    tokenizer: String,

    /// Include parameter-change anomalies in the summary.
    #[arg(long)]
    parameters: bool,
}

/// Runs the `sim` subcommand.
pub fn run(args: Args) -> Result<(), Box<dyn Error>> {
    let tokenizer = Tokenizer::from_name(&args.tokenizer)
        .ok_or_else(|| format!("unknown tokenizer: {}", args.tokenizer))?;
    let mut cfg = DetectorConfig {
        tokenizer,
        ..Default::default()
    };
    cfg.detect_parameter_changes = args.parameters;
    let mut detector = Detector::with_config(cfg);

    let mut counts: BTreeMap<&'static str, u64> = BTreeMap::new();
    let mut total = 0u64;
    let mut anomalous = 0u64;

    let mut t: i64 = 0;
    for line in super::read_stdin_lines()? {
        total += 1;
        if let Some(a) = detector.observe(&args.system, &line, t) {
            anomalous += 1;
            *counts.entry(a.kind.as_str()).or_default() += 1;
        }
        t += 1;
    }

    println!("events:    {total}");
    println!("anomalies: {anomalous}");
    let reduction = if total > 0 {
        100.0 * (1.0 - anomalous as f64 / total as f64)
    } else {
        0.0
    };
    println!("reduction: {reduction:.1}%");
    println!("profiles:  {}", detector.store().profile_count());
    for (kind, n) in counts {
        println!("  {kind:<18} {n}");
    }
    Ok(())
}
