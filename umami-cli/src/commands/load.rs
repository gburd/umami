//! `umami load` — throughput benchmark over synthetic or piped log data.

use clap::Args as ClapArgs;
use std::error::Error;
use std::time::Instant;
use umami::{Detector, DetectorConfig, Tokenizer};

/// Arguments for the `load` subcommand.
#[derive(ClapArgs)]
pub struct Args {
    /// Number of synthetic events to generate when no stdin is provided.
    #[arg(long, default_value_t = 1_000_000)]
    count: u64,

    /// Tokenizer to use: `structure` or `legacy`.
    #[arg(long, default_value = "structure")]
    tokenizer: String,

    /// Read lines from stdin instead of generating synthetic data.
    #[arg(long)]
    stdin: bool,
}

/// Runs the `load` subcommand.
pub fn run(args: Args) -> Result<(), Box<dyn Error>> {
    let tokenizer = Tokenizer::from_name(&args.tokenizer)
        .ok_or_else(|| format!("unknown tokenizer: {}", args.tokenizer))?;
    let cfg = DetectorConfig {
        tokenizer,
        ..Default::default()
    };
    let mut detector = Detector::with_config(cfg);

    let lines: Vec<String> = if args.stdin {
        super::read_stdin_lines()?
    } else {
        synth(args.count)
    };

    let start = Instant::now();
    let mut anomalies = 0u64;
    for (i, line) in lines.iter().enumerate() {
        if detector.observe("load", line, i as i64).is_some() {
            anomalies += 1;
        }
    }
    let elapsed = start.elapsed();
    let n = lines.len() as f64;
    let rate = n / elapsed.as_secs_f64();
    println!("processed {} events in {:.3?}", lines.len(), elapsed);
    println!("throughput {rate:.0} events/sec");
    println!("anomalies  {anomalies}");
    Ok(())
}

/// Generates `count` semi-repetitive synthetic log lines.
fn synth(count: u64) -> Vec<String> {
    let templates = [
        "GET /api/v2/users/{} HTTP/1.1 200 {}",
        "level=info msg=ok host=node{} latency={}",
        "Jan 23 10:23:45 web01 sshd[{}]: Accepted publickey for deploy port {}",
        "disk usage at {} percent on /dev/sda{}",
    ];
    (0..count)
        .map(|i| {
            let t = templates[(i % templates.len() as u64) as usize];
            t.replace("{}", &i.to_string())
        })
        .collect()
}
