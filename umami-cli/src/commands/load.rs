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

    /// Tokenizer to use.
    #[arg(long, default_value = "structure", value_parser = super::tokenizer_arg())]
    tokenizer: Tokenizer,

    /// Read lines from stdin instead of generating synthetic data.
    #[arg(long)]
    stdin: bool,
}

/// Runs the `load` subcommand.
pub fn run(args: Args) -> Result<(), Box<dyn Error>> {
    let mut cfg = DetectorConfig::default();
    cfg.tokenizer = args.tokenizer;
    let mut detector = Detector::with_config(cfg);

    let lines: Vec<String> = if args.stdin {
        let mut v = Vec::new();
        super::for_each_line(std::io::stdin().lock(), |l, _| {
            v.push(l.to_string());
            Ok(())
        })?;
        v
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
    let rate = lines.len() as f64 / elapsed.as_secs_f64();
    println!("processed {} events in {:.3?}", lines.len(), elapsed);
    println!("throughput {rate:.0} events/sec");
    println!("anomalies  {anomalies}");
    println!("profiles   {}", detector.store().profile_count());
    Ok(())
}

/// Generates `count` synthetic log lines from a handful of templates, varying
/// only their parameters, so the run measures steady-state filtering rather
/// than profile creation.
fn synth(count: u64) -> Vec<String> {
    (0..count)
        .map(|i| match i % 4 {
            0 => format!("GET /api/v2/users/{i} HTTP/1.1 200 {}", i % 5000),
            1 => format!("level=info msg=ok host=node{} latency={}ms", i % 16, i % 900),
            2 => format!(
                "Jan 23 10:23:45 web01 sshd[{}]: Accepted publickey for deploy from 10.0.{}.{} port {}",
                i % 30000,
                i % 256,
                i % 200,
                1024 + i % 60000
            ),
            _ => format!("disk usage at {} percent on /dev/sda{}", i % 100, i % 4),
        })
        .collect()
}
