//! `umami` — a command-line interface to the [`umami`] log anomaly-detection
//! library, compatible with the subcommands of Unomaly's `unomalycli`.
//!
//! Run `umami --help` or `umami <command> --help` for usage.

mod commands;

use clap::{Parser, Subcommand};
use std::process::ExitCode;

/// Detect anomalies and inspect the structure of log data.
#[derive(Parser)]
#[command(
    name = "umami",
    version,
    about = "Log anomaly detection and structural tokenization (a reimplementation of unomalycli).",
    long_about = None,
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Show the tokenized output of input log lines.
    Tokenize(commands::tokenize::Args),
    /// Feed logs through the detection pipeline and print anomalies.
    Pipeline(commands::pipeline::Args),
    /// Simulate a stream and summarize anomalies by type.
    Sim(commands::sim::Args),
    /// Read log lines and emit per-system anomaly events as JSON lines.
    Ingest(commands::ingest::Args),
    /// Load-test the detector and report throughput.
    Load(commands::load::Args),
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.command {
        Commands::Tokenize(args) => commands::tokenize::run(args),
        Commands::Pipeline(args) => commands::pipeline::run(args),
        Commands::Sim(args) => commands::sim::run(args),
        Commands::Ingest(args) => commands::ingest::run(args),
        Commands::Load(args) => commands::load::run(args),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("umami: {e}");
            ExitCode::FAILURE
        }
    }
}
