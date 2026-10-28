//! `umami` — a command-line interface to the [`umami`] log anomaly-detection
//! library.
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
    about = "Log anomaly detection and structural tokenization.",
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
    /// Stream logs through the detector and print anomalous lines.
    Pipeline(commands::detect::PipelineArgs),
    /// Stream logs through the detector and summarize anomalies by type.
    Sim(commands::detect::Args),
    /// Stream logs through the detector and emit anomalies as JSON lines.
    Ingest(commands::detect::Args),
    /// Load-test the detector and report throughput.
    Load(commands::load::Args),
}

fn main() -> ExitCode {
    use commands::detect::{run, run_pipeline, Format};
    let cli = Cli::parse();
    let result = match cli.command {
        Commands::Tokenize(args) => commands::tokenize::run(args),
        Commands::Pipeline(args) => run_pipeline(args),
        Commands::Sim(args) => run(args, Format::Summary),
        Commands::Ingest(args) => run(args, Format::Json),
        Commands::Load(args) => commands::load::run(args),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        // a closed pipe (`umami ... | head`) is a normal way to stop
        Err(e)
            if e.downcast_ref::<std::io::Error>().map(|e| e.kind())
                == Some(std::io::ErrorKind::BrokenPipe) =>
        {
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("umami: {e}");
            ExitCode::FAILURE
        }
    }
}
