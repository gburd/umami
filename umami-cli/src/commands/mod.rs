//! Subcommand implementations for the `umami` CLI.

pub mod ingest;
pub mod load;
pub mod pipeline;
pub mod sim;
pub mod tokenize;

use std::io::{self, BufRead};

/// Reads all lines from standard input, stripping the trailing newline.
pub(crate) fn read_stdin_lines() -> io::Result<Vec<String>> {
    let stdin = io::stdin();
    let mut out = Vec::new();
    for line in stdin.lock().lines() {
        out.push(line?);
    }
    Ok(out)
}
