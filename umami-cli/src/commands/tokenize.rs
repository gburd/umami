//! `umami tokenize` — tokenize log lines and print them in various formats.

use clap::Args as ClapArgs;
use std::error::Error;
use std::fs;
use std::io::Write;
use umami::{Pretty, Tokenizer};

/// Arguments for the `tokenize` subcommand.
#[derive(ClapArgs)]
pub struct Args {
    /// Name of the tokenizer to use: `structure` (default) or `legacy`.
    #[arg(long, default_value = "structure")]
    tokenizer: String,

    /// Pretty-printer: `test`, `colors`, `params`, `delimiters` or `static`.
    #[arg(long, default_value = "test")]
    pretty: String,

    /// Colorize output (only affects the `colors` printer).
    #[arg(long)]
    color: bool,

    /// Run a golden test file (`input` / `expected` line pairs) and report
    /// mismatches instead of reading stdin.
    #[arg(long, value_name = "FILE")]
    test: Option<String>,

    /// When running a `--test` file, rewrite it with the tokenizer's current
    /// output, fixing any mismatches.
    #[arg(long)]
    fix: bool,

    /// Print passing cases as well as failures when running a test file.
    #[arg(long)]
    verbose: bool,

    /// One or more log lines to tokenize. If omitted, read from stdin.
    #[arg(value_name = "LINE")]
    lines: Vec<String>,
}

/// Runs the `tokenize` subcommand.
pub fn run(args: Args) -> Result<(), Box<dyn Error>> {
    let tokenizer = Tokenizer::from_name(&args.tokenizer)
        .ok_or_else(|| format!("unknown tokenizer: {}", args.tokenizer))?;
    let pretty = Pretty::from_name(&args.pretty)
        .ok_or_else(|| format!("unknown pretty printer: {}", args.pretty))?;

    if let Some(path) = args.test {
        return run_test_file(&path, tokenizer, args.fix, args.verbose);
    }

    let stdout = std::io::stdout();
    let mut out = std::io::BufWriter::new(stdout.lock());

    if args.lines.is_empty() {
        // Stream stdin line by line for low memory use.
        let stdin = std::io::stdin();
        let mut line = String::new();
        loop {
            line.clear();
            let n = std::io::BufRead::read_line(&mut stdin.lock(), &mut line)?;
            if n == 0 {
                break;
            }
            let trimmed = line.trim_end_matches(['\n', '\r']);
            let tokens = tokenizer.tokenize(trimmed);
            writeln!(out, "{}", pretty.render(&tokens, args.color))?;
        }
    } else {
        for line in &args.lines {
            let tokens = tokenizer.tokenize(line);
            writeln!(out, "{}", pretty.render(&tokens, args.color))?;
        }
    }
    out.flush()?;
    Ok(())
}

/// A golden test file is a sequence of `input \t expected` lines (the same TSV
/// format used by the project corpus). This checks each line and, with `fix`,
/// rewrites mismatched expectations.
fn run_test_file(
    path: &str,
    tokenizer: Tokenizer,
    fix: bool,
    verbose: bool,
) -> Result<(), Box<dyn Error>> {
    let data = fs::read_to_string(path)?;
    let mut total = 0usize;
    let mut passed = 0usize;
    let mut fixed_lines = Vec::new();
    let mut failures = Vec::new();

    for line in data.lines() {
        let Some((input, expected)) = line.split_once('\t') else {
            fixed_lines.push(line.to_string());
            continue;
        };
        total += 1;
        let got = umami::Pretty::Test.render(&tokenizer.tokenize(input), false);
        if got == expected {
            passed += 1;
            if verbose {
                println!("PASS  {input}");
            }
            fixed_lines.push(format!("{input}\t{expected}"));
        } else {
            failures.push((input.to_string(), expected.to_string(), got.clone()));
            fixed_lines.push(format!("{input}\t{got}"));
        }
    }

    if fix {
        fs::write(path, fixed_lines.join("\n") + "\n")?;
        println!("fixed {} mismatched case(s) in {path}", failures.len());
        return Ok(());
    }

    for (input, expected, got) in &failures {
        println!("FAIL  {input}\n  expected: {expected}\n  got:      {got}");
    }
    println!("{passed}/{total} passed");
    if failures.is_empty() {
        Ok(())
    } else {
        Err(format!("{} test case(s) failed", failures.len()).into())
    }
}
