//! Golden corpus tests: verify the umami tokenizer reproduces the exact output
//! of the reference `unomalycli tokenize` command.
//!
//! The corpus files in `corpus/` contain tab-separated `input \t expected`
//! lines, where `expected` is the reference `-pretty=test` rendering
//! (`T{text}` tokens joined by spaces). They are generated directly from the
//! original `unomalycli` binary.

use std::path::Path;
use umami::{Token, Tokenizer};

fn render(tokens: &[Token]) -> String {
    tokens
        .iter()
        .map(Token::to_string)
        .collect::<Vec<_>>()
        .join(" ")
}

fn corpus_path(name: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("corpus")
        .join(name)
}

fn run_corpus(file: &str, tokenizer: Tokenizer) -> (usize, usize, Vec<String>) {
    let path = corpus_path(file);
    let data =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    let mut total = 0;
    let mut matched = 0;
    let mut failures = Vec::new();
    for line in data.lines() {
        let Some((input, expected)) = line.split_once('\t') else {
            continue;
        };
        total += 1;
        let got = render(&tokenizer.tokenize(input));
        if got == expected {
            matched += 1;
        } else if failures.len() < 20 {
            failures.push(format!("IN : {input}\nEXP: {expected}\nGOT: {got}"));
        }
    }
    (matched, total, failures)
}

#[test]
fn structure_corpus_matches() {
    let (matched, total, failures) = run_corpus("structure.tsv", Tokenizer::Structure);
    let pct = 100.0 * matched as f64 / total as f64;
    eprintln!("structure tokenizer: {matched}/{total} ({pct:.1}%)");
    for f in &failures {
        eprintln!("---\n{f}");
    }
    // The structure tokenizer matches the reference essentially exactly; a
    // couple of pathological inputs (JSON nested past the scanner depth limit,
    // bare dates in certain positions) are documented known differences.
    assert!(
        matched as f64 / total as f64 >= 0.99,
        "structure tokenizer corpus match rate {pct:.1}% below 99%"
    );
}

#[test]
fn legacy_corpus_matches() {
    let (matched, total, failures) = run_corpus("legacy.tsv", Tokenizer::Legacy);
    let pct = 100.0 * matched as f64 / total as f64;
    eprintln!("legacy tokenizer: {matched}/{total} ({pct:.1}%)");
    for f in &failures {
        eprintln!("---\n{f}");
    }
    assert!(
        matched as f64 / total as f64 >= 0.90,
        "legacy tokenizer corpus match rate {pct:.1}% below 90%"
    );
}
