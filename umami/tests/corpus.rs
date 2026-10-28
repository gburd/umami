//! Golden corpus tests: verify the umami tokenizer reproduces the expected
//! token output stored in the project corpus.
//!
//! The corpus files in `corpus/` contain tab-separated `input \t expected`
//! lines, where `expected` is the `test`-printer rendering (`T{text}` tokens
//! joined by spaces).

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

/// Inputs the legacy tokenizer is known to get wrong against the corpus. Any
/// other mismatch, or one of these starting to pass, fails the test.
const LEGACY_KNOWN_FAILURES: &[&str] = &[
    r#"nested {"a":{"b":{"c":1}}} done"#,
    "mac 00:11:22:33:44:55 time 10:23:45 date 2020-11-12",
    r#"empty values a= b=" " c="""#,
];

fn run_corpus(file: &str, tokenizer: Tokenizer) -> (usize, Vec<String>, Vec<String>) {
    let path = corpus_path(file);
    let data =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    let mut total = 0;
    let mut failed_inputs = Vec::new();
    let mut failures = Vec::new();
    for line in data.lines() {
        let Some((input, expected)) = line.split_once('\t') else {
            continue;
        };
        total += 1;
        let got = render(&tokenizer.tokenize(input));
        if got != expected {
            failed_inputs.push(input.to_string());
            failures.push(format!("IN : {input}\nEXP: {expected}\nGOT: {got}"));
        }
    }
    (total, failed_inputs, failures)
}

#[test]
fn structure_corpus_matches() {
    let (total, failed, failures) = run_corpus("structure.tsv", Tokenizer::Structure);
    assert!(total > 400, "corpus too small: {total}");
    assert!(failed.is_empty(), "{}", failures.join("\n---\n"));
}

#[test]
fn legacy_corpus_matches() {
    let (total, failed, failures) = run_corpus("legacy.tsv", Tokenizer::Legacy);
    assert!(total > 400, "corpus too small: {total}");
    assert_eq!(
        failed,
        LEGACY_KNOWN_FAILURES,
        "legacy mismatches changed:\n{}",
        failures.join("\n---\n")
    );
}
