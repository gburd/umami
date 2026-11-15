//! Property-based tests asserting invariants that must hold for *all* inputs.

use proptest::prelude::*;
use umami::{signature::structure_signature, Detector, TokenType, Tokenizer};

/// A strategy for log-line-like strings without leading/trailing whitespace or
/// newlines, so that exact reconstruction can be asserted.
fn line_strategy() -> impl Strategy<Value = String> {
    proptest::string::string_regex("[a-zA-Z0-9 ._/=:\\-\\[\\]{}\",]{0,80}")
        .unwrap()
        .prop_map(|s| s.trim().to_string())
        .prop_filter("non-empty", |s| !s.is_empty())
}

proptest! {
    #![proptest_config(ProptestConfig {
        failure_persistence: Some(Box::new(
            proptest::test_runner::FileFailurePersistence::WithSource("proptest-regressions"),
        )),
        ..ProptestConfig::default()
    })]

    /// Tokenization is lossless: concatenating token texts reproduces the
    /// (whitespace-trimmed) input for the tokenizer.
    #[test]
    fn tokenization_is_lossless_structure(line in line_strategy()) {
        let joined: String = Tokenizer::Structure
            .tokenize(&line)
            .iter()
            .map(|t| t.text.as_str())
            .collect();
        prop_assert_eq!(joined, line);
    }

    /// No token is ever empty.
    #[test]
    fn no_empty_tokens(line in line_strategy()) {
        for tok in Tokenizer::Structure.tokenize(&line) {
            prop_assert!(!tok.text.is_empty());
        }
    }

    /// Number tokens always start with a digit or a sign followed by a digit.
    #[test]
    fn numbers_start_with_digit(line in line_strategy()) {
        for tok in Tokenizer::Structure.tokenize(&line) {
            if tok.ty == TokenType::Number {
                let b = tok.text.as_bytes();
                let ok = b[0].is_ascii_digit()
                    || ((b[0] == b'+' || b[0] == b'-')
                        && b.get(1).is_some_and(u8::is_ascii_digit));
                prop_assert!(ok, "number token {:?} does not start with digit/sign", tok.text);
            }
        }
    }

    /// Delimiter tokens never contain ASCII alphanumeric characters.
    #[test]
    fn delimiters_have_no_alnum(line in line_strategy()) {
        for tok in Tokenizer::Structure.tokenize(&line) {
            if tok.ty == TokenType::Delimiter {
                prop_assert!(
                    !tok.text.bytes().any(|b| b.is_ascii_alphanumeric()),
                    "delimiter {:?} contains alnum",
                    tok.text
                );
            }
        }
    }

    /// The structure signature is deterministic.
    #[test]
    fn signature_is_deterministic(line in line_strategy()) {
        let a = structure_signature(&Tokenizer::Structure.tokenize(&line));
        let b = structure_signature(&Tokenizer::Structure.tokenize(&line));
        prop_assert_eq!(a, b);
    }

    /// Detector classification is deterministic across two fresh detectors.
    #[test]
    fn detector_is_deterministic(lines in proptest::collection::vec(line_strategy(), 1..20)) {
        let mut d1 = Detector::new();
        let mut d2 = Detector::new();
        for (i, line) in lines.iter().enumerate() {
            let a = d1.observe("sys", line, i as i64).map(|a| a.kind);
            let b = d2.observe("sys", line, i as i64).map(|a| a.kind);
            prop_assert_eq!(a, b);
        }
    }

    /// Substituting only the digits of numeric tokens preserves the structure
    /// signature (numbers are dynamic).
    #[test]
    fn digit_substitution_preserves_signature(seed in 0u64..1000) {
        let base = format!("request id={} took {} ms ok", seed, seed * 7 + 1);
        let alt = format!("request id={} took {} ms ok", seed + 1, seed * 3 + 2);
        let a = structure_signature(&Tokenizer::Structure.tokenize(&base));
        let b = structure_signature(&Tokenizer::Structure.tokenize(&alt));
        prop_assert_eq!(a, b);
    }
}

proptest! {
    #![proptest_config(ProptestConfig {
        failure_persistence: Some(Box::new(
            proptest::test_runner::FileFailurePersistence::WithSource("proptest-regressions"),
        )),
        ..ProptestConfig::default()
    })]

    /// The timestamp parser never panics, on any input.
    #[test]
    fn parse_timestamp_never_panics(s in "\\PC{0,40}", now in proptest::num::i64::ANY) {
        let _ = umami::time::parse_timestamp(&s, now);
    }

    /// Any ISO timestamp the tokenizer finds parses, to the value of its
    /// fields.
    #[test]
    fn iso_round_trip(y in 1970i64..2100, mo in 1i64..=12, d in 1i64..=28, h in 0i64..24, mi in 0i64..60, s in 0i64..60) {
        let text = format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}Z");
        let toks = Tokenizer::Structure.tokenize(&format!("{text} x"));
        prop_assert_eq!(toks[0].ty, TokenType::Timestamp);
        let t = umami::time::event_time(&toks, 0).unwrap();
        let days = t.div_euclid(86_400);
        prop_assert_eq!(t.rem_euclid(86_400), h * 3600 + mi * 60 + s);
        // the syslog form of the same instant, with an explicit year, agrees
        const M: [&str; 12] = ["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"];
        let sys = format!("{} {d:2} {h:02}:{mi:02}:{s:02} {y}", M[(mo - 1) as usize]);
        prop_assert_eq!(umami::time::parse_timestamp(&sys, 0), Some(t), "{}", sys);
        prop_assert!(days >= 0);
    }

    /// Tokenizing never panics and stays lossless on arbitrary Unicode,
    /// including quotes and apostrophes next to multibyte characters.
    #[test]
    fn tokenization_is_lossless_unicode(line in "[\\PC\"'=:{}]{0,60}") {
        let line = line.trim_matches(['\n', '\r']).to_string();
        let tok = Tokenizer::Structure;
        let joined: String = tok.tokenize(&line).iter().map(|t| t.text.as_str()).collect();
        prop_assert_eq!(&joined, &line);
    }
}

/// Each changing value occupies one parameter slot, even when its punctuation changes.
#[test]
fn variable_shapes_preserve_signatures() {
    for (first, second) in [
        ("connect alpha.example:80 ok", "connect beta.example:443 ok"),
        ("mail alice@example.org ok", "mail bob@other.net ok"),
        ("hash abcdefabcdefabcdef ok", "hash fedcbafedcbafedcba ok"),
        (
            "GET https://alpha.example/api?q=one&lang=en ok",
            "GET http://beta.example/other?offset=42 ok",
        ),
        ("size 1,234 ok", "size 1,234,567 ok"),
    ] {
        let first_tokens = Tokenizer::Structure.tokenize(first);
        let second_tokens = Tokenizer::Structure.tokenize(second);
        assert_eq!(
            structure_signature(&first_tokens),
            structure_signature(&second_tokens),
            "{first:?} and {second:?}"
        );
        assert_eq!(
            first_tokens.iter().filter(|t| t.is_parameter()).count(),
            1,
            "{first}"
        );
        assert_eq!(
            second_tokens.iter().filter(|t| t.is_parameter()).count(),
            1,
            "{second}"
        );
    }
}

#[test]
fn quote_heavy_input_stays_lossless() {
    for line in ["\"'é'=42 ".repeat(20_000), "\"".repeat(100_000)] {
        let tokens = Tokenizer::Structure.tokenize(&line);
        assert!(tokens.iter().all(|token| !token.text.is_empty()));
        assert_eq!(
            tokens
                .iter()
                .map(|token| token.text.as_str())
                .collect::<String>(),
            line
        );
    }
}

#[test]
fn bare_colon_labels_remain_structural() {
    let first = Tokenizer::Structure.tokenize("event error:123");
    let second = Tokenizer::Structure.tokenize("event warning:456");
    assert_ne!(structure_signature(&first), structure_signature(&second));
}

#[test]
fn array_commas_separate_numeric_slots() {
    for (first, second) in [
        ("value [1,234,567]", "value [1,2,3]"),
        ("value [[1,234],567]", "value [[1,2],3]"),
    ] {
        let first = Tokenizer::Structure.tokenize(first);
        let second = Tokenizer::Structure.tokenize(second);
        assert_eq!(structure_signature(&first), structure_signature(&second));
        assert_eq!(first.iter().filter(|t| t.is_parameter()).count(), 3);
    }
    let tokens = Tokenizer::Structure.tokenize("value [1,234] total 1,234,567");
    assert_eq!(tokens.iter().filter(|t| t.is_parameter()).count(), 3);
    let quoted = Tokenizer::Structure.tokenize(r#"["1,234,567",2]"#);
    assert_eq!(quoted.iter().filter(|t| t.is_parameter()).count(), 2);
}

#[test]
fn plus_email_stays_one_parameter_without_merging_words() {
    let first = Tokenizer::Structure.tokenize("mail alice+alerts@example.org");
    let second = Tokenizer::Structure.tokenize("mail bob@example.net");
    assert_eq!(structure_signature(&first), structure_signature(&second));
    assert_eq!(first.last().unwrap().text, "alice+alerts@example.org");
    let words = Tokenizer::Structure.tokenize("alpha+beta");
    assert_eq!(words.len(), 3);
    assert!(words[0].is_structural());
    assert!(words[2].is_structural());
    let long = format!("{}@example.org", "a+".repeat(200));
    let tokens = Tokenizer::Structure.tokenize(&long);
    assert_eq!(
        tokens.iter().map(|t| t.text.as_str()).collect::<String>(),
        long
    );
}

#[test]
fn url_query_commas_stay_in_parameter() {
    let first = Tokenizer::Structure.tokenize("GET https://example.org/?q=one,two");
    let second = Tokenizer::Structure.tokenize("GET https://example.org/?q=three");
    assert_eq!(structure_signature(&first), structure_signature(&second));
    assert_eq!(first.last().unwrap().text, "https://example.org/?q=one,two");
}
