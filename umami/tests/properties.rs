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
    /// Tokenization is lossless: concatenating token texts reproduces the
    /// (whitespace-trimmed) input for both tokenizers.
    #[test]
    fn tokenization_is_lossless_structure(line in line_strategy()) {
        let joined: String = Tokenizer::Structure
            .tokenize(&line)
            .iter()
            .map(|t| t.text.as_str())
            .collect();
        prop_assert_eq!(joined, line);
    }

    #[test]
    fn tokenization_is_lossless_legacy(line in line_strategy()) {
        let joined: String = Tokenizer::Legacy
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
        for tok in Tokenizer::Legacy.tokenize(&line) {
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
