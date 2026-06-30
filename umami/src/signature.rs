//! Structure signatures: the stable hash of a log line's *structural* tokens.
//!
//! Two log lines that differ only in their dynamic parts (numbers, timestamps,
//! IPs, quoted values) share the same structure signature and therefore map to
//! the same [`crate::profile::Profile`].

use crate::token::Token;
use std::fmt;
use std::hash::Hasher;

/// A 64-bit structure hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct StructureHash(pub u64);

impl fmt::Display for StructureHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:016x}", self.0)
    }
}

/// Returns the ordered list of structural token texts for `tokens`.
///
/// Structural tokens are those for which [`crate::TokenType::is_structural`] is
/// true ([`crate::TokenType::Literal`], [`crate::TokenType::JsonKey`],
/// [`crate::TokenType::Json`]). Delimiters and dynamic parameter tokens are
/// dropped.
pub fn structural_tokens(tokens: &[Token]) -> impl Iterator<Item = &Token> {
    tokens.iter().filter(|t| t.is_structural())
}

/// Computes the [`StructureHash`] for a tokenized log line.
///
/// The hash combines the type and text of each structural token (in order)
/// using the FNV-1a algorithm, which is fast, allocation-free and stable
/// across runs and platforms.
pub fn structure_signature(tokens: &[Token]) -> StructureHash {
    let mut h = Fnv1a::new();
    for t in structural_tokens(tokens) {
        h.write_u8(t.ty.as_u8());
        h.write(t.text.as_bytes());
        h.write_u8(0xff); // token separator
    }
    StructureHash(h.finish())
}

/// Renders the structure signature in human-readable form: the structural
/// token texts joined by single spaces (mirrors `unomalycli -pretty=static`).
pub fn structure_string(tokens: &[Token]) -> String {
    let mut out = String::new();
    for t in structural_tokens(tokens) {
        if !out.is_empty() {
            out.push(' ');
        }
        out.push_str(&t.text);
    }
    out
}

/// FNV-1a 64-bit hasher (inlined to avoid a dependency and stay `no_std`-able).
struct Fnv1a(u64);

impl Fnv1a {
    const OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x0000_0100_0000_01b3;

    #[inline]
    fn new() -> Self {
        Self(Self::OFFSET)
    }
}

impl Hasher for Fnv1a {
    #[inline]
    fn finish(&self) -> u64 {
        self.0
    }

    #[inline]
    fn write(&mut self, bytes: &[u8]) {
        let mut hash = self.0;
        for &b in bytes {
            hash ^= b as u64;
            hash = hash.wrapping_mul(Self::PRIME);
        }
        self.0 = hash;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tokenize;

    #[test]
    fn dynamic_parts_dont_affect_signature() {
        // Only numeric/timestamp parts are dynamic; literal words (incl.
        // key=value *values* that are words) are part of the structure, just
        // as the reference `unomalycli -pretty=static` shows.
        let a = structure_signature(&tokenize("request id=1 took 3 ms"));
        let b = structure_signature(&tokenize("request id=2 took 9 ms"));
        assert_eq!(a, b);
    }

    #[test]
    fn different_structure_differs() {
        let a = structure_signature(&tokenize("disk full on /dev/sda1"));
        let b = structure_signature(&tokenize("network down on eth0"));
        assert_ne!(a, b);
    }

    #[test]
    fn static_string_drops_dynamic() {
        let toks = tokenize("Jan 23 10:23:45 web01 failed for root from 10.0.0.1 port 22");
        let s = structure_string(&toks);
        assert!(!s.contains("10:23:45"));
        assert!(!s.contains("22"));
        assert!(s.contains("web01"));
        assert!(s.contains("failed"));
    }
}
