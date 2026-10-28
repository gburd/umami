//! Token types and the [`Token`] structure produced by tokenizers.
//!
//! The tokenizer classifies each fragment of a log line into one of a small
//! set of [`TokenType`]s. The numeric discriminants are stable so that golden
//! corpora can be compared directly against the `test` pretty-printer output.

use std::fmt;

/// The classification of a single [`Token`].
///
/// The numeric values are stable and match the integers printed by the
/// "test" pretty-printer (e.g. `0{web01}` is a [`TokenType::Literal`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(u8)]
pub enum TokenType {
    /// A static word / identifier fragment that contributes to structure.
    Literal = 0,
    /// Whitespace or punctuation separating meaningful tokens.
    Delimiter = 1,
    /// A recognized date/time expression (treated as dynamic).
    Timestamp = 2,
    /// An IPv4 address (rarely emitted by the structure tokenizer).
    Ipv4 = 3,
    /// The contents of a quoted string.
    Quoted = 4,
    /// A numeric value (treated as dynamic).
    Number = 5,
    /// A nested JSON value.
    Json = 6,
    /// A key in a `key=value` or JSON `"key":` pair.
    JsonKey = 7,
}

impl TokenType {
    /// Returns the numeric discriminant used by the reference implementation.
    #[inline]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    /// Parses a [`TokenType`] from its numeric discriminant.
    ///
    /// Returns [`None`] for values outside `0..=7`.
    #[inline]
    pub const fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            0 => Self::Literal,
            1 => Self::Delimiter,
            2 => Self::Timestamp,
            3 => Self::Ipv4,
            4 => Self::Quoted,
            5 => Self::Number,
            6 => Self::Json,
            7 => Self::JsonKey,
            _ => return None,
        })
    }

    /// A short lowercase name for the token type.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Literal => "literal",
            Self::Delimiter => "delimiter",
            Self::Timestamp => "timestamp",
            Self::Ipv4 => "ipv4",
            Self::Quoted => "quoted",
            Self::Number => "number",
            Self::Json => "json",
            Self::JsonKey => "jsonkey",
        }
    }

    /// Whether this token contributes to the *structure* of a log line.
    ///
    /// Dynamic tokens ([`TokenType::Number`], [`TokenType::Timestamp`],
    /// [`TokenType::Ipv4`], [`TokenType::Quoted`]) and
    /// [`TokenType::Delimiter`]s are excluded from the structure signature;
    /// [`TokenType::Literal`], [`TokenType::JsonKey`] and [`TokenType::Json`]
    /// are retained.
    #[inline]
    pub const fn is_structural(self) -> bool {
        matches!(self, Self::Literal | Self::JsonKey | Self::Json)
    }

    /// Whether this token represents a dynamic *parameter* value whose value
    /// is tracked per profile (numbers, timestamps, IPs, quoted strings).
    #[inline]
    pub const fn is_parameter(self) -> bool {
        matches!(
            self,
            Self::Number | Self::Timestamp | Self::Ipv4 | Self::Quoted
        )
    }
}

impl fmt::Display for TokenType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// A single token: a classified slice of the input line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Token {
    /// The classification of this token.
    pub ty: TokenType,
    /// The exact text covered by this token.
    pub text: String,
}

impl Token {
    /// Constructs a new token.
    pub fn new(ty: TokenType, text: impl Into<String>) -> Self {
        Self {
            ty,
            text: text.into(),
        }
    }

    /// Convenience constructor for a [`TokenType::Literal`].
    pub fn literal(text: impl Into<String>) -> Self {
        Self::new(TokenType::Literal, text)
    }

    /// Convenience constructor for a [`TokenType::Delimiter`].
    pub fn delimiter(text: impl Into<String>) -> Self {
        Self::new(TokenType::Delimiter, text)
    }

    /// Returns `true` if this token contributes to the structure signature:
    /// a structural type ([`TokenType::is_structural`]) that is not a
    /// [dynamic literal](Token::is_parameter).
    #[inline]
    pub fn is_structural(&self) -> bool {
        self.ty.is_structural() && !self.is_dynamic_literal()
    }

    /// Returns `true` if this token is a dynamic parameter value: a parameter
    /// type ([`TokenType::is_parameter`]) or a literal containing a digit or
    /// a `/` (`web01`, `/var/log/x`, `15ms`, a UUID).
    #[inline]
    pub fn is_parameter(&self) -> bool {
        self.ty.is_parameter() || self.is_dynamic_literal()
    }

    /// Digit-bearing literals are almost always ids, sizes or hostnames, and
    /// slash-bearing ones are paths or URLs, so both are treated as variables
    /// (the Drain pre-processing rule, plus paths).
    #[inline]
    fn is_dynamic_literal(&self) -> bool {
        self.ty == TokenType::Literal && self.text.bytes().any(|b| b.is_ascii_digit() || b == b'/')
    }
}

impl fmt::Display for Token {
    /// Formats the token in the reference `test` form, `T{text}`, where `T`
    /// is the numeric token type.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}{{{}}}", self.ty.as_u8(), self.text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_u8() {
        for v in 0u8..=7 {
            let t = TokenType::from_u8(v).unwrap();
            assert_eq!(t.as_u8(), v);
        }
        assert_eq!(TokenType::from_u8(8), None);
    }

    #[test]
    fn structural_classification() {
        assert!(TokenType::Literal.is_structural());
        assert!(TokenType::JsonKey.is_structural());
        assert!(!TokenType::Number.is_structural());
        assert!(!TokenType::Delimiter.is_structural());
    }

    #[test]
    fn digit_literals_are_parameters() {
        assert!(Token::literal("web01").is_parameter());
        assert!(Token::literal("/var/log/syslog").is_parameter());
        assert!(!Token::literal("web01").is_structural());
        assert!(Token::literal("web").is_structural());
        // keys stay structural even when they contain digits
        assert!(Token::new(TokenType::JsonKey, "field1").is_structural());
        assert!(!Token::delimiter("1").is_parameter());
    }

    #[test]
    fn display_test_form() {
        assert_eq!(Token::literal("web01").to_string(), "0{web01}");
        assert_eq!(Token::new(TokenType::Number, "42").to_string(), "5{42}");
    }
}
