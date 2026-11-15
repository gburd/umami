//! The structural log-line tokenizer.
//!
//! This module implements the `structure` tokenizer.  Tokenization
//! is the first stage of anomaly detection: a raw log line is
//! split into a sequence of typed [`Token`]s, from which a structure signature
//! is later derived.
//!
//! # Examples
//!
//! ```
//! use umami::{tokenize, TokenType};
//!
//! let tokens = tokenize("web01 sshd[1234]: ok from 10.0.0.1");
//! assert_eq!(tokens[0].text, "web01");
//! assert_eq!(tokens[0].ty, TokenType::Literal);
//! // The pid is numeric:
//! assert!(tokens.iter().any(|t| t.ty == TokenType::Number && t.text == "1234"));
//! ```

use crate::token::{Token, TokenType};

/// Which tokenizer variant to use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Tokenizer {
    /// The modern structural tokenizer. Understands
    /// key/value pairs, quoted strings and nested JSON. This is the default.
    #[default]
    Structure,
}

impl Tokenizer {
    /// Parses a tokenizer name (`"structure"`).
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "structure" => Some(Self::Structure),
            _ => None,
        }
    }

    /// The name accepted by [`Tokenizer::from_name`].
    pub const fn name(self) -> &'static str {
        match self {
            Self::Structure => "structure",
        }
    }

    /// Tokenizes a single log line into a sequence of [`Token`]s.
    pub fn tokenize(self, line: &str) -> Vec<Token> {
        match self {
            Tokenizer::Structure => tokenize_structure(line),
        }
    }
}

/// Tokenizes `line` with the default ([`Tokenizer::Structure`]) tokenizer.
pub fn tokenize(line: &str) -> Vec<Token> {
    Tokenizer::Structure.tokenize(line)
}

// ---------------------------------------------------------------------------
// Character classification
// ---------------------------------------------------------------------------

/// Characters that may appear *inside* a word token (besides letters/digits).
/// Determined empirically from the reference tokenizer.
#[inline]
fn is_word_char(c: char) -> bool {
    c.is_alphanumeric()
        || matches!(
            c,
            '.' | '-' | '_' | '/' | '%' | '@' | '!' | '?' | '&' | '\\' | '$' | '^' | '~'
        )
        || (!c.is_ascii() && !c.is_whitespace())
}

#[inline]
fn is_hex_digit(c: char) -> bool {
    c.is_ascii_hexdigit()
}

// ---------------------------------------------------------------------------
// Number classification
// ---------------------------------------------------------------------------

/// Classifies a word as a [`TokenType::Number`] if it matches one of the
/// numeric forms recognized by the reference tokenizer:
///
/// * decimal / float: `^[-+]?[0-9]*\.?[0-9]+([eE][-+]?[0-9]+)?$`
/// * thousands-grouped integer: `digit (',' digit)*` where commas sit between
///   digits (e.g. `1,234`)
/// * hexadecimal: starts with a digit and is otherwise all hex digits
///   (e.g. `42c`, `0xFF`), or has an explicit `0x` / `0X` prefix.
fn is_number(word: &str) -> bool {
    if word.is_empty() {
        return false;
    }

    // Explicit hex prefix: 0x / 0X followed by >=1 hex digit.
    if let Some(rest) = word.strip_prefix("0x").or_else(|| word.strip_prefix("0X")) {
        return !rest.is_empty() && rest.chars().all(is_hex_digit);
    }

    let bytes = word.as_bytes();
    let first = bytes[0];

    // Hex form: must begin with a decimal digit, remainder all hex digits.
    if first.is_ascii_digit() && word.chars().all(is_hex_digit) {
        return true;
    }

    // Decimal / float / thousands-grouped.
    is_decimal(word)
}

/// Matches a decimal/float number. Requires at least one digit, and a dot must
/// have a digit on at least one side via the leading-digit rule enforced by the
/// caller; here we additionally reject a trailing or leading bare dot
/// (`5.`, `.5` are *not* numbers in the reference tokenizer).
fn is_decimal(word: &str) -> bool {
    let bytes = word.as_bytes();
    // reject leading or trailing dot
    if bytes.first() == Some(&b'.') || bytes.last() == Some(&b'.') {
        return false;
    }
    let mut chars = word.chars().peekable();

    // optional sign
    if matches!(chars.peek(), Some('+') | Some('-')) {
        chars.next();
    }
    if chars.peek() == Some(&'.') {
        return false; // `-.5`, like `.5`, is not a number
    }

    let mut saw_digit = false;
    let mut saw_dot = false;
    let mut saw_exp = false;

    while let Some(&c) = chars.peek() {
        match c {
            '0'..='9' => {
                saw_digit = true;
                chars.next();
            }
            ',' => {
                chars.next();
                match chars.peek() {
                    Some(d) if d.is_ascii_digit() => {}
                    _ => return false,
                }
            }
            '.' if !saw_dot && !saw_exp => {
                saw_dot = true;
                chars.next();
                // dot must be followed by a digit
                match chars.peek() {
                    Some(d) if d.is_ascii_digit() => {}
                    _ => return false,
                }
            }
            'e' | 'E' if saw_digit && !saw_exp => {
                saw_exp = true;
                chars.next();
                if matches!(chars.peek(), Some('+') | Some('-')) {
                    chars.next();
                }
                match chars.peek() {
                    Some(d) if d.is_ascii_digit() => {}
                    _ => return false,
                }
            }
            _ => return false,
        }
    }

    saw_digit
}

// ---------------------------------------------------------------------------
// Timestamp detection
// ---------------------------------------------------------------------------

pub(crate) const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];
const WEEKDAYS: [&str; 7] = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];

/// Attempts to match a timestamp at the start of `s`, returning the byte
/// length of the match if successful.
///
/// Recognized forms (matching the reference tokenizer):
/// * Syslog: `[Wkd ]Mon DD HH:MM:SS[ YYYY]`
/// * ISO 8601: `YYYY-MM-DDTHH:MM:SS[.fff][Z|±HHMM]`
/// * ISO-like with space: `YYYY-MM-DD HH:MM:SS[,.fff]`
/// * CLF: `DD/Mon/YYYY:HH:MM:SS ±HHMM`
fn match_timestamp(s: &str) -> Option<usize> {
    match_iso(s)
        .or_else(|| match_clf(s))
        .or_else(|| match_syslog(s))
}

fn is_digits(s: &str, n: usize) -> bool {
    s.len() >= n && s.as_bytes()[..n].iter().all(u8::is_ascii_digit)
}

/// `HH:MM:SS` -> length consumed (8) or `None`.
fn match_hms(s: &str) -> Option<usize> {
    let b = s.as_bytes();
    if b.len() >= 8
        && b[0].is_ascii_digit()
        && b[1].is_ascii_digit()
        && b[2] == b':'
        && b[3].is_ascii_digit()
        && b[4].is_ascii_digit()
        && b[5] == b':'
        && b[6].is_ascii_digit()
        && b[7].is_ascii_digit()
    {
        Some(8)
    } else {
        None
    }
}

/// ISO 8601: `YYYY-MM-DD` then `T` or space, then `HH:MM:SS`, optional
/// fractional `.fff` / `,fff`, optional zone `Z` or `±HHMM` / `±HH:MM`.
fn match_iso(s: &str) -> Option<usize> {
    let b = s.as_bytes();
    if !(is_digits(s, 4) && b.len() > 10 && b[4] == b'-' && b[7] == b'-') {
        return None;
    }
    if !(b[5].is_ascii_digit()
        && b[6].is_ascii_digit()
        && b[8].is_ascii_digit()
        && b[9].is_ascii_digit())
    {
        return None;
    }
    let sep = b[10];
    if sep != b'T' && sep != b' ' {
        return None;
    }
    let mut i = 11;
    i += match_hms(&s[i..])?;
    // fractional seconds
    if i < b.len() && (b[i] == b'.' || b[i] == b',') {
        let mut j = i + 1;
        while j < b.len() && b[j].is_ascii_digit() {
            j += 1;
        }
        if j > i + 1 {
            i = j;
        }
    }
    // timezone
    if i < b.len() {
        match b[i] {
            b'Z' => i += 1,
            b'+' | b'-' => {
                let mut j = i + 1;
                let mut digits = 0;
                while j < b.len() && (b[j].is_ascii_digit() || b[j] == b':') {
                    if b[j].is_ascii_digit() {
                        digits += 1;
                    }
                    j += 1;
                }
                if digits >= 2 {
                    i = j;
                }
            }
            _ => {}
        }
    }
    Some(i)
}

/// CLF: `DD/Mon/YYYY:HH:MM:SS ±HHMM`.
fn match_clf(s: &str) -> Option<usize> {
    let b = s.as_bytes();
    // DD/
    if !(b.len() > 3 && b[0].is_ascii_digit() && b[1].is_ascii_digit() && b[2] == b'/') {
        return None;
    }
    let rest = &s[3..];
    let mon = rest.get(..3)?;
    if !MONTHS.contains(&mon) {
        return None;
    }
    let b2 = rest.as_bytes();
    if !(b2.len() > 9 && b2[3] == b'/' && is_digits(&rest[4..], 4) && b2[8] == b':') {
        return None;
    }
    // HH:MM:SS after the colon at index 8
    let mut i = 3 + 9; // up to and including ':'
    i += match_hms(&s[i..])?;
    // optional " ±HHMM"
    let tail = &s[i..];
    let tb = tail.as_bytes();
    if tb.len() >= 6 && tb[0] == b' ' && (tb[1] == b'+' || tb[1] == b'-') {
        let mut digits = 0;
        let mut j = 2;
        while j < tb.len() && tb[j].is_ascii_digit() {
            digits += 1;
            j += 1;
        }
        if digits >= 4 {
            i += j;
        }
    }
    Some(i)
}

/// Syslog: optional `Wkd[,] `, then `Mon DD HH:MM:SS`, optional ` YYYY`.
fn match_syslog(s: &str) -> Option<usize> {
    let mut i = 0;
    // optional weekday, possibly followed by a comma
    if let Some(w) = s.get(..3) {
        if WEEKDAYS.contains(&w) {
            let after = &s[3..];
            if after.starts_with(' ') {
                i = 4;
            } else if after.starts_with(", ") {
                // "Mon, 23 Jan ..." is NOT matched as a single timestamp by the
                // reference tokenizer, so bail out here.
                return None;
            }
        }
    }
    let rest = &s[i..];
    let mon = rest.get(..3)?;
    if !MONTHS.contains(&mon) {
        return None;
    }
    let after_mon = rest.as_bytes();
    // " D" or "  D" or " DD"
    let mut j = 3;
    if after_mon.get(j) != Some(&b' ') {
        return None;
    }
    while after_mon.get(j) == Some(&b' ') {
        j += 1;
    }
    let day_start = j;
    while after_mon.get(j).is_some_and(u8::is_ascii_digit) {
        j += 1;
    }
    let day_len = j - day_start;
    if !(1..=2).contains(&day_len) {
        return None;
    }
    if after_mon.get(j) != Some(&b' ') {
        return None;
    }
    j += 1;
    let hms = match_hms(&rest[j..])?;
    j += hms;
    let mut total = i + j;
    // optional " YYYY"
    let tail = &s[total..];
    let tb = tail.as_bytes();
    if tb.first() == Some(&b' ') && is_digits(&tail[1..], 4) {
        // ensure not part of a longer number
        let after = tail.as_bytes().get(5);
        if after.map_or(true, |c| !c.is_ascii_digit()) {
            total += 5;
        }
    }
    Some(total)
}

// ---------------------------------------------------------------------------
// Structure tokenizer
// ---------------------------------------------------------------------------

fn tokenize_structure(line: &str) -> Vec<Token> {
    let line = line.trim_matches(|c: char| c == '\n' || c == '\r');
    let mut tokens = Vec::new();
    tokenize_structure_into(line, &mut tokens);
    // Resolve key/value: a literal immediately followed by '=' becomes a key.
    promote_keys(&mut tokens);
    tokens
}

fn tokenize_structure_into(line: &str, tokens: &mut Vec<Token>) {
    let bytes = line.as_bytes();
    let mut i = 0;
    let n = bytes.len();
    let mut array_depth = 0usize;

    while i < n {
        let c = line[i..].chars().next().unwrap();

        // 1) Timestamp (highest priority, multi-token span).
        if let Some(len) = match_timestamp(&line[i..]) {
            tokens.push(Token::new(TokenType::Timestamp, &line[i..i + len]));
            i += len;
            continue;
        }

        // 2) Whitespace run -> single delimiter token.
        if c.is_whitespace() {
            let start = i;
            while i < n && line[i..].chars().next().unwrap().is_whitespace() {
                i += line[i..].chars().next().unwrap().len_utf8();
            }
            tokens.push(Token::delimiter(&line[start..i]));
            continue;
        }

        // 3) Quoted string: opening quote is a delimiter, contents are
        //    tokenized recursively (so numbers/timestamps inside quotes stay
        //    dynamic), closing quote a delimiter. A JSON key (`"k":`) stays one
        //    literal so `promote_keys` can see it. An apostrophe inside a word
        //    (`can't`) or an unclosed quote is just a delimiter.
        let at_word_start = i == 0 || !is_word_char(line[..i].chars().next_back().unwrap());
        if c == '"' || (c == '\'' && at_word_start) {
            if let Some(len) = line[i + 1..].find(c) {
                let (start, end) = (i + 1, i + 1 + len);
                tokens.push(Token::delimiter(&line[i..start]));
                let content = &line[start..end];
                if line[end + 1..].starts_with(':') && !content.is_empty() {
                    tokens.push(Token::literal(content));
                } else {
                    tokenize_structure_into(content, tokens);
                }
                tokens.push(Token::delimiter(&line[end..end + 1]));
                i = end + 1;
                continue;
            }
        }

        // 4) Word run (letters, digits and inner word punctuation), or a
        //    signed number beginning with '+' or '-'.
        let signed_number = (c == '+' || c == '-')
            && line[i + c.len_utf8()..]
                .chars()
                .next()
                .is_some_and(|d| d.is_ascii_digit());
        if is_word_char(c) || signed_number {
            let start = i;
            if signed_number {
                i += c.len_utf8();
            }
            i += consume_word(&line[i..], array_depth == 0);
            let word = &line[start..i];
            let ty = classify_word(word);
            tokens.push(Token::new(ty, word));
            continue;
        }

        // Quoted contents recurse with their own bracket context.
        match c {
            '[' => array_depth += 1,
            ']' => array_depth = array_depth.saturating_sub(1),
            _ => {}
        }

        // 5) Any other single character is a delimiter.
        let clen = c.len_utf8();
        tokens.push(Token::delimiter(&line[i..i + clen]));
        i += clen;
    }
}

/// Consumes a word, preserving URL queries and host ports as part of the value.
fn consume_word(s: &str, grouped_numbers: bool) -> usize {
    if s.starts_with("https://") || s.starts_with("http://") {
        return s
            .find(|c: char| {
                c.is_whitespace() || matches!(c, '\'' | '"' | '<' | '>' | ')' | ']' | '}')
            })
            .unwrap_or(s.len());
    }

    if let Some(len) = email_length(s) {
        return len;
    }

    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let c = s[i..].chars().next().unwrap();
        if is_word_char(c) {
            i += c.len_utf8();
        } else if c == ','
            && grouped_numbers
            && i > 0
            && bytes[i - 1].is_ascii_digit()
            && bytes
                .get(i + 1..i + 4)
                .is_some_and(|group| group.iter().all(u8::is_ascii_digit))
            && !bytes.get(i + 4).is_some_and(u8::is_ascii_digit)
        {
            i += 1;
        } else {
            break;
        }
    }

    // Bare labels and times retain their structure; only dotted hosts absorb a port.
    let host = &s[..i];
    if bytes.get(i) == Some(&b':')
        && host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
        && host.contains('.')
        && host.split('.').all(|label| !label.is_empty())
    {
        let port_len = bytes[i + 1..]
            .iter()
            .take_while(|b| b.is_ascii_digit())
            .count();
        let end = i + 1 + port_len;
        if port_len > 0 && s[end..].chars().next().map_or(true, |c| !is_word_char(c)) {
            return end;
        }
    }
    i
}

/// Recognizes an unquoted email address without changing ordinary plus-separated words.
fn email_length(s: &str) -> Option<usize> {
    // Bound lookahead by the email length limit, including for malformed plus-heavy input.
    let len = s
        .bytes()
        .take(255)
        .take_while(|b| {
            b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'%' | b'+' | b'-' | b'@')
        })
        .count();
    if len > 254 || s[len..].chars().next().is_some_and(is_word_char) {
        return None;
    }
    let (local, domain) = s[..len].split_once('@')?;
    if local.is_empty() || domain.is_empty() || domain.contains('@') {
        return None;
    }
    Some(len)
}

/// Classifies a completed word token.
fn classify_word(word: &str) -> TokenType {
    if is_number(word) {
        TokenType::Number
    } else {
        TokenType::Literal
    }
}

/// Promotes `literal '='` (and JSON `"key":`) patterns to [`TokenType::JsonKey`].
///
/// A bare word that is a simple identifier (`[A-Za-z0-9_]+`) directly followed
/// by `=` *and* a non-whitespace value becomes a key. Inside a quoted JSON
/// context `"key":` the quoted literal preceding a colon becomes a key.
fn promote_keys(tokens: &mut [Token]) {
    for idx in 0..tokens.len() {
        if tokens[idx].ty != TokenType::Literal {
            continue;
        }
        // key=value : next token is '=' delimiter (no whitespace), followed by
        // a non-whitespace value token, and the key is a simple identifier.
        if is_simple_identifier(&tokens[idx].text) {
            if let Some(next) = tokens.get(idx + 1) {
                if next.ty == TokenType::Delimiter && next.text == "=" {
                    let has_value = tokens
                        .get(idx + 2)
                        .is_some_and(|t| !t.text.chars().all(char::is_whitespace));
                    if has_value {
                        tokens[idx].ty = TokenType::JsonKey;
                        continue;
                    }
                }
            }
        }
        // JSON "key": pattern -> prev is `"`, next is `"` then `:`
        if idx >= 1 && tokens[idx - 1].ty == TokenType::Delimiter && tokens[idx - 1].text == "\"" {
            if let (Some(q), Some(colon)) = (tokens.get(idx + 1), tokens.get(idx + 2)) {
                if q.ty == TokenType::Delimiter
                    && q.text == "\""
                    && colon.ty == TokenType::Delimiter
                    && colon.text == ":"
                {
                    tokens[idx].ty = TokenType::JsonKey;
                }
            }
        }
    }
}

/// Whether `s` is a simple identifier: a non-empty run of ASCII alphanumerics
/// and underscores. Such tokens are eligible to be `key=value` keys.
fn is_simple_identifier(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(line: &str) -> String {
        tokenize(line)
            .iter()
            .map(Token::to_string)
            .collect::<Vec<_>>()
            .join(" ")
    }

    #[test]
    fn host_port_is_one_parameter() {
        let tokens = tokenize("alpha.example:8080");
        assert_eq!(tokens.len(), 1);
        assert!(tokens[0].is_parameter());
    }

    #[test]
    fn email_is_a_parameter() {
        assert!(tokenize("alice@example.org")[0].is_parameter());
    }

    #[test]
    fn long_hex_is_a_parameter_not_a_word() {
        assert!(tokenize("abcdefabcdefabcdef")[0].is_parameter());
        assert!(tokenize("decade")[0].is_structural());
    }

    #[test]
    fn url_query_is_one_parameter() {
        let tokens = tokenize("https://example.org/path?q=word&lang=en");
        assert_eq!(tokens.len(), 1);
        assert!(tokens[0].is_parameter());
    }

    #[test]
    fn comma_lists_do_not_become_grouped_numbers() {
        assert_eq!(
            s("[1,2,3,4]"),
            "1{[} 5{1} 1{,} 5{2} 1{,} 5{3} 1{,} 5{4} 1{]}"
        );
        assert_eq!(s("1,2345"), "5{1} 1{,} 5{2345}");
    }

    #[test]
    fn grouped_number_is_one_parameter() {
        assert_eq!(s("1,234,567"), "5{1,234,567}");
    }

    #[test]
    fn numbers() {
        assert!(is_number("42"));
        assert!(is_number("-42"));
        assert!(is_number("3.14"));
        assert!(is_number("1e10"));
        assert!(is_number("0xFF"));
        assert!(is_number("42c")); // hex
        assert!(is_number("1,234"));
        assert!(!is_number("5GB"));
        assert!(!is_number("4ever"));
        assert!(!is_number("1.2.3"));
        assert!(!is_number("-.5"));
        assert!(!is_number("v1"));
    }

    #[test]
    fn timestamps() {
        assert_eq!(s("Jan 23 10:23:45 host"), "2{Jan 23 10:23:45} 1{ } 0{host}");
        assert_eq!(
            s("2020-11-12T15:45:54+0000 x"),
            "2{2020-11-12T15:45:54+0000} 1{ } 0{x}"
        );
        // bare time is not a timestamp
        assert_eq!(s("10:23:45"), "5{10} 1{:} 5{23} 1{:} 5{45}");
    }

    #[test]
    fn key_value() {
        assert_eq!(s("k=v"), "7{k} 1{=} 0{v}");
        assert_eq!(s("n=3"), "7{n} 1{=} 5{3}");
        assert_eq!(s("k:v"), "0{k} 1{:} 0{v}");
    }

    #[test]
    fn words_keep_inner_punct() {
        assert_eq!(s("a.b-c_d/e"), "0{a.b-c_d/e}");
    }

    #[test]
    fn whitespace_runs_merge() {
        assert_eq!(s("a   b"), "0{a} 1{   } 0{b}");
    }

    #[test]
    fn quotes() {
        // contents are tokenized, so dynamic values inside quotes stay dynamic
        assert_eq!(
            s("msg=\"took 5 ms\""),
            "7{msg} 1{=} 1{\"} 0{took} 1{ } 5{5} 1{ } 0{ms} 1{\"}"
        );
        assert_eq!(
            s(r#"{"ts":"2020-11-12T15:45:54Z"}"#),
            r#"1{{} 1{"} 7{ts} 1{"} 1{:} 1{"} 2{2020-11-12T15:45:54Z} 1{"} 1{}}"#
        );
        // a key with spaces stays one key
        assert_eq!(s(r#""a b":1"#), r#"1{"} 7{a b} 1{"} 1{:} 5{1}"#);
        // apostrophes inside words are not quotes
        assert_eq!(s("user's id=5"), "0{user} 1{'} 0{s} 1{ } 7{id} 1{=} 5{5}");
        assert_eq!(s("'single'"), "1{'} 0{single} 1{'}");
        // an unclosed quote does not swallow the rest of the line
        assert_eq!(
            s("msg=\"open id=7"),
            "7{msg} 1{=} 1{\"} 0{open} 1{ } 7{id} 1{=} 5{7}"
        );
        assert_eq!(s("\"\""), "1{\"} 1{\"}");
        assert_eq!(s("\"\":"), "1{\"} 1{\"} 1{:}");
        // control characters inside quotes are kept (the line is only trimmed
        // at its ends)
        let quoted_cr = tokenize("x \"a\r\" y");
        assert_eq!(
            quoted_cr
                .iter()
                .map(|t| t.text.as_str())
                .collect::<String>(),
            "x \"a\r\" y"
        );
    }
}
