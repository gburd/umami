//! The structural log-line tokenizer.
//!
//! This module implements the `structure` and `legacy` tokenizers. Tokenization
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
    /// The original whitespace-oriented tokenizer. Splits primarily on
    /// whitespace, keeping most punctuation attached to adjacent words.
    Legacy,
}

impl Tokenizer {
    /// Parses a tokenizer name (`"structure"` or `"legacy"`).
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "structure" => Some(Self::Structure),
            "legacy" => Some(Self::Legacy),
            _ => None,
        }
    }

    /// Tokenizes a single log line into a sequence of [`Token`]s.
    pub fn tokenize(self, line: &str) -> Vec<Token> {
        match self {
            Tokenizer::Structure => tokenize_structure(line),
            Tokenizer::Legacy => tokenize_legacy(line),
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

const MONTHS: [&str; 12] = [
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

/// Timestamp matcher for the legacy tokenizer, which recognizes only the
/// syslog and CLF forms (not ISO 8601).
fn match_timestamp_legacy(s: &str) -> Option<usize> {
    match_clf(s).or_else(|| match_syslog(s))
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
    match match_hms(&s[i..]) {
        Some(n) => i += n,
        None => return None,
    }
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
    match match_hms(&s[i..]) {
        Some(n) => i += n,
        None => return None,
    }
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
        if after.is_none_or(|c| !c.is_ascii_digit()) {
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
    let mut tokens: Vec<Token> = Vec::new();
    let bytes = line.as_bytes();
    let mut i = 0;
    let n = bytes.len();

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

        // 3) Quoted string: opening quote is a delimiter, contents one token,
        //    closing quote a delimiter.
        if c == '"' || c == '\'' {
            tokens.push(Token::delimiter(&line[i..i + 1]));
            i += 1;
            let start = i;
            while i < n && line[i..].chars().next().unwrap() != c {
                i += line[i..].chars().next().unwrap().len_utf8();
            }
            if i > start {
                tokens.push(Token::new(TokenType::Literal, &line[start..i]));
            }
            if i < n {
                tokens.push(Token::delimiter(&line[i..i + 1]));
                i += 1;
            }
            continue;
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
            i += consume_word(&line[i..]);
            let word = &line[start..i];
            let ty = classify_word(word, &tokens, line, i);
            tokens.push(Token::new(ty, word));
            continue;
        }

        // 5) Any other single character is a delimiter.
        let clen = c.len_utf8();
        tokens.push(Token::delimiter(&line[i..i + clen]));
        i += clen;
    }

    // Resolve key/value: a literal immediately followed by '=' becomes a key.
    promote_keys(&mut tokens);
    tokens
}

/// Consumes a maximal word run, including a single digit-comma-digit group so
/// that thousands-separated numbers like `1,234` stay a single token. Only one
/// comma group is absorbed, matching the reference tokenizer (`1,234,567`
/// becomes `1,234` `,` `567`).
fn consume_word(s: &str) -> usize {
    let bytes = s.as_bytes();
    let mut i = 0;
    let n = bytes.len();
    let mut comma_used = false;
    while i < n {
        let c = s[i..].chars().next().unwrap();
        if is_word_char(c) {
            i += c.len_utf8();
        } else if c == ','
            && !comma_used
            && i > 0
            && bytes[i - 1].is_ascii_digit()
            && bytes.get(i + 1).is_some_and(u8::is_ascii_digit)
        {
            // digit,digit -> keep one comma group inside the word
            comma_used = true;
            i += 1;
        } else {
            break;
        }
    }
    i
}

/// Classifies a completed word token.
fn classify_word(word: &str, _prev: &[Token], _line: &str, _end: usize) -> TokenType {
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

// ---------------------------------------------------------------------------
// Legacy tokenizer
// ---------------------------------------------------------------------------

/// Strict numeric check for the legacy tokenizer: decimal integers and floats
/// with optional `.`, `,` or `:` separators between digit groups (covering
/// thousands groups, times and MAC/colon-separated values), but no sign, no
/// hex and no trailing alphabetic units. Must start and end with a digit and
/// contain no consecutive separators.
fn is_number_legacy(word: &str) -> bool {
    if word.is_empty() {
        return false;
    }
    let bytes = word.as_bytes();
    if !bytes[0].is_ascii_digit() || !bytes[bytes.len() - 1].is_ascii_digit() {
        return false;
    }
    let mut prev_sep = false;
    for &b in bytes {
        match b {
            b'0'..=b'9' => prev_sep = false,
            b'.' | b',' | b':' => {
                if prev_sep {
                    return false;
                }
                prev_sep = true;
            }
            _ => return false,
        }
    }
    true
}

/// The legacy tokenizer splits the line on whitespace into chunks; within each
/// chunk it peels a leading punctuation run (merged with the preceding
/// whitespace into a single delimiter) and a trailing punctuation run, leaving
/// the middle as one word token. Chunks containing a double quote are emitted
/// as a single quoted token up to the closing quote, and only the syslog/CLF
/// timestamp forms are recognized.
fn tokenize_legacy(line: &str) -> Vec<Token> {
    let line = line.trim_matches(|c: char| c == '\n' || c == '\r');
    let mut tokens = Vec::new();
    let n = line.len();
    let mut i = 0;

    while i < n {
        // Leading timestamp (syslog/CLF only).
        if let Some(len) = match_timestamp_legacy(&line[i..]) {
            tokens.push(Token::new(TokenType::Timestamp, &line[i..i + len]));
            i += len;
            continue;
        }

        let c = line[i..].chars().next().unwrap();

        // Whitespace run: a delimiter that also absorbs a following leading
        // punctuation run (the leading punctuation of the next chunk). If a
        // quote is encountered, the delimiter ends just after it and a quoted
        // span is emitted.
        if c.is_whitespace() {
            let start = i;
            while i < n && line[i..].chars().next().unwrap().is_whitespace() {
                i += line[i..].chars().next().unwrap().len_utf8();
            }
            let mut emitted_quote = false;
            while i < n {
                let ch = line[i..].chars().next().unwrap();
                if is_legacy_word_start(ch) || ch.is_whitespace() {
                    break;
                }
                if ch == '"' {
                    if let Some((clen, closer)) = legacy_quote_close(&line[i + 1..]) {
                        tokens.push(Token::delimiter(&line[start..i + 1]));
                        let content_start = i + 1;
                        let content_end = content_start + clen;
                        push_quoted(&mut tokens, &line[content_start..content_end]);
                        match closer {
                            QuoteCloser::Quote => {
                                tokens.push(Token::delimiter("\""));
                                i = content_end + 1;
                            }
                            QuoteCloser::Brace => {
                                tokens.push(Token::delimiter("}"));
                                i = content_end + 1;
                            }
                        }
                        emitted_quote = true;
                    }
                    break;
                }
                i += ch.len_utf8();
            }
            if !emitted_quote {
                tokens.push(Token::delimiter(&line[start..i]));
            }
            continue;
        }

        // A chunk begins here. Find its end (next whitespace), but a quote may
        // extend the span across whitespace.
        let chunk_start = i;
        let mut quoted_close: Option<usize> = None;
        let mut quote_open: Option<usize> = None;
        let mut closer = QuoteCloser::Quote;
        while i < n {
            let ch = line[i..].chars().next().unwrap();
            if ch == '"' {
                if let Some((clen, cl)) = legacy_quote_close(&line[i + 1..]) {
                    quote_open = Some(i);
                    quoted_close = Some(i + 1 + clen);
                    closer = cl;
                    break;
                }
            }
            if ch.is_whitespace() {
                break;
            }
            if i != chunk_start && match_timestamp_legacy(&line[i..]).is_some() {
                break;
            }
            i += ch.len_utf8();
        }

        if let (Some(open), Some(close)) = (quote_open, quoted_close) {
            let prefix = &line[chunk_start..open];
            if !prefix.is_empty() && prefix.chars().all(|c| !is_legacy_word_start(c)) {
                // Punctuation-only prefix (e.g. `{`): merge with the opening
                // quote into a single delimiter, content becomes the quoted
                // token.
                tokens.push(Token::delimiter(&line[chunk_start..open + 1]));
                push_quoted(&mut tokens, &line[open + 1..close]);
            } else {
                // Word prefix (e.g. `msg="`): the prefix and opening quote are
                // part of the quoted token.
                push_quoted(&mut tokens, &line[chunk_start..close]);
            }
            match closer {
                QuoteCloser::Quote => tokens.push(Token::delimiter("\"")),
                QuoteCloser::Brace => tokens.push(Token::delimiter("}")),
            }
            i = close + 1;
            continue;
        }

        let chunk = &line[chunk_start..i];
        emit_legacy_chunk(chunk, &mut tokens);
    }
    tokens
}

/// Pushes a [`TokenType::Quoted`] token, skipping it when the content is empty
/// (preserving the "no empty tokens" invariant on pathological quote input).
fn push_quoted(tokens: &mut Vec<Token>, content: &str) {
    if !content.is_empty() {
        tokens.push(Token::new(TokenType::Quoted, content));
    }
}

/// Locates the end of a legacy quoted span given the text immediately after an
/// opening quote. Returns `(content_len, closer)` where `content_len` is the
/// byte length of the quoted content and `closer` describes the closing
/// delimiter:
///
/// * the span closes at a `"` that is followed by whitespace, `}` or end; or
/// * it closes at a `}` (JSON object end), which itself forms the delimiter.
///
/// Returns `None` for an unterminated quote (the opening quote is then treated
/// literally by the caller).
fn legacy_quote_close(after: &str) -> Option<(usize, QuoteCloser)> {
    let bytes = after.as_bytes();
    let mut j = 0;
    while j < bytes.len() {
        match bytes[j] {
            b'"' => {
                let next = bytes.get(j + 1);
                match next {
                    None => return Some((j, QuoteCloser::Quote)),
                    Some(&b) if (b as char).is_whitespace() || b == b'}' => {
                        return Some((j, QuoteCloser::Quote))
                    }
                    _ => {}
                }
            }
            b'}' => return Some((j, QuoteCloser::Brace)),
            _ => {}
        }
        j += 1;
    }
    None
}

/// How a legacy quoted span is terminated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum QuoteCloser {
    /// Terminated by a closing `"`.
    Quote,
    /// Terminated by a `}` (JSON object end); the `}` is the delimiter.
    Brace,
}

/// Emits the tokens for a single whitespace-delimited legacy chunk that
/// contains no spanning quote.
fn emit_legacy_chunk(chunk: &str, tokens: &mut Vec<Token>) {
    if chunk.is_empty() {
        return;
    }
    // A leading `{"` or `"` with the rest being a quoted span handled above is
    // not expected here; treat any residual quote as a literal character.

    // Peel a leading punctuation run.
    let (leading, body) = split_leading_punct(chunk);
    if !leading.is_empty() {
        tokens.push(Token::delimiter(leading));
    }
    if body.is_empty() {
        return;
    }
    let (word, trailing) = split_trailing_punct(body);
    if !word.is_empty() {
        tokens.push(Token::new(classify_legacy(word), word));
    }
    if !trailing.is_empty() {
        tokens.push(Token::delimiter(trailing));
    }
}

/// Splits a chunk into `(leading_punct, rest)` by peeling a leading run of
/// non-word characters.
fn split_leading_punct(chunk: &str) -> (&str, &str) {
    for (idx, ch) in chunk.char_indices() {
        if is_legacy_word_start(ch) {
            return chunk.split_at(idx);
        }
    }
    // all punctuation
    (chunk, "")
}

/// A character that can begin (and appear within) a legacy word token.
#[inline]
fn is_legacy_word_start(c: char) -> bool {
    c.is_alphanumeric() || (!c.is_ascii() && !c.is_whitespace())
}

/// Splits a chunk into `(word, trailing_punct)` by peeling a trailing run of
/// non-word characters. Punctuation interior to the word is retained.
fn split_trailing_punct(chunk: &str) -> (&str, &str) {
    let mut end = chunk.len();
    for (idx, ch) in chunk.char_indices().rev() {
        if is_legacy_word_start(ch) {
            end = idx + ch.len_utf8();
            break;
        }
        if idx == 0 {
            end = 0;
        }
    }
    chunk.split_at(end)
}

/// Classifies a legacy word: IPv4, number or literal.
fn classify_legacy(word: &str) -> TokenType {
    if is_ipv4(word) {
        TokenType::Ipv4
    } else if is_number_legacy(word) {
        TokenType::Number
    } else {
        TokenType::Literal
    }
}

/// Whether `word` is a dotted-quad IPv4 address.
fn is_ipv4(word: &str) -> bool {
    let mut parts = 0;
    for part in word.split('.') {
        parts += 1;
        if part.is_empty() || part.len() > 3 || !part.bytes().all(|b| b.is_ascii_digit()) {
            return false;
        }
        if part.parse::<u16>().map(|v| v > 255).unwrap_or(true) {
            return false;
        }
    }
    parts == 4
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
}
