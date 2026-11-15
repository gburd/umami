//! Converting [`TokenType::Timestamp`] tokens to unix seconds, so the
//! detector can run on the time an event happened rather than the time it was
//! read.
//!
//! ```
//! use umami::{time::event_time, tokenize};
//!
//! let toks = tokenize("2020-11-12T15:45:54+0000 INFO started");
//! assert_eq!(event_time(&toks, 0), Some(1_605_195_954));
//! ```

use crate::token::{Token, TokenType};
use crate::tokenizer::MONTHS;

/// Returns the unix time of the line's header timestamp, if it has one and it
/// parses: the first timestamp token among the first
/// [`HEADER_TOKENS`] non-delimiter tokens. That covers a leading stamp and
/// formats with a short prefix (Apache's `ip - - [date]`), while a date in
/// the message body (`... cert expires 2099-01-01 ...`) is not taken as the
/// event time. `now` (unix seconds) only picks the year for forms that have
/// none; see [`parse_timestamp`].
pub fn event_time(tokens: &[Token], now: i64) -> Option<i64> {
    let t = tokens
        .iter()
        .filter(|t| t.ty != TokenType::Delimiter)
        .take(HEADER_TOKENS)
        .find(|t| t.ty == TokenType::Timestamp)?;
    parse_timestamp(&t.text, now)
}

/// Parses a header timestamp using a previous event as the year anchor.
///
/// Unlike [`event_time`]'s historical bootstrap, continuing yearless input may
/// advance by more than a day.  A backward jump of more than 183 days means
/// New Year rollover; smaller backward jumps remain late events.  Callers must
/// reject real-future results before updating their per-system anchor.
pub fn continuing_event_time(tokens: &[Token], previous: i64) -> Option<i64> {
    let t = tokens
        .iter()
        .filter(|t| t.ty != TokenType::Delimiter)
        .take(HEADER_TOKENS)
        .find(|t| t.ty == TokenType::Timestamp)?;
    parse_iso(&t.text)
        .or_else(|| parse_clf(&t.text))
        .or_else(|| parse_syslog_context(&t.text, previous, true))
}

/// How many leading non-delimiter tokens [`event_time`] searches.
pub const HEADER_TOKENS: usize = 4;

/// Parses a timestamp in one of the forms the tokenizers recognise into unix
/// seconds:
///
/// * ISO 8601: `YYYY-MM-DD[T ]HH:MM:SS[.fff][Z|±HH[:MM]]`
/// * CLF: `DD/Mon/YYYY:HH:MM:SS[ ±HHMM]`
/// * Syslog: `[Wkd ]Mon DD HH:MM:SS[ YYYY]`
///
/// A form without a zone is read as UTC. A syslog timestamp without a year is
/// placed in the latest year (of the year of `now` and the ones either side)
/// that does not put it more than a day after `now`: `Jan 1` read on Dec 31
/// is next year's, and `Mar 1` read in October is this year's, never a
/// future one. Impossible dates (`Feb 30`) are rejected. `now` is clamped to
/// years 0..=9999.
//
// shortcut: zone-less (local time) stamps are read as UTC, so they are offset
// from wall-clock time by the local zone; fine for intervals, wrong for
// absolute times. Take a zone offset parameter if that ever matters.
pub fn parse_timestamp(s: &str, now: i64) -> Option<i64> {
    parse_iso(s)
        .or_else(|| parse_clf(s))
        .or_else(|| parse_syslog(s, now))
}

/// `n` ASCII digits at byte offset `at`, as a number.
fn digits(s: &str, at: usize, n: usize) -> Option<i64> {
    let d = s.get(at..at + n)?;
    if !d.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    d.parse().ok()
}

fn byte_is(s: &str, at: usize, c: u8) -> bool {
    s.as_bytes().get(at) == Some(&c)
}

/// `HH:MM:SS` at `at`, as seconds into the day.
fn hms(s: &str, at: usize) -> Option<i64> {
    if !(byte_is(s, at + 2, b':') && byte_is(s, at + 5, b':')) {
        return None;
    }
    let (h, m, sec) = (
        digits(s, at, 2)?,
        digits(s, at + 3, 2)?,
        digits(s, at + 6, 2)?,
    );
    (h < 24 && m < 60 && sec <= 60).then_some(h * 3600 + m * 60 + sec)
}

fn month(s: &str, at: usize) -> Option<i64> {
    let name = s.get(at..at + 3)?;
    MONTHS.iter().position(|m| *m == name).map(|i| i as i64 + 1)
}

/// Seconds east of UTC for `Z`, `±HH`, `±HHMM` or `±HH:MM`; `None` if `s` is
/// not a zone.
fn zone(s: &str) -> Option<i64> {
    if s == "Z" {
        return Some(0);
    }
    let sign = match s.as_bytes().first()? {
        b'+' => 1,
        b'-' => -1,
        _ => return None,
    };
    let rest = s[1..].replace(':', "");
    let (h, m) = match rest.len() {
        2 => (digits(&rest, 0, 2)?, 0),
        4 => (digits(&rest, 0, 2)?, digits(&rest, 2, 2)?),
        _ => return None,
    };
    Some(sign * (h * 3600 + m * 60))
}

/// Unix seconds for a civil UTC date and seconds into that day, or `None`
/// for a date that does not exist.
fn unix(year: i64, month: i64, day: i64, secs: i64) -> Option<i64> {
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days_in_month = match month {
        2 if leap => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        1..=12 => 31,
        _ => return None,
    };
    if !(1..=days_in_month).contains(&day) {
        return None;
    }
    Some(days_from_civil(year, month, day) * 86_400 + secs)
}

/// Unix time range of years 0..=9999, which `now` is clamped to.
const NOW_RANGE: std::ops::RangeInclusive<i64> = -62_167_219_200..=253_402_300_799;

/// Days since 1970-01-01 (Howard Hinnant's `days_from_civil`).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * ((m + 9) % 12) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// The UTC year containing unix time `t` (Hinnant's `civil_from_days`).
fn year_of(t: i64) -> i64 {
    let z = t.div_euclid(86_400) + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    yoe + era * 400 + i64::from(mp >= 10)
}

fn parse_iso(s: &str) -> Option<i64> {
    if !(byte_is(s, 4, b'-')
        && byte_is(s, 7, b'-')
        && (byte_is(s, 10, b'T') || byte_is(s, 10, b' ')))
    {
        return None;
    }
    let t = unix(
        digits(s, 0, 4)?,
        digits(s, 5, 2)?,
        digits(s, 8, 2)?,
        hms(s, 11)?,
    )?;
    let mut rest = &s[19..];
    if rest.starts_with(['.', ',']) {
        rest = rest[1..].trim_start_matches(|c: char| c.is_ascii_digit());
    }
    let rest = rest.trim_start();
    if rest.is_empty() {
        return Some(t);
    }
    Some(t - zone(rest)?)
}

fn parse_clf(s: &str) -> Option<i64> {
    if !(byte_is(s, 2, b'/') && byte_is(s, 6, b'/') && byte_is(s, 11, b':')) {
        return None;
    }
    let t = unix(
        digits(s, 7, 4)?,
        month(s, 3)?,
        digits(s, 0, 2)?,
        hms(s, 12)?,
    )?;
    let rest = s[20..].trim_start();
    if rest.is_empty() {
        return Some(t);
    }
    Some(t - zone(rest)?)
}

fn parse_syslog(s: &str, now: i64) -> Option<i64> {
    parse_syslog_context(s, now, false)
}

fn parse_syslog_context(s: &str, now: i64, continuing: bool) -> Option<i64> {
    let s = match s.get(3..4) {
        Some(" ") if s.as_bytes()[0].is_ascii_alphabetic() && month(s, 0).is_none() => &s[4..],
        _ => s,
    };
    let mon = month(s, 0)?;
    let rest = s.get(3..)?.trim_start();
    let day_len = rest.bytes().take_while(u8::is_ascii_digit).count();
    if !(1..=2).contains(&day_len) || !byte_is(rest, day_len, b' ') {
        return None;
    }
    let day = digits(rest, 0, day_len)?;
    let secs = hms(rest, day_len + 1)?;
    let tail = rest[day_len + 9..].trim_start();
    if !tail.is_empty() {
        return unix(digits(tail, 0, 4)?, mon, day, secs);
    }
    let now = now.clamp(*NOW_RANGE.start(), *NOW_RANGE.end());
    let year = year_of(now);
    if continuing {
        let candidate = days_from_civil(year, mon, day) * 86_400 + secs;
        return if candidate < now - 183 * 86_400 {
            unix(year + 1, mon, day, secs)
        } else {
            unix(year, mon, day, secs)
        };
    }
    (year - 1..=year + 1)
        .filter_map(|y| unix(y, mon, day, secs))
        .filter(|&t| t <= now + 86_400)
        .max()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tokenizer::Tokenizer;

    // Expected values computed with Python's datetime.
    #[test]
    fn iso() {
        assert_eq!(
            parse_timestamp("2020-11-12T15:45:54+0000", 0),
            Some(1_605_195_954)
        );
        assert_eq!(
            parse_timestamp("2020-11-12T15:45:54Z", 0),
            Some(1_605_195_954)
        );
        assert_eq!(
            parse_timestamp("2020-11-12 15:45:54", 0),
            Some(1_605_195_954)
        );
        assert_eq!(
            parse_timestamp("2020-11-12T15:45:54.123-05:00", 0),
            Some(1_605_213_954)
        );
        assert_eq!(
            parse_timestamp("2020-11-12T15:45:54,5+01", 0),
            Some(1_605_192_354)
        );
        assert_eq!(
            parse_timestamp("2024-02-29 12:00:00", 0),
            Some(1_709_208_000)
        );
        assert_eq!(parse_timestamp("1969-07-20 20:17:40", 0), Some(-14_182_940));
        assert_eq!(parse_timestamp("2020-13-12T15:45:54", 0), None);
        assert_eq!(parse_timestamp("2021-02-29 00:00:00", 0), None);
        assert_eq!(parse_timestamp("2021-04-31 00:00:00", 0), None);
        assert_eq!(parse_timestamp("2020-11-12T25:45:54", 0), None);
    }

    #[test]
    fn clf() {
        assert_eq!(
            parse_timestamp("23/Jan/2020:10:23:45 +0530", 0),
            Some(1_579_755_225)
        );
        assert_eq!(
            parse_timestamp("23/Jan/2020:10:23:45", 0),
            Some(1_579_775_025)
        );
        assert_eq!(parse_timestamp("23/Foo/2020:10:23:45", 0), None);
    }

    #[test]
    fn syslog_year_is_inferred_from_now() {
        let now = 1_590_969_600; // 2020-06-01
        assert_eq!(parse_timestamp("Jan 23 10:23:45", now), Some(1_579_775_025));
        assert_eq!(
            parse_timestamp("Thu Jan 23 10:23:45", now),
            Some(1_579_775_025)
        );
        assert_eq!(
            parse_timestamp("Jan  3 10:23:45", now),
            Some(1_579_775_025 - 20 * 86_400)
        );
        // December, read in January: last year
        assert_eq!(
            parse_timestamp("Dec 31 23:59:59", 1_609_459_210),
            Some(1_609_459_199)
        );
        // January, read in late December (the clock is the previous line's
        // time): next year
        assert_eq!(
            parse_timestamp("Jan  1 00:00:10", 1_609_459_199),
            Some(1_609_459_210)
        );
        // a month long past is this year's, not next year's (replaying an
        // old log while the clock is still the wall clock)
        assert_eq!(
            parse_timestamp("Mar  1 00:00:00", 1_793_232_000), // 2026-10-29
            Some(1_772_323_200)                                // 2026-03-01
        );
        // Feb 29 only exists in leap years; read in 2021 it is 2020's
        assert_eq!(
            parse_timestamp("Feb 29 12:00:00", 1_617_235_200),
            Some(1_582_977_600)
        );
        // extreme `now` does not overflow
        for now in [i64::MIN, i64::MAX] {
            assert!(parse_timestamp("Jan 23 10:23:45", now).is_some());
        }
        // explicit year wins
        assert_eq!(
            parse_timestamp("Jan 23 10:23:45 2020", 0),
            Some(1_579_775_025)
        );
    }

    #[test]
    fn years() {
        assert_eq!(year_of(1_609_459_199), 2020);
        assert_eq!(year_of(1_609_459_200), 2021);
        assert_eq!(year_of(-1), 1969);
        assert_eq!(year_of(1_709_208_000), 2024);
    }

    #[test]
    fn only_a_header_timestamp_is_the_event_time() {
        let at = |s| event_time(&Tokenizer::Structure.tokenize(s), 0);
        assert_eq!(at("[2020-11-12 15:45:54] x"), Some(1_605_195_954));
        assert_eq!(at("cert for host expires 2099-01-01 00:00:00 renew"), None);
        assert_eq!(at(""), None);
    }

    #[test]
    fn every_tokenizer_timestamp_parses() {
        let now = 1_605_195_954;
        for line in [
            "Jan 23 10:23:45 host x",
            "Mon Jan 23 10:23:45 2020 host x",
            "2020-11-12T15:45:54+0000 x",
            "2020-11-12 15:45:54,123 x",
            "1.2.3.4 - - [23/Jan/2020:10:23:45 +0000] \"GET /\"",
        ] {
            let tok = Tokenizer::Structure;
            let toks = tok.tokenize(line);
            let has_ts = toks.iter().any(|t| t.ty == TokenType::Timestamp);
            assert_eq!(has_ts, event_time(&toks, now).is_some(), "{tok:?} {line}");
        }
    }
}

#[cfg(test)]
mod continuing_tests {
    use super::*;
    use crate::tokenizer::Tokenizer;

    #[test]
    fn continuing_year_keeps_small_late_events_and_rolls_over_large_backward_jumps() {
        let at =
            |line, previous| continuing_event_time(&Tokenizer::Structure.tokenize(line), previous);
        let march = 1_583_366_400;
        assert_eq!(at("Mar  1 00:00:00 tick", march), Some(1_583_020_800));
        assert_eq!(at("Apr  2 00:00:00 tick", march), Some(1_585_785_600));
        assert_eq!(
            at("Jan  2 00:00:00 tick", 1_609_459_199),
            Some(1_609_545_600)
        );
        assert_eq!(at("2020-01-01 00:00:00 tick", march), Some(1_577_836_800));
    }
}
