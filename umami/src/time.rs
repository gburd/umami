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

/// Returns the unix time of the first timestamp token in `tokens`, if it
/// parses. `now` (unix seconds) only picks the year for forms that have none;
/// see [`parse_timestamp`].
pub fn event_time(tokens: &[Token], now: i64) -> Option<i64> {
    let t = tokens.iter().find(|t| t.ty == TokenType::Timestamp)?;
    parse_timestamp(&t.text, now)
}

/// Parses a timestamp in one of the forms the tokenizers recognise into unix
/// seconds:
///
/// * ISO 8601: `YYYY-MM-DD[T ]HH:MM:SS[.fff][Z|±HH[:MM]]`
/// * CLF: `DD/Mon/YYYY:HH:MM:SS[ ±HHMM]`
/// * Syslog: `[Wkd ]Mon DD HH:MM:SS[ YYYY]`
///
/// A form without a zone is read as UTC. A syslog timestamp without a year is
/// placed in the latest year that does not put it more than a day after `now`.
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

/// Unix seconds for a civil UTC date and seconds into that day.
fn unix(year: i64, month: i64, day: i64, secs: i64) -> Option<i64> {
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    Some(days_from_civil(year, month, day) * 86_400 + secs)
}

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
    let year = year_of(now);
    let t = unix(year, mon, day, secs)?;
    if t > now + 86_400 {
        unix(year - 1, mon, day, secs)
    } else {
        Some(t)
    }
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
    fn every_tokenizer_timestamp_parses() {
        let now = 1_605_195_954;
        for line in [
            "Jan 23 10:23:45 host x",
            "Mon Jan 23 10:23:45 2020 host x",
            "2020-11-12T15:45:54+0000 x",
            "2020-11-12 15:45:54,123 x",
            "1.2.3.4 - - [23/Jan/2020:10:23:45 +0000] \"GET /\"",
        ] {
            for tok in [Tokenizer::Structure, Tokenizer::Legacy] {
                let toks = tok.tokenize(line);
                let has_ts = toks.iter().any(|t| t.ty == TokenType::Timestamp);
                assert_eq!(has_ts, event_time(&toks, now).is_some(), "{tok:?} {line}");
            }
        }
    }
}
