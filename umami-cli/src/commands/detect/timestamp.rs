//! Explicit strftime prefix parsing and token normalization.

use chrono::format::{parse_and_remainder, Fixed, Item, Numeric, Parsed, StrftimeItems};
use umami::{Token, TokenType, Tokenizer};

pub(super) struct TimestampFormat {
    items: Vec<Item<'static>>,
}

impl TimestampFormat {
    /// Validates the format before input or saved state can be changed.
    pub fn new(format: &str) -> Result<Self, String> {
        let items = StrftimeItems::new(format)
            .parse_to_owned()
            .map_err(|e| format!("--time-format: {e}"))?;
        let year = items.iter().any(|item| {
            matches!(
                item,
                Item::Numeric(Numeric::Year | Numeric::IsoYear, _) | Item::Fixed(Fixed::RFC3339)
            )
        });
        if !year {
            return Err("--time-format requires an explicit full year (%Y or %G)".into());
        }
        if items
            .iter()
            .any(|item| matches!(item, Item::Fixed(Fixed::TimezoneName)))
        {
            return Err("--time-format: use a numeric timezone offset, not %Z".into());
        }
        Ok(Self { items })
    }

    /// Parses only the first physical line, preserving the consumed prefix as one token.
    pub fn tokenize(&self, line: &str, tokenizer: Tokenizer) -> Result<(Vec<Token>, i64), String> {
        let first = line.split('\n').next().unwrap_or(line);
        let mut parsed = Parsed::new();
        let rest = parse_and_remainder(&mut parsed, first, self.items.iter())
            .map_err(|e| format!("--time-format mismatch: {e}"))?;
        if parsed.offset.is_none() {
            parsed
                .set_offset(0)
                .map_err(|e| format!("--time-format: {e}"))?;
        }
        let time = parsed
            .to_datetime()
            .map_err(|e| format!("--time-format mismatch: {e}"))?
            .timestamp();
        let consumed = first.len() - rest.len();
        let mut tokens = vec![Token::new(TokenType::Timestamp, &line[..consumed])];
        tokens.extend(tokenizer.tokenize(&line[consumed..]));
        Ok((tokens, time))
    }
}
