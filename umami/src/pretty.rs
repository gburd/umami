//! Pretty-printers that render a token sequence in several formats
//! (`test`, `colors`, `params`, `delimiters`, `static`).
//!
//! All formats are stable so that output can be diffed against golden corpora.

use crate::token::{Token, TokenType};
use std::fmt::Write;

/// The available pretty-printer styles.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Pretty {
    /// `T{text}` tokens joined by spaces, where `T` is the numeric type.
    #[default]
    Test,
    /// The original line, optionally colorized by token type.
    Colors,
    /// The line with a `^~~~` marker row underneath marking each token.
    Params,
    /// The line with a `^` marker row underneath marking each delimiter.
    Delimiters,
    /// The structural tokens (literals/keys) joined by spaces.
    Static,
}

impl Pretty {
    /// Parses a printer name (`test`, `colors`, `params`, `delimiters`,
    /// `static`).
    pub fn from_name(name: &str) -> Option<Self> {
        Some(match name {
            "test" => Self::Test,
            "colors" => Self::Colors,
            "params" => Self::Params,
            "delimiters" => Self::Delimiters,
            "static" => Self::Static,
            _ => return None,
        })
    }

    /// Renders `tokens` in this style. `color` enables ANSI coloring for the
    /// [`Pretty::Colors`] style.
    pub fn render(self, tokens: &[Token], color: bool) -> String {
        match self {
            Pretty::Test => render_test(tokens),
            Pretty::Colors => render_colors(tokens, color),
            Pretty::Params => render_markers(tokens, false),
            Pretty::Delimiters => render_markers(tokens, true),
            Pretty::Static => render_static(tokens),
        }
    }
}

fn render_test(tokens: &[Token]) -> String {
    tokens
        .iter()
        .map(Token::to_string)
        .collect::<Vec<_>>()
        .join(" ")
}

fn render_static(tokens: &[Token]) -> String {
    let mut out = String::new();
    for t in tokens.iter().filter(|t| t.ty.is_structural()) {
        out.push_str(&t.text);
        out.push(' ');
    }
    out
}

/// ANSI color codes per token type (matching the reference palette).
fn color_code(ty: TokenType) -> &'static str {
    match ty {
        TokenType::Literal => "\x1b[37m",   // white
        TokenType::Delimiter => "\x1b[36m", // cyan
        TokenType::Timestamp => "\x1b[35m", // magenta
        TokenType::Ipv4 => "\x1b[32m",      // green
        TokenType::Quoted => "\x1b[33m",    // yellow
        TokenType::Number => "\x1b[94m",    // bright blue
        TokenType::Json => "\x1b[35m",      // magenta
        TokenType::JsonKey => "\x1b[93m",   // bright yellow
    }
}

const RESET: &str = "\x1b[0m";

fn render_colors(tokens: &[Token], color: bool) -> String {
    let mut out = String::new();
    for t in tokens {
        if color {
            let _ = write!(out, "{}{}{}", color_code(t.ty), t.text, RESET);
        } else {
            out.push_str(&t.text);
        }
    }
    out
}

/// Renders the original line plus a marker row. When `delimiters_only` is true
/// only delimiter tokens are marked (with a single `^` under their first
/// column); otherwise every non-delimiter token is marked with `^` followed by
/// `~` across its width.
fn render_markers(tokens: &[Token], delimiters_only: bool) -> String {
    let mut line = String::new();
    let mut marks = String::new();
    for t in tokens {
        let width = t.text.chars().count();
        line.push_str(&t.text);
        if delimiters_only {
            if t.ty == TokenType::Delimiter {
                marks.push('^');
                for _ in 1..width {
                    marks.push(' ');
                }
            } else {
                for _ in 0..width {
                    marks.push(' ');
                }
            }
        } else if t.ty == TokenType::Delimiter {
            for _ in 0..width {
                marks.push(' ');
            }
        } else {
            marks.push('^');
            for _ in 1..width {
                marks.push('~');
            }
        }
    }
    format!("{line}\n{marks}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tokenize;

    #[test]
    fn test_printer_matches_reference_form() {
        let toks = tokenize("user=alice from 10.0.0.1 id 42");
        assert_eq!(
            Pretty::Test.render(&toks, false),
            "7{user} 1{=} 0{alice} 1{ } 0{from} 1{ } 0{10.0.0.1} 1{ } 0{id} 1{ } 5{42}"
        );
    }

    #[test]
    fn static_drops_dynamic_and_delimiters() {
        let toks = tokenize("user=alice from 10.0.0.1 id 42");
        assert_eq!(
            Pretty::Static.render(&toks, false),
            "user alice from 10.0.0.1 id "
        );
    }

    #[test]
    fn params_marker_row() {
        let toks = tokenize("user=alice from 10.0.0.1 id 42");
        let out = Pretty::Params.render(&toks, false);
        let (line, marks) = out.split_once('\n').unwrap();
        assert_eq!(line, "user=alice from 10.0.0.1 id 42");
        assert_eq!(marks, "^~~~ ^~~~~ ^~~~ ^~~~~~~~ ^~ ^~");
    }

    #[test]
    fn delimiters_marker_row() {
        let toks = tokenize("user=alice from 10.0.0.1 id 42");
        let out = Pretty::Delimiters.render(&toks, false);
        let (_, marks) = out.split_once('\n').unwrap();
        assert_eq!(marks, "    ^     ^    ^        ^  ^  ");
    }
}
