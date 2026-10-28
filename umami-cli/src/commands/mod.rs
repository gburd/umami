//! Subcommand implementations for the `umami` CLI.

pub mod detect;
pub mod load;
pub mod tokenize;

use clap::builder::{PossibleValuesParser, TypedValueParser};
use std::io::{self, BufRead, BufReader, Read};
use umami::{Pretty, Tokenizer};

/// Calls `f(line, more)` for each line of `r` as it arrives (newline and
/// trailing `\r` stripped; invalid UTF-8 replaced, not fatal). `more` is
/// `false` when the next read may block, so a streaming caller should flush
/// its output then.
pub(crate) fn for_each_line(
    r: impl Read,
    mut f: impl FnMut(&str, bool) -> io::Result<()>,
) -> io::Result<()> {
    let mut r = BufReader::new(r);
    let mut buf = Vec::new();
    while r.read_until(b'\n', &mut buf)? > 0 {
        let more = r.buffer().contains(&b'\n');
        f(
            String::from_utf8_lossy(&buf).trim_end_matches(['\n', '\r']),
            more,
        )?;
        buf.clear();
    }
    Ok(())
}

/// Parses `--tokenizer`, listing the choices in `--help` and errors.
pub(crate) fn tokenizer_arg() -> impl TypedValueParser<Value = Tokenizer> {
    PossibleValuesParser::new(["structure", "legacy"]).map(|s| Tokenizer::from_name(&s).unwrap())
}

/// Parses `--pretty`, listing the choices in `--help` and errors.
pub(crate) fn pretty_arg() -> impl TypedValueParser<Value = Pretty> {
    PossibleValuesParser::new(["test", "colors", "params", "delimiters", "static"])
        .map(|s| Pretty::from_name(&s).unwrap())
}
