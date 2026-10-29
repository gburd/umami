# umami

`umami` is a reusable Rust library for log anomaly detection: it learns the
structure of streaming log events and surfaces only the *new, changed and
anomalous* lines, filtering out the bulk of repetitive, already-seen logs.

## How it works

1. **Tokenization** — each log line is split into a sequence of typed tokens
   (literals, delimiters, numbers, timestamps, quoted strings, JSON keys, …).
   See [`tokenizer`].
2. **Structure signature** — the *static* tokens, plus a placeholder for each
   parameter, are hashed into a stable [`StructureHash`], so that lines
   differing only in their dynamic parts (numbers, timestamps, IPs, words with
   a digit or `/` in them) collapse to the same structure. See [`signature`].
3. **Profiles** — each structure is tracked per system in a [`Profile`] that
   records counts, first/last seen times, per-parameter distinct values and
   inter-arrival statistics. See [`profile`].
4. **Detection** — incoming events are classified as *never before seen*,
   *new in system*, *parameter change* or *frequency spike*, and periodic
   [`Detector::sweep`] calls report *event stop* and *system away*;
   everything else is filtered as normal. See [`detector`] and, for taking
   event time from the line, [`time`].

## Quick start

```rust
use umami::Detector;

let mut detector = Detector::new();

// The first time a structure is seen it is anomalous ...
let first = detector.observe("web01", "GET /health status 200", 0);
assert!(first.is_some());

// ... but a line with the same *structure* (only the dynamic number
// differs) is filtered out as normal.
let repeat = detector.observe("web01", "GET /health status 204", 1);
assert!(repeat.is_none());
```

## Tokenizing directly

```rust
use umami::{tokenize, TokenType};

let tokens = tokenize("Jan 23 10:23:45 web01 sshd[1234]: ok from 10.0.0.1");
assert_eq!(tokens[0].ty, TokenType::Timestamp);
```

## Crate features

The core library has no required dependencies and forbids `unsafe`.

* `serde` (off by default): `Serialize`/`Deserialize` for [`ProfileStore`]
  and the types in it, to save learned state and resume with
  [`Detector::with_store`].

A companion binary crate, `umami-cli`, provides a command-line interface.

## License

Licensed under either of Apache-2.0 or MIT at your option.
