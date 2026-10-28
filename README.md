# umami

`umami` is a Rust log anomaly-detection toolkit: it learns the *structure* of
streaming log events and surfaces only the new, changed, and anomalous lines,
filtering out the bulk of repetitive, already-seen traffic.

The workspace contains two crates:

| Crate | Purpose |
|---|---|
| [`umami`](umami/) | Reusable library — tokenization, signatures, profiles, detector |
| [`umami-cli`](umami-cli/) | Binary `umami` — five subcommands: tokenize, pipeline, sim, ingest, load |

---

## How the algorithm works

Log anomaly detection proceeds through four stages:

```
raw line
   │
   ▼
[1] Tokenize ──────────────────────────────────────────────────
    Split the line into typed tokens:
       Literal(0), Delimiter(1), Timestamp(2), Ipv4(3),
       Quoted(4), Number(5), Json(6), JsonKey(7)

   │
   ▼
[2] Structure signature ───────────────────────────────────────
    Keep only structural tokens (Literal, JsonKey, Json).
    Hash their text with FNV-1a → a stable 64-bit StructureHash.
    Lines differing only in numbers/timestamps/IPs hash identically.

   │
   ▼
[3] Per-system Profile ────────────────────────────────────────
    Look up (system, hash) in the ProfileStore.
    Track: event count, first/last seen, per-position parameter
    values (distinct, capped at 100), inter-arrival statistics
    (Welford online mean/variance for z-score).

   │
   ▼
[4] Classify ──────────────────────────────────────────────────
    never_before_seen  — hash not in any system's store
    new_in_system      — hash seen elsewhere, not here
    parameter_change   — known structure, new parameter value
    frequency_spike    — arrival rate >> learned baseline (z-score)
    event_stop         — periodic structure gone silent
    system_away        — system stopped reporting entirely
    (none)             — matches learned-normal → filtered out
```

### Tokenizers

Two tokenizer variants are available:

* **`structure`** (default): The modern structural tokenizer. Understands
  `key=value` pairs (promoting the key to `JsonKey`), quoted strings, and
  nested JSON contexts. Keys in `"key": value` JSON pairs are also promoted.
* **`legacy`**: A whitespace-oriented tokenizer. Splits primarily on
  whitespace, peels leading/trailing punctuation from each chunk, and recognizes
  IPv4 addresses. ISO 8601 timestamps are not recognized (only syslog and CLF forms).

Both tokenizers are validated **byte-for-byte** against a 400-line realistic
corpus and 500k lines of synthetic data, and sustain well over a million lines
per second.

---

## Build and install

**Requirements:** Rust 1.74 or later for the library, 1.85 or later for the CLI.

```sh
git clone https://codeberg.org/gregburd/umami
cd umami
cargo build --release
# Binary is at target/release/umami
```

Run all tests (including golden corpus tests):

```sh
cargo test --workspace
```

Run the criterion benchmarks:

```sh
cargo bench
```

---

## Library quick-start

Add to `Cargo.toml`:

```toml
[dependencies]
umami = "0.1"
```

### Anomaly detection

```rust
use umami::{Detector, AnomalyKind};

let mut det = Detector::new();

// First time a structure is seen → NeverBeforeSeen
let a = det.observe("web01", "GET /health status 200", 0).unwrap();
assert_eq!(a.kind, AnomalyKind::NeverBeforeSeen);

// Same structure, different dynamic value (200 vs 204) → filtered out
let b = det.observe("web01", "GET /health status 204", 1);
assert!(b.is_none());

// Same structure on a new system → NewInSystem
let c = det.observe("web02", "GET /health status 200", 2).unwrap();
assert_eq!(c.kind, AnomalyKind::NewInSystem);
```

### Direct tokenization

```rust
use umami::{tokenize, TokenType};

let tokens = tokenize("Jan 23 10:23:45 web01 sshd[1234]: Accepted from 10.0.0.1");
assert_eq!(tokens[0].ty, TokenType::Timestamp);   // "Jan 23 10:23:45"
assert!(tokens.iter().any(|t| t.ty == TokenType::Number && t.text == "1234"));

// Key/value promotion
let kv = tokenize("duration=3.14 status=ok");
assert_eq!(kv[0].ty, TokenType::JsonKey);  // "duration" → key
assert_eq!(kv[2].ty, TokenType::Number);   // "3.14" → number
assert_eq!(kv[4].ty, TokenType::JsonKey);  // "status" → key
assert_eq!(kv[6].ty, TokenType::Literal);  // "ok" → literal (not a number)
```

### Structure signatures

```rust
use umami::{tokenize, signature::{structure_signature, structure_string}};

let a = structure_signature(&tokenize("request id=1 took 3 ms"));
let b = structure_signature(&tokenize("request id=999 took 7 ms"));
assert_eq!(a, b);  // dynamic values don't affect the hash

let s = structure_string(&tokenize("Jan 23 10:23:45 sshd failed root 22"));
// Timestamps and numbers are dropped; literals remain:
assert!(!s.contains("10:23:45"));
assert!(s.contains("sshd"));
```

---

## CLI usage

```
umami <SUBCOMMAND> [OPTIONS] [ARGS...]
```

### `tokenize` — inspect tokenization

```sh
# Tokenize one line (default: structure tokenizer, test printer)
umami tokenize "Jan 23 10:23:45 web01 sshd[1234]: ok"

# Show which tokens are parameters (dynamic values)
umami tokenize --pretty params "Jan 23 10:23:45 web01 sshd[1234]: ok"

# Use the legacy tokenizer, colorized
umami tokenize --tokenizer legacy --pretty colors --color "Jan 23 10:23:45 web01"

# Read from stdin
journalctl -n 100 | umami tokenize --pretty static

# Run against a golden test file; report mismatches
umami tokenize --test corpus/structure.tsv

# Fix mismatches in-place
umami tokenize --test corpus/structure.tsv --fix
```

**Options:**

| Flag | Default | Description |
|---|---|---|
| `--tokenizer structure\|legacy` | `structure` | Tokenizer variant |
| `--pretty test\|colors\|params\|delimiters\|static` | `test` | Output format |
| `--color` | off | ANSI colorize (colors printer only) |
| `--test FILE` | — | Run golden test file |
| `--fix` | off | Rewrite test file with current output |
| `--verbose` | off | Print passing cases too |

Pretty-printer formats:

* `test` — `T{text}` tokens joined by spaces
* `colors` — original line with ANSI token-type coloring
* `params` — original line + `^~~~` markers under each dynamic token
* `delimiters` — original line + `^` markers under each delimiter
* `static` — structural tokens joined by spaces (the structure signature text)

---

### `pipeline` — filter a log stream

Reads lines from stdin, runs them through the detector, and prints only anomalous
lines (or all lines with `--show-all`).

```sh
# Filter a log file, show only anomalous lines
cat syslog | umami pipeline --system web01

# Show all lines with their classification
cat syslog | umami pipeline --system web01 --show-all

# Also detect parameter changes (new values on known structures)
cat syslog | umami pipeline --parameters
```

**Options:**

| Flag | Default | Description |
|---|---|---|
| `--system NAME` | `stdin` | System name attributed to events |
| `--tokenizer structure\|legacy` | `structure` | Tokenizer variant |
| `--parameters` | off | Emit parameter-change anomalies |
| `--show-all` | off | Print every line with its classification |

Each anomalous output line is prefixed with the kind (e.g. `never_before_seen`),
padded to 18 characters, followed by the original line.

---

### `sim` — summarize anomaly counts

Like `pipeline` but consumes the entire stream and prints a summary table rather
than individual lines.

```sh
cat syslog | umami sim --system web01
```

Example output:
```
events:    10000
anomalies: 47
reduction: 99.5%
profiles:  312
  never_before_seen  31
  new_in_system      12
  parameter_change   4
```

**Options:** `--system`, `--tokenizer`, `--parameters` (same as `pipeline`).

---

### `ingest` — structured JSON output

Emits one JSON object per anomalous event, suitable for piping to a log aggregator
or storage system.

```sh
# Single system
cat syslog | umami ingest --system web01

# Multi-system: input lines are "system<TAB>logline"
paste -d'\t' <(echo -e "web01\nweb02") <(echo -e "disk full\ndisk full") \
  | umami ingest --tagged
```

Each output line is a JSON object:
```json
{"system":"web01","kind":"never_before_seen","score":1.00,"signature":"disk full on","line":"disk full on /dev/sda1"}
```

**Options:** `--system`, `--tagged`, `--tokenizer`, `--parameters`.

---

### `load` — throughput benchmark

Measures how fast the detector processes events. Generates synthetic data by default.

```sh
# Benchmark with 1M synthetic events
umami load

# Benchmark with 500k events
umami load --count 500000

# Benchmark against real data from stdin
cat syslog | umami load --stdin
```

Example output:
```
processed 1000000 events in 0.621s
throughput 1610305 events/sec
anomalies  62
```

**Options:** `--count N` (default 1 000 000), `--tokenizer`, `--stdin`.

---

## Corpus / golden tests

The `corpus/` directory contains TSV files used as golden test fixtures:

| File | Tokenizer | Lines |
|---|---|---|
| `corpus/inputs.txt` | — | Raw input lines (shared) |
| `corpus/structure.tsv` | `structure` | `input<TAB>expected` pairs |
| `corpus/legacy.tsv` | `legacy` | `input<TAB>expected` pairs |

The `expected` column is the `test` pretty-printer output (`T{text}` format).
The integration test in `umami/tests/corpus.rs` loads both TSV files and asserts
≥ 99% match rate for `structure` and ≥ 90% for `legacy`. Known deviations
(deeply nested JSON past the scanner depth limit, certain bare-date edge cases)
are documented in the test.

The corpus is regenerated by capturing the `tokenize` output for each input line:

```sh
umami tokenize --pretty test --tokenizer structure < corpus/inputs.txt \
  | paste corpus/inputs.txt - > corpus/structure.tsv

umami tokenize --pretty test --tokenizer legacy < corpus/inputs.txt \
  | paste corpus/inputs.txt - > corpus/legacy.tsv
```

---

## Performance

Benchmarked with Criterion on 500 000 semi-realistic log lines (mixed syslog,
JSON, HTTP access, key=value formats):

| | Events/sec |
|---|---|
| `umami` (structure tokenizer) | ~1 600 000 |
| `umami` (legacy tokenizer) | ~1 550 000 |

The detector sustains roughly 775 000 events/sec end-to-end (tokenize +
signature + profile update + classify) on synthetic data.

---

## License

Licensed under either of:

* Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or
  <http://www.apache.org/licenses/LICENSE-2.0>)
* MIT license ([LICENSE-MIT](LICENSE-MIT) or <http://opensource.org/licenses/MIT>)

at your option.
