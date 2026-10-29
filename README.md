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

```text
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
    Parameters: numbers, timestamps, IPs, and any word with a digit
    or a '/' in it (web01, ids, paths, URLs). Everything else
    except delimiters is structure.
    Hash structure text + one placeholder per parameter with FNV-1a
    → a stable 64-bit StructureHash. Lines differing only in their
    parameter values hash identically.

   │
   ▼
[3] Per-system Profile ────────────────────────────────────────
    Look up (system, hash) in the ProfileStore.
    Track: event count, first/last seen, values per parameter
    slot (distinct, up to 100; past that the slot is ignored),
    inter-arrival statistics (Welford mean/variance, z-score).

   │
   ▼
[4] Classify ──────────────────────────────────────────────────
    never_before_seen  — hash not in any system's store
    new_in_system      — hash seen elsewhere, not here
    parameter_change   — known structure, new parameter value
    frequency_spike    — arrival rate >> learned baseline (z-score)
    event_stop         — periodic structure silent > 3 intervals
    system_away        — system silent > 10 minutes
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

Both tokenizers are checked against a 419-line golden corpus (`corpus/`): the
structure tokenizer must match every line, and the legacy tokenizer every line
except three listed in `umami/tests/corpus.rs`. The corpus records the
tokenizers' own output, so it catches changes, not mistakes.

### Accuracy

Grouping accuracy on the [LogHub](https://github.com/logpai/loghub) 2k-line
samples (16 datasets with hand-labelled templates; a line counts as correct
when umami groups it with exactly the lines that share its template):

| | structure tokenizer |
|---|---|
| mean over 16 datasets | 0.767 |
| ≥ 0.95 | Apache, BGL, HDFS, Hadoop, HealthApp, Windows, Zookeeper |
| < 0.5 | Linux 0.19, OpenSSH 0.39, Proxifier 0.001 |

The weak datasets vary *words* inside a template (user names, hostnames):
exact hashing can't merge those, a learned-wildcard parser such as Drain can.

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

// Words with digits or slashes are dynamic too: paths, ids, hostnames
assert!(det.observe("web01", "GET /users/42 status 200", 2).is_none()); // same shape as /health
assert!(det.observe("web01", "POST /users/42 status 201", 3).is_some()); // new shape

// Same structure on a new system → NewInSystem
let c = det.observe("web02", "GET /health status 200", 4).unwrap();
assert_eq!(c.kind, AnomalyKind::NewInSystem);

// `now` is unix seconds. Call sweep() regularly to find silences:
// web02 has been quiet for over 10 minutes.
let found = det.sweep(4 + 601);
assert!(found.iter().any(|a| a.system == "web02" && a.kind == AnomalyKind::SystemAway));
```

Use `umami::time::event_time(&tokens, now)` to take `now` from the line's own
timestamp. With the `serde` feature, `ProfileStore` (from `Detector::store()`)
can be saved and passed back to `Detector::with_store` to resume learning.

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
// Timestamps and numbers become <*>; literals remain:
assert_eq!(s, "<*> sshd failed root <*>");
```

---

## CLI usage

```text
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
* `params` — original line + `^~~~` markers under each parameter
* `delimiters` — original line + `^` markers under each delimiter
* `static` — the structure signature: structural tokens joined by spaces,
  `<*>` for each parameter

---

### `pipeline` — filter a log stream

Reads lines from stdin as they arrive, runs them through the detector, and
prints only anomalous lines (or all lines with `--show-all`).

```sh
# Filter a log file, show only anomalous lines
cat syslog | umami pipeline --system web01

# Show all lines with their classification
cat syslog | umami pipeline --system web01 --show-all

# Also detect parameter changes (new values on known structures)
cat syslog | umami pipeline --parameters

# Follow the journal, keeping what was learned between runs
journalctl -f | umami pipeline --state ~/.cache/umami.json
```

**Options** (`pipeline`, `sim` and `ingest` share all but `--show-all`):

| Flag | Default | Description |
|---|---|---|
| `--system NAME` | `stdin` | System name attributed to events |
| `--tagged` | off | Read lines as `system<TAB>logline` |
| `--tokenizer structure\|legacy` | `structure` | Tokenizer variant |
| `--parameters` | off | Emit parameter-change anomalies |
| `--state FILE` | — | Load learned profiles from FILE, save them back |
| `--show-all` | off | Print every line with its classification |

Each anomalous output line is prefixed with the kind (e.g. `never_before_seen`),
padded to 18 characters, followed by the original line. `event_stop` and
`system_away` have no line; they print `[system]` and the signature.

Detection runs on *event time*: each line is observed at its own timestamp
(ISO 8601, CLF or syslog), so replaying an old log reports the silences in it.
Silences are checked once per minute of event time. `--state` files record
the tokenizer and refuse to load under a different one.

---

### `sim` — summarize anomaly counts

Like `pipeline` but consumes the entire stream and prints a summary table rather
than individual lines.

```sh
cat syslog | umami sim --system web01
```

Example output (50k lines of a desktop journal):
```text
events:    50000
anomalies: 222
reduction: 99.6%
profiles:  210
  event_stop         9
  frequency_spike    12
  never_before_seen  210
```

**Options:** as for `pipeline`, without `--show-all`.

---

### `ingest` — structured JSON output

Emits one JSON object per anomalous event, suitable for piping to a log aggregator
or storage system.

```sh
# Single system
cat syslog | umami ingest --system web01

# Multi-system: input lines are "system<TAB>logline"
paste -d'\t' <(echo -e "web01\nweb02") <(echo -e "disk full on /dev/sda1\ndisk full on /dev/sdb1") \
  | umami ingest --tagged
```

Each output line is a JSON object. `hash` identifies the structure (`null`
for `system_away`) and is the field to deduplicate on:
```json
{"system":"web01","kind":"never_before_seen","score":1.00,"hash":"96a870bdc586e53c","signature":"disk full on <*>","line":"disk full on /dev/sda1"}
{"system":"web02","kind":"new_in_system","score":0.80,"hash":"96a870bdc586e53c","signature":"disk full on <*>","line":"disk full on /dev/sdb1"}
```

**Options:** as for `pipeline`, without `--show-all`.

---

### `load` — throughput benchmark

Measures how fast the detector processes events. By default it generates
synthetic lines from four templates, so the run measures steady-state
filtering.

```sh
# Benchmark with 1M synthetic events
umami load

# Benchmark with 500k events
umami load --count 500000

# Benchmark against real data from stdin
cat syslog | umami load --stdin
```

Example output:
```text
processed 1000000 events in 1.008s
throughput 992461 events/sec
anomalies  4
profiles   4
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
The integration test in `umami/tests/corpus.rs` requires the structure
tokenizer to match every line, and the legacy tokenizer every line except the
three listed in that test (nested JSON, a bare date, empty quoted values).

After an intended tokenizer change, review the diff and regenerate:

```sh
umami tokenize --test corpus/structure.tsv --fix
umami tokenize --tokenizer legacy --test corpus/legacy.tsv --fix
git diff corpus/
```

---

## Performance

Measured on an EC2 c7i.2xlarge (Sapphire Rapids), `cargo bench`:

| Benchmark | Throughput |
|---|---|
| `tokenize/structure` (6 mixed formats) | 82 MiB/s |
| `tokenize/legacy` | 95 MiB/s |
| `detect/observe_10k` (tokenize + hash + profile + classify) | 1.04 M events/s |

On an 856k-line, 3-day desktop journal, `umami sim` runs in 2.8 s with a
peak RSS of 18 MB, keeping 10,557 profiles (98.7% of lines filtered).

---

## License

Licensed under either of:

* Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or
  <http://www.apache.org/licenses/LICENSE-2.0>)
* MIT license ([LICENSE-MIT](LICENSE-MIT) or <http://opensource.org/licenses/MIT>)

at your option.
