# umami

umami filters repetitive log events by their structure.  It reports a structure on first sight,
then tracks changes in frequency and stable parameter values.  The library package is umami-log;
Rust code imports umami, and the command-line executable is umami.

umami detects novelty, not whether a message describes a failure.  A known error returning on
another day need not produce an alert.  Keep explicit monitoring rules for known failures.

## Build

The library supports Rust 1.74; the CLI and development tests require Rust 1.85 or later.

```sh
git clone https://codeberg.org/gregburd/umami
cd umami
export CARGO_TARGET_DIR=/scratch/umami/build
cargo build --release --locked
cargo test --workspace --all-features --locked
```

The binary is /scratch/umami/build/release/umami.  Run cargo doc --no-deps to build API documentation.

For a sibling checkout, add this dependency to an application's Cargo.toml:

```toml
[dependencies]
umami = { package = "umami-log", path = "../umami/umami" }
```

The crates.io package named umami belongs to an unrelated project.  These instructions use the
source checkout and do not assume that umami-log has been published to crates.io.

## Library

```rust
use umami::{AnomalyKind, Detector};

let mut detector = Detector::new();
let first = detector.observe("web", "GET /health status 200", 0).unwrap();
assert_eq!(first.kind, AnomalyKind::NeverBeforeSeen);
assert!(detector.observe("web", "GET /health status 204", 1).is_none());
assert!(detector.observe("web", "POST /health status 200", 2).is_some());

let silence = detector.sweep(603);
assert!(silence.iter().any(|a| a.kind == AnomalyKind::SystemAway));
```

Pass Unix seconds to observe(), or tokenize once and call observe_tokens().  Library callers
must call sweep() periodically to detect silence.  The optional serde feature serializes
ProfileStore; with_store() resumes it.  Callers own the choice and validation of their clock.

### Structures

The tokenizer recognizes timestamps, IPv4 addresses, numbers, quoted text, JSON keys, and
key=value pairs.  It retokenizes quoted message contents rather than hiding an entire message
inside one parameter.

Signatures retain fixed words and a placeholder for every parameter position.  Changing a
number does not change the signature; moving a parameter between words does.  Digits, paths,
URLs, email addresses, long hex identifiers, and dotted host:port values receive variable
handling.  These rules are heuristics: alphabetic names can still create separate structures.

Exact signatures use a 64-bit FNV-1a hash.  They do not learn wildcard templates.  Hashes are
not cryptographic identifiers, and this release changes some hashes from version 0.1.

### Alerts and learning

| Kind | Meaning |
| --- | --- |
| never_before_seen | Structure not seen on any system. |
| new_in_system | Structure known elsewhere, first seen on this system. |
| frequency_spike | Current minute count exceeds the learned completed-minute baseline. |
| parameter_change | A stable parameter slot receives a new value.  Opt-in. |
| event_stop | A sufficiently regular event stream goes silent. |
| system_away | No event from a system for ten minutes by default. |

Frequency detection waits for thirty completed minute buckets.  It compares the current count
with the historical mean, using a variance floor of max(variance, mean, 1).  The default
threshold is 3.  A spike reports the rate increase at its first threshold crossing; it does
not grade the eventual flood size or estimate an incident probability.  Empty minutes
contribute to learning without an iteration per missing minute.

Stop detection requires at least twenty intervals with standard deviation no greater than
one fifth of their mean.  Silence must exceed three mean intervals by default.  Return gaps
contribute to learning, so an outage can delay renewed eligibility for stop alerts.  Stop and
spike alerts have separate rolling 24-hour cooldowns per system and structure.  An uninterrupted
silence remains one episode rather than generating daily reminders.

Parameter tracking allocates no trackers when disabled.  When enabled, it excludes timestamp
tokens and requires twenty preceding observations with at most one distinct value per ten
observations.  Slots exceeding 100 distinct values become permanently free-form.  Changed-slot
ordinals include timestamp positions, even though those positions do not generate changes.

Out-of-order events do not move last_seen backward or train timing statistics.  They can still
contribute structural and parameter learning.  Profiles do not expire automatically.

## CLI

```sh
# Inspect parameters and fixed text.
umami tokenize --pretty static 'request id=42 took 3 ms'
umami tokenize --pretty params 'request id=42 took 3 ms'

# Filter, summarize, or produce one JSON object per anomaly.
umami pipeline < syslog
umami sim < syslog
umami ingest < syslog

# Retain learning across runs.
journalctl -f | umami pipeline --state ~/.cache/umami.json

# Opt into stable-parameter changes.
umami ingest --parameters < syslog

# Each input line carries system<TAB>message.
umami ingest --tagged < tagged.log
```

pipeline prints anomaly kind followed by the original event.  --show-all also prints normal
events with the kind ok.  Stop and away alerts have no source line and identify the system and
structure instead.  sim prints aggregate counts and the proportion of input events suppressed;
synthetic sweep alerts do not count as input events.  ingest provides JSON fields for system,
kind, score, hash, signature, original line, and changed parameter slots.

load runs a throughput probe, using four synthetic templates by default.  Use --stdin for a
real stream and --count to change the synthetic event count.  This measures filtering speed,
not incident-detection quality.

## Time, input, and state

Automatic timestamp recognition supports ISO, Apache CLF, and syslog headers.  Yearless syslog
input assumes substantially chronological order: initial inference uses the reference date,
then continuing inference recognizes forward movement and New Year rollover.  Arbitrarily
reordered yearless logs are ambiguous; supply explicit years for those replays.  Zone-less
timestamps use UTC.

Use --time-format with a strftime-style format for other header layouts.  The format must
supply a year, date, and time.  Its consumed prefix becomes a timestamp token, so changing its
value does not create a new structure.  Explicit format mismatches and timestamps beyond the
permitted real-future allowance fail rather than silently advancing learned time.

Use --multiline to join indented continuation lines to their preceding event.  It is opt-in;
default input remains one event per line.  The first physical line supplies the event time.
Assembly flushes at EOF or after a one-second idle interval and caps an event at 1 MiB.
Slow continuations can therefore become separate events.  --multiline and --tagged cannot be
combined in this version.

A state file belongs to one writer for the duration of a run.  Saving uses a unique temporary
file in the same directory followed by atomic replacement.  Invalid or incompatible state
fails without resetting or overwriting the learned data.  Keep state in a trusted directory.
Version 0.1 state cannot be reused because tokenization and detector state have changed;
retain the old file and choose a new state path to relearn.

## Reference fixtures and tests

umami is an independent detector, not a compatible implementation of unomalycli.  The original
419-line reference captures remain under umami/corpus/reference with provenance.  Independent
regression expectations live in umami/corpus/structure.tsv.  Never regenerate the reference
captures to make a changed tokenizer pass.

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
umami tokenize --test umami/corpus/structure.tsv
```

Review intentional expectation changes individually.  The tokenize --fix option rewrites its
input file; use it only on a copy of a regression fixture, never the reference captures.

## Measurement limits

The November 14 audit measured grouping accuracy 0.767 across sixteen LogHub 2k samples for the
pre-release tokenizer.  It missed ten true templates on first appearance.  On one workstation
journal, that build processed 7.8 million lines in about twenty seconds and 10 MB of peak RSS,
but still produced hundreds of alerts per day after initial learning.

Those historical measurements do not qualify version 0.2.0.  A local rerun of the integrated
0.2.0 tokenizer measured mean grouping accuracy 0.798 on the same sixteen message-body samples,
with 1,655 first-structure alerts and ten first-template misses.  Whole raw lines scored 0.694,
with 1,903 first-structure alerts and eight misses.  Header preprocessing changes the result.
Grouping accuracy is not incident precision or recall, and a high filtering percentage alone
does not establish useful alerts.

## License

Dual-licensed under Apache-2.0 or MIT, at your option.  See LICENSE-APACHE and LICENSE-MIT.
