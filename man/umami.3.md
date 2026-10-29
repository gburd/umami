% UMAMI(3) umami 0.1.0 | Library Functions
% umami contributors
% 2024

# NAME

umami — Rust library for structural log anomaly detection

# SYNOPSIS

```toml
[dependencies]
umami = "0.1"
```

```rust
use umami::{tokenize, Tokenizer, Token, TokenType};
use umami::signature::{structure_signature, structure_string, StructureHash};
use umami::{Detector, DetectorConfig, Anomaly, AnomalyKind};
use umami::{Pretty, Profile, ProfileStore};
use umami::profile::{RunningStats, ParamTracker};
```

# DESCRIPTION

The **umami** library implements a log anomaly-detection algorithm as a
self-contained Rust crate.

It is designed to be embedded in log-processing pipelines.  The high-level entry
point is **Detector**, which manages per-system state.  Lower-level building blocks
(tokenizer, signature, profile) are also exposed for custom pipelines.

The library forbids unsafe code and has no required runtime dependencies.

# MODULES

**token**
:   Token types and the **Token** struct.

**tokenizer**
:   The **structure** and **legacy** tokenizer implementations, plus the
    free function **tokenize** (shorthand for the structure tokenizer).

**signature**
:   **structure_signature** and **structure_string** — computing and rendering
    the structural fingerprint of a tokenized line.

**profile**
:   **Profile**, **ProfileStore**, **RunningStats**, **ParamTracker** — the
    per-system learned state.

**detector**
:   **Detector** — the stateful anomaly detector.  **AnomalyKind** and
    **Anomaly** — the result type.

**pretty**
:   **Pretty** — pretty-printers for debugging and CLI output.

**time**
:   **parse_timestamp** and **event_time** — turning a timestamp token into
    unix seconds, so the detector can run on event time.

# TYPES

## Tokenizer

```rust,ignore
pub enum Tokenizer { Structure, Legacy }
```

Selects the tokenizer variant.  **Structure** (default) is the modern tokenizer
that understands **key=value** pairs, quoted strings, and JSON contexts.
**Legacy** is the original whitespace-oriented tokenizer.

Call **Tokenizer::tokenize(line)** to produce a **Vec\<Token\>**, or use the
free function **tokenize(line)** as shorthand for **Tokenizer::Structure**.

## Token / TokenType

```rust,ignore
pub struct Token { pub ty: TokenType, pub text: String }

pub enum TokenType {
    Literal   = 0,  // static word/identifier
    Delimiter = 1,  // whitespace or punctuation
    Timestamp = 2,  // recognized date/time
    Ipv4      = 3,  // dotted-quad IPv4
    Quoted    = 4,  // quoted string contents
    Number    = 5,  // numeric value
    Json      = 6,  // nested JSON value
    JsonKey   = 7,  // key in key=value or {"key":...}
}
```

**TokenType::is_structural()** returns **true** for Literal, JsonKey, and Json;
**TokenType::is_parameter()** for Number, Timestamp, Ipv4, and Quoted.

The detector decides per token, with **Token::is_structural()** and
**Token::is_parameter()**: these follow the type, except that a Literal
containing a digit or a **/** (*web01*, an id, a path or URL) is a parameter.

## structure_signature

```rust,ignore
pub fn structure_signature(tokens: &[Token]) -> StructureHash
```

Computes the FNV-1a 64-bit hash of the structural tokens (type + text for each)
and of a placeholder for each parameter, in order, with a separator byte.  Two
lines with the same structure but different dynamic values produce the same
**StructureHash**; moving a parameter (*foo 1 bar* vs *foo bar 1*) changes it.

## structure_string

```rust,ignore
pub fn structure_string(tokens: &[Token]) -> String
```

Renders the signature as a space-joined string, with **<\*>** for each
parameter.  This is the human-readable form of the signature (the `static`
printer output).

## Detector

```rust,ignore
pub struct Detector { /* ... */ }

impl Detector {
    pub fn new() -> Self;
    pub fn with_config(config: DetectorConfig) -> Self;
    pub fn with_store(config: DetectorConfig, store: ProfileStore) -> Self;
    pub fn observe(&mut self, system: &str, line: &str, now: i64)
        -> Option<Anomaly>;
    pub fn observe_tokens(&mut self, system: &str, line: &str,
        tokens: &[Token], now: i64) -> Option<Anomaly>;
    pub fn sweep(&mut self, now: i64) -> Vec<Anomaly>;
    pub fn config(&self) -> &DetectorConfig;
    pub fn clock(&self) -> Option<i64>;
    pub fn store(&self) -> &ProfileStore;
}

pub struct Anomaly {
    pub system: String,
    pub kind: AnomalyKind,
    pub hash: Option<StructureHash>,  // None for SystemAway
    pub signature: String,
    pub line: String,                 // empty for EventStop / SystemAway
    pub score: f64,
}
```

*now* is unix seconds of event time; see **time::event_time** to take it from
the line itself.

**observe** tokenizes *line*, looks up or creates the per-system profile, updates
statistics, and returns **Some(Anomaly)** if the event is anomalous.  Returns
**None** if the event matches learned-normal behavior.

**observe_tokens** is identical but accepts pre-computed tokens (useful when the
caller has already tokenized the line).

**sweep** reports, as of *now*, periodic structures that have been silent for
more than **stop_factor** mean intervals (**EventStop**) and systems silent for
more than **away_secs** (**SystemAway**).  Call it periodically (e.g. once per
minute of event time).  Each silence is reported once, until the structure or
system sends a newer line; the output is sorted by system.  A structure is
periodic once it has at least three intervals whose standard deviation is
under half their mean.  Each system is judged on its own clock: *now* minus
how far behind the latest time its last line was when it arrived, so a system
whose timestamps lag the others' (local time, shipping delay) is not reported
for the lag.

**clock** returns the latest time passed to **observe** or **sweep** (for a
detector made with **with_store**, the latest time in the store).

**with_store** resumes from a previously learned **ProfileStore**; with the
**serde** feature, **ProfileStore** implements **Serialize** and
**Deserialize**.

## DetectorConfig

```rust,ignore
pub struct DetectorConfig {
    pub tokenizer: Tokenizer,
    pub learn_threshold: u64,
    pub spike_small: f64,
    pub spike_medium: f64,
    pub spike_large: f64,
    pub detect_parameter_changes: bool,
    pub stop_factor: f64,
    pub away_secs: i64,
}
```

Defaults: structure tokenizer, learn_threshold=1, spike thresholds 3/6/12 (z-score),
parameter changes disabled, stop_factor=3, away_secs=600.  Frequency spikes and
parameter changes are only reported once a profile has been seen
**learn_threshold** times.

**DetectorConfig** and **AnomalyKind** are **#[non_exhaustive]**: build a
config from **DetectorConfig::default()** and assign the fields you need.

## AnomalyKind

```rust,ignore
pub enum AnomalyKind {
    NeverBeforeSeen,
    NewInSystem,
    ParameterChange,
    FrequencySpike(SpikeMagnitude),  // Small | Medium | Large
    EventStop,
    SystemAway,
}
```

**AnomalyKind::as_str()** returns a stable lowercase identifier
(**never_before_seen**, **new_in_system**, **parameter_change**,
**frequency_spike**, **event_stop**, **system_away**).

## Profile / ProfileStore

**Profile** records what the detector has learned about one structure on one system:
event count, first/last seen timestamps (unix seconds), per-position
**ParamTracker**, and inter-arrival **RunningStats**.

**ProfileStore** is the in-memory (system → hash → Profile) map.  It also tracks
which hashes have been seen globally (across all systems) to enable the
**NeverBeforeSeen** vs **NewInSystem** distinction.

## RunningStats

Online mean/variance accumulator (Welford's algorithm) used for frequency z-scores.
**RunningStats::push(x)** adds a sample; **zscore(x)** returns how many standard
deviations *x* is from the current mean.

## ParamTracker

Tracks distinct values observed at one parameter slot (the *n*th parameter of
the line).  **ParamTracker::observe(value)** returns **true** when the value is
new.  Past 100 distinct values the slot is *saturated*: treated as free-form
(an id, a counter), it forgets its values and never reports a change again.

## Pretty

```rust,ignore
pub enum Pretty { Test, Colors, Params, Delimiters, Static }
```

Pretty-printers for token sequences.  **Pretty::render(tokens, color)** returns
the formatted string.  Used by **umami tokenize** to render tokens in the
supported pretty-printer formats.

# EXAMPLES

## Minimal detector

```rust
use umami::Detector;

let mut det = Detector::new();
// NeverBeforeSeen on first encounter
assert!(det.observe("host1", "service restarted", 0).is_some());
// Filtered on repeat (same structure, different nothing)
assert!(det.observe("host1", "service restarted", 1).is_none());
```

## Custom config

```rust
use umami::{Detector, DetectorConfig, Tokenizer};

let mut cfg = DetectorConfig::default();
cfg.tokenizer = Tokenizer::Legacy;
cfg.detect_parameter_changes = true;
let mut det = Detector::with_config(cfg);
```

## Tokenize and inspect

```rust
use umami::{tokenize, TokenType};

let toks = tokenize("level=info msg=started host=node01 count=42");
for t in &toks {
    if t.is_parameter() {
        println!("param: {}", t.text); // node01, 42
    }
}
```

## Event time

```rust
use umami::{time::event_time, tokenize};

let toks = tokenize("2020-11-12T15:45:54+0000 INFO started");
assert_eq!(event_time(&toks, 0), Some(1_605_195_954));
```

## Structure signature

```rust
use umami::{tokenize, signature::structure_signature};

let h1 = structure_signature(&tokenize("retries=1 timeout=30"));
let h2 = structure_signature(&tokenize("retries=9 timeout=60"));
assert_eq!(h1, h2); // only dynamic parts differ
```

# SEE ALSO

**umami**(1)

Source repository: https://codeberg.org/gregburd/umami
