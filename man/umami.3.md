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

The **umami** library reimplements the Unomaly log anomaly-detection algorithm as
a clean-room Rust crate.  It is not affiliated with Unomaly.

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

# TYPES

## Tokenizer

```rust
pub enum Tokenizer { Structure, Legacy }
```

Selects the tokenizer variant.  **Structure** (default) is the modern tokenizer
that understands **key=value** pairs, quoted strings, and JSON contexts.
**Legacy** is the original whitespace-oriented tokenizer.

Call **Tokenizer::tokenize(line)** to produce a **Vec\<Token\>**, or use the
free function **tokenize(line)** as shorthand for **Tokenizer::Structure**.

## Token / TokenType

```rust
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

**TokenType::is_structural()** returns **true** for Literal, JsonKey, and Json
(tokens that contribute to the structure signature).

**TokenType::is_parameter()** returns **true** for Number, Timestamp, Ipv4, and
Quoted (dynamic tokens tracked per profile).

## structure_signature

```rust
pub fn structure_signature(tokens: &[Token]) -> StructureHash
```

Computes the FNV-1a 64-bit hash of the structural tokens (type + text for each,
in order, with a separator byte).  Two lines with the same structure but different
dynamic values produce the same **StructureHash**.

## structure_string

```rust
pub fn structure_string(tokens: &[Token]) -> String
```

Renders the structural tokens as a space-joined string.  This is the
human-readable form of the signature, equivalent to **unomalycli -pretty=static**.

## Detector

```rust
pub struct Detector { /* ... */ }

impl Detector {
    pub fn new() -> Self;
    pub fn with_config(config: DetectorConfig) -> Self;
    pub fn observe(&mut self, system: &str, line: &str, now: i64)
        -> Option<Anomaly>;
    pub fn observe_tokens(&mut self, system: &str, line: &str,
        tokens: &[Token], now: i64) -> Option<Anomaly>;
    pub fn sweep(&self, now: i64, stop_factor: f64, away_secs: i64)
        -> Vec<Anomaly>;
    pub fn store(&self) -> &ProfileStore;
}
```

**observe** tokenizes *line*, looks up or creates the per-system profile, updates
statistics, and returns **Some(Anomaly)** if the event is anomalous.  Returns
**None** if the event matches learned-normal behavior.

**observe_tokens** is identical but accepts pre-computed tokens (useful when the
caller has already tokenized the line).

**sweep** scans all profiles for events/systems that have gone silent.  It should
be called periodically (e.g. once per minute).

## DetectorConfig

```rust
pub struct DetectorConfig {
    pub tokenizer: Tokenizer,
    pub learn_threshold: u64,
    pub spike_small: f64,
    pub spike_medium: f64,
    pub spike_large: f64,
    pub detect_parameter_changes: bool,
}
```

Defaults: structure tokenizer, learn_threshold=1, spike thresholds 3/6/12 (z-score),
parameter changes disabled.

## AnomalyKind

```rust
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

Tracks distinct values observed at one dynamic parameter position, capped at 100
entries.  **ParamTracker::observe(value)** returns **true** when the value is new.

## Pretty

```rust
pub enum Pretty { Test, Colors, Params, Delimiters, Static }
```

Pretty-printers for token sequences.  **Pretty::render(tokens, color)** returns
the formatted string.  Used by **umami tokenize** to reproduce the output of
**unomalycli -pretty=…**.

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

let cfg = DetectorConfig {
    tokenizer: Tokenizer::Legacy,
    detect_parameter_changes: true,
    ..DetectorConfig::default()
};
let mut det = Detector::with_config(cfg);
```

## Tokenize and inspect

```rust
use umami::{tokenize, TokenType};

let toks = tokenize("level=info msg=started host=node01 count=42");
for t in &toks {
    if t.ty.is_parameter() {
        println!("param: {}", t.text);
    }
}
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

Source repository: https://github.com/example/umami

Unomaly public documentation: https://unomaly.com (not affiliated).
