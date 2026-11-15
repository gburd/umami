% UMAMI(3) umami 0.2.0 | Library Functions
% umami contributors
% 2026

# NAME

umami - Rust library for structural log filtering

# SYNOPSIS

For a sibling source checkout:

```toml
[dependencies]
umami = { package = "umami-log", path = "../umami/umami" }
```

```rust
use umami::{AnomalyKind, Detector};
let mut detector = Detector::new();
assert_eq!(detector.observe("host", "status 200", 0).unwrap().kind,
           AnomalyKind::NeverBeforeSeen);
assert!(detector.observe("host", "status 204", 1).is_none());
```

# DESCRIPTION

The umami-log package exports the umami library.  The crates.io package named
umami belongs to another project.  The library forbids unsafe code and has no
required runtime dependencies.  Enable the serde feature to serialize learned profiles.

The detector groups events by exact structure and reports novelty, unusual minute
counts, stable-parameter changes, and silence.  It does not classify message meaning
or guarantee that a recurring known failure produces an alert.

# TOKENIZATION

**tokenize(line)** and **Tokenizer::Structure.tokenize(line)** produce typed tokens.
The Legacy tokenizer has been removed.  The retained tokenizer recognizes timestamps,
IPv4 addresses, numbers, quoted contents, JSON keys, and key=value pairs.

**Token::is_parameter()** also classifies variable-looking literals, including digits,
paths, email addresses, and long hexadecimal identifiers.  Type-level predicates do
not inspect literal text.  **structure_signature()** hashes fixed text and parameter
placeholders in position order; **structure_string()** renders that structure.

Signatures use 64-bit FNV-1a, not a cryptographic hash.  Version 0.2 changes some
signatures; applications must not silently reuse incompatible persistent profiles.

# DETECTOR

**Detector::new()** creates a default detector.  **with_config(config)** changes
thresholds; construct the non-exhaustive configuration from **DetectorConfig::default()**.
**with_store(config, store)** resumes learned profiles.

**observe(system, line, now)** tokenizes and observes one event.  **observe_tokens()**
accepts previously tokenized input.  Both return **Option<Anomaly>**.  Pass Unix seconds;
callers choose and validate their time source.

**sweep(now)** reports silent periodic events and absent systems.  Call it periodically;
no library background thread advances time.  Per-system lag adjustment prevents a
consistently delayed system from appearing absent just because other systems run ahead.
**clock()** returns the latest detector time, and **store()** borrows its profiles.

Older events do not move last_seen backward or update timing statistics.  They still
contribute counts and parameter learning.  Profiles remain allocated until the owning
application discards the store.

# LEARNING

Frequency detection compares a current minute's count with completed-minute statistics.
It requires thirty completed buckets and uses a variance floor of max(variance, mean, 1).
The default **spike_threshold** is 3.  A spike reports a threshold crossing immediately;
it does not grade the eventual flood or estimate incident probability.

A periodic event requires at least twenty intervals with standard deviation at most
one fifth of their mean.  **stop_factor** defaults to 3.  Return gaps train the interval
statistics, so a long outage can delay renewed periodic eligibility.  Stop and spike
alerts have separate rolling 86400-second cooldowns per system and structure.  A
continuous silence remains one episode.

**away_secs** defaults to 600.  **learn_threshold** defaults to 1 and adds an observation
count requirement to frequency and parameter learning; it does not suppress novelty.

**detect_parameter_changes** defaults to false.  Disabled detectors do not collect
parameter values.  Enabled detectors exclude timestamp tokens and require twenty preceding
observations with distinct values at most one tenth of the observation count.  More than
100 distinct values permanently saturates a slot and releases its stored values.

# RESULTS

**Anomaly** contains system, kind, optional structure hash, signature, original line,
score, and **changed_params**.  The latter contains zero-based dynamic-slot ordinals;
excluded timestamp slots still occupy an ordinal.  Stop and away events have no source
line.  System-away events also have no structure hash.

**AnomalyKind** is non-exhaustive.  Its variants are **NeverBeforeSeen**, **NewInSystem**,
**FrequencySpike**, **ParameterChange**, **EventStop**, and **SystemAway**.
**as_str()** returns stable lowercase names used by the CLI.  Scores are fixed values
by kind, not measured probabilities.  There is no SpikeMagnitude grading in version 0.2.

# LOWER-LEVEL TYPES

**ProfileStore** maps systems and hashes to profiles and records global novelty.
**Profile** includes event counts, timestamps, parameter trackers, interval statistics,
and private persisted rate/cooldown state.

**RunningStats** maintains count, mean, and squared deviations.  **push()**, **variance()**,
**stddev()**, and **zscore()** provide online summary calculations.

**ParamTracker::observe()** reports a new value only after stable learning; unlike version
0.1, its boolean does not signal every first-seen value.  **parameter_values()** excludes
timestamps while preserving dynamic-slot numbering.

**Pretty** supports Test, Colors, Params, Delimiters, and Static rendering.

**time::parse_timestamp()** and **time::event_time()** parse supported timestamp formats
into Unix seconds.  Initial yearless inference uses a reference date.  Continuing input
requires the explicit continuing-year context; arbitrary reordering without years remains
ambiguous.  Zone-less input uses UTC.

# SEE ALSO

**umami**(1), package-local README, and API documentation generated by
**cargo doc --no-deps -p umami-log**.
