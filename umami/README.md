# umami-log

`umami` is a reusable Rust library for log anomaly detection: it learns the
structure of streaming log events and surfaces only the *new, changed and
anomalous* lines, filtering out the bulk of repetitive, already-seen logs.

The registry package uses the name umami-log; Rust code imports umami.

```toml
[dependencies]
umami = { package = "umami-log", version = "0.2" }
```

## How it works

1. **Tokenization**: each log line is split into a sequence of typed tokens
   (literals, delimiters, numbers, timestamps, quoted strings, JSON keys, …).
   See [`tokenizer`].
2. **Structure signature**: the *static* tokens, plus a placeholder for each
   parameter, are hashed into a stable [`StructureHash`], so that lines
   differing only in their dynamic parts (numbers, timestamps, IPs, words with
   a digit or `/` in them, email addresses, and long hexadecimal identifiers) collapse to the same structure. See [`signature`].
3. **Profiles**: each structure is tracked per system in a [`Profile`] that
   records counts, first/last seen times, per-parameter distinct values and
   inter-arrival statistics. See [`profile`].
4. **Detection**: incoming events are classified as *never before seen*,
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

## More examples

These examples live in the package so extracted-crate doctests need no
workspace README or manual files.

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

```rust
use umami::{tokenize, signature::{structure_signature, structure_string}};

let a = structure_signature(&tokenize("request id=1 took 3 ms"));
let b = structure_signature(&tokenize("request id=999 took 7 ms"));
assert_eq!(a, b);  // dynamic values don't affect the hash

let s = structure_string(&tokenize("Jan 23 10:23:45 sshd failed root 22"));
// Timestamps and numbers become <*>; literals remain:
assert_eq!(s, "<*> sshd failed root <*>");
```

```rust
use umami::{tokenize, Tokenizer, Token, TokenType};
use umami::signature::{structure_signature, structure_string, StructureHash};
use umami::{Detector, DetectorConfig, Anomaly, AnomalyKind};
use umami::{Pretty, Profile, ProfileStore};
use umami::profile::{RunningStats, ParamTracker};
```

```rust
use umami::Detector;

let mut det = Detector::new();
// NeverBeforeSeen on first encounter
assert!(det.observe("host1", "service restarted", 0).is_some());
// Filtered on repeat (same structure, different nothing)
assert!(det.observe("host1", "service restarted", 1).is_none());
```

```rust
use umami::{Detector, DetectorConfig, Tokenizer};

let mut cfg = DetectorConfig::default();
cfg.tokenizer = Tokenizer::Structure;
cfg.detect_parameter_changes = true;
let mut det = Detector::with_config(cfg);
```

```rust
use umami::{tokenize, TokenType};

let toks = tokenize("level=info msg=started host=node01 count=42");
for t in &toks {
    if t.is_parameter() {
        println!("param: {}", t.text); // node01, 42
    }
}
```

```rust
use umami::{time::event_time, tokenize};

let toks = tokenize("2020-11-12T15:45:54+0000 INFO started");
assert_eq!(event_time(&toks, 0), Some(1_605_195_954));
```

```rust
use umami::{tokenize, signature::structure_signature};

let h1 = structure_signature(&tokenize("retries=1 timeout=30"));
let h2 = structure_signature(&tokenize("retries=9 timeout=60"));
assert_eq!(h1, h2); // only dynamic parts differ
```

## Crate features

The core library has no required dependencies and forbids `unsafe`.

* `serde` (off by default): `Serialize`/`Deserialize` for [`ProfileStore`]
  and the types in it, to save learned state and resume with
  [`Detector::with_store`].

A companion binary crate, `umami-cli`, provides a command-line interface.

## License

Licensed under either of Apache-2.0 or MIT at your option.
