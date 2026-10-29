//! The anomaly detection engine.
//!
//! [`Detector`] is the high-level entry point that ties together tokenization,
//! structure hashing and per-system profiles to classify each incoming log
//! event. It classifies each incoming log event into one of the following
//! anomaly kinds:
//!
//! * **Never before seen** — a structure new to the entire environment.
//! * **New in system** — a structure new to this system but seen elsewhere.
//! * **Parameter change** — a known structure with a previously unseen value
//!   in one of its dynamic parameters.
//! * **Frequency spike** — a known structure arriving far faster than its
//!   learned inter-arrival rate (graded small/medium/large by z-score).
//! * **Event stop** — a periodic structure that has gone silent.
//! * **System away** — a system that has stopped sending data entirely.
//!
//! Events that match a learned profile without triggering any of the above are
//! *not* anomalies and are filtered out.

use crate::profile::{parameter_values, ProfileStore};
use crate::signature::{structure_signature, structure_string, StructureHash};
use crate::token::Token;
use crate::tokenizer::Tokenizer;

/// The classification assigned to a processed event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AnomalyKind {
    /// New to the entire environment.
    NeverBeforeSeen,
    /// New to this system, seen on others.
    NewInSystem,
    /// Known structure, new parameter value.
    ParameterChange,
    /// Arrival rate significantly above the learned baseline.
    FrequencySpike(SpikeMagnitude),
    /// A periodic event that has stopped occurring.
    EventStop,
    /// A system that has stopped reporting entirely.
    SystemAway,
}

impl AnomalyKind {
    /// A short, stable, lowercase identifier for the anomaly kind.
    pub fn as_str(&self) -> &'static str {
        match self {
            AnomalyKind::NeverBeforeSeen => "never_before_seen",
            AnomalyKind::NewInSystem => "new_in_system",
            AnomalyKind::ParameterChange => "parameter_change",
            AnomalyKind::FrequencySpike(_) => "frequency_spike",
            AnomalyKind::EventStop => "event_stop",
            AnomalyKind::SystemAway => "system_away",
        }
    }
}

/// The graded severity of a [`AnomalyKind::FrequencySpike`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpikeMagnitude {
    /// Small spike (z-score over the small threshold).
    Small,
    /// Medium spike.
    Medium,
    /// Large spike.
    Large,
}

/// A detected anomaly, returned by [`Detector::observe`] and
/// [`Detector::sweep`].
#[derive(Debug, Clone, PartialEq)]
pub struct Anomaly {
    /// The system the event came from.
    pub system: String,
    /// The kind of anomaly detected.
    pub kind: AnomalyKind,
    /// The structure the anomaly is about, or `None` for
    /// [`AnomalyKind::SystemAway`].
    pub hash: Option<StructureHash>,
    /// The structure signature (static tokens) of the triggering event.
    pub signature: String,
    /// The original log line (empty for anomalies found by a sweep).
    pub line: String,
    /// A score in `[0, 1]` indicating how significant the anomaly is.
    pub score: f64,
}

/// Tunable thresholds controlling detection sensitivity.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct DetectorConfig {
    /// Which tokenizer variant to use.
    pub tokenizer: Tokenizer,
    /// Number of occurrences of a structure before its baseline is trusted:
    /// frequency spikes and parameter changes are only reported once a
    /// profile has been seen this many times.
    pub learn_threshold: u64,
    /// z-score above which a faster-than-usual arrival is a small spike.
    pub spike_small: f64,
    /// z-score for a medium spike.
    pub spike_medium: f64,
    /// z-score for a large spike.
    pub spike_large: f64,
    /// Whether to emit parameter-change anomalies.
    pub detect_parameter_changes: bool,
    /// [`Detector::sweep`] reports an [`AnomalyKind::EventStop`] when a
    /// periodic structure has been silent for this many mean intervals.
    pub stop_factor: f64,
    /// [`Detector::sweep`] reports an [`AnomalyKind::SystemAway`] when a
    /// system has sent nothing for this many seconds.
    pub away_secs: i64,
}

impl Default for DetectorConfig {
    fn default() -> Self {
        Self {
            tokenizer: Tokenizer::Structure,
            learn_threshold: 1,
            spike_small: 3.0,
            spike_medium: 6.0,
            spike_large: 12.0,
            detect_parameter_changes: false,
            stop_factor: 3.0,
            away_secs: 600,
        }
    }
}

/// The stateful anomaly detector.
#[derive(Debug, Default)]
pub struct Detector {
    config: DetectorConfig,
    store: ProfileStore,
    /// The latest time passed to `observe` or `sweep`.
    clock: Option<i64>,
}

impl Detector {
    /// Creates a detector with default configuration.
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a detector with a custom configuration.
    pub fn with_config(config: DetectorConfig) -> Self {
        Self {
            config,
            ..Self::default()
        }
    }

    /// Creates a detector that resumes from previously learned `store` (see
    /// [`Detector::store`] and the `serde` feature).
    pub fn with_store(config: DetectorConfig, store: ProfileStore) -> Self {
        let clock = store
            .iter_systems()
            .flat_map(|(_, profiles)| profiles.values().map(|p| p.last_seen))
            .max();
        Self { config, store, clock }
    }

    /// The detector's configuration.
    pub fn config(&self) -> &DetectorConfig {
        &self.config
    }

    /// The latest time passed to [`Detector::observe`] or [`Detector::sweep`]
    /// (or, for a detector made [with a store](Detector::with_store), the
    /// latest time in it), if any.
    pub fn clock(&self) -> Option<i64> {
        self.clock
    }

    /// Access the underlying profile store.
    pub fn store(&self) -> &ProfileStore {
        &self.store
    }

    /// Processes one log `line` from `system` at unix time `now` (seconds).
    ///
    /// Returns `Some(anomaly)` if the event is anomalous, or `None` if it
    /// matches learned-normal behavior and should be filtered out.
    pub fn observe(&mut self, system: &str, line: &str, now: i64) -> Option<Anomaly> {
        let tokens = self.config.tokenizer.tokenize(line);
        self.observe_tokens(system, line, &tokens, now)
    }

    /// Like [`Detector::observe`] but accepts pre-computed `tokens`.
    pub fn observe_tokens(
        &mut self,
        system: &str,
        line: &str,
        tokens: &[Token],
        now: i64,
    ) -> Option<Anomaly> {
        let hash = structure_signature(tokens);
        let seen_global = self.store.seen_globally(hash);
        let seen_system = self.store.seen_on_system(system, hash);

        // Determine structural novelty before mutating the store.
        let structural_kind = if !seen_system {
            Some(if seen_global {
                AnomalyKind::NewInSystem
            } else {
                AnomalyKind::NeverBeforeSeen
            })
        } else {
            None
        };

        let cfg = self.config;
        let clock = self.clock.map_or(now, |c| c.max(now));
        self.clock = Some(clock);
        // A line that is current, not lagging the clock, means the system is
        // back: re-arm its absence report. A late or lagging line does not.
        if clock - now <= cfg.away_secs {
            self.store.away.remove(system);
        }
        let (profile, _created) = self.store.get_or_insert(system, hash, tokens, now);
        let learned = !profile.is_newish(cfg.learn_threshold);
        let stop_after = cfg.stop_factor * profile.interval_stats.mean;

        // Update frequency stats from the inter-arrival interval. Skip a line
        // older than the last one (no interval), and a gap that sweep()
        // reported as a stop (an outage, not the rhythm).
        let gap = now - profile.last_seen;
        let outage = profile.stop_reported && gap as f64 > stop_after;
        let mut spike: Option<SpikeMagnitude> = None;
        if profile.count > 0 && gap >= 0 && !outage {
            let interval = gap as f64;
            let z = profile.interval_stats.zscore(interval);
            // A spike = arrivals *faster* than usual => interval well *below*
            // the mean => strongly negative z-score.
            let neg = -z;
            spike = if !learned {
                None
            } else if neg >= cfg.spike_large {
                Some(SpikeMagnitude::Large)
            } else if neg >= cfg.spike_medium {
                Some(SpikeMagnitude::Medium)
            } else if neg >= cfg.spike_small {
                Some(SpikeMagnitude::Small)
            } else {
                None
            };
            profile.interval_stats.push(interval);
        }

        // Update parameter trackers; record whether any value was new.
        let mut param_changed = false;
        for (idx, value) in parameter_values(tokens) {
            let tracker = profile.params.entry(idx).or_default();
            if tracker.observe(value) && learned {
                param_changed = true;
            }
        }

        profile.count += 1;
        profile.last_seen = profile.last_seen.max(now);
        if (clock - now) as f64 <= stop_after {
            profile.stop_reported = false; // current again: re-arm
        }

        let signature = if structural_kind.is_some() {
            structure_string(tokens)
        } else {
            profile.signature.clone()
        };

        // Priority: structural novelty > frequency spike > parameter change.
        let kind = if let Some(k) = structural_kind {
            Some(k)
        } else if let Some(mag) = spike {
            Some(AnomalyKind::FrequencySpike(mag))
        } else if param_changed && cfg.detect_parameter_changes {
            Some(AnomalyKind::ParameterChange)
        } else {
            None
        };

        kind.map(|kind| Anomaly {
            system: system.to_string(),
            kind,
            hash: Some(hash),
            signature,
            line: line.to_string(),
            score: score_for(kind),
        })
    }

    /// Reports systems and periodic events that have gone silent as of `now`,
    /// ordered by system, each system's stopped events before its absence.
    /// Call it regularly (say once a minute of event time); each silence is
    /// reported once, until the structure or system sends a *current* line:
    /// one no further behind the latest time seen than the threshold it
    /// broke.
    ///
    /// * An [`AnomalyKind::EventStop`] is reported for a periodic profile
    ///   (see [`crate::Profile::is_periodic`]) silent for more than
    ///   [`DetectorConfig::stop_factor`] times its mean interval.
    /// * An [`AnomalyKind::SystemAway`] is reported for a system whose most
    ///   recent event is more than [`DetectorConfig::away_secs`] old.
    ///
    /// Every system is judged against the same `now`: one whose clock runs
    /// behind the others by more than `away_secs` is reported away, once.
    pub fn sweep(&mut self, now: i64) -> Vec<Anomaly> {
        let cfg = self.config;
        self.clock = Some(self.clock.map_or(now, |c| c.max(now)));
        let mut out = Vec::new();
        let (systems, away) = self.store.systems_and_away_mut();
        for (system, profiles) in systems {
            let mut latest = i64::MIN;
            for profile in profiles.values_mut() {
                latest = latest.max(profile.last_seen);
                let silent = (now - profile.last_seen) as f64;
                if !profile.stop_reported
                    && profile.is_periodic()
                    && silent > cfg.stop_factor * profile.interval_stats.mean
                {
                    profile.stop_reported = true;
                    out.push(Anomaly {
                        system: system.clone(),
                        kind: AnomalyKind::EventStop,
                        hash: Some(profile.hash),
                        signature: profile.signature.clone(),
                        line: String::new(),
                        score: score_for(AnomalyKind::EventStop),
                    });
                }
            }
            if latest != i64::MIN && now - latest > cfg.away_secs && away.insert(system.clone()) {
                out.push(Anomaly {
                    system: system.clone(),
                    kind: AnomalyKind::SystemAway,
                    hash: None,
                    signature: String::new(),
                    line: String::new(),
                    score: score_for(AnomalyKind::SystemAway),
                });
            }
        }
        // HashMap order varies between runs; keep the output reproducible.
        // SystemAway has no hash, and sorts after the system's stops.
        out.sort_by_key(|a| (a.system.clone(), a.hash.map_or(u64::MAX, |h| h.0)));
        out
    }
}

/// Assigns a `[0,1]` significance score to an anomaly kind.
fn score_for(kind: AnomalyKind) -> f64 {
    match kind {
        AnomalyKind::NeverBeforeSeen => 1.0,
        AnomalyKind::NewInSystem => 0.8,
        AnomalyKind::FrequencySpike(SpikeMagnitude::Large) => 0.9,
        AnomalyKind::FrequencySpike(SpikeMagnitude::Medium) => 0.6,
        AnomalyKind::FrequencySpike(SpikeMagnitude::Small) => 0.4,
        AnomalyKind::ParameterChange => 0.5,
        AnomalyKind::EventStop => 0.7,
        AnomalyKind::SystemAway => 0.85,
    }
}

#[cfg(test)]
// DetectorConfig is non_exhaustive: callers build it from Default and assign.
#[allow(clippy::field_reassign_with_default)]
mod tests {
    use super::*;

    #[test]
    fn first_event_is_never_before_seen() {
        let mut d = Detector::new();
        let a = d.observe("host-a", "service started ok", 0).unwrap();
        assert_eq!(a.kind, AnomalyKind::NeverBeforeSeen);
    }

    #[test]
    fn repeat_same_structure_is_filtered() {
        let mut cfg = DetectorConfig::default();
        cfg.detect_parameter_changes = false;
        let mut d = Detector::with_config(cfg);
        d.observe("host-a", "request id=1 ok", 0);
        // identical structure, different dynamic value -> not anomalous
        let a = d.observe("host-a", "request id=2 ok", 1);
        assert_eq!(a, None);
    }

    #[test]
    fn new_in_system_after_seen_elsewhere() {
        let mut d = Detector::new();
        d.observe("host-a", "widget assembled", 0);
        let a = d.observe("host-b", "widget assembled", 1).unwrap();
        assert_eq!(a.kind, AnomalyKind::NewInSystem);
    }

    #[test]
    fn parameter_change_detected() {
        let mut cfg = DetectorConfig::default();
        cfg.detect_parameter_changes = true;
        let mut d = Detector::with_config(cfg);
        // establish the profile with one value
        d.observe("h", "temp reading 42C", 0);
        // new numeric value on an established profile -> parameter change
        let a = d.observe("h", "temp reading 99C", 1);
        assert!(matches!(
            a.map(|x| x.kind),
            Some(AnomalyKind::ParameterChange)
        ));
    }

    #[test]
    fn learn_threshold_delays_parameter_changes() {
        let mut cfg = DetectorConfig::default();
        cfg.detect_parameter_changes = true;
        cfg.learn_threshold = 3;
        let mut d = Detector::with_config(cfg);
        let kinds: Vec<_> = (0..5)
            .map(|i| d.observe("h", &format!("temp {i}"), i).map(|a| a.kind))
            .collect();
        use AnomalyKind::*;
        assert_eq!(
            kinds,
            [
                Some(NeverBeforeSeen),
                None,
                None,
                Some(ParameterChange),
                Some(ParameterChange)
            ]
        );
    }

    #[test]
    fn spike_on_early_arrival_of_periodic_event() {
        let mut d = Detector::new();
        let mut t = 0;
        for i in 0..20 {
            t += 60 + i % 2; // every 60-61 s
            assert_eq!(
                d.observe("h", "heartbeat ok", t).map(|a| a.kind),
                (i == 0).then_some(AnomalyKind::NeverBeforeSeen)
            );
        }
        let a = d.observe("h", "heartbeat ok", t + 1).unwrap();
        assert_eq!(a.kind, AnomalyKind::FrequencySpike(SpikeMagnitude::Large));
    }

    #[test]
    fn sweep_reports_each_silence_once() {
        let mut d = Detector::new();
        for i in 0..10 {
            d.observe("h", "heartbeat ok", i * 60);
        }
        d.observe("h", "something else", 540);
        assert!(d.sweep(600).is_empty());
        let kinds = |v: Vec<Anomaly>| v.into_iter().map(|a| a.kind).collect::<Vec<_>>();
        // 3 mean intervals (180 s) of silence -> the heartbeat stopped
        assert_eq!(kinds(d.sweep(800)), [AnomalyKind::EventStop]);
        assert!(d.sweep(900).is_empty());
        // 600 s with nothing at all -> the system is away
        assert_eq!(kinds(d.sweep(1200)), [AnomalyKind::SystemAway]);
        assert!(d.sweep(1300).is_empty());
        // it comes back, then stops again: both are reported again
        for i in 0..3 {
            d.observe("h", "heartbeat ok", 1300 + i * 60);
        }
        assert_eq!(
            kinds(d.sweep(3000)),
            [AnomalyKind::EventStop, AnomalyKind::SystemAway]
        );
    }

    #[test]
    fn a_lagging_system_is_reported_once() {
        // b's clock runs 15 minutes behind a's, on the shared sweep clock
        let mut d = Detector::new();
        let mut found = Vec::new();
        for m in 0..40 {
            d.observe("a", "tick", m * 60);
            d.observe("b", "tock", (m - 15) * 60);
            found.extend(d.sweep(m * 60).into_iter().map(|x| (x.system, x.kind)));
        }
        use AnomalyKind::*;
        assert_eq!(found, [("b".into(), SystemAway), ("b".into(), EventStop)]);
    }

    #[test]
    fn late_lines_do_not_rearm_or_skew_intervals() {
        let mut d = Detector::new();
        for i in 0..10 {
            d.observe("h", "heartbeat ok", i * 60);
        }
        assert_eq!(d.sweep(1200).len(), 2); // stop + away
        d.observe("h", "heartbeat ok", 120); // a straggler from the past
        assert!(d.sweep(1260).is_empty());
        let hb = structure_signature(&crate::tokenize("heartbeat ok"));
        assert_eq!(d.store().get("h", hb).unwrap().interval_stats.count, 9);
        d.observe("h", "heartbeat ok", 1300); // genuinely back
        // the 760 s outage is not learned as an interval
        assert_eq!(d.store().get("h", hb).unwrap().interval_stats.mean, 60.0);
        assert!(d.sweep(1310).is_empty());
        for i in 1..5 {
            d.observe("h", "heartbeat ok", 1300 + i * 60);
        }
        // stops again: reported again
        assert!(d.sweep(2000).iter().any(|a| a.kind == AnomalyKind::EventStop));
    }

    #[test]
    fn bursty_events_do_not_stop() {
        let mut d = Detector::new();
        for t in [0, 1, 2, 300, 301, 302, 900, 901] {
            d.observe("h", "burst", t);
        }
        assert!(d
            .sweep(5000)
            .iter()
            .all(|a| a.kind != AnomalyKind::EventStop));
    }
}

#[cfg(all(test, feature = "serde"))]
mod serde_tests {
    use super::*;

    #[test]
    fn learned_state_survives_a_round_trip() {
        let mut d = Detector::new();
        for i in 0..10 {
            d.observe("h", &format!("heartbeat {i} ok"), i * 60);
        }
        let json = serde_json::to_string(d.store()).unwrap();
        let store: ProfileStore = serde_json::from_str(&json).unwrap();
        let mut d = Detector::with_store(DetectorConfig::default(), store);
        assert_eq!(d.observe("h", "heartbeat 99 ok", 600), None);
        assert_eq!(
            d.observe("other", "heartbeat 1 ok", 600).map(|a| a.kind),
            Some(AnomalyKind::NewInSystem)
        );
        // the learned rhythm came back too
        let found: Vec<_> = d
            .sweep(2000)
            .into_iter()
            .map(|a| (a.system, a.kind))
            .collect();
        use AnomalyKind::*;
        assert_eq!(
            found,
            [
                ("h".into(), EventStop),
                ("h".into(), SystemAway),
                ("other".into(), SystemAway)
            ]
        );
        // what was reported is saved too: a resumed detector does not repeat it
        let json = serde_json::to_string(d.store()).unwrap();
        let store: ProfileStore = serde_json::from_str(&json).unwrap();
        let mut d = Detector::with_store(DetectorConfig::default(), store);
        assert!(d.sweep(2100).is_empty());
    }
}
