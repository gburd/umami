//! The anomaly detection engine.
//!
//! [`Detector`] is the high-level entry point that ties together tokenization,
//! structure hashing and per-system profiles to classify each incoming log
//! event. It reproduces Unomaly's anomaly taxonomy:
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
//! *not* anomalies and are filtered out — exactly the behavior of
//! `unomalycli`'s pipeline.

use crate::profile::{parameter_values, ProfileStore};
use crate::signature::{structure_signature, structure_string};
use crate::token::Token;
use crate::tokenizer::Tokenizer;

/// The classification assigned to a processed event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

/// A detected anomaly, returned by [`Detector::observe`].
#[derive(Debug, Clone, PartialEq)]
pub struct Anomaly {
    /// The system the event came from.
    pub system: String,
    /// The kind of anomaly detected.
    pub kind: AnomalyKind,
    /// The structure signature (static tokens) of the triggering event.
    pub signature: String,
    /// The original log line.
    pub line: String,
    /// A score in `[0, 1]` indicating how significant the anomaly is.
    pub score: f64,
}

/// Tunable thresholds controlling detection sensitivity.
#[derive(Debug, Clone, Copy)]
pub struct DetectorConfig {
    /// Which tokenizer variant to use.
    pub tokenizer: Tokenizer,
    /// Number of occurrences before a profile is considered "learned".
    pub learn_threshold: u64,
    /// z-score above which a faster-than-usual arrival is a small spike.
    pub spike_small: f64,
    /// z-score for a medium spike.
    pub spike_medium: f64,
    /// z-score for a large spike.
    pub spike_large: f64,
    /// Whether to emit parameter-change anomalies.
    pub detect_parameter_changes: bool,
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
        }
    }
}

/// The stateful anomaly detector.
#[derive(Debug, Default)]
pub struct Detector {
    config: DetectorConfig,
    store: ProfileStore,
}

impl Detector {
    /// Creates a detector with default configuration.
    pub fn new() -> Self {
        Self {
            config: DetectorConfig::default(),
            store: ProfileStore::new(),
        }
    }

    /// Creates a detector with a custom configuration.
    pub fn with_config(config: DetectorConfig) -> Self {
        Self {
            config,
            store: ProfileStore::new(),
        }
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
        let (profile, _created) = self.store.get_or_insert(system, hash, tokens, now);

        // Update frequency stats from the inter-arrival interval.
        let mut spike: Option<SpikeMagnitude> = None;
        if profile.count > 0 {
            let interval = (now - profile.last_seen).max(0) as f64;
            let z = profile.interval_stats.zscore(interval);
            // A spike = arrivals *faster* than usual => interval well *below*
            // the mean => strongly negative z-score.
            let neg = -z;
            spike = if neg >= cfg.spike_large {
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
            // Only count as a change once the profile is established.
            let is_new = tracker.observe(value);
            if is_new && profile.count > 0 {
                param_changed = true;
            }
        }

        profile.count += 1;
        profile.last_seen = now;

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
            signature,
            line: line.to_string(),
            score: score_for(kind),
        })
    }

    /// Scans all known profiles for systems/events that have gone silent.
    ///
    /// * An [`AnomalyKind::EventStop`] is reported for a periodic profile whose
    ///   silence exceeds `stop_factor` times its mean interval.
    /// * An [`AnomalyKind::SystemAway`] is reported for a system whose most
    ///   recent event is older than `away_secs`.
    pub fn sweep(&self, now: i64, stop_factor: f64, away_secs: i64) -> Vec<Anomaly> {
        let mut out = Vec::new();
        for (system, profiles) in self.store.iter_systems() {
            let mut latest = i64::MIN;
            for profile in profiles.values() {
                latest = latest.max(profile.last_seen);
                if let Some(mean) = profile.mean_interval() {
                    if mean > 0.0 {
                        let silent = (now - profile.last_seen) as f64;
                        if silent > stop_factor * mean {
                            out.push(Anomaly {
                                system: system.clone(),
                                kind: AnomalyKind::EventStop,
                                signature: profile.signature.clone(),
                                line: String::new(),
                                score: score_for(AnomalyKind::EventStop),
                            });
                        }
                    }
                }
            }
            if latest != i64::MIN && now - latest > away_secs {
                out.push(Anomaly {
                    system: system.clone(),
                    kind: AnomalyKind::SystemAway,
                    signature: String::new(),
                    line: String::new(),
                    score: score_for(AnomalyKind::SystemAway),
                });
            }
        }
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
}
