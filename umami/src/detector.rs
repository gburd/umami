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
//! * **Frequency spike**: a minute count above the learned completed-minute
//!   baseline, reported immediately at the configured z-score threshold.
//! * **Event stop** — a periodic structure that has gone silent.
//! * **System away** — a system that has stopped sending data entirely.
//!
//! Events that match a learned profile without triggering any of the above are
//! *not* anomalies and are filtered out.

use crate::profile::{parameter_values, ProfileStore, SystemClock};
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
    FrequencySpike,
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
            AnomalyKind::FrequencySpike => "frequency_spike",
            AnomalyKind::EventStop => "event_stop",
            AnomalyKind::SystemAway => "system_away",
        }
    }
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
    /// A fixed category weight in `[0, 1]`, not a probability or measured severity.
    pub score: f64,
    /// Dynamic parameter ordinals whose values changed after stable learning.
    /// Timestamp tokens consume an ordinal but never appear here.
    pub changed_params: Vec<usize>,
}

/// Tunable thresholds controlling detection sensitivity.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct DetectorConfig {
    /// Which tokenizer variant to use.
    pub tokenizer: Tokenizer,
    /// Number of occurrences of a structure before its baseline is trusted:
    /// frequency spikes and parameter changes are only reported once a
    /// profile has been seen this many times.  Minute-count and stable-parameter
    /// learning impose their own additional minimums.
    pub learn_threshold: u64,
    /// z-score above which a minute count triggers a spike, after thirty
    /// complete minutes.  The first partial minute does not enter the baseline.
    /// Variance has a floor of the mean or one.
    pub spike_threshold: f64,
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
            spike_threshold: 3.0,
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
        Self {
            config,
            store,
            clock,
        }
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
        let sys = self
            .store
            .clocks
            .entry(system.to_string())
            .or_insert(SystemClock {
                latest: i64::MIN,
                ..SystemClock::default()
            });
        if now > sys.latest {
            // the system is (still) here: note how far behind it runs, re-arm
            *sys = SystemClock {
                latest: now,
                lag: clock.saturating_sub(now),
                away: false,
            };
        }
        let (profile, _created) = self.store.get_or_insert(system, hash, tokens, now);
        let learned = !profile.is_newish(cfg.learn_threshold);
        let z = profile.observe_time(now);
        let spike =
            learned && z.is_some_and(|z| z >= cfg.spike_threshold) && profile.report_spike(now);

        let mut changed_params = Vec::new();
        if cfg.detect_parameter_changes {
            for (idx, value) in parameter_values(tokens) {
                if profile.params.entry(idx).or_default().observe(value) && learned {
                    changed_params.push(idx);
                }
            }
        }

        let signature = if structural_kind.is_some() {
            structure_string(tokens)
        } else {
            profile.signature.clone()
        };

        // Priority: structural novelty > frequency spike > parameter change.
        let kind = if let Some(k) = structural_kind {
            Some(k)
        } else if spike {
            Some(AnomalyKind::FrequencySpike)
        } else if !changed_params.is_empty() {
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
            changed_params,
        })
    }

    /// Reports systems and periodic events that have gone silent as of `now`,
    /// ordered by system, each system's stopped events before its absence.
    /// Call it regularly (say once a minute of event time); each silence is
    /// reported once, until the structure or system sends a line newer than
    /// its last one.  Stops also have a rolling 86400-second cooldown per
    /// profile, independent of the frequency-spike cooldown.
    ///
    /// * An [`AnomalyKind::EventStop`] is reported for a periodic profile
    ///   (see [`crate::Profile::is_periodic`]) silent for more than
    ///   [`DetectorConfig::stop_factor`] times its mean interval.
    /// * An [`AnomalyKind::SystemAway`] is reported for a system whose most
    ///   recent event is more than [`DetectorConfig::away_secs`] old.
    ///
    /// Each system is judged on its own clock: `now` minus how far behind
    /// `now` its latest line was when it arrived. So a system whose
    /// timestamps lag the others' (zone-less local time, shipping delay) is
    /// not reported for the lag, and is still reported when it goes quiet.
    pub fn sweep(&mut self, now: i64) -> Vec<Anomaly> {
        let cfg = self.config;
        self.clock = Some(self.clock.map_or(now, |c| c.max(now)));
        let mut out = Vec::new();
        let (systems, clocks) = self.store.systems_and_clocks_mut();
        for (system, profiles) in systems {
            let sys = clocks.entry(system.clone()).or_insert_with(|| SystemClock {
                latest: profiles
                    .values()
                    .map(|p| p.last_seen)
                    .max()
                    .unwrap_or(i64::MIN),
                ..SystemClock::default()
            });
            let now = now.saturating_sub(sys.lag);
            for profile in profiles.values_mut() {
                let silent = now.saturating_sub(profile.last_seen) as f64;
                if !profile.stop_reported
                    && profile.is_periodic()
                    && silent > cfg.stop_factor * profile.interval_stats.mean
                    && profile.report_stop(now)
                {
                    out.push(Anomaly {
                        system: system.clone(),
                        kind: AnomalyKind::EventStop,
                        hash: Some(profile.hash),
                        signature: profile.signature.clone(),
                        line: String::new(),
                        score: score_for(AnomalyKind::EventStop),
                        changed_params: Vec::new(),
                    });
                }
            }
            if !sys.away && sys.latest != i64::MIN && now.saturating_sub(sys.latest) > cfg.away_secs
            {
                sys.away = true;
                out.push(Anomaly {
                    system: system.clone(),
                    kind: AnomalyKind::SystemAway,
                    hash: None,
                    signature: String::new(),
                    line: String::new(),
                    score: score_for(AnomalyKind::SystemAway),
                    changed_params: Vec::new(),
                });
            }
        }
        // HashMap order varies between runs; keep the output reproducible.
        // SystemAway has no hash, and sorts after the system's stops.
        out.sort_by_key(|a| (a.system.clone(), a.hash.map_or(u64::MAX, |h| h.0)));
        out
    }
}

/// Assigns a fixed category weight, not an estimated probability or severity.
fn score_for(kind: AnomalyKind) -> f64 {
    match kind {
        AnomalyKind::NeverBeforeSeen => 1.0,
        AnomalyKind::NewInSystem => 0.8,
        AnomalyKind::FrequencySpike => 0.4,
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
    fn parameter_changes_require_stable_learning() {
        let mut cfg = DetectorConfig::default();
        cfg.detect_parameter_changes = true;
        let mut d = Detector::with_config(cfg);
        for i in 0..20 {
            assert_eq!(
                d.observe("h", "temp reading 42C", i).map(|a| a.kind),
                (i == 0).then_some(AnomalyKind::NeverBeforeSeen)
            );
        }
        let anomaly = d.observe("h", "temp reading 99C", 20).unwrap();
        assert_eq!(anomaly.kind, AnomalyKind::ParameterChange);
        assert_eq!(anomaly.changed_params, [0]);
    }

    #[test]
    fn timestamp_and_id_noise_stays_quiet() {
        let mut cfg = DetectorConfig::default();
        cfg.detect_parameter_changes = true;
        let mut d = Detector::with_config(cfg);
        for i in 0..100 {
            let tokens = [
                Token::new(crate::TokenType::Timestamp, i.to_string()),
                Token::literal("request"),
                Token::new(crate::TokenType::Number, i.to_string()),
            ];
            assert_eq!(
                d.observe_tokens("h", "", &tokens, i).map(|a| a.kind),
                (i == 0).then_some(AnomalyKind::NeverBeforeSeen)
            );
        }
    }

    #[test]
    fn changed_slots_include_timestamp_ordinals() {
        let mut cfg = DetectorConfig::default();
        cfg.detect_parameter_changes = true;
        cfg.learn_threshold = 21;
        let mut d = Detector::with_config(cfg);
        for i in 0..=21 {
            let tokens = [
                Token::new(crate::TokenType::Timestamp, i.to_string()),
                Token::new(crate::TokenType::Number, if i < 20 { "200" } else { "500" }),
                Token::new(crate::TokenType::Number, if i < 21 { "1" } else { "2" }),
            ];
            let anomaly = d.observe_tokens("h", "", &tokens, i);
            if i == 21 {
                assert_eq!(anomaly.unwrap().changed_params, [2]);
            } else if i > 0 {
                assert_eq!(anomaly, None);
            }
        }
        let profile = d
            .store()
            .iter_systems()
            .next()
            .unwrap()
            .1
            .values()
            .next()
            .unwrap();
        assert!(!profile.params.contains_key(&0));
    }

    #[test]
    fn default_detection_does_not_track_parameters() {
        let mut d = Detector::new();
        let a = d.observe("h", "request id=42", 0).unwrap();
        assert!(d
            .store()
            .get("h", a.hash.unwrap())
            .unwrap()
            .params
            .is_empty());
    }

    #[test]
    fn jittered_heartbeat_is_not_a_flood() {
        let mut d = Detector::new();
        let mut t = 0;
        for i in 0..40 {
            t += 60 + i % 2;
            assert_eq!(
                d.observe("h", "heartbeat ok", t).map(|a| a.kind),
                (i == 0).then_some(AnomalyKind::NeverBeforeSeen)
            );
        }
        assert_eq!(d.observe("h", "heartbeat ok", t + 1), None);
    }

    #[test]
    fn irregular_arrivals_still_detect_a_same_second_flood() {
        let mut d = Detector::new();
        for minute in 0..30 {
            d.observe("h", "request", minute * 60);
            d.observe("h", "request", minute * 60 + 1);
        }
        let alerts: Vec<_> = (0..100)
            .filter_map(|_| d.observe("h", "request", 1800))
            .collect();
        assert_eq!(alerts.len(), 1);
        assert!(matches!(alerts[0].kind, AnomalyKind::FrequencySpike));
    }

    #[test]
    fn partial_first_minute_does_not_hide_a_flood() {
        for start in [0, 59] {
            let mut d = Detector::new();
            for second in start..1860 {
                for _ in 0..100 {
                    d.observe("h", "request", second);
                }
            }
            let alerts: Vec<_> = (0..8000)
                .filter_map(|_| d.observe("h", "request", 1860))
                .collect();
            assert_eq!(alerts.len(), 1, "start={start}");
        }
    }

    #[test]
    fn spike_is_immediate_and_ungraded() {
        let mut d = Detector::new();
        for t in (0..1800).step_by(60) {
            d.observe("h", "request", t);
        }
        let alerts: Vec<_> = (1..=10_000)
            .filter_map(|count| d.observe("h", "request", 1800).map(|a| (count, a)))
            .collect();
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].0, 4);
        assert_eq!(alerts[0].1.kind, AnomalyKind::FrequencySpike);
        assert_eq!(alerts[0].1.score, 0.4);
    }

    #[test]
    fn zero_threshold_does_not_bypass_warmup_or_admit_late_events() {
        let mut cfg = DetectorConfig::default();
        cfg.spike_threshold = 0.0;
        let mut d = Detector::with_config(cfg);
        for t in (0..1800).step_by(60) {
            assert_eq!(
                d.observe("h", "request", t).map(|a| a.kind),
                (t == 0).then_some(AnomalyKind::NeverBeforeSeen)
            );
        }
        assert!(matches!(
            d.observe("h", "request", 1800).unwrap().kind,
            AnomalyKind::FrequencySpike
        ));
        // A fresh profile has no cooldown to hide accidental late-event alerts.
        cfg.learn_threshold = 100;
        let mut d = Detector::with_config(cfg);
        for t in (0..6000).step_by(60) {
            d.observe("h", "request", t);
        }
        assert!(d.observe("h", "request", 0).is_none());
    }

    #[test]
    fn minute_warmup_includes_skipped_zero_buckets() {
        let mut d = Detector::new();
        d.observe("h", "request", 0);
        for _ in 0..100 {
            assert_eq!(d.observe("h", "request", 1740), None);
        }
        let alerts: Vec<_> = (0..100)
            .filter_map(|_| d.observe("h", "request", 1800))
            .collect();
        assert_eq!(alerts.len(), 1);
    }

    #[test]
    fn stop_requires_twenty_regular_intervals() {
        let mut d = Detector::new();
        for i in 0..20 {
            d.observe("h", "heartbeat", i * 60);
        }
        assert!(d.sweep(1400).is_empty());
        d.observe("h", "heartbeat", 1200);
        assert_eq!(d.sweep(1601)[0].kind, AnomalyKind::EventStop);
    }

    #[test]
    fn jitter_above_twenty_percent_does_not_stop() {
        let mut d = Detector::new();
        let mut t = 0;
        for i in 0..40 {
            t += if i % 2 == 0 { 40 } else { 80 };
            d.observe("h", "heartbeat", t);
        }
        assert!(d.sweep(t + 300).is_empty());
    }

    #[test]
    fn extreme_timestamps_do_not_overflow() {
        let mut d = Detector::new();
        d.observe("h", "request", i64::MIN);
        d.observe("h", "request", i64::MAX);
        d.observe("h", "request", i64::MIN);
        d.sweep(i64::MAX);
        let hash = structure_signature(&crate::tokenize("request"));
        let p = d.store().get("h", hash).unwrap();
        assert_eq!(p.interval_stats.count, 1);
        assert_eq!(p.interval_stats.mean, i64::MAX as f64);
    }

    #[test]
    fn stop_cooldown_is_rolling_and_silence_is_one_episode() {
        let mut cfg = DetectorConfig::default();
        cfg.away_secs = i64::MAX;
        cfg.stop_factor = 0.5;
        let mut d = Detector::with_config(cfg);
        for i in 0..=20 {
            d.observe("a", "heartbeat", i * 60);
            d.observe("b", "heartbeat", i * 60);
        }
        assert_eq!(d.sweep(1231).len(), 2);
        d.observe("a", "heartbeat", 1260);
        assert!(d.sweep(1291).is_empty());
        assert!(d.sweep(87631).is_empty());
        // Keep normal arrivals while the cooldown expires, then stop again.
        let mut d = Detector::with_config(cfg);
        for t in (0..=87600).step_by(60) {
            d.observe("a", "heartbeat", t);
            if t == 1200 {
                assert_eq!(d.sweep(1231).len(), 1);
            }
            if t == 87540 {
                assert!(d.sweep(87571).is_empty());
            }
        }
        assert_eq!(d.sweep(87631)[0].kind, AnomalyKind::EventStop);
    }

    #[test]
    fn spike_cooldowns_are_independent_of_system_profile_and_stop() {
        let mut cfg = DetectorConfig::default();
        cfg.stop_factor = 0.5;
        let mut d = Detector::with_config(cfg);
        for t in (0..=1800).step_by(60) {
            d.observe("a", "heartbeat", t);
            d.observe("b", "heartbeat", t);
            d.observe("a", "request", t);
        }
        assert_eq!(d.sweep(1831).len(), 3);
        for (system, line) in [("a", "heartbeat"), ("b", "heartbeat"), ("a", "request")] {
            let alerts: Vec<_> = (0..10)
                .filter_map(|_| d.observe(system, line, 1832))
                .collect();
            assert_eq!(alerts.len(), 1);
            assert!(matches!(alerts[0].kind, AnomalyKind::FrequencySpike));
        }
    }

    #[test]
    fn late_flood_does_not_change_current_rate() {
        let mut d = Detector::new();
        for t in (0..1800).step_by(60) {
            d.observe("h", "request", t);
        }
        assert!(d.observe("h", "request", 1810).is_none());
        for _ in 0..100 {
            assert!(d.observe("h", "request", 1809).is_none());
        }
        for _ in 0..2 {
            assert!(d.observe("h", "request", 1810).is_none());
        }
        assert!(matches!(
            d.observe("h", "request", 1810).map(|a| a.kind),
            Some(AnomalyKind::FrequencySpike)
        ));
    }

    /// Two systems on `period`-second rhythms, `b` running `lag` seconds
    /// behind `a`, swept every 60 s; `b` stops at `b_stops` (minutes).
    fn lagging(period: i64, lag: i64, b_stops: i64) -> Vec<(String, AnomalyKind)> {
        let mut d = Detector::new();
        let mut found = Vec::new();
        let mut next_sweep = 0;
        for t in (0..3600).step_by(period as usize) {
            d.observe("a", "tick", t);
            if t < b_stops * 60 {
                d.observe("b", "tock", t - lag);
            }
            if t >= next_sweep {
                found.extend(d.sweep(t).into_iter().map(|x| (x.system, x.kind)));
                next_sweep = t + 60;
            }
        }
        found
    }

    #[test]
    fn a_lagging_system_is_judged_on_its_own_clock() {
        use AnomalyKind::*;
        for (period, lag) in [(60, 150), (60, 590), (60, 900), (5, 12), (5, 3000)] {
            assert_eq!(lagging(period, lag, 60), [], "period {period} lag {lag}");
            // and when it really stops, that is reported, once each
            let b = |v: Vec<(String, AnomalyKind)>| {
                v.into_iter()
                    .filter(|x| x.0 == "b")
                    .map(|x| x.1)
                    .collect::<Vec<_>>()
            };
            assert_eq!(
                b(lagging(period, lag, 30)),
                [EventStop, SystemAway],
                "period {period} lag {lag}"
            );
        }
    }

    #[test]
    fn batch_callers_work_system_by_system() {
        // all of a's day, then all of b's: b's lines are all "late"
        let mut d = Detector::new();
        for t in (0..3600).step_by(60) {
            d.observe("a", "tick", t);
        }
        for t in (0..1800).step_by(60) {
            d.observe("b", "tock", t);
        }
        let found: Vec<_> = d
            .sweep(3600)
            .into_iter()
            .map(|a| (a.system, a.kind))
            .collect();
        // b is judged at its own 1740 + lag-free time: not away, not stopped
        assert!(found.is_empty(), "{found:?}");
    }

    #[test]
    fn late_lines_do_not_rearm_and_return_gaps_are_learned() {
        let mut d = Detector::new();
        for i in 0..21 {
            d.observe("h", "heartbeat ok", i * 60);
        }
        assert_eq!(d.sweep(1900).len(), 2);
        d.observe("h", "heartbeat ok", 120);
        assert!(d.sweep(1960).is_empty());
        let hb = structure_signature(&crate::tokenize("heartbeat ok"));
        assert_eq!(d.store().get("h", hb).unwrap().interval_stats.count, 20);
        d.observe("h", "heartbeat ok", 2000);
        let profile = d.store().get("h", hb).unwrap();
        assert_eq!(profile.interval_stats.count, 21);
        assert!(profile.interval_stats.mean > 90.0);
        assert!(!profile.is_periodic());
        assert!(d.sweep(2300).is_empty());
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
        for i in 0..21 {
            d.observe("h", &format!("heartbeat {i} ok"), i * 60);
        }
        let json = serde_json::to_string(d.store()).unwrap();
        let store: ProfileStore = serde_json::from_str(&json).unwrap();
        let mut d = Detector::with_store(DetectorConfig::default(), store);
        assert_eq!(d.observe("h", "heartbeat 99 ok", 1260), None);
        assert_eq!(
            d.observe("other", "heartbeat 1 ok", 1260).map(|a| a.kind),
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

    #[test]
    fn partial_minute_and_spike_cooldown_survive_restart() {
        let mut d = Detector::new();
        for t in (0..1800).step_by(60) {
            d.observe("h", "request", t);
        }
        for _ in 0..3 {
            assert!(d.observe("h", "request", 1800).is_none());
        }
        let json = serde_json::to_string(d.store()).unwrap();
        let mut d = Detector::with_store(
            DetectorConfig::default(),
            serde_json::from_str(&json).unwrap(),
        );
        assert!(matches!(
            d.observe("h", "request", 1800).unwrap().kind,
            AnomalyKind::FrequencySpike
        ));
        let json = serde_json::to_string(d.store()).unwrap();
        let mut d = Detector::with_store(
            DetectorConfig::default(),
            serde_json::from_str(&json).unwrap(),
        );
        for _ in 0..20 {
            assert!(d.observe("h", "request", 1800).is_none());
            assert!(d.observe("h", "request", 1860).is_none());
        }
        for minute in 32..1470 {
            d.observe("h", "request", minute * 60);
        }
        for _ in 0..10 {
            assert!(d.observe("h", "request", 88199).is_none());
        }
        let alerts: Vec<_> = (0..30)
            .filter_map(|_| d.observe("h", "request", 88200))
            .collect();
        assert_eq!(alerts.len(), 1);
    }

    #[test]
    fn stop_cooldown_and_parameter_learning_survive_restart() {
        let cfg = DetectorConfig {
            stop_factor: 0.5,
            detect_parameter_changes: true,
            ..DetectorConfig::default()
        };
        let mut d = Detector::with_config(cfg);
        for t in (0..=1200).step_by(60) {
            d.observe("h", "status 200", t);
        }
        assert_eq!(d.sweep(1231)[0].kind, AnomalyKind::EventStop);
        let json = serde_json::to_string(d.store()).unwrap();
        let mut d = Detector::with_store(cfg, serde_json::from_str(&json).unwrap());
        assert_eq!(
            d.observe("h", "status 500", 1260).unwrap().changed_params,
            [0]
        );
        assert!(d.sweep(1291).is_empty());
    }

    #[test]
    fn initial_partial_minute_stays_excluded_after_restart() {
        let mut d = Detector::new();
        d.observe("h", "request", 59);
        let json = serde_json::to_string(d.store()).unwrap();
        let mut d = Detector::with_store(
            DetectorConfig::default(),
            serde_json::from_str(&json).unwrap(),
        );
        for t in (60..1800).step_by(60) {
            d.observe("h", "request", t);
        }
        for _ in 0..100 {
            assert!(d.observe("h", "request", 1800).is_none());
        }
        let alerts: Vec<_> = (0..100)
            .filter_map(|_| d.observe("h", "request", 1860))
            .collect();
        assert_eq!(alerts.len(), 1);
    }
}
