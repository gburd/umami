//! Per-structure event profiles and the in-memory profile store.
//!
//! A [`Profile`] records everything the detector learns about one log-line
//! structure on one system: how often it occurs, when it was first and last
//! seen, the distinct values observed for each dynamic parameter, and the
//! frequency statistics used to detect spikes.

use crate::signature::StructureHash;
use crate::token::{Token, TokenType};
use std::collections::{HashMap, HashSet};

/// The maximum number of distinct values tracked per dynamic parameter
/// (up to 100 values per parameter).
pub const MAX_PARAM_VALUES: usize = 100;

/// Online mean/variance accumulator (Welford's algorithm) used for frequency
/// z-scores.
#[derive(Debug, Clone, Default, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RunningStats {
    /// Number of samples observed.
    pub count: u64,
    /// Running mean.
    pub mean: f64,
    /// Sum of squared deviations from the mean (M2).
    pub m2: f64,
}

impl RunningStats {
    /// Adds a sample to the accumulator.
    pub fn push(&mut self, x: f64) {
        self.count = self.count.saturating_add(1);
        let delta = x - self.mean;
        self.mean += delta / self.count as f64;
        let delta2 = x - self.mean;
        self.m2 += delta * delta2;
    }

    /// Merges `count` zero samples without iterating over empty minutes.
    fn push_zeros(&mut self, count: u64) {
        if count == 0 {
            return;
        }
        let total = self.count.saturating_add(count);
        self.m2 += self.mean * self.mean * self.count as f64 * count as f64 / total as f64;
        self.mean *= self.count as f64 / total as f64;
        self.count = total;
    }

    /// Population variance, or `0.0` if fewer than two samples.
    pub fn variance(&self) -> f64 {
        if self.count < 2 {
            0.0
        } else {
            self.m2 / self.count as f64
        }
    }

    /// Population standard deviation.
    pub fn stddev(&self) -> f64 {
        self.variance().sqrt()
    }

    /// The z-score of `x` against the current distribution.
    ///
    /// Returns `0.0` when the standard deviation is zero (insufficient data or
    /// no variation), avoiding division by zero.
    pub fn zscore(&self, x: f64) -> f64 {
        let sd = self.stddev();
        if sd == 0.0 {
            0.0
        } else {
            (x - self.mean) / sd
        }
    }
}

/// Tracks the distinct values seen for a single dynamic parameter position.
#[derive(Debug, Clone, Default, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ParamTracker {
    /// Distinct values observed, capped at [`MAX_PARAM_VALUES`].
    values: Vec<String>,
    /// Total number of observations (including duplicates and those dropped
    /// after the cap was reached).
    total: u64,
    /// Set once more than [`MAX_PARAM_VALUES`] distinct values are seen.
    saturated: bool,
}

impl ParamTracker {
    /// Records a value, signaling a new value only after twenty preceding
    /// observations with at most one distinct value per ten observations.
    /// Once more than
    /// [`MAX_PARAM_VALUES`] distinct values have been seen the parameter is
    /// treated as free-form (an id, a counter) and never signals again.
    pub fn observe(&mut self, value: &str) -> bool {
        let stable = self.total >= 20 && self.values.len() as u64 <= self.total / 10;
        self.total = self.total.saturating_add(1);
        if self.saturated || self.values.iter().any(|v| v == value) {
            return false;
        }
        if self.values.len() < MAX_PARAM_VALUES {
            self.values.push(value.to_string());
            stable
        } else {
            self.saturated = true;
            self.values = Vec::new(); // free the memory; the set is meaningless now
            false
        }
    }

    /// The distinct values observed (up to [`MAX_PARAM_VALUES`]); empty once
    /// saturated.
    pub fn values(&self) -> &[String] {
        &self.values
    }

    /// Whether the distinct-value cap has been exceeded.
    pub fn is_saturated(&self) -> bool {
        self.saturated
    }

    /// Number of distinct values currently tracked (0 once saturated).
    pub fn cardinality(&self) -> usize {
        self.values.len()
    }
}

/// Completed-minute baseline and the currently accumulating minute.
#[derive(Debug, Clone, Default, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
struct MinuteRate {
    minute: Option<i64>,
    count: u64,
    stats: RunningStats,
    reported: bool,
}

impl MinuteRate {
    /// Counts an arrival against preceding completed minutes, ignoring old buckets.
    fn observe(&mut self, now: i64) -> Option<f64> {
        let minute = now.div_euclid(60);
        if let Some(previous) = self.minute {
            if minute < previous {
                return None;
            }
            if minute > previous {
                self.stats.push(self.count as f64);
                self.stats.push_zeros((minute - previous - 1) as u64);
                self.count = 0;
                self.reported = false;
            }
        }
        self.minute = Some(minute);
        self.count = self.count.saturating_add(1);
        if self.stats.count < 30 {
            return None;
        }
        let variance = self.stats.variance().max(self.stats.mean).max(1.0);
        Some((self.count as f64 - self.stats.mean) / variance.sqrt())
    }
}

/// Tests a rolling day without overflowing at either timestamp boundary.
fn cooldown_elapsed(last: Option<i64>, now: i64) -> bool {
    last.map_or(true, |last| now.saturating_sub(last) >= 86_400)
}

/// A learned profile for one log-line structure on one system.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Profile {
    /// The structure hash this profile represents.
    pub hash: StructureHash,
    /// The human-readable structure signature (static tokens joined by spaces).
    pub signature: String,
    /// Total number of events matched to this profile.
    pub count: u64,
    /// Timestamp (unix seconds) of the first observation.
    pub first_seen: i64,
    /// Timestamp (unix seconds) of the most recent observation.
    pub last_seen: i64,
    /// Per-parameter value trackers, keyed by parameter index within the line.
    pub params: HashMap<usize, ParamTracker>,
    /// Inter-arrival time statistics (seconds between consecutive events),
    /// used to determine periodicity and detect stops.
    pub interval_stats: RunningStats,
    /// Set by [`crate::Detector::sweep`] once this profile's silence has been
    /// reported, until it is seen again.
    pub(crate) stop_reported: bool,
    #[cfg_attr(feature = "serde", serde(default))]
    rate: MinuteRate,
    #[cfg_attr(feature = "serde", serde(default))]
    last_stop: Option<i64>,
    #[cfg_attr(feature = "serde", serde(default))]
    last_spike: Option<i64>,
}

impl Profile {
    /// Creates a new profile for `hash` first seen at `now`.
    pub fn new(hash: StructureHash, signature: String, now: i64) -> Self {
        Self {
            hash,
            signature,
            count: 0,
            first_seen: now,
            last_seen: now,
            params: HashMap::new(),
            interval_stats: RunningStats::default(),
            stop_reported: false,
            rate: MinuteRate::default(),
            last_stop: None,
            last_spike: None,
        }
    }

    /// Whether the structure arrives at a steady rate: at least twenty intervals,
    /// with a standard deviation at most one fifth of their mean.  Only periodic
    /// profiles are reported as [stopped](crate::AnomalyKind::EventStop).
    pub fn is_periodic(&self) -> bool {
        let s = &self.interval_stats;
        s.count >= 20 && s.mean > 0.0 && s.stddev() <= 0.2 * s.mean
    }

    /// Learns nonnegative intervals, including return gaps, and minute counts.
    pub(crate) fn observe_time(&mut self, now: i64) -> Option<f64> {
        let mut z = None;
        if now >= self.last_seen {
            if self.count > 0 {
                self.interval_stats
                    .push(now.saturating_sub(self.last_seen) as f64);
            }
            z = self.rate.observe(now);
            if now > self.last_seen {
                self.last_seen = now;
                self.stop_reported = false;
            }
        }
        self.count = self.count.saturating_add(1);
        z
    }

    /// Latches a spike for this minute and applies its independent daily cooldown.
    pub(crate) fn report_spike(&mut self, now: i64) -> bool {
        if self.rate.reported {
            return false;
        }
        self.rate.reported = true;
        if !cooldown_elapsed(self.last_spike, now) {
            return false;
        }
        self.last_spike = Some(now);
        true
    }

    /// Latches a silence even when its independent daily cooldown suppresses it.
    pub(crate) fn report_stop(&mut self, now: i64) -> bool {
        self.stop_reported = true;
        if !cooldown_elapsed(self.last_stop, now) {
            return false;
        }
        self.last_stop = Some(now);
        true
    }

    /// Average inter-arrival interval in seconds, if known.
    pub fn mean_interval(&self) -> Option<f64> {
        if self.interval_stats.count > 0 {
            Some(self.interval_stats.mean)
        } else {
            None
        }
    }

    /// Whether the profile is still "newish" — seen too few times to be
    /// considered learned: a structure must recur before it stops being
    /// highlighted.
    pub fn is_newish(&self, learn_threshold: u64) -> bool {
        self.count < learn_threshold
    }
}

/// An in-memory, per-system store of profiles keyed by structure hash.
#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ProfileStore {
    systems: HashMap<String, HashMap<StructureHash, Profile>>,
    /// Structure hashes ever seen across *all* systems (for "never before
    /// seen" vs "new in system" classification).
    global_hashes: HashSet<StructureHash>,
    /// Per-system clock bookkeeping for [`crate::Detector::sweep`].
    #[cfg_attr(feature = "serde", serde(default))]
    pub(crate) clocks: HashMap<String, SystemClock>,
}

/// How one system's time relates to the detector's, so each system can be
/// judged on its own clock.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub(crate) struct SystemClock {
    /// The system's latest event time.
    pub(crate) latest: i64,
    /// How far behind the detector's clock that event was when it arrived
    /// (zone-less local time, shipping delay).
    pub(crate) lag: i64,
    /// Whether the system has been reported away since `latest`.
    pub(crate) away: bool,
}

impl ProfileStore {
    /// Creates an empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of distinct systems known to the store.
    pub fn system_count(&self) -> usize {
        self.systems.len()
    }

    /// Total number of profiles across all systems.
    pub fn profile_count(&self) -> usize {
        self.systems.values().map(HashMap::len).sum()
    }

    /// Iterates over `(system, profiles)` pairs.
    pub fn iter_systems(
        &self,
    ) -> impl Iterator<Item = (&String, &HashMap<StructureHash, Profile>)> {
        self.systems.iter()
    }

    #[allow(clippy::type_complexity)]
    pub(crate) fn systems_and_clocks_mut(
        &mut self,
    ) -> (
        impl Iterator<Item = (&String, &mut HashMap<StructureHash, Profile>)>,
        &mut HashMap<String, SystemClock>,
    ) {
        (self.systems.iter_mut(), &mut self.clocks)
    }

    /// Returns the profile for `hash` on `system`, if present.
    pub fn get(&self, system: &str, hash: StructureHash) -> Option<&Profile> {
        self.systems.get(system)?.get(&hash)
    }

    /// Whether `hash` has ever been seen on any system.
    pub fn seen_globally(&self, hash: StructureHash) -> bool {
        self.global_hashes.contains(&hash)
    }

    /// Whether `hash` has been seen on the given `system`.
    pub fn seen_on_system(&self, system: &str, hash: StructureHash) -> bool {
        self.systems
            .get(system)
            .is_some_and(|m| m.contains_key(&hash))
    }

    /// Returns a mutable reference to the profile for `(system, hash)`,
    /// inserting a new one (built from `tokens`/`now`) if absent. The boolean
    /// is `true` when a profile was newly created.
    pub fn get_or_insert(
        &mut self,
        system: &str,
        hash: StructureHash,
        tokens: &[Token],
        now: i64,
    ) -> (&mut Profile, bool) {
        self.global_hashes.insert(hash);
        let map = self.systems.entry(system.to_string()).or_default();
        let mut created = false;
        let profile = map.entry(hash).or_insert_with(|| {
            created = true;
            Profile::new(hash, crate::signature::structure_string(tokens), now)
        });
        (profile, created)
    }
}

/// Extracts the `(slot, value)` pairs of dynamic parameter tokens from a
/// tokenized line, where `slot` is the parameter's ordinal (0 for the first
/// parameter). Lines sharing a [`StructureHash`] have the same slots, so a
/// slot names the same field across every line of a profile.  Timestamp tokens
/// consume an ordinal but are excluded from the returned values.
pub fn parameter_values(tokens: &[Token]) -> Vec<(usize, &str)> {
    tokens
        .iter()
        .filter(|t| t.is_parameter())
        .enumerate()
        .filter(|(_, t)| t.ty != TokenType::Timestamp)
        .map(|(slot, t)| (slot, t.text.as_str()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signature::structure_signature;
    use crate::token::TokenType;
    use crate::tokenize;

    #[test]
    fn running_stats_zscore() {
        let mut s = RunningStats::default();
        for _ in 0..10 {
            s.push(1.0);
        }
        assert_eq!(s.zscore(1.0), 0.0); // no variance
        s.push(100.0);
        assert!(s.zscore(100.0) > 0.0);
    }

    #[test]
    fn skipped_minutes_match_explicit_zero_samples() {
        let mut rate = MinuteRate::default();
        rate.observe(-60);
        rate.observe(-59);
        rate.observe(1800);
        let mut expected = RunningStats::default();
        expected.push(2.0);
        for _ in 0..30 {
            expected.push(0.0);
        }
        assert_eq!(rate.stats.count, expected.count);
        assert!((rate.stats.mean - expected.mean).abs() < 1e-12);
        assert!((rate.stats.m2 - expected.m2).abs() < 1e-12);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn new_private_fields_default_when_loading_old_profiles() {
        let profile = Profile::new(StructureHash(1), "request".into(), 0);
        let mut value = serde_json::to_value(&profile).unwrap();
        let object = value.as_object_mut().unwrap();
        for field in ["rate", "last_stop", "last_spike"] {
            object.remove(field);
        }
        let restored: Profile = serde_json::from_value(value).unwrap();
        assert_eq!(profile, restored);
    }

    #[test]
    fn param_tracker_caps() {
        let mut p = ParamTracker::default();
        let new = (0..150).filter(|i| p.observe(&i.to_string())).count();
        assert_eq!(new, 0); // Free-form values never become stable.
        assert!(p.is_saturated());
        assert!(!p.observe("0"));
        assert_eq!(p.total, 151);
    }

    #[test]
    fn timestamp_exclusion_preserves_dynamic_ordinals() {
        let tokens = [
            Token::new(TokenType::Timestamp, "now"),
            Token::literal("status"),
            Token::new(TokenType::Number, "200"),
        ];
        assert_eq!(parameter_values(&tokens), vec![(1, "200")]);
    }

    #[test]
    fn parameter_learning_uses_preceding_observations() {
        let mut tracker = ParamTracker::default();
        for _ in 0..19 {
            assert!(!tracker.observe("200"));
        }
        assert!(!tracker.observe("201"));
        assert!(tracker.observe("500"));
        assert!(!tracker.observe("501"));
    }

    #[test]
    fn store_tracks_systems_and_globals() {
        let mut store = ProfileStore::new();
        let toks = tokenize("service started ok");
        let h = structure_signature(&toks);
        let (_, created) = store.get_or_insert("host-a", h, &toks, 0);
        assert!(created);
        assert!(store.seen_globally(h));
        assert!(store.seen_on_system("host-a", h));
        assert!(!store.seen_on_system("host-b", h));
        let (_, created2) = store.get_or_insert("host-a", h, &toks, 1);
        assert!(!created2);
    }

    #[test]
    fn param_values_are_dynamic_only() {
        let toks = tokenize("user=alice from 10.0.0.1 count=42");
        assert_eq!(parameter_values(&toks), vec![(0, "10.0.0.1"), (1, "42")]);
        assert!(TokenType::Number.is_parameter());
    }
}
