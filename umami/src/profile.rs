//! Per-structure event profiles and the in-memory profile store.
//!
//! A [`Profile`] records everything Unomaly learns about one log-line
//! structure on one system: how often it occurs, when it was first and last
//! seen, the distinct values observed for each dynamic parameter, and the
//! frequency statistics used to detect spikes.

use crate::signature::{structure_signature, StructureHash};
use crate::token::Token;
use std::collections::HashMap;

/// The maximum number of distinct values tracked per dynamic parameter,
/// matching Unomaly's behavior (it tracks up to 100 values per parameter).
pub const MAX_PARAM_VALUES: usize = 100;

/// Online mean/variance accumulator (Welford's algorithm) used for frequency
/// z-scores.
#[derive(Debug, Clone, Default, PartialEq)]
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
        self.count += 1;
        let delta = x - self.mean;
        self.mean += delta / self.count as f64;
        let delta2 = x - self.mean;
        self.m2 += delta * delta2;
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
    /// Records a parameter value, returning `true` if it had not been seen
    /// before (a parameter-change signal).
    pub fn observe(&mut self, value: &str) -> bool {
        self.total += 1;
        if self.values.iter().any(|v| v == value) {
            return false;
        }
        if self.values.len() < MAX_PARAM_VALUES {
            self.values.push(value.to_string());
        } else {
            self.saturated = true;
        }
        true
    }

    /// The distinct values observed (up to [`MAX_PARAM_VALUES`]).
    pub fn values(&self) -> &[String] {
        &self.values
    }

    /// Whether the distinct-value cap has been exceeded.
    pub fn is_saturated(&self) -> bool {
        self.saturated
    }

    /// Number of distinct values currently tracked.
    pub fn cardinality(&self) -> usize {
        self.values.len()
    }
}

/// A learned profile for one log-line structure on one system.
#[derive(Debug, Clone, PartialEq)]
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
    /// used to detect frequency spikes and stops.
    pub interval_stats: RunningStats,
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
        }
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
    /// considered learned. Mirrors Unomaly's notion that a structure must
    /// recur before it stops being highlighted.
    pub fn is_newish(&self, learn_threshold: u64) -> bool {
        self.count < learn_threshold
    }
}

/// An in-memory, per-system store of profiles keyed by structure hash.
#[derive(Debug, Clone, Default)]
pub struct ProfileStore {
    systems: HashMap<String, HashMap<StructureHash, Profile>>,
    /// Structure hashes ever seen across *all* systems (for "never before
    /// seen" vs "new in system" classification).
    global_hashes: HashMap<StructureHash, u64>,
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

    /// Returns the profile for `hash` on `system`, if present.
    pub fn get(&self, system: &str, hash: StructureHash) -> Option<&Profile> {
        self.systems.get(system)?.get(&hash)
    }

    /// Whether `hash` has ever been seen on any system.
    pub fn seen_globally(&self, hash: StructureHash) -> bool {
        self.global_hashes.contains_key(&hash)
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
        *self.global_hashes.entry(hash).or_insert(0) += 1;
        let map = self.systems.entry(system.to_string()).or_default();
        let mut created = false;
        let profile = map.entry(hash).or_insert_with(|| {
            created = true;
            Profile::new(hash, crate::signature::structure_string(tokens), now)
        });
        (profile, created)
    }
}

/// Extracts the `(index, value)` pairs of dynamic parameter tokens from a
/// tokenized line, where `index` is the token position.
pub fn parameter_values(tokens: &[Token]) -> Vec<(usize, &str)> {
    tokens
        .iter()
        .enumerate()
        .filter(|(_, t)| t.ty.is_parameter())
        .map(|(i, t)| (i, t.text.as_str()))
        .collect()
}

/// Convenience: compute the structure hash for `tokens`.
pub fn hash_tokens(tokens: &[Token]) -> StructureHash {
    structure_signature(tokens)
}

#[cfg(test)]
mod tests {
    use super::*;
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
    fn param_tracker_caps() {
        let mut p = ParamTracker::default();
        for i in 0..150 {
            p.observe(&i.to_string());
        }
        assert_eq!(p.cardinality(), MAX_PARAM_VALUES);
        assert!(p.is_saturated());
        assert_eq!(p.total, 150);
    }

    #[test]
    fn store_tracks_systems_and_globals() {
        let mut store = ProfileStore::new();
        let toks = tokenize("service started ok");
        let h = hash_tokens(&toks);
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
        let params = parameter_values(&toks);
        // 42 is the dynamic number; alice/10.0.0.1 are literals in structure tok.
        assert!(params.iter().any(|(_, v)| *v == "42"));
        assert!(TokenType::Number.is_parameter());
    }
}
