//! A time-windowed single-use filter: each key is accepted once while its
//! stamp is within the window of the clock. The one single-use cache of the
//! library; hosts use it for anything sent as early data.

use std::collections::HashSet;
use std::hash::{BuildHasher, RandomState};
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// The result of [`ReplayFilter::check`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ReplayVerdict {
    /// Accepted, and recorded.
    Fresh,
    /// The key was seen within the window.
    Seen,
    /// The stamp is outside the window, or before the filter's `not_before`.
    Outside,
    /// The filter holds its maximum of keys: nothing new is accepted.
    Full,
}

/// An invalid [`ReplayFilter`] configuration: a window below 1 ms or a
/// maximum of 0 keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidReplayConfig;

impl std::fmt::Display for InvalidReplayConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("replay filter needs a window of at least 1 ms and a maximum above 0")
    }
}

impl std::error::Error for InvalidReplayConfig {}

/// Remembers keys so that each is accepted once: [`check`](Self::check)
/// accepts a key stamped `t` (Unix milliseconds) when `|now - t| <= window`
/// and it was not seen, and records it for at most `2 * window`. At most
/// `max` keys are held; a full filter accepts nothing new. Safe for
/// concurrent use.
///
/// Keys are kept as two independent keyed hashes, so an unbounded key length
/// costs nothing; hash or truncate as suits the caller.
#[derive(Debug)]
pub struct ReplayFilter {
    window: i64,
    width: i64,
    max: usize,
    not_before: Option<i64>,
    seeds: [RandomState; 2],
    state: Mutex<Buckets>,
}

#[derive(Debug, Default)]
struct Buckets {
    held: usize,
    buckets: Vec<(i64, HashSet<(u64, u64)>)>,
}

impl ReplayFilter {
    /// A filter of `window` (at least 1 ms) holding at most `max` keys (at
    /// least 1).
    pub fn new(window: Duration, max: usize) -> Result<Self, InvalidReplayConfig> {
        let w = i64::try_from(window.as_millis()).unwrap_or(i64::MAX / 4);
        if w <= 0 || max == 0 {
            return Err(InvalidReplayConfig);
        }
        let width = (w / 4).max(1);
        // Whole buckets over 2 * window, and the ones they straddle.
        let n = usize::try_from(2i64.saturating_mul(w).saturating_add(width - 1) / width + 2)
            .unwrap_or(16);
        let buckets = (0..n).map(|_| (0, HashSet::new())).collect();
        Ok(Self {
            window: w,
            width,
            max,
            not_before: None,
            seeds: [RandomState::new(), RandomState::new()],
            state: Mutex::new(Buckets { held: 0, buckets }),
        })
    }

    /// Rejects stamps before `time` (a process start: what an earlier run
    /// recorded is gone).
    #[must_use]
    pub fn with_not_before(mut self, time: SystemTime) -> Self {
        self.not_before = Some(unix_ms(time));
        self
    }

    /// [`check_at`](Self::check_at) by the system clock.
    pub fn check(&self, key: &[u8], t: i64) -> ReplayVerdict {
        self.check_at(key, t, unix_ms(SystemTime::now()))
    }

    /// Checks `key` stamped `t`, the clock at `now` (Unix milliseconds).
    pub fn check_at(&self, key: &[u8], t: i64, now: i64) -> ReplayVerdict {
        if t < now.saturating_sub(self.window)
            || t > now.saturating_add(self.window)
            || self.not_before.is_some_and(|n| t < n)
        {
            return ReplayVerdict::Outside;
        }
        let hashed = (self.seeds[0].hash_one(key), self.seeds[1].hash_one(key));
        let index = t.saturating_add(self.window).div_euclid(self.width);
        let low = now.div_euclid(self.width);
        let mut st = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        let Buckets { held, buckets } = &mut *st;
        for (idx, set) in buckets.iter_mut() {
            if *idx < low && !set.is_empty() {
                *held -= set.len();
                set.clear();
            }
        }
        if buckets.iter().any(|(_, set)| set.contains(&hashed)) {
            return ReplayVerdict::Seen;
        }
        if *held >= self.max {
            return ReplayVerdict::Full;
        }
        let n = i64::try_from(buckets.len()).unwrap_or(1);
        let slot = usize::try_from(index.rem_euclid(n)).unwrap_or(0);
        let (idx, set) = &mut buckets[slot];
        if *idx != index {
            *held -= set.len();
            set.clear();
            *idx = index;
        }
        set.insert(hashed);
        *held += 1;
        ReplayVerdict::Fresh
    }

    /// The keys held now.
    pub fn len(&self) -> usize {
        self.state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .held
    }

    /// Whether no key is held.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

fn unix_ms(t: SystemTime) -> i64 {
    match t.duration_since(UNIX_EPOCH) {
        Ok(d) => i64::try_from(d.as_millis()).unwrap_or(i64::MAX),
        Err(e) => i64::try_from(e.duration().as_millis()).map_or(i64::MIN, |m| -m),
    }
}
