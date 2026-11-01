//! Exponential backoff with jitter.

use std::time::Duration;

/// Exponential backoff: delays doubling from [`initial`](Self::initial) up
/// to [`max`](Self::max), each reduced by a random fraction of up to
/// [`jitter`](Self::jitter). Redials of a pipe pool
/// ([`PipePool::backoff`](crate::helpers::PipePool::backoff)) and
/// repetitions of a carrier adapter's requests use it.
#[derive(Debug, Clone, Copy, PartialEq)]
#[non_exhaustive]
pub struct Backoff {
    /// The first delay.
    pub initial: Duration,
    /// The largest delay.
    pub max: Duration,
    /// Each delay is reduced by a random fraction of up to this (0 to 1).
    pub jitter: f64,
}

/// The largest delay of the default [`Backoff`], which pipe pools redial
/// with.
pub const DEFAULT_BACKOFF_MAX: Duration = Duration::from_secs(60);

impl Default for Backoff {
    /// From 1 s to at most [`DEFAULT_BACKOFF_MAX`] (60 s), with 20 % jitter.
    fn default() -> Self {
        Self::new(Duration::from_secs(1), DEFAULT_BACKOFF_MAX).with_jitter(0.2)
    }
}

impl Backoff {
    /// From `initial` to at most `max`, without jitter.
    pub fn new(initial: Duration, max: Duration) -> Self {
        Self {
            initial,
            max,
            jitter: 0.0,
        }
    }

    /// With this jitter (0 to 1).
    #[must_use]
    pub fn with_jitter(mut self, jitter: f64) -> Self {
        self.jitter = jitter;
        self
    }

    /// The delay after `failures` consecutive failures (none before the
    /// first).
    pub fn delay(&self, failures: u32) -> Duration {
        if failures == 0 {
            return Duration::ZERO;
        }
        let exp = self
            .initial
            .saturating_mul(1u32.checked_shl(failures - 1).unwrap_or(u32::MAX))
            .min(self.max);
        reduce(exp, self.jitter)
    }
}

/// `d` reduced by a random fraction of up to `jitter`.
pub(crate) fn reduce(d: Duration, jitter: f64) -> Duration {
    let f = 1.0 - jitter.clamp(0.0, 1.0) * random_fraction();
    // Saturating: near the largest duration the product rounds above it.
    Duration::try_from_secs_f64(d.as_secs_f64() * f).map_or(d, |r| r.min(d))
}

/// A uniform value in [0, 1).
pub(crate) fn random_fraction() -> f64 {
    #[cfg(test)]
    DRAWS.with(|d| d.set(d.get() + 1));
    let r = crate::util::random_u64() >> 11;
    r as f64 / (1u64 << 53) as f64
}

// The draws of `random_fraction` on this thread (unit tests count them on
// a current-thread runtime).
#[cfg(test)]
thread_local! {
    pub(crate) static DRAWS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    /// Durations have no maximum: the largest one
    /// reduces and backs off without overflowing, and never comes.
    #[test]
    fn the_largest_durations_saturate() {
        assert!(reduce(Duration::MAX, 0.0) <= Duration::MAX);
        assert!(reduce(Duration::MAX, 0.5) <= Duration::MAX);
        let b = Backoff::new(Duration::MAX, Duration::MAX);
        assert!(Instant::now().checked_add(b.delay(40)).is_none());
    }

    #[test]
    fn backoff_doubles_up_to_the_max() {
        let b = Backoff::new(Duration::from_millis(100), Duration::from_secs(1));
        let d: Vec<_> = (0..7).map(|n| b.delay(n).as_millis()).collect();
        assert_eq!(d, [0, 100, 200, 400, 800, 1000, 1000]);
        assert_eq!(b.delay(u32::MAX), Duration::from_secs(1));
        let j = b.with_jitter(0.5);
        for _ in 0..100 {
            let d = j.delay(2);
            assert!(d <= Duration::from_millis(200) && d >= Duration::from_millis(100));
        }
    }
}
