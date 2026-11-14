//! Exponential backoff with jitter.

use std::time::Duration;

/// The default [`Backoff::jitter`]: each delay is reduced by a random
/// fraction of up to 20 %.
pub const DEFAULT_BACKOFF_JITTER: f64 = 0.2;

/// Exponential backoff, the one retry backoff of every component: delays
/// doubling from [`min`](Self::min) up to [`max`](Self::max), each reduced
/// by a random fraction of up to [`jitter`](Self::jitter). The
/// [`redial`](crate::Config#structfield.redial) hook
/// ([`Config::redial_backoff`](crate::Config#structfield.redial_backoff)),
/// pipe pools ([`PipePool::backoff`](crate::helpers::PipePool::backoff)) and
/// the repetitions of a carrier adapter's requests use it.
#[derive(Debug, Clone, Copy, PartialEq)]
#[non_exhaustive]
pub struct Backoff {
    /// The first delay.
    pub min: Duration,
    /// The largest delay.
    pub max: Duration,
    /// Each delay is reduced by a random fraction of up to this (\[0, 1); 0 is
    /// none; default [`DEFAULT_BACKOFF_JITTER`]).
    pub jitter: f64,
}

impl Default for Backoff {
    /// From [`DEFAULT_MIN_BACKOFF`](crate::DEFAULT_MIN_BACKOFF) (1 s) to
    /// at most [`DEFAULT_MAX_BACKOFF`](crate::DEFAULT_MAX_BACKOFF) (60 s),
    /// with [`DEFAULT_BACKOFF_JITTER`]: the backoff of the redial hook and
    /// of pipe pools.
    fn default() -> Self {
        Self::new(crate::DEFAULT_MIN_BACKOFF, crate::DEFAULT_MAX_BACKOFF)
    }
}

impl Backoff {
    /// From `min` to at most `max`, with [`DEFAULT_BACKOFF_JITTER`]; assign
    /// [`jitter`](Self::jitter) for another.
    pub fn new(min: Duration, max: Duration) -> Self {
        Self {
            min,
            max,
            jitter: DEFAULT_BACKOFF_JITTER,
        }
    }

    /// Whether the bounds are valid: `min` not zero and not above `max`,
    /// and the jitter in \[0, 1) (0: none; NaN is invalid).
    pub fn validate(&self) -> Result<(), crate::InvalidConfig> {
        if self.min.is_zero() {
            return Err(crate::InvalidConfig::new("Backoff::min", "zero"));
        }
        if self.min > self.max {
            return Err(crate::InvalidConfig::new("Backoff::min", "above max"));
        }
        if !(0.0..1.0).contains(&self.jitter) {
            return Err(crate::InvalidConfig::new(
                "Backoff::jitter",
                "outside [0, 1)",
            ));
        }
        Ok(())
    }

    /// The delay after `failures` consecutive failures (none before the
    /// first).
    pub fn delay(&self, failures: u32) -> Duration {
        if failures == 0 {
            return Duration::ZERO;
        }
        let exp = self
            .min
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
    DRAWS.set(DRAWS.get() + 1);
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
        let mut b = Backoff::new(Duration::MAX, Duration::MAX);
        b.jitter = 0.0;
        assert!(Instant::now().checked_add(b.delay(40)).is_none());
    }

    #[test]
    fn backoff_doubles_up_to_the_max() {
        let mut b = Backoff::new(Duration::from_millis(100), Duration::from_secs(1));
        b.jitter = 0.0;
        let d: Vec<_> = (0..7).map(|n| b.delay(n).as_millis()).collect();
        assert_eq!(d, [0, 100, 200, 400, 800, 1000, 1000]);
        assert_eq!(b.delay(u32::MAX), Duration::from_secs(1));
        let mut j = b;
        j.jitter = 0.5;
        for _ in 0..100 {
            let d = j.delay(2);
            assert!(d <= Duration::from_millis(200) && d >= Duration::from_millis(100));
        }
    }
}
