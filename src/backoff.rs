//! Exponential backoff with jitter.

use std::time::Duration;

/// The default [`Backoff::jitter`]: each delay is reduced by a random
/// fraction of up to 20 %.
pub const DEFAULT_BACKOFF_JITTER: f64 = 0.2;

/// Exponential backoff, the one retry backoff of every component: delays
/// doubling from [`min`](Self::min) up to [`max`](Self::max), each reduced
/// by a random fraction of up to [`jitter`](Self::jitter).
#[derive(Debug, Clone, Copy, PartialEq)]
#[non_exhaustive]
pub struct Backoff {
    /// The first delay.
    pub min: Duration,
    /// The largest nominal delay.
    pub max: Duration,
    /// Each delay is reduced by a random fraction of up to this (\[0, 1\]; 0 is
    /// none; default [`DEFAULT_BACKOFF_JITTER`]).
    pub jitter: f64,
    /// Maximum increase over the nominal delay, in \[0, 1\]. Defaults to zero.
    pub jitter_up: f64,
}

impl Default for Backoff {
    /// From [`DEFAULT_MIN_BACKOFF`](crate::DEFAULT_MIN_BACKOFF) (1 s) to
    /// at most [`DEFAULT_MAX_BACKOFF`](crate::DEFAULT_MAX_BACKOFF) (60 s),
    /// with [`DEFAULT_BACKOFF_JITTER`].
    fn default() -> Self {
        Self::new(crate::DEFAULT_MIN_BACKOFF, crate::DEFAULT_MAX_BACKOFF)
    }
}

impl Backoff {
    /// From `min` to at most `max`, with [`DEFAULT_BACKOFF_JITTER`]; assign
    /// [`jitter`](Self::jitter) for another.
    #[must_use]
    pub fn new(min: Duration, max: Duration) -> Self {
        Self {
            min,
            max,
            jitter: DEFAULT_BACKOFF_JITTER,
            jitter_up: 0.0,
        }
    }

    /// Whether the bounds are valid: `min` not zero and not above `max`,
    /// and the jitter in \[0, 1\]. The owner validates the largest wait
    /// against its monotonic clock when admitting a configuration.
    ///
    /// # Errors
    ///
    /// [`InvalidConfig`](crate::InvalidConfig) naming the first field that
    /// violates these bounds.
    pub fn validate(&self) -> Result<(), crate::InvalidConfig> {
        if self.min.is_zero() {
            return Err(crate::InvalidConfig::new("Backoff::min", "zero"));
        }
        if self.min > self.max {
            return Err(crate::InvalidConfig::new("Backoff::min", "above max"));
        }
        if !(0.0..=1.0).contains(&self.jitter) {
            return Err(crate::InvalidConfig::new(
                "Backoff::jitter",
                "outside [0, 1]",
            ));
        }
        if !(0.0..=1.0).contains(&self.jitter_up) {
            return Err(crate::InvalidConfig::new(
                "Backoff::jitter_up",
                "outside [0, 1]",
            ));
        }
        Ok(())
    }

    /// The delay after `failures` consecutive failures (none before the
    /// first).
    #[must_use]
    pub fn delay(&self, failures: u32) -> Duration {
        if failures == 0 {
            return Duration::ZERO;
        }
        let mut nominal = self.min;
        for _ in 1..failures {
            if nominal >= self.max || nominal.is_zero() {
                break;
            }
            nominal = self.next_nominal(nominal);
        }
        self.wait(nominal.min(self.max))
    }

    pub(crate) fn next_nominal(&self, previous: Duration) -> Duration {
        previous.saturating_mul(2).clamp(self.min, self.max)
    }

    pub(crate) fn wait_upper(&self) -> Duration {
        scale_nanos(self.max, 1.0 + self.jitter_up)
    }

    pub(crate) fn wait(&self, nominal: Duration) -> Duration {
        if self.jitter == 0.0 && self.jitter_up == 0.0 {
            return nominal;
        }
        jittered(nominal, self.jitter, self.jitter_up, random_fraction())
    }
}

fn jittered(nominal: Duration, down: f64, up: f64, sample: f64) -> Duration {
    let upper = 1.0 + up;
    let factor = if sample.to_bits() == 1.0_f64.to_bits() {
        upper
    } else {
        (1.0 - down + (down + up) * sample).min(upper)
    };
    scale_nanos(nominal, factor)
}

#[allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "jitter uses a floating-point factor and truncates in whole nanoseconds"
)]
pub(crate) fn scale_nanos(nominal: Duration, factor: f64) -> Duration {
    const NANOS_PER_SECOND: u128 = Duration::from_secs(1).as_nanos();
    if factor.to_bits() == 1.0_f64.to_bits() {
        return nominal;
    }
    let nanos = (nominal.as_nanos() as f64 * factor) as u128;
    let nanos = nanos.min(Duration::MAX.as_nanos());
    Duration::new(
        (nanos / NANOS_PER_SECOND) as u64,
        (nanos % NANOS_PER_SECOND) as u32,
    )
}

/// A uniform value in [0, 1].
pub(crate) fn random_fraction() -> f64 {
    #[cfg(all(feature = "test-hooks", feature = "tokio", not(loom)))]
    if let Some(sample) = FIXTURE_SAMPLE.with(|slot| {
        let (sample, count) = slot.get()?;
        slot.set(Some((sample, count + 1)));
        Some(sample)
    }) {
        return sample;
    }
    #[cfg(test)]
    DRAWS.set(DRAWS.get() + 1);
    let r = crate::util::random_u64() >> 11;
    crate::util::f64_of(r) / crate::util::f64_of((1u64 << 53) - 1)
}

#[cfg(all(feature = "test-hooks", feature = "tokio", not(loom)))]
thread_local! {
    static FIXTURE_SAMPLE: std::cell::Cell<Option<(f64, u64)>> = const { std::cell::Cell::new(None) };
}

#[cfg(all(feature = "test-hooks", feature = "tokio", not(loom)))]
pub(crate) fn with_fixture_sample<T>(sample: f64, apply: impl FnOnce() -> T) -> (T, u64) {
    struct Restore(Option<(f64, u64)>);
    impl Drop for Restore {
        fn drop(&mut self) {
            FIXTURE_SAMPLE.set(self.0);
        }
    }

    let _restore = Restore(FIXTURE_SAMPLE.replace(Some((sample, 0))));
    let result = apply();
    let count = FIXTURE_SAMPLE.get().map_or(0, |(_, count)| count);
    (result, count)
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
        assert_eq!(jittered(Duration::MAX, 0.0, 1.0, 1.0), Duration::MAX);
        assert_eq!(jittered(Duration::MAX, 1.0, 1.0, 0.0), Duration::ZERO);
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

    #[test]
    fn jitter_includes_both_endpoints() {
        let nominal = Duration::from_secs(1);
        assert_eq!(jittered(nominal, 1.0, 1.0, 0.0), Duration::ZERO);
        assert_eq!(jittered(nominal, 1.0, 1.0, 1.0), nominal * 2);
        assert_eq!(jittered(nominal, 1.0, 1.0, 0.5), nominal);
    }

    #[test]
    fn jitter_truncates_to_nanoseconds() {
        assert_eq!(
            jittered(Duration::from_nanos(3), 0.5, 0.0, 0.0),
            Duration::from_nanos(1)
        );
        assert_eq!(
            jittered(Duration::from_secs(30), 0.2, 0.2, 1.0),
            Duration::from_secs(36)
        );
        let nominal = Duration::from_nanos((1 << 53) + 1);
        assert_eq!(jittered(nominal, 0.5, 0.5, 0.5), nominal);
        let mut exact = Backoff::new(nominal, nominal);
        exact.jitter = 0.0;
        let draws = DRAWS.get();
        assert_eq!(exact.delay(1), nominal);
        assert_eq!(DRAWS.get(), draws);
    }
}
