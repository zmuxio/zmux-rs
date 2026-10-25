//! Per-second rate limits of frames.

use std::time::{Duration, Instant};

/// One second in nanoseconds.
const SECOND: u64 = 1_000_000_000;

/// At most `N` frames of a kind in any one-second interval at a sustained
/// `N` per second: 8 PIPE_PING frames (MULTIPATH.md Section 6.4).
///
/// A sliding window, not a token bucket: a bucket of `N` tokens refilled at
/// `N` per second lets almost `2N` frames into one second. The window keeps
/// the send times of the last `N` frames inline, as their ages in
/// nanoseconds before the latest one (saturated far above a second), so a
/// session holds no allocation for it.
#[derive(Debug, Clone)]
pub(crate) struct RateLimiter<const N: usize> {
    /// When the latest frame was sent (`None`: no frame yet).
    latest: Option<Instant>,
    /// The age of each of the last `N` send times at `latest`.
    ages: [u32; N],
}

impl<const N: usize> Default for RateLimiter<N> {
    fn default() -> Self {
        Self {
            latest: None,
            ages: [u32::MAX; N],
        }
    }
}

/// Nanoseconds of `d`, saturated at `u64::MAX`.
fn nanos(d: Duration) -> u64 {
    u64::try_from(d.as_nanos()).unwrap_or(u64::MAX)
}

impl<const N: usize> RateLimiter<N> {
    /// Frames that may be sent at `now`.
    pub(crate) fn available(&self, now: Instant) -> usize {
        let Some(latest) = self.latest else {
            return N;
        };
        // A send time t frees its slot once now - t >= 1 s, with
        // t = latest - age.
        let (ahead, behind) = (
            nanos(now.saturating_duration_since(latest)),
            nanos(latest.saturating_duration_since(now)),
        );
        self.ages
            .iter()
            .filter(|&&a| (u64::from(a) + ahead) >= SECOND.saturating_add(behind))
            .count()
    }

    /// When the next slot frees up.
    pub(crate) fn next_slot(&self, now: Instant) -> Option<Instant> {
        if self.available(now) > 0 {
            return Some(now);
        }
        let oldest = self.ages.iter().max()?;
        (self.latest? + Duration::from_secs(1))
            .checked_sub(Duration::from_nanos(u64::from(*oldest)))
    }

    /// Records a frame sent at `now` (replacing the oldest entry).
    pub(crate) fn record(&mut self, now: Instant) {
        let age = match self.latest {
            Some(latest) if now < latest => nanos(latest - now),
            latest => {
                let d = latest.map_or(u64::MAX, |l| nanos(now - l));
                for a in &mut self.ages {
                    *a = u32::try_from(u64::from(*a).saturating_add(d)).unwrap_or(u32::MAX);
                }
                self.latest = Some(now);
                0
            }
        };
        if let Some(oldest) = self.ages.iter_mut().max() {
            *oldest = u32::try_from(age).unwrap_or(u32::MAX);
        }
    }
}

/// At most `N` frames in any one-second interval, as a token bucket of
/// `N / 2` tokens refilled at `N / 2` per second (the generic cell rate
/// algorithm: one instant of state, no history): a burst of `N / 2`, then
/// one frame every `2 / N` seconds, so that a burst and the refill within
/// any second stay within `N`. Half the sliding window's sustained rate,
/// for a fraction of its size; the probes it limits (SPEC.md Section
/// 9.4.3 rule 1) are rare.
#[derive(Debug, Clone, Default)]
pub(crate) struct TokenBucket<const N: usize> {
    /// When the bucket is full again (the theoretical arrival time of the
    /// next frame); `None` or a past instant: full.
    full_at: Option<Instant>,
}

impl<const N: usize> TokenBucket<N> {
    /// The bucket's size.
    const BURST: usize = N / 2;
    /// The time one token takes to come back.
    const REFILL: Duration = Duration::from_nanos(SECOND / (N as u64 / 2));

    /// Frames that may be sent at `now`.
    pub(crate) fn available(&self, now: Instant) -> usize {
        let owed = self
            .full_at
            .map_or(Duration::ZERO, |t| t.saturating_duration_since(now));
        Self::BURST.saturating_sub(owed.as_nanos().div_ceil(Self::REFILL.as_nanos()) as usize)
    }

    /// When the next token is there.
    pub(crate) fn next_slot(&self, now: Instant) -> Option<Instant> {
        if self.available(now) > 0 {
            return Some(now);
        }
        // Full at `full_at`: one token is there BURST - 1 refills earlier.
        self.full_at?
            .checked_sub(Self::REFILL * (Self::BURST as u32 - 1))
    }

    /// Records a frame sent at `now`.
    pub(crate) fn record(&mut self, now: Instant) {
        let from = self.full_at.map_or(now, |t| t.max(now));
        self.full_at = Some(from + Self::REFILL);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The window of SPEC.md Section 9.4.3 rule 1: 16 frames at once, then
    /// each slot frees exactly one second after the frame that took it, so
    /// no one-second interval holds more than 16.
    #[test]
    fn sixteen_in_any_second() {
        let t0 = Instant::now();
        let ms = |m: u64| t0 + Duration::from_millis(m);
        let mut r = RateLimiter::<16>::default();
        assert_eq!(r.available(t0), 16);
        // 10 at 0 ms, 6 at 300 ms.
        for _ in 0..10 {
            r.record(t0);
        }
        assert_eq!(r.available(ms(300)), 6);
        for _ in 0..6 {
            r.record(ms(300));
        }
        assert_eq!(r.available(ms(300)), 0);
        assert_eq!(r.next_slot(ms(500)), Some(ms(1000)));
        assert_eq!(r.available(ms(999)), 0);
        assert_eq!(r.available(ms(1000)), 10);
        // One more at 1000 ms: the slots of 0 ms stay free beside it.
        r.record(ms(1000));
        assert_eq!(r.available(ms(1000)), 9);
        assert_eq!(r.available(ms(1299)), 9);
        assert_eq!(r.available(ms(1300)), 15);
        assert_eq!(r.available(ms(2000)), 16);
        // An earlier time than the latest frame counts from that time.
        assert_eq!(r.available(ms(999)), 0);
        // Sending whenever a slot is free: 16 per second, never more than
        // 16 within one second.
        let mut r = RateLimiter::<16>::default();
        let mut sent = Vec::new();
        let mut t = t0;
        while t < t0 + Duration::from_secs(5) {
            while r.available(t) > 0 {
                r.record(t);
                sent.push(t);
            }
            t = r.next_slot(t).unwrap();
        }
        for (i, &s) in sent.iter().enumerate() {
            let within = sent[i..]
                .iter()
                .take_while(|&&u| u < s + Duration::from_secs(1))
                .count();
            assert!(within <= 16, "{within} frames within a second of {i}");
        }
        assert!(sent.len() >= 16 * 5, "{} frames in 5 s", sent.len());
    }

    /// The bucket of SPEC.md Section 9.4.3 rule 1: 8 at once, then one
    /// every 125 ms; sending whenever it lets, no one-second interval
    /// holds more than 16.
    #[test]
    fn bucket_keeps_sixteen_in_any_second() {
        let t0 = Instant::now();
        let ms = |m: u64| t0 + Duration::from_millis(m);
        let mut b = TokenBucket::<16>::default();
        assert_eq!(b.available(t0), 8);
        for _ in 0..8 {
            b.record(t0);
        }
        assert_eq!(b.available(t0), 0);
        assert_eq!(b.next_slot(t0), Some(ms(125)));
        assert_eq!(b.available(ms(124)), 0);
        assert_eq!(b.available(ms(125)), 1);
        assert_eq!(b.available(ms(1000)), 8);
        let mut b = TokenBucket::<16>::default();
        let mut sent = Vec::new();
        let mut t = t0;
        while t < t0 + Duration::from_secs(5) {
            while b.available(t) > 0 {
                b.record(t);
                sent.push(t);
            }
            t = b.next_slot(t).unwrap();
        }
        for (i, &s) in sent.iter().enumerate() {
            let within = sent[i..]
                .iter()
                .take_while(|&&u| u <= s + Duration::from_secs(1))
                .count();
            assert!(within <= 16, "{within} frames within a second of {i}");
        }
        assert!(sent.len() >= 8 * 5, "{} frames in 5 s", sent.len());
    }
}
