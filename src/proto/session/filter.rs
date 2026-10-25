//! Small estimators shared by the session's modules: a windowed minimum or
//! maximum, the exact maximum of a sliding window, a rate over the last few
//! intervals, and the RFC 9002 RTT smoothing. Each exists once; the modules that need one keep an
//! instance.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

/// The span of the RTT minima: the credit-loop minimum and each pipe's
/// min_rtt.
pub(super) const LOOP_SPAN: Duration = Duration::from_secs(300);

/// A windowed minimum (`MAX` false) or maximum (`MAX` true) over a span
/// given with each sample: the best sample, and the best ones of later
/// sub-windows ready to take over when it expires (the running minimum of
/// Linux's `win_minmax`).
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct WinFilter<T, const MAX: bool> {
    s: Option<[(Instant, T); 3]>,
}

/// A windowed minimum.
pub(crate) type MinFilter = WinFilter<Duration, false>;

impl<T: Copy + Ord, const MAX: bool> WinFilter<T, MAX> {
    /// `a` is at least as good as `b`.
    fn better(a: T, b: T) -> bool {
        if MAX { a >= b } else { a <= b }
    }

    /// The best sample, `None` before the first one. The best sample
    /// expires only as later samples arrive.
    pub(crate) fn get(&self) -> Option<T> {
        self.s.map(|s| s[0].1)
    }

    /// Adds a sample taken at `now`, for a minimum or maximum over `span`.
    pub(crate) fn update(&mut self, now: Instant, v: T, span: Duration) {
        let x = (now, v);
        let Some(s) = &mut self.s else {
            self.s = Some([x; 3]);
            return;
        };
        if Self::better(v, s[0].1) || now.saturating_duration_since(s[2].0) > span {
            *s = [x; 3];
            return;
        }
        if Self::better(v, s[1].1) {
            s[1] = x;
            s[2] = x;
        } else if Self::better(v, s[2].1) {
            s[2] = x;
        }
        // Expire the best sample, and refresh the sub-window samples.
        let age = now.saturating_duration_since(s[0].0);
        if age > span {
            *s = [s[1], s[2], x];
            if now.saturating_duration_since(s[0].0) > span {
                *s = [s[1], s[2], x];
            }
        } else if s[1].0 == s[0].0 && age > span / 4 {
            s[1] = x;
            s[2] = x;
        } else if s[2].0 == s[1].0 && age > span / 2 {
            s[2] = x;
        }
    }
}

impl MinFilter {
    /// Adds an RTT sample (at least 1 ns) taken at `now`, for a minimum
    /// over `span`.
    pub(crate) fn sample(&mut self, now: Instant, rtt: Duration, span: Duration) {
        self.update(now, rtt.max(Duration::from_nanos(1)), span);
    }
}

/// The maximum of the samples of a sliding window: the samples that no
/// later and larger one supersedes, oldest (and largest) first. Each sample
/// is pushed and dropped once, so the work is constant per sample
/// amortised. A sample smaller than one taken less than 1/64 of the span
/// before it is not kept apart, so that a steadily falling series holds at
/// most 64 entries, not every sample of the window: the maximum may then
/// lack, for at most 1/64 of the span, a sample below the one that left.
#[derive(Debug, Clone, Default)]
pub(crate) struct SlidingMax {
    s: VecDeque<(Instant, u64)>,
}

impl SlidingMax {
    /// The largest sample taken within `span` of `now`.
    pub(crate) fn within(&self, now: Instant, span: Duration) -> Option<u64> {
        self.s
            .iter()
            .find(|(t, _)| now.saturating_duration_since(*t) <= span)
            .map(|&(_, v)| v)
    }

    /// Adds a sample taken at `now`, for a maximum over `span`.
    pub(crate) fn update(&mut self, now: Instant, v: u64, span: Duration) {
        while self.s.back().is_some_and(|&(_, b)| b <= v) {
            self.s.pop_back();
        }
        let close = self
            .s
            .back()
            .is_some_and(|&(t, _)| now.saturating_duration_since(t) < span / 64);
        if !close {
            self.s.push_back((now, v));
        }
        while self
            .s
            .front()
            .is_some_and(|&(t, _)| now.saturating_duration_since(t) > span)
        {
            self.s.pop_front();
        }
    }

    /// Heap bytes held.
    pub(crate) fn memory(&self) -> usize {
        self.s.capacity() * std::mem::size_of::<(Instant, u64)>()
    }
}

/// The shortest rate interval.
const RATE_INTERVAL_FLOOR: Duration = Duration::from_millis(1);

/// A rate over intervals of max(RTT, 1 ms): the largest of the last 4
/// (the send rate of the low-water mark,
/// and the arrival rate of auto-tuning, Section 6.2).
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct IntervalRate {
    rates: [u64; 4],
    /// Slots of `rates` filled.
    filled: u8,
    /// The slot of the current interval.
    cur: u8,
    /// Start of the current interval: time and count.
    start: Option<(Instant, u64)>,
}

impl IntervalRate {
    /// Per second; `None` before the first interval ended.
    pub(crate) fn get(&self) -> Option<u64> {
        (self.filled > 0).then(|| self.rates.iter().copied().max().unwrap_or(0))
    }

    /// The slot of the current interval (0 to 3).
    pub(crate) fn slot(&self) -> usize {
        usize::from(self.cur)
    }

    /// The count reached `total` at `now`; `rtt` sets the interval. Returns
    /// whether an interval ended (the next slot is current then).
    pub(crate) fn update(&mut self, now: Instant, total: u64, rtt: Option<Duration>) -> bool {
        let Some((t0, n0)) = self.start else {
            self.start = Some((now, total));
            return false;
        };
        let span = now.saturating_duration_since(t0);
        if span < RATE_INTERVAL_FLOOR.max(rtt.unwrap_or_default()) {
            return false;
        }
        let cur = usize::from(self.cur);
        self.rates[cur] = (total.saturating_sub(n0) as f64 / span.as_secs_f64()) as u64;
        self.filled = (self.filled + 1).min(4);
        self.cur = ((cur + 1) % 4) as u8;
        self.start = Some((now, total));
        true
    }
}

/// RFC 9002 Section 5.3 smoothing: the smoothed RTT and its variation after
/// a sample `adjusted` (the ACK delay taken off where allowed); `first` is
/// what the first sample sets (the unadjusted one). Without a variation
/// (`rttvar` `None`) it starts at `first / 2`; without a smoothed RTT the
/// smoothed RTT is `first`.
pub(crate) fn smooth_rtt(
    srtt: Option<Duration>,
    rttvar: Option<Duration>,
    adjusted: Duration,
    first: Duration,
) -> (Duration, Duration) {
    let var = match (rttvar, srtt) {
        (Some(v), Some(s)) => (v * 3 + s.abs_diff(adjusted)) / 4,
        _ => first / 2,
    };
    let s = match srtt {
        Some(s) => (s * 7 + adjusted) / 8,
        None => first,
    };
    (s, var)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keeps_the_minimum_and_expires_it() {
        let t0 = Instant::now();
        let ms = Duration::from_millis;
        let mut f = MinFilter::default();
        assert_eq!(f.get(), None);
        let w = Duration::from_secs(10);
        f.sample(t0, ms(20), w);
        f.sample(t0 + ms(100), ms(5), w);
        f.sample(t0 + ms(200), ms(30), w);
        assert_eq!(f.get(), Some(ms(5)));
        // Queueing samples never raise it within the window.
        f.sample(t0 + Duration::from_secs(9), ms(80), w);
        assert_eq!(f.get(), Some(ms(5)));
        // After the window the minimum of the later samples takes over.
        f.sample(t0 + Duration::from_secs(12), ms(60), w);
        assert!(f.get().is_some_and(|r| r >= ms(30)), "{:?}", f.get());
    }

    #[test]
    fn the_sliding_maximum_keeps_the_largest_sample_left() {
        // A sample just below the window's best, taken while a three-sample
        // filter keeps only the best, is the maximum once the best expired.
        let t0 = Instant::now();
        let ms = Duration::from_millis;
        let w = ms(1000);
        let mut f = SlidingMax::default();
        assert_eq!(f.within(t0, w), None);
        f.update(t0, 100, w);
        f.update(t0 + ms(100), 99, w);
        f.update(t0 + ms(300), 50, w);
        f.update(t0 + ms(900), 80, w);
        assert_eq!(f.within(t0 + ms(900), w), Some(100));
        assert_eq!(f.within(t0 + ms(1050), w), Some(99));
        assert_eq!(f.within(t0 + ms(1200), w), Some(80));
        assert_eq!(f.within(t0 + ms(2000), w), None);
        // A larger sample supersedes the smaller ones before it.
        f.update(t0 + ms(1300), 120, w);
        assert_eq!(f.s.len(), 1);
    }

    /// A steadily falling series keeps at most 64 entries per window.
    #[test]
    fn a_falling_series_stays_bounded() {
        let t0 = Instant::now();
        let w = Duration::from_secs(10);
        let mut f = SlidingMax::default();
        for i in 0..100_000u64 {
            f.update(t0 + Duration::from_micros(100 * i), 1_000_000 - i, w);
        }
        assert!(f.s.len() <= 65, "{} entries", f.s.len());
    }
}
