//! Receive-window auto-tuning state (rule RB of SPEC.md Section 8.3 rule
//! 6): a scope's arrival rate and its
//! credit-loop samples.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use super::filter::IntervalRate;

/// Credit-loop samples a scope keeps pending at most; a full queue drops
/// samples, never credit.
const PENDING: usize = 17;
/// K of rule RB: windows target K x RTT_min of the arrival rate.
const K: u32 = 4;

/// An update sent at `sent_at` that raised the limit from `old_limit`;
/// `blocked` once the peer used exactly all of the old limit.
#[derive(Debug, Clone, Copy)]
struct Loop {
    old_limit: u64,
    sent_at: Instant,
    blocked: bool,
}

/// Receive-window auto-tuning of one scope (a stream's receiving part, or
/// the session), SPEC.md Section 8.3 rule 6:
/// the window is the arrival rate (the
/// largest of the last 4 intervals of max(RTT, 1 ms)) times max(K x
/// RTT_min, B), and never shrinks.
#[derive(Debug, Clone, Default)]
pub(super) struct Tuner {
    /// The arrival rate over intervals of max(RTT, 1 ms).
    rate: IntervalRate,
    /// Multipath: per interval, the largest pipe_min_rtt (us) of the pipes
    /// the scope's data arrived on.
    seen: [u32; 4],
    /// Updates whose credit-loop sample is pending.
    pending: VecDeque<Loop>,
}

/// A stream's auto-tuning: none until data arrives or the window is
/// raised, so that idle streams pay a pointer for it.
#[derive(Debug, Clone, Default)]
pub(super) struct StreamTuner(Option<Box<Tuner>>);

impl StreamTuner {
    /// Whether the stream has none yet.
    pub(super) fn is_empty(&self) -> bool {
        self.0.is_none()
    }

    /// Takes `t` (a cleared tuner of a discarded stream) when it has none.
    pub(super) fn install(&mut self, t: Box<Tuner>) {
        self.0.get_or_insert(t);
    }

    /// The tuner, cleared, for reuse by another stream.
    pub(super) fn take(&mut self) -> Option<Box<Tuner>> {
        let mut t = self.0.take()?;
        t.rate = IntervalRate::default();
        t.seen = [0; 4];
        t.pending.clear();
        Some(t)
    }

    pub(super) fn rtt_seen(&self) -> Option<Duration> {
        self.0.as_ref()?.rtt_seen()
    }

    pub(super) fn on_data(
        &mut self,
        off: u64,
        now: Instant,
        interval_rtt: Option<Duration>,
        pipe_rtt: Option<Duration>,
    ) -> Option<Duration> {
        self.0
            .get_or_insert_with(Box::default)
            .on_data(off, now, interval_rtt, pipe_rtt)
    }

    pub(super) fn on_blocked(&mut self, limit: u64) {
        if let Some(t) = self.0.as_mut() {
            t.on_blocked(limit);
        }
    }

    pub(super) fn target(&self, rtt: Option<Duration>, b: Duration) -> Option<u64> {
        self.0.as_ref()?.target(rtt, b)
    }

    pub(super) fn sent(&mut self, old_limit: u64, highest: u64, now: Instant) {
        self.0
            .get_or_insert_with(Box::default)
            .sent(old_limit, highest, now);
    }

    /// Heap bytes held.
    pub(super) fn memory(&self) -> usize {
        self.0.as_ref().map_or(0, |t| {
            std::mem::size_of::<Tuner>() + t.pending.capacity() * std::mem::size_of::<Loop>()
        })
    }
}

impl Tuner {
    /// The arrival rate R in bytes per second, `None` before the first
    /// interval ended.
    pub(super) fn rate(&self) -> Option<u64> {
        self.rate.get()
    }

    /// Multipath RTT_max: the largest pipe_min_rtt over the current and the
    /// last 3 intervals; `None` before data arrived on a pipe with an RTT.
    pub(super) fn rtt_seen(&self) -> Option<Duration> {
        let us = self.seen.iter().copied().max().unwrap_or(0);
        (us > 0).then(|| Duration::from_micros(u64::from(us)))
    }

    /// New data up to offset `off` arrived at `now` (on a pipe whose
    /// pipe_min_rtt is `pipe_rtt`, multipath). `interval_rtt` is the RTT of
    /// the scope, which sets the rate interval. Returns a credit-loop
    /// sample when the first byte beyond a limit the peer was blocked at
    /// arrived.
    pub(super) fn on_data(
        &mut self,
        off: u64,
        now: Instant,
        interval_rtt: Option<Duration>,
        pipe_rtt: Option<Duration>,
    ) -> Option<Duration> {
        if let Some(r) = pipe_rtt {
            let us = u32::try_from(r.as_micros()).unwrap_or(u32::MAX).max(1);
            let slot = &mut self.seen[self.rate.slot()];
            *slot = (*slot).max(us);
        }
        let mut sample = None;
        while let Some(p) = self.pending.front_mut() {
            if off < p.old_limit {
                break;
            }
            if off == p.old_limit {
                // The peer used exactly all of it.
                p.blocked = true;
                break;
            }
            if p.blocked {
                let s = now.saturating_duration_since(p.sent_at);
                sample = Some(sample.map_or(s, |x: Duration| x.min(s)));
            }
            self.pending.pop_front();
        }
        if self.rate.update(now, off, interval_rtt) {
            // The oldest slot is reused.
            self.seen[self.rate.slot()] = 0;
        }
        sample
    }

    /// DATA_BLOCKED or STREAM_DATA_BLOCKED at `limit`.
    pub(super) fn on_blocked(&mut self, limit: u64) {
        for p in &mut self.pending {
            if p.old_limit == limit {
                p.blocked = true;
            }
        }
    }

    /// The window growth of rule RB: the target for `rtt` (the scope's
    /// RTT_min, `None` before a sample) and the latency budget `b`.
    pub(super) fn target(&self, rtt: Option<Duration>, b: Duration) -> Option<u64> {
        let rate = self.rate()?;
        let span = rtt.map_or(b, |r| (r * K).max(b));
        Some((rate as f64 * span.as_secs_f64()) as u64)
    }

    /// An update raised the advertised limit from `old_limit`.
    pub(super) fn sent(&mut self, old_limit: u64, highest: u64, now: Instant) {
        if self.pending.len() >= PENDING {
            return;
        }
        if self.pending.capacity() == 0 {
            self.pending.reserve_exact(PENDING);
        }
        self.pending.push_back(Loop {
            old_limit,
            sent_at: now,
            blocked: highest == old_limit,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const B: Duration = Duration::from_micros(100);

    #[test]
    fn rate_times_k_rtt_or_budget() {
        let t0 = Instant::now();
        let ms = Duration::from_millis;
        let mut t = Tuner::default();
        assert_eq!(
            t.target(Some(ms(10)), B),
            None,
            "no rate before an interval"
        );
        t.on_data(0, t0, Some(ms(10)), None);
        // 1 MB in 10 ms: 100 MB/s.
        t.on_data(1_000_000, t0 + ms(10), Some(ms(10)), None);
        assert_eq!(t.rate(), Some(100_000_000));
        // W = R x 4 x RTT_min = 4 MB; without an RTT, R x B = 10 kB.
        assert_eq!(t.target(Some(ms(10)), B), Some(4_000_000));
        assert_eq!(t.target(None, B), Some(10_000));
        // Below B / 4 the budget wins.
        assert_eq!(t.target(Some(Duration::from_micros(10)), B), Some(10_000));
        // The maximum of the last 4 intervals: a slow interval does not
        // lower it.
        t.on_data(1_100_000, t0 + ms(20), Some(ms(10)), None);
        assert_eq!(t.rate(), Some(100_000_000));
    }

    #[test]
    fn credit_loop_sample_only_after_a_block() {
        let t0 = Instant::now();
        let ms = Duration::from_millis;
        let mut t = Tuner::default();
        // An update raising 1000 while the peer had sent 500: not blocked.
        t.sent(1000, 500, t0);
        assert_eq!(t.on_data(1200, t0 + ms(5), None, None), None);
        // The peer uses exactly all of 2000, then the next update's credit
        // arrives: the first byte beyond 2000 measures the loop.
        t.sent(2000, 1200, t0 + ms(10));
        assert_eq!(t.on_data(2000, t0 + ms(12), None, None), None);
        assert_eq!(t.on_data(2100, t0 + ms(31), None, None), Some(ms(21)));
        // DATA_BLOCKED at the limit marks it too.
        t.sent(3000, 2100, t0 + ms(40));
        t.on_blocked(3000);
        assert_eq!(t.on_data(3001, t0 + ms(52), None, None), Some(ms(12)));
    }

    #[test]
    fn multipath_rtt_is_the_largest_seen_in_four_intervals() {
        let t0 = Instant::now();
        let ms = Duration::from_millis;
        let mut t = Tuner::default();
        t.on_data(0, t0, None, Some(ms(5)));
        t.on_data(10, t0 + ms(1), None, Some(ms(50)));
        assert_eq!(t.rtt_seen(), Some(ms(50)));
        for i in 2..7 {
            t.on_data(10 * i, t0 + ms(i * 60), None, Some(ms(5)));
        }
        assert_eq!(t.rtt_seen(), Some(ms(5)), "the 50 ms pipe aged out");
    }
}
