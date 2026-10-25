//! A pipe's estimates: the RTT and delivery-rate
//! estimator, the sample state of the write batches in flight, and the
//! samples an acknowledgement gives.

use std::cell::Cell;
use std::collections::VecDeque;
use std::time::{Duration, Instant};

/// One write call handed to the carrier: its
/// send time and the delivery-rate state at that moment.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Batch {
    /// Position of the batch's first byte: bytes before it that no batch
    /// records (those sent before the sample state was kept, such as the
    /// preamble ahead of the peer's parameters) give no RTT sample.
    pub(crate) start: u64,
    /// Position after the batch.
    pub(crate) end: u64,
    pub(crate) time: Instant,
    /// The batch holds an ack-eliciting frame.
    pub(crate) eliciting: bool,
    /// Its acknowledgement is waited for by failure detection: false for
    /// what was sent before multipath was in use (MULTIPATH.md Section
    /// 7.1 starts with the session's data).
    pub(crate) watched: bool,
    pub(crate) delivered: u64,
    pub(crate) delivered_time: Instant,
    pub(crate) first_sent_time: Instant,
    /// Sent before the pipe's first acknowledgement advance.
    pub(crate) before_first_ack: bool,
    /// The pipe's bottleneck epoch at sending: a sample is not
    /// application-limited when the pipe refused bytes while data waited
    /// between the send and the acknowledgement.
    pub(crate) bottleneck_epoch: u64,
    /// Sent while an application-limited bubble was in flight (BBR's
    /// `app_limited` mark).
    pub(crate) in_bubble: bool,
    /// Bytes queued ahead of the batch in the carrier (queue_p).
    pub(crate) unsent_ahead: u64,
    /// The lane of the pipe it went on (MULTIPATH.md Section 2.5); its
    /// positions are the pipe's send order.
    pub(crate) lane: u32,
    /// The acknowledgement time expected at sending, E of MULTIPATH.md
    /// Section 7.5.1: (unsent_ahead + L) / R_p + min_rtt_p + the peer's
    /// max ACK delay, with the estimates of that moment.
    pub(crate) expect: Duration,
}

/// RFC 9002 initial smoothed RTT.
pub(crate) const INITIAL_RTT: Duration = Duration::from_millis(333);
/// The initial delivery rate, 1 MB/s.
pub(crate) const INITIAL_RATE: u64 = 1_000_000;
const RATE_WINDOW: Duration = Duration::from_secs(10);
const RATE_ROUNDS: u64 = 10;

/// RTT and delivery-rate estimates of an outbound pipe.
#[derive(Debug, Clone)]
pub(crate) struct Estimator {
    pub(crate) srtt: Duration,
    pub(crate) rttvar: Duration,
    pub(crate) latest: Option<Duration>,
    /// min_rtt: the minimum over the last 300 s, kept while no sample was
    /// taken in that window; also the pipe_min_rtt of auto-tuning and of
    /// the low-water mark without a carrier minimum.
    pub(crate) min_rtt: super::filter::MinFilter,
    /// Whether an RTT sample was taken (else the initial values apply).
    pub(crate) sampled: bool,
    pub(crate) last_sample: Option<Instant>,
    /// Delivery rate R_p in bytes per second: `peak`, or the carrier queue
    /// limiter's rate bound below it.
    pub(crate) rate: u64,
    /// The maximum of the delivery-rate samples in the window.
    pub(crate) peak: u64,
    /// The limiter's rate bound R_lo.
    pub(crate) rate_lo: Option<u64>,
    pub(crate) rate_sampled: bool,
    /// A sample was taken while the pipe was the bottleneck: the rate is
    /// measured, not only a lower bound.
    pub(crate) rate_measured: bool,
    /// A penalty measured the pipe slow (MULTIPATH.md Section 7.5.1): like
    /// a bottleneck sample, it ends the placement rate.
    pub(crate) penalized: bool,
    /// The round trip in which the placement rate first counted for more
    /// than R_p: it lasts four of the pipe's round trips from then. Set
    /// where a spreading policy places data, which reads the estimates
    /// only.
    pub(crate) placed_from: Cell<Option<u64>>,
    rate_window: VecDeque<(Instant, u64, u64)>,
    pub(crate) round: u64,
    pub(crate) round_end: u64,
    pub(crate) delivered_time: Instant,
    pub(crate) first_sent_time: Instant,
}

impl Estimator {
    pub(crate) fn new(initial_rtt: Duration, now: Instant) -> Self {
        Self {
            srtt: initial_rtt,
            rttvar: initial_rtt / 2,
            latest: None,
            min_rtt: super::filter::MinFilter::default(),
            sampled: false,
            last_sample: None,
            rate: INITIAL_RATE,
            peak: INITIAL_RATE,
            rate_lo: None,
            rate_sampled: false,
            rate_measured: false,
            penalized: false,
            placed_from: Cell::new(None),
            rate_window: VecDeque::new(),
            round: 0,
            round_end: 0,
            delivered_time: now,
            first_sent_time: now,
        }
    }

    /// An RTT sample (RFC 9002 Section 5.3) with the peer's ACK Delay,
    /// already capped; returns the adjusted RTT.
    pub(crate) fn rtt_sample(
        &mut self,
        latest: Duration,
        ack_delay: Duration,
        now: Instant,
    ) -> Duration {
        self.latest = Some(latest);
        self.last_sample = Some(now);
        self.min_rtt.sample(now, latest, super::filter::LOOP_SPAN);
        let min_rtt = self.min_rtt.get().unwrap_or(latest);
        let adjusted = if latest >= min_rtt + ack_delay {
            latest - ack_delay
        } else {
            latest
        };
        let prev = self.sampled.then_some((self.srtt, self.rttvar));
        (self.srtt, self.rttvar) =
            super::filter::smooth_rtt(prev.map(|p| p.0), prev.map(|p| p.1), adjusted, latest);
        self.sampled = true;
        adjusted
    }

    /// A delivery-rate sample in bytes per second.
    pub(crate) fn rate_sample(&mut self, rate: u64, app_limited: bool, now: Instant) {
        self.rate_measured |= !app_limited;
        if app_limited && rate <= self.rate {
            return;
        }
        while self.rate_window.back().is_some_and(|&(_, _, r)| r <= rate) {
            self.rate_window.pop_back();
        }
        self.rate_window.push_back((now, self.round, rate));
        self.rate_sampled = true;
        self.expire_rates(now);
    }

    /// Sets the limiter's rate bound R_lo (`None` drops it).
    pub(crate) fn set_rate_lo(&mut self, lo: Option<u64>) {
        self.rate_lo = lo;
        self.bound();
    }

    /// R_p: the windowed maximum within the rate bound.
    fn bound(&mut self) {
        self.rate = self.rate_lo.map_or(self.peak, |lo| lo.min(self.peak));
    }

    /// Drops the samples older than 10 rounds or 10 s, as time and the
    /// rounds pass, not only when a new sample comes: the maximum is then
    /// that of the samples left. An empty window keeps the last value of
    /// R_p, so idle periods never lower it, and a sample that left the
    /// window never comes back when the rate bound is dropped.
    pub(crate) fn expire_rates(&mut self, now: Instant) {
        let round = self.round;
        while self.rate_window.front().is_some_and(|&(t, rd, _)| {
            rd + RATE_ROUNDS < round || now.saturating_duration_since(t) > RATE_WINDOW
        }) {
            self.rate_window.pop_front();
        }
        if !self.rate_sampled {
            return;
        }
        // An empty window keeps the maximum it had: the filter's value,
        // not the limiter's bound on it.
        if let Some(&(_, _, r)) = self.rate_window.front() {
            self.peak = r;
        }
        self.bound();
    }

    /// Opportunistic-reinjection penalty (MULTIPATH.md Section 7.5.1).
    pub(crate) fn penalize(&mut self) {
        self.penalized = true;
        self.rate_window.clear();
        self.peak = (self.rate / 2).max(1);
        self.bound();
    }

    /// PTO without the queue term (RFC 9002 Section 6.2.1).
    pub(crate) fn pto(&self, peer_max_ack_delay: Duration) -> Duration {
        self.srtt + (self.rttvar * 4).max(Duration::from_millis(1)) + peer_max_ack_delay
    }

    /// The minimum RTT, or the smoothed RTT before the first sample.
    pub(crate) fn min_or_srtt(&self) -> Duration {
        self.min_rtt.get().unwrap_or(self.srtt)
    }
}

/// An RTT sample.
#[derive(Debug, Clone, Copy)]
pub(crate) struct RttSample {
    /// latest_rtt: from handing the batch to the carrier to the
    /// acknowledgement.
    pub(crate) latest: Duration,
    /// latest_rtt minus the capped ACK Delay, when that stays at or above
    /// min_rtt.
    pub(crate) adjusted: Duration,
    /// The bytes the carrier held ahead of the batch when it was handed on
    /// (unsent_ahead, zero on a carrier that does not report them).
    pub(crate) unsent_ahead: u64,
    /// When the sampled byte was handed to the carrier.
    pub(crate) sent_at: Instant,
}

/// What one advance of an outbound pipe's acknowledged position measured: the
/// samples the estimators took, which are
/// also the inputs of the carrier queue limiter.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct AckSample {
    /// The RTT sample, when the advance gave one.
    pub(crate) rtt: Option<RttSample>,
    /// The delivery-rate sample in bytes per second, and whether it is
    /// application-limited.
    pub(crate) rate: Option<(u64, bool)>,
    /// A round trip ended.
    pub(crate) round_end: bool,
    /// min_rtt changed.
    pub(crate) min_moved: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A sample that left the window is gone for good: once the old
    /// maximum of a pipe that slowed down ages out, R_p is the maximum of
    /// the samples left, and dropping the limiter's rate bound then does
    /// not bring the old maximum back.
    #[test]
    fn aged_samples_leave_the_maximum_without_new_ones() {
        let t0 = Instant::now();
        let mut est = Estimator::new(INITIAL_RTT, t0);
        est.rate_sample(12_500_000, false, t0);
        est.rate_sample(2_500_000, false, t0 + Duration::from_secs(2));
        est.set_rate_lo(Some(2_500_000));
        assert_eq!(est.rate, 2_500_000);
        // Acknowledgements of application-limited data only, past 10 s.
        est.expire_rates(t0 + Duration::from_secs(11));
        assert_eq!(est.peak, 2_500_000);
        est.set_rate_lo(None);
        assert_eq!(est.rate, 2_500_000);
        // Then the window empties: the last R_p is kept.
        est.expire_rates(t0 + Duration::from_secs(13));
        assert_eq!(est.rate, 2_500_000);
    }
}
