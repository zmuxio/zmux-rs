//! The carrier queue limiter.
//!
//! A carrier that neither reports its unsent bytes nor has a low-water mark
//! (a TLS or WebSocket library with its own buffer, an in-process pipe, a
//! user adapter) accepts bytes until its own buffer is full, and that
//! buffer becomes the queue in front of every urgent frame. On such a pipe
//! the sender paces itself in the manner of BBR from what the peer
//! acknowledges, and from nothing else: the inputs are the RTT and
//! delivery-rate samples of PIPE_ACK, the bytes in
//! flight and the round trips of the delivery-rate estimator.
//!
//! The estimates reach the limiter through one call per acknowledgement
//! that advances the pipe's position ([`SessionCore::pace_ack`] with an
//! [`AckEvent`]) and one per batch handed to the carrier
//! ([`Limiter::on_sent`]); a multipath session feeds every outbound pipe,
//! and a single pipe with pipe acknowledgement (MULTIPATH.md Section 3.5)
//! feeds pipe 0 the same way. Everything is constant work per event
//! (amortised): the standing queue is a three-sample windowed minimum,
//! r_q the exact maximum of its window, the gain cycle a phase and its
//! start, the pacing a token bucket refilled with the time that elapsed.

use std::time::{Duration, Instant};

use super::estimator::{AckSample, Estimator, RttSample};
use super::filter::{MinFilter, SlidingMax};

/// The timer granularity G the drivers honour: they never arm a timer
/// earlier than 1 ms from now, so a paced pipe wakes at most 1000 times a
/// second, and each wake-up releases a quantum of gain x R_p x G.
pub(crate) const GRANULARITY: Duration = Duration::from_millis(1);
/// The start-up gain 2 / ln 2, and the drain gain its inverse.
const STARTUP_GAIN: f64 = 2.885;
/// The gains of the cycle after the drain, each for max(RTT_base, 1 ms),
/// but the 0.75 phase ([`DOWN`]).
const CYCLE: [f64; 8] = [1.25, 0.75, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0];
/// The 0.75 phase lasts until the bytes in flight are at most R_p x
/// RTT_base_p + A, and at most this many phase durations (BBR v2's
/// ProbeBW_DOWN).
const DOWN: usize = 1;
const DOWN_PHASES: u32 = 4;
/// The pacing bucket holds up to this many quanta.
const BUCKET_QUANTA: f64 = 2.0;
/// Start-up ends once R_p has not grown by this factor over three round
/// trips.
const FULL_GROWTH: f64 = 1.25;
const FULL_ROUNDS: u8 = 3;
/// A probe follows 10 s without a sample near the base: within B + A / R_p
/// + RTT_base_p / 8 of it.
const BASE_SPAN: Duration = Duration::from_secs(10);
const BASE_TOLERANCE: u32 = 8;
/// ... or max(1 s, 8 x RTT_base) without one the in-flight cap explains.
pub(super) const EXPLAINED_SPAN: Duration = Duration::from_secs(1);
const EXPLAINED_BASES: u32 = 8;
/// A probe lasts at least max(200 ms, smoothed_rtt).
const PROBE_MIN: Duration = Duration::from_millis(200);
/// r_q is the largest bottleneck sample of the last max(500 ms, 4 x
/// RTT_base).
const RQ_SPAN: Duration = Duration::from_millis(500);
const RQ_BASES: u32 = 4;
/// A rate bound that no later probe set again lapses after 10 s.
const RATE_BOUND_LIFE: Duration = Duration::from_secs(10);

/// The session's values the limiter uses.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Params {
    /// The latency budget B.
    pub(crate) budget: Duration,
    /// The peer's `zmux_ack_threshold`.
    pub(crate) threshold: u64,
    /// The peer's `zmux_max_ack_delay`.
    pub(crate) max_ack_delay: Duration,
    /// `spread_chunk`.
    pub(crate) chunk: u64,
    /// Ablation switches (test hooks only): pacing, the rate bound, the
    /// span without an explained sample that starts a probe, the relative
    /// term of the base-refresh tolerance, a probe that ends unmeasured,
    /// the drain exit at R_p x RTT_base_p + A, and start-up counting
    /// application-limited round trips.
    pub(crate) pacing: bool,
    pub(crate) rate_bound: bool,
    pub(crate) explained_span: Duration,
    pub(crate) relative_tolerance: bool,
    pub(crate) probe_end_due: bool,
    pub(crate) drain_plus_slack: bool,
    pub(crate) startup_counts_all: bool,
}

impl Params {
    /// A = min(the peer's threshold, R_p x its max_ack_delay) +
    /// spread_chunk: what the peer may leave unacknowledged.
    fn slack(&self, rate: u64) -> u64 {
        let delayed = (rate as f64 * self.max_ack_delay.as_secs_f64()) as u64;
        self.threshold.min(delayed).saturating_add(self.chunk)
    }

    /// The time `bytes` take at `rate`.
    fn at(bytes: u64, rate: u64) -> Duration {
        Duration::from_secs_f64(bytes as f64 / rate.max(1) as f64)
    }
}

/// One acknowledgement that advanced a pipe's position: the samples the
/// estimator took, and the positions after it.
#[derive(Debug, Clone, Copy)]
pub(crate) struct AckEvent<'a> {
    pub(crate) sample: &'a AckSample,
    /// The acknowledged position.
    pub(crate) acked: u64,
    /// The position after the last ack-eliciting batch (or the
    /// acknowledged one, when that is further): the in-flight cap and a
    /// probe's drain count up to it, since nothing makes the peer
    /// acknowledge records that elicit nothing (RFC 9002 Section 2).
    pub(crate) sent: u64,
    /// The held bytes, which the bytes in flight leave out.
    pub(crate) held: Held,
}

/// The held bytes of a pipe with lanes: bytes
/// acknowledged on their own lanes beyond the cumulative point, now and
/// their smallest count over the last RTT_base_p.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Held {
    pub(crate) now: u64,
    pub(crate) min: u64,
}

/// The limiter's phase.
#[derive(Debug, Clone, Copy)]
enum Mode {
    /// Gain 2.885 until R_p stops growing: its last growth step and the
    /// round trips since without 25 % more.
    Startup { full: u64, flat: u8 },
    /// Gain 1 / 2.885 until the queue start-up built is gone.
    Drain,
    /// The cycle of 1.25, 0.75 and six times 1.
    Cruise(Cycle),
    /// The in-flight cap is A while the base is measured again.
    Probe(Probe),
}

/// A phase of the gain cycle and when it began.
#[derive(Debug, Clone, Copy)]
struct Cycle {
    phase: usize,
    since: Instant,
}

impl Cycle {
    fn start(now: Instant) -> Self {
        Self {
            phase: 0,
            since: now,
        }
    }

    /// The cycle at `t` as it runs on from `self` with phases of `unit`,
    /// the 0.75 phase over at once when `down_done` (the bytes in flight
    /// are low enough) and lasting [`DOWN_PHASES`] units otherwise; and
    /// the integral of the gain from `self.since` to `t`, in seconds. The
    /// bytes in flight and the unit change only with the limiter's events,
    /// which settle the cycle first, so between two events they are
    /// constant: whole cycles are skipped in one step.
    fn walk(self, t: Instant, unit: Duration, down_done: bool) -> (Self, f64) {
        let unit = unit.as_nanos().max(1);
        let len = |k: usize| match k {
            DOWN if down_done => 0,
            DOWN => unit * u128::from(DOWN_PHASES),
            _ => unit,
        };
        let mut left = t.saturating_duration_since(self.since).as_nanos();
        let mut k = self.phase;
        let mut start = 0u128;
        let mut gain = 0.0;
        let whole = |k: usize, start: &mut u128, left: &mut u128, gain: &mut f64| {
            let l = len(k);
            if *left < l {
                return false;
            }
            *gain += CYCLE[k] * l as f64;
            *start += l;
            *left -= l;
            true
        };
        if whole(k, &mut start, &mut left, &mut gain) {
            k = (k + 1) % CYCLE.len();
            let period: u128 = (0..CYCLE.len()).map(len).sum();
            let n = left / period;
            gain += n as f64
                * (0..CYCLE.len())
                    .map(|i| CYCLE[i] * len(i) as f64)
                    .sum::<f64>();
            start += n * period;
            left -= n * period;
            // Within one period: at most a phase of each.
            while whole(k, &mut start, &mut left, &mut gain) {
                k = (k + 1) % CYCLE.len();
            }
        }
        gain += CYCLE[k] * left as f64;
        let since = u64::try_from(start)
            .ok()
            .and_then(|n| self.since.checked_add(Duration::from_nanos(n)))
            .unwrap_or(t);
        (Self { phase: k, since }, gain / 1e9)
    }
}

/// A base refresh in progress.
#[derive(Debug, Clone, Copy)]
struct Probe {
    since: Instant,
    /// max(200 ms, smoothed_rtt) at its start.
    length: Duration,
    /// The send position at its start: the old queue is gone once the
    /// acknowledged position reaches it.
    start_sent: u64,
    /// When the old queue was gone.
    drained_at: Option<Instant>,
    /// The base before the probe.
    old_base: Duration,
    /// The minimum u of bytes sent after the old queue was gone: the base
    /// the probe measures (the samples of the bytes in flight when it began
    /// carry the queue it is there to drain).
    after_drain: Option<Duration>,
    /// The largest recent bottleneck rate sample at its start.
    r_q: Option<u64>,
}

/// The carrier queue limiter of one outbound pipe.
#[derive(Debug, Clone)]
pub(crate) struct Limiter {
    mode: Mode,
    /// RTT_base_p, kept as BBR keeps min_rtt: the smallest u so far, which
    /// only a probe replaces (with what it measured); one value, no window
    /// of samples. A base that slid with a window would take in the
    /// pipe's own standing queue whenever no sample came near the base for
    /// the window, the in-flight cap with it, and the queue further, step
    /// by step. A base that no sample came near for 10 s is measured again
    /// by a probe instead. The smoothed RTT applies before the first
    /// sample.
    base: Option<Duration>,
    /// The last sample within B + A / R_p + RTT_base_p / 8 of the base.
    near_at: Instant,
    /// The last sample within 2 x (RTT_base + B) + A / R_p of it.
    explained_at: Instant,
    /// u over the last max(smoothed_rtt / 2, the interval since the
    /// previous sample): S_p is its minimum minus the base.
    recent: MinFilter,
    last_sample: Option<Instant>,
    /// Bottleneck rate samples over max(500 ms, 4 x RTT_base) (r_q).
    bottleneck: SlidingMax,
    /// The largest bottleneck sample of the current round trip.
    round_max: u64,
    /// When a probe last set the rate bound R_lo.
    bound_set: Option<Instant>,
    /// The token bucket: bytes that may leave now, at the last refill
    /// (`None` at the start: a full quantum).
    tokens: Option<f64>,
    refilled: Instant,
    /// The bytes in flight at the last event: from the acknowledged
    /// position to the end of the last ack-eliciting byte (RFC 9002 Section 2).
    in_flight: u64,
    /// Held back now; when the bucket lets it go again (`None`: when an
    /// acknowledgement makes room under the cap).
    held: bool,
    release: Option<Instant>,
}

impl Limiter {
    pub(crate) fn new(now: Instant) -> Self {
        Self {
            mode: Mode::Startup { full: 0, flat: 0 },
            base: None,
            near_at: now,
            explained_at: now,
            recent: MinFilter::default(),
            last_sample: None,
            bottleneck: SlidingMax::default(),
            round_max: 0,
            bound_set: None,
            tokens: None,
            refilled: now,
            in_flight: 0,
            held: false,
            release: None,
        }
    }

    /// Whether the limiter holds the pipe back (it is not writable for the
    /// scheduler).
    pub(crate) fn held(&self) -> bool {
        self.held
    }

    /// When a held pipe may send again without an acknowledgement.
    pub(crate) fn release(&self) -> Option<Instant> {
        self.release.filter(|_| self.held)
    }

    /// RTT_base_p.
    fn base(&self, est: &Estimator) -> Duration {
        self.base.unwrap_or(est.srtt)
    }

    /// Past start-up, cruising with RTT_base_p `base` (tests).
    #[cfg(test)]
    pub(crate) fn cruise(&mut self, base: Duration, now: Instant) {
        self.mode = Mode::Cruise(Cycle::start(now));
        self.base = Some(base);
    }

    /// RTT_base_p, the window of the held bytes' minimum.
    pub(crate) fn base_rtt(&self, est: &Estimator) -> Duration {
        self.base(est)
    }

    /// The held bytes left out of the bytes in flight (Section 9.1): all
    /// of them during start-up, their smallest count over the last
    /// RTT_base_p afterwards.
    pub(crate) fn left_out(&self, held: Held) -> u64 {
        match self.mode {
            Mode::Startup { .. } => held.now,
            _ => held.min,
        }
    }

    /// Heap bytes held.
    pub(crate) fn memory(&self) -> usize {
        self.bottleneck.memory()
    }

    /// The unit of the gain cycle: max(RTT_base_p, 1 ms).
    fn unit(&self, est: &Estimator) -> Duration {
        self.base(est).max(GRANULARITY)
    }

    /// The 0.75 phase is over: at most R_p x RTT_base_p + A in flight.
    fn down_done(&self, est: &Estimator, p: &Params) -> bool {
        let bdp = (est.rate as f64 * self.base(est).as_secs_f64()) as u64;
        self.in_flight <= bdp.saturating_add(p.slack(est.rate))
    }

    /// The pacing gain at `now`.
    fn gain(&self, now: Instant, est: &Estimator, p: &Params) -> f64 {
        match self.mode {
            Mode::Startup { .. } => STARTUP_GAIN,
            Mode::Drain => 1.0 / STARTUP_GAIN,
            Mode::Cruise(c) => {
                let (c, _) = c.walk(now, self.unit(est), self.down_done(est, p));
                CYCLE[c.phase]
            }
            Mode::Probe(_) => 1.0,
        }
    }

    /// The pacing rate and quantum: gain x R_p, and max(2 x spread_chunk,
    /// gain x R_p x G).
    fn pace(&self, now: Instant, est: &Estimator, p: &Params) -> (f64, f64) {
        let rate = self.gain(now, est, p) * est.rate.max(1) as f64;
        let quantum = (2 * p.chunk) as f64;
        (rate, quantum.max(rate * GRANULARITY.as_secs_f64()))
    }

    /// The integral of the pacing gain over `[from, to]`, in seconds: each
    /// phase of the cycle counts with its own gain. Charging a whole
    /// refill interval at the gain of its end would favour the phase a
    /// held pipe wakes up in, and overrun R_p (by about 0.2 % with
    /// chunk-sized sends, a queue that grows by milliseconds a second).
    fn gain_time(&self, from: Instant, to: Instant, est: &Estimator, p: &Params) -> f64 {
        let Mode::Cruise(c) = self.mode else {
            return self.gain(to, est, p) * to.saturating_duration_since(from).as_secs_f64();
        };
        let (unit, done) = (self.unit(est), self.down_done(est, p));
        (c.walk(to, unit, done).1 - c.walk(from, unit, done).1).max(0.0)
    }

    /// The bucket at `now`: it fills with the time that elapsed at the
    /// pacing rate, up to two quanta.
    fn tokens(&self, now: Instant, est: &Estimator, p: &Params) -> f64 {
        let (_, quantum) = self.pace(now, est, p);
        let Some(tokens) = self.tokens else {
            return quantum;
        };
        let credit = est.rate.max(1) as f64 * self.gain_time(self.refilled, now, est, p);
        (tokens + credit).min(BUCKET_QUANTA * quantum)
    }

    /// Settles the bucket at `now`, at the gain that applied so far, and
    /// spends `bytes` from it.
    fn settle(&mut self, now: Instant, bytes: u64, est: &Estimator, p: &Params) {
        self.tokens = Some(self.tokens(now, est, p) - bytes as f64);
        self.refilled = now;
    }

    /// Brings the bucket and the gain cycle to `now`, as they ran with the
    /// bytes in flight of the last event; then takes `in_flight` as the
    /// bytes in flight from now on, which may end the 0.75 phase.
    fn advance(&mut self, now: Instant, in_flight: u64, est: &Estimator, p: &Params) {
        self.settle(now, 0, est, p);
        if let Mode::Cruise(c) = self.mode {
            let (c, _) = c.walk(now, self.unit(est), self.down_done(est, p));
            self.mode = Mode::Cruise(c);
        }
        self.in_flight = in_flight;
        let done = self.down_done(est, p);
        if let Mode::Cruise(c) = &mut self.mode
            && c.phase == DOWN
            && done
        {
            *c = Cycle {
                phase: DOWN + 1,
                since: now,
            };
        }
    }

    /// The in-flight cap: 2 x R_p x (RTT_base_p + B) + A, or A during a
    /// probe.
    fn cap(&self, est: &Estimator, p: &Params) -> u64 {
        let a = p.slack(est.rate);
        if matches!(self.mode, Mode::Probe(_)) {
            return a;
        }
        let span = self.base(est) + p.budget;
        (2.0 * est.rate as f64 * span.as_secs_f64()) as u64 + a
    }

    /// Bytes of stream data the pipe may take now: none while the bucket is
    /// empty or the in-flight cap reached, else what the bucket holds
    /// within the room under the cap, rounded up to whole chunks. The
    /// pipe so takes full chunks, never a fragment of what refilled since
    /// the last batch, and a frame that starts within the room goes whole
    /// (the writer never cuts one at the room): the bucket and the cap may
    /// be overrun by less than a chunk or a frame, a debt the bucket pays
    /// before the pipe is let go again.
    pub(crate) fn room(&self, now: Instant, in_flight: u64, est: &Estimator, p: &Params) -> u64 {
        let tokens = if p.pacing {
            self.tokens(now, est, p)
        } else {
            f64::MAX
        };
        let cap = self.cap(est, p);
        if tokens < 1.0 || in_flight >= cap {
            return 0;
        }
        let room = (tokens as u64).min(cap - in_flight).max(1);
        let chunk = p.chunk.max(1);
        room.div_ceil(chunk).saturating_mul(chunk)
    }

    /// Re-evaluates whether the pipe is held back, and until when, with
    /// `in_flight` bytes in flight: an empty bucket refills by itself,
    /// which the session's timer deadline wakes up for, a full cap only
    /// with an acknowledgement.
    ///
    /// The drivers arm a timer no earlier than G from now and it fires on
    /// a tick of their clock, so a pipe the bucket held is let go up to 2 x
    /// G after its release time, later still on a busy host. The bucket
    /// holds what accrued meanwhile, up to two quanta: cut at one, the
    /// lateness of every wake-up would be lost to the pacing rate (a third
    /// of it at quantum = R_p x G with wake-ups 1 to 2 ms apart), more than
    /// the cycle's probing gain makes up, and R_p would fall round by round
    /// while the RTT stays at the base.
    pub(crate) fn refresh(&mut self, now: Instant, in_flight: u64, est: &Estimator, p: &Params) {
        self.advance(now, in_flight, est, p);
        self.held = self.room(now, in_flight, est, p) == 0;
        self.release = None;
        let tokens = self.tokens(now, est, p);
        if self.held && p.pacing && tokens < 1.0 {
            let (rate, _) = self.pace(now, est, p);
            // Rounded up, so that the bucket holds a byte then.
            let wait = (1.0 - tokens) / rate + 1e-6;
            self.release = Duration::try_from_secs_f64(wait)
                .ok()
                .and_then(|w| now.checked_add(w));
        }
    }

    /// A batch of `bytes` was handed to the carrier. The bucket pays for
    /// all of it, as R_p counts it, though only stream data, reinjection
    /// and copies wait for the bucket: control frames are never held back.
    pub(crate) fn on_sent(&mut self, now: Instant, bytes: u64, est: &Estimator, p: &Params) {
        self.settle(now, bytes, est, p);
    }

    /// S_p: the standing queue.
    fn standing(&self, est: &Estimator) -> Duration {
        self.recent
            .get()
            .map_or(Duration::ZERO, |u| u.saturating_sub(self.base(est)))
    }

    /// An acknowledgement advanced the pipe's position: its samples, the
    /// round trip it ended, the phase changes it brings and the rate bound
    /// R_lo, which it sets in `est`.
    pub(crate) fn on_ack(
        &mut self,
        now: Instant,
        ev: &AckEvent<'_>,
        est: &mut Estimator,
        p: &Params,
    ) {
        // The bucket and the cycle are settled at the gain, mode and bytes
        // in flight that applied so far.
        self.advance(now, self.in_flight, est, p);
        // The probe rules judge the samples before this one, as if checked
        // continuously: a probe that came due since the last
        // acknowledgement starts now, not only if this one's samples, too,
        // stay away from the base.
        if matches!(self.mode, Mode::Drain | Mode::Cruise(_)) {
            self.maybe_probe(now, ev, est, p);
        }
        let rate = est.rate.max(1);
        let a_time = Params::at(p.slack(rate), rate);
        if let Some(s) = &ev.sample.rtt {
            self.rtt_sample(now, s, est, p, a_time);
        }
        let base = self.base(est);
        if let Some((rate, false)) = ev.sample.rate {
            self.round_max = self.round_max.max(rate);
            let span = RQ_SPAN.max(base * RQ_BASES);
            self.bottleneck.update(now, rate, span);
        }
        if ev.sample.round_end {
            self.round_ended(est, p, a_time);
        }
        if let Some(lo) = est.rate_lo
            && (est.peak <= lo
                || self
                    .bound_set
                    .is_none_or(|t| now.saturating_duration_since(t) >= RATE_BOUND_LIFE))
        {
            est.set_rate_lo(None);
            self.bound_set = None;
        }
        // The bytes in flight from now on, without the held bytes the
        // phase leaves out.
        let in_flight = ev
            .sent
            .saturating_sub(ev.acked)
            .saturating_sub(self.left_out(ev.held));
        match &mut self.mode {
            Mode::Startup { .. } => {}
            Mode::Drain => {
                // The queue is gone, or at most max(R_p x RTT_base_p, A)
                // is in flight: the A bytes the peer may leave
                // unacknowledged stay in flight however empty the queue,
                // so on a path whose BDP is below A (a LAN) the bytes in
                // flight never fall to the BDP, and where timers jitter by
                // more than B, S_p <= B may never hold either. Not the BDP
                // plus A: that leaves up to A standing in the queue of
                // every pipe, which then needs a probe.
                let bdp = (est.rate as f64 * base.as_secs_f64()) as u64;
                let a = p.slack(est.rate);
                let exit = if p.drain_plus_slack {
                    bdp.saturating_add(a)
                } else {
                    bdp.max(a)
                };
                if self.standing(est) <= p.budget || in_flight <= exit {
                    self.mode = Mode::Cruise(Cycle::start(now));
                }
            }
            Mode::Cruise(_) => {}
            Mode::Probe(probe) => {
                if probe.drained_at.is_none() && ev.acked >= probe.start_sent {
                    probe.drained_at = Some(now);
                }
                // At least max(200 ms, smoothed_rtt), then until the old
                // queue is gone and a byte sent after it was measured (or
                // nothing is in flight): a probe that ended as the old
                // queue drained, without such a sample, would have
                // measured nothing, and missed the rate drop it was there
                // to find.
                let end = probe.since + probe.length;
                let measured = probe.after_drain.is_some() || ev.acked >= ev.sent;
                let over = now >= end
                    && probe
                        .drained_at
                        .is_some_and(|d| measured || (p.probe_end_due && d <= end));
                if over {
                    let probe = *probe;
                    self.end_probe(now, &probe, est, p);
                }
            }
        }
        self.refresh(now, in_flight, est, p);
    }

    /// A round trip of the pipe measured outside PIPE_ACK: the response to
    /// the QX_PING request of a single pipe's first record, which waited
    /// behind nothing and was answered at once, unlike the first PIPE_ACK,
    /// which may wait the peer's `zmux_max_ack_delay`.
    pub(crate) fn ping_sample(&mut self, now: Instant, rtt: Duration, est: &Estimator, p: &Params) {
        let rate = est.rate.max(1);
        let a_time = Params::at(p.slack(rate), rate);
        let s = RttSample {
            latest: rtt,
            adjusted: rtt,
            unsent_ahead: 0,
            sent_at: now.checked_sub(rtt).unwrap_or(now),
        };
        self.rtt_sample(now, &s, est, p, a_time);
    }

    fn rtt_sample(
        &mut self,
        now: Instant,
        s: &RttSample,
        est: &Estimator,
        p: &Params,
        a_time: Duration,
    ) {
        let ahead = Params::at(s.unsent_ahead, est.rate);
        let u = s.adjusted.saturating_sub(ahead);
        let gap = self
            .last_sample
            .map_or(Duration::ZERO, |t| now.saturating_duration_since(t));
        self.recent.sample(now, u, (est.srtt / 2).max(gap));
        self.last_sample = Some(now);
        if let Mode::Probe(probe) = &mut self.mode
            && probe.drained_at.is_some_and(|d| s.sent_at >= d)
        {
            probe.after_drain = Some(probe.after_drain.map_or(u, |m| m.min(u)));
        }
        if self.base.is_none_or(|b| u < b) {
            self.base = Some(u);
        }
        let base = self.base(est);
        let relative = if p.relative_tolerance {
            base / BASE_TOLERANCE
        } else {
            Duration::ZERO
        };
        if u <= base + p.budget + a_time + relative {
            self.near_at = now;
        }
        if u <= (base + p.budget) * 2 + a_time {
            self.explained_at = now;
        }
    }

    /// A round trip ended: start-up's growth test, and the rate bound
    /// follows a path that recovered.
    fn round_ended(&mut self, est: &mut Estimator, p: &Params, a_time: Duration) {
        let sampled = std::mem::take(&mut self.round_max);
        if let Mode::Startup { full, flat } = &mut self.mode
            && (sampled > 0 || p.startup_counts_all)
        {
            // As in BBR, rounds without a bottleneck sample (limited by
            // the application) say nothing of the path.
            if est.rate as f64 >= *full as f64 * FULL_GROWTH {
                *full = est.rate;
                *flat = 0;
            } else {
                *flat += 1;
                if *flat >= FULL_ROUNDS {
                    self.mode = Mode::Drain;
                }
            }
        }
        if let Some(lo) = est.rate_lo
            && sampled > lo
            && self.standing(est) <= p.budget + a_time
        {
            est.set_rate_lo(Some(sampled));
        }
    }

    /// Starts a probe when no sample was near the base for 10 s, or none
    /// within what the cap can queue for max(1 s, 8 x RTT_base).
    fn maybe_probe(&mut self, now: Instant, ev: &AckEvent<'_>, est: &Estimator, p: &Params) {
        let base = self.base(est);
        let far = now.saturating_duration_since(self.near_at) >= BASE_SPAN;
        let unexplained = now.saturating_duration_since(self.explained_at)
            >= p.explained_span.max(base * EXPLAINED_BASES);
        if !far && !unexplained {
            return;
        }
        let span = RQ_SPAN.max(base * RQ_BASES);
        self.mode = Mode::Probe(Probe {
            since: now,
            length: PROBE_MIN.max(est.srtt),
            start_sent: ev.sent,
            drained_at: (ev.acked >= ev.sent).then_some(now),
            old_base: base,
            after_drain: None,
            r_q: self.bottleneck.within(now, span),
        });
    }

    /// The probe is over: the base is measured again, unless a byte sent
    /// after the old queue was gone came back near the old base, which
    /// shows the queue was the sender's and the path slower: then the
    /// old base stays and R_lo = r_q.
    fn end_probe(&mut self, now: Instant, probe: &Probe, est: &mut Estimator, p: &Params) {
        let old = probe.old_base;
        let unchanged = match (probe.after_drain, probe.r_q) {
            (Some(u), Some(r_q)) => u <= old + p.budget + Params::at(p.slack(r_q), r_q),
            _ => false,
        };
        // The base is what the probe measured: older samples, from before
        // the path's delay may have changed, no longer count; when the
        // probe found the path slower, not longer, the old base stays.
        let base = match probe
            .r_q
            .filter(|&r| unchanged && r < est.rate && p.rate_bound)
        {
            Some(r_q) => {
                est.set_rate_lo(Some(r_q));
                self.bound_set = Some(now);
                Some(old)
            }
            None => probe.after_drain,
        };
        if base.is_some() {
            self.base = base;
        }
        self.near_at = now;
        self.explained_at = now;
        self.mode = Mode::Cruise(Cycle::start(now));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MS: Duration = Duration::from_millis(1);

    fn params() -> Params {
        Params {
            budget: Duration::from_micros(100),
            threshold: 64 * 1024,
            max_ack_delay: 25 * MS,
            chunk: 16 * 1024,
            pacing: true,
            rate_bound: true,
            explained_span: EXPLAINED_SPAN,
            relative_tolerance: true,
            probe_end_due: false,
            drain_plus_slack: false,
            startup_counts_all: false,
        }
    }

    /// A pipe of `rate` bytes per second and `rtt` that the limiter paces:
    /// it sends what the limiter allows each millisecond, the path
    /// delivers at its rate after `rtt`, and the peer acknowledges every
    /// millisecond.
    struct Path {
        lim: Limiter,
        est: Estimator,
        now: Instant,
        rate: u64,
        rtt: Duration,
        sent: u64,
        acked: u64,
        /// The batches in flight: send time, end position, and the
        /// acknowledged position and its time at sending.
        flight: std::collections::VecDeque<(Instant, u64, u64, Instant)>,
        /// When the path has delivered everything sent so far.
        busy_until: Instant,
        /// Delivered position and when.
        arrivals: std::collections::VecDeque<(Instant, u64)>,
        round_end: u64,
        last_ack: (Instant, u64),
    }

    impl Path {
        fn new(rate: u64, rtt: Duration) -> Self {
            let now = Instant::now();
            Self {
                lim: Limiter::new(now),
                est: Estimator::new(super::super::pipes::INITIAL_RTT, now),
                now,
                rate,
                rtt,
                sent: 0,
                acked: 0,
                flight: Default::default(),
                busy_until: now,
                arrivals: Default::default(),
                round_end: 0,
                last_ack: (now, 0),
            }
        }

        /// One millisecond: the sender sends what the limiter allows (it
        /// always has data), and acknowledgements of what arrived come
        /// back.
        fn step(&mut self) {
            let p = params();
            self.now += MS;
            let now = self.now;
            // Acknowledgements of bytes that arrived rtt/2 ago (one way
            // each way).
            let mut ack = None;
            while let Some(&(t, pos)) = self.arrivals.front() {
                if t + self.rtt / 2 > now {
                    break;
                }
                self.arrivals.pop_front();
                ack = Some(pos);
            }
            if let Some(pos) = ack.filter(|&p| p > self.acked) {
                let &(t_sent, ..) = self.flight.iter().find(|f| f.1 >= pos).unwrap();
                let rtt = now - t_sent;
                self.est.rtt_sample(rtt, Duration::ZERO, now);
                // Over the flight of the last batch covered.
                let &(_, _, delivered, at) = self
                    .flight
                    .iter()
                    .take_while(|f| f.1 <= pos)
                    .last()
                    .unwrap();
                let interval = now.saturating_duration_since(at).max(MS);
                let rate = ((pos - delivered) as f64 / interval.as_secs_f64()) as u64;
                self.est.rate_sample(rate, false, now);
                self.last_ack = (now, pos);
                self.acked = pos;
                let round_end = pos >= self.round_end;
                if round_end {
                    self.est.round += 1;
                    self.round_end = self.sent;
                }
                while self.flight.front().is_some_and(|f| f.1 <= pos) {
                    self.flight.pop_front();
                }
                let sample = AckSample {
                    rtt: Some(RttSample {
                        latest: rtt,
                        adjusted: rtt,
                        unsent_ahead: 0,
                        sent_at: t_sent,
                    }),
                    rate: Some((rate, false)),
                    round_end,
                    min_moved: false,
                };
                let ev = AckEvent {
                    sample: &sample,
                    acked: pos,
                    sent: self.sent,
                    held: Held::default(),
                };
                self.lim.on_ack(now, &ev, &mut self.est, &p);
            }
            if self.lim.release().is_some_and(|t| t <= now) {
                self.lim.refresh(now, self.sent - self.acked, &self.est, &p);
            }
            let room = self.lim.room(now, self.sent - self.acked, &self.est, &p);
            if room > 0 && !self.lim.held() {
                let n = room.min(256 * 1024);
                self.sent += n;
                self.flight
                    .push_back((now, self.sent, self.acked, self.last_ack.0));
                // The path takes the bytes at its rate after what it holds.
                let start = self.busy_until.max(now);
                let done = start + Params::at(n, self.rate);
                self.busy_until = done;
                self.arrivals.push_back((done + self.rtt / 2, self.sent));
                self.lim.on_sent(now, n, &self.est, &p);
                self.lim.refresh(now, self.sent - self.acked, &self.est, &p);
            }
        }

        /// The queue at the path's bottleneck, in time.
        fn queue(&self) -> Duration {
            self.busy_until.saturating_duration_since(self.now)
        }

        fn run(&mut self, d: Duration) -> u64 {
            let start = self.acked;
            let steps = d.as_millis();
            for _ in 0..steps {
                self.step();
            }
            self.acked - start
        }
    }

    #[test]
    fn start_up_ends_and_the_queue_stays_small() {
        // 100 Mbit/s x 10 ms behind a carrier that hides any buffer.
        let rate = 12_500_000;
        let mut p = Path::new(rate, 10 * MS);
        p.run(Duration::from_secs(2));
        assert!(
            matches!(p.lim.mode, Mode::Cruise(_) | Mode::Probe(_)),
            "{:?}",
            p.lim.mode
        );
        let delivered = p.run(Duration::from_secs(2));
        let mbps = delivered as f64 * 8.0 / 2.0 / 1e6;
        assert!(mbps > 90.0, "{mbps} Mbit/s");
        // The queue is what the in-flight cap allows beyond the path's
        // BDP (about one round trip plus A / R_p, 17 ms here), not the
        // carrier's buffer, which the sender would otherwise fill.
        let mut worst = Duration::ZERO;
        for _ in 0..1000 {
            p.step();
            worst = worst.max(p.queue());
        }
        assert!(worst < 25 * MS, "queue {worst:?}");
    }

    #[test]
    fn a_rate_drop_is_bounded_within_a_probe() {
        // 100 Mbit/s x 100 ms, then 20 Mbit/s.
        let mut p = Path::new(12_500_000, 100 * MS);
        p.run(Duration::from_secs(15));
        p.rate = 2_500_000;
        p.run(Duration::from_millis(2500));
        // A probe found the base unchanged and bounded the rate: the
        // queue is gone, where R_p alone, a maximum over round trips the
        // queue lengthened, would keep about a second of it for 10 s.
        let mut worst = Duration::ZERO;
        for _ in 0..2500 {
            p.step();
            worst = worst.max(p.queue());
        }
        assert!(worst < 300 * MS, "queue {worst:?}");
        let delivered = p.run(Duration::from_secs(5));
        let mbps = delivered as f64 * 8.0 / 5.0 / 1e6;
        assert!(mbps > 17.0, "{mbps} Mbit/s");
    }

    #[test]
    fn a_delay_rise_is_learnt_not_taken_for_a_rate_drop() {
        // 10 Mbit/s whose one-way delay rises from 5 to 150 ms: the base
        // follows within seconds and the rate is not bounded.
        let mut p = Path::new(1_250_000, 10 * MS);
        p.run(Duration::from_secs(5));
        p.rtt = 300 * MS;
        p.run(Duration::from_secs(5));
        assert!(
            p.lim.base.is_some_and(|b| b >= 250 * MS),
            "base {:?}",
            p.lim.base
        );
        assert_eq!(p.est.rate_lo, None);
        let delivered = p.run(Duration::from_secs(5));
        let mbps = delivered as f64 * 8.0 / 5.0 / 1e6;
        assert!(mbps > 8.5, "{mbps} Mbit/s");
    }

    #[test]
    fn a_quiet_base_is_refreshed_after_ten_seconds() {
        let mut p = Path::new(12_500_000, 10 * MS);
        p.run(Duration::from_secs(3));
        // From now on the samples stay above the base by more than B + A /
        // R_p, within what the in-flight cap explains (a queue the cap
        // explains): the base stays, and is measured again by a probe 10 s
        // after the last sample near it.
        let p2 = params();
        let base = p.lim.base(&p.est);
        let t = p.now;
        let a_time = Params::at(p2.slack(p.est.rate), p.est.rate);
        let u = base * 3 / 2 + p2.budget + a_time;
        let late = AckSample {
            rtt: Some(RttSample {
                latest: u,
                adjusted: u,
                unsent_ahead: 0,
                sent_at: t,
            }),
            ..AckSample::default()
        };
        let ev = AckEvent {
            sample: &late,
            acked: p.acked,
            sent: p.sent,
            held: Held::default(),
        };
        let mut lim = p.lim.clone();
        let near = lim.near_at;
        let mut started = None;
        for i in 1..=40 {
            let now = t + 250 * MS * i;
            lim.on_ack(now, &ev, &mut p.est, &p2);
            if matches!(lim.mode, Mode::Probe(_)) {
                started = Some(now);
                break;
            }
            assert_eq!(lim.base(&p.est), base, "{i}");
        }
        let started = started.expect("a probe");
        let after = started.saturating_duration_since(near);
        assert!(
            after >= BASE_SPAN && after < BASE_SPAN + 250 * MS,
            "{after:?}"
        );
        // During the probe the cap is A.
        assert_eq!(lim.cap(&p.est, &p2), p2.slack(p.est.rate));
    }

    #[test]
    fn pacing_releases_quanta_at_most_once_per_granularity() {
        let p = params();
        let now = Instant::now();
        let mut est = Estimator::new(10 * MS, now);
        // 10 Gbit/s.
        est.rate_sample(1_250_000_000, false, now);
        let mut lim = Limiter::new(now);
        lim.mode = Mode::Cruise(Cycle::start(now));
        lim.base = Some(10 * MS);
        // A full quantum: gain x R_p x G, 1.25 MB in a phase of gain 1.
        let t = now + 3 * 10 * MS;
        let room = lim.room(t, 0, &est, &p);
        assert!((1_200_000..=1_300_000).contains(&room), "{room}");
        lim.on_sent(t, room, &est, &p);
        lim.refresh(t, 0, &est, &p);
        assert!(lim.held());
        let release = lim.release().unwrap();
        assert!(
            release > t && release - t < GRANULARITY,
            "{:?}",
            release - t
        );
        // A slow pipe with room under its cap: the quantum is two chunks.
        let mut est = Estimator::new(10 * MS, now);
        est.rate_sample(100_000, false, now);
        let mut lim = Limiter::new(now);
        lim.mode = Mode::Cruise(Cycle::start(now));
        lim.base = Some(Duration::from_secs(1));
        assert_eq!(lim.room(now, 0, &est, &p), 2 * p.chunk);
    }

    #[test]
    fn the_gain_is_charged_for_the_time_spent_in_each_phase() {
        // However a held pipe's refills fall on the phases, the gains of the
        // cycle are charged for the time spent in each, here with the 0.75
        // phase at its longest (the bytes in flight stay high): 1.25 for
        // one unit, 0.75 for four, 1 for six.
        let p = params();
        let now = Instant::now();
        let (mut lim, est) = cruising(12_500_000, 10 * MS, now);
        lim.refresh(now, u64::MAX / 2, &est, &p);
        let cycle = 10 * MS * 11;
        let mut t = now;
        let mut sum = 0.0;
        let step = Duration::from_micros(1300);
        while t + step <= now + cycle * 5 {
            sum += lim.gain_time(t, t + step, &est, &p);
            t += step;
        }
        sum += lim.gain_time(t, now + cycle * 5, &est, &p);
        let whole = 5.0 * (1.25 + 0.75 * 4.0 + 6.0) * 0.010;
        assert!((sum - whole).abs() < 1e-9, "{sum} vs {whole}");
        assert!((lim.gain_time(now, now + cycle * 5, &est, &p) - whole).abs() < 1e-9);
        // The first phase probes at 1.25.
        let first = lim.gain_time(now, now + 5 * MS, &est, &p);
        assert!((first - 1.25 * 0.005).abs() < 1e-9, "{first}");
    }

    #[test]
    fn the_down_phase_lasts_until_the_bytes_in_flight_fall() {
        // 100 Mbit/s x 10 ms: R_p x RTT_base_p + A is 125 kB + A.
        let p = params();
        let t0 = Instant::now();
        let rate = 12_500_000;
        let low = 125_000 + p.slack(rate);
        let gain = |lim: &Limiter, est: &Estimator, t: Duration| lim.gain(t0 + t, est, &p);
        // More in flight: the 0.75 phase lasts four units, 10 to 50 ms.
        let (mut lim, est) = cruising(rate, 10 * MS, t0);
        lim.refresh(t0, low + 1, &est, &p);
        assert_eq!(gain(&lim, &est, 5 * MS), 1.25);
        assert_eq!(gain(&lim, &est, 15 * MS), 0.75);
        assert_eq!(gain(&lim, &est, 45 * MS), 0.75);
        assert_eq!(gain(&lim, &est, 55 * MS), 1.0);
        // ... and ends as soon as they fall to it: six units of 1 follow,
        // then the next probe.
        lim.refresh(t0 + 20 * MS, low, &est, &p);
        assert_eq!(gain(&lim, &est, 20 * MS), 1.0);
        assert_eq!(gain(&lim, &est, 79 * MS), 1.0);
        assert_eq!(gain(&lim, &est, 81 * MS), 1.25);
        // Little in flight when the probe ends: no 0.75 phase at all.
        let (mut lim, est) = cruising(rate, 10 * MS, t0);
        lim.refresh(t0, low, &est, &p);
        assert_eq!(gain(&lim, &est, 11 * MS), 1.0);
        assert_eq!(gain(&lim, &est, 69 * MS), 1.0);
        assert_eq!(gain(&lim, &est, 71 * MS), 1.25);
        // A late event finds the cycle where it ran to without it.
        lim.refresh(t0 + 75 * MS, low + 1, &est, &p);
        assert_eq!(gain(&lim, &est, 79 * MS), 1.25);
        assert_eq!(gain(&lim, &est, 81 * MS), 0.75);
        assert_eq!(gain(&lim, &est, 119 * MS), 0.75);
        assert_eq!(gain(&lim, &est, 121 * MS), 1.0);
    }

    #[test]
    fn a_late_wake_up_sends_what_accrued_up_to_two_quanta() {
        // 100 Mbit/s, gain 1: a quantum of 2 x spread_chunk (32 KiB), more
        // than R_p x G (12.5 kB).
        let p = params();
        let t0 = Instant::now();
        let (mut lim, est) = cruising(12_500_000, 10 * MS, t0);
        lim.mode = Mode::Cruise(Cycle {
            phase: 2,
            since: t0,
        });
        let quantum = (2 * p.chunk) as f64;
        lim.on_sent(t0, 2 * p.chunk, &est, &p);
        lim.refresh(t0, 0, &est, &p);
        assert!(lim.held());
        let release = lim.release().unwrap();
        // Woken 3 ms late: what accrued since is sent, not cut at the
        // quantum; whole chunks.
        let late = release + 3 * MS;
        lim.refresh(late, 0, &est, &p);
        let accrued = lim.tokens(late, &est, &p);
        assert!(accrued > quantum, "{accrued}");
        let room = lim.room(late, 0, &est, &p);
        assert!(room as f64 >= accrued && room % p.chunk == 0, "{room}");
        // Woken very late: two quanta at most.
        let later = release + Duration::from_secs(1);
        assert_eq!(lim.tokens(later, &est, &p), 2.0 * quantum);
    }

    #[test]
    fn rate_bound_lapses() {
        let p = params();
        let now = Instant::now();
        let mut est = Estimator::new(10 * MS, now);
        est.rate_sample(10_000_000, false, now);
        let mut lim = Limiter::new(now);
        lim.mode = Mode::Cruise(Cycle::start(now));
        est.set_rate_lo(Some(2_000_000));
        lim.bound_set = Some(now);
        assert_eq!(est.rate, 2_000_000);
        let none = AckSample::default();
        let ev = AckEvent {
            sample: &none,
            acked: 0,
            sent: 0,
            held: Held::default(),
        };
        lim.on_ack(now + Duration::from_secs(5), &ev, &mut est, &p);
        assert_eq!(est.rate, 2_000_000);
        lim.on_ack(now + Duration::from_secs(10), &ev, &mut est, &p);
        assert_eq!(est.rate_lo, None);
        assert_eq!(est.rate, 10_000_000);
    }

    /// An acknowledgement of `acked` of `sent`, with an RTT sample `u` of a
    /// byte sent at `sent_at` if any.
    fn ack(u: Option<(Duration, Instant)>) -> AckSample {
        AckSample {
            rtt: u.map(|(u, sent_at)| RttSample {
                latest: u,
                adjusted: u,
                unsent_ahead: 0,
                sent_at,
            }),
            ..AckSample::default()
        }
    }

    fn feed(
        lim: &mut Limiter,
        est: &mut Estimator,
        p: &Params,
        now: Instant,
        s: &AckSample,
        acked: u64,
        sent: u64,
    ) {
        let ev = AckEvent {
            sample: s,
            acked,
            sent,
            held: Held::default(),
        };
        lim.on_ack(now, &ev, est, p);
    }

    /// A limiter past start-up at `rate` with RTT_base_p `base`.
    fn cruising(rate: u64, base: Duration, now: Instant) -> (Limiter, Estimator) {
        let mut est = Estimator::new(base, now);
        est.rate_sample(rate, false, now);
        let mut lim = Limiter::new(now);
        lim.mode = Mode::Cruise(Cycle::start(now));
        lim.base = Some(base);
        (lim, est)
    }

    #[test]
    fn the_base_is_the_smallest_sample_within_an_eighth() {
        // 1 Gbit/s x 100 ms whose round trips stay 1/16 of the base above
        // it (jitter beyond B + A / R_p, 0.75 ms here): RTT_base_p stays
        // the smallest sample, never the minimum of a recent window, and
        // no probe is needed, since the cap's gain of 2 covers a base low
        // by less than an eighth.
        let base = 100 * MS;
        let run = |p: &Params| {
            let t0 = Instant::now();
            let (mut lim, mut est) = cruising(125_000_000, base, t0);
            let a_time = Params::at(p.slack(est.rate), est.rate);
            let u = base + p.budget + a_time + base / 16;
            for i in 1..=80 {
                let now = t0 + 250 * MS * i;
                feed(&mut lim, &mut est, p, now, &ack(Some((u, now - u))), 0, 0);
                if matches!(lim.mode, Mode::Probe(_)) {
                    return Some(now - t0);
                }
                assert_eq!(lim.base, Some(base));
            }
            None
        };
        assert_eq!(run(&params()), None);
        // Without the relative term every 10 s holds the pipe at A in a
        // probe.
        let absolute = Params {
            relative_tolerance: false,
            ..params()
        };
        assert!(run(&absolute).is_some_and(|t| t <= BASE_SPAN + 250 * MS));
    }

    #[test]
    fn the_drain_ends_at_a_or_the_bdp_whichever_is_larger() {
        let p = params();
        let t0 = Instant::now();
        // A standing queue S_p well above B, so only the bytes in flight
        // can end the drain.
        let drain = |rate: u64, base: Duration, in_flight: u64, p: &Params| {
            let (mut lim, mut est) = cruising(rate, base, t0);
            lim.mode = Mode::Drain;
            let u = base + 10 * MS;
            feed(
                &mut lim,
                &mut est,
                p,
                t0,
                &ack(Some((u, t0 - u))),
                0,
                in_flight,
            );
            matches!(lim.mode, Mode::Drain)
        };
        // A LAN path, 1 Gbit/s x 50 us: its BDP (6 KB) is below A (80 KiB),
        // which the peer may leave unacknowledged however empty the queue.
        let a = p.slack(125_000_000);
        assert!(!drain(125_000_000, Duration::from_micros(50), a / 2, &p));
        assert!(drain(125_000_000, Duration::from_micros(50), a + 1, &p));
        // 100 Mbit/s x 100 ms: a BDP of 1.25 MB, which A does not extend.
        let bdp = 1_250_000;
        assert!(!drain(12_500_000, 100 * MS, bdp, &p));
        assert!(drain(12_500_000, 100 * MS, bdp + a / 2, &p));
        let plus = Params {
            drain_plus_slack: true,
            ..params()
        };
        assert!(!drain(12_500_000, 100 * MS, bdp + a / 2, &plus));
    }

    #[test]
    fn a_probe_ends_only_once_a_byte_sent_after_the_old_queue_is_measured() {
        let p = params();
        let t0 = Instant::now();
        let (mut lim, mut est) = cruising(12_500_000, 50 * MS, t0);
        // No sample near the base for 10 s: a probe, 100 kB in flight.
        let t1 = t0 + Duration::from_secs(11);
        feed(&mut lim, &mut est, &p, t1, &ack(None), 0, 100_000);
        assert!(matches!(lim.mode, Mode::Probe(_)), "{:?}", lim.mode);
        // The old queue drains at once; its last byte's sample is 60 ms,
        // and 20 kB sent meanwhile are in flight.
        let t = t1 + 10 * MS;
        feed(
            &mut lim,
            &mut est,
            &p,
            t,
            &ack(Some((60 * MS, t - 60 * MS))),
            100_000,
            120_000,
        );
        // A sample below the base lowers it at once, during the probe too:
        // no queue makes a round trip shorter.
        let t = t1 + 20 * MS;
        feed(
            &mut lim,
            &mut est,
            &p,
            t,
            &ack(Some((40 * MS, t1 + 5 * MS))),
            100_000,
            120_000,
        );
        assert_eq!(lim.base, Some(40 * MS));
        assert!(matches!(lim.mode, Mode::Probe(_)), "{:?}", lim.mode);
        // max(200 ms, srtt) is over, but nothing sent after the old queue
        // drained was measured: the probe goes on.
        feed(
            &mut lim,
            &mut est,
            &p,
            t1 + 250 * MS,
            &ack(None),
            100_000,
            120_000,
        );
        assert!(matches!(lim.mode, Mode::Probe(_)), "{:?}", lim.mode);
        // A byte sent after the old queue drained comes back: the base is
        // its sample, not the smaller one of the old queue's last byte.
        let t = t1 + 300 * MS;
        feed(
            &mut lim,
            &mut est,
            &p,
            t,
            &ack(Some((80 * MS, t1 + 220 * MS))),
            120_000,
            120_000,
        );
        assert!(matches!(lim.mode, Mode::Cruise(_)), "{:?}", lim.mode);
        // The end of the probe sets what it measured, though a sample of a
        // byte sent before the old queue drained was smaller.
        assert_eq!(lim.base, Some(80 * MS));
    }

    #[test]
    fn start_up_counts_only_round_trips_with_a_bottleneck_sample() {
        let rounds = |p: &Params, app_limited: bool, n: usize| {
            let t0 = Instant::now();
            let mut est = Estimator::new(10 * MS, t0);
            est.rate_sample(1_750_000, false, t0);
            let mut lim = Limiter::new(t0);
            for i in 1..=n {
                let now = t0 + 10 * MS * i as u32;
                est.rate_sample(1_750_000, app_limited, now);
                let s = AckSample {
                    rate: Some((1_750_000, app_limited)),
                    round_end: true,
                    ..AckSample::default()
                };
                feed(&mut lim, &mut est, p, now, &s, 0, 0);
            }
            matches!(lim.mode, Mode::Startup { .. })
        };
        // Round trips limited by the application (14 of 100 Mbit/s) say
        // nothing about the path: start-up goes on.
        assert!(rounds(&params(), true, 20));
        // Four with bottleneck samples and no growth end it.
        assert!(!rounds(&params(), false, 4));
        let all = Params {
            startup_counts_all: true,
            ..params()
        };
        assert!(!rounds(&all, true, 4));
    }
}
