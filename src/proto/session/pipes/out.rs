//! The outbound pipe of an attachment: its state machine, positions, the sample
//! state of the batches in flight, the retained frames, write progress, probes,
//! penalties, probation and the redundant copies queued for it.

use std::cell::Cell;
use std::collections::VecDeque;
use std::time::{Duration, Instant};

use super::lanes::OutLanes;
use super::probation::{History, Probation};
use super::{
    AckSample, Batch, Estimator, OutState, OutboundState, Revalidation, RttSample, SentFrame,
};
use crate::proto::record::Framing;
use crate::proto::session::Period;
use crate::proto::session::limiter::{Held, Limiter};
use crate::proto::session::stream::StreamKey;

/// A redundant copy queued for a pipe: the stream range of the frame it
/// copies, and whether that frame carried the FIN.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct QueuedCopy {
    key: StreamKey,
    off: u64,
    end: u64,
    fin: bool,
}

impl QueuedCopy {
    /// A copy of stream `key`'s bytes `off..end`, with the FIN when `fin`.
    pub(crate) fn new(key: StreamKey, off: u64, end: u64, fin: bool) -> Self {
        Self { key, off, end, fin }
    }

    /// The stream.
    #[inline]
    pub(crate) fn key(&self) -> StreamKey {
        self.key
    }

    /// Where the bytes still to copy start.
    #[inline]
    pub(crate) fn off(&self) -> u64 {
        self.off
    }

    /// Where the copied range ends.
    #[inline]
    pub(crate) fn end(&self) -> u64 {
        self.end
    }

    /// The copied frame carried the FIN.
    #[inline]
    pub(crate) fn fin(&self) -> bool {
        self.fin
    }
}

/// What a batch starts with, taken when the batch is built.
#[derive(Debug, Clone, Copy)]
pub(crate) struct BatchStart {
    /// The joiner's first record after Proven.
    pub(crate) joined_first: bool,
    pub(crate) framing: Framing,
    /// QX_TRANSPORT_PARAMETERS is still to be written first.
    pub(crate) parameters: bool,
    /// The pipe is live.
    pub(crate) live: bool,
    /// CONNECTION_CLOSE was written on it.
    pub(crate) close_sent: bool,
    /// The write side is to be shut down with this batch.
    pub(crate) shutdown: bool,
}

/// The quality counters of an outbound pipe.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct PipeQuality {
    pub(crate) joined_at: Option<Instant>,
    pub(crate) suspect_count: u64,
    pub(crate) in_probation: bool,
    pub(crate) revalidating: bool,
    pub(crate) bytes_reinjected: u64,
    pub(crate) bytes_opportunistic: u64,
    pub(crate) bytes_redundant: u64,
    pub(crate) pings_sent: u64,
    pub(crate) pings_answered: u64,
}

/// What an advance of the acknowledged position brought.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Acked {
    /// The samples it gave.
    pub(crate) sample: AckSample,
    /// The opportunistic-reinjection penalty ended.
    pub(crate) unpenalized: bool,
    /// The revalidation's PIPE_PING was acknowledged.
    pub(crate) revalidated: bool,
    /// A record that carried an activity frame was acknowledged.
    pub(crate) activity: bool,
}

/// What holds a pipe's writes back: the one write-progress input of a pipe, in
/// the state each driver style reports. The write-stall clock runs from it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Hold {
    /// A write call in progress (a blocking driver's): when it started, and
    /// its size.
    Call { start: Instant, bytes: u64 },
    /// The carrier refused bytes (a non-blocking driver's): when the call
    /// that found it full ended, and U, what it held unsent then.
    Refused { end: Instant, unsent: u64 },
}

/// The outbound pipe of an attachment.
#[derive(Debug)]
pub(crate) struct OutPipe {
    framing: Framing,
    state: OutState,
    /// QX_TRANSPORT_PARAMETERS written (bootstrap pipes; true elsewhere).
    tp_sent: bool,
    /// The largest record plaintext of the carrier, local.
    max_record: Option<usize>,
    close_sent: bool,
    /// Write side to be shut down with the next batch.
    shutdown: bool,
    /// The driver was told to shut down.
    shutdown_reported: bool,
    /// The driver will not write any more (carrier closed).
    out_closed: bool,
    /// The driver was told to abort the carrier.
    abort_reported: bool,
    /// Bytes passed to the carrier (the send position).
    sent: u64,
    /// The largest acknowledged position.
    acked: u64,
    /// The last acknowledgement advance, or when the pipe became usable.
    last_advance: Instant,
    batches: VecDeque<Batch>,
    /// Positions up to which every batch is acknowledged or not
    /// ack-eliciting, respectively not watched: where the searches for the
    /// oldest unacknowledged ones resume, so that a run of batches without
    /// ack-eliciting frames (PIPE_ACK alone) is passed over once.
    eliciting_from: Cell<u64>,
    watched_from: Cell<u64>,
    est: Estimator,
    /// A write call in progress, or a carrier that refuses bytes.
    hold: Option<Hold>,
    /// Stream data waited when the hold began.
    held_with_data: bool,
    /// The carrier has a low-water mark (TCP_NOTSENT_LOWAT): the carrier
    /// queue limiter does not pace it.
    low_water: bool,
    /// Bytes of the last batch handed to the carrier.
    last_batch: u64,
    /// Bytes of lane 0's batch that the carrier has not taken yet: the
    /// write calls in progress (part of the queue Q_p).
    writing: u64,
    /// The carrier reports its unsent bytes (an optional capability).
    unsent_reported: bool,
    /// The position after the last ack-eliciting batch: what follows it
    /// (records of PIPE_ACK alone) the peer need not acknowledge.
    eliciting_end: u64,
    /// Carrier bytes not yet transmitted, as the adapter reports them.
    carrier_unsent: u64,
    /// The carrier's own RTT estimate, as the adapter reports it.
    carrier_rtt: Option<Duration>,
    /// Bumped whenever the pipe is seen as the bottleneck: it held the
    /// writes back (a call in progress, or a refusal) while stream data
    /// waited.
    bottleneck_epoch: u64,
    /// The position at the pipe's last application-limited moment (a write
    /// opportunity that left it writable with nothing to send for it),
    /// until the acknowledged position passes it.
    bubble: Option<u64>,
    /// Records written so far.
    records: u64,
    /// The carrier queue limiter, which paces
    /// the pipe while its carrier has neither a low-water mark nor an
    /// unsent count. Allocated while the pipe is paced.
    limiter: Option<Box<Limiter>>,
    /// Multipath state of the pipe, allocated only in a multipath session.
    mp: Option<Box<OutMp>>,
    /// The carrier offers lanes: the adapter opens further streams of lane
    /// 0's connection.
    lanes_offered: bool,
    /// The lanes, allocated with the first one: without them the pipe is
    /// its lane 0, whose positions are the send order.
    lanes: Option<Box<OutLanes>>,
    /// The carrier's datagram channel, as the driver last reported it.
    channel: Option<Channel>,
    /// The carrier's retransmissions, once the adapter reported a count.
    loss: Option<Box<CarrierLoss>>,
    /// Bytes sent and not acknowledged when the pipe failed.
    lost: u64,
}

/// A carrier's own retransmissions as its adapter reports them, and the
/// smoothed loss rate sampled from them.
#[derive(Debug, Clone, Copy)]
struct CarrierLoss {
    /// The latest count.
    retransmitted: u64,
    /// The smoothed rate, after the first sample.
    rate: Option<f64>,
    /// The last sample: when, the bytes sent and the count then.
    at: Instant,
    sent: u64,
    count: u64,
}

/// The shortest time between two samples of a pipe's loss rate.
const LOSS_SAMPLE_GAP: Duration = Duration::from_secs(1);

/// A pipe carrier's datagram channel as the core uses it to decide where a
/// DATAGRAM frame goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Channel {
    /// The Pipe Stream ID that starts the pipe's channel datagrams, on
    /// channels shared by the streams of a connection.
    pub(crate) id: Option<u64>,
    /// The largest channel datagram the channel takes now, Pipe Stream ID
    /// included; 0 while it takes none.
    pub(crate) max: usize,
}

/// The multipath part of an outbound pipe.
#[derive(Debug)]
struct OutMp {
    /// A DRAINING pipe that stalled.
    suspect_mark: bool,
    /// The join was confirmed (or needs no confirmation).
    confirmed: bool,
    usable_at: Instant,
    /// Retained frames: (end position of their record, frame).
    log: VecDeque<(u64, SentFrame)>,
    /// End positions of records that carried an activity frame.
    activity_ends: VecDeque<u64>,
    /// Since when bytes wait for this pipe while its carrier refuses them.
    waiting_since: Option<Instant>,
    /// When the carrier's unsent count last decreased.
    unsent_progress: Instant,
    /// Information up to this position was reinjected already.
    reinjected_upto: u64,
    /// Stream data up to this position was re-sent for a penalty already.
    penalty_resent_upto: u64,
    /// When the last ack-eliciting byte was sent.
    last_eliciting: Option<Instant>,
    /// The current idle-probe wait is a bootstrap pipe's first, drawn from
    /// the whole interval: no PIPE_PING was sent on the pipe by either
    /// end. A joined pipe carried the joiner's PIPE_PING, so both of its
    /// ends draw as usual.
    boot_wait: bool,
    /// A PIPE_PING is owed since this time.
    ping_wanted: Option<Instant>,
    /// When the pipe entered DRAINING.
    drain_since: Option<Instant>,
    /// When the join was sent (handshake timeout of an unconfirmed pipe).
    joined_at: Instant,
    suspect_floor: Duration,
    dead_timeout: Option<Duration>,
    /// The two above when the pipe last turned suspect.
    suspect_held: (Duration, Option<Duration>),
    /// The pipe's own idle-probe interval and jitter (`None`: the
    /// session's), and the draw u of the current wait, k (1 - j u), made
    /// when the wait starts from the pipe's generator.
    probe_interval: Option<Period>,
    probe_jitter: Option<f64>,
    probe_rng: u64,
    probe_u: f64,
    /// H_p of the current wait, fixed when it is first measured after it
    /// started (in nanoseconds; `u64::MAX`: not yet), so that a
    /// guardrail's budget used up meanwhile does not move the deadline.
    /// Atomic only to be set from a shared borrow; the core is single-owner.
    probe_hold: std::sync::atomic::AtomicU64,
    /// No new stream data until the acknowledged position reaches this
    /// (opportunistic-reinjection penalty).
    penalty_until: Option<u64>,
    /// A new pipe reinjects at most one chunk until the first PIPE_ACK received
    /// after it became live, or this deadline (one smoothed RTT); and the bytes
    /// it reinjected meanwhile.
    reinject_hold: Option<Instant>,
    reinject_held: u64,
    /// The first record carries a complete PIPE_ACK snapshot.
    snapshot_first: bool,
    /// The joiner's first record after Proven is due.
    joined_first: bool,
    probation: Probation,
    /// The send position when the pipe last became SUSPECT: bytes up to
    /// it give no RTT or rate samples.
    suspect_pos: u64,
    /// The `spread-round-robin` current value of the session's policy.
    rr_current: f64,
    /// Quality counters.
    suspect_count: u64,
    pings_sent: u64,
    pings_answered: u64,
    bytes_reinjected: u64,
    bytes_opportunistic: u64,
    /// Redundant copies sent.
    bytes_redundant: u64,
    /// A PIPE_PING went into the current batch.
    ping_in_batch: bool,
    /// The records with a PIPE_PING not acknowledged yet: their lane and
    /// the lane's position at their end, in order per lane.
    pings_unanswered: Vec<(u64, u64)>,
    /// A PIPE_PING arrived on the attachment's inbound pipe: the PIPE_ACK
    /// that answers it also goes on this pipe.
    answer_ping: bool,
    /// Awaiting revalidation.
    revalidating: Option<Revalidation>,
    /// Redundant copies queued for the pipe's next write opportunity, and
    /// the bytes of new data still to be copied after an idle period.
    copies: VecDeque<QueuedCopy>,
    idle_copy: u64,
}

/// The detection settings of a multipath outbound pipe: the T_suspect
/// floor, the dead timeout, its idle-probe interval and jitter (`None`:
/// the session's) and the seed of its idle-probe draws.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Detection {
    pub(crate) suspect_floor: Duration,
    pub(crate) dead_timeout: Option<Duration>,
    pub(crate) probe_interval: Option<Period>,
    pub(crate) probe_jitter: Option<f64>,
    pub(crate) probe_seed: u64,
}

impl Detection {
    /// The settings of a pipe outside multipath (none is used).
    const NONE: Self = Self {
        suspect_floor: Duration::ZERO,
        dead_timeout: None,
        probe_interval: None,
        probe_jitter: None,
        probe_seed: 0,
    };
}

/// The next value of a SplitMix64 generator.
pub(crate) fn splitmix(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}

impl OutMp {
    fn new(state: OutState, d: Detection, now: Instant) -> Self {
        let mut m = Self {
            suspect_mark: false,
            confirmed: !matches!(state, OutState::Joining | OutState::Deferred),
            usable_at: now,
            log: VecDeque::new(),
            activity_ends: VecDeque::new(),
            unsent_progress: now,
            waiting_since: None,
            reinjected_upto: 0,
            penalty_resent_upto: 0,
            last_eliciting: None,
            boot_wait: false,
            ping_wanted: None,
            drain_since: None,
            joined_at: now,
            suspect_floor: d.suspect_floor,
            dead_timeout: d.dead_timeout,
            suspect_held: (d.suspect_floor, d.dead_timeout),
            probe_interval: d.probe_interval,
            probe_jitter: d.probe_jitter,
            probe_rng: d.probe_seed,
            probe_u: 0.0,
            probe_hold: std::sync::atomic::AtomicU64::new(u64::MAX),
            penalty_until: None,
            reinject_hold: None,
            reinject_held: 0,
            snapshot_first: false,
            joined_first: false,
            probation: Probation::default(),
            suspect_pos: 0,
            rr_current: 0.0,
            suspect_count: 0,
            pings_sent: 0,
            pings_answered: 0,
            bytes_reinjected: 0,
            bytes_opportunistic: 0,
            bytes_redundant: 0,
            ping_in_batch: false,
            pings_unanswered: Vec::new(),
            answer_ping: false,
            revalidating: None,
            copies: VecDeque::new(),
            idle_copy: 0,
        };
        m.draw_probe_wait();
        m
    }

    /// A new idle-probe wait starts: its draw u in \[0, 1).
    fn draw_probe_wait(&mut self) {
        self.probe_u = (splitmix(&mut self.probe_rng) >> 11) as f64 / (1u64 << 53) as f64;
        *self.probe_hold.get_mut() = u64::MAX;
    }

    /// The idle probe's reference: the last ack-eliciting byte, or when the
    /// pipe became usable if later.
    fn last_eliciting_or_usable(&self) -> Instant {
        self.last_eliciting
            .unwrap_or(self.usable_at)
            .max(self.usable_at)
    }
}

impl OutPipe {
    pub(crate) fn new(
        framing: Framing,
        state: OutState,
        initial_rtt: Duration,
        now: Instant,
    ) -> Self {
        Self {
            framing,
            state,
            tp_sent: true,
            max_record: None,
            close_sent: false,
            shutdown: false,
            shutdown_reported: false,
            out_closed: false,
            abort_reported: false,
            sent: 0,
            acked: 0,
            last_advance: now,
            batches: VecDeque::new(),
            eliciting_from: Cell::new(0),
            watched_from: Cell::new(0),
            est: Estimator::new(initial_rtt, now),
            hold: None,
            held_with_data: false,
            low_water: false,
            last_batch: 0,
            writing: 0,
            unsent_reported: false,
            eliciting_end: 0,
            carrier_unsent: 0,
            carrier_rtt: None,
            bottleneck_epoch: 0,
            bubble: None,
            records: 0,
            limiter: None,
            mp: None,
            lanes_offered: false,
            lanes: None,
            channel: None,
            loss: None,
            lost: 0,
        }
    }

    /// The carrier's retransmitted bytes, as its adapter reports them, and
    /// a sample of the smoothed loss rate: an EWMA with gain 1/8 of the
    /// retransmitted bytes per byte sent between samples at least
    /// [`LOSS_SAMPLE_GAP`] apart. A count that moves back counts as no
    /// retransmission.
    pub(crate) fn set_retransmitted(&mut self, count: u64, now: Instant) {
        let sent = self.bytes_written();
        let Some(l) = self.loss.as_deref_mut() else {
            self.loss = Some(Box::new(CarrierLoss {
                retransmitted: count,
                rate: None,
                at: now,
                sent,
                count,
            }));
            return;
        };
        l.retransmitted = count;
        if now.saturating_duration_since(l.at) < LOSS_SAMPLE_GAP || sent <= l.sent {
            return;
        }
        let x = count.saturating_sub(l.count) as f64 / (sent - l.sent) as f64;
        l.rate = Some(match l.rate {
            Some(r) => r + (x - r) / 8.0,
            None => x,
        });
        (l.at, l.sent, l.count) = (now, sent, count);
    }

    /// The carrier's retransmitted bytes, once reported.
    pub(crate) fn retransmitted(&self) -> Option<u64> {
        self.loss.as_deref().map(|l| l.retransmitted)
    }

    /// The smoothed carrier loss rate, after its first sample.
    pub(crate) fn loss_rate(&self) -> Option<f64> {
        self.loss.as_deref().and_then(|l| l.rate)
    }

    /// Bytes sent and not acknowledged when the pipe failed (0 before).
    pub(crate) fn lost(&self) -> u64 {
        self.lost
    }

    /// The acknowledged positions summed over every lane.
    pub(crate) fn acked_total(&self) -> u64 {
        match self.lanes.as_deref() {
            Some(l) => {
                l.tx(0).map_or(0, |t| t.acked())
                    + l.iter().map(|(_, x)| x.tx().acked()).sum::<u64>()
            }
            None => self.acked,
        }
    }

    /// The pipe with its multipath state, for a multipath session: the
    /// detection floor and dead timeout of failure detection.
    pub(crate) fn with_mp(mut self, d: Detection, now: Instant) -> Self {
        self.mp = Some(Box::new(OutMp::new(self.state, d, now)));
        self
    }

    /// A bootstrap pipe: QX_TRANSPORT_PARAMETERS opens its first
    /// record.
    pub(crate) fn with_parameters_first(mut self) -> Self {
        self.tp_sent = false;
        if let Some(m) = self.mp.as_deref_mut() {
            m.boot_wait = true;
        }
        self
    }

    /// The bootstrap pipe of a session that starts using multipath: its
    /// multipath state with the detection settings, usable from now.
    pub(crate) fn start_multipath(self, d: Detection, now: Instant) -> Self {
        let mut o = self.with_mp(d, now);
        let m = o.mp_mut();
        m.usable_at = now;
        m.boot_wait = true;
        o.last_advance = now;
        o
    }

    /// Heap bytes the pipe holds.
    pub(crate) fn heap_bytes(&self) -> usize {
        self.batches.capacity() * size_of::<Batch>()
            + self.lanes.as_deref().map_or(0, OutLanes::heap_bytes)
            + self
                .limiter
                .as_ref()
                .map_or(0, |l| size_of::<Limiter>() + l.memory())
            + self.mp.as_deref().map_or(0, |m| {
                size_of::<OutMp>()
                    + m.log.capacity() * size_of::<(u64, SentFrame)>()
                    + m.activity_ends.capacity() * size_of::<u64>()
                    + m.copies.capacity() * size_of::<QueuedCopy>()
            })
    }

    /// The multipath state: a pipe of a multipath session has it; any
    /// other reads the state of a pipe that never needed any.
    #[inline]
    fn mp(&self) -> &OutMp {
        // The core reads no clock: the defaults take their times from the
        // first pipe that asks (no time in them is ever used).
        static NONE: std::sync::OnceLock<OutMp> = std::sync::OnceLock::new();
        self.mp.as_deref().unwrap_or_else(|| {
            NONE.get_or_init(|| OutMp::new(OutState::Active, Detection::NONE, self.last_advance))
        })
    }

    /// The multipath state, allocated on first use (a pipe of a multipath
    /// session has it from the start, with its detection settings).
    #[inline]
    fn mp_mut(&mut self) -> &mut OutMp {
        let (state, at) = (self.state, self.last_advance);
        self.mp
            .get_or_insert_with(|| Box::new(OutMp::new(state, Detection::NONE, at)))
    }

    // ---- the carrier queue limiter --------------------

    /// Whether the carrier queue limiter holds the pipe back.
    #[inline]
    pub(crate) fn limiter_held(&self) -> bool {
        self.limiter.as_ref().is_some_and(|l| l.held())
    }

    /// When a pipe the limiter holds may send again.
    pub(crate) fn limiter_release(&self) -> Option<Instant> {
        self.limiter.as_ref()?.release()
    }

    /// The limiter, if the pipe is paced, with the estimator it reads.
    pub(crate) fn limiter_parts(&mut self) -> Option<(&mut Limiter, &mut Estimator)> {
        Some((self.limiter.as_deref_mut()?, &mut self.est))
    }

    /// The limiter while the pipe is paced.
    pub(crate) fn limiter(&self) -> Option<&Limiter> {
        self.limiter.as_deref()
    }

    /// The pipe is paced from now on (`true`), or no longer.
    pub(crate) fn set_paced(&mut self, paced: bool, now: Instant) {
        match (paced, self.limiter.is_some()) {
            (true, false) => self.limiter = Some(Box::new(Limiter::new(now))),
            (false, true) => self.limiter = None,
            _ => {}
        }
    }

    /// The carrier declared a low-water mark or an unsent count: the
    /// limiter no longer applies, and nor does its rate bound.
    pub(crate) fn unpace(&mut self, now: Instant) {
        self.est.set_rate_lo(None);
        self.set_paced(false, now);
    }

    /// The carrier tells how much it queues: a low-water mark or an unsent
    /// count; otherwise the limiter paces it.
    pub(crate) fn carrier_signals_queue(&self) -> bool {
        self.low_water || self.unsent_reported
    }

    // ---- state -----------------------------------------------------------------------

    #[inline]
    pub(crate) fn state(&self) -> OutState {
        self.state
    }

    /// The state as the API reports it.
    #[inline]
    pub(crate) fn public_state(&self) -> OutboundState {
        self.state.public()
    }

    #[inline]
    pub(crate) fn is_live(&self) -> bool {
        self.state.is_live() && !self.out_closed
    }

    /// Usable for new stream data: never before its handshake.
    #[inline]
    pub(crate) fn takes_new_data(&self) -> bool {
        self.state == OutState::Active && !self.out_closed && !self.shutdown
    }

    /// The write side is to be shut down with the next batch (drained or
    /// failed).
    #[inline]
    pub(crate) fn shutdown_pending(&self) -> bool {
        self.shutdown
    }

    /// The carrier is closed: the driver writes no more.
    #[inline]
    pub(crate) fn out_closed(&self) -> bool {
        self.out_closed
    }

    /// The driver writes no more: the carrier is closed, or was told to
    /// shut down or to abort (a failed pipe's carrier is aborted, never
    /// shut down gracefully: its peer must not take its end for a clean
    /// one).
    #[inline]
    pub(crate) fn writes_ended(&self) -> bool {
        self.out_closed || self.shutdown_reported || self.abort_reported
    }

    /// The first frames of the pipe are owed: QX_TRANSPORT_PARAMETERS, or
    #[inline]
    pub(crate) fn leading_frames_owed(&self) -> bool {
        !self.tp_sent
    }

    /// Live, and not yet told to shut down: a batch may still be written.
    #[inline]
    pub(crate) fn unwritten(&self) -> bool {
        self.state.is_live() && !self.shutdown_reported && !self.out_closed
    }

    /// The write side is done: closed, shut down, or no longer live.
    #[inline]
    pub(crate) fn write_done(&self) -> bool {
        self.out_closed || self.shutdown_reported || !self.state.is_live()
    }

    /// The join was confirmed (or needed none).
    #[inline]
    pub(crate) fn confirmed(&self) -> bool {
        self.mp().confirmed
    }

    /// A DRAINING pipe that stalled.
    #[inline]
    pub(crate) fn suspect_mark(&self) -> bool {
        self.mp().suspect_mark
    }

    /// The pipe is suspect, or draining and marked suspect: bytes
    /// acknowledged now measure the outage.
    #[inline]
    pub(crate) fn in_outage(&self) -> bool {
        self.state == OutState::Suspect || self.mp().suspect_mark
    }

    /// The preference class of the pipe for control frames: ACTIVE,
    /// JOINING, SUSPECT, DRAINING, DRAINING marked suspect.
    #[inline]
    pub(crate) fn control_rank(&self) -> Option<u8> {
        if !self.is_live() || self.shutdown {
            return None;
        }
        Some(match self.state {
            OutState::Active => 0,
            OutState::Joining => 1,
            OutState::Suspect => 2,
            OutState::Draining if !self.mp().suspect_mark => 3,
            OutState::Draining => 4,
            _ => return None,
        })
    }

    /// Usable for new stream data at a scheduling decision (11 and 11.1):
    /// ACTIVE (a JOINING pipe is not usable
    /// until its join is confirmed), not penalized, and out of probation
    /// and not awaiting revalidation unless `probation_ok`.
    #[inline]
    pub(crate) fn usable(&self, probation_ok: bool) -> bool {
        self.state == OutState::Active
            && !self.out_closed
            && !self.shutdown
            && self.mp.as_deref().is_none_or(|m| {
                m.penalty_until.is_none()
                    && (probation_ok || (!m.probation.active() && m.revalidating.is_none()))
            })
    }

    /// Whether a revalidation may start: ACTIVE, open, and none awaited.
    fn revalidatable(&self) -> bool {
        self.state == OutState::Active
            && !self.out_closed
            && !self.shutdown
            && self.mp().revalidating.is_none()
    }

    /// Whether the pipe may carry the endpoint's pending stream data and reinjection
    /// for the write-stall rule: ACTIVE, open, and not penalized (standby and lower
    /// tiers included).
    #[inline]
    pub(crate) fn may_carry(&self) -> bool {
        self.takes_new_data() && self.mp.as_deref().is_none_or(|m| m.penalty_until.is_none())
    }

    /// A deferred join goes: the pipe is joining.
    pub(crate) fn release_join(&mut self) {
        self.state = OutState::Joining;
    }

    /// Its handshake runs: nothing but the handshake reaches the carrier.
    #[inline]
    pub(crate) fn in_handshake(&self) -> bool {
        matches!(self.state, OutState::Joining | OutState::Deferred)
    }

    /// The joiner's first record after Proven is still due.
    pub(crate) fn joined_first(&self) -> bool {
        self.mp.as_deref().is_some_and(|m| m.joined_first)
    }

    /// The largest record plaintext of the pipe's carrier.
    pub(crate) fn set_max_record(&mut self, max: usize) {
        self.max_record = Some(max);
    }

    /// See [`OutPipe::set_max_record`].
    pub(crate) fn max_record(&self) -> Option<usize> {
        self.max_record
    }

    /// The join goes now: its handshake timeout runs. No stall clock runs until it is
    /// ACTIVE.
    pub(crate) fn start_join(&mut self, now: Instant) {
        self.mp_mut().joined_at = now;
    }

    /// A verified Reply: ACTIVE. Stall clocks start here, the first record carries a
    /// complete snapshot and a PIPE_PING, and reinjection waits for a PIPE_ACK for up to a
    /// smoothed RTT.
    pub(crate) fn join_proven(&mut self, now: Instant) {
        let reinject_hold = now + self.est.srtt;
        self.state = OutState::Active;
        self.last_advance = now;
        let m = self.mp_mut();
        m.confirmed = true;
        m.joined_at = now;
        m.usable_at = now;
        m.draw_probe_wait();
        m.ping_wanted = Some(now);
        m.snapshot_first = true;
        m.joined_first = true;
        m.reinject_hold = Some(reinject_hold);
    }

    /// The pipe of a join accepted from the peer: its first record carries a complete
    /// snapshot and a PIPE_PING, and reinjection waits for a PIPE_ACK for up to a smoothed
    /// RTT.
    pub(crate) fn accepted(mut self, now: Instant) -> Self {
        let reinject_hold = now + self.est.srtt;
        let m = self.mp_mut();
        m.ping_wanted = Some(now);
        m.snapshot_first = true;
        m.reinject_hold = Some(reinject_hold);
        self
    }

    /// Starts draining: `false` when it drains, failed or closed already.
    pub(crate) fn start_drain(&mut self, now: Instant) -> bool {
        if matches!(
            self.state,
            OutState::Draining | OutState::Failed | OutState::Closed
        ) {
            return false;
        }
        self.state = OutState::Draining;
        let m = self.mp_mut();
        m.drain_since = Some(now);
        m.waiting_since = None;
        true
    }

    /// When the pipe entered DRAINING.
    #[inline]
    pub(crate) fn drain_since(&self) -> Option<Instant> {
        self.mp().drain_since
    }

    /// The pipe becomes suspect, or a DRAINING one is marked so: `false` when
    /// nothing changed. A PIPE_PING is owed, and the bytes sent so far give no
    /// samples.
    pub(crate) fn suspect(&mut self, now: Instant) -> bool {
        match self.state {
            OutState::Active => self.state = OutState::Suspect,
            OutState::Draining if !self.mp().suspect_mark => self.mp_mut().suspect_mark = true,
            _ => return false,
        }
        let sent = self.sent;
        let m = self.mp_mut();
        m.ping_wanted.get_or_insert(now);
        m.suspect_held = (m.suspect_floor, m.dead_timeout);
        // Bytes held through the outage give no samples.
        m.suspect_pos = sent;
        m.suspect_count += 1;
        true
    }

    /// The acknowledged position advanced: a suspect pipe whose carrier takes bytes
    /// recovers; whether one did.
    pub(crate) fn ack_progress(&mut self) -> bool {
        if self.state == OutState::Suspect && self.open() {
            self.state = OutState::Active;
            return true;
        }
        false
    }

    /// The attachment failed, after its information was reinjected: the pipe stops,
    /// its retained state goes and its write side is shut down. Whether the driver
    /// is still to be told to abort the carrier.
    pub(crate) fn fail(&mut self) -> bool {
        self.lost = self.bytes_written().saturating_sub(self.acked_total());
        self.state = OutState::Failed;
        // The storage goes too: a failed pipe waits for its retirement.
        self.batches = VecDeque::new();
        if let Some(l) = self.lanes.as_deref_mut() {
            l.forget();
        }
        let m = self.mp_mut();
        m.log = VecDeque::new();
        m.activity_ends = Default::default();
        m.waiting_since = None;
        m.ping_wanted = None;
        self.shutdown = true;
        let report = !self.out_closed && !self.abort_reported && !self.shutdown_reported;
        self.abort_reported = true;
        report
    }

    /// A drained pipe closes: its write side is shut down with the next
    /// batch.
    pub(crate) fn close_drained(&mut self) {
        self.state = OutState::Closed;
        self.shutdown = true;
    }

    /// The session is closing: a live pipe's write side is shut down.
    pub(crate) fn shut_down(&mut self) {
        if self.is_live() {
            self.shutdown = true;
        }
    }

    /// A write failed: the carrier is gone and its write side shut down;
    /// `false` when it was closed already.
    pub(crate) fn write_failed(&mut self) -> bool {
        if self.out_closed {
            return false;
        }
        self.out_closed = true;
        self.shutdown = true;
        true
    }

    /// The carrier is closed under the pipe.
    pub(crate) fn carrier_closed(&mut self) {
        self.out_closed = true;
    }

    /// The session closed: nothing more is written.
    pub(crate) fn session_closed(&mut self) {
        self.shutdown = true;
        self.out_closed = true;
    }

    /// The driver was told to abort the carrier.
    pub(crate) fn abort_reported(&mut self) {
        self.abort_reported = true;
    }

    /// The driver has not been told to end the carrier: it is still to be
    /// closed when the attachment retires.
    pub(crate) fn close_unreported(&self) -> bool {
        !self.out_closed && !self.abort_reported && !self.shutdown_reported
    }

    /// The handshake deadline of a join that is not confirmed, and the
    /// moment it was sent.
    #[inline]
    pub(crate) fn joined_at(&self) -> Instant {
        self.mp().joined_at
    }

    /// The last progress: the last acknowledgement advance, or the join.
    #[inline]
    pub(crate) fn last_progress(&self) -> Instant {
        self.last_advance.max(self.mp().joined_at)
    }

    /// Replaces the floor of T_suspect and the dead timeout of this pipe.
    pub(crate) fn set_detection_limits(&mut self, floor: Duration, dead: Option<Duration>) {
        if self.mp.is_some() {
            let m = self.mp_mut();
            m.suspect_floor = floor;
            m.dead_timeout = dead;
        }
    }

    /// Replaces this pipe's own idle-probe settings.
    pub(crate) fn set_probe(&mut self, interval: Option<Period>, jitter: Option<f64>) {
        if self.mp.is_some() {
            let m = self.mp_mut();
            m.probe_interval = interval;
            m.probe_jitter = jitter;
        }
    }

    /// The floor of T_suspect and the dead timeout when the pipe last turned
    /// suspect.
    #[inline]
    pub(crate) fn held_detection(&self) -> (Duration, Option<Duration>) {
        self.mp().suspect_held
    }

    /// The floor of T_suspect and the dead timeout of this pipe.
    #[inline]
    pub(crate) fn detection(&self) -> (Duration, Option<Duration>) {
        (self.mp().suspect_floor, self.mp().dead_timeout)
    }

    // ---- building batches ----------------------------------------------------------

    /// A batch starts: what it begins with, `None` when the pipe writes no
    /// more. The parameters are written once.
    pub(crate) fn begin_batch(&mut self, closed: bool) -> Option<BatchStart> {
        if self.out_closed || self.shutdown_reported || closed || self.in_handshake() {
            return None;
        }
        Some(BatchStart {
            framing: self.framing,
            parameters: !std::mem::replace(&mut self.tp_sent, true),
            joined_first: self
                .mp
                .as_deref_mut()
                .is_some_and(|m| std::mem::take(&mut m.joined_first)),
            live: self.state.is_live(),
            close_sent: self.close_sent,
            shutdown: self.shutdown,
        })
    }

    /// Gives back what [`OutPipe::begin_batch`] took for a batch that wrote
    /// nothing: the transport parameters still owed.
    pub(crate) fn unbegin_batch(&mut self, parameters: bool, joined_first: bool) {
        if parameters {
            self.tp_sent = false;
        }
        if joined_first {
            self.mp_mut().joined_first = true;
        }
    }

    /// The pipe's carrier no longer holds a close back: it took the whole
    /// batch with CONNECTION_CLOSE (nothing follows it, and a lane's next
    /// batch is taken only once the last is written), or the pipe cannot
    /// carry it: closed, shut down without it, not live, or still in its
    /// handshake.
    pub(crate) fn close_handed_off(&self) -> bool {
        if self.close_sent {
            return self.out_closed || self.writing == 0;
        }
        self.out_closed || self.shutdown_reported || !self.state.is_live() || self.in_handshake()
    }

    /// The batch with CONNECTION_CLOSE was written, with the shutdown.
    pub(crate) fn close_written(&mut self) {
        self.close_sent = true;
        self.shutdown_reported = true;
    }

    /// The batch with the shutdown was written.
    pub(crate) fn shutdown_written(&mut self) {
        self.shutdown_reported = true;
    }

    /// A retained frame of a batch on lane `lane`, whose record ends at
    /// send-order position `end`.
    #[inline]
    pub(crate) fn retain_frame(&mut self, lane: u64, end: u64, f: SentFrame) {
        match self.lanes.as_deref_mut().and_then(|l| l.log_mut(lane)) {
            Some(log) => log.push_back((end, f)),
            None => self.mp_mut().log.push_back((end, f)),
        }
    }

    /// A record of a batch, ending at `end`, carried an activity frame.
    #[inline]
    pub(crate) fn activity_at(&mut self, end: u64) {
        self.mp_mut().activity_ends.push_back(end);
    }

    /// A batch of `total` bytes in `records` records went to lane `lane`'s
    /// carrier; its last ack-eliciting byte ends `eliciting` bytes in, if
    /// any. Its bytes continue the pipe's send order.
    #[inline]
    pub(crate) fn batch_sent(
        &mut self,
        lane: u64,
        total: u64,
        records: u64,
        eliciting: Option<u64>,
    ) {
        let base = self.sent;
        if let Some(l) = self.lanes.as_deref_mut() {
            l.wrote(lane, base, total);
        }
        // The lane's previous batch is written: a driver takes the next one
        // only then.
        match self.lanes.as_deref_mut() {
            Some(l) if lane != 0 => l.set_writing(lane, total),
            _ => self.writing = total,
        }
        self.sent += total;
        self.records += records;
        self.last_batch = total;
        if let Some(end) = eliciting {
            self.eliciting_end = base + end;
        }
    }

    /// The multipath bookkeeping of a batch just sent: an outstanding
    /// PIPE_PING (and a revalidation's), the bytes waiting for the pipe,
    /// the idle probe's reference, and the batch's sample state; `peer_mad`
    /// is the peer's `zmux_max_ack_delay`.
    pub(crate) fn mp_batch_sent(
        &mut self,
        lane: u64,
        eliciting: bool,
        peer_mad: Duration,
        now: Instant,
    ) {
        let sent = self.sent;
        let lane_end = self.sent_on(lane);
        let m = self.mp_mut();
        let ping = std::mem::take(&mut m.ping_in_batch);
        if ping {
            m.pings_unanswered.push((lane, lane_end));
            if m.revalidating == Some(Revalidation::PingOwed) {
                m.revalidating = Some(Revalidation::Until(sent));
            }
        }
        m.waiting_since = None;
        if eliciting {
            m.last_eliciting = Some(now);
        }
        if ping {
            // A PIPE_PING went: the next idle-probe wait starts.
            m.boot_wait = false;
            m.draw_probe_wait();
        }
        self.record_batch(lane, eliciting, peer_mad, now);
    }

    // ---- positions -------------------------------------------------------------------

    /// The send position: bytes passed to the carrier.
    #[inline]
    pub(crate) fn framing(&self) -> Framing {
        self.framing
    }

    /// The carrier's framing, known only once a reserved pipe's carrier
    /// is attached (before any byte was written).
    pub(crate) fn set_framing(&mut self, framing: Framing) {
        self.framing = framing;
    }

    pub(crate) fn sent(&self) -> u64 {
        self.sent
    }

    /// The largest acknowledged position.
    #[inline]
    pub(crate) fn acked(&self) -> u64 {
        self.acked
    }

    /// The position after the last ack-eliciting batch.
    #[inline]
    pub(crate) fn eliciting_end(&self) -> u64 {
        self.eliciting_end
    }

    /// The last acknowledgement advance, or when the pipe became usable.
    #[inline]
    pub(crate) fn last_advance(&self) -> Instant {
        self.last_advance
    }

    /// Records written so far.
    #[inline]
    pub(crate) fn records(&self) -> u64 {
        self.records
    }

    /// Unacknowledged bytes in flight.
    #[inline]
    pub(crate) fn in_flight(&self) -> u64 {
        self.sent - self.acked
    }

    /// The bytes in flight that an acknowledgement is due for: up to the
    /// end of the last ack-eliciting batch, as RFC 9002 Section 2 counts
    /// bytes in flight. A trailing run of records that elicit nothing is
    /// acknowledged only with later data, if ever.
    #[inline]
    pub(crate) fn eliciting_in_flight(&self) -> u64 {
        self.eliciting_end.saturating_sub(self.acked)
    }

    /// The pipe's estimates.
    #[inline]
    pub(crate) fn est(&self) -> &Estimator {
        &self.est
    }

    /// The estimates, for tests that set them up.
    #[cfg(test)]
    pub(crate) fn est_mut(&mut self) -> &mut Estimator {
        &mut self.est
    }

    /// The carrier's own RTT estimate, as the adapter reports it.
    #[inline]
    pub(crate) fn carrier_rtt(&self) -> Option<Duration> {
        self.carrier_rtt
    }

    /// The adapter reports the carrier's RTT estimate (`None`: unknown).
    pub(crate) fn set_carrier_rtt(&mut self, rtt: Option<Duration>) {
        self.carrier_rtt = rtt.filter(|r| !r.is_zero());
    }

    /// pipe_min_rtt: the carrier's minimum
    /// when it reports one, else the minimum of the pipe's samples.
    #[inline]
    pub(crate) fn min_rtt(&self) -> Option<Duration> {
        self.carrier_rtt.or(self.est.min_rtt.get())
    }

    /// An RTT sample from a QX_PING round trip on the single pipe, taken
    /// with no ACK Delay.
    pub(crate) fn ping_rtt_sample(&mut self, rtt: Duration, now: Instant) {
        self.est.rtt_sample(rtt, Duration::ZERO, false, now);
    }

    // ---- the batches in flight ----------------------------

    /// The oldest unacknowledged batch that `pick` selects, searched from
    /// the position `from` and above, which then moves past the batches
    /// passed over: amortized constant work per batch. Batch ends only
    /// grow, and a batch becomes neither ack-eliciting nor watched later.
    fn oldest_unacked(&self, from: &Cell<u64>, pick: impl Fn(&Batch) -> bool) -> Option<&Batch> {
        let floor = from.get().max(self.acked);
        let i = self.batches.partition_point(|b| b.end <= floor);
        let mut passed = floor;
        let found = self.batches.range(i..).find(|b| {
            let hit = pick(b);
            if !hit {
                passed = b.end;
            }
            hit
        });
        from.set(passed);
        found
    }

    /// When the oldest unacknowledged batch failure detection waits for
    /// was sent.
    pub(crate) fn oldest_unacked_watched(&self) -> Option<Instant> {
        self.oldest_unacked(&self.watched_from, |b| b.watched)
            .map(|b| b.time)
    }

    /// The oldest unacknowledged ack-eliciting batch.
    pub(crate) fn oldest_eliciting_batch(&self) -> Option<&Batch> {
        self.oldest_unacked(&self.eliciting_from, |b| b.eliciting)
    }

    /// The oldest unacknowledged ack-eliciting batch's send time.
    pub(crate) fn oldest_unacked_eliciting(&self) -> Option<Instant> {
        self.oldest_eliciting_batch().map(|b| b.time)
    }

    /// The first batch that ends at or after `pos`.
    pub(crate) fn batch_reaching(&self, pos: u64) -> Option<&Batch> {
        let i = self.batches.partition_point(|b| b.end < pos);
        self.batches.get(i)
    }

    /// The batches sent so far are not watched by failure detection: they
    /// went out before multipath was in use.
    pub(crate) fn unwatch_batches(&mut self) {
        for b in &mut self.batches {
            b.watched = false;
        }
    }

    /// The sample state of the batches sent so far is not needed (no pipe
    /// acknowledgement).
    pub(crate) fn forget_batches(&mut self) {
        self.batches = VecDeque::new();
    }

    /// Keeps the sample state of the batch just handed to the carrier, the
    /// last `last_batch` bytes up to `sent`;
    /// `peer_mad` is the peer's `zmux_max_ack_delay`.
    pub(crate) fn record_batch(
        &mut self,
        lane: u64,
        eliciting: bool,
        peer_mad: Duration,
        now: Instant,
    ) {
        if self.oldest_unacked_eliciting().is_none() {
            // Nothing in flight: the delivery-rate interval starts now.
            // Records without ack-eliciting frames (PIPE_ACK alone) do not
            // count, as in RFC 9002: nothing makes the peer acknowledge
            // them soon, and one left unacknowledged across an idle period
            // would stretch the first samples of the next burst over that
            // period.
            self.est.delivered_time = now;
            self.est.first_sent_time = now;
        }
        // Q_p now includes the batch itself (`batch_sent`): what is ahead
        // of it excludes it.
        let queued = self.queued();
        let unsent_ahead = queued.saturating_sub(self.last_batch);
        let queue =
            Duration::from_secs_f64((unsent_ahead as f64 / self.est.rate.max(1) as f64).min(1.0));
        let expect = Duration::from_secs_f64(queued as f64 / self.est.rate.max(1) as f64)
            + self.est.min_or_srtt()
            + peer_mad;
        self.batches.push_back(Batch {
            start: self.sent - self.last_batch.min(self.sent),
            end: self.sent,
            time: now,
            eliciting,
            watched: eliciting,
            delivered: self.acked,
            delivered_time: self.est.delivered_time,
            first_sent_time: self.est.first_sent_time,
            before_first_ack: self.acked == 0,
            bottleneck_epoch: self.bottleneck_epoch,
            in_bubble: self.bubble.is_some(),
            unsent_ahead,
            queue,
            lane: u32::try_from(lane).unwrap_or(u32::MAX),
            expect,
        });
    }

    /// Keeps the sample state of a batch of the single pipe, at most
    /// `entries` of them: beyond that a batch joins the latest entry (an
    /// ack-eliciting one replaces a non-eliciting entry with its own send
    /// time, from where the one it replaces started), so that a peer that
    /// acknowledges late cannot make the state grow with the batches sent
    /// meanwhile.
    pub(crate) fn record_single_batch(
        &mut self,
        lane: u64,
        eliciting: bool,
        entries: usize,
        peer_mad: Duration,
        now: Instant,
    ) {
        let mut start = None;
        if self.batches.len() >= entries
            && let Some(last) = self.batches.back_mut()
        {
            if !eliciting || last.eliciting {
                // The entry's lane is that of its first batch: only
                // multipath reads it (`covered`).
                last.end = self.sent;
                return;
            }
            // An ack-eliciting batch does not inherit the send time and
            // delivery state of non-eliciting ones before it: they may be
            // old (acknowledgements alone draw no acknowledgement), which
            // would make a huge RTT sample. The entry starts afresh, but
            // from where the one it replaces started, so that positions
            // there still give samples.
            start = self.batches.pop_back().map(|b| b.start);
        }
        self.record_batch(lane, eliciting, peer_mad, now);
        if let (Some(start), Some(b)) = (start, self.batches.back_mut()) {
            b.start = start;
        }
    }

    /// Advances the acknowledged position to `pos`, above the current one,
    /// takes the RTT and delivery-rate samples
    /// from the batches it covers and releases them. An RTT sample needs
    /// `rtt_ok`; `usable` says whether a batch may give samples at all
    /// (never one that would measure an outage), and `proven_ok` whether one
    /// that `usable` refuses may still give a queue-proven rate sample.
    /// `ack_delay` is the entry's ACK Delay, `peer_mad` the peer's
    /// `zmux_max_ack_delay`; a `quiet` sample enters min_rtt only while it has
    /// none.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn sample_ack(
        &mut self,
        pos: u64,
        ack_delay: Duration,
        peer_mad: Duration,
        rtt_ok: bool,
        quiet: bool,
        usable: impl Fn(&Batch) -> bool,
        proven_ok: impl Fn(&Batch) -> bool,
        now: Instant,
    ) -> AckSample {
        let old = self.acked;
        self.acked = pos;
        self.last_advance = now;
        // The idle period is over once the pipe is acknowledged again: what
        // is left of the first chunk's copy lapses.
        if let Some(m) = self.mp.as_deref_mut() {
            m.idle_copy = 0;
        }
        let mut s = AckSample::default();
        // RTT sample from the batch that holds byte pos - 1.
        let carrier = self
            .batches
            .iter()
            .find(|b| b.end >= pos)
            .filter(|b| b.start < pos)
            .copied();
        let mut eliciting = false;
        for b in &self.batches {
            eliciting |= b.end > old && b.eliciting;
            if b.end >= pos {
                break;
            }
        }
        if let Some(b) = carrier
            && rtt_ok
            && eliciting
            && usable(&b)
        {
            let stale = self
                .est
                .last_sample
                .is_none_or(|t| now.saturating_duration_since(t) >= Duration::from_secs(1));
            if ack_delay <= peer_mad || stale {
                let latest = now.saturating_duration_since(b.time);
                let min_rtt = self.est.min_rtt.get();
                let adjusted = self
                    .est
                    .rtt_sample(latest, ack_delay.min(peer_mad), quiet, now);
                s.min_moved = self.est.min_rtt.get() != min_rtt;
                s.rtt = Some(RttSample {
                    latest,
                    adjusted,
                    unsent_ahead: b.unsent_ahead,
                    sent_at: b.time,
                });
            }
        }
        // Delivery rate from the most recently sent ack-eliciting range
        // covered. A range of PIPE_ACK or PADDING alone is acknowledged
        // only with whatever the peer acknowledges next, on its timer: its
        // few bytes over that wait would read as a rate of a few hundred
        // bytes a second and, as a bottleneck sample, replace R_p (a
        // session-affinity pipe was then held for seconds by the limiter).
        // Queue-proven: the corrected RTT of the batch exceeds min_rtt by at least
        // 4 x min_rtt. A FIFO path held its bytes that long and was busy all the
        // while, so the sample is the path's rate: a bottleneck sample, in a bubble
        // too, and taken also from bytes sent before the pipe became SUSPECT (its
        // RTT sample stays out).
        // A zero RTT (which the filter keeps as 1 ns) proves nothing.
        let min_rtt = self
            .est
            .min_rtt
            .get()
            .filter(|&m| m > Duration::from_nanos(1));
        let proven = |b: &Batch| {
            min_rtt.is_some_and(|m| {
                now.saturating_duration_since(b.time)
                    .saturating_sub(ack_delay.min(peer_mad))
                    .saturating_sub(m)
                    >= m * 4
            })
        };
        if let Some(b) = self
            .batches
            .iter()
            .take_while(|b| b.end <= pos)
            .filter(|b| b.eliciting)
            .last()
            .copied()
            .filter(|b| usable(b) || (proven(b) && proven_ok(b)))
        {
            // As BBR, the delivered bytes over the longer of the send and
            // the acknowledgement interval, but each with its own bytes:
            // the position may cover part of a later batch, sent after
            // this one, outside its send interval. Counting those over the
            // send interval would overstate the rate (by up to a batch per
            // round trip on a slow pipe whose peer acknowledges on its
            // timer, which the estimator's maximum then keeps).
            let send = b.time.saturating_duration_since(b.first_sent_time);
            let ack = now.saturating_duration_since(b.delivered_time);
            let rate_over =
                |bytes: u64, d: Duration| (!d.is_zero()).then(|| bytes as f64 / d.as_secs_f64());
            let sent_rate = rate_over(b.end - b.delivered.min(b.end), send);
            let acked_rate = rate_over(pos - b.delivered, ack);
            let rate = match (sent_rate, acked_rate) {
                (Some(s), Some(a)) => Some(s.min(a)),
                (s, a) => s.or(a),
            }
            .map(|r| r as u64)
            .filter(|&r| r > 0);
            if let Some(rate) = rate {
                let app_limited = (b.before_first_ack
                    || b.in_bubble
                    || self.bottleneck_epoch == b.bottleneck_epoch)
                    && !proven(&b);
                self.est.rate_sample(rate, app_limited, now);
                s.rate = Some((rate, app_limited));
            }
            self.est.first_sent_time = b.time;
        }
        self.est.delivered_time = now;
        if pos >= self.est.round_end {
            self.est.round += 1;
            self.est.round_end = self.sent;
            s.round_end = true;
        }
        self.est.expire_rates(now);
        while self.batches.front().is_some_and(|b| b.end <= pos) {
            self.batches.pop_front();
        }
        if self.bubble.is_some_and(|p| pos >= p) {
            self.bubble = None;
        }
        s
    }

    /// A PIPE_ACK of a multipath session advanced the acknowledged position
    /// to `pos` (see [`OutPipe::sample_ack`]): bytes sent before the pipe
    /// last became SUSPECT, or while it is suspect, and those `heard`
    /// rejects give no samples. The penalty, the outstanding PIPE_PING
    /// frames and a revalidation end when the position reaches them, and
    /// the acknowledged activity records go. `quiet`: the session is quiet,
    /// and the sample keeps out of min_rtt.
    pub(crate) fn mp_acked(
        &mut self,
        pos: u64,
        ack_delay: Duration,
        peer_mad: Duration,
        quiet: bool,
        heard: impl Fn(&Batch) -> bool,
        now: Instant,
    ) -> Acked {
        // Bytes sent before the pipe last became SUSPECT give no samples; nor
        // do bytes acknowledged while the
        // pipe is suspect: a probe sent during the outage measures the
        // outage, not the path.
        let outage = if self.in_outage() {
            self.sent
        } else {
            self.mp().suspect_pos
        };
        let usable = |b: &Batch| b.end > outage && heard(b);
        let rtt_ok = self.state != OutState::Failed;
        // Bytes sent before SUSPECT (or acknowledged while suspect) still give a
        // queue-proven rate sample; a failed pipe and a suspension give none.
        let proven_ok = |b: &Batch| rtt_ok && heard(b);
        let sample = self.sample_ack(
            pos, ack_delay, peer_mad, rtt_ok, quiet, usable, proven_ok, now,
        );
        let m = self.mp_mut();
        let unpenalized = m.penalty_until.is_some_and(|p| pos >= p);
        if unpenalized {
            m.penalty_until = None;
        }
        // The acknowledged position reached the revalidation's PIPE_PING.
        let revalidated = matches!(m.revalidating, Some(Revalidation::Until(e)) if pos >= e);
        let mut activity = false;
        while m.activity_ends.front().is_some_and(|&e| e <= pos) {
            m.activity_ends.pop_front();
            activity = true;
        }
        Acked {
            sample,
            unpenalized,
            revalidated,
            activity,
        }
    }

    // ---- retained frames ------------------------------------------------------------

    /// The send-order position up to which lane `lane`'s bytes are all
    /// acknowledged: every frame it carried that ends there or before is
    /// acknowledged. Without lanes, the acknowledged position.
    #[inline]
    fn lane_floor(&self, lane: u64) -> u64 {
        match self.lanes.as_deref() {
            Some(l) => l.floor_of(lane).unwrap_or(u64::MAX),
            None => self.acked,
        }
    }

    /// Moves the retained frames of lane `lane` that its position covers
    /// to `acked`.
    pub(crate) fn take_acked_frames(&mut self, lane: u64, acked: &mut Vec<SentFrame>) {
        let floor = self.lane_floor(lane);
        let log = match self.lanes.as_deref_mut().and_then(|l| l.log_mut(lane)) {
            Some(log) => log,
            None => &mut self.mp_mut().log,
        };
        while let Some(&(end, f)) = log.front() {
            if end > floor {
                break;
            }
            log.pop_front();
            acked.push(f);
        }
    }

    /// The retained frames of each lane, lane 0 first: the send-order
    /// position after their record, and the frame, in the order sent.
    pub(crate) fn retained(
        &self,
    ) -> impl Iterator<Item = impl Iterator<Item = (u64, SentFrame)> + '_> + '_ {
        std::iter::once(&self.mp().log)
            .chain(self.lanes.iter().flat_map(|l| l.logs().map(|(_, log)| log)))
            .map(|log| log.iter().copied())
    }

    /// Whether the frame of lane `lane` whose record ends at send-order
    /// position `end` is acknowledged.
    #[inline]
    pub(crate) fn covered(&self, lane: u64, end: u64) -> bool {
        end <= self.lane_floor(lane)
    }

    /// Whether what the pipe sent up to send-order position `end`, in the
    /// batch that holds it, is acknowledged: by the cumulative point, or by
    /// the position of the lane the batch went on.
    pub(crate) fn covered_at(&self, end: u64) -> bool {
        if end <= self.acked {
            return true;
        }
        self.lanes.is_some()
            && self
                .batch_reaching(end)
                .is_some_and(|b| self.covered(u64::from(b.lane), end))
    }

    /// Stream data beyond the acknowledged position is retained.
    pub(crate) fn stream_unacked(&self) -> bool {
        let unacked = |lane: u64, log: &VecDeque<(u64, SentFrame)>| {
            let floor = self.lane_floor(lane);
            log.iter()
                .any(|(end, f)| *end > floor && matches!(f, SentFrame::Stream { .. }))
        };
        unacked(0, &self.mp().log)
            || self
                .lanes
                .as_deref()
                .is_some_and(|l| l.logs().any(|(n, log)| unacked(n, log)))
    }

    /// Adds to `frames` every retained frame beyond the acknowledged
    /// position of its lane not reinjected yet (once per pipe), and counts
    /// their stream bytes as reinjected.
    pub(crate) fn take_reinjection(&mut self, frames: &mut Vec<SentFrame>) {
        let sent = self.sent;
        let upto = self.mp().reinjected_upto;
        let beyond = |floor: u64, log: &VecDeque<(u64, SentFrame)>, frames: &mut Vec<SentFrame>| {
            let from = floor.max(upto);
            frames.extend(log.iter().filter(|(end, _)| *end > from).map(|(_, f)| *f));
        };
        beyond(self.lane_floor(0), &self.mp().log, frames);
        if let Some(l) = self.lanes.as_deref() {
            for (n, log) in l.logs() {
                beyond(l.floor_of(n).unwrap_or(u64::MAX), log, frames);
            }
        }
        let m = self.mp_mut();
        m.reinjected_upto = sent;
        m.bytes_reinjected += frames
            .iter()
            .map(|f| match f {
                SentFrame::Stream { len, .. } => *len,
                _ => 0,
            })
            .sum::<u64>();
    }

    /// The STREAM frames of the directions `moves` names that the pipe sent
    /// and has not had acknowledged, for the re-send on a penalty: each once,
    /// what an earlier penalty or a reinjection re-sent excluded.
    pub(crate) fn take_penalty_resend(
        &mut self,
        moves: impl Fn(StreamKey) -> bool,
        frames: &mut Vec<SentFrame>,
    ) {
        let sent = self.sent;
        let upto = self.mp().reinjected_upto.max(self.mp().penalty_resent_upto);
        let mut beyond = |floor: u64, log: &VecDeque<(u64, SentFrame)>| {
            let from = floor.max(upto);
            frames.extend(log.iter().filter_map(|&(end, f)| match f {
                SentFrame::Stream { key, .. } if end > from && moves(key) => Some(f),
                _ => None,
            }));
        };
        beyond(self.lane_floor(0), &self.mp().log);
        if let Some(l) = self.lanes.as_deref() {
            for (n, log) in l.logs() {
                beyond(l.floor_of(n).unwrap_or(u64::MAX), log);
            }
        }
        self.mp_mut().penalty_resent_upto = sent;
    }

    // ---- lanes ----------------------------------------------------------------------

    /// The lanes, once one was opened.
    #[inline]
    pub(crate) fn lanes(&self) -> Option<&OutLanes> {
        self.lanes.as_deref()
    }

    /// The carrier offers lanes (or no longer).
    pub(crate) fn set_lanes_offered(&mut self, on: bool) {
        self.lanes_offered = on;
    }

    /// The carrier's datagram channel, as the driver reports it.
    pub(crate) fn set_channel(&mut self, channel: Option<Channel>) {
        self.channel = channel;
    }

    /// The carrier's datagram channel.
    #[inline]
    pub(crate) fn channel(&self) -> Option<Channel> {
        self.channel
    }

    /// Whether the carrier offers lanes.
    #[inline]
    pub(crate) fn lanes_offered(&self) -> bool {
        self.lanes_offered
    }

    /// The lanes of the direction, lane 0 included.
    pub(crate) fn lane_count(&self) -> u64 {
        1 + self.lanes.as_deref().map_or(0, OutLanes::opened)
    }

    /// Bytes written to the carriers, over every lane (the first records of
    /// lanes included).
    pub(crate) fn bytes_written(&self) -> u64 {
        match self.lanes.as_deref() {
            Some(l) => {
                l.tx(0).map_or(0, |t| t.sent()) + l.iter().map(|(_, x)| x.tx().sent()).sum::<u64>()
            }
            None => self.sent,
        }
    }

    /// The bytes written on lane `lane` (its position): 0 for a lane never
    /// opened.
    pub(crate) fn sent_on(&self, lane: u64) -> u64 {
        match self.lanes.as_deref() {
            Some(l) => l.tx(lane).map_or(0, |t| t.sent()),
            None if lane == 0 => self.sent,
            None => 0,
        }
    }

    /// The position acknowledged on lane `lane`.
    pub(crate) fn acked_on(&self, lane: u64) -> u64 {
        match self.lanes.as_deref() {
            Some(l) => l.tx(lane).map_or(0, |t| t.acked()),
            None if lane == 0 => self.acked,
            None => 0,
        }
    }

    /// The acknowledged position of lane `lane` reached `pos`: the records
    /// with a PIPE_PING it covers are answered, each once.
    pub(crate) fn pings_acked(&mut self, lane: u64, pos: u64) {
        let Some(m) = self.mp.as_deref_mut() else {
            return;
        };
        let before = m.pings_unanswered.len();
        m.pings_unanswered
            .retain(|&(l, end)| l != lane || end > pos);
        m.pings_answered += (before - m.pings_unanswered.len()) as u64;
    }

    /// The peer acknowledged position `pos`, at most the bytes written
    /// there, on lane `lane`: whether the lane's position moved, and the
    /// cumulative acknowledgement point when it advanced. Without lanes
    /// both move together. With lanes the held bytes are taken again at
    /// `now`.
    pub(crate) fn ack_lane(&mut self, lane: u64, pos: u64, now: Instant) -> (bool, Option<u64>) {
        let span = self.held_span();
        let Some(l) = self.lanes.as_deref_mut() else {
            let moved = lane == 0 && pos > self.acked;
            return (moved, moved.then_some(pos));
        };
        if !l.ack(lane, pos) {
            return (false, None);
        }
        l.note_held(self.sent, now, span);
        let cum = l.cumulative(self.sent);
        (true, (cum > self.acked).then_some(cum))
    }

    /// The window of the held bytes' minimum: RTT_base_p.
    fn held_span(&self) -> Duration {
        self.limiter
            .as_deref()
            .map_or(self.est.srtt, |l| l.base_rtt(&self.est))
    }

    /// The held bytes the limiter leaves out of the bytes in flight at
    /// `now`: all of them during start-up, the
    /// smallest count of the last RTT_base_p afterwards; none without
    /// lanes or a limiter.
    pub(crate) fn held_out(&self, now: Instant) -> Held {
        match self.lanes.as_deref() {
            Some(l) => Held {
                now: l.held().count(),
                min: l.held().min(now, self.held_span()),
            },
            None => Held::default(),
        }
    }

    /// The bytes in flight as the limiter counts them at `now`: the
    /// ack-eliciting bytes beyond the acknowledged position, less the held
    /// bytes it leaves out.
    pub(crate) fn limiter_in_flight(&self, now: Instant) -> u64 {
        let raw = self.eliciting_in_flight();
        match self.limiter.as_deref() {
            Some(l) => raw.saturating_sub(l.left_out(self.held_out(now))),
            None => raw,
        }
    }

    /// Whether a lane may be opened now: the carrier offers lanes, a
    /// position above 0 is acknowledged on lane 0, no lane is unconfirmed,
    /// none was refused, and the next number is below the peer's `max`
    /// (its Max Lanes).
    pub(crate) fn may_open_lane(&self, max: u64, now: Instant) -> bool {
        if !self.lanes_offered || !self.takes_new_data() || self.acked_on(0) == 0 {
            return false;
        }
        match self.lanes.as_deref() {
            None => max > 1,
            Some(l) => {
                !l.closed()
                    && l.unconfirmed().is_none()
                    && l.next_number() < max
                    && l.retry_due(now)
            }
        }
    }

    /// Requests the next lane: its number. The driver attaches its stream
    /// with [`Self::lane_attached`].
    pub(crate) fn request_lane(&mut self) -> u64 {
        let (sent, acked, unsent) = (self.sent, self.acked, self.carrier_unsent);
        self.lanes
            .get_or_insert_with(|| Box::new(OutLanes::new(sent, acked, unsent)))
            .request()
    }

    /// The driver attached requested lane `n`; `false` when it is not one.
    pub(crate) fn lane_attached(&mut self, n: u64, framing: Framing, now: Instant) -> bool {
        self.lanes
            .as_deref_mut()
            .is_some_and(|l| l.attach(n, framing, now))
    }

    /// Requested lane `n` was not opened this time (no error): requested
    /// again later.
    /// Not before one smoothed RTT: a stream may be free by then.
    pub(crate) fn lane_unopened(&mut self, n: u64, now: Instant) -> bool {
        let retry_at = now + self.est.srtt;
        self.lanes
            .as_deref_mut()
            .is_some_and(|l| l.unrequest(n, retry_at))
    }

    /// Lane `n` ended before it was confirmed: refused. `false` when it was
    /// not unconfirmed.
    pub(crate) fn refuse_lane(&mut self, n: u64) -> bool {
        self.lanes.as_deref_mut().is_some_and(|l| l.refuse(n))
    }

    /// The lanes, to change their bindings and write state.
    #[inline]
    pub(crate) fn lanes_mut(&mut self) -> Option<&mut OutLanes> {
        self.lanes.as_deref_mut()
    }

    // ---- write progress -------------------------------------------------------------

    /// The carrier takes bytes: it did not refuse the last ones.
    #[inline]
    pub(crate) fn writable(&self) -> bool {
        !matches!(self.hold, Some(Hold::Refused { .. }))
    }

    /// The carrier takes bytes now: writable, and no write call in
    /// progress.
    #[inline]
    pub(crate) fn open(&self) -> bool {
        self.hold.is_none()
    }

    /// The carrier declares a low-water mark (or no longer); `true` when it
    /// declares one it did not have.
    pub(crate) fn set_low_water(&mut self, on: bool) -> bool {
        let new = on && !self.low_water;
        self.low_water = on;
        new
    }

    /// The carrier's unsent bytes; `true` when this is the first count it
    /// reports (which declares the capability).
    pub(crate) fn set_unsent(&mut self, bytes: u64, now: Instant) -> bool {
        let first = !self.unsent_reported;
        if (first || bytes < self.carrier_unsent || bytes == 0)
            && let Some(m) = self.mp.as_deref_mut()
        {
            m.unsent_progress = now;
        }
        self.unsent_reported = true;
        self.carrier_unsent = bytes;
        first
    }

    /// The unsent bytes of lane `lane`'s carrier stream; the pipe's are
    /// the sum over its lanes. `true` when this
    /// is the first count the pipe reports.
    pub(crate) fn set_lane_unsent(&mut self, lane: u64, bytes: u64, now: Instant) -> bool {
        let total = match self.lanes.as_deref_mut() {
            Some(l) => l.set_unsent(lane, bytes),
            None if lane == 0 => bytes,
            None => return false,
        };
        self.set_unsent(total, now)
    }

    /// A write to lane `lane` (not 0) ended, the carrier refusing bytes or
    /// not: the lane's writability and write stall
    /// ([`OutPipe::write_stall_from`]).
    pub(crate) fn lane_write(&mut self, lane: u64, refused: bool, now: Instant) {
        if let Some(l) = self.lanes.as_deref_mut() {
            l.set_writable(lane, !refused, now);
        }
    }

    /// The carrier's unsent bytes, `None` until the adapter reported a
    /// count (reported as `queued_bytes`).
    #[inline]
    pub(crate) fn reported_unsent(&self) -> Option<u64> {
        self.unsent_reported.then_some(self.carrier_unsent)
    }

    /// The carrier took `bytes` of the batch being written on lane `lane`.
    pub(crate) fn written(&mut self, lane: u64, bytes: u64) {
        match self.lanes.as_deref_mut() {
            Some(l) if lane != 0 => l.took(lane, bytes),
            _ => self.writing = self.writing.saturating_sub(bytes),
        }
    }

    /// Q_p: bytes committed to the pipe and not yet transmitted, over its
    /// lanes: those of the batches whose write calls have not finished (in
    /// full until a call returns, then what the carrier did not take) plus
    /// the carrier's unsent count, 0 where the adapter reports none.
    #[inline]
    pub(crate) fn queued(&self) -> u64 {
        self.carrier_unsent + self.writing + self.lanes.as_deref().map_or(0, OutLanes::writing)
    }

    /// A write call's progress: `w` reports a call that started, or one
    /// that ended and whether the carrier refused bytes. `has_data`: stream
    /// data waits for a pipe, which makes a pipe that holds the writes the
    /// bottleneck, when the hold begins or ends. `waits`: bytes wait for
    /// this one, which starts the write-stall clock of a refusing carrier.
    /// A refusal reported again changes nothing.
    pub(crate) fn write_progress(
        &mut self,
        w: &super::super::PipeWrite,
        has_data: bool,
        waits: bool,
        now: Instant,
    ) {
        let hold = match w.end {
            None => Hold::Call {
                start: w.start,
                bytes: w.bytes,
            },
            Some(end) if w.refused => Hold::Refused {
                end,
                unsent: w.unsent,
            },
            Some(end) => {
                if w.bytes > 0
                    && let Some(l) = self.lanes.as_deref_mut()
                {
                    l.zero_progress(end);
                }
                if self.hold.take().is_none() {
                    return;
                }
                if let Some(m) = self.mp.as_deref_mut() {
                    m.waiting_since = None;
                }
                if std::mem::take(&mut self.held_with_data) || has_data {
                    self.bottleneck_epoch += 1;
                }
                return;
            }
        };
        match self.hold {
            Some(Hold::Refused { .. }) if matches!(hold, Hold::Refused { .. }) => return,
            None => self.held_with_data = has_data,
            Some(_) => self.held_with_data |= has_data,
        }
        self.hold = Some(hold);
        if waits && matches!(hold, Hold::Refused { .. }) {
            self.mp_mut().waiting_since = Some(now);
        }
    }

    /// A write opportunity ended: with nothing more to send it is an
    /// application-limited moment (`waiting` false); one that the limiter
    /// ended while data waited makes the pipe the bottleneck.
    pub(crate) fn opportunity_ended(&mut self, waiting: bool) {
        if !waiting {
            self.bubble = Some(self.sent);
        } else if self.limiter_held() {
            self.bottleneck_epoch += 1;
        }
    }

    /// Bytes wait for the pipe while it refuses them: the write-stall
    /// clock starts now.
    pub(crate) fn refused_since(&mut self, now: Instant) {
        self.mp_mut().waiting_since = Some(now);
    }

    /// Whether the write-stall clock of a refusing pipe is still to start:
    /// live, not writable, no bytes recorded as waiting.
    pub(crate) fn refusing_unclocked(&self) -> bool {
        !self.writable() && self.is_live() && self.mp().waiting_since.is_none()
    }

    /// The reference time of a write stall, if the pipe has one: a write
    /// call in progress from its start plus its expected duration, its
    /// size / R_p; a refusing carrier, while bytes wait (since
    /// `waits_since` when none were recorded), from when its unsent count
    /// last decreased, or from the end of the call that found it full plus
    /// the time to drain U, what it held then.
    ///
    /// With lanes, each lane with bytes waiting is a carrier of its own:
    /// the shortest of their stalls, and none longer than the time since
    /// any lane progressed.
    pub(crate) fn write_stall_from(
        &self,
        waits_since: impl FnOnce() -> Option<Instant>,
    ) -> Option<Instant> {
        let zero = self.lane_zero_stall_from(waits_since);
        match self.lanes.as_deref() {
            Some(l) => l.stall_from(zero),
            None => zero,
        }
    }

    /// The write stall reference of the pipe's own carrier (lane 0).
    fn lane_zero_stall_from(
        &self,
        waits_since: impl FnOnce() -> Option<Instant>,
    ) -> Option<Instant> {
        let rate = self.est.rate.max(1) as f64;
        match self.hold? {
            Hold::Call { start, bytes } => {
                start.checked_add(Duration::from_secs_f64(bytes as f64 / rate))
            }
            Hold::Refused { end, unsent } => {
                let m = self.mp();
                let since = m.waiting_since.or_else(waits_since)?;
                if self.unsent_reported {
                    // Since the carrier's unsent count last decreased.
                    return Some(since.max(m.unsent_progress));
                }
                // Minus the time the carrier needs to drain what it held
                // when the call ended: a slow carrier still taking bytes at
                // its rate never looks stalled.
                let drain = Duration::from_secs_f64(unsent as f64 / rate);
                since.max(end).checked_add(drain)
            }
        }
    }

    /// The reference time of an ack stall, not before `detect_from`, if
    /// the pipe has one.
    pub(crate) fn ack_stall_from(&self, detect_from: Instant) -> Option<Instant> {
        let oldest = self.oldest_unacked_watched()?;
        let from = self.last_advance.max(oldest);
        Some(from.max(detect_from))
    }

    /// queue_p of the oldest unacknowledged ack-eliciting batch: min(1 s,
    /// unsent_ahead / R_p), both as of when it was handed to the carrier.
    pub(crate) fn queue_term(&self) -> Duration {
        self.oldest_eliciting_batch()
            .map_or(Duration::ZERO, |b| b.queue)
    }

    /// The time the carrier's unsent bytes need to be transmitted,
    /// queued_bytes / R_p; `None` where the adapter reports no count.
    pub(crate) fn queue_delay(&self) -> Option<Duration> {
        let unsent = self.reported_unsent()?;
        Some(Duration::from_secs_f64(
            unsent as f64 / self.est.rate.max(1) as f64,
        ))
    }

    // ---- probes ---------------------------------------------------------------------

    /// Since when a PIPE_PING is owed.
    #[inline]
    pub(crate) fn ping_wanted(&self) -> Option<Instant> {
        self.mp().ping_wanted
    }

    /// A PIPE_PING is owed from now, unless one is.
    pub(crate) fn want_ping(&mut self, now: Instant) {
        self.mp_mut().ping_wanted.get_or_insert(now);
    }

    /// A PIPE_PING is due now (an idle probe).
    pub(crate) fn probe(&mut self, now: Instant) {
        self.mp_mut().ping_wanted = Some(now);
    }

    /// A PIPE_PING went into the batch being written.
    pub(crate) fn ping_written(&mut self) {
        let m = self.mp_mut();
        m.ping_wanted = None;
        m.pings_sent += 1;
        m.ping_in_batch = true;
    }

    /// The reference of the idle probe: the last ack-eliciting byte, or
    /// when the pipe became usable if later.
    #[inline]
    pub(crate) fn last_eliciting(&self) -> Instant {
        self.mp().last_eliciting_or_usable()
    }

    /// The pipe's own idle-probe interval and jitter (`None`: the
    /// session's), the draw u of the current wait, and whether it draws as
    /// usual (false: a bootstrap pipe's first wait, from the whole interval).
    #[inline]
    pub(crate) fn probe_settings(&self) -> (Option<Period>, Option<f64>, f64, bool) {
        let m = self.mp();
        (m.probe_interval, m.probe_jitter, m.probe_u, !m.boot_wait)
    }

    /// H_p of the current idle-probe wait: `hold()` the first time it is
    /// asked for after the wait started, the same value after.
    pub(crate) fn probe_hold(&self, hold: impl FnOnce() -> Duration) -> Duration {
        use std::sync::atomic::Ordering::Relaxed;
        let c = &self.mp().probe_hold;
        match c.load(Relaxed) {
            u64::MAX => {
                let h = hold();
                let n = u64::try_from(h.as_nanos()).unwrap_or(u64::MAX - 1);
                c.store(n, Relaxed);
                Duration::from_nanos(n)
            }
            n => Duration::from_nanos(n),
        }
    }

    /// Return-pipe liveness: a PIPE_PING is owed when the pipe has sent
    /// nothing ack-eliciting for longer than `quiet`, unless the batch
    /// carries one.
    pub(crate) fn check_liveness(&mut self, quiet: Duration, now: Instant) {
        let last = self.mp().last_eliciting_or_usable();
        let m = self.mp_mut();
        // One PIPE_PING per batch is enough.
        if !m.ping_in_batch && now.saturating_duration_since(last) > quiet {
            m.ping_wanted.get_or_insert(now);
        }
    }

    // ---- PIPE_ACK on the pipe -------------------------------------------------------

    /// The first record still owes its complete snapshot.
    #[inline]
    pub(crate) fn snapshot_first(&self) -> bool {
        self.mp().snapshot_first
    }

    /// A PIPE_PING arrived on the attachment's inbound pipe: the PIPE_ACK
    /// that answers it goes on this pipe too.
    #[inline]
    pub(crate) fn answers_ping(&self) -> bool {
        self.mp().answer_ping
    }

    /// The answer to a PIPE_PING goes on this pipe too.
    pub(crate) fn answer_ping(&mut self) {
        self.mp_mut().answer_ping = true;
    }

    /// The first record owes no snapshot any more (nothing to report).
    pub(crate) fn no_first_snapshot(&mut self) {
        self.mp_mut().snapshot_first = false;
    }

    /// A PIPE_ACK went on the pipe: the first record's snapshot and the
    /// answer to a PIPE_PING are written.
    pub(crate) fn pipe_ack_written(&mut self) {
        let m = self.mp_mut();
        m.snapshot_first = false;
        m.answer_ping = false;
    }

    // ---- reinjection hold -----------------------------------------------------------

    /// The reinjection hold ends: a PIPE_ACK arrived.
    pub(crate) fn end_reinject_hold(&mut self) {
        self.mp_mut().reinject_hold = None;
    }

    /// When the reinjection hold ends, while it lasts after `now`.
    #[inline]
    pub(crate) fn reinject_hold_after(&self, now: Instant) -> Option<Instant> {
        self.mp().reinject_hold.filter(|&t| t > now)
    }

    /// The bytes the pipe may still reinject while its reinjection hold
    /// lasts at `now` (`chunk` in all); `None` without a hold.
    #[inline]
    pub(crate) fn reinject_room(&self, chunk: u64, now: Instant) -> Option<u64> {
        let m = self.mp();
        m.reinject_hold
            .is_some_and(|t| now < t)
            .then(|| chunk.saturating_sub(m.reinject_held))
    }

    /// The reinjection hold is used up for now (a frame at offset 0 needs
    /// more than it leaves): at least `chunk` counts as reinjected.
    pub(crate) fn exhaust_reinject_hold(&mut self, chunk: u64) {
        let m = self.mp_mut();
        m.reinject_held = m.reinject_held.max(chunk);
    }

    /// The pipe reinjected `n` bytes: they count against the hold while
    /// one is set.
    pub(crate) fn reinjected(&mut self, n: u64) {
        let m = self.mp_mut();
        if m.reinject_hold.is_some() {
            m.reinject_held += n;
        }
    }

    // ---- penalties and counters ------------------------------------------------------

    /// The opportunistic-reinjection penalty: the pipe takes no new stream
    /// data until everything sent so far is acknowledged; the first of an
    /// episode halves its rate. `None` when nothing is in flight, else
    /// whether this started an episode.
    pub(crate) fn penalize(&mut self) -> Option<bool> {
        if self.acked >= self.sent {
            return None;
        }
        let sent = self.sent;
        let first = self.mp().penalty_until.is_none();
        if first {
            self.est.penalize();
        }
        self.mp_mut().penalty_until = Some(sent);
        Some(first)
    }

    /// Bytes copied opportunistically onto the pipe.
    pub(crate) fn opportunistic(&mut self, n: u64) {
        self.mp_mut().bytes_opportunistic += n;
    }

    /// The quality counters: `None` outside
    /// multipath.
    pub(crate) fn quality(&self) -> Option<PipeQuality> {
        let m = self.mp.as_deref()?;
        Some(PipeQuality {
            joined_at: Some(m.joined_at),
            suspect_count: m.suspect_count,
            in_probation: m.probation.active(),
            revalidating: m.revalidating.is_some(),
            bytes_reinjected: m.bytes_reinjected,
            bytes_opportunistic: m.bytes_opportunistic,
            bytes_redundant: m.bytes_redundant,
            pings_sent: m.pings_sent,
            pings_answered: m.pings_answered,
        })
    }

    /// The `spread-round-robin` current value of the session's policy.
    #[inline]
    pub(crate) fn rr_current(&self) -> f64 {
        self.mp().rr_current
    }

    /// Moves the round-robin current value by `delta`, or resets it for a
    /// pipe that is not eligible (`None`).
    pub(crate) fn rr_step(&mut self, delta: Option<f64>) {
        let m = self.mp_mut();
        m.rr_current = delta.map_or(0.0, |d| m.rr_current + d);
    }

    // ---- revalidation ----------------------------------

    /// Starts a revalidation: its PIPE_PING is owed now. `false` when the
    /// pipe is not eligible or awaits one.
    pub(crate) fn revalidate(&mut self, now: Instant) -> bool {
        if !self.revalidatable() {
            return false;
        }
        let m = self.mp_mut();
        m.revalidating = Some(Revalidation::PingOwed);
        m.ping_wanted.get_or_insert(now);
        true
    }

    /// The revalidation ends; whether one was awaited.
    pub(crate) fn end_revalidation(&mut self) -> bool {
        self.mp_mut().revalidating.take().is_some()
    }

    // ---- probation ---------------------------------------

    /// In probation.
    #[inline]
    pub(crate) fn in_probation(&self) -> bool {
        self.mp().probation.active()
    }

    /// When the current probation started, and its exponent.
    pub(crate) fn probation(&self) -> Option<(Instant, u32)> {
        self.mp.as_deref()?.probation.current()
    }

    /// The pipe's own probation history (fate group 0).
    pub(crate) fn history(&self) -> History {
        self.mp().probation.history()
    }

    /// The pipe's own probation history, to change.
    pub(crate) fn history_mut(&mut self) -> &mut History {
        self.mp_mut().probation.history_mut()
    }

    /// A probation with exponent `k` starts now, when `enabled`; the ACTIVE
    /// period that begins counts for the uptime cap when `counted`.
    pub(crate) fn start_probation(&mut self, k: u32, enabled: bool, counted: bool, now: Instant) {
        self.mp_mut().probation.start(k, enabled, counted, now);
    }

    /// Probation was disabled: one in progress ends now; whether one did.
    pub(crate) fn cancel_probation(&mut self) -> bool {
        self.mp_mut().probation.cancel()
    }

    /// The probation ended when due.
    pub(crate) fn end_probation(&mut self) {
        self.mp_mut().probation.end();
    }

    /// The pipe became suspect: whether it was in probation, and when its
    /// ACTIVE period began if it counts for the uptime cap.
    pub(crate) fn probation_suspected(&mut self) -> (bool, Option<Instant>) {
        self.mp_mut().probation.suspected()
    }

    /// The attachment failed: whether the pipe was in probation, and when
    /// its ACTIVE period began if it counts for the uptime cap.
    pub(crate) fn probation_failed(&mut self) -> (bool, Option<Instant>) {
        self.mp_mut().probation.failed()
    }

    /// The probes of a probation, every `every`: a PIPE_PING is owed when
    /// one is due.
    pub(crate) fn probation_probe(&mut self, every: Duration, now: Instant) {
        if self.mp().probation.active() && self.is_live() {
            let m = self.mp_mut();
            if m.probation.probe(every, now) {
                m.ping_wanted.get_or_insert(now);
            }
        }
    }

    /// When the next probation probe is due, every `every`.
    pub(crate) fn next_probation_probe(&self, every: Duration, now: Instant) -> Instant {
        self.mp().probation.next_probe(every, now)
    }

    // ---- redundant copies -------------------------------

    /// The copies queued for lane `lane`: lane 0's for redundant chunks of
    /// another pipe, the copy lane's for those of the pipe itself in a tier
    /// where it is the only usable pipe.
    fn copies(&self, lane: u64) -> Option<&VecDeque<QueuedCopy>> {
        if lane == 0 {
            return Some(&self.mp().copies);
        }
        self.lanes.as_deref()?.copies(lane)
    }

    fn copies_mut(&mut self, lane: u64) -> Option<&mut VecDeque<QueuedCopy>> {
        if lane == 0 {
            return Some(&mut self.mp_mut().copies);
        }
        self.lanes.as_deref_mut()?.copies_mut(lane)
    }

    /// The first copy queued for lane `lane`.
    #[inline]
    pub(crate) fn next_copy(&self, lane: u64) -> Option<QueuedCopy> {
        self.copies(lane)?.front().copied()
    }

    /// Copies are queued for lane `lane`.
    #[inline]
    pub(crate) fn copies_queued(&self, lane: u64) -> bool {
        self.copies(lane).is_some_and(|c| !c.is_empty())
    }

    /// The first copy queued for lane `lane` is done.
    pub(crate) fn pop_copy(&mut self, lane: u64) {
        if let Some(c) = self.copies_mut(lane) {
            c.pop_front();
        }
    }

    /// The first copy queued for lane `lane` was sent up to `off`.
    pub(crate) fn copy_sent_to(&mut self, lane: u64, off: u64) {
        if let Some(front) = self.copies_mut(lane).and_then(VecDeque::front_mut) {
            front.off = off;
        }
    }

    /// Queues a copy for lane `lane`; returns how many are queued.
    pub(crate) fn queue_copy(&mut self, lane: u64, c: QueuedCopy) -> usize {
        let Some(copies) = self.copies_mut(lane) else {
            return 0;
        };
        copies.push_back(c);
        copies.len()
    }

    /// Takes the queue of copies of lane `lane`, to filter it (it keeps its
    /// capacity when given back).
    pub(crate) fn take_copies(&mut self, lane: u64) -> VecDeque<QueuedCopy> {
        self.copies_mut(lane)
            .map(std::mem::take)
            .unwrap_or_default()
    }

    /// Gives the queue of copies of lane `lane` back.
    pub(crate) fn restore_copies(&mut self, lane: u64, copies: VecDeque<QueuedCopy>) {
        if let Some(c) = self.copies_mut(lane) {
            *c = copies;
        }
    }

    /// Redundant bytes sent on the pipe.
    pub(crate) fn redundant(&mut self, n: u64) {
        self.mp_mut().bytes_redundant += n;
    }

    /// The first chunk of new data after an idle period is copied: whether
    /// no such copy runs.
    pub(crate) fn idle_copy_clear(&self) -> bool {
        self.mp().idle_copy == 0
    }

    /// New data of `n` bytes goes on the pipe: the part of it still to be
    /// copied after an idle period (`arm`, `chunk` from now on).
    pub(crate) fn idle_copy_take(&mut self, arm: Option<u64>, n: u64) -> u64 {
        let m = self.mp_mut();
        if let Some(chunk) = arm {
            m.idle_copy = chunk;
        }
        let idle = m.idle_copy.min(n);
        m.idle_copy -= idle;
        idle
    }

    /// The idle copy lapses.
    pub(crate) fn end_idle_copy(&mut self) {
        self.mp_mut().idle_copy = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::session::PipeWrite;

    const MS: Duration = Duration::from_millis(1);

    /// A multipath pipe at the initial rate of 1 MB/s.
    fn pipe(now: Instant) -> OutPipe {
        OutPipe::new(Framing::ByteStream, OutState::Active, MS * 100, now).with_mp(
            Detection {
                suspect_floor: MS * 250,
                dead_timeout: None,
                probe_interval: None,
                probe_jitter: None,
                probe_seed: 0,
            },
            now,
        )
    }

    /// A failed pipe lost what it had sent and not had acknowledged; a
    /// live one nothing.
    #[test]
    fn a_failure_loses_the_unacknowledged_bytes() {
        let mut o = pipe(Instant::now());
        o.sent = 1000;
        o.acked = 400;
        assert_eq!(o.lost(), 0);
        o.fail();
        assert_eq!(o.lost(), 600);
    }

    /// The loss rate: no sample before a second has passed or before bytes
    /// were sent; then an EWMA with gain 1/8, and a count that moves back
    /// counts as no retransmission.
    #[test]
    fn the_loss_rate_is_sampled_once_a_second() {
        let t = Instant::now();
        let mut o = pipe(t);
        o.set_retransmitted(0, t);
        assert_eq!((o.retransmitted(), o.loss_rate()), (Some(0), None));
        o.sent = 1000;
        o.set_retransmitted(10, t + MS * 500);
        assert_eq!((o.retransmitted(), o.loss_rate()), (Some(10), None));
        o.set_retransmitted(10, t + MS * 1000);
        assert_eq!(o.loss_rate(), Some(0.01));
        o.sent = 2000;
        o.set_retransmitted(5, t + MS * 2000);
        assert_eq!(o.loss_rate(), Some(0.01 * 7.0 / 8.0));
    }

    /// Each PIPE_PING counts as answered once, when the acknowledged
    /// position of its record's lane reaches the record's end, whatever
    /// later pings do.
    #[test]
    fn pings_are_answered_each_once_by_their_own_record() {
        let now = Instant::now();
        let mut o = pipe(now);
        for _ in 0..2 {
            o.ping_written();
            o.batch_sent(0, 100, 1, Some(100));
            o.mp_batch_sent(0, true, MS * 25, now);
        }
        assert_eq!(o.mp().pings_sent, 2);
        // A position inside the first record answers nothing.
        o.pings_acked(0, 99);
        assert_eq!(o.mp().pings_answered, 0);
        // The first record's end answers the first ping only.
        o.pings_acked(0, 100);
        assert_eq!(o.mp().pings_answered, 1);
        // Another lane's position answers none of lane 0's.
        o.pings_acked(1, 1000);
        assert_eq!(o.mp().pings_answered, 1);
        o.pings_acked(0, 200);
        o.pings_acked(0, 300);
        assert_eq!(o.mp().pings_answered, 2);
    }

    /// Each idle-probe wait draws u once, when it starts: ack-eliciting
    /// batches keep it, a batch with a PIPE_PING draws the next; the draws
    /// cover [0, 1) to within 10% of both ends.
    #[test]
    fn probe_waits_draw_once_per_wait() {
        let now = Instant::now();
        let mut o = pipe(now);
        let mut us = Vec::new();
        for _ in 0..1000 {
            let u = o.probe_settings().2;
            assert!((0.0..1.0).contains(&u));
            o.mp_batch_sent(0, true, MS * 25, now);
            assert_eq!(o.probe_settings().2, u, "an eliciting batch drew again");
            o.ping_written();
            o.mp_batch_sent(0, true, MS * 25, now);
            us.push(u);
        }
        assert!(us.iter().any(|&u| u < 0.1) && us.iter().any(|&u| u > 0.9));
        assert!(us.windows(2).all(|w| w[0] != w[1]));
    }

    /// Only a bootstrap pipe draws its first idle-probe wait from the whole
    /// interval: a joined pipe carried the joiner's PIPE_PING, so both of
    /// its ends draw as usual from the start.
    #[test]
    fn only_a_bootstrap_pipe_draws_its_first_wait_from_the_whole_interval() {
        let now = Instant::now();
        assert!(pipe(now).accepted(now).probe_settings().3, "accepted join");
        let mut joiner = pipe(now);
        joiner.join_proven(now);
        assert!(joiner.probe_settings().3, "join proven");
        let mut boot = pipe(now).with_parameters_first();
        assert!(!boot.probe_settings().3, "bootstrap");
        boot.ping_written();
        boot.mp_batch_sent(0, true, MS * 25, now);
        assert!(boot.probe_settings().3, "bootstrap after a PIPE_PING");
        let mut started = OutPipe::new(Framing::ByteStream, OutState::Active, MS * 100, now)
            .start_multipath(Detection::NONE, now);
        assert!(!started.probe_settings().3, "bootstrap starting multipath");
        started.ping_written();
        started.mp_batch_sent(0, true, MS * 25, now);
        assert!(started.probe_settings().3);
    }

    /// H_p is fixed for a wait the first time it is measured and taken
    /// again only when the next wait starts (a PIPE_PING went).
    #[test]
    fn probe_hold_is_fixed_per_wait() {
        let now = Instant::now();
        let mut o = pipe(now);
        assert_eq!(o.probe_hold(|| MS * 300), MS * 300);
        // A guardrail's budget spent meanwhile does not move it.
        assert_eq!(o.probe_hold(|| MS * 100), MS * 300);
        o.mp_batch_sent(0, true, MS * 25, now);
        assert_eq!(o.probe_hold(|| MS * 100), MS * 300);
        o.ping_written();
        o.mp_batch_sent(0, true, MS * 25, now);
        assert_eq!(o.probe_hold(|| MS * 100), MS * 100);
    }

    #[test]
    fn both_driver_styles_feed_one_write_stall_clock() {
        let t0 = Instant::now();
        let mut o = pipe(t0);
        // A blocking call of 100 kB in progress is expected to take 100 ms
        // at 1 MB/s: its stall is measured from then.
        o.write_progress(&PipeWrite::started(t0, 100_000), true, false, t0);
        assert!(o.writable() && !o.open());
        assert_eq!(o.queued(), 0, "a call reports no queue of its own");
        assert_eq!(o.write_stall_from(|| None), Some(t0 + MS * 100));
        // Its return while data waits makes the pipe the bottleneck.
        let t1 = t0 + MS * 30;
        o.write_progress(
            &PipeWrite::returned(t0, t1, 100_000, 0, false),
            false,
            false,
            t1,
        );
        assert!(o.open() && o.bottleneck_epoch == 1);
        assert_eq!(o.write_stall_from(|| Some(t1)), None);

        // A non-blocking carrier that refuses bytes while bytes wait: from
        // when they waited, less the time to drain the 50 kB it held.
        let t2 = t0 + MS * 40;
        o.write_progress(
            &PipeWrite::returned(t2, t2, 0, 50_000, true),
            false,
            true,
            t2,
        );
        assert!(!o.writable() && !o.open());
        assert_eq!(o.write_stall_from(|| None), Some(t2 + MS * 50));
        // A refusal again changes nothing; the carrier taking bytes ends
        // the hold, without a bottleneck when no data waited.
        let t3 = t0 + MS * 60;
        o.write_progress(&PipeWrite::returned(t3, t3, 0, 0, true), false, true, t3);
        assert_eq!(o.write_stall_from(|| None), Some(t2 + MS * 50));
        o.write_progress(
            &PipeWrite::returned(t3, t3, 1000, 0, false),
            false,
            false,
            t3,
        );
        assert!(o.writable() && o.open() && o.bottleneck_epoch == 1);
        assert_eq!(o.write_stall_from(|| Some(t3)), None);
    }

    /// A batch of `len` bytes of the send order on lane `lane`, with its
    /// sample state, as a write opportunity leaves it.
    fn batch(o: &mut OutPipe, lane: u64, len: u64, now: Instant) {
        o.batch_sent(lane, len, 1, Some(len));
        o.mp_batch_sent(lane, true, MS * 25, now);
    }

    /// Acknowledges `pos` on `lane` as a PIPE_ACK entry does: the samples
    /// come from the cumulative point when it advances.
    fn ack(o: &mut OutPipe, lane: u64, pos: u64, now: Instant) -> Option<u64> {
        let (_, cum) = o.ack_lane(lane, pos, now);
        if let Some(c) = cum {
            o.mp_acked(c, Duration::ZERO, MS * 25, false, |_| true, now);
        }
        cum
    }

    /// A slow path of 20 kB/s and 20 ms behind a deep carrier buffer: a
    /// small batch gives min_rtt, then 2 s of batches handed over at once,
    /// which the carrier takes whole (never a bottleneck by refusal), are
    /// acknowledged as the path serialises them. `suspect` marks the pipe
    /// SUSPECT once they are handed over. Returns R_p after the last.
    fn deep_buffer_rate(suspect: bool) -> u64 {
        let t0 = Instant::now();
        let mut o = pipe(t0);
        let (rate, rtt) = (20_000.0, MS * 20);
        let mut pos = 0;
        let mut done = t0;
        let mut acks = Vec::new();
        for (i, len) in std::iter::once(20)
            .chain(std::iter::repeat_n(1000, 40))
            .enumerate()
        {
            let sent = if i == 0 { t0 } else { t0 + rtt * 2 };
            batch(&mut o, 0, len, sent);
            pos += len;
            done = done.max(sent) + Duration::from_secs_f64(len as f64 / rate);
            acks.push((pos, done + rtt));
            if i == 0 {
                ack(&mut o, 0, pos, done + rtt);
                acks.clear();
            }
        }
        if suspect {
            assert!(o.suspect(t0 + rtt * 2));
        }
        for (p, at) in acks {
            ack(&mut o, 0, p, at);
        }
        o.est().rate
    }

    /// Queue-proven samples: on a deep carrier buffer R_p converges to the
    /// slow path's rate, though no write was ever refused.
    #[test]
    fn a_deep_buffer_slow_pipe_converges() {
        let r = deep_buffer_rate(false);
        assert!((10_000..=40_000).contains(&r), "R_p {r}");
    }

    /// Bytes sent before SUSPECT give no RTT sample but a queue-proven rate
    /// sample: R_p does not stay at its old maximum.
    #[test]
    fn a_suspect_pipe_does_not_keep_its_old_rate() {
        let r = deep_buffer_rate(true);
        assert!((10_000..=40_000).contains(&r), "R_p {r}");
    }

    /// Q_p and unsent_ahead on a slow carrier that reports no unsent
    /// count: a batch whose write call has not returned counts in full
    /// ahead of a batch handed to another lane, then by what the carrier
    /// did not take; a count the carrier reports adds to it, and is all
    /// `queued_bytes` shows.
    #[test]
    fn unsent_ahead_counts_the_batches_still_being_written() {
        let t0 = Instant::now();
        let mut o = pipe(t0);
        assert_eq!(o.request_lane(), 1);
        assert!(o.lane_attached(1, Framing::ByteStream, t0));
        o.lanes_mut().unwrap().wrote_first(1, 23);
        // 50 kB on lane 0 that the carrier has taken none of yet.
        o.batch_sent(0, 50_000, 1, None);
        o.mp_batch_sent(0, false, MS * 25, t0);
        assert_eq!((o.queued(), o.reported_unsent()), (50_000, None));
        batch(&mut o, 1, 1000, t0);
        let b = o.oldest_eliciting_batch().expect("the batch on lane 1");
        assert_eq!(b.unsent_ahead, 50_000);
        // queue_p: 50 kB at 1 MB/s.
        assert_eq!(o.queue_term(), MS * 50);
        o.written(0, 20_000);
        assert_eq!(o.queued(), 31_000);
        o.set_lane_unsent(1, 400, t0);
        assert_eq!((o.queued(), o.reported_unsent()), (31_400, Some(400)));
        o.written(1, 1000);
        o.written(0, 30_000);
        assert_eq!(o.queued(), 400);
        // The snapshot does not grow or shrink afterwards, nor follow
        // R_p: a rate sample taken since leaves it as it was.
        assert_eq!(o.queue_term(), MS * 50);
        o.est.rate = 10_000_000;
        assert_eq!(o.queue_term(), MS * 50);
    }

    /// The cumulative acknowledgement point: a lane acknowledged ahead of another moves no
    /// whole-pipe state, neither the samples nor the last progress nor the ack stall, until
    /// the point moves; the first record of a lane is outside the send order.
    #[test]
    fn the_cumulative_point_moves_as_the_position_of_a_pipe_without_lanes() {
        let t0 = Instant::now();
        let mut o = pipe(t0);
        batch(&mut o, 0, 100, t0);
        assert_eq!(ack(&mut o, 0, 100, t0 + MS * 10), Some(100));
        assert_eq!(o.acked(), 100);
        // Lane 1 opens: its PIPE_LANE record is outside the send order, and
        // its confirmation moves nothing of the pipe.
        assert_eq!(o.request_lane(), 1);
        assert!(o.lane_attached(1, Framing::ByteStream, t0));
        o.lanes_mut().unwrap().wrote_first(1, 23);
        assert_eq!(o.sent(), 100);
        assert_eq!(ack(&mut o, 1, 23, t0 + MS * 20), None);
        assert!(o.lanes().unwrap().get(1).unwrap().confirmed());
        // Send order 100..200 on lane 1, then 200..300 on lane 0.
        let t1 = t0 + MS * 30;
        batch(&mut o, 1, 100, t1);
        batch(&mut o, 0, 100, t1);
        assert_eq!((o.sent_on(0), o.sent_on(1)), (200, 123));
        // Lane 0 acknowledged ahead: its frames are, the pipe is not.
        let advance = o.last_advance();
        assert_eq!(ack(&mut o, 0, 200, t1 + MS * 5), None);
        assert_eq!(o.acked(), 100);
        assert_eq!(o.last_advance(), advance);
        assert!(o.covered(0, 300) && !o.covered(1, 200));
        assert_eq!(o.oldest_unacked_eliciting(), Some(t1));
        // Lane 1 caught up: the point moves past both.
        assert_eq!(ack(&mut o, 1, 123, t1 + MS * 50), Some(300));
        assert_eq!(o.acked(), 300);
        assert_eq!(o.oldest_unacked_eliciting(), None);
        // A refused lane's acknowledgement is ignored.
        assert_eq!(o.request_lane(), 2);
        assert!(o.lane_attached(2, Framing::ByteStream, t1));
        o.lanes_mut().unwrap().wrote_first(2, 23);
        assert!(o.refuse_lane(2));
        assert_eq!(o.ack_lane(2, 23, t1), (false, None));
        assert!(
            !o.may_open_lane(16, Instant::now()),
            "no lane after a refusal"
        );
    }

    /// Held bytes: bytes acknowledged on lane 2 behind a hold on lane 1 are all
    /// left out of the limiter's bytes in flight in start-up; afterwards a
    /// hold shorter than RTT_base_p still counts, and one that lasts leaves
    /// out its smallest count of the last RTT_base_p, which keeps the
    /// in-flight cap open for bytes that have not arrived.
    #[test]
    fn held_bytes_leave_the_limiters_flight_as_the_phase_says() {
        let t0 = Instant::now();
        let base = MS * 100;
        let mut o = pipe(t0);
        batch(&mut o, 0, 100, t0);
        assert_eq!(ack(&mut o, 0, 100, t0), Some(100));
        for n in [1, 2] {
            assert_eq!(o.request_lane(), n);
            assert!(o.lane_attached(n, Framing::ByteStream, t0));
            o.lanes_mut().unwrap().wrote_first(n, 23);
            assert_eq!(ack(&mut o, n, 23, t0), None);
        }
        o.set_paced(true, t0);
        // Send order 100..10100 on lane 1, 10100..20100 on lane 2.
        batch(&mut o, 1, 10_000, t0);
        batch(&mut o, 2, 10_000, t0);
        assert_eq!(o.limiter_in_flight(t0), 20_000);
        // Start-up: lane 2 acknowledged behind lane 1's hole; every held
        // byte is left out at once.
        let t1 = t0 + MS * 10;
        assert_eq!(ack(&mut o, 2, 23 + 10_000, t1), None);
        assert_eq!(o.held_out(t1).now, 10_000);
        assert_eq!(o.limiter_in_flight(t1), 10_000);
        // Past start-up (RTT_base_p 100 ms), the hole repaired: nothing
        // held.
        o.limiter.as_deref_mut().unwrap().cruise(base, t1);
        let t2 = t1 + MS * 5;
        assert_eq!(ack(&mut o, 1, 23 + 10_000, t2), Some(20_100));
        assert_eq!(o.held_out(t2).now, 0);
        // Send order 20100..30100 on lane 1, 30100..40100 on lane 2; lane 2
        // acknowledged behind a new hole on lane 1.
        batch(&mut o, 1, 10_000, t2);
        batch(&mut o, 2, 10_000, t2);
        let t3 = t2 + MS * 10;
        assert_eq!(ack(&mut o, 2, 23 + 20_000, t3), None);
        assert_eq!(o.held_out(t3).now, 10_000);
        // The hold counts until it lasted RTT_base_p.
        assert_eq!(o.limiter_in_flight(t3 + MS * 50), 20_000);
        assert_eq!(o.limiter_in_flight(t3 + base), 10_000);
        // Lane 1 repaired in steps while still held: the count stays
        // (lane 2's bytes are still beyond the point).
        let t4 = t3 + MS * 200;
        assert_eq!(ack(&mut o, 1, 23 + 15_000, t4), Some(25_100));
        let t5 = t4 + MS * 20;
        assert_eq!(ack(&mut o, 1, 23 + 17_000, t5), Some(27_100));
        assert_eq!(o.held_out(t5).now, 10_000);
        // More data on lane 2, acknowledged at once: 13 000 held. The
        // smallest count of the last RTT_base_p is what is left out.
        batch(&mut o, 2, 3_000, t5);
        let t6 = t5 + MS * 30;
        assert_eq!(ack(&mut o, 2, 23 + 23_000, t6), None);
        assert_eq!(o.held_out(t6).now, 13_000);
        assert_eq!(o.held_out(t6 + MS * 50).min, 10_000);
        assert_eq!(o.held_out(t6 + base).min, 13_000);
        // Lane 1 repaired: nothing held, everything acknowledged.
        let t7 = t6 + base + MS;
        assert_eq!(ack(&mut o, 1, 23 + 20_000, t7), Some(43_100));
        assert_eq!(o.held_out(t7).now, 0);
        assert_eq!(o.held_out(t7).min, 0);
        assert_eq!(o.limiter_in_flight(t7), 0);
    }
}
