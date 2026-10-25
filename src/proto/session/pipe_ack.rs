//! Pipe acknowledgement without multipath (MULTIPATH.md Section 3.5): two
//! zmux endpoints acknowledge the single pipe pair of a session that does
//! not use multipath, for the sender's estimates
//! and its carrier queue limiter only. Nothing
//! is retained: the sender keeps the sample state of each write batch in
//! flight, which the next PIPE_ACK releases, and the receiver a few
//! counters of pipe 0. Every path here is O(1) per record, batch or
//! acknowledgement and allocates nothing beyond the reused batch queue.

use std::time::{Duration, Instant};

use super::SessionCore;
use super::filter::LOOP_SPAN;
use super::output::Records;
use super::pipes::{AckSample, Attachment};
use crate::proto::frame::{Frame, FrameType, PipeAck};
use crate::proto::{DetailKey, Error};

/// The pipe pair of a session without multipath (MULTIPATH.md Section 4.2).
const PIPE: u64 = 0;

/// The most sample entries kept for batches in flight: at 10 Gbit/s and
/// 100 ms, 256 KiB batches fill about 480, so an entry spans two at most.
const SAMPLE_ENTRIES: usize = 256;

/// The fixed record of pipe acknowledgement.
#[derive(Debug, Clone)]
pub(crate) struct PipeAckState {
    /// Our own `zmux_ack_threshold`: ack-eliciting bytes that make a
    /// PIPE_ACK due at once.
    pub(crate) threshold: u64,
    /// Our own `zmux_max_ack_delay`.
    pub(crate) local_mad: Duration,
    /// The peer's `zmux_ack_threshold`: what it may leave unacknowledged
    /// (the A term of the limiter's in-flight cap).
    pub(crate) peer_threshold: u64,
    /// The peer's `zmux_max_ack_delay`, the cap of the ACK Delay that RTT
    /// samples subtract.
    pub(crate) peer_mad: Duration,
    /// The threshold was reached: a PIPE_ACK goes with the next records.
    due: bool,
    /// The send-order ends of batches that carried an activity frame and
    /// wait for the PIPE_ACK that restarts the idle timer (SPEC.md Section
    /// 6.4): the oldest and the newest (0: none). The ones between count
    /// as the newest, which can only make the timer restart later, never
    /// keep a session alive longer.
    activity_first: u64,
    activity_last: u64,
}

impl SessionCore {
    /// Starts pipe acknowledgement once the parameters put it in use;
    /// otherwise drops the sample state of what was sent before them.
    pub(super) fn pipe_ack_setup(&mut self) {
        let Some(peer) = self.peer_tp.as_ref() else {
            return;
        };
        if self.features.pipe_ack {
            self.pipe_ack = Some(PipeAckState {
                threshold: self.local_tp().ack_threshold(),
                local_mad: Duration::from_millis(self.local_tp().max_ack_delay()),
                peer_threshold: peer.ack_threshold(),
                peer_mad: Duration::from_millis(peer.max_ack_delay()),
                due: false,
                activity_first: 0,
                activity_last: 0,
            });
        } else if self.features.multipath {
            // The batches before multipath was in use stay for the
            // positions their PIPE_ACK counts (MULTIPATH.md Section 6),
            // without starting the acknowledgement-stall clock: failure
            // detection starts with the session's first data.
            if let Some(o) = self.out_mut(PIPE) {
                o.unwatch_batches();
            }
        } else if let Some(o) = self.out_mut(PIPE) {
            // A multipath session keeps it: PIPE_ACK acknowledges the
            // pipe's positions from its first byte (MULTIPATH.md Section 6).
            o.forget_batches();
        }
    }

    /// A batch was handed to the single pipe's carrier: its sample state is
    /// kept while pipe acknowledgement is in use, and for the first batch,
    /// which goes out before the peer's parameters say whether it will be
    /// (positions count from the pipe's first byte, MULTIPATH.md Section
    /// 3.5). At most [`SAMPLE_ENTRIES`] are kept: beyond them a batch joins
    /// the latest entry (an ack-eliciting one replaces a non-eliciting
    /// entry with its own send time), so that a peer that
    /// acknowledges late (a large `zmux_max_ack_delay`) cannot make the
    /// state grow with the batches sent meanwhile.
    pub(super) fn single_batch_sent(&mut self, eliciting: bool, now: Instant) {
        let peer_mad = match &self.pipe_ack {
            Some(pa) => pa.peer_mad,
            None if self.peer_tp.is_none()
                && (self.local_tp().pipe_ack || self.local_tp().multipath.is_some()) =>
            {
                Duration::from_millis(crate::proto::params::DEFAULT_MAX_ACK_DELAY_MS)
            }
            None => return,
        };
        let lane = self.tx_lane;
        if let Some(o) = self.out_mut(PIPE) {
            o.record_single_batch(lane, eliciting, SAMPLE_ENTRIES, peer_mad, now);
        }
    }

    // ---- receiving -------------------------------------------------------------

    /// A complete record of `len` bytes was processed on pipe 0, whose
    /// position already counts it.
    pub(super) fn single_record_end(&mut self, len: u64, eliciting: bool, now: Instant) {
        let Some(pa) = self.pipe_ack.as_mut() else {
            return;
        };
        let Some(p) = self.atts.first_mut().and_then(Attachment::inp_mut) else {
            return;
        };
        pa.due |= p.await_ack(self.rx_lane, len, eliciting, pa.threshold, now);
    }

    /// When the received ack-eliciting bytes must be acknowledged at the
    /// latest: our `zmux_max_ack_delay` after the first of them
    /// (MULTIPATH.md Section 6.3 rule 2).
    fn single_ack_deadline(&self, pa: &PipeAckState) -> Option<Instant> {
        let p = self.atts.first()?.inp()?;
        Some(p.unacked_since()? + pa.local_mad)
    }

    /// Whether a PIPE_ACK is due on pipe 0 (MULTIPATH.md Section 6.3 rules
    /// 1 and 2).
    pub(super) fn single_pipe_ack_due(&self, now: Instant) -> bool {
        self.pipe_ack
            .as_ref()
            .is_some_and(|pa| pa.due || self.single_ack_deadline(pa).is_some_and(|t| now >= t))
    }

    /// The acknowledgement timer, while a PIPE_ACK is not due yet.
    pub(super) fn single_pipe_ack_timer(&self) -> Option<Instant> {
        let pa = self.pipe_ack.as_ref()?;
        if pa.due || self.state >= super::State::Closing {
            return None;
        }
        self.single_ack_deadline(pa).filter(|&t| t > self.now)
    }

    /// Writes the PIPE_ACK of pipe 0 when it is due, or when the batch
    /// carries a credit update anyway while received bytes wait for it
    /// (MULTIPATH.md Sections 3.5 and 6.3): a record of its own only when
    /// the deadline passed with nothing else to send.
    pub(super) fn write_single_pipe_ack(&mut self, w: &mut Records<'_>, now: Instant) {
        if self.pipe_ack.is_none() {
            return;
        }
        let Some(p) = self.atts.first().and_then(Attachment::inp) else {
            return;
        };
        if p.unacked() == 0 {
            return;
        }
        if !self.single_pipe_ack_due(now) && !self.credit_update_pending() {
            return;
        }
        if p.lane_count() > 1 {
            // Every lane in an entry of its own; unchanged ones may be
            // omitted, with a complete snapshot at least once per second
            // (MULTIPATH.md Sections 3.5 and 6.2).
            let mut entries = Vec::new();
            let complete =
                super::ack::snapshot_of(&self.atts, &mut entries, p.complete_due(now), now);
            if !Self::write_snapshot(&entries, w) {
                return;
            }
            if let Some(p) = self.atts.first_mut().and_then(Attachment::inp_mut) {
                p.ack_sent();
                if complete {
                    p.complete_sent_at(now);
                }
            }
            if let Some(pa) = &mut self.pipe_ack {
                pa.due = false;
            }
            return;
        }
        let entry = p.ack_entry(PIPE, now);
        if !w.try_frame(&Frame::PipeAck(PipeAck::new(std::slice::from_ref(&entry)))) {
            return;
        }
        if let Some(p) = self.atts.first_mut().and_then(Attachment::inp_mut) {
            p.ack_sent();
        }
        if let Some(pa) = &mut self.pipe_ack {
            pa.due = false;
        }
    }

    /// PIPE_ACK while pipe acknowledgement is in use: one entry, for pipe
    /// 0, at most the bytes sent on it (MULTIPATH.md Section 3.5).
    pub(super) fn on_single_pipe_ack(
        &mut self,
        f: &PipeAck<'_>,
        now: Instant,
    ) -> Result<(), Error> {
        let ty = FrameType::PIPE_ACK.0;
        let Some(peer_mad) = self.pipe_ack.as_ref().map(|pa| pa.peer_mad) else {
            return Ok(());
        };
        for e in f.entries() {
            if e.pipe_id != PIPE {
                return Err(
                    Error::protocol_violation(ty, "PIPE_ACK for a pipe other than 0")
                        .detail(DetailKey::Pipe, e.pipe_id),
                );
            }
            if e.position == 0 {
                // Ignored, never charged.
                continue;
            }
            let sent = self.sent_on(PIPE, e.lane);
            if e.position > sent {
                return Err(Error::protocol_violation(
                    ty,
                    "PIPE_ACK acknowledges bytes never sent",
                )
                .detail(DetailKey::Pipe, PIPE)
                .detail(DetailKey::Pos, e.position)
                .detail(DetailKey::Limit, sent));
            }
            let Some(o) = self.out_mut(PIPE) else {
                continue;
            };
            // Outdated entries are ignored, never charged. The samples come
            // from the cumulative acknowledgement point (MULTIPATH.md
            // Section 2.5).
            let lanes = o.lanes().is_some();
            let (moved, cum) = o.ack_lane(e.lane, e.position, now);
            if let Some(cum) = cum {
                let delay = Duration::from_micros(e.ack_delay.min(u64::MAX >> 2));
                let sample = o.sample_ack(cum, delay, peer_mad, true, |_| true, now);
                self.single_pipe_acked(sample, now);
                self.activity_acked(cum, now);
            }
            if lanes && moved {
                self.single_lane_acked(now);
            }
        }
        Ok(())
    }

    /// The response to a QX_PING request came back after `rtt`: on the
    /// single pipe with pipe acknowledgement whose carrier the limiter
    /// paces, the pipe's first RTT sample, for its estimators and the
    /// limiter's base, while no PIPE_ACK gave one. That is the request of
    /// the first record, which waited behind nothing and was answered at
    /// once (the scheduler takes a new pipe's first sample from
    /// its first record), whereas the first PIPE_ACK may come a whole
    /// `zmux_max_ack_delay` late with nothing to subtract it from, a delay
    /// that would stay in min_rtt and the base. Later responses feed
    /// neither: the limiter's inputs come from PIPE_ACK.
    pub(super) fn single_ping_sample(&mut self, rtt: Duration, now: Instant) {
        if self.pipe_ack.is_none()
            || !self
                .out_ref(PIPE)
                .is_some_and(|o| !o.est().sampled && self.paced(o))
        {
            return;
        }
        let p = self.pacing_params();
        if let Some(o) = self.out_mut(PIPE) {
            o.ping_rtt_sample(rtt, now);
            o.set_paced(true, now);
            if let Some((limiter, est)) = o.limiter_parts() {
                limiter.ping_sample(now, rtt, est, &p);
            }
        }
    }

    /// What an acknowledgement of the single pipe measured: the estimators
    /// of pipe 0 have taken it, and its RTT sample enters the credit-loop
    /// minimum of auto-tuning (SPEC.md Section 8.3 rule 6). This is where
    /// per-acknowledgement consumers of the samples, such as the carrier
    /// queue limiter, take them.
    /// A batch that carried activity ended at send-order position `end`.
    pub(super) fn note_acked_activity(&mut self, end: u64) {
        if let Some(pa) = self.pipe_ack.as_mut() {
            if pa.activity_first == 0 {
                pa.activity_first = end;
            }
            pa.activity_last = end;
        }
    }

    /// The cumulative point reached `cum`: acknowledged activity restarts
    /// the idle timer (SPEC.md Section 6.4).
    fn activity_acked(&mut self, cum: u64, now: Instant) {
        let Some(pa) = self.pipe_ack.as_mut() else {
            return;
        };
        if pa.activity_first == 0 || pa.activity_first > cum {
            return;
        }
        if pa.activity_last <= cum {
            pa.activity_first = 0;
            pa.activity_last = 0;
        } else {
            pa.activity_first = pa.activity_last;
        }
        self.restart_idle(now);
    }

    fn single_pipe_acked(&mut self, sample: AckSample, now: Instant) {
        if let Some(rtt) = sample.rtt {
            self.loop_min.sample(now, rtt.latest, LOOP_SPAN);
        }
        self.pace_ack(PIPE, &sample, now);
    }

    // ---- sending: application-limited samples --------

    /// After a write opportunity: the pipe still writable with nothing more
    /// to send is an application-limited moment.
    pub(super) fn single_pipe_bubble(&mut self) {
        let waiting = self.data_waiting();
        if let Some(o) = self.out_mut(PIPE).filter(|o| o.writable()) {
            // The carrier queue limiter ending the opportunity while data
            // waits makes the pipe the bottleneck.
            o.opportunity_ended(waiting);
        }
    }

    // ---- accessors for the sender's consumers ----------------------------------

    /// The state of pipe acknowledgement, while it is in use.
    pub(crate) fn pipe_ack_state(&self) -> Option<&PipeAckState> {
        self.pipe_ack.as_ref()
    }
}
