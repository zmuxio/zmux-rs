//! The transmit path: control state and stream data become records when a
//! pipe can take bytes (late binding).

use std::time::{Duration, Instant};

use bytes::Bytes;

use super::ledger::Tag;
use super::pipes::{Attachment, BatchStart, OutPipe};
use super::sched::Decision;
use super::stream::{self, Offer, RecvState, SendPart, SendState, StreamKey};
use super::tier::GateInputs;
use super::transmit::{COPY_THRESHOLD, TransmitBuf};
use super::{
    BIDI, CloseFrame, LaneId, SEND_DATAGRAM_QUEUE, SessionCore, State, Transmit, UNI, config, di,
    dir_of_index, mpath, pipes,
};
use crate::proto::frame::{
    ConnectionClose, DataBlocked, Frame, GoAwayFrame, MAX_COUNT, MaxData, MaxStreamData,
    MaxStreams, PipeAbandon, PipeLane, PriorityUpdate, QxPing, ResetStream, ResetStreamAt,
    StopSending, StreamDataBlocked, StreamHeader, StreamsBlocked,
};
use crate::proto::meter::Count;
use crate::proto::params::{DEFAULT_MAX_RECORD_SIZE, Role};
use crate::proto::payload::{AppTlvs, Flow, GreaseTlv, WirePreamble};
use crate::proto::record::Framing;
use crate::proto::varint;

/// The deficit round robin quantum.
const QUANTUM: i64 = 16 * 1024;

/// The largest STREAM frame header: type, stream ID, offset and length.
const MAX_STREAM_HEADER: usize = 1 + 8 + 8 + 8;

/// Data smaller than this does not start a STREAM frame at the end of a
/// nearly full record when it could go whole into the next one.
const MIN_FRAGMENT: usize = 1024;

/// The smallest message of a message-framed pipe the write-call bound
/// leaves (the smallest `max_send_record`).
const MIN_MESSAGE: usize = 1024;

/// The result of writing one STREAM frame.
enum Step {
    /// The stream has nothing more to send now.
    Done,
    /// More to send; `rotate` when its quantum is used up.
    More { rotate: bool },
    /// Stream credit, or a pinned stream's opening frame, holds it back.
    Blocked,
    /// Session credit holds it back.
    SessionBlocked,
    /// The batch is full.
    Full,
    /// Nothing more from this stream on this pipe now: the retransmit
    /// budget is spent, the pipe is JOINING while new data has another
    /// (rule S1), the reinjection hold is used up, or only reinjected
    /// information is owed, which goes elsewhere.
    Budget,
}

/// The batch is full.
pub(super) struct Full;

/// What the batch being written logs in a multipath session: the retained
/// frames with the index of their record in the batch, the records that
/// carry an activity frame, the PIPE_ABANDON frames it carries; and the
/// credit copies owed and the tier loads of its gates.
#[derive(Debug, Default)]
pub(crate) struct BatchLog {
    /// Frames written in the current batch that are retained, with the
    /// index of their record in the batch.
    txlog: Vec<(u32, pipes::SentFrame)>,
    /// The last entry of `txlog` is new stream data, which a frame that
    /// continues it may extend.
    txlog_new: bool,
    /// The records of the batch that carry an activity frame.
    txactivity: Vec<u32>,
    /// The current batch holds new stream data: later new data in it is
    /// not the first after an idle period.
    new_data: bool,
    /// Pipes whose PIPE_ABANDON the current batch carries.
    abandons_sent: Vec<u64>,
    /// Credit frames sent while the window was the bottleneck, with the
    /// pipe that carried them: a copy goes on a second pipe (MULTIPATH.md
    /// Section 6.5).
    credit_copies: Vec<(mpath::CreditCopy, u64)>,
    /// The tier loads of the gates of the batch being written.
    gate_inputs: GateInputs,
}

impl BatchLog {
    /// Heap bytes held.
    pub(super) fn heap_bytes(&self) -> usize {
        use std::mem::size_of;
        self.txlog.capacity() * size_of::<(u32, pipes::SentFrame)>()
            + self.txactivity.capacity() * size_of::<u32>()
            + self.abandons_sent.capacity() * size_of::<u64>()
    }

    /// The batch holds new stream data already.
    pub(super) fn new_data(&self) -> bool {
        self.new_data
    }
}

impl SessionCore {
    /// Whether the driver should write to the pipe (the lane of it) when
    /// it can.
    pub fn wants_write(&self, at: impl Into<LaneId>) -> bool {
        let at = at.into();
        if at.lane.0 != 0 {
            return self.lane_wants_write(at.pipe.0, at.lane.0);
        }
        let id = at.pipe.0;
        let Some(a) = self.att(id) else {
            return false;
        };
        let Some(o) = a.out() else {
            return false;
        };
        if o.writes_ended() || self.state == State::Closed {
            return false;
        }
        if o.leading_frames_owed() {
            return true;
        }
        if self.state == State::Closing {
            // An orderly close that waits for the other lanes writes only
            // the PIPE_ACK due meanwhile.
            return !self.close_waiting() || self.single_pipe_ack_due(self.now);
        }
        if o.shutdown_pending() {
            // Drained, or failed: the write side is to be closed.
            return true;
        }
        if self.state == State::Establishing {
            // Early data under the floor (SPEC.md Section 6.1.2).
            return self.early_open() && id == 0 && (self.opening_ready() || self.data_pending());
        }
        if self.mp.is_none() {
            return self.control_pending()
                || self.opening_ready()
                || self.data_pending()
                || self.single_pipe_ack_due(self.now);
        }
        if !o.is_live() {
            return false;
        }
        let now = self.now;
        if a.abandon_owed(true) || self.wants_pipe_ack(id, now) || self.ping_due(id, now) {
            return true;
        }
        let control = self.control_pipe(None) == Some(id);
        if control && (self.control_pending() || self.mp_control_pending()) {
            return true;
        }
        if control && o.takes_new_data() && self.opening_ready() {
            return true;
        }
        if o.state() == pipes::OutState::Active
            && self
                .dgram()
                .send
                .iter()
                .any(|(f, _)| self.datagram_pipe(*f) == Some(id))
        {
            return true;
        }
        // Stream data before the opportunistic copies, which cost more to
        // look for and matter only while flow control holds data back.
        // Both are paced: a held pipe waits for
        // its release.
        self.data_for_pipe(id)
            || (!o.limiter_held()
                && (self.copies_queued(id, 0) || self.opp_due(id, now, None).is_some()))
    }

    /// Whether any pipe has something to write (drivers wake their writers
    /// on it).
    pub fn wants_write_any(&self) -> bool {
        self.atts.iter().any(|a| {
            a.out().is_some_and(|o| {
                let id = super::PipeId(a.id());
                self.wants_write(id)
                    || o.lanes()
                        .is_some_and(|l| l.iter().any(|(n, _)| self.wants_write(id.lane(n))))
            })
        })
    }

    /// Control frames of the session or its streams are pending.
    fn control_pending(&self) -> bool {
        self.ping.response_pending.is_some()
            || (self.ping.request_pending && self.ping.outstanding.is_none())
            || self.streams.control_pending()
            || self.goaway().pending.is_some()
            || self.goaway().resend.is_some()
            || self
                .dgram()
                .send
                .iter()
                .any(|(f, _)| self.datagram_pipe(*f).is_none())
    }

    /// A credit update (MAX_DATA, MAX_STREAMS, MAX_STREAM_DATA) waits:
    /// a PIPE_ACK goes in the same batch (MULTIPATH.md Section 6.3).
    pub(super) fn credit_update_pending(&self) -> bool {
        self.streams.credit_update_pending()
    }

    /// Pipe-layer control frames are pending (PIPE_ABANDON, PIPE_STATUS).
    fn mp_control_pending(&self) -> bool {
        self.mp.is_some()
            && self
                .atts
                .iter()
                .any(|a| a.abandon_owed(false) || (a.tier().status_owed() && !a.joining_local()))
    }

    /// Whether latency-sensitive work waits for pipe `id`'s next write
    /// call: input not yet processed
    /// (`input_pending`, which the driver knows); frames queued that go
    /// ahead of bulk data, control frames or stream data of urgency 0 to 2
    /// or of a small direction; or within the last max(10 x B, RTT_min) an
    /// exchange of anything but acknowledgements and credit. All of it is
    /// local state that exists on every carrier.
    pub(super) fn latency_work(&self, id: u64, input_pending: bool, now: Instant) -> bool {
        if input_pending
            || self.control_pending()
            || self.mp_control_pending()
            || self.ack_due(now)
            || self.streams.queue().levels()[..3]
                .iter()
                .any(|q| !q.is_empty())
            || self.small_ready()
        {
            return true;
        }
        let Some(at) = self.exchange_at else {
            return false;
        };
        let rtt_min = if self.mp.is_some() {
            self.pipe_min_rtt(id)
        } else {
            self.carrier_rtt.or(self.loop_min.get())
        };
        let window = self
            .config
            .latency_budget
            .saturating_mul(10)
            .max(rtt_min.unwrap_or_default());
        now.saturating_duration_since(at) < window
    }

    /// A small direction (at most 64 KiB held)
    /// has new data queued: on a single pipe every byte held is unsent, in
    /// a multipath session the ledger counts the unsent ones (retained
    /// bytes wait only for their acknowledgement).
    fn small_ready(&self) -> bool {
        match self.ledger() {
            Some(l) => l.any_small(),
            None => self.streams.small_held() && !self.streams.queue().is_empty(),
        }
    }

    /// Whether stream `key` owes only a FIN that neither stream nor session
    /// credit nor the retransmit budget holds back (SPEC.md Section 8.2):
    /// a FIN-only frame of an opened stream, or one that opens a stream
    /// without a preamble while the peer's stream limit lets it.
    pub(super) fn fin_only(&self, key: StreamKey) -> bool {
        self.streams.get(key).is_some_and(|s| {
            s.send.as_ref().is_some_and(SendPart::fin_only)
                && (s.id.is_some()
                    || (!self.features.preamble && {
                        let ld = self.streams.local_dir(di(s.dir));
                        ld.next_index < ld.peer_max
                    }))
        })
    }

    /// Stream data is ready for lane 0 of the single pipe, and the limiter
    /// lets it go.
    fn data_pending(&self) -> bool {
        self.data_waiting()
            && self.out_ref(0).is_none_or(|o| {
                !o.limiter_held() && (o.lanes().is_none() || self.data_for_lane(o, 0, 0))
            })
    }

    /// Stream data is ready (single pipe), whatever the limiter holds back.
    pub(super) fn data_waiting(&self) -> bool {
        self.streams.data_waiting()
    }

    /// Whether a scheduled stream has data for pipe `id` (its lane 0) that
    /// the pipe may take now (multipath).
    fn data_for_pipe(&self, id: u64) -> bool {
        let Some(o) = self.out_ref(id) else {
            return false;
        };
        if o.limiter_held() {
            return false;
        }
        if o.lanes().is_some() {
            return self.data_for_lane(o, id, 0);
        }
        self.data_for_pipe_unpaced(id)
    }

    /// Whether a scheduled stream has data for lane `lane` of pipe `id`,
    /// whatever the limiter holds back: one that goes on the pipe (in a
    /// multipath session) and on that lane.
    pub(super) fn data_for_lane(&self, o: &OutPipe, id: u64, lane: u64) -> bool {
        if self.streams.queue().is_empty() {
            return false;
        }
        if self.mp.is_none() {
            let stalled = self.streams.session_stalled();
            return self
                .streams
                .queue()
                .keys()
                .any(|key| (!stalled || self.fin_only(key)) && self.lane_for(o, key) == lane);
        }
        if !o.takes_new_data() || !o.writable() {
            return false;
        }
        let budget_left = self.mp().retained() < self.retransmit_budget();
        let d = self.decision(id, self.gate());
        let fresh = !self.streams.session_stalled() && budget_left;
        self.streams.queue().keys().any(|key| {
            (self
                .streams
                .send(key)
                .is_some_and(|send| send.has_lost() || fresh)
                || self.fin_only(key))
                && self.stream_on_pipe(&d, key)
                && self.lane_for(o, key) == lane
        })
    }

    /// Whether the driver should write to lane `n` (not 0) of pipe `id`:
    /// its first record, its shutdown, or the stream data placed on it.
    fn lane_wants_write(&self, id: u64, n: u64) -> bool {
        let Some(o) = self.out_ref(id) else {
            return false;
        };
        let Some(l) = o.lanes().and_then(|l| l.get(n)) else {
            return false;
        };
        if !l.attached() || l.writes_ended() || self.state == State::Closed {
            return false;
        }
        if l.first_owed() || self.lane_shutdown(o) {
            return true;
        }
        if self.state == State::Establishing || !Self::lane_open(o, n) || !l.writable() {
            return false;
        }
        !o.limiter_held() && (self.copies_queued(id, n) || self.data_for_lane(o, id, n))
    }

    /// Whether the lanes of `o` are to be shut down: the session closes,
    /// or the pipe drained or failed.
    fn lane_shutdown(&self, o: &OutPipe) -> bool {
        self.state >= State::Closing || o.shutdown_pending() || o.writes_ended()
    }

    /// Whether a scheduled stream has data for pipe `id`, whatever the
    /// limiter holds back (multipath).
    fn data_for_pipe_unpaced(&self, id: u64) -> bool {
        if self.streams.queue().is_empty() {
            return false;
        }
        let Some(o) = self.out_ref(id) else {
            return false;
        };
        if !o.takes_new_data() || !o.writable() {
            return false;
        }
        let budget_left = self.mp().retained() < self.retransmit_budget();
        let d = self.decision(id, self.gate());
        // New data waits for session credit or the retransmit budget;
        // reinjected information does not.
        let fresh = !self.streams.session_stalled() && budget_left;
        // A FIN-only frame waits for neither (SPEC.md Section 8.2): looked
        // for only while they hold new data back.
        let found = self.any_stream_on(&d, fresh)
            || (!fresh
                && self
                    .streams
                    .queue()
                    .keys()
                    .any(|key| self.fin_only(key) && self.stream_on_pipe(&d, key)));
        #[cfg(debug_assertions)]
        if self.streams.len() <= 64 {
            let scan = self.streams.queue().keys().any(|key| {
                (self
                    .streams
                    .send(key)
                    .is_some_and(|send| send.has_lost() || fresh)
                    || self.fin_only(key))
                    && self.stream_on_pipe(&d, key)
            });
            debug_assert_eq!(found, scan, "data for pipe {id}");
        }
        found
    }

    /// A PIPE_PING is owed on `id` and the limit of 8 per second lets it go
    /// now: pipes that have waited longest first (MULTIPATH.md 6.4).
    pub(super) fn ping_due(&self, id: u64, now: Instant) -> bool {
        let Some(mp) = self.mp.as_deref() else {
            return false;
        };
        let Some(o) = self.out_ref(id) else {
            return false;
        };
        let Some(since) = o.ping_wanted() else {
            return false;
        };
        if !o.is_live() || o.shutdown_pending() {
            return false;
        }
        let slots = mp.ping_slots(now).min(self.requests.available(now));
        if slots == 0 {
            return false;
        }
        let ahead = self
            .atts
            .iter()
            .filter(|a| a.id() != id)
            .filter_map(|a| {
                let x = a.out()?;
                let t = x.ping_wanted()?;
                (x.is_live() && x.writable() && !x.shutdown_pending() && (t, a.id()) < (since, id))
                    .then_some(())
            })
            .count();
        ahead < slots
    }

    /// Whether the first pinned stream of a type can write its opening
    /// frame (or must leave the queue).
    fn opening_ready(&self) -> bool {
        let session_room = self.streams.send_flow().room();
        self.streams.pinned_fronts().any(|key| {
            let Some(s) = self.streams.get(key) else {
                return true;
            };
            match s.send.as_ref() {
                Some(send) if s.open_pending && s.goaway.is_none() => {
                    let len = send.preamble_left as u64;
                    len <= send.max_data.saturating_sub(send.offset) && len <= session_room
                }
                _ => true,
            }
        })
    }

    /// The largest Frames field of a record this endpoint sends.
    pub(super) fn max_record(&self) -> usize {
        let peer = self
            .send_tp()
            .map_or(DEFAULT_MAX_RECORD_SIZE, |t| t.max_record_size());
        (self.config.max_send_record as u64).min(peer) as usize
    }

    /// Fills `out` with the next batch for a pipe (a lane of it) that can
    /// take bytes. The driver writes the whole batch before calling this
    /// again for the lane; on [`Transmit::Shutdown`] it then shuts the
    /// lane's write side down.
    pub fn poll_transmit(
        &mut self,
        at: impl Into<LaneId>,
        now: Instant,
        out: &mut TransmitBuf,
    ) -> Transmit {
        let at = at.into();
        if at.lane.0 != 0 {
            return self.poll_lane(at.pipe.0, at.lane.0, now, out);
        }
        self.tick(now);
        out.clear();
        let id = at.pipe.0;
        self.tx = id;
        self.tx_lane = 0;
        self.tx_lanes = self.out_ref(id).is_some_and(|o| o.lanes().is_some());
        let closed = self.state == State::Closed;
        let Some(BatchStart {
            framing,
            parameters,
            join,
            live,
            close_sent,
            shutdown,
        }) = self.out_mut(id).and_then(|p| p.begin_batch(closed))
        else {
            return Transmit::Idle;
        };
        out.set_framing(framing);
        // A message is one write call: within the write-call bound the
        // driver gives.
        let max_record = match framing {
            Framing::ByteStream => self.max_record(),
            Framing::Records => self.max_record().min(out.max_message().max(MIN_MESSAGE)),
        };
        let mut w = Records::new(out, max_record);
        if parameters {
            self.offer_exporter_only_with_one();
            // QX_TRANSPORT_PARAMETERS opens the first record (SPEC.md 5.1).
            let grease = Some(config::grease_ref(&self.grease));
            let tp = self.local_parameters();
            let n = tp.frame_len(grease);
            w.force(n);
            w.out
                .push_with(n, |dst| tp.encode_frame(grease, dst).unwrap_or(0));
            // Without a carrier RTT, a QX_PING request in the first record
            // gives auto-tuning an early sample (SPEC.md Section 5.1 rule 3).
            if id == 0
                && self.carrier_rtt.is_none()
                && self.config.hooks.rtt.is_none()
                && !self.config.hooks.no_first_ping
                && self.ping.outstanding.is_none()
            {
                self.write_ping_request(&mut w, now);
            }
        }
        if let Some((buf, len)) = join {
            // An in-band PIPE_JOIN is the first frame of the pipe; then a
            // complete PIPE_ACK snapshot and a PIPE_PING, in that order,
            // continuing in the next record when they do not fit
            // (MULTIPATH.md Section 5.2).
            let len = usize::from(len);
            w.force(len);
            w.out.push_bytes(&buf[..len]);
            w.elicit();
            self.write_pipe_ack(id, &mut w, now);
            if let Some(o) = self.out_mut(id) {
                o.want_ping(now);
            }
            self.write_pipe_ping(id, &mut w, now);
        }
        if self.state == State::Closing && self.close_waiting() {
            // The close waits for the other lanes (SPEC.md Section 6.5 step
            // 1); the acknowledgements the peer waits for meanwhile go.
            self.write_single_pipe_ack(&mut w, now);
            w.end_record();
            let records = w.finish();
            self.count_sent(out.len(), records);
            self.after_batch(id, out, None, now);
            return if out.is_empty() {
                Transmit::Idle
            } else {
                Transmit::Data
            };
        }
        if self.state == State::Closing {
            if live
                && !close_sent
                && let Some(cf) = self.close.as_deref().cloned()
            {
                let frame = match &cf {
                    CloseFrame::Transport {
                        code,
                        frame_type,
                        reason,
                    } => ConnectionClose {
                        application: false,
                        error_code: *code,
                        frame_type: *frame_type,
                        reason,
                    },
                    CloseFrame::Application { code, reason } => ConnectionClose {
                        application: true,
                        error_code: *code,
                        frame_type: 0,
                        reason,
                    },
                };
                let frame = Frame::ConnectionClose(frame);
                w.force(frame.encoded_len());
                let _ = w.out.push_frame(&frame);
            }
            let records = w.finish();
            self.count_sent(out.len(), records);
            self.after_batch(id, out, None, now);
            if let Some(p) = self.out_mut(id) {
                p.close_written();
            }
            // Linger from the time the close is written (SPEC.md 6.5).
            self.linger_deadline = Some(now + self.linger_timeout());
            self.maybe_closed(now);
            return Transmit::Shutdown;
        }
        if shutdown {
            // A drained pipe (MULTIPATH.md Section 8.2) or a failed one.
            let records = w.finish();
            self.count_sent(out.len(), records);
            self.after_batch(id, out, None, now);
            if let Some(p) = self.out_mut(id) {
                p.shutdown_written();
            }
            return Transmit::Shutdown;
        }
        if self.early_open() && id == 0 {
            // Early data: the fence, then openings and stream data within
            // the floor (SPEC.md Section 6.1.2).
            if (self.opening_ready() || self.data_pending()) && self.write_fence(&mut w) {
                self.write_openings(&mut w);
                self.write_stream_data(id, &mut w);
            }
        } else if self.state != State::Establishing {
            let mp = self.mp.is_some();
            if mp {
                self.write_pipe_frames(id, &mut w, now);
            } else if self.pipe_ack.is_some() {
                self.write_single_pipe_ack(&mut w, now);
            }
            let control = self.is_control_pipe(id);
            let data = self.out_ref(id).is_some_and(|o| o.takes_new_data() || !mp);
            if control {
                self.write_control(&mut w, now);
                if data {
                    self.write_openings(&mut w);
                }
                self.write_stream_controls(&mut w, now);
            }
            if data && !self.dgram().send.is_empty() {
                self.write_datagrams(id, control, &mut w);
            }
            if data {
                // The carrier queue limiter paces stream data, reinjection
                // and copies, never control frames.
                self.pace_left = self.pacing_room(id, now);
                self.write_stream_data(id, &mut w);
                self.pace_left = None;
            }
            if control && self.control_pending() {
                // Resets whose reliable data just went out, and credit
                // that writing stream data released (a stream it
                // completed).
                self.write_control(&mut w, now);
                self.write_stream_controls(&mut w, now);
            }
        }
        let activity = w.activity;
        let traffic = w.traffic;
        let acked_activity = w.traffic || w.ping;
        if w.exchange {
            self.exchange_at = Some(now);
        }
        w.end_record();
        let eliciting = w.eliciting_end();
        let records = w.finish();
        self.count_sent(out.len(), records);
        self.after_batch(id, out, eliciting, now);
        if traffic {
            self.note_traffic(now);
        }
        // The bucket pays for the whole batch as the carrier takes it,
        // framing and control frames included: R_p measures those bytes,
        // and paying for the stream data alone would overrun the path by
        // the rest and build a queue round by round. Control frames are
        // never held back for it.
        self.pace_sent(id, out.len() as u64, now);
        if self
            .mp
            .as_deref()
            .is_some_and(|m| !m.batch().abandons_sent.is_empty())
        {
            // Handing our PIPE_ABANDON to a carrier may complete an
            // exchange, and with it a drain (MULTIPATH.md Section 8.2).
            let mut sent = std::mem::take(&mut self.mp_mut().batch_mut().abandons_sent);
            for &pipe in &sent {
                self.exchange_progress(pipe, now);
            }
            sent.clear();
            self.mp_mut().batch_mut().abandons_sent = sent;
        }
        // After the scheduling decisions: data still waiting for a tier
        // has waited since before this batch.
        self.refresh_tiers();
        // A write opportunity that leaves the pipe writable with nothing
        // for it is an application-limited moment; one that the limiter
        // ends while data waits makes the pipe the bottleneck.
        if self.mp.is_some()
            && self
                .out_ref(id)
                .is_some_and(|o| o.writable() && o.is_live())
        {
            let waiting = self.data_for_pipe_unpaced(id);
            if let Some(o) = self.out_mut(id) {
                o.opportunity_ended(waiting);
            }
        }
        if self.pipe_ack.is_some() {
            self.single_pipe_bubble();
        }
        if out.is_empty() {
            return Transmit::Idle;
        }
        // A record passed to the carrier restarts the idle timer outside
        // multipath, unless it carries only a QX_PING request (SPEC.md
        // Section 6.4): an unanswered keep-alive must not keep a dead
        // session open. In a multipath session only acknowledged activity
        // counts.
        if self.mp.is_none() {
            if self.pipe_ack.is_some() {
                // With acknowledgement only acknowledged activity counts:
                // the batch's end waits for the PIPE_ACK that covers it.
                if acked_activity && let Some(end) = self.out_ref(id).map(OutPipe::sent) {
                    self.note_acked_activity(end);
                }
            } else if activity {
                self.restart_idle(now);
            }
        }
        Transmit::Data
    }

    /// The next batch of lane `n` (not 0) of pipe `id`: its first record,
    /// PIPE_LANE alone; then, once it is confirmed, the stream data placed
    /// on it; its shutdown with the pipe's.
    fn poll_lane(&mut self, id: u64, n: u64, now: Instant, out: &mut TransmitBuf) -> Transmit {
        self.tick(now);
        out.clear();
        self.tx = id;
        self.tx_lane = n;
        self.tx_lanes = true;
        let Some(o) = self.out_ref(id) else {
            return Transmit::Idle;
        };
        let Some(l) = o.lanes().and_then(|l| l.get(n)) else {
            return Transmit::Idle;
        };
        if !l.attached() || l.writes_ended() || self.state == State::Closed {
            return Transmit::Idle;
        }
        let (framing, first) = (l.framing(), l.first_owed());
        let shutdown = self.lane_shutdown(o);
        out.set_framing(framing);
        let max_record = match framing {
            Framing::ByteStream => self.max_record(),
            Framing::Records => self.max_record().min(out.max_message().max(MIN_MESSAGE)),
        };
        if first && !shutdown {
            let Some(lane_key) = self.peer_lane_key() else {
                return Transmit::Idle;
            };
            // The first record holds PIPE_LANE alone (MULTIPATH.md
            // Section 5.8); its bytes are outside the pipe's send order.
            let frame = Frame::PipeLane(PipeLane {
                lane_key,
                pipe_id: id,
                lane: n,
            });
            let mut w = Records::new(out, max_record);
            w.force(frame.encoded_len());
            let _ = w.out.push_frame(&frame);
            let records = w.finish();
            self.count_sent(out.len(), records);
            let len = out.stream_len();
            if let Some(l) = self.out_mut(id).and_then(OutPipe::lanes_mut) {
                l.wrote_first(n, len);
            }
            return Transmit::Data;
        }
        if shutdown {
            if let Some(l) = self.out_mut(id).and_then(OutPipe::lanes_mut) {
                l.shutdown_written(n);
            }
            return Transmit::Shutdown;
        }
        if self.state == State::Establishing || !Self::lane_open(o, n) || !l.writable() {
            return Transmit::Idle;
        }
        let mut w = Records::new(out, max_record);
        self.pace_left = self.pacing_room(id, now);
        self.write_stream_data(id, &mut w);
        self.pace_left = None;
        if w.exchange {
            self.exchange_at = Some(now);
        }
        let traffic = w.traffic;
        w.end_record();
        let eliciting = w.eliciting_end();
        let records = w.finish();
        self.count_sent(out.len(), records);
        self.after_batch(id, out, eliciting, now);
        if traffic {
            self.note_traffic(now);
        }
        self.pace_sent(id, out.len() as u64, now);
        if out.is_empty() {
            Transmit::Idle
        } else {
            Transmit::Data
        }
    }

    /// Accounts a batch handed to pipe `id`: its position, the retained
    /// frames and the batch log (MULTIPATH.md Sections 6 and 7);
    /// `eliciting` is where its last ack-eliciting byte ends, if any.
    fn after_batch(&mut self, id: u64, out: &TransmitBuf, eliciting: Option<u64>, now: Instant) {
        let lane = self.tx_lane;
        let total = out.stream_len();
        let mp = self.mp.is_some();
        let peer_mad = self
            .mp
            .as_deref()
            .map_or(Duration::ZERO, mpath::Mp::peer_mad);
        let Some(o) = self.atts.get_mut(id).and_then(Attachment::out_mut) else {
            return;
        };
        let base = o.sent();
        if let Some(m) = self.mp.as_deref_mut().map(mpath::Mp::batch_mut) {
            m.new_data = false;
            m.txlog_new = false;
            let ends = out.record_ends();
            for (idx, f) in m.txlog.drain(..) {
                let end = ends.get(idx as usize).copied().unwrap_or(total);
                o.retain_frame(lane, base + end, f);
                if let pipes::SentFrame::Stream { key, off, len, .. } = f
                    && let Some(send) = self.streams.send_mut(key)
                {
                    send.mp_mut().carry(stream::Carry {
                        off,
                        end: off + len,
                        pipe: id,
                        pos: base + end,
                    });
                }
            }
            for idx in m.txactivity.drain(..) {
                let end = ends.get(idx as usize).copied().unwrap_or(total);
                o.activity_at(base + end);
            }
        }
        if total == 0 {
            return;
        }
        o.batch_sent(lane, total, out.record_ends().len() as u64, eliciting);
        if let Some(l) = o.lanes_mut() {
            l.bind_batch(lane, base + total);
        }
        let eliciting = eliciting.is_some();
        if !mp {
            // Pipe acknowledgement keeps the sample state of each batch
            // (MULTIPATH.md Section 3.5); so does the first batch, sent
            // before the peer's parameters tell whether it is in use.
            self.single_batch_sent(eliciting, now);
            return;
        }
        if let Some(o) = self.out_mut(id) {
            o.mp_batch_sent(lane, eliciting, peer_mad, now);
        }
        self.batch_stream_bytes = 0;
    }

    fn count_sent(&mut self, bytes: usize, records: u64) {
        self.stats.bytes_sent += bytes as u64;
        self.stats.records_sent += records;
        if self.mp.is_none() {
            let rtt = self.carrier_rtt.or(self.loop_min.get());
            self.send_rate.update(self.now, self.stats.bytes_sent, rtt);
        }
    }

    /// Owes a copy of a credit frame just written, when the window is the
    /// bottleneck: the latest value rides with the next redundant snapshot
    /// on the second pipe, due at most 50 ms later (MULTIPATH.md Section
    /// 6.5).
    fn copy_credit(&mut self, kind: mpath::CreditCopy) {
        if self.mp.is_none() {
            return;
        }
        let tx = self.tx;
        let now = self.now;
        let second = self
            .atts
            .iter()
            .any(|a| a.id() != tx && a.out().and_then(OutPipe::control_rank).is_some());
        let Some(mp) = self.mp.as_deref_mut().filter(|_| second) else {
            return;
        };
        let copies = &mut mp.batch_mut().credit_copies;
        if let Some(c) = copies.iter_mut().find(|c| c.0 == kind) {
            c.1 = tx;
        } else {
            copies.push((kind, tx));
        }
        mp.acks_mut().copy_by(now + mpath::ACK_COPY_INTERVAL);
    }

    /// Writes the credit copies owed by frames another pipe carried, with
    /// the current values, in the record of the redundant snapshot. `false`
    /// when the batch filled up.
    fn write_credit_copies(&mut self, id: u64, w: &mut Records<'_>) -> bool {
        let mut i = 0;
        while let Some(&(kind, carrier)) = self.mp().batch().credit_copies.get(i) {
            if carrier == id {
                i += 1;
                continue;
            }
            let written = match kind {
                mpath::CreditCopy::Session => {
                    let maximum = self.streams.recv_flow().limit_sent;
                    w.try_frame(&Frame::MaxData(MaxData { maximum }))
                        .then(|| self.log(w, pipes::SentFrame::MaxData))
                        .is_some()
                }
                mpath::CreditCopy::Streams(d) => {
                    let frame = Frame::MaxStreams(MaxStreams {
                        dir: dir_of_index(d),
                        maximum: self.streams.remote_dir(d).limit_sent,
                    });
                    w.try_frame(&frame)
                        .then(|| self.log(w, pipes::SentFrame::MaxStreams { dir: d }))
                        .is_some()
                }
                mpath::CreditCopy::Stream(key) => {
                    let open = self.streams.get(key).and_then(|s| {
                        let r = s.recv.as_ref()?;
                        (r.state == RecvState::Recv && r.cold().stopped.is_none())
                            .then_some((s.id?, r.limit))
                    });
                    match open {
                        Some((stream_id, maximum)) => {
                            let f = Frame::MaxStreamData(MaxStreamData { stream_id, maximum });
                            w.try_frame(&f)
                                .then(|| self.log(w, pipes::SentFrame::MaxStreamData { key }))
                                .is_some()
                        }
                        // No longer needed.
                        None => true,
                    }
                }
            };
            if !written {
                return false;
            }
            self.mp_mut().batch_mut().credit_copies.swap_remove(i);
        }
        true
    }

    /// Records a retained frame of the current batch (multipath only).
    pub(super) fn log(&mut self, w: &Records<'_>, f: pipes::SentFrame) {
        if let Some(m) = self.mp.as_deref_mut().map(mpath::Mp::batch_mut) {
            m.txlog.push((w.record_index(), f));
            m.txlog_new = false;
        }
    }

    /// Records a STREAM frame of new data: one that continues the stream's
    /// last frame in the batch extends it instead (the frame ends in a
    /// later record of the same batch), so that a pipe's log, the
    /// direction's carried frames and the acknowledgements walk one entry
    /// per run of a stream in a batch rather than one per record.
    fn log_new_data(&mut self, w: &Records<'_>, key: StreamKey, off: u64, len: u64, fin: bool) {
        let Some(m) = self.mp.as_deref_mut().map(mpath::Mp::batch_mut) else {
            return;
        };
        let idx = w.record_index();
        if let Some((
            at,
            pipes::SentFrame::Stream {
                key: k,
                off: o,
                len: l,
                fin: f,
            },
        )) = m.txlog.last_mut()
            && m.txlog_new
            && *k == key
            && *o + *l == off
            && !*f
        {
            *l += len;
            *f = fin;
            *at = idx;
            return;
        }
        m.txlog
            .push((idx, pipes::SentFrame::Stream { key, off, len, fin }));
        m.txlog_new = true;
    }

    /// The current record carries an activity frame (multipath idle
    /// timer, SPEC.md Section 6.4).
    fn note_activity(&mut self, w: &Records<'_>) {
        if let Some(m) = self.mp.as_deref_mut().map(mpath::Mp::batch_mut) {
            let idx = w.record_index();
            if m.txactivity.last() != Some(&idx) {
                m.txactivity.push(idx);
            }
        }
    }

    // ---- pipe-layer frames (multipath) -------------------------------------------

    /// PIPE_PING, PIPE_ACK, PIPE_ABANDON and PIPE_STATUS for pipe `id`.
    fn write_pipe_frames(&mut self, id: u64, w: &mut Records<'_>, now: Instant) {
        self.write_pipe_ping(id, w, now);
        if self.write_pipe_ack(id, w, now) && !self.write_credit_copies(id, w) {
            return;
        }
        if self.att(id).is_some_and(|a| a.abandon_owed(true)) {
            self.write_abandon(w, Some(id));
        }
        if self.control_pipe(None) != Some(id) {
            // PIPE_ABANDON of the pipe's own attachment when no other pipe
            // can carry it.
            if self.control_pipe(Some(id)).is_none() {
                self.write_abandon(w, Some(id));
            }
            return;
        }
        self.write_abandon(w, None);
        for i in 0..self.atts.len() {
            // No PIPE_STATUS for our own attachment while it is JOINING: a
            // changed request goes out once it is ACTIVE (MULTIPATH.md
            // Section 5.7 step 3).
            if !self.atts.at(i).joining_local() && !self.write_status(i, w) {
                return;
            }
        }
    }

    /// Writes the PIPE_PING pipe `id` wants, when the rate limits allow.
    pub(super) fn write_pipe_ping(&mut self, id: u64, w: &mut Records<'_>, now: Instant) {
        if self.ping_due(id, now) && w.try_frame(&Frame::PipePing) {
            self.mp_mut().ping_sent(now);
            self.requests.record(now);
            if let Some(o) = self.out_mut(id) {
                o.ping_written();
            }
        }
    }

    /// Writes the pending PIPE_ABANDON frames (only that of `only` when
    /// given).
    fn write_abandon(&mut self, w: &mut Records<'_>, only: Option<u64>) {
        let mut i = 0;
        while i < self.atts.len() {
            let a = self.atts.at(i);
            let pipe = a.id();
            if let Some(code) = a
                .abandon_to_write(only.is_some())
                .filter(|_| only.is_none_or(|o| o == pipe))
            {
                let frame = Frame::PipeAbandon(PipeAbandon {
                    pipe_id: pipe,
                    error_code: code,
                });
                if !w.try_frame(&frame) {
                    return;
                }
                self.atts.at_mut(i).abandon_written();
                self.mp_mut().batch_mut().abandons_sent.push(pipe);
                self.log(w, pipes::SentFrame::PipeAbandon { pipe });
            }
            i += 1;
        }
    }

    // ---- session control frames ------------------------------------------

    fn write_ping_request(&mut self, w: &mut Records<'_>, now: Instant) -> bool {
        if self.requests.available(now) == 0 {
            // Rate-limited (SPEC.md 9.4.3 rule 1): later, not lost.
            return true;
        }
        let seq = self.ping.next_seq;
        let f = Frame::QxPing(QxPing {
            response: false,
            sequence: seq,
        });
        if !w.try_frame(&f) {
            return false;
        }
        self.ping.next_seq += 1;
        self.ping.request_pending = false;
        self.requests.record(now);
        self.ping.outstanding = Some((seq, now));
        self.ping.largest_sent = Some(seq);
        self.log(w, pipes::SentFrame::Ping { seq });
        self.note_activity(w);
        if self.goaway().fence_pending {
            self.goaway_mut().fence_pending = false;
            self.goaway_mut().fence = Some(seq);
        }
        true
    }

    fn write_control(&mut self, w: &mut Records<'_>, now: Instant) {
        if let Some(seq) = self.ping.response_pending {
            let f = Frame::QxPing(QxPing {
                response: true,
                sequence: seq,
            });
            if !w.try_frame(&f) {
                return;
            }
            self.ping.response_pending = None;
            self.note_activity(w);
        }
        // A fence request follows its GOAWAY (EXTENSIONS.md Section 3.3).
        if self.ping.request_pending
            && self.ping.outstanding.is_none()
            && !(self.goaway().fence_pending && self.goaway().pending.is_some())
            && !self.write_ping_request(w, now)
        {
            return;
        }
        let f = self.streams.recv_flow();
        if f.update_pending || f.resend {
            let value = if f.update_pending {
                self.session_credit_value(now)
            } else {
                f.limit_sent
            };
            let f = self.streams.recv_flow();
            if value > f.limit_sent || f.resend {
                let value = value.max(f.limit_sent);
                if !w.try_frame(&Frame::MaxData(MaxData { maximum: value })) {
                    return;
                }
                self.log(w, pipes::SentFrame::MaxData);
                if self.streams.max_data_written(value, now) {
                    self.copy_credit(mpath::CreditCopy::Session);
                }
            }
            self.streams.max_data_settled();
        }
        for d in [BIDI, UNI] {
            let r = self.streams.remote_dir(d);
            if !r.update_pending && !r.resend {
                continue;
            }
            let value = r.limit_due(MAX_COUNT);
            let goaway = self.goaway_announced();
            let raise = value > r.limit_sent && !goaway;
            if raise || r.resend {
                let value = if raise { value } else { r.limit_sent };
                let frame = Frame::MaxStreams(MaxStreams {
                    dir: dir_of_index(d),
                    maximum: value,
                });
                if !w.try_frame(&frame) {
                    return;
                }
                self.log(w, pipes::SentFrame::MaxStreams { dir: d });
                if self.streams.max_streams_written(d, value) {
                    self.copy_credit(mpath::CreditCopy::Streams(d));
                }
            }
            self.streams.max_streams_settled(d);
        }
        let f = self.streams.send_flow();
        if f.blocked_pending || f.blocked_resend {
            let limit = f.max;
            if f.blocked_reported != Some(limit) || f.blocked_resend {
                if !w.try_frame(&Frame::DataBlocked(DataBlocked { limit })) {
                    return;
                }
                self.log(w, pipes::SentFrame::DataBlocked);
                self.streams.data_blocked_written(limit);
            }
            self.streams.data_blocked_settled();
        }
        for d in [BIDI, UNI] {
            let ld = self.streams.local_dir(d);
            if !ld.blocked_pending && !ld.blocked_resend {
                continue;
            }
            let limit = ld.peer_max;
            if ld.blocked_reported != Some(limit) || ld.blocked_resend {
                let frame = Frame::StreamsBlocked(StreamsBlocked {
                    dir: dir_of_index(d),
                    limit,
                });
                if !w.try_frame(&frame) {
                    return;
                }
                self.log(w, pipes::SentFrame::StreamsBlocked { dir: d });
                self.streams.streams_blocked_written(d, limit);
            }
            self.streams.streams_blocked_settled(d);
        }
        if let Some((bidi, uni)) = self.goaway().resend
            && self.goaway().pending.is_none()
        {
            // The current watermarks again (MULTIPATH.md Section 7.4).
            let code = self.goaway().shutdown.unwrap_or(0);
            let frame = Frame::GoAway(GoAwayFrame {
                max_bidi: bidi,
                max_uni: uni,
                error_code: code,
            });
            if !w.try_frame(&frame) {
                return;
            }
            self.log(w, pipes::SentFrame::GoAway);
            self.goaway_mut().resend = None;
            if self.goaway().fence_pending && self.ping.outstanding.is_none() {
                self.write_ping_request(w, now);
            }
        }
        if let Some((bidi, uni, code)) = self.goaway().pending {
            let frame = Frame::GoAway(GoAwayFrame {
                max_bidi: bidi,
                max_uni: uni,
                error_code: code,
            });
            if !w.try_frame(&frame) {
                return;
            }
            self.log(w, pipes::SentFrame::GoAway);
            self.goaway_mut().pending = None;
            self.goaway_mut().resend = None;
            self.goaway_mut().sent = Some((bidi, uni));
            for (d, wm) in [(BIDI, bidi), (UNI, uni)] {
                self.streams.goaway_written(d, wm);
            }
            if self.goaway().fence_pending && self.ping.outstanding.is_none() {
                self.write_ping_request(w, now);
            }
        }
    }

    // ---- per-stream control frames ------------------------------------------

    fn write_stream_controls(&mut self, w: &mut Records<'_>, now: Instant) {
        while let Some(key) = self.streams.pop_ctrl() {
            if self.write_one_control(key, w, now).is_err() {
                self.streams.requeue_ctrl(key);
                return;
            }
            self.try_discard(key);
        }
    }

    /// Writes the control frames a stream owes, in this order:
    /// STOP_SENDING, MAX_STREAM_DATA, PRIORITY_UPDATE, STREAM_DATA_BLOCKED,
    /// and its reset.
    fn write_one_control(
        &mut self,
        key: StreamKey,
        w: &mut Records<'_>,
        now: Instant,
    ) -> Result<(), Full> {
        let Some(s) = self.streams.get_mut(key) else {
            return Ok(());
        };
        // A stream without an identifier, or whose opening frame is not
        // written yet, is queued again once it is (`assign_id`,
        // `write_openings`); its control state waits.
        let Some(id) = s.id.filter(|_| !s.open_pending) else {
            return Ok(());
        };
        if let Some(r) = s.recv.as_mut()
            && r.stop_pending
        {
            let f = Frame::StopSending(StopSending {
                stream_id: id,
                error_code: r.cold().stopped.unwrap_or(0),
            });
            if !w.try_frame(&f) {
                return Err(Full);
            }
            r.stop_pending = false;
            self.log(w, pipes::SentFrame::StopSending { key });
            self.note_activity(w);
        }
        let s = self.stream_mut(key);
        if s.recv
            .as_ref()
            .is_some_and(|r| r.update_pending || r.resend)
        {
            let open = s
                .recv
                .as_ref()
                .is_some_and(|r| r.state == RecvState::Recv && r.cold().stopped.is_none());
            let update = s.recv.as_ref().is_some_and(|r| r.update_pending);
            let value = if !open {
                None
            } else if update {
                self.stream_credit_value(key, now)
            } else {
                Some(self.recv_mut(key).limit)
            };
            if let Some(value) = value {
                let r = self.recv_mut(key);
                if value > r.limit || r.resend {
                    let value = value.max(r.limit);
                    let f = Frame::MaxStreamData(MaxStreamData {
                        stream_id: id,
                        maximum: value,
                    });
                    if !w.try_frame(&f) {
                        return Err(Full);
                    }
                    let r = self.recv_mut(key);
                    let remaining = r.limit.saturating_sub(r.received);
                    let bottleneck =
                        remaining < r.window / 4 || r.cold().blocked_seen == Some(r.limit);
                    let old = r.limit;
                    r.limit = value;
                    if value > old {
                        self.streams.autotune_sent_stream(key, old, now);
                    }
                    self.log(w, pipes::SentFrame::MaxStreamData { key });
                    if bottleneck {
                        self.copy_credit(mpath::CreditCopy::Stream(key));
                    }
                }
            }
            let r = self.recv_mut(key);
            r.resend = false;
            self.streams.mark_stream_update(key, false);
        }
        let s = self.stream_mut(key);
        let priority = match (s.extra().priority_update, s.extra().priority_resend) {
            (Some(p), _) => Some((s.extra().priority_seq, p, true)),
            (None, true) => s.extra().priority_sent.map(|(q, p)| (q, p, false)),
            _ => None,
        };
        if let Some((seq, p, fresh)) = priority {
            let f = Frame::PriorityUpdate(PriorityUpdate {
                stream_id: id,
                sequence: seq,
                priority: p,
            });
            if !w.try_frame(&f) {
                return Err(Full);
            }
            let s = self.stream_mut(key);
            if fresh {
                let e = s.extra_mut();
                e.priority_update = None;
                e.priority_seq += 1;
            }
            let e = s.extra_mut();
            e.priority_sent = Some((seq, p));
            e.priority_resend = false;
            self.log(w, pipes::SentFrame::PriorityUpdate { key, seq });
        }
        if self.send_ctrl_elsewhere(key) {
            // The sending part's frames stay on its lane until a PIPE_ACK
            // covers them there: these go once it does.
            return Ok(());
        }
        let s = self.stream_mut(key);
        if let Some(send) = s.send.as_mut()
            && let Some(limit) = send.blocked_at
        {
            if limit == send.max_data
                && send.cold().reset.is_none()
                && send.blocked_reported != Some(limit)
            {
                let f = Frame::StreamDataBlocked(StreamDataBlocked {
                    stream_id: id,
                    limit,
                });
                if !w.try_frame(&f) {
                    return Err(Full);
                }
                send.blocked_reported = Some(limit);
                self.log(w, pipes::SentFrame::StreamDataBlocked { key });
            } else {
                send.blocked_at = None;
            }
            if let Some(send) = self.stream_mut(key).send.as_mut() {
                send.blocked_at = None;
            }
        }
        self.write_reset(key, id, w)
    }

    fn stream_mut(&mut self, key: StreamKey) -> &mut stream::Stream {
        self.streams.get_mut(key).expect("stream present")
    }

    fn recv_mut(&mut self, key: StreamKey) -> &mut stream::RecvPart {
        self.stream_mut(key)
            .recv
            .as_mut()
            .expect("receiving part present")
    }

    /// Writes the opening frames of pinned streams, per type in identifier
    /// order, stopping at the first that credit holds back (SPEC.md Section
    /// 7.2: no stream's first frame before those of lower-numbered ones).
    fn write_openings(&mut self, w: &mut Records<'_>) {
        for d in [BIDI, UNI] {
            let mut opened = false;
            while let Some(&key) = self.streams.pinned(d).front() {
                let pending = self
                    .streams
                    .get(key)
                    .is_some_and(|s| s.open_pending && s.goaway.is_none());
                if pending {
                    match self.write_opening(key, w) {
                        Ok(true) => {}
                        Ok(false) => break,
                        Err(Full) => return,
                    }
                }
                opened = true;
                if self.streams.unpin_first(d) {
                    self.schedule(key);
                }
            }
            if opened && self.streams.pinned(d).is_empty() {
                self.schedule_unopened(d);
            }
        }
    }

    /// Writes the opening frame of a pinned stream: the rest of its
    /// preamble, or an empty STREAM frame. `Ok(false)` while stream or
    /// session credit holds it back.
    fn write_opening(&mut self, key: StreamKey, w: &mut Records<'_>) -> Result<bool, Full> {
        let session_room = self.streams.send_flow().room();
        let tx = self.tx;
        let mp = self.mp.is_some();
        let s = self.stream_mut(key);
        let (Some(id), Some(send)) = (s.id, s.send.as_mut()) else {
            return Ok(true);
        };
        let len = send.preamble_left as u64;
        if len > send.max_data.saturating_sub(send.offset) || len > session_room {
            return Ok(false);
        }
        let header = StreamHeader {
            stream_id: id,
            offset: send.offset,
            len,
            fin: false,
            explicit_offset: false,
            explicit_len: true,
        };
        if !w.ensure(header.encoded_len() + len as usize) {
            return Err(Full);
        }
        w.stream_header(&header);
        if let Some(pre) = &send.preamble {
            w.out.push_bytes(&pre[pre.len() - send.preamble_left..]);
        }
        let off = send.offset;
        if off == 0
            && let Some(m) = send.mp_in(mp)
            && m.open_pipe.is_none()
        {
            m.open_pipe = Some(tx);
        }
        send.offset += len;
        send.preamble_left = 0;
        if send.state == SendState::Ready {
            send.state = SendState::Send;
        }
        self.streams.spend(len);
        self.note_lane_frame(key);
        if self.mp.is_some() {
            self.mp_mut().retain(len);
            self.log(
                w,
                pipes::SentFrame::Stream {
                    key,
                    off,
                    len,
                    fin: false,
                },
            );
            self.note_activity(w);
        }
        Ok(true)
    }

    /// Writes a reset the stream owes, once the data below its Reliable
    /// Size is written (SPEC.md Section 4.3); in a multipath session also
    /// again when it was lost with a pipe (MULTIPATH.md Section 7.4).
    fn write_reset(&mut self, key: StreamKey, id: u64, w: &mut Records<'_>) -> Result<(), Full> {
        let peer_rsa = self.send_tp().is_some_and(|t| t.reset_stream_at);
        let mp = self.mp.is_some();
        // Carrier early data may still be rejected: nothing is final yet.
        let held = self.early_retains();
        let s = self.stream_mut(key);
        let Some(send) = s.send.as_mut() else {
            return Ok(());
        };
        let Some(reset) = send
            .cold()
            .reset
            .filter(|r| !r.written || (send.mp().reset_lost && !send.state.is_terminal()))
        else {
            return Ok(());
        };
        let again = reset.written;
        let reliable = if again {
            send.mp().reliable_sent
        } else {
            send.reset_reliable().filter(|_| peer_rsa)
        };
        if !again && reliable.is_some_and(|r| send.offset < r) {
            // The data path queues the stream again when it is out.
            return Ok(());
        }
        let final_size = send.offset;
        let frame = match reliable {
            Some(r) => Frame::ResetStreamAt(ResetStreamAt {
                stream_id: id,
                error_code: reset.code,
                final_size,
                reliable_size: r.min(final_size),
            }),
            None => Frame::ResetStream(ResetStream {
                stream_id: id,
                error_code: reset.code,
                final_size,
            }),
        };
        if !w.try_frame(&frame) {
            return Err(Full);
        }
        if let Some(m) = send.mp.as_deref_mut() {
            m.reset_lost = false;
        }
        if let Some(r) = send.reset_mut() {
            r.written = true;
        }
        if again {
            self.log(w, pipes::SentFrame::Reset { key });
            self.note_activity(w);
            return Ok(());
        }
        let before = send.unacked();
        let unsent = send.buf.len();
        send.buf.clear_unsent();
        send.preamble_left = 0;
        if mp {
            let m = send.mp_mut();
            m.reliable_sent = reliable.map(|r| r.min(final_size));
            m.fin_lost = false;
            // Data at or beyond the Reliable Size is never sent again.
            let limit = m.reliable_sent.unwrap_or(0);
            m.lost.remove(limit, u64::MAX);
            if limit == 0 || limit <= m.buf_floor {
                m.lost.clear();
                send.buf.clear();
            }
            send.state = SendState::ResetSent;
        } else if held {
            send.state = SendState::ResetSent;
        } else {
            // Outside multipath a written reset is acknowledged (SPEC.md 7.4).
            send.state = SendState::ResetRecvd;
        }
        let after = send.unacked();
        self.streams.drop_unsent(unsent);
        if mp {
            self.mp_mut().retained_changed(before, after);
            self.log(w, pipes::SentFrame::Reset { key });
            self.note_activity(w);
        }
        self.unschedule(key);
        self.wake_send_waiters();
        self.notify_writable(key);
        Ok(())
    }

    // ---- datagrams -----------------------------------------------------------

    /// The pipe a stream datagram must follow (multipath): the pipe of the
    /// stream's opening frame while that is unacknowledged and the pipe is
    /// live (EXTENSIONS.md Section 6.4, MULTIPATH.md Section 11).
    fn datagram_pipe(&self, flow: Option<(u64, u64)>) -> Option<u64> {
        self.mp.as_ref()?;
        let (stream_id, _) = flow?;
        let send = self.streams.send(self.streams.key_of(stream_id)?)?;
        let opened = send.mp().acked.contains(0, 1)
            || send.mp().buf_floor > 0
            || (send.base > 0 && send.mp().preamble_acked);
        let pipe = send.mp().open_pipe.filter(|_| !opened)?;
        self.out_ref(pipe).filter(|o| o.is_live()).map(|_| pipe)
    }

    /// Writes queued datagrams that may go on pipe `pipe`: on the control
    /// pipe every datagram except the stream datagrams that follow their
    /// opening frame on another pipe; on another pipe only those that
    /// follow it there, and only while it may carry DATAGRAM (ACTIVE).
    fn write_datagrams(&mut self, pipe: u64, control: bool, w: &mut Records<'_>) {
        let flows = self.features.datagram_flows;
        let max_frame = self.max_datagram_frame().unwrap_or(0);
        let carries = self.mp.is_none()
            || self
                .out_ref(pipe)
                .is_some_and(|o| o.state() == pipes::OutState::Active);
        let mut i = 0;
        loop {
            let Some((flow, data)) = self.dgram().send.get(i) else {
                return;
            };
            let follow = self.datagram_pipe(*flow);
            let here = match follow {
                Some(p) => p == pipe && carries,
                None => control,
            };
            if !here {
                i += 1;
                continue;
            }
            let flow = match (flows, *flow) {
                (false, _) => None,
                (true, None) => Some(Flow::Session),
                (true, Some((stream_id, context))) => Some(Flow::Stream { stream_id, context }),
            };
            let prefix = flow.map_or(0, |f| f.encoded_len());
            let total = prefix + data.len();
            // With a Length field when it fits the peer's frame limit and
            // our records; otherwise last in its record, in one of its own
            // when it exceeds our record size (EXTENSIONS.md Section 6.6).
            let with_len = 1 + varint::len(total as u64) + total;
            let last = with_len > max_frame.min(w.max_record());
            let frame_len = if last { 1 + total } else { with_len };
            let room = if frame_len <= w.max_record() {
                w.ensure(frame_len)
            } else {
                w.own_record(frame_len)
            };
            if !room {
                return;
            }
            let was_full = self.dgram().send.len() >= SEND_DATAGRAM_QUEUE;
            let Some((_, data)) = self.dgram_mut().send.remove(i) else {
                return;
            };
            let mut header = [0u8; 9 + 16];
            let mut n = 1;
            if last {
                header[0] = 0x30;
            } else {
                header[0] = 0x31;
                n += varint::encode(total as u64, &mut header[1..]).unwrap_or(0);
            }
            if let Some(f) = flow {
                n += f.encode(&mut header[n..]).unwrap_or(0);
            }
            w.out.push_bytes(&header[..n]);
            let len = data.len() as u64;
            w.payload(data);
            w.activity = true;
            w.traffic = true;
            w.elicit();
            self.note_activity(w);
            if last {
                w.end_record();
            }
            self.stats.datagrams_sent += 1;
            // Handed to the carrier with this batch: application bytes.
            self.meter.add(Count::DatagramSent, len);
            if let Some(Flow::Stream { stream_id, .. }) = flow
                && let Some(s) = self
                    .streams
                    .key_of(stream_id)
                    .and_then(|k| self.streams.get_mut(k))
            {
                let d = &mut s.datagrams_mut().counts;
                d.sent += 1;
                d.bytes_sent += len;
                s.count(Count::DatagramSent, len);
            }
            if was_full {
                self.events.push_back(super::CoreEvent::DatagramsUnblocked);
            }
        }
    }

    // ---- stream data -----------------------------------------------------------

    /// Queues a stream in the scheduler when it has something to send.
    pub(super) fn schedule(&mut self, key: StreamKey) {
        self.pick_input();
        if !self.is_established() && !self.early_open() {
            return;
        }
        let Some(s) = self.streams.get_mut(key) else {
            return;
        };
        if s.goaway.is_some() || s.open_pending {
            return;
        }
        let Some(send) = s.send.as_mut() else {
            return;
        };
        if send.queued.is_some() || !send.has_pending() {
            return;
        }
        // A stream without an identifier is scheduled even without credit:
        // its first frame gives it one (STREAM_DATA_BLOCKED at a zero
        // window opens it at the peer).
        if send.credit_blocked()
            && send.cold().reset.is_none()
            && s.id.is_some()
            && !send.has_lost()
        {
            // Wait for MAX_STREAM_DATA; report the block once.
            if send.blocked_reported != Some(send.max_data) {
                send.blocked_at = Some(send.max_data);
                self.streams.queue_ctrl(key);
            }
            return;
        }
        let u = send.priority.urgency();
        if let Some(mp) = self.mp.as_deref_mut()
            && let Some(b) = send.mp().bound
        {
            // Re-evaluated with the next batch.
            mp.affinity_mut().queued(b.epoch);
        }
        self.streams.enqueue(key, u);
    }

    /// Moves a stream to the queue of its current urgency.
    pub(super) fn reschedule(&mut self, key: StreamKey) {
        if self.unschedule(key) {
            self.schedule(key);
        }
    }

    /// Removes a stream from the scheduler; returns whether it was queued.
    pub(super) fn unschedule(&mut self, key: StreamKey) -> bool {
        let Some(send) = self.streams.send_mut(key) else {
            return false;
        };
        let Some(u) = send.queued else {
            return false;
        };
        self.streams.dequeue(usize::from(u), key);
        true
    }

    /// Schedules the local streams of a type that wait for their first
    /// frame (after the pinned streams of the type opened).
    pub(super) fn schedule_unopened(&mut self, d: usize) {
        let keys: Vec<StreamKey> = self
            .streams
            .keys()
            .filter(|&k| {
                self.streams
                    .get(k)
                    .is_some_and(|s| s.local && s.id.is_none() && di(s.dir) == d)
            })
            .collect();
        for k in keys {
            self.schedule(k);
        }
    }

    fn write_stream_data(&mut self, pipe: u64, w: &mut Records<'_>) {
        if self.mp.is_some() {
            self.write_stream_data_mp(pipe, w);
            return;
        }
        if self.out_ref(pipe).is_some_and(|o| o.lanes().is_some()) {
            self.write_stream_data_lanes(pipe, w);
            return;
        }
        let offered = self.out_ref(pipe).is_some_and(OutPipe::lanes_offered);
        // Streams passed over in this round because session credit is out.
        let mut passed = 0;
        while self.streams.queue().len() > passed {
            let Some((u, key)) = self.streams.pick() else {
                return;
            };
            if offered {
                self.maybe_open_lane(pipe, key);
            }
            match self.write_stream_frame(pipe, key, None, w) {
                Step::Done => {
                    self.streams.dequeue_first(u, key);
                    self.after_stream_frame(key);
                }
                Step::More { rotate } => {
                    if rotate {
                        self.streams.move_back(u, 0);
                    }
                }
                Step::Blocked => {
                    self.streams.dequeue_first(u, key);
                }
                Step::SessionBlocked => {
                    // Blocked by session credit, at the limit or by a
                    // preamble that does not fit in what is left: report it
                    // once per limit (SPEC.md Section 8.4).
                    if let Some(limit) = self.streams.report_data_blocked()
                        && w.try_frame(&Frame::DataBlocked(DataBlocked { limit }))
                    {
                        self.streams.data_blocked_written(limit);
                    }
                    if self.streams.send_flow().exhausted() {
                        // Send what needs no credit and wait for MAX_DATA.
                        if self.write_credit_free(w, None) {
                            self.streams.stall_if_queued();
                        }
                        return;
                    }
                    // Some credit is left, too little for this stream's
                    // preamble: others may use it.
                    self.streams.move_back(u, 0);
                    passed += 1;
                }
                Step::Full | Step::Budget => return,
            }
        }
        if passed > 0 && self.write_credit_free(w, None) {
            self.streams.stall_if_queued();
        }
    }

    /// Stream data for the lane of the single pipe that the batch is for: the
    /// directions placed on it, by urgency
    /// and round robin within each.
    fn write_stream_data_lanes(&mut self, pipe: u64, w: &mut Records<'_>) {
        let lane = self.tx_lane;
        // Directions passed over because what is left of the session
        // credit is too little for their preamble.
        let mut skipped: Vec<StreamKey> = Vec::new();
        loop {
            let Some(o) = self.out_ref(pipe) else {
                return;
            };
            let found = (0..8).find_map(|u| {
                self.streams
                    .queue()
                    .level(u)
                    .iter()
                    .position(|&k| !skipped.contains(&k) && self.lane_for(o, k) == lane)
                    .map(|i| (u, i))
            });
            let Some((u, i)) = found else {
                break;
            };
            let key = self.streams.queue().level(u)[i];
            self.maybe_open_lane(pipe, key);
            match self.write_stream_frame(pipe, key, None, w) {
                Step::Done => {
                    self.streams.dequeue_at(u, i);
                    self.after_stream_frame(key);
                }
                Step::More { rotate } => {
                    if rotate {
                        self.streams.move_back(u, i);
                    }
                }
                Step::Blocked => {
                    self.streams.dequeue_at(u, i);
                }
                Step::SessionBlocked => {
                    if let Some(limit) = self.streams.report_data_blocked()
                        && w.try_frame(&Frame::DataBlocked(DataBlocked { limit }))
                    {
                        self.streams.data_blocked_written(limit);
                    }
                    if self.streams.send_flow().exhausted() {
                        if self.write_credit_free(w, None) {
                            self.streams.stall_if_queued();
                        }
                        return;
                    }
                    skipped.push(key);
                }
                Step::Full | Step::Budget => return,
            }
        }
        if !skipped.is_empty() && self.write_credit_free(w, None) {
            self.streams.stall_if_queued();
        }
    }

    /// Opens a lane of the pipe when direction `key`, about to write, needs
    /// a data lane the pipe does not have free.
    fn maybe_open_lane(&mut self, pipe: u64, key: StreamKey) {
        if self
            .out_ref(pipe)
            .is_some_and(|o| o.lanes_offered() && self.wants_data_lane(o, key))
        {
            self.request_lane(pipe);
        }
    }

    /// Stream data for pipe `pipe` in a multipath session: reinjected data
    /// first, then new data of the streams the scheduler places on the pipe
    /// (MULTIPATH.md Section 11), by urgency and round robin.
    fn write_stream_data_mp(&mut self, pipe: u64, w: &mut Records<'_>) {
        // Redundant copies queued for the pipe go first.
        if !self.write_copies(pipe, w) {
            return;
        }
        let mut inputs = std::mem::take(&mut self.mp_mut().batch_mut().gate_inputs);
        inputs.reset();
        self.write_new_data_mp(pipe, &mut inputs, w);
        self.mp_mut().batch_mut().gate_inputs = inputs;
    }

    /// The chunks of [`Self::write_stream_data_mp`], one decision each.
    /// A decision is worked out again only when its gate or the pipe views
    /// changed: the same inputs give the same decision. The scan of the
    /// queues goes on where the last chunk was taken while nothing before
    /// that place was passed over by the decision (a direction passed over
    /// may go after a chunk of another changed what it depends on, the
    /// bindings' loads, the backlog or a round-robin turn).
    fn write_new_data_mp(&mut self, pipe: u64, inputs: &mut GateInputs, w: &mut Records<'_>) {
        // Directions passed over in this batch because what is left of the
        // session credit is too little for their preamble: rare, and few.
        let mut skipped: Vec<StreamKey> = Vec::new();
        // Bindings are re-evaluated once per batch.
        let gate = self.gate_from(inputs);
        self.refresh_bindings(gate.as_ref());
        self.prune_credit_blocked();
        let mut kept: Option<(Decision, u64)> = None;
        // Where the scan goes on: (level, index).
        let mut at = (0, 0);
        loop {
            // The gate of this decision: one per chunk.
            let gate = self.gate_from(inputs);
            let generation = self.mp().tiers().view_generation();
            let mut d = match kept.take() {
                Some((mut d, g)) if g == generation && d.gate == gate => {
                    d.renew();
                    #[cfg(debug_assertions)]
                    d.check_renewed(self);
                    d
                }
                _ => {
                    at = (0, 0);
                    self.decision(pipe, gate)
                }
            };
            // Reinjected information goes first (MULTIPATH.md Section 11 rule S3).
            // Reinjected information goes to the eligible pipe with the
            // earliest arrival; other pipes go on with new data meanwhile.
            if let Some((u, key)) = self.first_lost().filter(|&(_, k)| {
                self.reinject_room(pipe) > 0
                    && self.stream_on_pipe(&d, k)
                    && self
                        .out_ref(pipe)
                        .is_none_or(|o| self.lane_for(o, k) == self.tx_lane)
            }) {
                if let Step::Full = self.write_lost_frame(key, w) {
                    return;
                }
                let pending = self.streams.send(key).is_some_and(|x| x.has_pending());
                if !pending {
                    self.streams.dequeue(u, key);
                    self.after_stream_frame(key);
                }
                // Queues and holds moved: the scan starts over.
                kept = Some((d, generation));
                at = (0, 0);
                continue;
            }
            // Opportunistic copies of the data that blocks the window
            // (Section 7.5.1).
            let copied = self.stats.bytes_opportunistic;
            if !self.write_opportunistic(pipe, self.now, d.gate, w) {
                return;
            }
            if self.stats.bytes_opportunistic != copied {
                // The copies penalized a pipe: the new data goes by the
                // pipes as they are now, under the same gate.
                d = self.decision(pipe, d.gate);
                at = (0, 0);
            }
            if self.streams.session_stalled() {
                // Only FIN-only frames go (SPEC.md Section 8.2).
                self.write_credit_free(w, Some(&d));
                return;
            }
            if !self.any_stream_on(&d, true) {
                // No direction goes on the pipe: the ledger tells without
                // a pass over the queues.
                return;
            }
            let Some((u, i, step)) = self.scan_mp(pipe, &d, &skipped, &mut at, w) else {
                return;
            };
            let key = self.streams.queue().level(u)[i];
            match step {
                Step::Done => {
                    self.streams.dequeue_at(u, i);
                    self.after_stream_frame(key);
                }
                Step::More { rotate } => {
                    if rotate {
                        self.streams.move_back(u, i);
                    }
                }
                Step::Blocked => {
                    self.streams.dequeue_at(u, i);
                    self.note_credit_blocked(key);
                }
                Step::SessionBlocked => {
                    if let Some(limit) = self.streams.report_data_blocked()
                        && w.try_frame(&Frame::DataBlocked(DataBlocked { limit }))
                    {
                        self.log(w, pipes::SentFrame::DataBlocked);
                        self.streams.data_blocked_written(limit);
                    }
                    if self.streams.send_flow().exhausted() {
                        if self.write_credit_free(w, Some(&d)) {
                            self.streams.stall_if_queued();
                        }
                        return;
                    }
                    // Too little credit for this stream's preamble:
                    // others may use it.
                    skipped.push(key);
                    if at == (u, i) {
                        at.1 += 1;
                    }
                }
                Step::Full | Step::Budget => return,
            }
            kept = Some((d, generation));
        }
    }

    /// Finds the next direction from `at` on that goes on the decision's
    /// pipe and writes a frame of it: its level, its index and the outcome.
    /// `at` is left where the scan goes on next time: there while every
    /// direction before it was skipped or passed over for good (bound to
    /// another usable pipe, which no chunk of another direction changes),
    /// else at the start.
    fn scan_mp(
        &mut self,
        pipe: u64,
        d: &Decision,
        skipped: &[StreamKey],
        at: &mut (usize, usize),
        w: &mut Records<'_>,
    ) -> Option<(usize, usize, Step)> {
        let mut passed = false;
        let (mut u, mut i) = *at;
        let lanes = self
            .out_ref(pipe)
            .is_some_and(|o| o.lanes().is_some() || o.lanes_offered());
        while u < 8 {
            while i < self.streams.queue().level(u).len() {
                let key = self.streams.queue().level(u)[i];
                if !skipped.is_empty() && skipped.contains(&key) {
                    i += 1;
                    continue;
                }
                if !self.stream_on_pipe(d, key) {
                    passed = passed || !self.bound_elsewhere(d, key);
                    i += 1;
                    continue;
                }
                if lanes {
                    // The direction's lane of the pipe: another one goes there, for good
                    // while it is bound.
                    self.maybe_open_lane(pipe, key);
                    if self
                        .out_ref(pipe)
                        .is_some_and(|o| self.lane_for(o, key) != self.tx_lane)
                    {
                        i += 1;
                        continue;
                    }
                }
                let step = self.write_stream_frame(pipe, key, d.gate.as_ref(), w);
                *at = if passed { (0, 0) } else { (u, i) };
                return Some((u, i, step));
            }
            u += 1;
            i = 0;
        }
        None
    }

    /// The first direction with reinjected information pending, by urgency
    /// and then queue order: the lowest level among the ledger's losing
    /// directions, then the first of them in that queue.
    fn first_lost(&self) -> Option<(usize, StreamKey)> {
        let ledger = self.ledger()?;
        let losing = ledger.losing()?;
        let level = losing
            .iter()
            .filter_map(|&k| ledger.share(k))
            .map(|s| usize::from(s.level))
            .min()?;
        let key = self
            .streams
            .queue()
            .level(level)
            .iter()
            .copied()
            .find(|k| losing.contains(k))?;
        Some((level, key))
    }

    /// Whether a direction is bound to another pipe that is usable under
    /// the decision's gate (ledger tag [`Tag::Bound`]): it goes there and
    /// nowhere else until its own data is acknowledged.
    fn bound_elsewhere(&self, d: &Decision, key: StreamKey) -> bool {
        let Some(class) = d.gate.map(|g| g.class()) else {
            return false;
        };
        match self.ledger().and_then(|l| l.share(key)).map(|s| s.tag) {
            Some(Tag::Bound(p)) => p != d.id && self.att(p).is_some_and(|a| class.usable(a)),
            _ => false,
        }
    }

    /// Re-sends lost stream data or a lost FIN (MULTIPATH.md Section 7.4).
    /// The frame at offset 0 carries the whole preamble.
    fn write_lost_frame(&mut self, key: StreamKey, w: &mut Records<'_>) -> Step {
        let Some(send) = self.streams.send(key) else {
            return Step::Done;
        };
        let final_off = send.offset;
        let (start, end) = match send.mp().lost.first() {
            Some((a, b)) if a < send.base => (0, b.max(send.base)),
            Some(r) => r,
            None => (final_off, final_off),
        };
        let fin_ok = send.mp().fin_lost && send.fin_sent && send.cold().reset.is_none();
        let room = self.reinject_room(self.tx);
        if start < send.base && room < send.base {
            // The frame at offset 0 carries the whole preamble, more than
            // the reinjection hold leaves: the hold is used up for now, and
            // new data goes on.
            let chunk = self.config.spread_chunk as u64;
            if let Some(o) = self.out_mut(self.tx) {
                o.exhaust_reinject_hold(chunk);
            }
            return Step::Budget;
        }
        let end = end.min(start.saturating_add(room));
        let Ok((n, fin)) = self.write_copy(key, start, end, fin_ok, w) else {
            return Step::Full;
        };
        self.batch_stream_bytes += n;
        self.note_lane_frame(key);
        if let Some(o) = self.out_mut(self.tx) {
            o.reinjected(n);
        }
        let send = self.stream_mut(key).send.as_mut().expect("present");
        // Bytes no longer held (acknowledged meanwhile, or dropped by a
        // reset) are not owed any more.
        let done = if n == 0 && !fin { end } else { start + n };
        send.mp_mut().lost.remove(start, done);
        // A reset replaces the FIN: it is not owed again.
        if fin || send.cold().reset.is_some() {
            send.mp_mut().fin_lost = false;
        }
        let more = send.has_pending();
        self.stats.bytes_reinjected += n;
        if more {
            Step::More { rotate: false }
        } else {
            Step::Done
        }
    }

    /// Writes a STREAM frame with a copy of the sent bytes from `start`, at
    /// most up to `end`, and the FIN when `fin_ok` and the copy reaches the
    /// final size; logs it for the pipe. The frame at offset 0 carries the
    /// whole preamble. Returns the bytes copied and whether the FIN went.
    pub(super) fn write_copy(
        &mut self,
        key: StreamKey,
        start: u64,
        end: u64,
        fin_ok: bool,
        w: &mut Records<'_>,
    ) -> Result<(u64, bool), Full> {
        let Some(s) = self.streams.get(key) else {
            return Ok((0, false));
        };
        let (Some(id), Some(send)) = (s.id, s.send.as_ref()) else {
            return Ok((0, false));
        };
        let base = send.base;
        let final_off = send.offset;
        // Only bytes still held are ever copied: what was released (an
        // acknowledged range, or data dropped by a reset) is never sent
        // again.
        let held_end = send.mp().buf_floor + send.buf.kept();
        let end = if start < base {
            if send.preamble.is_none() {
                start
            } else if send.mp().buf_floor > base {
                end.min(base)
            } else {
                end.min(held_end.max(base))
            }
        } else if start < send.mp().buf_floor {
            start
        } else {
            end.min(held_end)
        };
        if end <= start && !(fin_ok && start == final_off) {
            return Ok((0, false));
        }
        let min = if start == 0 && base > 0 {
            (base as usize).min(w.max_data())
        } else {
            1.min((end - start) as usize)
        };
        let want = (end - start) as usize;
        if self.pace_left == Some(0) && want > 0 {
            // The carrier queue limiter's room,
            // which lets whole frames go.
            return Err(Full);
        }
        let Some(room) = w
            .stream_room(MAX_STREAM_HEADER + min, MAX_STREAM_HEADER + want)
            .filter(|&r| r >= min)
        else {
            return Err(Full);
        };
        let n = want.min(room) as u64;
        if let Some(left) = &mut self.pace_left {
            *left = left.saturating_sub(n);
        }
        let fin = fin_ok && start + n == final_off;
        let header = StreamHeader {
            stream_id: id,
            offset: start,
            len: n,
            fin,
            explicit_offset: false,
            explicit_len: true,
        };
        w.stream_header(&header);
        let send = self.stream_mut(key).send.as_mut().expect("present");
        let mut at = start;
        let stop = start + n;
        if at < base {
            if let Some(p) = &send.preamble {
                let k = (base.min(stop) - at) as usize;
                w.out.push_bytes(&p[at as usize..at as usize + k]);
            }
            at = base.min(stop);
        }
        if at < stop {
            send.mp_mut().resent += stop - at;
            let off = at - send.mp().buf_floor;
            let len = (stop - at) as usize;
            if let Some(b) = send
                .buf
                .shared_kept(off, len)
                .filter(|_| len >= COPY_THRESHOLD)
            {
                w.out.push_shared(b);
            } else {
                // Held, as checked above.
                let buf = &send.buf;
                w.out.push_with(len, |dst| {
                    let held = buf.copy_kept(off, dst);
                    debug_assert!(held, "copy of bytes not held");
                    dst.len()
                });
            }
        }
        self.log(
            w,
            pipes::SentFrame::Stream {
                key,
                off: start,
                len: n,
                fin,
            },
        );
        self.note_activity(w);
        Ok((n, fin))
    }

    /// Writes the queued frames that need no session credit (a FIN without
    /// data), in a multipath session those that go on the decision's pipe.
    /// Returns `false` when the batch filled up first.
    fn write_credit_free(&mut self, w: &mut Records<'_>, d: Option<&Decision>) -> bool {
        let preamble = self.features.preamble;
        for u in 0..8 {
            let mut i = 0;
            while i < self.streams.queue().level(u).len() {
                let key = self.streams.queue().level(u)[i];
                let free = self.streams.get(key).is_some_and(|s| {
                    (s.id.is_some() || !preamble)
                        && s.send
                            .as_ref()
                            .is_some_and(|x| x.buf.is_empty() && x.preamble_left == 0)
                }) && d.is_none_or(|d| self.stream_on_pipe(d, key));
                if !free {
                    i += 1;
                    continue;
                }
                let tx = self.tx;
                let gate = d.and_then(|d| d.gate.as_ref());
                match self.write_stream_frame(tx, key, gate, w) {
                    Step::Done => {
                        self.streams.dequeue_at(u, i);
                        self.after_stream_frame(key);
                    }
                    Step::Full => return false,
                    _ => i += 1,
                }
            }
        }
        true
    }

    /// Writes one STREAM frame of new data for a stream (on pipe `pipe` in
    /// a multipath session).
    fn write_stream_frame(
        &mut self,
        pipe: u64,
        key: StreamKey,
        gate: Option<&super::tier::Gate>,
        w: &mut Records<'_>,
    ) -> Step {
        let Some(s) = self.streams.get(key) else {
            return Step::Done;
        };
        if s.goaway.is_some() {
            return Step::Done;
        }
        if s.id.is_none() {
            let d = di(s.dir);
            if self.streams.local_dir(d).goaway.is_some() {
                // After a GOAWAY no stream emits its first frame
                // (EXTENSIONS.md Section 3.5 rule 2).
                self.reject_unopened(key, stream::GoAwayFail::GoingAway);
                return Step::Done;
            }
            if !self.streams.pinned(d).is_empty() {
                // The pinned streams of this type open first; the last
                // opening schedules this stream again.
                return Step::Blocked;
            }
            let ld = self.streams.local_dir(d);
            if ld.next_index >= ld.peer_max {
                // Opened before establishment beyond the peer's limit:
                // MAX_STREAMS schedules it again.
                self.streams.report_streams_blocked(d);
                return Step::Blocked;
            }
            let need = MAX_STREAM_HEADER + self.preamble_len(key);
            if w.stream_room(need, need)
                .is_none_or(|r| r < need - MAX_STREAM_HEADER)
            {
                return Step::Full;
            }
            // The identifier goes with the first frame (SPEC.md Section
            // 7.2): not assigned while the limiter holds back the bytes
            // that frame would carry.
            if self.pace_left == Some(0) && self.opening_paced(key) {
                return Step::Full;
            }
            self.assign_id(key);
        }
        let session_room = self.streams.send_flow().room();
        let mp = self.mp.is_some();
        // Sent bytes stay held for a retransmission, or while carrier early
        // data may still be rejected (SPEC.md Section 6.1.2).
        let retain = mp || self.early_retains();
        // Multipath: the retransmit budget, one chunk per
        // decision for every policy but `affinity` (spreading, overflow
        // and the custom policy decide chunk by chunk).
        let mut cap = u64::MAX;
        // The carrier queue limiter's room: it
        // holds back stream bytes only, never a control frame owed instead
        // (a reset, a credit limit to report), so it is checked below. It
        // lets whole frames go and never cuts one: the bucket pays for the
        // overrun before the pipe is let go again, where a cut would leave
        // a fragment to wait for the stream's next turn.
        let paced_out = self.pace_left == Some(0);
        if mp {
            let budget = self.retransmit_budget();
            let retained = self.mp().retained();
            let fin_only = self.fin_only(key);
            if retained >= budget && !fin_only {
                return Step::Budget;
            }
            cap = cap.min(budget.saturating_sub(retained));
            // Redundant frames are chunks under every policy: each is
            // copied whole to the other pipe of the pair.
            if !matches!(self.policy_for(key), super::Policy::Affinity)
                || self
                    .streams
                    .send(key)
                    .is_some_and(|send| self.redundant(send))
            {
                cap = cap.min(self.config.spread_chunk as u64);
            }
            // Rule S1: a JOINING pipe takes new data only while no pipe is
            // usable (a decision without a tier gate).
            if self.out_ref(pipe).is_some_and(|o| {
                o.state() == pipes::OutState::Joining && (gate.is_some() || !o.joining_takes())
            }) {
                return Step::Budget;
            }
        }
        // The stream and the session's chunk pool are borrowed together.
        let (s, chunks) = self.streams.stream_and_chunks(key).expect("stream present");
        let id = s.id.expect("identifier assigned");
        let Some(send) = s.send.as_mut() else {
            return Step::Done;
        };
        // Data of urgency 0 to 2 or of a small direction is an exchange.
        let exchange = send.queued.is_some_and(|u| u <= 2) || !send.waits.holding;
        let reliable = send.reset_reliable();
        if send.cold().reset.is_some() && reliable.is_none_or(|r| send.offset >= r) {
            // Only the reset is owed.
            self.streams.queue_ctrl(key);
            return Step::Done;
        }
        let mut available = send.preamble_left as u64 + send.buf.len();
        if let Some(r) = reliable {
            available = available.min(r - send.offset);
        }
        let stream_room = send.max_data.saturating_sub(send.offset);
        let credit = available.min(stream_room).min(session_room);
        let credit = if credit as usize >= send.preamble_left {
            credit.min(cap.max(send.preamble_left as u64))
        } else {
            credit
        };
        let fin_owed = send.fin && !send.fin_sent && send.cold().reset.is_none();
        if available == 0 && !fin_owed {
            if !send.has_pending() {
                // Nothing is owed any more (reinjected information was
                // acknowledged meanwhile): the direction leaves the queue
                // rather than end the batch for the others.
                return Step::Done;
            }
            // Only reinjected information is owed, which goes elsewhere or
            // later: nothing new here, and no credit is short. With none
            // owed either (a copy elsewhere was acknowledged meanwhile),
            // nothing is left to schedule.
            return if send.has_lost() {
                Step::Budget
            } else {
                Step::Done
            };
        }
        if credit == 0 && !(fin_owed && available == 0) {
            if stream_room == 0 {
                if send.blocked_reported != Some(send.max_data) {
                    send.blocked_at = Some(send.max_data);
                    self.streams.queue_ctrl(key);
                }
                return Step::Blocked;
            }
            return Step::SessionBlocked;
        }
        let pre = send.preamble_left;
        if (credit as usize) < pre {
            // The preamble goes whole into the frame at offset 0; report
            // the limit that holds it back (SPEC.md Section 8.4).
            if stream_room < pre as u64 {
                if send.blocked_reported != Some(send.max_data) {
                    send.blocked_at = Some(send.max_data);
                    self.streams.queue_ctrl(key);
                }
                return Step::Blocked;
            }
            return Step::SessionBlocked;
        }
        if paced_out && credit > 0 {
            // Stream bytes to send, and no room for them now.
            return Step::Full;
        }
        if send.offset == 0
            && let Some(m) = send.mp_in(mp)
            && m.open_pipe.is_none()
        {
            m.open_pipe = Some(pipe);
        }
        // At least the whole preamble, and no tiny fragment when a larger
        // one fits in the next record; never more than a record holds.
        let min = pre.max((credit.min(MIN_FRAGMENT as u64) as usize).min(w.max_data()));
        let Some(room) = w
            .stream_room(MAX_STREAM_HEADER + min, MAX_STREAM_HEADER + credit as usize)
            .filter(|&r| r >= min)
        else {
            return Step::Full;
        };
        let n = credit.min(room as u64);
        if let Some(left) = &mut self.pace_left {
            *left = left.saturating_sub(n);
        }
        let fin = fin_owed && n == available;
        let header = StreamHeader {
            stream_id: id,
            offset: send.offset,
            len: n,
            fin,
            explicit_offset: false,
            explicit_len: true,
        };
        w.stream_header(&header);
        w.exchange |= exchange;
        let mut left = n as usize;
        if pre > 0 {
            if let Some(p) = &send.preamble {
                let start = p.len() - pre;
                w.out.push_bytes(&p[start..]);
            }
            send.preamble_left = 0;
            left -= pre;
        }
        let app = left as u64;
        while left > 0 {
            let run = send.buf.front_len().min(left);
            if run >= COPY_THRESHOLD {
                let chunk = send.buf.take_shared(run, retain, chunks);
                left -= chunk.len();
                w.out.push_shared(chunk);
            } else {
                let buf = &mut send.buf;
                w.out.push_with(run, |dst| buf.copy_to(dst, retain, chunks));
                left -= run;
            }
        }
        let off = send.offset;
        send.offset += n;
        send.deficit -= n as i64;
        let lanes = self.tx_lanes;
        if send.state == SendState::Ready {
            send.state = SendState::Send;
        }
        if fin {
            send.fin_sent = true;
            // Outside multipath a written FIN is acknowledged (SPEC.md 7.4);
            // in a multipath session a PIPE_ACK must cover it.
            send.state = if retain {
                SendState::DataSent
            } else {
                SendState::DataRecvd
            };
        }
        if lanes {
            self.note_lane_frame(key);
        }
        if mp {
            self.batch_stream_bytes += n;
            self.mp_mut().retain(n);
            self.log_new_data(w, key, off, n, fin);
            self.note_activity(w);
            self.bind_on_send(pipe, key, n);
            self.copy_chunk(pipe, key, (off, n, fin), gate);
            self.mp_mut().batch_mut().new_data = true;
            if matches!(
                self.policy_for(key),
                super::Policy::SpreadRoundRobin | super::Policy::SpreadRateWeighted
            ) && let Some(g) = gate
            {
                self.round_robin_commit(pipe, key, g);
            }
        }
        let s = self.stream_mut(key);
        let send = s.send.as_mut().expect("sending part");
        let more = send.has_pending();
        let blocked = send.credit_blocked();
        let incremental = send.priority.incremental();
        if !more && send.priority.urgency() <= 2 {
            // An urgent write ends its record, so the receiver, which
            // decodes whole records, does not wait for the bulk data
            // behind it (SPEC.md Section 3.3).
            w.end_record();
        }
        // The quantum is used up, up to less than a small fragment that
        // would not finish the stream's data: the remainder carries over
        // instead of a tiny frame of its own.
        let left = send.buf.len() as i64;
        let rotate =
            send.deficit <= 0 || (send.deficit < MIN_FRAGMENT as i64 && left > send.deficit);
        if rotate {
            send.deficit += QUANTUM;
        }
        let reset_owed = send.cold().reset.is_some_and(|r| !r.written);
        self.streams.sent(n, app);
        if app > 0 {
            self.after_send_progress(key);
        }
        if reset_owed && !more {
            self.streams.queue_ctrl(key);
        }
        if !more {
            Step::Done
        } else if blocked {
            let send = self.stream_mut(key).send.as_mut().expect("sending part");
            if send.blocked_reported != Some(send.max_data) {
                send.blocked_at = Some(send.max_data);
                self.streams.queue_ctrl(key);
            }
            Step::Blocked
        } else {
            Step::More {
                rotate: rotate && incremental,
            }
        }
    }

    /// A local stream that never sent a frame fails after the peer's
    /// GOAWAY: it never opens (EXTENSIONS.md Section 3.5).
    pub(super) fn reject_unopened(&mut self, key: StreamKey, why: stream::GoAwayFail) {
        let s = self.stream_mut(key);
        s.goaway = Some(why);
        let mut unsent = 0;
        if let Some(send) = s.send.as_mut() {
            unsent = send.buf.len();
            send.buf.clear();
            send.state = SendState::ResetRecvd;
        }
        if let Some(r) = s.recv.as_mut() {
            r.state = RecvState::ResetRead;
        }
        self.streams.drop_unsent(unsent);
        self.streams.settle_local_recv(key);
        self.wake_send_waiters();
        self.notify_writable(key);
        self.notify_readable(key);
    }

    /// Whether the first frame of unopened stream `key` would carry bytes
    /// that the carrier queue limiter paces: not when only its reset is
    /// owed, or when a credit limit holds back what it would carry (both
    /// go out as control frames, which are never held back).
    fn opening_paced(&self, key: StreamKey) -> bool {
        let Some(send) = self.streams.send(key) else {
            return false;
        };
        let reliable = send.reset_reliable();
        if send.cold().reset.is_some() && reliable.is_none_or(|r| send.offset >= r) {
            return false;
        }
        let pre = self.preamble_len(key) as u64;
        let mut available = pre + send.buf.len();
        if let Some(r) = reliable {
            available = available.min(r - send.offset);
        }
        let session_room = self.streams.send_flow().room();
        let credit = available
            .min(send.max_data.saturating_sub(send.offset))
            .min(session_room);
        available > 0 && credit > 0 && credit >= pre
    }

    /// The preamble length a local stream will send (0 without the
    /// preamble feature).
    fn preamble_len(&self, key: StreamKey) -> usize {
        if !self.features.preamble {
            return 0;
        }
        let Some(s) = self.streams.get(key) else {
            return 0;
        };
        let grease = (!self.grease_tlv_used).then(|| self.grease_tlv());
        let g = grease
            .as_ref()
            .map(|(ty, v)| GreaseTlv { ty: *ty, value: v });
        WirePreamble {
            open_info: s.extra().open_info.as_deref(),
            priority: s.extra().peer_priority,
            pipe_carrier: s.extra().pipe_carrier,
            app_tlvs: AppTlvs::new(s.extra().app_tlvs.as_deref().unwrap_or_default()),
        }
        .encoded_len(g)
    }

    /// Allocates the next identifier of a local stream's type and builds
    /// its preamble (SPEC.md Section 7.2, EXTENSIONS.md Section 4).
    pub(super) fn assign_id(&mut self, key: StreamKey) {
        let client = matches!(self.role, Role::Initiator);
        let mp = self.mp.is_some();
        let preamble = self.features.preamble;
        let grease = (preamble && !self.grease_tlv_used).then(|| self.grease_tlv());
        let Some(s) = self.streams.assign_id(key, client) else {
            return;
        };
        if preamble && let (Some(send), extra) = s.send_and_extra() {
            let g = grease
                .as_ref()
                .map(|(ty, v)| GreaseTlv { ty: *ty, value: v });
            let p = WirePreamble {
                open_info: extra.open_info.as_deref(),
                priority: extra.peer_priority,
                pipe_carrier: extra.pipe_carrier,
                app_tlvs: AppTlvs::new(extra.app_tlvs.as_deref().unwrap_or_default()),
            };
            let mut buf = [0u8; 64];
            let bytes = match p.encoded_len(g) {
                len if len <= buf.len() => {
                    let n = p.encode(g, &mut buf[..len]).unwrap_or(0);
                    match &buf[..n] {
                        // The empty preamble, the common case.
                        [0] => Bytes::from_static(&[0]),
                        b => Bytes::copy_from_slice(b),
                    }
                }
                len => {
                    let mut v = vec![0u8; len];
                    let n = p.encode(g, &mut v).unwrap_or(0);
                    v.truncate(n);
                    Bytes::from(v)
                }
            };
            let n = bytes.len();
            send.base = n as u64;
            if let Some(m) = send.mp_in(mp) {
                m.buf_floor = n as u64;
            }
            send.preamble_left = n;
            send.preamble = Some(bytes);
            if grease.is_some() {
                self.grease_tlv_used = true;
            }
        }
        // Control state set before the identifier existed (a receive
        // window, STOP_SENDING, PRIORITY_UPDATE) goes out now.
        self.streams.queue_ctrl(key);
    }

    /// The GREASE TLV of the session's first preamble: the test hook's, or
    /// a random one (EXTENSIONS.md Section 4.3).
    fn grease_tlv(&self) -> (u64, Vec<u8>) {
        if let Some(g) = &self.config.hooks.grease_tlv {
            return g.clone();
        }
        let r = super::random_u64();
        let ty = crate::proto::payload::grease_tlv_type(r % 1024).unwrap_or(0x21);
        let len = ((r >> 10) % 9) as usize;
        (ty, (0..len).map(|i| (r >> (16 + 5 * i)) as u8).collect())
    }

    /// Data left a stream's send buffer: wake writers that have room again.
    ///
    /// A capacity wait may be over now: it is also over with any capacity
    /// once nothing is unsent, and sending changes no
    /// credit, so no MAX_DATA or MAX_STREAM_DATA would end it.
    pub(super) fn after_send_progress(&mut self, key: StreamKey) {
        let mut sent = false;
        if let Some(send) = self.streams.send_mut(key) {
            send.pop_marks();
            sent = send.sent_waiting && send.buf.is_empty();
            send.sent_waiting &= !sent;
        }
        self.sync_holder(key);
        self.wake_send_waiters();
        self.check_capacity_wait(key);
        if sent {
            self.notify_writable(key);
        }
    }

    fn after_stream_frame(&mut self, key: StreamKey) {
        let finished = self
            .streams
            .send(key)
            .is_some_and(|s| s.state == SendState::DataRecvd);
        if finished {
            self.notify_writable(key);
        }
        // Finished, or rejected by a GOAWAY before its first frame.
        self.try_discard(key);
    }

    // ---- discarding -------------------------------------------------------------

    /// Discards a stream once both parts are terminal, its control frames
    /// are out, and the application released it or the stack rejected it
    /// (SPEC.md Section 7.6). A peer stream returns its credit (Section
    /// 8.5).
    pub(super) fn try_discard(&mut self, key: StreamKey) {
        if self.early_retains() {
            // Carrier early data may still be rejected and sent again.
            return;
        }
        self.streams.settle_local_recv(key);
        let Some(s) = self.streams.get(key) else {
            return;
        };
        if !s.parts_terminal() || !(s.released || s.offer == Offer::Rejected) || s.ctrl_queued {
            return;
        }
        if s.send.as_ref().is_some_and(|x| x.queued.is_some()) {
            return;
        }
        let Some(s) = self.streams.remove(key) else {
            return;
        };
        if let Some(mp) = self.mp.as_deref_mut() {
            mp.picks_mut().forget(key);
            mp.blocked_mut().forget(key);
        }
        if let Some(r) = &s.recv
            && r.held() > 0
        {
            self.credit_consumed(r.held());
        }
        if let Some(owed) = s.recv.as_ref().map(stream::RecvPart::credit_owed)
            && owed > 0
        {
            // Bytes below a Reliable Size that never arrived would be
            // discarded on arrival (SPEC.md Section 8.3).
            self.credit_received(0, 0, owed);
        }
        if let Some(send) = &s.send
            && let Some(mp) = self.mp.as_deref_mut()
        {
            mp.release(send.unacked());
        }
        for (_, d) in s.datagrams.iter().flat_map(|d| &d.queue) {
            self.dgram_mut().recv_bytes -= d.len();
        }
        if !s.local {
            self.stream_count_credit(di(s.dir));
        }
        self.streams.recycle(s);
        let now = self.now;
        self.check_shutdown_done(now);
    }
}

/// Builds records in a batch: frames go into records of at most
/// `max_record` bytes, and the batch stays within its limit.
pub(super) struct Records<'a> {
    pub(super) out: &'a mut TransmitBuf,
    max_record: usize,
    records: u64,
    /// A frame other than a QX_PING request (or PADDING) was written: the
    /// batch restarts the idle timer (SPEC.md Section 6.4).
    activity: bool,
    /// The record of the last ack-eliciting frame written (SPEC.md
    /// Section 1.4), by its index in the batch: the bytes in flight end
    /// with it.
    eliciting: Option<u64>,
    /// A frame that goes ahead of bulk data was written, other than an
    /// acknowledgement or credit.
    pub(super) exchange: bool,
    /// A traffic frame was written: STREAM, RESET_STREAM,
    /// RESET_STREAM_AT, STOP_SENDING or DATAGRAM (MULTIPATH.md Section
    /// 7.1, the busy window).
    traffic: bool,
    /// A QX_PING was written: with `traffic`, the activity a PIPE_ACK
    /// confirms in a session with acknowledgement (SPEC.md Section 6.4).
    ping: bool,
}

impl<'a> Records<'a> {
    pub(super) fn new(out: &'a mut TransmitBuf, max_record: usize) -> Self {
        Self {
            out,
            max_record,
            records: 0,
            activity: false,
            eliciting: None,
            exchange: false,
            traffic: false,
            ping: false,
        }
    }

    /// The largest record of the batch.
    pub(super) fn max_record(&self) -> usize {
        self.max_record
    }

    /// The index in the batch of the record being built.
    pub(super) fn record_index(&self) -> u32 {
        self.records as u32
    }

    /// The frame just written to the open record elicits an
    /// acknowledgement (raw frames written directly mark it themselves).
    pub(super) fn elicit(&mut self) {
        self.eliciting = Some(self.records);
    }

    /// Where the last ack-eliciting byte of the batch ends, in the batch's
    /// byte stream, once its records are closed.
    fn eliciting_end(&self) -> Option<u64> {
        let i = usize::try_from(self.eliciting?).ok()?;
        Some(
            self.out
                .record_ends()
                .get(i)
                .copied()
                .unwrap_or_else(|| self.out.stream_len()),
        )
    }

    fn size_width(&self) -> usize {
        self.out.size_width(self.max_record)
    }

    /// The most STREAM data one record holds.
    fn max_data(&self) -> usize {
        self.max_record - MAX_STREAM_HEADER
    }

    /// Ends the open record, if any; the next frame starts a new one.
    pub(super) fn end_record(&mut self) {
        if self.out.end_record() {
            self.records += 1;
        }
    }

    /// Makes room for `n` frame bytes in one record, closing the open one
    /// if they do not fit. `false` when the batch is full.
    pub(super) fn ensure(&mut self, n: usize) -> bool {
        if n > self.max_record {
            return false;
        }
        if self.out.in_record() {
            if self.out.record_len() + n <= self.max_record && self.out.room() >= n {
                return true;
            }
            self.end_record();
        }
        if self.out.room() < self.size_width() + n {
            return false;
        }
        self.out.begin_record(self.max_record);
        true
    }

    /// Opens a record of its own for one frame of `n` bytes, more than
    /// the batch's record size (a large datagram, EXTENSIONS.md Section
    /// 6.6): the record may exceed the write-call bound by what the frame
    /// needs. `false` when the batch already holds records and has no
    /// room left for it.
    fn own_record(&mut self, n: usize) -> bool {
        self.end_record();
        if !self.out.is_empty() && self.out.room() < self.out.size_width(n) + n {
            return false;
        }
        self.out.begin_record(n);
        true
    }

    /// Like [`Records::ensure`], but always opens room: the first frame and
    /// CONNECTION_CLOSE go out even beyond the batch limit.
    pub(super) fn force(&mut self, n: usize) {
        self.activity = true;
        if !self.ensure(n) {
            self.end_record();
            self.out.begin_record(self.max_record.max(n));
        }
        self.elicit();
    }

    pub(super) fn try_frame(&mut self, f: &Frame<'_>) -> bool {
        if !self.ensure(f.encoded_len()) {
            return false;
        }
        let _ = self.out.push_frame(f);
        if matches!(f, Frame::QxPing(_)) {
            self.ping = true;
        }
        if !matches!(
            f,
            Frame::QxPing(QxPing {
                response: false,
                ..
            }) | Frame::Padding(_)
        ) {
            self.activity = true;
        }
        if !matches!(
            f,
            Frame::Padding(_) | Frame::PipeAck(_) | Frame::ConnectionClose(_)
        ) {
            self.elicit();
        }
        if !matches!(
            f,
            Frame::Padding(_)
                | Frame::PipeAck(_)
                | Frame::MaxData(_)
                | Frame::MaxStreamData(_)
                | Frame::MaxStreams(_)
                | Frame::DataBlocked(_)
                | Frame::StreamDataBlocked(_)
                | Frame::StreamsBlocked(_)
        ) {
            self.exchange = true;
        }
        if matches!(
            f,
            Frame::Stream(_)
                | Frame::ResetStream(_)
                | Frame::ResetStreamAt(_)
                | Frame::StopSending(_)
                | Frame::Datagram(_)
        ) {
            self.traffic = true;
        }
        true
    }

    /// Data room for a STREAM frame. The frame stays in the open record
    /// when at least `min` bytes (header included) fit there, or `want`
    /// bytes do; otherwise it starts a new record. Returns the data bytes
    /// that fit after a header of [`MAX_STREAM_HEADER`] bytes; `None` when
    /// the batch is full and no record is open.
    fn stream_room(&mut self, min: usize, want: usize) -> Option<usize> {
        if self.out.in_record() {
            let left = (self.max_record - self.out.record_len()).min(self.out.room());
            if left >= min.max(want.min(MAX_STREAM_HEADER + MIN_FRAGMENT)) {
                return Some(left - MAX_STREAM_HEADER);
            }
            self.end_record();
        }
        let room = self.out.room().saturating_sub(self.size_width());
        let fits = room.min(self.max_record);
        if fits < min {
            // The batch is full: no record is open, so nothing may be
            // written (even a frame without data, such as a lone FIN).
            return None;
        }
        self.out.begin_record(self.max_record);
        Some(fits - MAX_STREAM_HEADER)
    }

    fn stream_header(&mut self, h: &StreamHeader) {
        self.activity = true;
        self.traffic = true;
        self.elicit();
        let n = h.encoded_len();
        self.out.push_with(n, |dst| h.encode(dst).unwrap_or(0));
    }

    /// A datagram or stream payload: copied when small, referenced
    /// otherwise.
    fn payload(&mut self, b: Bytes) {
        if b.len() < COPY_THRESHOLD {
            self.out.push_bytes(&b);
        } else {
            self.out.push_shared(b);
        }
    }

    /// Closes the open record; returns the number of records written.
    pub(super) fn finish(mut self) -> u64 {
        self.end_record();
        self.records
    }
}
