//! The path layer: where a session on one pipe and a multipath session
//! differ in what they keep and measure. Callers ask the layer and get the
//! value of the session's mode (or nothing, for state only multipath
//! keeps); they do not branch on the mode themselves.
//!
//! Mode checks that stay where they are: the protocol's rules that differ
//! by mode (frames of the multipath layer are a violation outside it,
//! duplicates and stale frames go uncharged in it, a single pipe's STREAM
//! data arrives in order, a stale QX_PING is ignored there), and the
//! multipath module's own entry points.

pub(super) mod ack;
pub(super) mod ledger;
pub(super) mod mpath;
pub(super) mod opp;
pub(super) mod redundancy;
pub(super) mod resume;
pub(super) mod sched;
pub(super) mod tier;

use super::output::{BatchLog, LanePick, Records, SinglePick};
use super::rtt::{MP_WRITE_CALL_MIN, MP_WRITE_CALL_SPAN, PROBE_INTERVAL, WRITE_CALL_MAX};
use super::sched::Picks;
use super::stream::Offer;
use super::streams::SendBuffer;
use super::tier::Gate;
#[allow(clippy::wildcard_imports)]
use super::*;
use crate::proto::payload::Flow;
use crate::proto::varint;

impl SessionCore {
    /// A session with acknowledgement: multipath or pipe acknowledgement
    /// in use, as between zmux endpoints always (SPEC.md Section 6.4).
    pub(super) fn acknowledged(&self) -> bool {
        self.mp.is_some() || self.pipe_ack.is_some()
    }

    /// The bytes sent and kept until a PIPE_ACK covers them (multipath
    /// only: a single pipe drops what it sent).
    pub(super) fn retained(&self) -> u64 {
        self.mp.as_deref().map_or(0, super::mpath::Mp::retained)
    }

    /// The log of the batch being built, which multipath keeps for its
    /// acknowledgements and reinjection.
    pub(super) fn batch_log(&mut self) -> Option<&mut BatchLog> {
        self.mp.as_deref_mut().map(super::mpath::Mp::batch_mut)
    }

    /// The scheduler's outstanding picks (multipath only).
    pub(super) fn picks(&mut self) -> Option<&mut Picks> {
        self.mp.as_deref_mut().map(super::mpath::Mp::picks_mut)
    }

    /// The tier gate now, in a multipath session.
    pub(super) fn path_gate(&self) -> Option<Gate> {
        self.mp.as_ref().and_then(|_| self.gate())
    }

    /// The minimum RTT that bounds pipe `id`'s work: the pipe's in a
    /// multipath session, else the session's (the carrier's own, or the
    /// credit loop's).
    pub(super) fn rtt_min(&self, id: u64) -> Option<Duration> {
        if self.mp.is_some() {
            self.pipe_min_rtt(id)
        } else {
            self.session_rtt_min()
        }
    }

    /// The single pipe's minimum RTT: the carrier's own, else the credit
    /// loop's.
    pub(super) fn session_rtt_min(&self) -> Option<Duration> {
        self.carrier_rtt.or(self.loop_min.get())
    }

    /// The sending rate of a pipe in bytes per second: its delivery-rate
    /// estimate in a multipath session, else the rate the session hands
    /// bytes to its carrier; 0 before the first measurement.
    pub(super) fn pipe_send_rate(&self, pipe: super::PipeId) -> u64 {
        if self.mp.is_some() {
            self.out_ref(pipe.0).map_or(0, |o| o.est().rate)
        } else {
            self.send_rate.get().unwrap_or(0)
        }
    }
}

// The forks between the two modes' handling of the same event.
impl SessionCore {
    /// A direction's sent bytes were dropped: those it retained no longer
    /// count.
    pub(super) fn release_retained(&mut self, n: u64) {
        if let Some(mp) = self.mp.as_deref_mut() {
            mp.release(n);
        }
    }

    /// The session's RTT estimate changed: on a single pipe, that pipe's
    /// quality (a multipath pipe samples its own).
    pub(super) fn session_rtt_sampled(&mut self, now: Instant) {
        if self.mp.is_none() {
            self.quality_sample(0, now);
        }
    }

    /// The next deadline of the mode's own timers.
    pub(super) fn path_deadline(&self) -> Option<Instant> {
        if self.mp.is_some() {
            self.mp_deadline()
        } else {
            self.single_pipe_ack_timer()
        }
    }

    /// Fires the mode's own timers that are due (a single pipe's are
    /// fired with the session's).
    pub(super) fn path_timeout(&mut self, now: Instant) {
        if self.mp.is_some() {
            self.mp_timeout(now);
        }
    }

    /// Inbound pipe `pipe` ended (`end` of the carrier that ended last): at
    /// a record boundary of every lane (`clean`), or otherwise.
    pub(super) fn inbound_ended(&mut self, pipe: u64, end: PipeEnd, clean: bool, now: Instant) {
        if self.mp.is_some() {
            self.mp_inbound_ended(pipe, end, clean, now);
        } else {
            self.single_inbound_ended(pipe, end, clean, now);
        }
    }
}

impl SessionCore {
    /// Pipe-layer control frames are pending (PIPE_ABANDON, PIPE_STATUS).
    pub(super) fn mp_control_pending(&self) -> bool {
        self.mp.is_some()
            && self
                .atts
                .iter()
                .any(|a| a.abandon_owed(false) || (a.tier().status_owed() && !a.joining_local()))
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

    /// Owes a copy of a credit frame just written, when the window is the
    /// bottleneck: the latest value rides with the next redundant snapshot
    /// on the second pipe, due at most 50 ms later (MULTIPATH.md Section
    /// 6.5).
    pub(super) fn copy_credit(&mut self, kind: mpath::CreditCopy) {
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

    /// The pipe a stream datagram must follow (multipath): the pipe of the
    /// stream's opening frame while that is unacknowledged and the pipe is
    /// live (EXTENSIONS.md Section 6.4, MULTIPATH.md Section 11).
    pub(super) fn datagram_pipe(&self, flow: Option<(u64, u64)>) -> Option<u64> {
        self.mp.as_ref()?;
        let (stream_id, _) = flow?;
        let send = self.streams.send(self.streams.key_of(stream_id)?)?;
        let opened = send.mp().acked.contains(0, 1)
            || send.mp().buf_floor > 0
            || (send.base > 0 && send.mp().preamble_acked);
        let pipe = send.mp().open_pipe.filter(|_| !opened)?;
        self.out_ref(pipe).filter(|o| o.is_live()).map(|_| pipe)
    }

    pub(super) fn count_sent(&mut self, bytes: usize, records: u64) {
        self.stats.bytes_sent += bytes as u64;
        self.stats.records_sent += records;
        if self.mp.is_none() {
            let rtt = self.session_rtt_min();
            self.send_rate.update(self.now, self.stats.bytes_sent, rtt);
        }
    }
}

impl SessionCore {
    /// The pipe-view generation of a multipath session.
    pub(super) fn view_generation(&self) -> Option<u64> {
        self.mp.as_deref().map(|m| m.tiers().view_generation())
    }
}

impl SessionCore {
    /// The Session Nonces both endpoints sent in `zmux_multipath`
    /// (MULTIPATH.md Section 3.1), this endpoint's first, while multipath
    /// is in use.
    pub fn session_nonces(&self) -> Option<([u8; 16], [u8; 16])> {
        if !self.is_multipath() {
            return None;
        }
        let local = self.local_tp().multipath?;
        let peer = self.peer_tp.as_ref()?.multipath?;
        Some((local.session_nonce, peer.session_nonce))
    }

    /// The RTT estimate rules use: the smoothed RTT or 333 ms (SPEC.md
    /// Section 1.3). In a multipath session it is the largest smoothed RTT
    /// of the live outbound pipes.
    pub(super) fn rtt_or_default(&self) -> Duration {
        if self.mp.is_some()
            && let Some(r) = self
                .atts
                .outs()
                .filter(|o| o.is_live())
                .map(|o| o.est().srtt)
                .max()
        {
            return r;
        }
        self.srtt.unwrap_or(Duration::from_millis(333))
    }
}

impl SessionCore {
    /// The TCP_NOTSENT_LOWAT a pipe's carrier should use now: on a single pipe max(128 KiB, send
    /// rate x RTT_min / 8), in a multipath session max(32 KiB, R_p x
    /// RTT_min_p / 8) per pipe. Without an RTT_min the floor. The driver
    /// applies it at most every 20 ms and only when it changes by more than
    /// 25 %, never above the carrier's send buffer.
    pub fn notsent_lowat(&self, pipe: super::PipeId) -> u64 {
        const SINGLE: u64 = 128 * 1024;
        const MULTI: u64 = 32 * 1024;
        if self.mp.is_some() {
            let Some(o) = self.out_ref(pipe.0) else {
                return MULTI;
            };
            let Some(rtt) = o.min_rtt() else {
                return MULTI;
            };
            let term = (o.est().rate as f64 * rtt.as_secs_f64() / 8.0) as u64;
            return MULTI.max(term);
        }
        let Some(rtt) = self.session_rtt_min() else {
            return SINGLE;
        };
        let term = (self.send_rate.get().unwrap_or(0) as f64 * rtt.as_secs_f64() / 8.0) as u64;
        SINGLE.max(term)
    }

    /// Asks for a QX_PING sample when auto-tuning would grow a window but
    /// has no RTT: one at a time, at most once per [`PROBE_INTERVAL`].
    pub(super) fn probe_rtt(&mut self, now: Instant) {
        if self.mp.is_some()
            || self.state != State::Active
            || self.ping.outstanding.is_some()
            || self.ping.request_pending
            || self
                .last_rtt_probe
                .is_some_and(|t| now.saturating_duration_since(t) < PROBE_INTERVAL)
        {
            return;
        }
        self.last_rtt_probe = Some(now);
        self.ping.request_pending = true;
    }
}

impl SessionCore {
    /// The RTT input of auto-tuning for a scope (`key` a stream, `None` the
    /// session): on a single pipe the
    /// carrier's minimum RTT, else the credit-loop minimum (300 s, QX_PING
    /// samples included); in a multipath session the largest pipe_min_rtt
    /// of the pipes the scope's data arrived on in the last 4 intervals.
    pub(super) fn autotune_rtt(&self, key: Option<StreamKey>) -> Option<Duration> {
        if let Some(r) = self.config.hooks.rtt {
            return Some(r);
        }
        if self.mp.is_some() {
            return match key {
                Some(k) => self.streams.recv(k).and_then(|r| r.tuner.rtt_seen()),
                None => self.streams.recv_flow().tuner.rtt_seen(),
            };
        }
        self.session_rtt_min()
    }
}

impl SessionCore {
    /// The session send buffer in force: `send_buffer`, grown to the
    /// retransmit budget in a multipath session up to `send_buffer_max`.
    pub(super) fn session_send_buffer(&self) -> u64 {
        let b = self.config.send_buffer;
        if self.mp.is_none() {
            return b;
        }
        b.max(self.retransmit_budget())
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
        // A record whose plan sets a delay waits for it, and the pipe
        // sends nothing else meanwhile but CONNECTION_CLOSE.
        let delayed = self.shape.is_some() && self.shape_delayed(id);
        if self.state == State::Closing {
            // An orderly close that waits for the other lanes writes only
            // the PIPE_ACK due meanwhile.
            return !self.close_waiting()
                || !delayed && (o.leading_frames_owed() || self.single_pipe_ack_due(self.now));
        }
        if o.shutdown_pending() {
            // Drained, or failed: the write side is to be closed.
            return true;
        }
        if delayed {
            return false;
        }
        if o.leading_frames_owed() {
            return true;
        }
        if self.state == State::Establishing {
            // Early data under the floor (SPEC.md Section 6.1.2).
            return self.early_open() && id == 0 && (self.opening_ready() || self.data_pending());
        }
        if self.shape.is_some() && self.shape_wants(id) {
            return true;
        }
        let held = self.shape.is_some() && self.shape_held(id);
        if self.mp.is_none() {
            return self.control_pending()
                || !held && (self.opening_ready() || self.data_pending())
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
        !held && self.data_for_pipe(id)
            || (!o.limiter_held()
                && (self.copies_queued(id, 0) || self.opp_due(id, now, None).is_some()))
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

    /// Accounts a batch handed to pipe `id`: its position, the retained
    /// frames and the batch log (MULTIPATH.md Sections 6 and 7);
    /// `eliciting` is where its last ack-eliciting byte ends, if any.
    pub(super) fn after_batch(
        &mut self,
        id: u64,
        out: &TransmitBuf,
        eliciting: Option<u64>,
        now: Instant,
    ) {
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

    /// Writes queued datagrams that may go on pipe `pipe`: on the control
    /// pipe every datagram except the stream datagrams that follow their
    /// opening frame on another pipe; on another pipe only those that
    /// follow it there, and only while it may carry DATAGRAM (ACTIVE).
    /// Those that the pipe's datagram channel takes are left to
    /// [`SessionCore::poll_channel`] (EXTENSIONS.md Section 6.8).
    pub(super) fn write_datagrams(&mut self, pipe: u64, control: bool, w: &mut Records<'_>) {
        let send_queue = self.config.datagram_send_queue;
        let max_frame = self.max_datagram_frame().unwrap_or(0);
        let ch = control
            .then(|| self.channel_for(pipe, w.shape.is_some()))
            .flatten();
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
            let flow = self.flow_of(*flow);
            let prefix = flow.map_or(0, |f| f.encoded_len());
            let total = prefix + data.len();
            if follow.is_none()
                && ch.is_some_and(|c| {
                    crate::proto::frame::channel::datagram_len(c.id, total) <= c.max
                })
            {
                // The channel's task sends it.
                i += 1;
                continue;
            }
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
            let was_full = self.dgram().send.len() >= send_queue;
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
            self.datagram_sent(flow, len);
            if was_full {
                self.events.push_back(super::CoreEvent::DatagramsUnblocked);
            }
        }
    }

    /// Counts a datagram handed to a carrier, in a record or on a datagram
    /// channel: application bytes, and its stream's.
    pub(super) fn datagram_sent(&mut self, flow: Option<Flow>, len: u64) {
        self.stats.datagrams_sent += 1;
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
    }

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

    pub(super) fn write_stream_data(&mut self, pipe: u64, w: &mut Records<'_>) {
        if self.mp.is_some() {
            self.write_stream_data_mp(pipe, w);
            return;
        }
        if self.out_ref(pipe).is_some_and(|o| o.lanes().is_some()) {
            let lane = self.tx_lane;
            self.write_streams(
                pipe,
                &mut LanePick {
                    lane,
                    skipped: Vec::new(),
                },
                w,
            );
            return;
        }
        let offered = self.out_ref(pipe).is_some_and(OutPipe::lanes_offered);
        self.write_streams(pipe, &mut SinglePick { offered, passed: 0 }, w);
    }

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
        // A handle that outlives the stream keeps its final statistics.
        if let Some(slot) = s.final_stats.clone()
            && Arc::strong_count(&slot) > 1
            && let Some(st) = self.stream_stats(key)
        {
            let _ = slot.set(st);
        }
        let Some(s) = self.streams.remove(key) else {
            return;
        };
        if let Some(id) = s.id
            && (self.shape.is_some() || self.shape_pending.is_some())
        {
            self.shape_stream(super::shaping::EventKind::StreamEnd, id);
        }
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
        if let Some(send) = &s.send {
            self.release_retained(send.unacked());
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

impl SessionCore {
    /// A snapshot of the statistics.
    pub fn stats(&self) -> SessionStats {
        let mut s = self.stats.clone();
        let app = self.meter.get();
        s.bytes_written = app.bytes_written;
        s.bytes_read = app.bytes_read;
        s.datagram_bytes_sent = app.datagram_bytes_sent;
        s.datagram_bytes_received = app.datagram_bytes_received;
        s.no_effect_budget = self.budget.tokens();
        if let Some(mp) = self.mp.as_deref() {
            let (fallbacks, applied) = mp.picks().counts();
            s.scheduler_fallbacks += fallbacks;
            s.scheduler_answers += applied;
        }
        s.streams_active = self.streams.len() as u64;
        s.smoothed_rtt = self.srtt;
        s.send_buffered = self.streams.send_flow().buffered;
        s.recv_buffered = self.streams.recv_flow().buffered;
        if self.mp.is_none() {
            // Those of pipe 0.
            let r = self.rtt_of(self.out_ref(0));
            s.smoothed_rtt = r.srtt;
            s.min_rtt = r.min;
            s.latest_rtt = r.latest;
            s.mean_deviation = r.rttvar;
        }
        if let Some(mp) = self.mp.as_deref() {
            s.retained = mp.retained();
            s.pipes_active = self
                .atts
                .outs()
                .filter(|o| o.state() == OutState::Active)
                .count() as u64;
            // The primary pipe's estimates (MULTIPATH.md Section 6.5).
            let primary = mp
                .acks()
                .primary()
                .and_then(|p| self.out_ref(p))
                .or_else(|| self.atts.outs().next());
            if let Some(est) = primary.map(OutPipe::est).filter(|e| e.sampled) {
                s.smoothed_rtt = Some(est.srtt);
                s.min_rtt = est.min_rtt.get();
                s.latest_rtt = est.latest;
                s.mean_deviation = Some(est.rttvar);
            }
            if let Some(t) = mp.suspension().since() {
                s.suspended_time += self.now.saturating_duration_since(t);
            }
        }
        s
    }

    /// Data bytes the session holds: unread received data (reassembly
    /// included), written data not yet sent, retained unacknowledged data
    /// and queued datagrams (the listener's memory budget).
    pub fn held_bytes(&self) -> u64 {
        // Sent bytes held for reinjection, the acknowledged ones behind a
        // gap included.
        let kept: u64 = if self.mp.is_some() {
            self.streams
                .keys()
                .filter_map(|k| self.streams.get(k)?.send.as_ref())
                .map(|s| s.buf.kept())
                .sum()
        } else {
            0
        };
        self.streams.recv_flow().buffered
            + self.streams.send_flow().buffered
            + kept
            + (self.dgram().recv_bytes + self.dgram().held_bytes) as u64
    }

    /// Heap and inline bytes the core holds, for memory accounting.
    pub fn memory_usage(&self) -> usize {
        // The configuration counts in equal parts for the sessions that
        // share it.
        let config =
            (size_of::<Config>() + 2 * size_of::<usize>()) / Arc::strong_count(&self.config);
        let mut n = size_of::<Self>() + config + self.streams.heap_bytes();
        n += self.events.capacity() * size_of::<CoreEvent>();
        // Attachments (with their pipe halves) live inline in `atts`.
        n += self.atts.heap_bytes();
        n += self.mp.as_deref().map_or(0, mpath::Mp::heap_bytes);
        n += self.grease.1.capacity() + self.exporter.as_ref().map_or(0, Vec::capacity);
        n += self.error.as_ref().map_or(0, |_| size_of::<SessionError>());
        n += self.close.as_ref().map_or(0, |_| size_of::<CloseFrame>());
        n += self
            .goaway
            .as_deref()
            .map_or(0, |g| size_of::<GoAwayState>() + g.reason.len());
        n += self.dgram.as_deref().map_or(0, DatagramState::heap_bytes);
        n += self
            .quality
            .as_deref()
            .map_or(0, quality::Quality::heap_bytes);
        n
    }

    /// Outbound pipe `pipe` failed under us.
    pub(super) fn outbound_failed(&mut self, pipe: u64, cause: PipeFailure, now: Instant) {
        if !self.out_mut(pipe).is_some_and(OutPipe::write_failed) {
            return;
        }
        self.views_changed();
        if self.mp.is_some() && self.state < State::Closing {
            self.mp_outbound_failed(pipe, cause, now);
            return;
        }
        if self.state == State::Closing {
            self.maybe_closed(now);
            return;
        }
        if self.state != State::Closed {
            self.set_error(SessionError::PipesLost { last: Some(cause) });
            self.closed_now();
        }
    }

    /// The fence completed (EXTENSIONS.md Section 3.3): phase 2 follows
    /// at once, or one SRTT later in a multipath session and in a session
    /// whose pipe toward this endpoint has lanes, as the response may have
    /// overtaken stream frames on a slower pipe or lane.
    pub(super) fn fence_completed(&mut self, now: Instant) {
        let lanes = self.mp.is_none()
            && self
                .atts
                .first()
                .and_then(Attachment::inp)
                .is_some_and(|p| p.lane_count() > 1);
        if self.mp.is_some() || lanes {
            let at = now + self.rtt_or_default();
            self.goaway_mut().fence = None;
            self.goaway_mut().phase_two_at = Some(at);
        } else {
            self.goaway_phase_two(now);
        }
    }
}

impl SessionCore {
    /// The send buffer the fair share divides, with the retained bytes of
    /// a multipath session.
    pub(super) fn send_buffer(&self) -> SendBuffer {
        SendBuffer {
            total: self.session_send_buffer(),
            retained: self.mp.as_deref().map(super::mpath::Mp::retained),
        }
    }

    /// Updates whether a direction counts in the fair share; one that
    /// left it leaves a larger share for the others.
    pub(super) fn sync_holder(&mut self, key: StreamKey) {
        if self.streams.sync_holder(key, self.mp.is_some()) {
            self.wake_send_waiters();
        }
    }

    /// Records `n` bytes the application just wrote; `waiting` when the
    /// write could not take all its data and waits for space.
    pub(super) fn mark_write(&mut self, key: StreamKey, n: u64, waiting: bool) {
        let mp = self.mp.is_some();
        self.streams.mark_write(key, n, waiting, mp, self.now);
    }

    /// Wakes the writers waiting for send-buffer room that have room now
    /// (their own share, or the session buffer), in the order they began to
    /// wait. A multipath session looks only at those the ledger shows may
    /// have room.
    pub(super) fn wake_send_waiters(&mut self) {
        let Some(few_stale) = self.streams.start_waking() else {
            return;
        };
        // The session buffer stays as it is while writers are woken.
        let buffer = self.send_buffer();
        if self.mp.is_some() && few_stale {
            self.wake_some(buffer);
        } else {
            self.streams.wake_every(buffer, &mut self.events);
        }
        self.streams.stop_waking();
    }
}

impl SessionCore {}

impl SessionCore {
    /// Stream data arrived: the arrival rates and credit-loop samples of
    /// the stream (whose highest received offset is `off`) and of the
    /// session.
    pub(super) fn autotune_data(&mut self, key: StreamKey, off: u64, now: Instant) {
        let pipe_rtt = if self.mp.is_some() {
            self.pipe_min_rtt(self.rx)
        } else {
            None
        };
        let rtt = self.autotune_rtt(Some(key));
        let session_rtt = self.autotune_rtt(None);
        let samples = self
            .streams
            .autotune_data(key, off, now, (rtt, session_rtt), pipe_rtt);
        for s in samples.into_iter().flatten() {
            self.loop_min.sample(now, s, super::filter::LOOP_SPAN);
        }
    }
}

impl SessionCore {
    /// The most bytes a driver hands a pipe's carrier in the write call it
    /// is about to make, of a batch (or what is left of one) of `batch`
    /// bytes: the whole of it, except while
    /// latency-sensitive work waits ([`SessionCore`]'s own state, and
    /// `input_pending`: bytes the driver received and has not handed to the
    /// core yet), when the bound clamp(R x B / 2, 16 KiB, 64 KiB) lets a
    /// request, an acknowledgement or credit wait for at most one short
    /// call. A `blocking` write in a multipath session also holds at most
    /// max(4 KiB, R_p x 50 ms), so that no call is
    /// expected to take much longer than 50 ms. Independent of the
    /// carrier: any carrier works with it, whatever signals it offers.
    pub fn write_call_limit(
        &self,
        pipe: super::PipeId,
        batch: usize,
        blocking: bool,
        input_pending: bool,
        now: Instant,
    ) -> usize {
        let rate = self.pipe_send_rate(pipe);
        let mut limit = batch as u64;
        if self.latency_work(pipe.0, input_pending, now) {
            let budget = self.config.latency_budget.as_secs_f64();
            let bound =
                ((rate as f64 * budget / 2.0) as u64).clamp(WRITE_CALL_MIN as u64, WRITE_CALL_MAX);
            limit = limit.min(bound);
        }
        if blocking && self.mp.is_some() {
            let mp = ((rate as f64 * MP_WRITE_CALL_SPAN.as_secs_f64()) as u64)
                .clamp(MP_WRITE_CALL_MIN, (batch as u64).max(MP_WRITE_CALL_MIN));
            limit = limit.min(mp);
        }
        usize::try_from(limit).unwrap_or(usize::MAX).max(1)
    }
}

impl SessionCore {
    pub(super) fn on_record_end(&mut self, len: u64, now: Instant) -> Result<(), Error> {
        self.stats.records_received += 1;
        let (id, li) = (self.rx, self.rx_lane);
        let Some(p) = self.inp_mut(id) else {
            return Ok(());
        };
        // A leading QX_TRANSPORT_PARAMETERS record on a pipe we joined
        // confirms nothing, is not counted and is not acknowledged
        // (MULTIPATH.md Section 5.7 step 3).
        if !p.record_closed(li) {
            return Ok(());
        }
        if self.mp.is_some() {
            self.mp_record_end(len, now);
        } else {
            let mut activity = false;
            if let Some(p) = self.inp_mut(id) {
                let (eliciting, act) = p.single_record(li, len);
                activity = act;
                self.single_record_end(len, eliciting, now);
            }
            // With acknowledgement only a record with an activity frame
            // counts; without it, every record (SPEC.md Section 6.4).
            if activity || !self.acknowledged() {
                self.restart_idle(now);
            }
        }
        Ok(())
    }
}

// The path layer's properties and the hooks of what multipath alone does.
impl SessionCore {
    /// Whether sent stream data is kept until a PIPE_ACK covers it and
    /// resent when lost (MULTIPATH.md Sections 6 and 7.4); a single pipe
    /// drops what it wrote.
    #[inline]
    pub(super) fn retains(&self) -> bool {
        self.mp.is_some()
    }

    /// Whether outbound pipes are measured, scheduled and failed one by
    /// one (MULTIPATH.md Sections 7 to 11); a single pipe is the session's.
    #[inline]
    pub(super) fn per_pipe(&self) -> bool {
        self.mp.is_some()
    }

    /// The pipe-layer frames of a batch on pipe `id`: PIPE_ACK, PIPE_PING
    /// and the pipe control frames in a multipath session, the single
    /// pipe's acknowledgement when it is in use.
    pub(super) fn write_path_frames(&mut self, id: u64, w: &mut Records<'_>, now: Instant) {
        if self.mp.is_some() {
            self.write_pipe_frames(id, w, now);
        } else if self.pipe_ack.is_some() {
            self.write_single_pipe_ack(w, now);
        }
    }

    /// Whether pipe `id` takes data in this batch: a multipath pipe while
    /// the scheduler lets it, a single pipe always.
    pub(super) fn pipe_takes_data(&self, id: u64) -> bool {
        self.out_ref(id)
            .is_some_and(|o| o.takes_new_data() || self.mp.is_none())
    }

    /// The end of a write opportunity of a multipath pipe: application
    /// limited when it stays writable with nothing for it, else the pipe
    /// is the bottleneck.
    pub(super) fn opportunity_ended(&mut self, id: u64) {
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
    }

    /// GOAWAY while suspended: the drain starts once the session resumes
    /// (RESUME.md Section 4.1).
    pub(super) fn drain_after_suspension(&mut self) {
        if let Some(mp) = self.mp.as_deref_mut() {
            mp.suspension_mut().drain_after();
        }
    }
}

impl SessionCore {
    /// Whether a direction that is not bound goes on lane 0: urgency 0 to
    /// 2 outside multipath (which sends nothing twice), a direction sent
    /// redundantly in a multipath session.
    pub(super) fn on_lane_zero(&self, key: StreamKey) -> bool {
        let Some(send) = self.streams.send(key) else {
            return true;
        };
        if self.mp.is_some() {
            self.redundant(send)
        } else {
            send.priority.urgency() <= 2
        }
    }
}
