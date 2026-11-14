//! Multipath acknowledgement and reinjection: receive positions and
//! PIPE_ACK generation, PIPE_ACK processing with RTT and delivery-rate
//! sampling, and re-sending the information of suspect and failed pipes.

use std::time::{Duration, Instant};

use crate::proto::frame::{Frame, PipeAck, PipeAckEntry};
use crate::proto::session::output::Records;
use crate::proto::session::pipes::{Attachment, Batch, OutPipe, OutState, SentFrame};
use crate::proto::session::stream::{RecvState, SendState};
use crate::proto::session::{BIDI, CoreEvent, PipeId, SessionCore, StreamKey, UNI};
use crate::proto::{DetailKey, Error};

/// Snapshots listing at most this many pipes are always complete; larger
/// ones omit the unchanged entries.
const PARTIAL_SNAPSHOT: usize = 8;
/// A complete snapshot goes out at least this often while snapshots are
/// sent.
const COMPLETE_SNAPSHOT: Duration = Duration::from_secs(1);

/// The acknowledgement state of a multipath session: what PIPE_ACK owes,
/// the primary pipe and its redundant copy, and the scratch of snapshots
/// and acknowledged frames.
#[derive(Debug)]
pub(crate) struct AckState {
    /// Our own `zmux_max_ack_delay` and `zmux_ack_threshold`.
    local_mad: Duration,
    threshold: u64,
    /// A PIPE_ACK is owed now (PIPE_PING received, a pipe ended).
    ack_now: bool,
    /// The primary pipe owes it whatever the session's activity: a pipe
    /// ended, or a PIPE_PING arrived on a pipe pair without a usable
    /// outbound direction to answer on.
    primary_owed: bool,
    /// Inbound positions changed since the last snapshot on the primary
    /// pipe; when the redundant copy is due, and on which pipe the last
    /// snapshot went.
    snapshot_dirty: bool,
    copy_due: Option<Instant>,
    primary: Option<u64>,
    /// The next primary snapshot must be complete: it answers a PIPE_PING
    /// in the first record of a newly attached inbound pipe.
    complete_owed: bool,
    /// When the last complete PIPE_ACK snapshot was sent.
    complete_ack_at: Option<Instant>,
    /// Scratch for PIPE_ACK entries and acknowledged frames.
    scratch: Vec<PipeAckEntry>,
    frames: Vec<SentFrame>,
}

impl AckState {
    pub(in crate::proto::session) fn new(local_mad: Duration, threshold: u64) -> Self {
        Self {
            local_mad,
            threshold,
            ack_now: false,
            primary_owed: false,
            snapshot_dirty: false,
            copy_due: None,
            primary: None,
            complete_owed: false,
            complete_ack_at: None,
            scratch: Vec::new(),
            frames: Vec::new(),
        }
    }

    /// Heap bytes held.
    pub(in crate::proto::session) fn heap_bytes(&self) -> usize {
        self.frames.capacity() * size_of::<SentFrame>()
            + self.scratch.capacity() * size_of::<PipeAckEntry>()
    }

    /// A PIPE_ACK is owed now (a pipe ended).
    pub(in crate::proto::session) fn owe_now(&mut self) {
        self.ack_now = true;
        self.primary_owed = true;
    }

    /// The pipe the last primary snapshot went on.
    pub(in crate::proto::session) fn primary(&self) -> Option<u64> {
        self.primary
    }

    /// When the redundant copy of the snapshot is due.
    pub(in crate::proto::session) fn copy_due(&self) -> Option<Instant> {
        self.copy_due
    }

    /// The redundant copy goes at `at` at the latest.
    pub(in crate::proto::session) fn copy_by(&mut self, at: Instant) {
        self.copy_due.get_or_insert(at);
    }

    /// The redundant copy goes at once (the primary pipe became suspect).
    pub(in crate::proto::session) fn copy_now(&mut self, now: Instant) {
        self.copy_due = Some(now);
    }

    /// The session is closing: no copy is due any more.
    pub(in crate::proto::session) fn closing(&mut self) {
        self.copy_due = None;
    }
}

/// Builds a snapshot of the inbound pipes of `atts` into `entries`, every
/// lane of a pipe with lanes in its own entry: complete when `complete` or
/// when it lists at most [`PARTIAL_SNAPSHOT`] entries, otherwise only the
/// entries changed since the last complete snapshot. Whether it is
/// complete.
pub(in crate::proto::session) fn snapshot_of(
    atts: &crate::proto::session::pipes::Attachments,
    entries: &mut Vec<PipeAckEntry>,
    complete: bool,
    now: Instant,
) -> bool {
    let fill = |entries: &mut Vec<PipeAckEntry>, complete: bool| {
        entries.clear();
        for a in atts {
            if let Some(p) = a.inp() {
                p.ack_entries(a.id(), complete, now, entries);
            }
        }
    };
    fill(entries, true);
    if complete || entries.len() <= PARTIAL_SNAPSHOT {
        return true;
    }
    fill(entries, false);
    false
}

impl SessionCore {
    /// Reports one of our joins that was not attached before, once it is.
    fn note_attached(&mut self, id: u64) {
        if self.att(id).is_some_and(Attachment::peer_attached) {
            self.push_event(CoreEvent::PipeAttached { pipe: PipeId(id) });
        }
    }

    // ---- receive positions --------------------------------------------------------

    /// A complete record of `len` bytes was processed on the inbound pipe
    /// `self.rx`.
    pub(in crate::proto::session) fn mp_record_end(&mut self, len: u64, now: Instant) {
        let (id, li) = (self.rx, self.rx_lane);
        let (threshold, delay) = {
            let acks = self.mp().acks();
            (acks.threshold, acks.local_mad)
        };
        let attached = self.att(id).is_none_or(Attachment::peer_attached);
        let Some(p) = self.inp_mut(id) else {
            return;
        };
        let rec = p.mp_record(li, len, threshold, delay, now);
        if !attached {
            self.note_attached(id);
        }
        // The answer to a PIPE_PING in the first record of a newly attached
        // pipe is a complete snapshot.
        let first_ping = rec.first_ping && id != 0;
        let acks = self.mp_mut().acks_mut();
        acks.snapshot_dirty = true;
        acks.ack_now |= rec.immediate;
        acks.complete_owed |= first_ping;
        if rec.ping {
            // The answer goes on the probed pair when its outbound
            // direction is neither suspect nor failed; else on the primary
            // pipe whatever the session's activity.
            match self
                .out_mut(id)
                .filter(|o| o.is_live() && !o.shutdown_pending() && o.state() != OutState::Suspect)
            {
                Some(o) => o.answer_ping(),
                None => self.mp_mut().acks_mut().primary_owed = true,
            }
        }
        if rec.activity {
            self.restart_idle(now);
        }
    }

    /// The acknowledgement timer: when a PIPE_ACK becomes due, while it is
    /// in the future (a due one is the transmit path's business).
    pub(in crate::proto::session) fn ack_timer(&self) -> Option<Instant> {
        if self.mp.as_deref()?.acks().ack_now {
            return None;
        }
        self.ack_deadline().filter(|&t| t > self.now)
    }

    /// When a PIPE_ACK is due on the primary pipe; never while the answers
    /// on the probed pairs acknowledge everything owed.
    pub(in crate::proto::session) fn ack_deadline(&self) -> Option<Instant> {
        let acks = self.mp.as_deref()?.acks();
        if self.pairs_answer_all() {
            return None;
        }
        if acks.ack_now {
            return Some(self.now);
        }
        let mad = acks.local_mad;
        self.atts
            .iter()
            .filter_map(|a| a.inp()?.unacked_since())
            .min()
            .map(|t| t + mad)
    }

    /// When a shaping delay of `pipe`'s next record ends because the record
    /// carries a pending PIPE_ACK: our `zmux_max_ack_delay` after the first
    /// ack-eliciting byte it reports (MULTIPATH.md Section 6.3), on any
    /// inbound pipe, not only those the primary PIPE_ACK owes. The peer's
    /// T_suspect counts on that bound: held longer, its working pipe turns
    /// suspect at every exchange. `None` when the record carries none.
    pub(in crate::proto::session) fn ack_release(&self, pipe: u64) -> Option<Instant> {
        let Some(mp) = self.mp.as_deref() else {
            return self.single_ack_release();
        };
        let carries = self.snapshot_first(pipe)
            || self.out_ref(pipe).is_some_and(OutPipe::answers_ping)
            || !self.pairs_answer_all() && self.control_pipe(None) == Some(pipe);
        if !carries {
            return None;
        }
        let mad = mp.acks().local_mad;
        self.atts
            .iter()
            .filter_map(|a| a.inp()?.unacked_since())
            .min()
            .map(|t| t + mad)
    }

    pub(in crate::proto::session) fn ack_due(&self, now: Instant) -> bool {
        self.ack_deadline().is_some_and(|t| now >= t)
    }

    /// Whether, in a quiet session, everything a PIPE_ACK owes is
    /// PIPE_PING frames answered on their own pipe pairs: such an answer
    /// goes only there, neither on the primary pipe nor as the redundant
    /// copy.
    fn pairs_answer_all(&self) -> bool {
        let Some(mp) = self.mp.as_deref() else {
            return false;
        };
        let acks = mp.acks();
        self.is_quiet(self.now)
            && !acks.primary_owed
            && self.atts.outs().any(OutPipe::answers_ping)
            && !self
                .atts
                .iter()
                .any(|a| a.inp().is_some_and(|p| p.unacked_other()))
    }

    // ---- pipe choice --------------------------------------------------------------

    /// The estimated one-way delay of an outbound pipe.
    pub(in crate::proto::session) fn owd(&self, o: &OutPipe) -> Duration {
        match self.mp {
            Some(_) => self.views().owd(o),
            // The single pipe is the live pipe with the smallest min_rtt.
            None => crate::proto::session::tier::owd(o, o.est().min_rtt.get().unwrap_or_default()),
        }
    }

    /// The pipe that carries control frames and PIPE_ACK first, optionally
    /// excluding one (for the redundant copy): the first in the
    /// acknowledgement control order (ACTIVE first, then the most preferred
    /// tier, non-standby, then the lowest priority, then the lowest one-way
    /// delay). A carrier that refused its last bytes keeps the role: it takes
    /// bytes again soon, and the frames go first in its next batch, while a
    /// slower pipe whose carrier takes everything would deliver them behind
    /// its own queue.
    pub(in crate::proto::session) fn control_pipe(&self, except: Option<u64>) -> Option<u64> {
        let views = self.views();
        views
            .control()
            .iter()
            .map(|&i| self.atts.at(i))
            .find(|a| Some(a.id()) != except && a.out().is_some())
            .map(Attachment::id)
    }

    /// Whether `pipe` should carry the session's control frames now.
    pub(in crate::proto::session) fn is_control_pipe(&self, pipe: u64) -> bool {
        self.mp.is_none() || self.control_pipe(None) == Some(pipe)
    }

    // ---- writing PIPE_ACK --------------------------------------------------------

    /// Whether `pipe` has a PIPE_ACK to write now.
    pub(in crate::proto::session) fn wants_pipe_ack(&self, pipe: u64, now: Instant) -> bool {
        let Some(mp) = self.mp.as_deref() else {
            return false;
        };
        if self.snapshot_first(pipe) || self.out_ref(pipe).is_some_and(OutPipe::answers_ping) {
            return true;
        }
        if self.ack_due(now) && self.control_pipe(None) == Some(pipe) {
            return true;
        }
        let acks = mp.acks();
        acks.copy_due.is_some_and(|t| now >= t)
            && acks.primary.is_some()
            && self.copy_pipe() == Some(pipe)
    }

    /// The pipe for the redundant copy of the snapshot.
    fn copy_pipe(&self) -> Option<u64> {
        let primary = self.mp().acks().primary;
        self.control_pipe(primary)
    }

    /// Whether the first record on a new outbound pipe still owes its
    /// complete snapshot; only when there is at least one entry.
    fn snapshot_first(&self, pipe: u64) -> bool {
        self.out_ref(pipe).is_some_and(OutPipe::snapshot_first)
            && self
                .atts
                .iter()
                .any(|a| a.inp().is_some_and(|p| p.listed()))
    }

    /// Builds the current snapshot into `entries`; returns whether it is
    /// complete. A large snapshot may omit the pipes and lanes whose
    /// position has not changed since the last complete one, which goes
    /// out at least once per second; `complete` forces a complete one.
    fn snapshot(&self, entries: &mut Vec<PipeAckEntry>, complete: bool, now: Instant) -> bool {
        let complete = complete
            || self
                .mp()
                .acks()
                .complete_ack_at
                .is_none_or(|t| now.saturating_duration_since(t) >= COMPLETE_SNAPSHOT);
        snapshot_of(&self.atts, entries, complete, now)
    }

    /// Writes PIPE_ACK on `pipe` when it is due there (primary), the
    /// redundant copy is due there, or it is the first record on a new
    /// outbound pipe (a complete snapshot). Returns whether it wrote the
    /// redundant copy, with which the credit copies go.
    pub(in crate::proto::session) fn write_pipe_ack(
        &mut self,
        pipe: u64,
        w: &mut Records<'_>,
        now: Instant,
    ) -> bool {
        let Some(mp) = self.mp.as_deref() else {
            return false;
        };
        let first = self.snapshot_first(pipe);
        // The answer to a PIPE_PING that arrived on this pipe pair.
        let pair = self.out_ref(pipe).is_some_and(OutPipe::answers_ping);
        // It is all that is owed (a quiet session's probes).
        let pair_only = pair && self.pairs_answer_all();
        // Due, or a credit update goes out in this batch while something
        // is unacknowledged.
        let due = self.ack_due(now)
            || (self
                .atts
                .iter()
                .any(|a| a.inp().is_some_and(|p| p.unacked() > 0))
                && self.credit_update_pending());
        let primary = due && self.control_pipe(None) == Some(pipe);
        let copy = !primary
            && mp.acks().copy_due.is_some_and(|t| now >= t)
            && mp.acks().primary.is_some()
            && self.copy_pipe() == Some(pipe);
        if !primary && !copy && !first && !pair {
            if let Some(o) = self.out_mut(pipe) {
                // Nothing to report: the first record owes nothing.
                o.no_first_snapshot();
            }
            return false;
        }
        let force = first || ((primary || pair_only) && self.mp().acks().complete_owed);
        let mut entries = std::mem::take(&mut self.mp_mut().acks_mut().scratch);
        let complete = self.snapshot(&mut entries, force, now);
        let written = entries.is_empty() || Self::write_snapshot(&entries, w);
        self.mp_mut().acks_mut().scratch = entries;
        if !written {
            // The complete snapshot is still owed, at the start of the next
            // record.
            return false;
        }
        if let Some(o) = self.out_mut(pipe) {
            o.pipe_ack_written();
        }
        if (primary || pair_only) && complete {
            self.mp_mut().acks_mut().complete_owed = false;
        }
        if !primary && !copy {
            // The first record's snapshot, and the answer on the probed
            // pair, are in addition to the others: same-value copies,
            // unless the answers on the probed pairs are all that is owed.
            if complete {
                self.mp_mut().acks_mut().complete_ack_at = Some(now);
                for p in self.atts.inps_mut() {
                    p.complete_sent();
                }
            }
            if pair_only {
                for p in self.atts.inps_mut() {
                    p.ack_sent(now);
                }
                let acks = self.mp_mut().acks_mut();
                acks.ack_now = false;
                acks.snapshot_dirty = false;
            }
            if pair {
                self.liveness_ping(pipe, w, now);
            }
            return false;
        }
        if complete {
            self.mp_mut().acks_mut().complete_ack_at = Some(now);
            for p in self.atts.inps_mut() {
                p.complete_sent();
            }
        }
        let live_out = self.atts.iter().filter(|a| a.out_live()).count();
        if primary {
            for p in self.atts.inps_mut() {
                p.ack_sent(now);
            }
            let acks = self.mp_mut().acks_mut();
            let dirty = std::mem::take(&mut acks.snapshot_dirty);
            acks.ack_now = false;
            acks.primary_owed = false;
            acks.primary = Some(pipe);
            if dirty && live_out >= 2 {
                acks.copy_by(now + crate::proto::session::mpath::ACK_COPY_INTERVAL);
            }
        } else {
            self.mp_mut().acks_mut().copy_due = None;
        }
        // The answer on a probed pair always; the primary PIPE_ACK and its
        // copy only while the session is busy: in a quiet one their pipes
        // are idle pipes, probed as such.
        if pair || !self.is_quiet(now) {
            self.liveness_ping(pipe, w, now);
        }
        copy
    }

    /// A PIPE_ACK written on a pipe whose last ack-eliciting byte (or its
    /// becoming live) is more than R_p = max(1 s, T_suspect) ago gets a
    /// PIPE_PING in the same record: the answer on a probed pair, which
    /// starts the pipe's next probe wait, and in a busy session the primary
    /// PIPE_ACK and its redundant copy (return-pipe liveness).
    fn liveness_ping(&mut self, pipe: u64, w: &mut Records<'_>, now: Instant) {
        let t_suspect = self.out_ref(pipe).map(|o| self.limits(o).0);
        if let Some(o) = self.out_mut(pipe) {
            let quiet = t_suspect.unwrap_or_default().max(Duration::from_secs(1));
            o.check_liveness(quiet, now);
        }
        self.write_pipe_ping(pipe, w, now);
    }

    /// Writes a snapshot: one PIPE_ACK, or several with strictly increasing
    /// subsets when one does not fit in a record. `false` when the batch
    /// could not take all of it.
    pub(in crate::proto::session) fn write_snapshot(
        entries: &[PipeAckEntry],
        w: &mut Records<'_>,
    ) -> bool {
        if w.try_frame(&Frame::PipeAck(PipeAck::new(entries))) {
            return true;
        }
        // An entry takes at most 32 bytes; the frame header at most 16.
        let per = (w.max_record().saturating_sub(16) / 32).max(1);
        if per >= entries.len() {
            return false;
        }
        entries
            .chunks(per)
            .all(|c| w.try_frame(&Frame::PipeAck(PipeAck::new(c))))
    }

    // ---- receiving PIPE_ACK --------------------------------------------------------

    /// Processes a received PIPE_ACK.
    pub(in crate::proto::session) fn on_pipe_ack(
        &mut self,
        f: &PipeAck<'_>,
        now: Instant,
    ) -> Result<(), Error> {
        let ty = 0x0b2b_3eeb;
        // The first PIPE_ACK after a pipe became live ends its reinjection
        // hold.
        for o in self.atts.outs_mut() {
            o.end_reinject_hold();
        }
        for e in f.entries() {
            if self.mp().is_local(e.pipe_id) && !self.local_id_taken(e.pipe_id) {
                return Err(
                    Error::protocol_violation(ty, "PIPE_ACK for an untaken local pipe ID")
                        .detail(DetailKey::Pipe, e.pipe_id),
                );
            }
            if e.position == 0 || self.is_retired(e.pipe_id) {
                continue;
            }
            let sent = self.sent_on(e.pipe_id, e.lane);
            if e.position > sent {
                // The peer claims data never sent; with resume the two
                // states diverged, which fails closed.
                let reason = "PIPE_ACK acknowledges bytes never sent";
                let err = if self.mp().resume() {
                    Error::new(
                        crate::proto::TransportErrorCode::ZMUX_RESUME_FAILED,
                        ty,
                        reason,
                    )
                } else {
                    Error::protocol_violation(ty, reason)
                };
                return Err(err
                    .detail(DetailKey::Pipe, e.pipe_id)
                    .detail(DetailKey::Pos, e.position)
                    .detail(DetailKey::Limit, sent));
            }
            let delay = Duration::from_micros(e.ack_delay.min(u64::MAX >> 2));
            let attached = self.att(e.pipe_id).is_none_or(Attachment::peer_attached);
            self.process_ack(e.pipe_id, e.lane, e.position, delay, now);
            if !attached {
                self.note_attached(e.pipe_id);
            }
        }
        Ok(())
    }

    /// The bytes written on a lane of an outbound pipe: 0 for a pipe without
    /// an outbound direction and for a lane never opened.
    pub(in crate::proto::session) fn sent_on(&self, pipe: u64, lane: u64) -> u64 {
        self.out_ref(pipe).map_or(0, |o| o.sent_on(lane))
    }

    /// The peer's position on lane `lane` of an outbound pipe advanced to
    /// `pos`; `delay` is the entry's ACK Delay. The frames the lane carried
    /// up to it are acknowledged, and the pipe's samples and progress come
    /// from its cumulative acknowledgement point.
    pub(in crate::proto::session) fn process_ack(
        &mut self,
        id: u64,
        lane: u64,
        pos: u64,
        delay: Duration,
        now: Instant,
    ) {
        let peer_mad = self.mp().peer_mad();
        let quiet = self.is_quiet(now);
        let suspended_at = self.mp().suspension().since();
        let deaf = self.mp().no_inbound();
        // Bytes sent while no inbound pipe was live give no samples.
        let heard =
            |t: Instant| deaf.is_none_or(|(from, to)| t < from || to.is_some_and(|to| t >= to));
        let Some(o) = self.out_mut(id) else {
            return;
        };
        let (moved, cum) = o.ack_lane(lane, pos, now);
        if !moved {
            return;
        }
        o.pings_acked(lane, pos);
        if let Some(l) = o.lanes_mut() {
            l.clear_released();
        }
        // Bytes sent before the session last suspended give no samples.
        let heard = |b: &Batch| suspended_at.is_none_or(|s| b.time >= s) && heard(b.time);
        let ack = cum.map(|cum| o.mp_acked(cum, delay, peer_mad, quiet, heard, now));
        if let Some(ack) = &ack {
            self.pace_ack(id, &ack.sample, now);
            // A new minimum RTT moves the one-way delays.
            if ack.sample.min_moved {
                self.views_changed();
            }
            if ack.unpenalized {
                // Usable again: eligibility and the standby takeover
                // change, as at the end of a revalidation.
                self.advance_pick_generation();
                self.check_standby_takeover();
            }
            if ack.revalidated {
                self.end_revalidation(id);
            }
        }
        // Frames now acknowledged.
        let mut acked = std::mem::take(&mut self.mp_mut().acks_mut().frames);
        self.out_mut(id)
            .expect("present")
            .take_acked_frames(lane, &mut acked);
        // The pipe position passed these frames: what the ledger keeps of
        // their streams depends on it, before any of them is processed.
        for f in &acked {
            if let SentFrame::Stream { key, .. } = *f {
                self.streams.touch(key);
            }
        }
        for f in acked.drain(..) {
            self.frame_acked(f, now);
        }
        self.mp_mut().acks_mut().frames = acked;
        if let Some(ack) = ack {
            if ack.activity {
                // A record with an activity frame was acknowledged: the
                // idle timer restarts.
                self.restart_idle(now);
            }
            self.ack_progress(id, now);
        }
        self.check_drained(id, now);
        self.try_retire(now);
        if self.state == crate::proto::session::State::Suspended {
            self.check_resume(now);
        }
    }

    /// A retained frame was acknowledged.
    fn frame_acked(&mut self, f: SentFrame, now: Instant) {
        match f {
            SentFrame::Stream { key, off, len, fin } => self.stream_acked(key, off, len, fin),
            SentFrame::Reset { key } => {
                if let Some(send) = self.streams.send_mut(key)
                    && send.cold().reset.is_some_and(|r| r.written)
                {
                    send.mp_mut().reset_acked = true;
                    send.mp_mut().reset_lost = false;
                    self.check_send_done(key);
                }
            }
            SentFrame::PipeAbandon { pipe } => {
                let delay = self.retire_delay();
                if let Some(a) = self.att_mut(pipe) {
                    a.abandon_acknowledged(delay, now);
                }
                self.exchange_progress(pipe, now);
            }
            SentFrame::PriorityUpdate { key, seq } => {
                if let Some(s) = self.streams.get_mut(key)
                    && s.extra().priority_sent.is_some_and(|(q, _)| q == seq)
                {
                    s.extra_mut().priority_resend = false;
                }
            }
            SentFrame::EpochAnswer { epoch } => self.epoch_answer_acked(epoch, now),
            _ => {}
        }
    }

    /// The delay of unilateral retirement: max(2 s, 3 x PTO).
    fn retire_delay(&self) -> Duration {
        let mad = self.mp().peer_mad();
        let mut pto = None::<Duration>;
        for active_only in [true, false] {
            for o in self.atts.outs() {
                if o.is_live() && (!active_only || o.state() == OutState::Active) {
                    let p = o.est().pto(mad);
                    pto = Some(pto.map_or(p, |x| x.max(p)));
                }
            }
            if pto.is_some() {
                break;
            }
        }
        let pto = pto.unwrap_or_else(|| {
            crate::proto::session::pipes::INITIAL_RTT
                + crate::proto::session::pipes::INITIAL_RTT * 2
                + mad
        });
        Duration::from_secs(2).max(pto * 3)
    }

    /// Stream bytes `off..off + len` (and the FIN) were acknowledged.
    fn stream_acked(&mut self, key: StreamKey, off: u64, len: u64, fin: bool) {
        let mut released = 0;
        if let Some((s, chunks)) = self.streams.stream_and_chunks(key)
            && let Some(send) = s.send.as_mut()
        {
            let before = send.unacked();
            send.mp_mut().ack(off, off + len);
            send.mp_mut().lost.remove(off, off + len);
            if fin {
                send.mp_mut().fin_acked = true;
                send.mp_mut().fin_lost = false;
            }
            if !send.mp().preamble_acked
                && (send.preamble.is_none() || send.mp().acked.contains(0, send.base))
            {
                send.mp_mut().preamble_acked = true;
            }
            // Release the acknowledged prefix of the bytes held.
            if send.mp().preamble_acked {
                let floor = send.mp().buf_floor;
                let end = send.mp().acked.contiguous_end(floor);
                let n = end.saturating_sub(floor).min(send.buf.kept());
                if n > 0 {
                    send.buf.release(n, chunks);
                    let m = send.mp_mut();
                    m.release_below(floor + n);
                    m.buf_floor = floor + n;
                }
            }
            released = before - send.unacked();
        }
        if released > 0 {
            self.mp_mut().release(released);
            // Acknowledged bytes free send-buffer room.
            self.sync_holder(key);
            self.wake_send_waiters();
        }
        self.check_send_done(key);
    }

    /// A multipath sending part reaches "Data Recvd" or "Reset Recvd"
    /// once acknowledged.
    pub(in crate::proto::session) fn check_send_done(&mut self, key: StreamKey) {
        let Some(send) = self.streams.send_mut(key) else {
            return;
        };
        let done = match send.state {
            SendState::DataSent => {
                send.mp().fin_acked
                    && send.buf.kept() == 0
                    && send.buf.is_empty()
                    && (send.base == 0 || send.mp().preamble_acked)
                    && !send.has_lost()
            }
            SendState::ResetSent => {
                // The reset and every byte below its Reliable Size.
                let r = send.mp().reliable_sent.unwrap_or(0);
                send.cold().reset.is_some_and(|r| r.written)
                    && send.mp().reset_acked
                    && (send.base == 0 || r == 0 || send.mp().preamble_acked)
                    && (send.mp().buf_floor >= r
                        || send.mp().acked.contains(send.mp().buf_floor, r))
                    && send.mp().lost.first().is_none_or(|(a, _)| a >= r)
            }
            _ => false,
        };
        if !done {
            return;
        }
        let reset = send.state == SendState::ResetSent;
        let kept = send.unacked();
        send.state = if reset {
            SendState::ResetRecvd
        } else {
            SendState::DataRecvd
        };
        send.buf.clear();
        let m = send.mp_mut();
        m.lost.clear();
        m.clear_ranges();
        m.drop_carried(u64::MAX);
        self.release_retained(kept);
        self.notify_writable(key);
        self.try_discard(key);
    }

    // ---- reinjection --------------------------------------------------------------

    /// Re-sends the information of every ack-eliciting frame sent on an
    /// outbound pipe beyond its acknowledged position, once per pipe.
    pub(in crate::proto::session) fn reinject(&mut self, id: u64, now: Instant) {
        let mut frames = std::mem::take(&mut self.mp_mut().acks_mut().frames);
        let Some(o) = self.out_mut(id) else {
            self.mp_mut().acks_mut().frames = frames;
            return;
        };
        o.take_reinjection(&mut frames);
        if frames.is_empty() {
            self.mp_mut().acks_mut().frames = frames;
            return;
        }
        self.stats.reinjections += 1;
        for f in frames.drain(..) {
            self.reinject_frame(f, now);
        }
        self.mp_mut().acks_mut().frames = frames;
    }

    pub(super) fn reinject_frame(&mut self, f: SentFrame, now: Instant) {
        match f {
            SentFrame::Stream { key, off, len, fin } => {
                let Some(send) = self.streams.send_mut(key) else {
                    return;
                };
                if send.state.is_terminal() {
                    return;
                }
                // After a reset only data below the Reliable Size counts.
                let limit = match send.cold().reset {
                    Some(_) => send
                        .mp()
                        .reliable_sent
                        .or(send.reset_reliable())
                        .unwrap_or(0),
                    None => u64::MAX,
                };
                let end = (off + len).min(limit);
                let start = off.max(send.held_from());
                if end > start {
                    if !send.has_lost() {
                        send.waits.age_mut().lost_at = Some(now);
                    }
                    // Only the parts not acknowledged meanwhile, without
                    // allocating.
                    let m = send.mp_mut();
                    let (acked, lost) = (&m.acked, &mut m.lost);
                    let mut at = start;
                    for (a, b) in acked.iter() {
                        if b <= at {
                            continue;
                        }
                        if a >= end {
                            break;
                        }
                        if a > at {
                            lost.insert(at, a);
                        }
                        at = at.max(b);
                    }
                    if at < end {
                        lost.insert(at, end);
                    }
                }
                if fin && send.cold().reset.is_none() && !send.mp().fin_acked {
                    send.mp_mut().fin_lost = true;
                }
                if send.has_lost() {
                    self.schedule(key);
                }
            }
            SentFrame::Reset { key } => {
                if let Some(send) = self.streams.send_mut(key)
                    && !send.mp().reset_acked
                    && !send.state.is_terminal()
                {
                    send.mp_mut().reset_lost = true;
                    self.streams.queue_ctrl(key);
                }
            }
            SentFrame::StopSending { key } => {
                if let Some(r) = self.streams.recv_mut(key)
                    && !r.state.is_terminal()
                    && r.cold().stopped.is_some()
                    && r.cold().reset.is_none()
                {
                    r.stop_pending = true;
                    self.streams.queue_ctrl(key);
                }
            }
            SentFrame::MaxData => self.streams.max_data_lost(),
            SentFrame::MaxStreamData { key } => {
                if let Some(r) = self.streams.recv_mut(key)
                    && r.state == RecvState::Recv
                    && r.cold().stopped.is_none()
                {
                    r.resend = true;
                    self.streams.queue_ctrl(key);
                }
            }
            SentFrame::MaxStreams { dir } => {
                if dir == BIDI || dir == UNI {
                    self.streams.max_streams_lost(dir);
                }
            }
            SentFrame::DataBlocked => self.streams.data_blocked_lost(),
            SentFrame::StreamDataBlocked { key } => {
                if let Some(send) = self.streams.send_mut(key)
                    && send.blocked_reported == Some(send.max_data)
                    && send.offset >= send.max_data
                {
                    send.blocked_at = Some(send.max_data);
                    send.blocked_reported = None;
                    self.streams.queue_ctrl(key);
                }
            }
            SentFrame::StreamsBlocked { dir } => self.streams.streams_blocked_lost(dir),
            SentFrame::GoAway => {
                if let Some(sent) = self.goaway().sent {
                    self.goaway_mut().resend = Some(sent);
                }
            }
            SentFrame::PriorityUpdate { key, seq } => {
                if let Some(s) = self.streams.get_mut(key)
                    && s.extra().priority_sent.is_some_and(|(q, _)| q == seq)
                {
                    s.extra_mut().priority_resend = true;
                    self.streams.queue_ctrl(key);
                }
            }
            SentFrame::PipeStatus { pipe, seq } => {
                // Only the latest request is sent again.
                if let Some(a) = self.att_mut(pipe) {
                    a.tier_mut().request_again(seq);
                }
            }
            SentFrame::PipeAbandon { pipe } => {
                if let Some(a) = self.att_mut(pipe) {
                    a.abandon_lost();
                }
            }
            // An answer repeats on its own until this end switches.
            SentFrame::EpochAnswer { .. } => {}
            SentFrame::Ping { seq } => {
                // The request stops being outstanding with its pipe; a
                // GOAWAY fence asks again.
                if self.ping.outstanding.is_some_and(|(s, _)| s == seq) {
                    self.ping_lost();
                }
                if self.goaway().fence == Some(seq) {
                    self.goaway_mut().fence = None;
                    self.goaway_mut().fence_pending = true;
                    self.ping.request_pending = true;
                }
            }
        }
        let _ = now;
    }
}
