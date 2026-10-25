//! Lanes at the session level (MULTIPATH.md Sections 2.5, 3.6 and 5.8):
//! opening the lanes of outbound pipes and accepting the peer's, the ends
//! of lanes, and the placement of frames on the lanes of a pipe.
//!
//! A pipe is one pipe for everything else: its estimates, failure
//! detection and place in the scheduler see its cumulative
//! acknowledgement point (`pipes/lanes.rs`).

use std::time::Instant;

use super::pipes::{LaneEnd, LaneState, OutPipe};
use super::{CoreEvent, LaneId, PipeEnd, SessionCore, SessionError, State, StreamKey};

use crate::proto::Error;
use crate::proto::frame::{Frame, FrameType};
use crate::proto::record::Framing;

/// What became of a lane the peer opened (MULTIPATH.md Section 5.8).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LaneAccept {
    /// The lane belongs to the pipe: feed its bytes, from its first, to
    /// [`SessionCore::receive`] and the other receive calls.
    Accepted,
    /// It names no pipe of the session with a live inbound direction:
    /// abort reading it and do nothing else.
    Refused,
    /// It breaks the rules of the peer's lanes: the session is closing
    /// with the error; abort reading it.
    Violation,
}

impl SessionCore {
    /// The Lane Key every PIPE_LANE toward this endpoint carries
    /// (MULTIPATH.md Section 3.6): the key by which a driver routes the
    /// streams the peer opens to the session, comparing it in constant
    /// time (MULTIPATH.md Section 5.8, [`crate::proto::keys::lane_key_eq`]).
    pub fn lane_key(&self) -> Option<[u8; 16]> {
        self.local_tp().lane_key
    }

    /// The carrier of the pipe's lane 0 offers lanes (or no longer): the
    /// adapter opens further streams of its connection on
    /// [`CoreEvent::OpenLane`].
    pub fn set_pipe_lanes(&mut self, pipe: super::PipeId, offered: bool) {
        if let Some(o) = self.out_mut(pipe.0) {
            o.set_lanes_offered(offered);
        }
    }

    /// The driver attached the stream of a lane it was asked to open with
    /// [`CoreEvent::OpenLane`]: its first record, PIPE_LANE alone, goes out
    /// with the next [`SessionCore::poll_transmit`] for it. `false` when the
    /// lane was not asked for (or no longer is).
    pub fn lane_opened(&mut self, lane: LaneId, framing: Framing, now: Instant) -> bool {
        self.tick(now);
        if self.state >= State::Closing {
            return false;
        }
        self.out_mut(lane.pipe.0)
            .is_some_and(|o| o.lane_attached(lane.lane.0, framing, now))
    }

    /// Whether inbound pipe `pipe` is OPEN (STATE_MACHINE.md Section 3.2):
    /// the session is established and not closing, and the pipe is
    /// attached, takes records and has not ended. A new stream on its
    /// carrier connection may be its lane (MULTIPATH.md Section 5.5).
    pub fn inbound_open(&self, pipe: super::PipeId) -> bool {
        matches!(
            self.state,
            State::Active | State::Draining | State::Suspended
        ) && self
            .att(pipe.0)
            .and_then(super::Attachment::inp)
            .is_some_and(|p| p.state() == super::InState::Open)
    }

    /// The copy lane of outbound pipe `pipe`, while it has one open.
    pub fn copy_lane(&self, pipe: super::PipeId) -> Option<u64> {
        self.out_ref(pipe.0)?.lanes()?.copy_lane()
    }

    /// The peer's initial_max_streams_bidi, once its parameters arrived: a
    /// stream carrier's lanes on this session are at most half of it
    /// (MULTIPATH.md Section 5.8).
    pub fn peer_initial_streams_bidi(&self) -> Option<u64> {
        self.peer_tp.as_ref().map(|t| t.streams_bidi)
    }

    /// The driver did not open lane `lane` this time, which is no refusal:
    /// a carrier that shares its stream credit with the application opens
    /// a lane only when it can at once (MULTIPATH.md Section 5.8). The
    /// writer asks again at its next chance.
    pub fn lane_unopened(&mut self, lane: LaneId, now: Instant) {
        self.tick(now);
        if let Some(o) = self.out_mut(lane.pipe.0) {
            o.lane_unopened(lane.lane.0, now);
        }
    }

    /// A new stream that the peer opened on the carrier connection of the
    /// pipe's lane 0, whose first record begins with PIPE_LANE naming this
    /// session's Lane Key, the pipe and the lane (MULTIPATH.md Section 5.8;
    /// the driver checked the key and the connection). Its bytes, from its
    /// first, go to the receive calls once it is accepted.
    pub fn accept_lane(&mut self, lane: LaneId, framing: Framing, now: Instant) -> LaneAccept {
        self.tick(now);
        let (pipe, number) = (lane.pipe.0, lane.lane.0);
        if self.state >= State::Closing || !self.att(pipe).is_some_and(|a| a.in_live()) {
            return LaneAccept::Refused;
        }
        let ty = FrameType::PIPE_LANE.0;
        if self.peer_tp.is_none() || !self.features.lanes_in {
            // A frame of a feature not in use (SPEC.md Section 4.1 rule 3).
            self.protocol_error(
                Error::frame_encoding(ty, "lanes not available toward the receiver"),
                now,
            );
            return LaneAccept::Violation;
        }
        if number == 0 || number >= self.local_tp().max_lanes() {
            self.protocol_error(
                Error::protocol_violation(ty, "PIPE_LANE with a lane number out of range"),
                now,
            );
            return LaneAccept::Violation;
        }
        let max = self.local_tp().max_record_size();
        let added = self
            .inp_mut(pipe)
            .and_then(|p| p.add_lane(number, framing, max, now));
        if added.is_none() {
            self.protocol_error(
                Error::protocol_violation(ty, "PIPE_LANE for a lane already open"),
                now,
            );
            return LaneAccept::Violation;
        }
        LaneAccept::Accepted
    }

    /// A frame of the first record of an inbound lane: PIPE_LANE naming
    /// the lane, then PADDING only (MULTIPATH.md Section 5.8 reader rule
    /// 2).
    pub(super) fn on_lane_first_frame(&mut self, frame: &Frame<'_>) -> Result<(), Error> {
        let (id, li) = (self.rx, self.rx_lane);
        let key = self.lane_key();
        let Some(p) = self.inp_mut(id) else {
            return Ok(());
        };
        let number = p.lane_number(li);
        let padding = matches!(frame, Frame::Padding(_));
        let first = match p.frame_in(li, false, padding, !padding, false) {
            super::pipes::FrameIn::Process { first, .. } => first,
            super::pipes::FrameIn::Discarded => return Ok(()),
        };
        let ty = frame.frame_type().0;
        match frame {
            Frame::PipeLane(f) if first => {
                if Some(f.lane_key) == key && f.pipe_id == id && f.lane == number {
                    Ok(())
                } else {
                    Err(Error::protocol_violation(
                        ty,
                        "PIPE_LANE does not name the lane it opens",
                    ))
                }
            }
            Frame::Padding(_) if !first => Ok(()),
            _ => Err(Error::protocol_violation(
                ty,
                "a lane's first record holds a frame other than PIPE_LANE and PADDING",
            )),
        }
    }

    // ---- ends of lanes ------------------------------------------------------------

    /// Lane `li` (not 0) of inbound pipe `pipe` ended (MULTIPATH.md
    /// Sections 5.8 and 7.3, SPEC.md Section 6.6).
    pub(super) fn inbound_lane_ended(&mut self, pipe: u64, li: usize, end: PipeEnd, now: Instant) {
        let Some(p) = self.inp_mut(pipe) else {
            return;
        };
        match p.lane_ended(li, end == PipeEnd::Eof) {
            LaneEnd::Nothing => {}
            LaneEnd::Graceful => self.inbound_ended(pipe, end, true, now),
            LaneEnd::Failed => self.inbound_ended(pipe, end, false, now),
        }
    }

    /// Lane `n` (not 0) of outbound pipe `pipe` failed under us, or its
    /// stream ended or was reset: before it was confirmed it is refused,
    /// which costs the pipe nothing; after, the pipe failed (MULTIPATH.md
    /// Sections 5.8 and 7.1).
    pub(super) fn outbound_lane_failed(
        &mut self,
        pipe: u64,
        n: u64,
        kind: std::io::ErrorKind,
        now: Instant,
    ) {
        let Some(o) = self.out_mut(pipe) else {
            return;
        };
        if o.refuse_lane(n) {
            return;
        }
        let confirmed = o
            .lanes()
            .and_then(|l| l.get(n))
            .is_some_and(|l| l.confirmed());
        if let Some(l) = o.lanes_mut() {
            l.lane_closed(n);
        }
        if confirmed {
            self.outbound_failed(pipe, super::PipeFailure::Carrier(kind), now);
        }
    }

    /// A write call on lane `n` (not 0) of pipe `pipe` progressed or ended
    /// (each lane's writability is reported as for a
    /// pipe).
    pub(super) fn lane_write(&mut self, pipe: u64, n: u64, write: &super::PipeWrite, now: Instant) {
        self.tick(now);
        if write.end.is_none() {
            return;
        }
        if let Some(o) = self.out_mut(pipe) {
            o.lane_write(n, write.refused, now);
        }
    }

    // ---- opening lanes ----------------------------------------------------------

    /// Asks the driver for the next lane of outbound pipe `pipe` when one
    /// may be opened (MULTIPATH.md Section 5.8): the peer's Max Lanes
    /// allows it, its carrier offers lanes, lane 0 has an acknowledged
    /// position and no lane is unconfirmed or was refused.
    pub(super) fn request_lane(&mut self, pipe: u64) {
        let Some(max) = self.peer_tp.as_ref().map(|t| t.max_lanes()) else {
            return;
        };
        if self.state >= State::Closing || self.peer_lane_key().is_none() {
            return;
        }
        let now = self.now;
        let Some(o) = self.out_mut(pipe).filter(|o| o.may_open_lane(max, now)) else {
            return;
        };
        let n = o.request_lane();
        self.push_event(CoreEvent::OpenLane(super::PipeId(pipe).lane(n)));
    }

    /// Whether the session's streams are delivered independently: it uses
    /// more than one pipe, or its pipe has lanes. A stream of such a
    /// session is a carrier whose lanes pay off.
    pub fn carries_independent_streams(&self) -> bool {
        self.atts.iter().filter(|a| a.out_live()).count() > 1
            || self.atts.iter().any(|a| {
                a.out().is_some_and(|o| o.lane_count() > 1)
                    || a.inp().is_some_and(|p| p.lane_count() > 1)
            })
    }

    /// The peer's Lane Key, which our PIPE_LANE frames carry, while lanes
    /// are available toward it.
    pub(super) fn peer_lane_key(&self) -> Option<[u8; 16]> {
        if !self.features.lanes_out {
            return None;
        }
        self.peer_tp.as_ref()?.lane_key
    }

    /// When an opening lane is due to be refused for not being confirmed
    /// within the handshake timeout (MULTIPATH.md Section 5.8).
    pub(super) fn lanes_deadline(&self) -> Option<Instant> {
        let timeout = self.config.handshake_timeout;
        self.atts
            .outs()
            .filter_map(|o| o.lanes()?.opening_since())
            .filter_map(|(_, t)| t.checked_add(timeout))
            .min()
    }

    /// Refuses the lanes not confirmed within the handshake timeout: the
    /// driver resets them.
    pub(super) fn lanes_timeouts(&mut self, now: Instant) {
        let timeout = self.config.handshake_timeout;
        for i in 0..self.atts.len() {
            let a = self.atts.at(i);
            let pipe = a.id();
            let Some((n, since)) = a.out().and_then(|o| o.lanes()?.opening_since()) else {
                continue;
            };
            if since.checked_add(timeout).is_none_or(|t| now < t) {
                continue;
            }
            if let Some(o) = self.atts.at_mut(i).out_mut() {
                o.refuse_lane(n);
            }
            self.push_event(CoreEvent::ResetLane(super::PipeId(pipe).lane(n)));
        }
    }

    // ---- placement -------------------------------------

    /// The lane of outbound pipe `o` stream direction `key` writes on now:
    /// the lane it is bound to while its data there is unacknowledged;
    /// lane 0 for the directions that go there (urgent, or sent
    /// redundantly); else the confirmed data lane with the fewest bound
    /// directions, then the fewest unacknowledged bytes; lane 0 while
    /// there is none. A pipe without lanes is its lane 0.
    pub(super) fn lane_for(&self, o: &OutPipe, key: StreamKey) -> u64 {
        let Some(lanes) = o.lanes() else {
            return 0;
        };
        if let Some(n) = lanes.bound(key) {
            return n;
        }
        // Outside multipath a direction with data on lane 0 from before the
        // pipe had lanes stays there until it is acknowledged (MULTIPATH.md
        // Section 5.8).
        if self.on_lane_zero(key) || (self.mp.is_none() && lanes.before_unacked()) {
            return 0;
        }
        lanes
            .iter()
            .filter(|&(n, _)| lanes.data_lane(n))
            .map(|(n, _)| (lanes.bound_on(n), lanes.unacked(n), n))
            .min()
            .map_or(0, |(_, _, n)| n)
    }

    /// Whether a direction that is not bound goes on lane 0: urgency 0 to
    /// 2 outside multipath (which sends nothing twice), a direction sent
    /// redundantly in a multipath session.
    fn on_lane_zero(&self, key: StreamKey) -> bool {
        let Some(send) = self.streams.send(key) else {
            return true;
        };
        if self.mp.is_some() {
            self.redundant(send)
        } else {
            send.priority.urgency() <= 2
        }
    }

    /// Whether a direction that is not bound would need a data lane that
    /// the pipe does not have free: every data lane has a bound direction
    /// (or there is none), so the writer opens one.
    pub(super) fn wants_data_lane(&self, o: &OutPipe, key: StreamKey) -> bool {
        if self.on_lane_zero(key) {
            return false;
        }
        match o.lanes() {
            None => true,
            Some(lanes) => {
                lanes.bound(key).is_none()
                    && lanes
                        .iter()
                        .filter(|&(n, _)| lanes.data_lane(n))
                        .all(|(n, _)| lanes.bound_on(n) > 0)
            }
        }
    }

    /// Notes that the batch being written carries a STREAM frame of `key`:
    /// it binds to the batch's lane while the pipe has lanes.
    #[inline]
    pub(super) fn note_lane_frame(&mut self, key: StreamKey) {
        if self.tx_lanes
            && let Some(l) = self.out_mut(self.tx).and_then(OutPipe::lanes_mut)
        {
            l.note(key);
        }
    }

    /// Whether the session's state lets lane `n` of `o` write data: it is
    /// confirmed, attached and not shut.
    pub(super) fn lane_open(o: &OutPipe, n: u64) -> bool {
        n == 0
            || o.lanes()
                .and_then(|l| l.get(n))
                .is_some_and(|l| l.state() == LaneState::Confirmed && !l.writes_ended())
    }

    // ---- the orderly close outside multipath (SPEC.md Section 6.5) ---------------

    /// Whether an orderly CONNECTION_CLOSE of a session without multipath
    /// waits for a PIPE_ACK to cover the other lanes of its pipe (SPEC.md
    /// Section 6.5 step 1): the peer would otherwise discard data that
    /// SPEC.md Section 7.4 counts as delivered.
    pub(super) fn close_waiting(&self) -> bool {
        self.mp.is_none()
            && self
                .out_ref(0)
                .and_then(OutPipe::lanes)
                .is_some_and(|l| l.close_wait().is_some())
    }

    /// The close starts: an orderly one (no error, or the application's)
    /// of a session without multipath waits for the other lanes, at most
    /// `until`.
    pub(super) fn start_close_wait(&mut self, until: Instant) {
        let remote = self.error.as_deref().is_some_and(SessionError::is_remote);
        let orderly = match self.close.as_deref() {
            Some(super::CloseFrame::Application { .. }) => true,
            Some(super::CloseFrame::Transport { code, .. }) => *code == 0,
            None => false,
        };
        if self.mp.is_some() || remote || !orderly {
            return;
        }
        if let Some(l) = self.out_mut(0).and_then(OutPipe::lanes_mut)
            && !l.others_covered()
        {
            l.wait_close(until);
        }
    }

    /// The close waits no longer: the other lanes are covered, the wait
    /// is over, or the peer's CONNECTION_CLOSE arrived.
    pub(super) fn end_close_wait(&mut self) {
        if let Some(l) = self.out_mut(0).and_then(OutPipe::lanes_mut) {
            l.end_close_wait();
        }
    }

    /// When the close stops waiting for the other lanes.
    pub(super) fn close_wait_deadline(&self) -> Option<Instant> {
        self.out_ref(0)?.lanes()?.close_wait()
    }

    /// A lane's position moved on the single pipe: the directions it
    /// released send the control frames of their sending parts that waited
    /// for it, on lane 0 now; the close may stop waiting.
    pub(super) fn single_lane_acked(&mut self, _now: Instant) {
        let released = self
            .out_mut(0)
            .and_then(OutPipe::lanes_mut)
            .map(|l| l.take_released())
            .unwrap_or_default();
        for key in released {
            if self.send_ctrl_owed(key) {
                self.streams.queue_ctrl(key);
            }
        }
        if self
            .out_ref(0)
            .and_then(OutPipe::lanes)
            .is_some_and(|l| l.close_wait().is_some() && l.others_covered())
        {
            self.end_close_wait();
        }
    }

    /// Outside multipath, whether the control frames of `key`'s sending
    /// part (STREAM_DATA_BLOCKED, its reset) wait because its frames are
    /// on another lane than the batch's until a PIPE_ACK covers them
    /// (MULTIPATH.md Section 5.8).
    pub(super) fn send_ctrl_elsewhere(&self, key: StreamKey) -> bool {
        self.tx_lanes
            && self.mp.is_none()
            && self
                .out_ref(self.tx)
                .and_then(OutPipe::lanes)
                .and_then(|l| l.bound(key))
                .is_some_and(|n| n != self.tx_lane)
    }

    /// Whether `key`'s sending part owes a control frame: a
    /// STREAM_DATA_BLOCKED or its reset.
    fn send_ctrl_owed(&self, key: StreamKey) -> bool {
        self.streams.send(key).is_some_and(|send| {
            send.blocked_at.is_some() || send.cold().reset.is_some_and(|r| !r.written)
        })
    }
}

/// The positions of the lanes of a pipe's directions, by lane number;
/// empty when neither direction has lanes.
pub(super) fn lane_infos(
    o: Option<&OutPipe>,
    i: Option<&super::pipes::InPipe>,
) -> Vec<super::LaneStats> {
    let out = o.and_then(OutPipe::lanes);
    let inp = i.filter(|p| p.lane_count() > 1);
    if out.is_none() && inp.is_none() {
        return Vec::new();
    }
    let mut lanes: Vec<super::LaneStats> = Vec::new();
    fn at(lanes: &mut Vec<super::LaneStats>, n: u64) -> &mut super::LaneStats {
        let k = match lanes.binary_search_by_key(&n, |l| l.lane.0) {
            Ok(k) => k,
            Err(k) => {
                lanes.insert(
                    k,
                    super::LaneStats {
                        lane: super::Lane(n),
                        position_sent: None,
                        position_acked: None,
                        position_received: None,
                    },
                );
                k
            }
        };
        &mut lanes[k]
    }
    if let Some(o) = o {
        let numbers =
            std::iter::once(0).chain(out.into_iter().flat_map(|l| l.iter().map(|(n, _)| n)));
        for n in numbers {
            let x = at(&mut lanes, n);
            x.position_sent = Some(o.sent_on(n));
            x.position_acked = Some(o.acked_on(n));
        }
    }
    if let Some(p) = i {
        for (n, pos) in p.lane_positions() {
            at(&mut lanes, n).position_received = Some(pos);
        }
    }
    lanes
}
