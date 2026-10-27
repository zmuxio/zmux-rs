//! The lanes of a pipe direction (MULTIPATH.md Section 2.5): further
//! streams of the carrier connection of the pipe's lane 0, each a record
//! stream with its own position.
//!
//! A direction without lanes is its lane 0 and keeps no state here: its
//! position is the pipe's. The state of lanes 1, 2, ... is allocated when
//! the first of them is opened (outbound) or accepted (inbound).
//!
//! Outbound, the pipe numbers the bytes it hands to its lanes in one send
//! order (the first record of a lane, its PIPE_LANE, excluded); the
//! pipe's acknowledged position is the cumulative acknowledgement point,
//! the send-order number of its oldest unacknowledged byte, so that
//! everything that sees the pipe as a whole works with lanes as without.
//! Each lane maps its unacknowledged batches to the send order, and keeps
//! the frames it carried, acknowledged by its own position.

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

use super::{QueuedCopy, SentFrame};
use crate::proto::record::Framing;
use crate::proto::session::stream::StreamKey;

// ---- outbound ------------------------------------------------------------------

/// Where an outbound lane stands (MULTIPATH.md Section 5.8).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LaneState {
    /// Asked of the driver, which has not attached a stream yet (it may
    /// wait for the carrier's stream credit).
    Requested,
    /// Attached: its first record holds PIPE_LANE alone, and nothing else
    /// goes on it until it is confirmed; since when.
    Opening(Instant),
    /// A PIPE_ACK acknowledged a position above 0 on it.
    Confirmed,
    /// Ended, reset or failed before it was confirmed, or not confirmed
    /// within the handshake timeout: no event of the pipe, and the pipe
    /// opens no further lane.
    Refused,
}

/// A batch of the pipe's send order written on a lane and not yet wholly
/// acknowledged.
#[derive(Debug, Clone, Copy)]
struct Seg {
    /// The lane position after the batch.
    lane_end: u64,
    /// The send-order number of its first byte, and its length.
    order: u64,
    len: u64,
}

/// The position of a lane and the map of its unacknowledged bytes to the
/// pipe's send order.
#[derive(Debug, Default)]
pub(crate) struct LaneTx {
    /// Bytes written on the lane, its first record included.
    sent: u64,
    /// The largest position acknowledged on it.
    acked: u64,
    segs: VecDeque<Seg>,
    /// The bytes of `segs`.
    seg_bytes: u64,
}

impl LaneTx {
    /// A lane 0 that carried send-order bytes up to `sent`, acknowledged up
    /// to `acked`, before the pipe had lanes: positions and order agree.
    fn identity(sent: u64, acked: u64) -> Self {
        let mut segs = VecDeque::new();
        if sent > acked {
            segs.push_back(Seg {
                lane_end: sent,
                order: acked,
                len: sent - acked,
            });
        }
        Self {
            sent,
            acked,
            segs,
            seg_bytes: sent - acked.min(sent),
        }
    }

    /// A batch of `len` bytes of the send order from `order` went on the
    /// lane.
    fn wrote(&mut self, order: u64, len: u64) {
        self.sent += len;
        self.seg_bytes += len;
        self.segs.push_back(Seg {
            lane_end: self.sent,
            order,
            len,
        });
    }

    /// The send-order number of the lane's oldest unacknowledged byte;
    /// `None` when every byte of the send order on it is acknowledged.
    fn floor(&self) -> Option<u64> {
        let s = self.segs.front()?;
        let start = s.lane_end - s.len;
        Some(s.order + self.acked.saturating_sub(start))
    }

    /// The position advanced to `pos` (not beyond the bytes written):
    /// whether it moved.
    fn ack(&mut self, pos: u64) -> bool {
        if pos <= self.acked {
            return false;
        }
        self.acked = pos;
        while let Some(s) = self.segs.front().filter(|s| s.lane_end <= pos) {
            self.seg_bytes -= s.len;
            self.segs.pop_front();
        }
        true
    }

    /// Send-order bytes on the lane not yet acknowledged.
    fn unacked(&self) -> u64 {
        let start = self.segs.front().map_or(0, |s| s.lane_end - s.len);
        self.seg_bytes - self.acked.saturating_sub(start).min(self.seg_bytes)
    }

    #[inline]
    pub(crate) fn sent(&self) -> u64 {
        self.sent
    }

    #[inline]
    pub(crate) fn acked(&self) -> u64 {
        self.acked
    }

    fn heap_bytes(&self) -> usize {
        self.segs.capacity() * size_of::<Seg>()
    }

    /// The pipe failed: nothing waits for acknowledgement any more.
    fn forget(&mut self) {
        self.segs = VecDeque::new();
        self.seg_bytes = 0;
    }
}

/// An outbound lane other than lane 0.
#[derive(Debug)]
pub(crate) struct OutLane {
    state: LaneState,
    framing: Framing,
    tx: LaneTx,
    /// The first record, PIPE_LANE alone, is still to be written.
    first_owed: bool,
    /// The frames it carried that are retained (MULTIPATH.md Section 7.4),
    /// with the send-order position after their record.
    log: VecDeque<(u64, SentFrame)>,
    /// The carrier stream takes bytes, and what it holds unsent.
    writable: bool,
    unsent: u64,
    /// Since when the carrier stream refuses bytes it was given (its write
    /// stall, MULTIPATH.md Section 7.1).
    refused_since: Option<Instant>,
    /// The driver was told to shut the lane down or to reset it, or wrote
    /// its last batch; the stream failed or ended under us.
    shutdown_reported: bool,
    out_closed: bool,
}

/// The lanes of an outbound pipe, lane 0's lane-side state included.
#[derive(Debug)]
pub(crate) struct OutLanes {
    zero: LaneTx,
    /// The send order written before the pipe had lanes, all on lane 0:
    /// whose directions are not bound.
    before: u64,
    /// What lane 0's carrier holds unsent, when it reports it.
    zero_unsent: u64,
    /// Lanes 1, 2, ...: lane n at index n - 1 (numbers are given in
    /// order and each once, MULTIPATH.md Section 5.8).
    lanes: Vec<OutLane>,
    /// The last write of any lane, lane 0 included, that the carrier
    /// took bytes of: no lane's stall is longer than the time since
    /// (MULTIPATH.md Section 7.1).
    progress: Option<Instant>,
    /// A lane was not opened (no refusal): none is requested before this.
    retry_at: Option<Instant>,
    /// A lane was refused: no further lane is opened.
    closed: bool,
    refused: u64,
    /// The lane each bound stream direction is on, and the directions of each
    /// lane by number, with the
    /// send-order position up to which they stay.
    lane_of: HashMap<StreamKey, u64>,
    by_lane: Vec<Vec<(StreamKey, u64)>>,
    /// Directions whose binding ended since the session last looked.
    released: Vec<StreamKey>,
    /// The directions whose STREAM frames the batch being written
    /// carries: they bind to its lane.
    batch: Vec<StreamKey>,
    /// The copy lane: it pairs with
    /// lane 0 for the redundant chunks of a tier whose only usable pipe
    /// this is, and no data direction binds to it. A lane is wanted for it
    /// while the next confirmed lane is to become it; the copies queued for
    /// it.
    copy_lane: Option<u64>,
    copy_wanted: bool,
    copies: VecDeque<QueuedCopy>,
    /// Outside multipath, the orderly CONNECTION_CLOSE waits until a
    /// PIPE_ACK covers the other lanes, at most until then (SPEC.md
    /// Section 6.5 step 1).
    close_wait: Option<Instant>,
    /// The held bytes and their minimum over the last RTT_base_p.
    held: HeldBytes,
}

/// The held bytes of a pipe with lanes: send-order bytes acknowledged on
/// their own lane but beyond the cumulative acknowledgement point, and
/// their minimum over a sliding window.
///
/// The window is a monotone deque of (time, count) with increasing counts:
/// a new count drops the entries at or above it, and the front goes only
/// while the entry after it began at or before the window's start, so the
/// count in force when the window began still counts.
#[derive(Debug, Default)]
pub(crate) struct HeldBytes {
    count: u64,
    window: VecDeque<(Instant, u64)>,
}

impl HeldBytes {
    /// The count changed to `count` at `now`, the window being `span`.
    fn set(&mut self, now: Instant, count: u64, span: Duration) {
        if count == self.count && !self.window.is_empty() {
            return;
        }
        if self.window.is_empty() {
            // The count so far was in force until now.
            self.window.push_back((now, self.count));
        }
        self.count = count;
        // An entry equal to the new count keeps its earlier start: the
        // count has been at least that since then.
        while self.window.back().is_some_and(|&(_, c)| c > count) {
            self.window.pop_back();
        }
        if self.window.back().is_none_or(|&(_, c)| c < count) {
            self.window.push_back((now, count));
        }
        let start = now.checked_sub(span);
        while self.window.len() > 1
            && start.is_some_and(|s| self.window.get(1).is_some_and(|&(t, _)| t <= s))
        {
            self.window.pop_front();
        }
    }

    /// The held bytes now.
    pub(crate) fn count(&self) -> u64 {
        self.count
    }

    /// The smallest count at any moment of the last `span` before `now`:
    /// the counts rise along the deque, so it is the one in force at the
    /// window's start.
    pub(crate) fn min(&self, now: Instant, span: Duration) -> u64 {
        let Some(start) = now.checked_sub(span) else {
            return self.window.front().map_or(self.count, |&(_, c)| c);
        };
        let after = self.window.partition_point(|&(t, _)| t <= start);
        self.window
            .get(after.saturating_sub(1))
            .map_or(self.count, |&(_, c)| c)
    }
}

impl OutLanes {
    /// The lanes of a pipe that carried its send order on lane 0 alone up
    /// to `sent`, acknowledged up to `acked`, its carrier holding `unsent`.
    pub(crate) fn new(sent: u64, acked: u64, unsent: u64) -> Self {
        Self {
            zero: LaneTx::identity(sent, acked),
            before: sent,
            zero_unsent: unsent,
            lanes: Vec::new(),
            progress: None,
            retry_at: None,
            closed: false,
            refused: 0,
            lane_of: HashMap::new(),
            by_lane: Vec::new(),
            released: Vec::new(),
            batch: Vec::new(),
            copy_lane: None,
            copy_wanted: false,
            copies: VecDeque::new(),
            close_wait: None,
            held: HeldBytes::default(),
        }
    }

    /// The held bytes.
    pub(crate) fn held(&self) -> &HeldBytes {
        &self.held
    }

    /// Takes the held bytes again after an acknowledgement at `now`: of
    /// the send order up to `sent`, what is beyond the cumulative point and
    /// no longer unacknowledged on its lane, the window being `span`.
    pub(crate) fn note_held(&mut self, sent: u64, now: Instant, span: Duration) {
        let txs = || std::iter::once(&self.zero).chain(self.lanes.iter().map(|l| &l.tx));
        let cum = txs().filter_map(LaneTx::floor).min().unwrap_or(sent);
        let unacked: u64 = txs().map(LaneTx::unacked).sum();
        let count = sent.saturating_sub(cum).saturating_sub(unacked);
        self.held.set(now, count, span);
    }

    pub(crate) fn heap_bytes(&self) -> usize {
        use std::mem::size_of;
        size_of::<Self>()
            + self.zero.heap_bytes()
            + self.lanes.capacity() * size_of::<OutLane>()
            + self
                .lanes
                .iter()
                .map(|l| l.tx.heap_bytes() + l.log.capacity() * size_of::<(u64, SentFrame)>())
                .sum::<usize>()
            + self.lane_of.capacity() * (size_of::<(StreamKey, u64)>() + 1)
            + self.by_lane.capacity() * size_of::<Vec<(StreamKey, u64)>>()
            + self
                .by_lane
                .iter()
                .map(|v| v.capacity() * size_of::<(StreamKey, u64)>())
                .sum::<usize>()
            + (self.released.capacity() + self.batch.capacity()) * size_of::<StreamKey>()
            + self.copies.capacity() * size_of::<QueuedCopy>()
            + self.held.window.capacity() * size_of::<(Instant, u64)>()
    }

    /// The lanes, lane 0 excluded, opened so far (refused ones included).
    #[inline]
    pub(crate) fn opened(&self) -> u64 {
        self.lanes.len() as u64
    }

    /// The number the next lane gets.
    #[inline]
    pub(crate) fn next_number(&self) -> u64 {
        self.lanes.len() as u64 + 1
    }

    /// Lanes refused so far.
    #[inline]
    pub(crate) fn refused(&self) -> u64 {
        self.refused
    }

    /// No further lane may be opened (one was refused).
    #[inline]
    pub(crate) fn closed(&self) -> bool {
        self.closed
    }

    /// A lane is requested or opening: at most one is (MULTIPATH.md
    /// Section 5.8).
    pub(crate) fn unconfirmed(&self) -> Option<u64> {
        self.lanes
            .iter()
            .position(|l| matches!(l.state, LaneState::Requested | LaneState::Opening(_)))
            .map(|i| i as u64 + 1)
    }

    /// The handshake deadline reference of the opening lane.
    pub(crate) fn opening_since(&self) -> Option<(u64, Instant)> {
        self.lanes
            .iter()
            .enumerate()
            .find_map(|(i, l)| match l.state {
                LaneState::Opening(t) => Some((i as u64 + 1, t)),
                _ => None,
            })
    }

    /// Lane `n` (not 0).
    #[inline]
    pub(crate) fn get(&self, n: u64) -> Option<&OutLane> {
        usize::try_from(n.checked_sub(1)?)
            .ok()
            .and_then(|i| self.lanes.get(i))
    }

    #[inline]
    fn get_mut(&mut self, n: u64) -> Option<&mut OutLane> {
        usize::try_from(n.checked_sub(1)?)
            .ok()
            .and_then(|i| self.lanes.get_mut(i))
    }

    /// The lanes, numbered from 1.
    pub(crate) fn iter(&self) -> impl Iterator<Item = (u64, &OutLane)> {
        self.lanes
            .iter()
            .enumerate()
            .map(|(i, l)| (i as u64 + 1, l))
    }

    /// Requests the next lane of the driver: its number.
    pub(crate) fn request(&mut self) -> u64 {
        self.lanes.push(OutLane {
            state: LaneState::Requested,
            framing: Framing::ByteStream,
            tx: LaneTx::default(),
            first_owed: false,
            log: VecDeque::new(),
            writable: true,
            unsent: 0,
            refused_since: None,
            shutdown_reported: false,
            out_closed: false,
        });
        self.lanes.len() as u64
    }

    /// The driver did not open requested lane `n` this time (its carrier
    /// had no stream for it now): the request goes, and the number is
    /// requested again with the next one, as the peer never saw it.
    /// It is not requested again before `retry_at`.
    pub(crate) fn unrequest(&mut self, n: u64, retry_at: Instant) -> bool {
        let last = self.lanes.len() as u64 == n
            && self
                .lanes
                .last()
                .is_some_and(|l| l.state == LaneState::Requested);
        if last {
            self.lanes.pop();
            self.retry_at = Some(retry_at);
        }
        last
    }

    /// Whether a lane may be requested at `now` (after one not opened).
    pub(crate) fn retry_due(&self, now: Instant) -> bool {
        self.retry_at.is_none_or(|t| now >= t)
    }

    /// The driver attached the stream of requested lane `n`: its first
    /// record is owed. `false` when `n` is not a requested lane.
    pub(crate) fn attach(&mut self, n: u64, framing: Framing, now: Instant) -> bool {
        match self.get_mut(n) {
            Some(l) if l.state == LaneState::Requested => {
                l.state = LaneState::Opening(now);
                l.framing = framing;
                l.first_owed = true;
                true
            }
            _ => false,
        }
    }

    /// Lane `n` ended before it was confirmed: it is refused, and no
    /// further lane is opened. `false` when it was not unconfirmed.
    pub(crate) fn refuse(&mut self, n: u64) -> bool {
        let Some(l) = self.get_mut(n) else {
            return false;
        };
        if !matches!(l.state, LaneState::Requested | LaneState::Opening(_)) {
            return false;
        }
        l.state = LaneState::Refused;
        l.out_closed = true;
        l.first_owed = false;
        self.closed = true;
        self.refused += 1;
        true
    }

    /// The lane-side state of lane `n`, lane 0 included.
    pub(crate) fn tx(&self, n: u64) -> Option<&LaneTx> {
        if n == 0 {
            Some(&self.zero)
        } else {
            self.get(n).map(|l| &l.tx)
        }
    }

    fn tx_mut(&mut self, n: u64) -> Option<&mut LaneTx> {
        if n == 0 {
            Some(&mut self.zero)
        } else {
            self.get_mut(n).map(|l| &mut l.tx)
        }
    }

    /// A batch of the send order went on lane `n`.
    pub(crate) fn wrote(&mut self, n: u64, order: u64, len: u64) {
        if let Some(t) = self.tx_mut(n) {
            t.wrote(order, len);
        }
    }

    /// The first record of lane `n`, PIPE_LANE alone, was written: `len`
    /// bytes of the lane outside the send order.
    pub(crate) fn wrote_first(&mut self, n: u64, len: u64) {
        if let Some(l) = self.get_mut(n) {
            l.tx.sent += len;
            l.first_owed = false;
        }
    }

    /// Lane `n`'s position advanced to `pos`; whether it moved. An opening
    /// lane is confirmed by it; a refused lane's acknowledgement is
    /// ignored.
    pub(crate) fn ack(&mut self, n: u64, pos: u64) -> bool {
        if let Some(l) = self.get_mut(n) {
            match l.state {
                LaneState::Refused => return false,
                LaneState::Opening(_) if pos > 0 => {
                    l.state = LaneState::Confirmed;
                    if std::mem::take(&mut self.copy_wanted) && self.copy_lane.is_none() {
                        self.copy_lane = Some(n);
                    }
                }
                _ => {}
            }
        }
        let moved = self.tx_mut(n).is_some_and(|t| t.ack(pos));
        if moved {
            let floor = self.floor_of(n);
            let (released, lane_of) = (&mut self.released, &mut self.lane_of);
            if let Some(bound) = usize::try_from(n)
                .ok()
                .and_then(|i| self.by_lane.get_mut(i))
            {
                bound.retain(|&(key, until)| {
                    let keep = floor.is_some_and(|f| until > f);
                    if !keep {
                        lane_of.remove(&key);
                        released.push(key);
                    }
                    keep
                });
            }
        }
        moved
    }

    /// The send-order number of lane `n`'s oldest unacknowledged byte, if
    /// any.
    pub(crate) fn floor_of(&self, n: u64) -> Option<u64> {
        self.tx(n).and_then(LaneTx::floor)
    }

    /// The cumulative acknowledgement point given the pipe's send order up
    /// to `sent` (MULTIPATH.md Section 2.5).
    pub(crate) fn cumulative(&self, sent: u64) -> u64 {
        std::iter::once(&self.zero)
            .chain(self.lanes.iter().map(|l| &l.tx))
            .filter_map(LaneTx::floor)
            .min()
            .unwrap_or(sent)
    }

    /// Send-order bytes unacknowledged on lane `n`.
    pub(crate) fn unacked(&self, n: u64) -> u64 {
        self.tx(n).map_or(0, LaneTx::unacked)
    }

    pub(crate) fn log_mut(&mut self, n: u64) -> Option<&mut VecDeque<(u64, SentFrame)>> {
        self.get_mut(n).map(|l| &mut l.log)
    }

    /// Every lane's retained frames, lane 0 excluded.
    pub(crate) fn logs(&self) -> impl Iterator<Item = (u64, &VecDeque<(u64, SentFrame)>)> {
        self.iter().map(|(n, l)| (n, &l.log))
    }

    /// The pipe failed: the retained state goes.
    pub(crate) fn forget(&mut self) {
        for l in &mut self.lanes {
            l.log = VecDeque::new();
            l.tx.forget();
        }
        self.zero.forget();
        self.lane_of = HashMap::new();
        self.by_lane = Vec::new();
        self.copies = VecDeque::new();
        self.held = HeldBytes::default();
        self.closed = true;
    }

    /// Whether a PIPE_ACK covers every record written on the lanes other
    /// than lane 0 (refused ones aside).
    pub(crate) fn others_covered(&self) -> bool {
        self.lanes
            .iter()
            .filter(|l| l.state != LaneState::Refused)
            .all(|l| l.tx.acked >= l.tx.sent)
    }

    /// The orderly close waits for the other lanes until `until`.
    pub(crate) fn wait_close(&mut self, until: Instant) {
        self.close_wait = Some(until);
    }

    /// Until when the orderly close waits, while it does.
    pub(crate) fn close_wait(&self) -> Option<Instant> {
        self.close_wait
    }

    /// The close waits no longer.
    pub(crate) fn end_close_wait(&mut self) {
        self.close_wait = None;
    }

    // ---- write progress of the lanes ---------------------------------------------

    /// What lane `n`'s carrier holds unsent; returns the pipe's sum (Q_p).
    pub(crate) fn set_unsent(&mut self, n: u64, bytes: u64) -> u64 {
        if n == 0 {
            self.zero_unsent = bytes;
        } else if let Some(l) = self.get_mut(n) {
            l.unsent = bytes;
        }
        self.zero_unsent + self.lanes.iter().map(|l| l.unsent).sum::<u64>()
    }

    /// A write to lane `n` (not 0) ended at `now`: the carrier stream
    /// took bytes, or refused them.
    pub(crate) fn set_writable(&mut self, n: u64, writable: bool, now: Instant) {
        if let Some(l) = self.get_mut(n) {
            l.writable = writable;
            if writable {
                l.refused_since = None;
            } else {
                l.refused_since.get_or_insert(now);
            }
        }
        if writable {
            self.progress = Some(now);
        }
    }

    /// A write to lane 0 that the carrier took bytes of ended at `now`.
    pub(crate) fn zero_progress(&mut self, now: Instant) {
        self.progress = Some(now);
    }

    /// The write stall of the pipe's lanes (MULTIPATH.md Section 7.1):
    /// each lane with bytes waiting is a carrier of its own, the pipe's
    /// stall is the shortest of theirs and no longer than the time since
    /// any lane progressed. `zero` is lane 0's stall reference, if it has
    /// one; a lane that takes bytes has none, and then neither has the
    /// pipe unless lane 0 has. Returns the reference time.
    pub(crate) fn stall_from(&self, zero: Option<Instant>) -> Option<Instant> {
        let stalled = self
            .lanes
            .iter()
            .filter(|l| !l.out_closed && !l.shutdown_reported)
            .filter_map(|l| l.refused_since);
        let from = zero.into_iter().chain(stalled).max()?;
        Some(self.progress.map_or(from, |p| from.max(p)))
    }

    /// The driver will not write lane `n` any more: its carrier failed or
    /// ended under us, or it was told to shut it down.
    pub(crate) fn lane_closed(&mut self, n: u64) {
        if let Some(l) = self.get_mut(n) {
            l.out_closed = true;
        }
    }

    /// Lane `n`'s last batch, with the shutdown, was written.
    pub(crate) fn shutdown_written(&mut self, n: u64) {
        if let Some(l) = self.get_mut(n) {
            l.shutdown_reported = true;
        }
    }

    // ---- the copy lane ------------------------

    /// The copy lane, while it is open.
    pub(crate) fn copy_lane(&self) -> Option<u64> {
        self.copy_lane.filter(|&n| {
            self.get(n)
                .is_some_and(|l| l.confirmed() && !l.writes_ended())
        })
    }

    /// Finds the copy lane: the lowest-numbered confirmed lane with no
    /// bound direction; `None`, and the next confirmed lane is to become
    /// it, when there is none.
    pub(crate) fn find_copy_lane(&mut self) -> Option<u64> {
        if let Some(n) = self.copy_lane() {
            return Some(n);
        }
        let free = self
            .iter()
            .find(|(n, l)| l.confirmed() && !l.writes_ended() && self.bound_on(*n) == 0)
            .map(|(n, _)| n);
        self.copy_lane = free;
        self.copy_wanted = free.is_none();
        free
    }

    /// The next lane confirmed becomes the copy lane.
    pub(crate) fn want_copy_lane(&mut self) {
        if self.copy_lane().is_none() {
            self.copy_wanted = true;
        }
    }

    /// Whether lane `n` is a data lane: confirmed, open, and not the copy
    /// lane.
    pub(crate) fn data_lane(&self, n: u64) -> bool {
        self.copy_lane != Some(n)
            && self
                .get(n)
                .is_some_and(|l| l.confirmed() && !l.writes_ended())
    }

    pub(crate) fn copies(&self, n: u64) -> Option<&VecDeque<QueuedCopy>> {
        (self.copy_lane == Some(n)).then_some(&self.copies)
    }

    pub(crate) fn copies_mut(&mut self, n: u64) -> Option<&mut VecDeque<QueuedCopy>> {
        (self.copy_lane == Some(n)).then_some(&mut self.copies)
    }

    // ---- bindings -------------------------------------

    /// Whether lane 0 still has unacknowledged bytes written before the
    /// pipe had lanes, whose directions were not bound to it.
    pub(crate) fn before_unacked(&self) -> bool {
        self.zero.floor().is_some_and(|f| f < self.before)
    }

    /// The lane `key` is bound to, if any.
    #[inline]
    pub(crate) fn bound(&self, key: StreamKey) -> Option<u64> {
        if self.lane_of.is_empty() {
            return None;
        }
        self.lane_of.get(&key).copied()
    }

    /// The directions bound to lane `n`.
    #[inline]
    pub(crate) fn bound_on(&self, n: u64) -> usize {
        usize::try_from(n)
            .ok()
            .and_then(|i| self.by_lane.get(i))
            .map_or(0, Vec::len)
    }

    /// The batch being written carries a STREAM frame of `key` (a direction
    /// listed twice binds once).
    #[inline]
    pub(crate) fn note(&mut self, key: StreamKey) {
        if self.batch.last() != Some(&key) {
            self.batch.push(key);
        }
    }

    /// The batch went on lane `n`, up to send-order position `end`: the
    /// directions it carried stay on the lane until that is acknowledged.
    pub(crate) fn bind_batch(&mut self, n: u64, end: u64) {
        let mut keys = std::mem::take(&mut self.batch);
        for &k in &keys {
            self.bind(k, n, end);
        }
        keys.clear();
        self.batch = keys;
    }

    /// `key` wrote a frame on lane `n` whose record ends at send-order
    /// position `until`: it stays on the lane until that is acknowledged.
    fn bind(&mut self, key: StreamKey, n: u64, until: u64) {
        let Ok(i) = usize::try_from(n) else {
            return;
        };
        if self.by_lane.len() <= i {
            self.by_lane.resize_with(i + 1, Vec::new);
        }
        match self.lane_of.get(&key) {
            Some(&lane) => {
                debug_assert_eq!(lane, n, "a bound direction moved");
                if let Some(b) = self.by_lane[i].iter_mut().find(|b| b.0 == key) {
                    b.1 = b.1.max(until);
                }
            }
            None => {
                self.lane_of.insert(key, n);
                self.by_lane[i].push((key, until));
            }
        }
    }

    /// The directions whose binding ended since the last call.
    pub(crate) fn take_released(&mut self) -> Vec<StreamKey> {
        std::mem::take(&mut self.released)
    }

    /// Forgets the directions whose binding ended (a multipath session
    /// needs no list of them).
    pub(crate) fn clear_released(&mut self) {
        self.released.clear();
    }
}

impl OutLane {
    #[inline]
    pub(crate) fn state(&self) -> LaneState {
        self.state
    }

    #[inline]
    pub(crate) fn confirmed(&self) -> bool {
        self.state == LaneState::Confirmed
    }

    #[inline]
    pub(crate) fn framing(&self) -> Framing {
        self.framing
    }

    #[inline]
    pub(crate) fn tx(&self) -> &LaneTx {
        &self.tx
    }

    /// Its first record is still to be written.
    #[inline]
    pub(crate) fn first_owed(&self) -> bool {
        self.first_owed
    }

    #[inline]
    pub(crate) fn writable(&self) -> bool {
        self.writable
    }

    /// The driver writes no more on it.
    #[inline]
    pub(crate) fn writes_ended(&self) -> bool {
        self.out_closed || self.shutdown_reported
    }

    /// Attached and still written: opening or confirmed.
    #[inline]
    pub(crate) fn attached(&self) -> bool {
        matches!(self.state, LaneState::Opening(_) | LaneState::Confirmed)
    }
}

#[cfg(test)]
mod tests {
    /// A count falling back to a value already in the window keeps that
    /// value's earlier start, so an older, smaller count expires on time.
    #[test]
    fn held_bytes_equal_count_keeps_its_start() {
        let t0 = Instant::now();
        let ms = Duration::from_millis;
        let span = ms(10);
        let mut h = HeldBytes::default();
        h.set(t0, 2, span);
        h.set(t0 + ms(2), 3, span);
        h.set(t0 + ms(3), 5, span);
        h.set(t0 + ms(4), 3, span);
        // The window starts after 3 took over from 2 (at 2 ms).
        assert_eq!(h.min(t0 + ms(13), span), 3);
        assert_eq!(h.min(t0 + ms(11), span), 2);
    }

    use super::*;
    use std::time::Duration;

    /// The pipe's write stall with lanes (MULTIPATH.md Section 7.1): the
    /// shortest stall of the lanes that refuse bytes, none longer than the
    /// time since any lane progressed.
    #[test]
    fn the_shortest_lane_stall_capped_by_any_progress() {
        let t0 = Instant::now();
        let ms = |m: u64| t0 + Duration::from_millis(m);
        let mut l = OutLanes::new(0, 0, 0);
        assert_eq!(l.request(), 1);
        assert_eq!(l.request(), 2);
        assert_eq!(l.stall_from(None), None);
        l.set_writable(1, false, ms(10));
        assert_eq!(l.stall_from(None), Some(ms(10)));
        // A refusal reported again keeps its start.
        l.set_writable(1, false, ms(15));
        l.set_writable(2, false, ms(20));
        assert_eq!(l.stall_from(None), Some(ms(20)));
        assert_eq!(l.stall_from(Some(ms(30))), Some(ms(30)));
        // Lane 0 progressed: no stall is longer than the time since.
        l.zero_progress(ms(40));
        assert_eq!(l.stall_from(None), Some(ms(40)));
        // Lane 2 takes bytes again: lane 1 is left, still since lane 2's
        // progress.
        l.set_writable(2, true, ms(50));
        assert_eq!(l.stall_from(None), Some(ms(50)));
        l.set_writable(1, true, ms(60));
        assert_eq!(l.stall_from(None), None);
    }
}
