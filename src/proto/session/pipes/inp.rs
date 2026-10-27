//! The inbound pipe of an attachment: its state, the record reader and
//! the receive position with what PIPE_ACK reports of it (MULTIPATH.md
//! Sections 6.1 to 6.3 and 7.3).

use std::time::{Duration, Instant};

use super::InState;
use crate::proto::frame::PipeAckEntry;
use crate::proto::ident::{Classifier, Verdict};
use crate::proto::record::{Framing, RecordReader};

/// The receive state of one record stream: lane 0 of an inbound pipe, or
/// another lane of it (MULTIPATH.md Section 2.5).
#[derive(Debug)]
pub(crate) struct RecvLane {
    reader: Option<RecordReader>,
    /// The driver holds bytes of an incomplete record (in-place receiving).
    partial: bool,
    frames_in: u64,
    /// The record being received: PADDING only so far, ack-eliciting,
    /// carries an activity frame, carries PIPE_PING.
    rec_padding_only: bool,
    rec_eliciting: bool,
    rec_activity: bool,
    rec_ping: bool,
    /// Receive position (MULTIPATH.md Section 6.1).
    position: u64,
    /// When the record that brought the position to its value was
    /// processed (ACK Delay).
    position_at: Instant,
    /// The position listed in the last complete snapshot.
    complete_reported: u64,
}

impl RecvLane {
    fn new(framing: Framing, max_record: u64, now: Instant) -> Self {
        Self {
            reader: Some(RecordReader::with_framing(max_record, framing)),
            partial: false,
            frames_in: 0,
            rec_padding_only: true,
            rec_eliciting: false,
            rec_activity: false,
            rec_ping: false,
            position: 0,
            position_at: now,
            complete_reported: 0,
        }
    }

    fn heap_bytes(&self) -> usize {
        self.reader
            .as_ref()
            .map_or(0, RecordReader::buffer_capacity)
    }

    /// The carrier ended at a record boundary, with no incomplete record
    /// held by the driver.
    fn at_clean_end(&self) -> bool {
        !self.partial
            && self
                .reader
                .as_ref()
                .is_some_and(RecordReader::at_record_boundary)
    }

    fn entry(&self, pipe_id: u64, lane: u64, now: Instant) -> PipeAckEntry {
        let delay = now.saturating_duration_since(self.position_at);
        PipeAckEntry {
            pipe_id,
            lane,
            position: self.position,
            ack_delay: u64::try_from(delay.as_micros()).unwrap_or(u64::MAX >> 2),
        }
    }

    /// The record ended: its marks are taken.
    fn take_marks(&mut self) -> (bool, bool, bool) {
        self.rec_padding_only = true;
        (
            std::mem::replace(&mut self.rec_eliciting, false),
            std::mem::replace(&mut self.rec_activity, false),
            std::mem::replace(&mut self.rec_ping, false),
        )
    }
}

/// Where an inbound lane other than lane 0 stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LaneIn {
    /// Its first record, PIPE_LANE and PADDING, has not ended yet.
    First,
    /// Reading.
    Open,
    /// Ended, at a record boundary (`clean`) or not.
    Ended { clean: bool },
}

/// An inbound lane other than lane 0.
#[derive(Debug)]
struct InLane {
    number: u64,
    state: LaneIn,
    recv: RecvLane,
    /// Complete records received.
    records: u64,
}

impl InLane {
    /// Whether its end is the pipe's: once a record after its first has
    /// arrived (MULTIPATH.md Section 5.8 reader rule 3).
    fn counts(&self) -> bool {
        self.records > 1
    }
}

/// How the end of an inbound lane other than lane 0 affects its pipe
/// (MULTIPATH.md Sections 5.8 and 7.3, SPEC.md Section 6.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LaneEnd {
    /// No event of the pipe: it ended before its second record, or other
    /// lanes are still open.
    Nothing,
    /// Every lane of the pipe ended at a record boundary: the pipe's
    /// graceful end.
    Graceful,
    /// It ended inside a record, or with an error: the pipe failed.
    Failed,
}

/// The inbound pipe of an attachment.
#[derive(Debug)]
pub(crate) struct InPipe {
    framing: Framing,
    /// First-record check of a bootstrap pipe, until decided.
    classifier: Option<Classifier>,
    /// Bytes the classifier has seen (in-place receiving).
    classified: usize,
    /// Lane 0: the pipe's own carrier.
    zero: RecvLane,
    /// Lane 0 ended at a record boundary while other lanes were open.
    zero_ended: bool,
    state: InState,
    /// The next frame is the in-band PIPE_JOIN the listener verified.
    skip_join: bool,
    /// The record being read is a leading QX_TRANSPORT_PARAMETERS record
    /// on a pipe this endpoint joined: it is discarded (MULTIPATH.md
    /// Section 5.7 step 3).
    discard: bool,
    /// The first record ended: no record is a leading one any more.
    leading_seen: bool,
    /// Ack-eliciting bytes since the last PIPE_ACK that listed the pipe,
    /// summed over its lanes, and when the first of them arrived.
    elicit: u64,
    elicit_since: Option<Instant>,
    last_record: Instant,
    /// G_p: the longest interval between two complete records.
    gap: Duration,
    records: u64,
    opened_at: Instant,
    /// Duplicate stream bytes received on the pipe.
    dup_bytes: u64,
    /// Linger deadline after the PIPE_ABANDON exchange (MULTIPATH.md 8.2).
    linger_until: Option<Instant>,
    /// The driver was told to close the carrier half.
    close_reported: bool,
    /// The lanes other than lane 0, in number order, allocated with the
    /// first one.
    lanes: Option<Box<InLanes>>,
}

/// The lanes of an inbound pipe other than lane 0, in number order.
#[derive(Debug, Default)]
struct InLanes {
    list: Vec<InLane>,
    /// When the last complete snapshot listed them, outside multipath
    /// (MULTIPATH.md Section 6.2; a multipath session keeps one time for
    /// every pipe).
    complete_at: Option<Instant>,
}

impl std::ops::Deref for InLanes {
    type Target = Vec<InLane>;

    fn deref(&self) -> &Vec<InLane> {
        &self.list
    }
}

impl std::ops::DerefMut for InLanes {
    fn deref_mut(&mut self) -> &mut Vec<InLane> {
        &mut self.list
    }
}

/// What a classifier decided about the first bytes of a bootstrap pipe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Classified {
    /// Read on (accepted, or no check runs).
    Read,
    /// Undecided: an in-place receiver keeps the bytes.
    Wait,
    /// No valid first record: the bytes the classifier saw this time.
    Rejected(usize),
}

/// What the end of a record on a pipe of a multipath session brings
/// (MULTIPATH.md Section 6.1).
#[derive(Debug, Clone, Copy)]
pub(crate) struct RecordEnd {
    /// The record carried an activity frame.
    pub(crate) activity: bool,
    /// It carried PIPE_PING.
    pub(crate) ping: bool,
    /// It confirmed a joining pipe, which is open now.
    pub(crate) joined: bool,
    /// A PIPE_ACK is due at once (a PIPE_PING, or the ack threshold).
    pub(crate) immediate: bool,
    /// The pipe's first record carried a PIPE_PING.
    pub(crate) first_ping: bool,
}

/// What a received frame is to the pipe's record accounting.
#[derive(Debug, Clone, Copy)]
pub(crate) enum FrameIn {
    /// Part of a discarded leading record: not processed.
    Discarded,
    /// Processed: whether it is the pipe's first frame, and whether it is
    /// the in-band PIPE_JOIN the listener verified.
    Process { first: bool, skip_join: bool },
}

impl InPipe {
    pub(crate) fn new(framing: Framing, max_record: u64, state: InState, now: Instant) -> Self {
        Self {
            framing,
            classifier: None,
            classified: 0,
            zero: RecvLane::new(framing, max_record, now),
            zero_ended: false,
            state,
            skip_join: false,
            discard: false,
            leading_seen: false,
            elicit: 0,
            elicit_since: None,
            last_record: now,
            gap: Duration::ZERO,
            records: 0,
            opened_at: now,
            dup_bytes: 0,
            linger_until: None,
            close_reported: false,
            lanes: None,
        }
    }

    /// The carrier's framing, known only once a reserved pipe's carrier
    /// is attached (before any byte was read).
    pub(crate) fn set_framing(&mut self, framing: Framing, max_record: u64, now: Instant) {
        self.framing = framing;
        self.zero = RecvLane::new(framing, max_record, now);
    }

    /// With the first-record check of a bootstrap pipe.
    pub(crate) fn with_classifier(mut self, classifier: Classifier) -> Self {
        self.classifier = Some(classifier);
        self
    }

    /// With the in-band PIPE_JOIN the listener verified as its first frame
    /// (`inband`, MULTIPATH.md Section 5.2).
    pub(crate) fn with_inband_join(mut self, inband: bool) -> Self {
        self.skip_join = inband;
        self
    }

    /// Heap bytes held.
    pub(super) fn heap_bytes(&self) -> usize {
        self.zero.heap_bytes()
            + self.lanes.as_deref().map_or(0, |l| {
                size_of::<InLanes>()
                    + l.capacity() * size_of::<InLane>()
                    + l.iter().map(|x| x.recv.heap_bytes()).sum::<usize>()
            })
    }

    #[inline]
    pub(crate) fn is_live(&self) -> bool {
        matches!(self.state, InState::Joining | InState::Open)
    }

    #[inline]
    pub(crate) fn state(&self) -> InState {
        self.state
    }

    #[inline]
    pub(crate) fn framing(&self) -> Framing {
        self.framing
    }

    /// Its clocks start now (the pipe joined, or multipath started).
    pub(crate) fn restart(&mut self, now: Instant) {
        self.opened_at = now;
        self.last_record = now;
    }

    /// A deferred join goes: the pipe is joining.
    pub(crate) fn release_join(&mut self) {
        self.state = InState::Joining;
    }

    /// When the pipe was opened (attached, or its join confirmed).
    #[inline]
    pub(crate) fn opened_at(&self) -> Instant {
        self.opened_at
    }

    /// When the last complete record was processed.
    #[inline]
    pub(crate) fn last_record(&self) -> Instant {
        self.last_record
    }

    /// The last progress: the last record, or the opening.
    #[inline]
    pub(crate) fn last_progress(&self) -> Instant {
        self.last_record.max(self.opened_at)
    }

    /// G_p: the longest interval between two complete records.
    #[inline]
    pub(crate) fn gap(&self) -> Duration {
        self.gap
    }

    /// Complete records received, over every lane.
    #[inline]
    pub(crate) fn records(&self) -> u64 {
        self.records
    }

    /// Bytes received in complete records, over every lane.
    pub(crate) fn bytes_received(&self) -> u64 {
        self.zero.position
            + self
                .lanes
                .as_deref()
                .map_or(0, |l| l.iter().map(|x| x.recv.position).sum::<u64>())
    }

    /// Duplicate stream bytes received.
    #[inline]
    pub(crate) fn dup_bytes(&self) -> u64 {
        self.dup_bytes
    }

    /// Duplicate stream bytes arrived on the pipe.
    pub(crate) fn duplicate(&mut self, bytes: u64) {
        self.dup_bytes += bytes;
    }

    // ---- lanes (MULTIPATH.md Sections 2.5 and 5.8) -------------------------------

    /// Whether lane `number` (0: the pipe's own carrier) is still read: it
    /// was accepted and has not ended.
    pub(crate) fn lane_reads(&self, number: u64) -> bool {
        if number == 0 {
            return !self.zero_ended;
        }
        self.lane_index(number)
            .and_then(|li| self.lanes.as_deref()?.get(li - 1))
            .is_some_and(|l| !matches!(l.state, LaneIn::Ended { .. }))
    }

    /// The index of lane `number` among the pipe's lanes (0 for lane 0),
    /// if it was accepted.
    pub(crate) fn lane_index(&self, number: u64) -> Option<usize> {
        if number == 0 {
            return Some(0);
        }
        let lanes = self.lanes.as_deref()?;
        lanes
            .binary_search_by_key(&number, |l| l.number)
            .ok()
            .map(|i| i + 1)
    }

    /// The number of the lane at index `li`.
    pub(crate) fn lane_number(&self, li: usize) -> u64 {
        match li {
            0 => 0,
            _ => self.lanes.as_deref().map_or(0, |l| l[li - 1].number),
        }
    }

    /// Lanes of the direction, lane 0 included.
    pub(crate) fn lane_count(&self) -> u64 {
        1 + self.lanes.as_deref().map_or(0, |l| l.len() as u64)
    }

    /// The positions of the lanes: number and position, lane 0 first.
    pub(crate) fn lane_positions(&self) -> impl Iterator<Item = (u64, u64)> + '_ {
        std::iter::once((0, self.zero.position)).chain(
            self.lanes
                .iter()
                .flat_map(|l| l.iter().map(|x| (x.number, x.recv.position))),
        )
    }

    /// Accepts lane `number` (not 0) from its first byte: its index, or
    /// `None` when that lane was opened already.
    pub(crate) fn add_lane(
        &mut self,
        number: u64,
        framing: Framing,
        max_record: u64,
        now: Instant,
    ) -> Option<usize> {
        let lanes = self.lanes.get_or_insert_with(Box::default);
        let at = lanes.binary_search_by_key(&number, |l| l.number).err()?;
        lanes.insert(
            at,
            InLane {
                number,
                state: LaneIn::First,
                recv: RecvLane::new(framing, max_record, now),
                records: 0,
            },
        );
        Some(at + 1)
    }

    /// Whether lane `li` (not 0) is still in its first record.
    pub(crate) fn in_first_record(&self, li: usize) -> bool {
        li > 0
            && self
                .lanes
                .as_deref()
                .is_some_and(|l| l[li - 1].state == LaneIn::First)
    }

    #[inline]
    fn recv_mut(&mut self, li: usize) -> &mut RecvLane {
        match li {
            0 => &mut self.zero,
            _ => &mut self.lanes.as_deref_mut().expect("lanes")[li - 1].recv,
        }
    }

    // ---- reading ---------------------------------------------------------------------

    /// The first-record check of a bootstrap pipe on `data` (with
    /// `retain`, the bytes the driver passes again until consumed: each is
    /// checked once). A decision ends the check.
    pub(crate) fn classify(&mut self, data: &[u8], retain: bool) -> Classified {
        let Some(c) = &mut self.classifier else {
            return Classified::Read;
        };
        // Nothing is consumed before it decides, since it decides within
        // the first record.
        let fresh = if retain {
            let seen = self.classified.min(data.len());
            self.classified = data.len();
            &data[seen..]
        } else {
            data
        };
        match c.push(fresh) {
            Verdict::NeedMore if retain => Classified::Wait,
            Verdict::NeedMore => Classified::Read,
            Verdict::Accept(_) => {
                self.classifier = None;
                Classified::Read
            }
            Verdict::Reject { .. } => {
                self.classifier = None;
                Classified::Rejected(fresh.len())
            }
        }
    }

    /// The first-record check on a whole message: `false` when it rejects
    /// it. The check ends with the first message.
    pub(crate) fn classify_message(&mut self, message: &[u8]) -> bool {
        match self.classifier.take() {
            Some(mut c) => !matches!(c.message(message), Verdict::Reject { .. }),
            None => true,
        }
    }

    /// The record reader of lane `li`, taken while it reads (none once the
    /// pipe or the lane ended).
    pub(crate) fn take_reader(&mut self, li: usize) -> Option<RecordReader> {
        self.recv_mut(li).reader.take()
    }

    /// The reader goes back after reading, unless the pipe or the lane
    /// ended meanwhile; whether it ended.
    pub(crate) fn return_reader(&mut self, li: usize, reader: RecordReader) -> bool {
        if self.state == InState::Ended || (li == 0 && self.zero_ended) {
            return true;
        }
        if li > 0
            && matches!(
                self.lanes.as_deref().map(|l| l[li - 1].state),
                Some(LaneIn::Ended { .. })
            )
        {
            return true;
        }
        self.recv_mut(li).reader = Some(reader);
        false
    }

    /// The driver holds bytes of an incomplete record of lane `li`
    /// (in-place receiving).
    pub(crate) fn set_partial(&mut self, li: usize, partial: bool) {
        self.recv_mut(li).partial = partial;
    }

    /// Lane 0's carrier ended at a record boundary, after the first-record
    /// check, with no incomplete record held by the driver.
    pub(crate) fn at_clean_end(&self) -> bool {
        self.zero.at_clean_end() && self.classifier.is_none()
    }

    /// Whether the first record of a pipe this endpoint joined may still
    /// be a leading QX_TRANSPORT_PARAMETERS record (MULTIPATH.md Section
    /// 5.7 step 3).
    pub(crate) fn leading_possible(&self) -> bool {
        matches!(self.state, InState::Joining | InState::Deferred) && !self.leading_seen
    }

    /// A frame of the current record of lane `li`: `leading_tp`, a
    /// QX_TRANSPORT_PARAMETERS frame that leads the first record of a pipe
    /// this endpoint joined, discards the record; the frame's kind marks
    /// the record (not PADDING, ack-eliciting, an activity frame).
    pub(crate) fn frame_in(
        &mut self,
        li: usize,
        leading_tp: bool,
        padding: bool,
        eliciting: bool,
        activity: bool,
    ) -> FrameIn {
        if li == 0 {
            if self.discard {
                return FrameIn::Discarded;
            }
            if leading_tp {
                self.zero.frames_in += 1;
                self.discard = true;
                return FrameIn::Discarded;
            }
        }
        let skip_join = li == 0 && std::mem::replace(&mut self.skip_join, false);
        let r = self.recv_mut(li);
        r.frames_in += 1;
        r.rec_padding_only &= padding;
        r.rec_eliciting |= eliciting;
        r.rec_activity |= activity;
        FrameIn::Process {
            first: r.frames_in == 1,
            skip_join,
        }
    }

    /// The current record of lane `li` carries a PIPE_PING.
    pub(crate) fn ping_in(&mut self, li: usize) {
        self.recv_mut(li).rec_ping = true;
    }

    /// The current record of lane `li` ended: `None` for a discarded
    /// leading record (which counts for nothing, MULTIPATH.md Section 5.7
    /// step 3), else whether it held PADDING only.
    pub(crate) fn record_closed(&mut self, li: usize) -> Option<bool> {
        if li == 0 {
            self.leading_seen = true;
            if std::mem::replace(&mut self.discard, false) {
                self.zero.take_marks();
                return None;
            }
        }
        Some(std::mem::replace(
            &mut self.recv_mut(li).rec_padding_only,
            true,
        ))
    }

    /// A record of `len` bytes ended on lane `li` of a pipe outside
    /// multipath: the position counts it; returns whether it was
    /// ack-eliciting and whether it carried an activity frame.
    pub(crate) fn single_record(&mut self, li: usize, len: u64) -> (bool, bool) {
        self.lane_record(li);
        let r = self.recv_mut(li);
        r.position += len;
        let (eliciting, activity, _) = r.take_marks();
        (eliciting, activity)
    }

    /// A record ended on lane `li`: a lane other than lane 0 leaves its
    /// first record.
    fn lane_record(&mut self, li: usize) {
        if li > 0
            && let Some(l) = self.lanes.as_deref_mut().map(|l| &mut l[li - 1])
        {
            l.records += 1;
            if l.state == LaneIn::First {
                l.state = LaneIn::Open;
            }
        }
    }

    /// Lane `li`'s position was processed now; ack-eliciting bytes of the
    /// record wait for a PIPE_ACK. Whether the bytes waiting, summed over
    /// the lanes, reach `threshold` (MULTIPATH.md Section 6.3).
    pub(crate) fn await_ack(
        &mut self,
        li: usize,
        len: u64,
        eliciting: bool,
        threshold: u64,
        now: Instant,
    ) -> bool {
        self.recv_mut(li).position_at = now;
        if !eliciting {
            return false;
        }
        self.elicit += len;
        self.elicit_since.get_or_insert(now);
        self.elicit >= threshold
    }

    /// A record of `len` bytes ended on lane `li` of a pipe of a multipath
    /// session (MULTIPATH.md Section 6.1): the position and the record
    /// statistics count it, a joining pipe opens, and its ack-eliciting
    /// bytes wait for a PIPE_ACK, due at once from `threshold` bytes.
    pub(crate) fn mp_record(
        &mut self,
        li: usize,
        len: u64,
        threshold: u64,
        now: Instant,
    ) -> RecordEnd {
        self.lane_record(li);
        self.records += 1;
        if self.records > 1 {
            let gap = now.saturating_duration_since(self.last_record);
            self.gap = self.gap.max(gap);
        }
        self.last_record = now;
        let r = self.recv_mut(li);
        r.position += len;
        let (eliciting, activity, ping) = r.take_marks();
        let joined = self.state == InState::Joining;
        if joined {
            self.state = InState::Open;
            self.opened_at = now;
        }
        let threshold_reached = self.await_ack(li, len, eliciting, threshold, now);
        RecordEnd {
            activity,
            ping,
            joined,
            immediate: ping || threshold_reached,
            first_ping: ping && self.records == 1,
        }
    }

    // ---- acknowledging ------------------------------------------------------------------

    /// Ack-eliciting bytes received since the last PIPE_ACK listed the
    /// pipe.
    #[inline]
    pub(crate) fn unacked(&self) -> u64 {
        self.elicit
    }

    /// When the first of them arrived.
    #[inline]
    pub(crate) fn unacked_since(&self) -> Option<Instant> {
        self.elicit_since
    }

    /// Whether a PIPE_ACK lists the pipe: a position above 0 on a lane.
    pub(crate) fn listed(&self) -> bool {
        self.zero.position > 0
            || self
                .lanes
                .as_deref()
                .is_some_and(|l| l.iter().any(|x| x.recv.position > 0))
    }

    /// The entries the pipe, numbered `pipe_id`, adds to a PIPE_ACK at
    /// `now`, in lane order: every lane with a position above 0, or with
    /// `!complete` only those whose position changed since the last
    /// complete snapshot (MULTIPATH.md Section 6.2). How many.
    pub(crate) fn ack_entries(
        &self,
        pipe_id: u64,
        complete: bool,
        now: Instant,
        out: &mut Vec<PipeAckEntry>,
    ) -> usize {
        let before = out.len();
        let mut push = |number: u64, r: &RecvLane| {
            if r.position > 0 && (complete || r.position != r.complete_reported) {
                out.push(r.entry(pipe_id, number, now));
            }
        };
        push(0, &self.zero);
        if let Some(l) = self.lanes.as_deref() {
            for x in l.iter() {
                push(x.number, &x.recv);
            }
        }
        out.len() - before
    }

    /// Lane 0's PIPE_ACK entry, numbered `pipe_id`, at `now`.
    pub(crate) fn ack_entry(&self, pipe_id: u64, now: Instant) -> PipeAckEntry {
        self.zero.entry(pipe_id, 0, now)
    }

    /// A PIPE_ACK listing the positions went out: nothing waits for one.
    pub(crate) fn ack_sent(&mut self) {
        self.elicit = 0;
        self.elicit_since = None;
    }

    /// Whether the PIPE_ACK of a pipe with lanes outside multipath must be
    /// a complete snapshot: none went out in the last second (MULTIPATH.md
    /// Sections 3.5 and 6.2).
    pub(crate) fn complete_due(&self, now: Instant) -> bool {
        self.lanes.as_deref().is_none_or(|l| {
            l.complete_at
                .is_none_or(|t| now.saturating_duration_since(t) >= Duration::from_secs(1))
        })
    }

    /// A complete snapshot outside multipath went out now.
    pub(crate) fn complete_sent_at(&mut self, now: Instant) {
        self.complete_sent();
        if let Some(l) = self.lanes.as_deref_mut() {
            l.complete_at = Some(now);
        }
    }

    /// A complete snapshot listing the positions went out.
    pub(crate) fn complete_sent(&mut self) {
        self.zero.complete_reported = self.zero.position;
        if let Some(l) = self.lanes.as_deref_mut() {
            for x in l.iter_mut() {
                x.recv.complete_reported = x.recv.position;
            }
        }
    }

    // ---- ending -----------------------------------------------------------------------

    /// The linger deadline after the PIPE_ABANDON exchange.
    pub(crate) fn linger_until(&self) -> Option<Instant> {
        self.linger_until
    }

    /// Starts the linger after the PIPE_ABANDON exchange (MULTIPATH.md
    /// Section 8.2), unless it runs or the pipe is not live.
    pub(crate) fn start_linger(&mut self, until: Instant) {
        if self.is_live() && self.linger_until.is_none() {
            self.linger_until = Some(until);
        }
    }

    /// The readers go: the pipe ended.
    fn drop_readers(&mut self) {
        self.zero.reader = None;
        if let Some(l) = self.lanes.as_deref_mut() {
            for x in l.iter_mut() {
                x.recv.reader = None;
            }
        }
    }

    /// Whether every lane other than lane 0 whose end counts ended at a
    /// record boundary (MULTIPATH.md Section 7.3).
    fn lanes_ended_cleanly(&self) -> bool {
        self.lanes.as_deref().is_none_or(|l| {
            l.iter()
                .filter(|x| x.counts())
                .all(|x| x.state == LaneIn::Ended { clean: true })
        })
    }

    /// Lane 0 ended at a record boundary: whether that is the pipe's
    /// graceful end, every lane whose end counts having ended so too;
    /// otherwise the pipe waits for the others (SPEC.md Section 6.6).
    pub(crate) fn zero_ended_cleanly(&mut self) -> bool {
        self.zero_ended = true;
        self.zero.reader = None;
        self.lanes_ended_cleanly()
    }

    /// Lane `li` (not 0) ended, at a record boundary when `clean` (and the
    /// driver holds no incomplete record of it): what that is to the pipe.
    pub(crate) fn lane_ended(&mut self, li: usize, eof: bool) -> LaneEnd {
        let zero_ended = self.zero_ended;
        let Some(l) = self.lanes.as_deref_mut().and_then(|l| l.get_mut(li - 1)) else {
            return LaneEnd::Nothing;
        };
        if matches!(l.state, LaneIn::Ended { .. }) {
            return LaneEnd::Nothing;
        }
        let clean = eof && l.recv.at_clean_end();
        l.state = LaneIn::Ended { clean };
        l.recv.reader = None;
        if !l.counts() {
            // Before its second record: no event of the pipe (its writer
            // may see it as refused), and no part of its end.
            return LaneEnd::Nothing;
        }
        if !clean {
            return LaneEnd::Failed;
        }
        if zero_ended && self.lanes_ended_cleanly() {
            LaneEnd::Graceful
        } else {
            LaneEnd::Nothing
        }
    }

    /// The pipe ends gracefully (expected, or the linger is over); whether
    /// the driver is still to be told to close the carrier half.
    pub(crate) fn end_gracefully(&mut self) -> bool {
        self.state = InState::Ended;
        self.drop_readers();
        !std::mem::replace(&mut self.close_reported, true)
    }

    /// The attachment failed: the pipe ends; whether the driver is still
    /// to be told to close the carrier half, `None` when it had ended.
    pub(crate) fn fail(&mut self) -> Option<bool> {
        if self.state == InState::Ended {
            return None;
        }
        self.state = InState::Ended;
        self.drop_readers();
        Some(!std::mem::replace(&mut self.close_reported, true))
    }

    /// The single pipe ended.
    pub(crate) fn end(&mut self) {
        self.state = InState::Ended;
    }

    /// The carrier half ended on its own: no close to report.
    pub(crate) fn carrier_ended(&mut self) {
        self.close_reported = true;
    }

    /// The driver was not told to close the carrier half yet.
    pub(crate) fn close_unreported(&self) -> bool {
        !self.close_reported
    }
}
