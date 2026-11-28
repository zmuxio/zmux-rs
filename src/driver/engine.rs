//! The pipe I/O both drivers share, without I/O of its own: a pipe's
//! outbound batch with its write calls, and the session timer's handling.
//! The tokio driver and the std driver decide only when to call it, and do
//! the reads and writes with their carriers.

use std::io::IoSlice;
use std::time::{Duration, Instant};

use crate::Chunk;
#[cfg(feature = "tokio")]
use crate::proto::session::ChunkBuffer;
#[cfg(feature = "tokio")]
use std::{sync::Arc, task::Context};

use super::CallLimit;
use crate::proto::record::Framing;
use crate::proto::session::{
    DEFAULT_BATCH, LaneId, PieceCursor, PipeWrite, SessionCore as Core, Transmit, TransmitBuf,
    WRITE_CALL_MIN,
};

/// How long the last batches of a closed session may take to be written
/// before the carriers are ended.
pub(crate) const FINAL_WRITE: Duration = Duration::from_secs(1);

/// A deadline as a timer is armed for it: as it is when it is ahead, so
/// that a timer whose resolution is a millisecond (tokio's rounds up to its
/// next tick) is not a tick later still; one that is due already (the
/// core keeps it while nothing changed) a millisecond ahead, which would
/// otherwise fire at once forever.
pub(crate) fn timer_deadline(deadline: Option<Instant>, now: Instant) -> Option<Instant> {
    deadline.map(|d| {
        if d > now {
            d
        } else {
            now + Duration::from_millis(1)
        }
    })
}

/// Fires the core's timers when due; returns whether that changed the next
/// deadline (a deadline that stays due changed nothing).
pub(crate) fn fire_timers(core: &mut Core, now: Instant) -> bool {
    let due = core.poll_timeout();
    if due.is_none_or(|t| t > now) {
        return false;
    }
    core.handle_timeout(now);
    core.poll_timeout() != due
}

/// How a driver's write calls behave.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Calls {
    /// Non-blocking calls that may take part of a batch.
    #[cfg(feature = "tokio")]
    NonBlocking,
    /// Blocking calls on a writer thread: a call's bytes are handed on
    /// when it returns.
    Blocking,
}

/// A pipe's write calls that the core has not heard of, as the one
/// write-progress report both drivers send:
/// the std driver as its blocking calls start and return, the tokio driver
/// for the calls of a round, in the next critical section. Calls in between
/// merge (the first start, the last end, the bytes of all, the last
/// outcome), and a report that changes nothing the core holds (a call
/// that returned while the carrier took everything, a refusal again) is
/// not sent: the core's write-progress state is a call in progress, a
/// refusing carrier, or neither.
#[derive(Debug, Default)]
pub(crate) struct Progress {
    pending: Option<Pending>,
    /// What the reports sent left the core with.
    told: Told,
    /// The bytes of the last call that took any, across reports: what a
    /// carrier with a low-water mark may hold beyond the mark when a later
    /// call finds it full.
    last_added: u64,
}

#[derive(Debug, Clone, Copy)]
struct Pending {
    start: Instant,
    end: Option<Instant>,
    bytes: u64,
    refused: bool,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
enum Told {
    #[default]
    Open,
    Call,
    Refused,
}

impl Progress {
    /// A blocking call handed `bytes` to the carrier at `start`.
    #[cfg(feature = "blocking")]
    pub(crate) fn started(&mut self, start: Instant, bytes: usize) {
        self.pending = Some(Pending {
            start,
            end: None,
            bytes: bytes as u64,
            refused: false,
        });
    }

    /// A call that started at `start` returned at `end`: the carrier took
    /// `bytes`, and `refused` the rest.
    pub(crate) fn returned(&mut self, start: Instant, end: Instant, bytes: usize, refused: bool) {
        let bytes = bytes as u64;
        if bytes > 0 {
            self.last_added = bytes;
        }
        let p = match &mut self.pending {
            // A later call of the same round.
            Some(p) if p.end.is_some() => {
                p.bytes += bytes;
                p
            }
            pending => pending.insert(Pending {
                start,
                end: None,
                bytes,
                refused,
            }),
        };
        p.end = Some(end);
        p.refused = refused;
    }

    /// Hands the report to the core, under its lock, when it changes what
    /// the core holds; returns whether it did. U is 0 unless the carrier
    /// refused bytes; then, with a low-water mark (`low_water`), up to the
    /// mark the core gives it plus what the last call added.
    pub(crate) fn report(
        &mut self,
        core: &mut Core,
        id: impl Into<LaneId>,
        low_water: bool,
        now: Instant,
    ) -> bool {
        let id = id.into();
        let Some(p) = self.pending.take() else {
            return false;
        };
        let told = match p.end {
            None => Told::Call,
            Some(_) if p.refused => Told::Refused,
            Some(_) => Told::Open,
        };
        if told == self.told && told != Told::Call {
            return false;
        }
        self.told = told;
        let write = match p.end {
            None => PipeWrite::started(p.start, p.bytes),
            Some(end) => {
                let unsent = self.unsent(p.refused, low_water.then(|| core.notsent_lowat(id.pipe)));
                PipeWrite::returned(p.start, end, p.bytes, unsent, p.refused)
            }
        };
        core.pipe_write(id, write, now);
        true
    }

    /// U of a call that ended: 0 unless the carrier refused bytes; then,
    /// with a low-water mark `mark`, the mark plus what the last call that
    /// took bytes added, however many reports ago it was.
    fn unsent(&self, refused: bool, mark: Option<u64>) -> u64 {
        match mark {
            Some(m) if refused => m + self.last_added,
            _ => 0,
        }
    }
}

/// A pipe's outbound batch: taken from the core under its lock, written in
/// bounded calls without it.
struct BatchAccounting {
    lane: u64,
    ledger: std::sync::Arc<crate::proto::session::accounting::Ledger>,
    records: usize,
    complete: usize,
}

/// Optional state used by message framing and attributed record writes.
#[derive(Default)]
struct WriteExtras {
    message: Vec<u8>,
    accounting: Option<BatchAccounting>,
}

pub(crate) struct Outbound {
    extra: Option<Box<WriteExtras>>,
    framing: Framing,
    calls: Calls,
    out: TransmitBuf,
    /// Bytes of the batch already written.
    pos: usize,
    /// The writer may have consumed a prefix it never reported.
    unproved_progress: bool,
    /// Bytes written that the core has not been told of
    /// ([`Outbound::tell`]).
    untold: u64,
    /// The batch ends with a shutdown of the write side.
    shutdown: Shutdown,
    /// The most bytes one write call hands the carrier.
    call_limit: usize,
    /// `call_limit` as computed under the core lock, reused within the
    /// latency budget.
    cached: CallLimit,
    /// The next message of a message-framed carrier: its index among the
    /// batch's messages (written ones are whole).
    msg_index: usize,
    /// Where the last walk of the batch ended.
    cursor: PieceCursor,
    /// The batch from `pos` on as owned buffers, for a carrier that takes
    /// them (`ChunkWrite`): built up to byte `owned_end` as
    /// write calls need them, taken from `owned_head` on (the carrier
    /// leaves what it took empty).
    owned: Vec<Chunk>,
    owned_head: usize,
    owned_end: usize,
    /// The copies of built bytes in `owned`, split off as they are made.
    #[cfg(feature = "tokio")]
    scratch: ChunkBuffer,
    #[cfg(feature = "tokio")]
    memory_wait: Option<Arc<crate::proto::memory::BudgetWait>>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Shutdown {
    None,
    Pending,
    Complete,
}

impl Outbound {
    pub(crate) fn new(framing: Framing, calls: Calls) -> Self {
        Self {
            extra: None,
            framing,
            calls,
            out: TransmitBuf::default(),
            pos: 0,
            unproved_progress: false,
            untold: 0,
            shutdown: Shutdown::None,
            call_limit: WRITE_CALL_MIN,
            cached: CallLimit::default(),
            msg_index: 0,
            cursor: PieceCursor::default(),
            owned: Vec::new(),
            owned_head: 0,
            owned_end: 0,
            #[cfg(feature = "tokio")]
            scratch: ChunkBuffer::default(),
            #[cfg(feature = "tokio")]
            memory_wait: None,
        }
    }

    pub(crate) fn framing(&self) -> Framing {
        self.framing
    }

    /// The batch, whole (written or not).
    #[cfg(feature = "tokio")]
    pub(crate) fn batch(&self) -> &TransmitBuf {
        &self.out
    }

    /// Where the unwritten rest of the batch starts.
    #[cfg(feature = "tokio")]
    pub(crate) fn pos(&self) -> usize {
        self.pos
    }

    /// Bytes of the batch left to write.
    pub(crate) fn left(&self) -> usize {
        self.out.len().saturating_sub(self.pos)
    }

    /// Nothing left to write.
    pub(crate) fn is_empty(&self) -> bool {
        self.out.is_empty()
    }

    /// The batch ends with a shutdown of the write side, still to do.
    pub(crate) fn shutdown_pending(&self) -> bool {
        self.shutdown == Shutdown::Pending
    }

    /// The carrier confirmed shutdown of its sending half.
    pub(crate) fn shutdown_done(&mut self) {
        self.shutdown = Shutdown::Complete;
    }

    /// Drops the batch: the write side is closed.
    pub(crate) fn clear(&mut self) {
        self.finish_io();
        self.shutdown = Shutdown::None;
    }

    /// Writes for the next batch start at its beginning.
    fn restart(&mut self) {
        self.pos = 0;
        self.msg_index = 0;
        self.unproved_progress = false;
    }

    /// Clears I/O storage while preserving the confirmed prefix for `tell`.
    fn finish_io(&mut self) {
        self.finish_accounting();
        self.out.clear_io();
        self.owned.clear();
        self.owned_head = 0;
        self.owned_end = 0;
    }

    /// The batch's buffers go while the pipe is idle.
    #[cfg(feature = "tokio")]
    pub(crate) fn release(&mut self) {
        self.out.shrink();
        if let Some(extra) = &mut self.extra {
            extra.message = Vec::new();
        }
        self.owned = Vec::new();
        self.scratch.release_storage();
    }

    /// The batch's storage is that of a small batch.
    #[cfg(feature = "tokio")]
    pub(crate) fn is_small(&self) -> bool {
        self.out.is_small()
    }

    /// Heap bytes held.
    #[cfg(feature = "tokio")]
    pub(crate) fn capacity(&self) -> usize {
        self.out.capacity()
            + self.extra.as_ref().map_or(0, |extra| {
                size_of::<WriteExtras>() + extra.message.capacity()
            })
            + self.owned.capacity() * size_of::<Chunk>()
            + self.scratch.bytes.capacity()
    }

    /// Takes the next batch of pipe `id` from the core, under its lock,
    /// when the last one is done; `input`: reads deliver data, so batches
    /// are smaller and do not hold the reads back. Returns whether there is
    /// something to write or a shutdown to do.
    pub(crate) fn take_batch(
        &mut self,
        core: &mut Core,
        id: impl Into<LaneId>,
        now: Instant,
        input: bool,
    ) -> bool {
        let id = id.into();
        self.tell(core, id, now);
        if !self.out.is_empty() || self.shutdown_pending() || !core.wants_write(id) {
            return false;
        }
        let blocking = self.calls == Calls::Blocking;
        // A smaller batch while reads deliver data, and write calls bounded
        // while latency-sensitive work waits (whatever the carrier is: these
        // use zmux's own state and rate estimate).
        let batch = match self.calls {
            #[cfg(feature = "tokio")]
            Calls::NonBlocking => core.batch_limit(id.pipe, DEFAULT_BATCH, input),
            Calls::Blocking => DEFAULT_BATCH,
        };
        self.out.set_max_len(batch);
        if self.framing == Framing::Records {
            // One message per call, built within the bound.
            let limit = core.write_call_limit(id.pipe, batch, blocking, input, now);
            #[cfg(feature = "tokio")]
            let limit = if self.scratch.space.is_some() {
                limit.min(crate::proto::memory::WriteWorkspace::MAX_ROOT)
            } else {
                limit
            };
            self.out.set_max_message(limit);
        }
        let t = core.poll_transmit(id, now, &mut self.out);
        self.restart();
        if let Some(ledger) = core.pipe_ledger(id.pipe) {
            let accounting = self
                .extra
                .get_or_insert_default()
                .accounting
                .get_or_insert_with(|| BatchAccounting {
                    lane: id.lane.0,
                    ledger: ledger.clone(),
                    records: 0,
                    complete: 0,
                });
            if !std::sync::Arc::ptr_eq(ledger, &accounting.ledger) {
                accounting.ledger = ledger.clone();
            }
        }
        if t == Transmit::Shutdown {
            self.shutdown = Shutdown::Pending;
        }
        let left = self.out.len();
        let limit = core.write_call_limit(id.pipe, left, blocking, input, now);
        self.call_limit = self
            .cached
            .set(left, limit, input, now, core.latency_budget());
        !self.out.is_empty() || self.shutdown_pending()
    }

    /// The limit of the next write call: the cached one while it holds,
    /// else `compute` (under the core lock) gives the core's limit and the
    /// session's latency budget for the bytes left.
    pub(crate) fn call_limit(
        &mut self,
        input: bool,
        now: Instant,
        compute: impl FnOnce(usize) -> (usize, Duration),
    ) -> usize {
        let left = self.left();
        if self.framing == Framing::Records || left <= WRITE_CALL_MIN {
            // Whole messages, or a call within the floor anyway.
            return self.call_limit;
        }
        // The first call of a batch keeps the decision made when it was
        // taken, which saw this round's input, while that decision holds
        // (within the latency budget).
        let input = input && self.pos > 0;
        self.call_limit = if let Some(limit) = self.cached.get(left, input, now) {
            limit
        } else {
            let (limit, budget) = compute(left);
            self.cached.set(left, limit, input, now, budget)
        };
        self.call_limit
    }

    /// The cached call limit (for writes with a budget of their own).
    #[cfg(feature = "tokio")]
    pub(crate) fn current_call_limit(&self) -> usize {
        self.call_limit
    }

    /// The next call's bytes of a byte stream: at most `limit` of the rest
    /// of the batch, as slices.
    pub(crate) fn slices<'a>(&'a self, limit: usize, slices: &mut [IoSlice<'a>]) -> usize {
        self.out.io_slices_from(self.pos, limit, slices)
    }

    /// The length of the next message of a message-framed carrier.
    fn message_len(&self) -> usize {
        self.out
            .message_lens()
            .get(self.msg_index)
            .copied()
            .unwrap_or(self.out.len() - self.pos)
    }

    /// The next message of a message-framed carrier, whole: borrowed from
    /// the batch when it is one piece, else copied once.
    pub(crate) fn message(&mut self) -> &[u8] {
        let len = self.message_len();
        let extra = self.extra.get_or_insert_default();
        self.out
            .contiguous(&mut self.cursor, self.pos, len, &mut extra.message)
    }

    /// The next call's bytes for a carrier that takes owned buffers: at
    /// most `limit` bytes of the rest of the batch (the next message,
    /// whole, on a message-framed carrier), referenced payloads shared and
    /// built bytes copied once. The carrier leaves what it takes empty.
    #[cfg(feature = "tokio")]
    pub(crate) fn chunks(&mut self, limit: usize, cx: &Context<'_>) -> Option<&mut [Chunk]> {
        let head = self.owned_head;
        if self.framing == Framing::Records {
            if head == self.owned.len() {
                self.prepare_chunks(self.pos, self.message_len(), true, cx)?;
            }
            let end = (head + 1).min(self.owned.len());
            return Some(&mut self.owned[head..end]);
        }
        let limit = limit.min(crate::proto::memory::WriteWorkspace::MAX_ROOT);
        let want = (self.pos + limit).min(self.out.len());
        if self.owned_end < want {
            let ready = self.prepare_chunks(self.owned_end, want - self.owned_end, false, cx);
            if ready.is_none() && head == self.owned.len() {
                return None;
            }
        }
        let mut sum = 0;
        let mut end = head;
        while end < self.owned.len() && sum < limit {
            let len = self.owned[end].len();
            if sum + len > limit {
                let tail = self.owned[end].split_off(limit - sum);
                self.owned.insert(end + 1, tail);
                end += 1;
                break;
            }
            sum += len;
            end += 1;
        }
        Some(&mut self.owned[head..end])
    }

    #[cfg(feature = "tokio")]
    fn prepare_chunks(
        &mut self,
        offset: usize,
        len: usize,
        whole: bool,
        cx: &Context<'_>,
    ) -> Option<()> {
        loop {
            let epoch = self
                .scratch
                .space
                .as_ref()
                .map(|space| space.domain().release_epoch());
            if let Some(n) = self.out.owned_pieces(
                &mut self.cursor,
                offset,
                len,
                whole,
                &mut self.owned,
                &mut self.scratch,
            ) {
                self.owned_end += n;
                self.memory_wait = None;
                return Some(());
            }
            let space = self
                .scratch
                .space
                .as_ref()
                .expect("an unlimited workspace cannot be denied");
            if !space
                .domain()
                .watch(epoch.unwrap(), &mut self.memory_wait, cx.waker())
            {
                return None;
            }
        }
    }

    #[cfg(feature = "tokio")]
    pub(crate) fn with_workspace(
        mut self,
        workspace: Option<std::sync::Arc<crate::proto::memory::WriteWorkspace>>,
    ) -> Self {
        self.scratch.space = workspace;
        self
    }

    /// A prefix of the remaining whole messages, ready for the carrier in
    /// one call. A later message waiting for memory leaves this prefix ready.
    #[cfg(feature = "tokio")]
    pub(crate) fn message_batch(&mut self, cx: &Context<'_>) -> Option<&mut [Chunk]> {
        let head = self.owned_head;
        if head == self.owned.len() {
            let (mut pos, mut index) = (self.pos, self.msg_index);
            while pos < self.out.len() {
                let len = self
                    .out
                    .message_lens()
                    .get(index)
                    .copied()
                    .unwrap_or(self.out.len() - pos);
                if self.prepare_chunks(pos, len, true, cx).is_none() {
                    break;
                }
                pos += len;
                index += 1;
            }
        }
        (head < self.owned.len()).then_some(&mut self.owned[head..])
    }

    /// Tells the core, under its lock, the bytes the carrier took since
    /// it was last told: what is left of the batch counts in `Q_p`
    /// ([`Core::pipe_written`]). [`Outbound::take_batch`] does it first.
    /// The last byte of a batch that ends with a shutdown is told once the
    /// shutdown is done: a close counts as handed off only when the
    /// carrier's write side is shut, so a process that exits then leaves no
    /// half-written carrier behind. Returns whether the driver must dispatch
    /// the resulting core events.
    pub(crate) fn tell(&mut self, core: &mut Core, id: impl Into<LaneId>, now: Instant) -> bool {
        let id = id.into();
        let held =
            u64::from(self.shutdown_pending() && self.pos >= self.out.len() && self.untold > 0);
        let n = self.untold - held;
        self.untold = held;
        let done = self.out.is_empty();
        let shaped = (self.untold != 0 || n != 0 || done && self.out.has_committed_cover())
            && self.complete_prefix(core, id, done, now);
        if n > 0 {
            core.pipe_written(id, n, now);
        }
        let completed = self.shutdown == Shutdown::Complete;
        if completed {
            self.shutdown = Shutdown::None;
            core.write_shutdown_complete(id, now);
        }
        shaped || completed || n != 0 && core.state() >= crate::proto::session::State::Closing
    }

    fn complete_prefix(&mut self, core: &mut Core, id: LaneId, done: bool, now: Instant) -> bool {
        let accepted = if self.framing == Framing::Records {
            self.msg_index
                .checked_sub(1)
                .and_then(|i| self.out.records().get(i))
                .map_or(0, |record| record.end)
        } else {
            self.pos as u64
        };
        if done && self.unproved_progress {
            core.transmit_progress_unknown(id, &mut self.out, accepted, now)
        } else {
            core.transmit_progress(id, &mut self.out, accepted, done, now)
        }
    }

    #[cfg(feature = "tokio")]
    pub(crate) const fn note_unproved_progress(&mut self, unknown: bool) {
        self.unproved_progress = unknown;
    }

    /// Settles observed progress when the runtime abandons the remaining I/O.
    pub(crate) fn cancel(&mut self, core: &mut Core, id: impl Into<LaneId>, now: Instant) -> bool {
        let id = id.into();
        let notified = self.tell(core, id, now);
        self.complete_prefix(core, id, true, now) || notified
    }

    /// A write call took `n` bytes; returns whether the batch is done.
    pub(crate) fn written(&mut self, n: usize) -> bool {
        self.pos += n;
        if let Some(accounting) = self
            .extra
            .as_mut()
            .and_then(|extra| extra.accounting.as_mut())
        {
            accounting.written(&self.out, self.pos);
        }
        let done = self.pos >= self.out.len();
        let accepted = if self.framing == Framing::Records && n > 0 {
            // The core counts accepted whole messages with their synthetic Size.
            let records = self.out.records();
            let start = self.msg_index.checked_sub(1).map_or(0, |i| records[i].end);
            let mut pending = n;
            while pending != 0 {
                let len = self.out.message_lens()[self.msg_index];
                pending = pending
                    .checked_sub(len)
                    .expect("carrier accepted whole messages");
                self.msg_index += 1;
            }
            records[self.msg_index - 1].end - start
        } else {
            n as u64
        };
        self.untold += accepted;
        if done {
            self.finish_io();
            return true;
        }
        while self.owned.get(self.owned_head).is_some_and(Chunk::is_empty) {
            self.owned_head += 1;
        }
        if self.owned_head == self.owned.len() {
            self.owned.clear();
            self.owned_head = 0;
        }
        false
    }
}

impl Outbound {
    fn finish_accounting(&mut self) {
        if self.out.is_empty() {
            return;
        }
        if let Some(accounting) = self
            .extra
            .as_mut()
            .and_then(|extra| extra.accounting.as_mut())
        {
            if self.pos > accounting.complete {
                accounting.ledger.finish_write(accounting.lane);
            }
            accounting.records = 0;
            accounting.complete = 0;
        }
    }
}

impl Drop for Outbound {
    fn drop(&mut self) {
        self.finish_accounting();
    }
}

impl BatchAccounting {
    fn written(&mut self, batch: &TransmitBuf, pos: usize) {
        let before = (self.records, self.complete);
        if batch.is_records() {
            for &len in &batch.message_lens()[self.records..] {
                if self.complete + len > pos {
                    break;
                }
                self.records += 1;
                self.complete += len;
            }
        } else {
            let ends = batch.records();
            self.records = ends.partition_point(|record| record.end <= pos as u64);
            if self.records != 0 {
                self.complete = crate::util::usize_sat(ends[self.records - 1].end);
            }
        }
        self.ledger.write_progress(
            self.lane,
            (self.complete - before.1) as u64,
            (self.records - before.0) as u64,
            (pos - self.complete) as u64,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::session::{Config, PipeId, Role};

    /// A batch of `n` records, each of a built part and a referenced
    /// payload (or, on a message-framed pipe with `alone`, the first
    /// message a payload only).
    fn records(framing: Framing, n: u8, alone: bool) -> (TransmitBuf, Vec<Chunk>) {
        let mut b = TransmitBuf::default();
        b.set_framing(framing);
        let mut payloads = Vec::new();
        for i in 0..n {
            b.begin_record(1 << 20);
            if !(alone && i == 0) {
                b.push_bytes(&[i; 7]);
            }
            let p = Chunk::from(vec![i.wrapping_mul(31); 5000 + usize::from(i)]);
            b.push_shared(p.clone());
            payloads.push(p);
            assert!(b.end_record());
        }
        (b, payloads)
    }

    /// Owned buffers for a carrier that takes them: written in calls of
    /// any limit, taken in part or whole, they are the batch's bytes in
    /// order, payloads shared and built bytes copied once.
    #[test]
    fn chunks_cover_the_batch_and_share_its_payloads() {
        let (b, payloads) = records(Framing::ByteStream, 20, false);
        let mut whole = Vec::new();
        b.copy_to_vec(&mut whole);
        let mut o = Outbound::new(Framing::ByteStream, Calls::NonBlocking);
        o.out = b;
        let mut got = Vec::new();
        let mut shared = 0;
        let mut step = 0usize;
        loop {
            step += 1;
            let limit = [3000, 100, 9000, 1, 70000][step % 5];
            let chunks = o
                .chunks(limit, &Context::from_waker(std::task::Waker::noop()))
                .unwrap();
            assert!(chunks.iter().map(Chunk::len).sum::<usize>() <= limit);
            // Take all but a few bytes now and then.
            let mut want = chunks.iter().map(Chunk::len).sum::<usize>();
            if step.is_multiple_of(3) {
                want = want.saturating_sub(5);
            }
            let mut n = 0;
            for c in chunks.iter_mut() {
                let take = c.len().min(want - n);
                if payloads
                    .iter()
                    .any(|p| p.as_ptr_range().contains(&c.as_ptr()))
                {
                    shared += 1;
                }
                got.extend_from_slice(&c.split_to(take));
                n += take;
                if n == want {
                    break;
                }
            }
            if o.written(n) {
                break;
            }
        }
        assert_eq!(got, whole);
        assert!(shared >= payloads.len());
        assert_eq!(o.owned, Vec::<Chunk>::new());
    }

    /// A message-framed carrier gets one message per call: a message of
    /// one referenced payload as that payload, any other copied once.
    #[test]
    fn messages_are_whole_and_borrowed_when_one_piece() {
        let (b, payloads) = records(Framing::Records, 3, true);
        let lens = b.message_lens().to_vec();
        let stream_len = b.stream_len();
        let mut o = Outbound::new(Framing::Records, Calls::NonBlocking);
        o.out = b;
        // Slices: the first message borrowed from its payload.
        assert_eq!(o.message().as_ptr(), payloads[0].as_ptr());
        let (b, _) = records(Framing::Records, 3, true);
        let mut o2 = Outbound::new(Framing::Records, Calls::NonBlocking);
        o2.out = b;
        for (i, len) in lens.iter().enumerate() {
            let m = o2.message();
            assert_eq!(m.len(), *len);
            if i > 0 {
                assert_eq!(&m[..7], &[u8::try_from(i).unwrap(); 7]);
            }
            o2.written(*len);
        }
        assert!(o2.is_empty());
        assert_eq!(o2.untold, stream_len);
        let (batch, _) = records(Framing::Records, 3, true);
        o2.untold = 0;
        o2.out = batch;
        o2.restart();
        assert!(o2.written(lens.iter().sum()));
        assert_eq!(o2.untold, stream_len);
        // Owned buffers: the first message is the payload itself.
        for (i, len) in lens.iter().enumerate() {
            let chunks = o
                .chunks(1, &Context::from_waker(std::task::Waker::noop()))
                .unwrap();
            assert_eq!(chunks.len(), 1);
            assert_eq!(chunks[0].len(), *len);
            if i == 0 {
                assert_eq!(chunks[0].as_ptr(), payloads[0].as_ptr());
            } else {
                assert_eq!(&chunks[0][7..], &payloads[i][..]);
            }
            chunks[0] = Chunk::new();
            o.written(*len);
        }
        assert!(o.is_empty());
    }

    #[test]
    fn progress_reports_what_changes_the_cores_write_state() {
        let now = Instant::now();
        let mut core = Core::new(Config::default(), Role::Client, None, now).unwrap();
        let id = PipeId(0);
        core.attach_pipe(id, Framing::ByteStream, now);
        let writable = |c: &Core| c.pipe_info(id).is_some_and(|p| p.writable);
        let mut p = Progress::default();
        // Non-blocking calls that took everything: nothing to tell.
        p.returned(now, now, 100, false);
        assert!(!p.report(&mut core, id, false, now));
        // A refusal, merged with the call of the round before it.
        p.returned(now, now, 100, false);
        p.returned(now, now, 0, true);
        assert!(p.report(&mut core, id, true, now));
        assert!(!writable(&core));
        // Refused again: nothing new.
        p.returned(now, now, 0, true);
        assert!(!p.report(&mut core, id, true, now));
        p.returned(now, now, 10, false);
        assert!(p.report(&mut core, id, true, now));
        assert!(writable(&core));
        // A blocking call: reported as it starts and as it returns.
        p.started(now, 1000);
        assert!(p.report(&mut core, id, false, now));
        p.returned(now, now, 1000, false);
        assert!(p.report(&mut core, id, false, now));
        assert!(writable(&core));
    }

    /// A carrier with a low-water mark that refuses bytes holds the mark
    /// plus what the last call that took bytes added, also when that call
    /// was in an earlier round whose report changed nothing.
    #[test]
    fn the_unsent_bytes_count_the_last_call_of_an_earlier_round() {
        let now = Instant::now();
        let mut core = Core::new(Config::default(), Role::Client, None, now).unwrap();
        let id = PipeId(0);
        core.attach_pipe(id, Framing::ByteStream, now);
        let mut p = Progress::default();
        p.returned(now, now, 16_384, false);
        assert!(!p.report(&mut core, id, true, now));
        p.returned(now, now, 0, true);
        assert_eq!(p.unsent(true, Some(4096)), 4096 + 16_384);
        assert_eq!(p.unsent(true, None), 0);
        assert!(p.report(&mut core, id, true, now));
    }
}
