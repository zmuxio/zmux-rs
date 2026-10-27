//! Per-stream state: the sending and receiving parts of RFC 9000 Section 3
//! with the zmux deltas of STATE_MACHINE.md Section 2.

use std::cell::{Cell, RefCell};
use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Instant;

use bytes::{Buf, Bytes, BytesMut};

use super::ranges::RangeSet;
use super::reasm::{Arrived, Held};
use super::recv_buf::{Backing, RecvBuf};
use super::tuner::StreamTuner;
use crate::proto::frame::{Dir, Priority};
use crate::proto::meter::{Count, Meter};

/// A handle to a stream in a session. It stays valid until the stream's
/// state is discarded; a stale handle is reported as a closed stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct StreamKey {
    pub(crate) slot: u32,
    pub(crate) generation: u32,
}

/// RFC 9000 Section 3.1 sending-part states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SendState {
    /// Opened, nothing sent.
    Ready,
    /// Sending data.
    Send,
    /// Everything up to the FIN was sent; waiting for acknowledgement
    /// (multipath only: outside multipath a written FIN is acknowledged).
    DataSent,
    /// Everything up to the FIN was acknowledged.
    DataRecvd,
    /// A reset is pending or was written.
    ResetSent,
    /// The reset was written.
    ResetRecvd,
}

impl SendState {
    pub(crate) fn is_terminal(self) -> bool {
        matches!(self, Self::DataRecvd | Self::ResetRecvd)
    }
}

/// RFC 9000 Section 3.2 receiving-part states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RecvState {
    Recv,
    SizeKnown,
    DataRecvd,
    DataRead,
    ResetRecvd,
    ResetRead,
}

impl RecvState {
    pub(crate) fn is_terminal(self) -> bool {
        matches!(self, Self::DataRead | Self::ResetRead)
    }
}

/// The size of the chunks `write` copies into.
const CHUNK: usize = 64 * 1024;
/// The smallest first chunk of a stream.
const SMALL_CHUNK: usize = 1024;
/// A receive buffer that empties with more capacity than this gives it up;
/// the session keeps one such buffer for the next data of any stream.
pub(crate) const RECV_KEEP: usize = 64 * 1024;
/// Chunks a batch being written may still reference, and one more.
const IN_FLIGHT: usize = super::DEFAULT_BATCH / CHUNK + 1;

/// Released chunks of the session's send buffers, reused by any stream once
/// nothing references them any more (a steady transfer allocates nothing).
/// Bounded by the session's send buffer, and counted in its memory; streams
/// themselves keep none, so an idle stream holds only its tail.
#[derive(Debug, Default)]
pub(crate) struct ChunkPool {
    free: VecDeque<Bytes>,
    cap: usize,
}

impl ChunkPool {
    /// Keeps at most the chunks of `bytes` of send buffer, and those a
    /// batch may still reference.
    pub(crate) fn set_limit(&mut self, bytes: u64) {
        self.cap = usize::try_from(bytes / CHUNK as u64)
            .unwrap_or(usize::MAX)
            .saturating_add(IN_FLIGHT);
        self.free.truncate(self.cap);
    }

    fn put(&mut self, chunk: Bytes) {
        if self.free.len() < self.cap {
            self.free.push_back(chunk);
        }
    }

    /// A released chunk nothing references any more, cleared.
    fn take(&mut self) -> Option<BytesMut> {
        for _ in 0..self.free.len() {
            let b = self.free.pop_front()?;
            match b.try_into_mut() {
                Ok(mut m) => {
                    m.clear();
                    m.reserve(CHUNK);
                    return Some(m);
                }
                // Still referenced (by a batch being written): later.
                Err(b) => self.free.push_back(b),
            }
        }
        None
    }

    /// Heap bytes held.
    pub(crate) fn memory(&self) -> usize {
        self.free.len() * CHUNK
    }
}

/// Stream data that the application wrote, in order, copied at most once:
/// `write` copies into `tail`, a growing buffer that reclaims its space in
/// place once what was taken from it is released (a steady transfer
/// allocates nothing), and `write_chunk` chunks are referenced. Runs of
/// [`super::COPY_THRESHOLD`] bytes or more leave as references (`tail` is
/// frozen into a segment for that), so bulk data goes from the
/// application's buffer to the carrier with one copy; smaller runs are
/// copied into the batch, which merges small frames.
///
/// A cursor separates the bytes already sent from the unsent ones. Outside
/// multipath, sent bytes are dropped at once; in a multipath session they
/// stay until a PIPE_ACK covers them and are
/// read again for reinjection.
#[derive(Debug, Default)]
pub(crate) struct SendBuf {
    /// Frozen data (chunks, and `tail` data that was referenced), oldest
    /// first; all of it precedes `tail`.
    segs: VecDeque<Seg>,
    /// Data copied from `write`, after every segment: a chunk filled up to
    /// its capacity, never grown in place.
    tail: BytesMut,
    /// Unsent bytes (after the cursor).
    len: u64,
    /// Sent bytes still held (before the cursor).
    kept: u64,
    /// The cursor: the index of its segment (`segs.len()` for `tail`) and
    /// the offset in it.
    seg: usize,
    seg_off: usize,
}

/// A segment of a send buffer: its bytes, and whether they are a chunk of
/// the buffer (frozen from `tail`) rather than the application's `Bytes`.
#[derive(Debug)]
struct Seg {
    bytes: Bytes,
    own: bool,
}

impl SendBuf {
    /// Unsent bytes.
    pub(crate) fn len(&self) -> u64 {
        self.len
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Sent bytes still held for retransmission.
    pub(crate) fn kept(&self) -> u64 {
        self.kept
    }

    /// The bytes of run `i` (a segment, or `tail` for `segs.len()`).
    fn run(&self, i: usize) -> &[u8] {
        self.segs.get(i).map_or(&self.tail[..], |s| &s.bytes[..])
    }

    pub(crate) fn push_slice(&mut self, mut data: &[u8], pool: &mut ChunkPool) {
        self.len += data.len() as u64;
        while !data.is_empty() {
            let room = self.tail.capacity() - self.tail.len();
            if room == 0 {
                self.next_chunk(data.len(), pool);
                continue;
            }
            let k = room.min(data.len());
            self.tail.extend_from_slice(&data[..k]);
            data = &data[k..];
        }
    }

    /// Starts a new chunk for `tail`: the filled one is frozen, and a
    /// released one is reused when nothing references it any more.
    fn next_chunk(&mut self, want: usize, pool: &mut ChunkPool) {
        self.freeze_tail();
        if let Some(m) = pool.take() {
            self.tail = m;
            return;
        }
        // The first chunk of a stream fits small writes; later ones are
        // full chunks.
        let size = if self.segs.is_empty() && self.kept == 0 {
            want.clamp(SMALL_CHUNK, CHUNK).next_power_of_two()
        } else {
            CHUNK
        };
        self.tail = BytesMut::with_capacity(size);
    }

    pub(crate) fn push_bytes(&mut self, data: Bytes) {
        if data.is_empty() {
            return;
        }
        self.freeze_tail();
        self.len += data.len() as u64;
        self.segs.push_back(Seg {
            bytes: data,
            own: false,
        });
    }

    /// Moves `tail`'s data into a segment, so that it can be referenced
    /// (or a chunk can follow it); the cursor keeps its place.
    fn freeze_tail(&mut self) {
        if !self.tail.is_empty() {
            let frozen = self.tail.split().freeze();
            self.segs.push_back(Seg {
                bytes: frozen,
                own: true,
            });
            // A cursor at the end of the frozen data moves to what follows.
            if self.seg < self.segs.len() && self.seg_off >= self.segs[self.seg].bytes.len() {
                self.seg += 1;
                self.seg_off = 0;
            }
        }
    }

    /// The length of the next contiguous unsent run.
    pub(crate) fn front_len(&self) -> usize {
        self.run(self.seg).len() - self.seg_off
    }

    /// Moves the cursor over `n` bytes of its run.
    fn advance_cursor(&mut self, n: usize) {
        self.seg_off += n;
        if self.seg < self.segs.len() && self.seg_off >= self.segs[self.seg].bytes.len() {
            self.seg += 1;
            self.seg_off = 0;
        }
        self.len -= n as u64;
        self.kept += n as u64;
    }

    /// Copies up to `dst.len()` unsent bytes into `dst` and moves them to
    /// the sent side; without `retain` they are dropped. Returns the number
    /// copied.
    pub(crate) fn copy_to(&mut self, dst: &mut [u8], retain: bool, pool: &mut ChunkPool) -> usize {
        let mut done = 0;
        while done < dst.len() && self.len > 0 {
            let run = &self.run(self.seg)[self.seg_off..];
            let k = (dst.len() - done).min(run.len());
            dst[done..done + k].copy_from_slice(&run[..k]);
            self.advance_cursor(k);
            done += k;
        }
        if !retain {
            self.release(self.kept, pool);
        }
        done
    }

    /// Takes up to `max` bytes of the front run without copying.
    pub(crate) fn take_shared(&mut self, max: usize, retain: bool, pool: &mut ChunkPool) -> Bytes {
        if self.seg == self.segs.len() {
            self.freeze_tail();
        }
        let Some(c) = self.segs.get(self.seg).map(|s| &s.bytes) else {
            return Bytes::new();
        };
        let k = (c.len() - self.seg_off).min(max);
        let out = c.slice(self.seg_off..self.seg_off + k);
        self.advance_cursor(k);
        if !retain {
            self.release(self.kept, pool);
        }
        out
    }

    /// Moves every sent byte still held back to the unsent side: they are
    /// sent again from the first (carrier early data that was rejected).
    pub(crate) fn rewind(&mut self) {
        self.len += self.kept;
        self.kept = 0;
        self.seg = 0;
        self.seg_off = 0;
    }

    /// Drops `n` sent bytes from the front (acknowledged, or not needed).
    pub(crate) fn release(&mut self, n: u64, pool: &mut ChunkPool) {
        let mut left = n.min(self.kept) as usize;
        self.kept -= left as u64;
        while left > 0 {
            let Some(front) = self.segs.front_mut().map(|s| &mut s.bytes) else {
                // The rest is at the front of `tail`; all of it keeps the
                // chunk's capacity for the next writes.
                if left == self.tail.len() {
                    self.tail.clear();
                } else {
                    self.tail.advance(left);
                }
                self.seg_off -= left;
                return;
            };
            let k = left.min(front.len());
            left -= k;
            if k == front.len() {
                if let Some(done) = self.segs.pop_front()
                    && done.own
                {
                    pool.put(done.bytes);
                }
                if self.seg > 0 {
                    self.seg -= 1;
                } else {
                    self.seg_off = 0;
                }
            } else {
                front.advance(k);
                if self.seg == 0 {
                    self.seg_off -= k;
                }
            }
        }
    }

    /// The runs of the held (sent) bytes, oldest first.
    fn kept_runs(&self) -> impl Iterator<Item = &[u8]> {
        (0..=self.seg).map(move |i| {
            let r = self.run(i);
            if i == self.seg { &r[..self.seg_off] } else { r }
        })
    }

    /// Copies `dst.len()` sent bytes starting `off` bytes after the first
    /// one held (reinjection). Returns `false` when they are not held.
    pub(crate) fn copy_kept(&self, off: u64, dst: &mut [u8]) -> bool {
        if off + dst.len() as u64 > self.kept {
            return false;
        }
        let mut skip = off as usize;
        let mut done = 0;
        for run in self.kept_runs() {
            if done == dst.len() {
                break;
            }
            if skip >= run.len() {
                skip -= run.len();
                continue;
            }
            let k = (run.len() - skip).min(dst.len() - done);
            dst[done..done + k].copy_from_slice(&run[skip..skip + k]);
            skip = 0;
            done += k;
        }
        done == dst.len()
    }

    /// The sent bytes at `off..off + len` after the first one held, without
    /// copying, when they lie in one frozen segment.
    pub(crate) fn shared_kept(&self, off: u64, len: usize) -> Option<Bytes> {
        if off + len as u64 > self.kept {
            return None;
        }
        let mut skip = off as usize;
        for seg in self.segs.iter().take(self.seg + 1).map(|s| &s.bytes) {
            let l = seg.len();
            if skip >= l {
                skip -= l;
                continue;
            }
            return (skip + len <= l).then(|| seg.slice(skip..skip + len));
        }
        None
    }

    /// Drops all data, sent and unsent; the buffers keep their capacity
    /// (a discarded stream's buffers serve the next stream).
    pub(crate) fn clear(&mut self) {
        self.segs.clear();
        self.tail.clear();
        self.len = 0;
        self.kept = 0;
        self.seg = 0;
        self.seg_off = 0;
    }

    /// Heap bytes the buffers hold.
    pub(crate) fn capacity(&self) -> usize {
        self.tail.capacity() + self.segs.capacity() * size_of::<Seg>()
    }

    /// Drops the unsent data; sent bytes stay held.
    pub(crate) fn clear_unsent(&mut self) {
        self.truncate(0);
    }

    /// Drops every unsent byte beyond the first `keep`.
    pub(crate) fn truncate(&mut self, keep: u64) {
        if keep >= self.len {
            return;
        }
        if self.kept == 0 && keep == 0 {
            self.clear();
            return;
        }
        // Walk from the cursor, keeping `keep` bytes.
        let mut left = keep as usize;
        let mut i = self.seg;
        let mut off = self.seg_off;
        while left > 0 {
            let avail = self.run(i).len() - off;
            let k = avail.min(left);
            left -= k;
            off += k;
            if left > 0 {
                i += 1;
                off = 0;
            }
        }
        // Run `i` keeps its first `off` bytes; later ones go.
        if i < self.segs.len() {
            if off > 0 {
                self.segs[i].bytes.truncate(off);
                self.segs.truncate(i + 1);
            } else {
                self.segs.truncate(i);
            }
            self.tail.clear();
        } else {
            self.tail.truncate(off);
        }
        self.len = keep;
    }
}

/// A reset this endpoint owes or sent on its sending part.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct LocalReset {
    pub(crate) code: u64,
    /// Application bytes that must still be delivered (the reliable
    /// boundary), for RESET_STREAM_AT.
    pub(crate) reliable_app: Option<u64>,
    /// The preamble stays reliable (EXTENSIONS.md Section 4.5).
    pub(crate) keep_preamble: bool,
    /// The reset answers the peer's STOP_SENDING.
    pub(crate) answer: bool,
    /// The frame was written.
    pub(crate) written: bool,
}

/// What ended the sending part first (STATE_MACHINE.md Section 2.5: the
/// first outcome wins).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SendOutcome {
    /// The application finished the stream.
    Finished,
    /// The application reset the stream.
    Reset,
    /// The peer sent STOP_SENDING with this code.
    Stopped(u64),
}

/// The waiting state of a sending part's writer: the fair share, and in a
/// multipath session the age test (boxed, so that single-pipe streams do
/// not carry it).
#[derive(Debug, Default)]
pub(crate) struct Waits {
    /// A write waits for send-buffer space.
    pub(crate) waiting: bool,
    /// Counted in the session's `send_holders` (holds more than the floor, or
    /// a write waits).
    pub(crate) holding: bool,
    /// Bytes counted in the session's `small_held` (a direction within its
    /// floor and with no write waiting).
    pub(crate) small: u64,
    /// Multipath: how long data waits.
    pub(crate) age: Option<Box<Age>>,
}

/// The ages of a multipath sending part's waiting data.
#[derive(Debug, Default)]
pub(crate) struct Age {
    /// Write marks of uncommitted bytes: (end, in application bytes
    /// written; when the bytes started to wait). Oldest first.
    pub(crate) marks: VecDeque<(u64, Instant)>,
    /// Since when the current (or last) write waited for space.
    pub(crate) wait_start: Option<Instant>,
    /// When the last waiting write completed.
    pub(crate) wait_end: Option<Instant>,
    /// When stream credit last arrived after the part was blocked on it.
    pub(crate) credit_at: Option<Instant>,
    /// When reinjected information was first queued and is still pending.
    pub(crate) lost_at: Option<Instant>,
}

impl Waits {
    /// The age state, created on first use.
    pub(crate) fn age_mut(&mut self) -> &mut Age {
        self.age.get_or_insert_with(Box::default)
    }
}

/// The sending part of a stream.
#[derive(Debug)]
pub(crate) struct SendPart {
    pub(crate) state: SendState,
    /// The first outcome.
    pub(crate) outcome: Option<SendOutcome>,
    pub(crate) buf: SendBuf,
    /// Next stream offset to send.
    pub(crate) offset: u64,
    /// The peer's MAX_STREAM_DATA.
    pub(crate) max_data: u64,
    /// STREAM_DATA_BLOCKED to send at this limit.
    pub(crate) blocked_at: Option<u64>,
    /// The limit last reported in STREAM_DATA_BLOCKED.
    pub(crate) blocked_reported: Option<u64>,
    /// The application finished the stream.
    pub(crate) fin: bool,
    /// The FIN was written.
    pub(crate) fin_sent: bool,
    /// The preamble, built at the first emission (local streams with the
    /// preamble in use).
    pub(crate) preamble: Option<Bytes>,
    /// Bytes of the preamble not yet sent.
    pub(crate) preamble_left: usize,
    /// Preamble size (stream offset where application data starts).
    pub(crate) base: u64,
    /// Total bytes the application wrote.
    pub(crate) written: u64,
    /// RFC 9218 priority for local scheduling.
    pub(crate) priority: Priority,
    /// DRR deficit within the urgency level.
    pub(crate) deficit: i64,
    /// The urgency level whose scheduler queue holds the stream, while it
    /// is queued.
    pub(crate) queued: Option<u8>,
    /// While a writer waits for room: its entry in the session's list of
    /// waiting writers (`SessionCore::send_waiters`).
    pub(crate) waiter: Option<u32>,
    /// Waits until every byte written was sent (`SessionCore::data_sent`).
    pub(crate) sent_waiting: bool,
    /// Write marks and waits (the fair share and the age test).
    pub(crate) waits: Waits,
    /// Multipath-only state, allocated when the stream first needs it in a
    /// multipath session (runtime zero cost on a single pipe).
    pub(crate) mp: Option<Box<SendMp>>,
    /// The rarely used state of a sending part: resets, STOP_SENDING, limits and waits.
    cold: Option<Box<SendCold>>,
}

/// The rarely used state of a sending part: resets, STOP_SENDING, limits
/// and waits.
#[derive(Debug, Clone)]
pub(crate) struct SendCold {
    pub(crate) reset: Option<LocalReset>,
    /// The peer's STOP_SENDING code.
    pub(crate) stopped: Option<u64>,
    /// Reliable boundary set by the application, in application bytes.
    pub(crate) reliable_boundary: Option<u64>,
    /// Last PRIORITY_UPDATE sequence applied from the peer.
    pub(crate) peer_priority_seq: Option<u64>,
    /// Unsent bytes allowed for this stream (`set_send_buffer`).
    pub(crate) send_limit: Option<u64>,
    /// The `min` of a capacity wait, while the part is listed in
    /// `SessionCore::capacity_waiters`.
    pub(crate) capacity_wait: Option<u64>,
}

impl SendCold {
    const NONE: Self = Self {
        reset: None,
        stopped: None,
        reliable_boundary: None,
        peer_priority_seq: None,
        send_limit: None,
        capacity_wait: None,
    };
}

/// The multipath part of a sending part: retention and acknowledgement,
/// reinjection, scheduling state (MULTIPATH.md Sections 7 and 11).
#[derive(Debug, Default)]
pub(crate) struct SendMp {
    /// Multipath retention (MULTIPATH.md Section 7.4): the
    /// stream offset of the first byte held in `buf`.
    pub(crate) buf_floor: u64,
    /// Acknowledged ranges above `buf_floor` (multipath).
    pub(crate) acked: RangeSet,
    /// Ranges to send again (reinjection, multipath).
    pub(crate) lost: RangeSet,
    /// The FIN was acknowledged / must be sent again (multipath).
    pub(crate) fin_acked: bool,
    pub(crate) fin_lost: bool,
    /// The preamble was acknowledged (multipath).
    pub(crate) preamble_acked: bool,
    /// The reset was acknowledged / must be sent again (multipath).
    pub(crate) reset_acked: bool,
    pub(crate) reset_lost: bool,
    /// The smallest Reliable Size sent in a RESET_STREAM_AT (multipath).
    pub(crate) reliable_sent: Option<u64>,
    /// Bytes sent opportunistically up to this offset (MULTIPATH.md
    /// Section 7.5.1).
    pub(crate) opportunistic_to: u64,
    /// The pipe the direction is bound to (`affinity`), with whether the
    /// binding is provisional.
    pub(crate) bound: Option<super::policy::Binding>,
    /// Per-direction scheduler override.
    pub(crate) scheduler: Option<super::policy::Policy>,
    /// The current values of the direction's own `spread-round-robin`
    /// policy, by pipe; absent pipes are at 0.
    pub(crate) rr: Vec<(u64, f64)>,
    /// `set_redundant`: `None` follows the session's `redundancy`.
    pub(crate) redundant: Option<bool>,
    /// The ranges with a redundant copy queued or sent, above the bytes released.
    pub(crate) copied: RangeSet,
    /// The bytes of `copied` not in `acked`, kept as both change: the copy
    /// bound reads it at every ledger sync.
    copies_unacked: u64,
    /// The custom policy's answer for the next chunk.
    pub(crate) picked: Option<super::policy::Picked>,
    /// The pipe that carried the stream's opening frame (multipath): its
    /// datagrams follow it there until the opening is acknowledged
    /// (EXTENSIONS.md Section 6.4).
    pub(crate) open_pipe: Option<u64>,
    /// The STREAM frames of the direction in the pipes' logs (MULTIPATH.md
    /// Section 7.5.1): the first transmissions in offset order, the copies
    /// (reinjected, opportunistic and redundant) in order of their ends,
    /// and the end of the first transmissions logged.
    pub(crate) carried: VecDeque<Carry>,
    pub(crate) copies: VecDeque<Carry>,
    pub(crate) logged_to: u64,
    /// The longest copy logged: a copy that carried byte `x` ends within
    /// it after `x`.
    copy_span: u64,
    /// The direction's place in the list of those held back by stream
    /// credit, while listed (`Mp::credit_blocked`).
    pub(crate) listed: Option<u64>,
    /// Application bytes sent again as copies (reinjected, opportunistic,
    /// redundant).
    pub(crate) resent: u64,
}

/// A STREAM frame in a pipe's log: its stream range, the pipe, and the
/// pipe position after it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Carry {
    pub(crate) off: u64,
    pub(crate) end: u64,
    pub(crate) pipe: u64,
    pub(crate) pos: u64,
}

impl SendMp {
    /// Logs a STREAM frame sent on a pipe.
    pub(crate) fn carry(&mut self, c: Carry) {
        if c.end <= c.off {
            return;
        }
        if c.off >= self.logged_to {
            self.logged_to = c.end;
            self.carried.push_back(c);
        } else {
            // Redundant copies come in offset order and go at the back.
            self.copy_span = self.copy_span.max(c.end - c.off);
            let i = self.copies.partition_point(|x| x.end <= c.end);
            self.copies.insert(i, c);
        }
    }

    /// The frames that carried byte `x`.
    pub(crate) fn carriers(&self, x: u64) -> impl Iterator<Item = Carry> + '_ {
        let i = self.carried.partition_point(|c| c.end <= x);
        let first = self.carried.get(i).filter(|c| c.off <= x).copied();
        // The copies ending after `x`, up to those that start after it
        // whatever their length: the copies are in order of their ends.
        let j = self.copies.partition_point(|c| c.end <= x);
        let last = x.saturating_add(self.copy_span);
        first.into_iter().chain(
            self.copies
                .range(j..)
                .take_while(move |c| c.end <= last)
                .filter(move |c| c.off <= x)
                .copied(),
        )
    }

    /// Bytes `[off, end)` were acknowledged.
    pub(crate) fn ack(&mut self, off: u64, end: u64) {
        let copied = &self.copied;
        let newly: u64 = self
            .acked
            .gaps(off, end)
            .map(|(a, b)| copied.covered(a, b))
            .sum();
        self.copies_unacked -= newly;
        self.acked.insert(off, end);
    }

    /// Bytes `[off, end)` have a redundant copy queued.
    pub(crate) fn copy(&mut self, off: u64, end: u64) {
        let acked = &self.acked;
        let newly: u64 = self
            .copied
            .gaps(off, end)
            .map(|(a, b)| (b - a) - acked.covered(a, b))
            .sum();
        self.copies_unacked += newly;
        self.copied.insert(off, end);
    }

    /// The copy of bytes `[off, end)` was dropped.
    pub(crate) fn uncopy(&mut self, off: u64, end: u64) {
        let acked = &self.acked;
        let gone: u64 = self
            .copied
            .within(off, end)
            .map(|(a, b)| (b - a) - acked.covered(a, b))
            .sum();
        self.copies_unacked -= gone;
        self.copied.remove(off, end);
    }

    /// Forgets the acknowledged bytes below `floor`, released.
    pub(crate) fn release_below(&mut self, floor: u64) {
        debug_assert!(self.acked.contains(self.buf_floor.min(floor), floor));
        self.acked.remove_below(floor);
        self.copied.remove_below(floor);
        self.drop_carried(floor);
    }

    /// Forgets every acknowledged and copied range.
    pub(crate) fn clear_ranges(&mut self) {
        self.acked.clear();
        self.copied.clear();
        self.copies_unacked = 0;
    }

    /// Forgets the frames below `floor` (released bytes are never copied).
    pub(crate) fn drop_carried(&mut self, floor: u64) {
        while self.carried.front().is_some_and(|c| c.end <= floor) {
            self.carried.pop_front();
        }
        while self.copies.front().is_some_and(|c| c.end <= floor) {
            self.copies.pop_front();
        }
    }

    /// The state of a part that never needed any.
    pub(crate) const EMPTY: Self = Self {
        buf_floor: 0,
        acked: RangeSet::new(),
        lost: RangeSet::new(),
        fin_acked: false,
        fin_lost: false,
        preamble_acked: false,
        reset_acked: false,
        reset_lost: false,
        reliable_sent: None,
        opportunistic_to: 0,
        bound: None,
        scheduler: None,
        rr: Vec::new(),
        redundant: None,
        copied: RangeSet::new(),
        copies_unacked: 0,
        picked: None,
        open_pipe: None,
        carried: VecDeque::new(),
        copies: VecDeque::new(),
        logged_to: 0,
        copy_span: 0,
        listed: None,
        resent: 0,
    };
}

static EMPTY_SEND_MP: SendMp = SendMp::EMPTY;

impl SendPart {
    /// A sending part whose data goes into `buf` (an empty buffer, maybe
    /// with capacity from a discarded stream).
    pub(crate) fn with_buf(max_data: u64, buf: SendBuf) -> Self {
        Self {
            state: SendState::Ready,
            outcome: None,
            buf,
            offset: 0,
            max_data,
            blocked_at: None,
            blocked_reported: None,
            fin: false,
            fin_sent: false,
            preamble: None,
            preamble_left: 0,
            base: 0,
            written: 0,
            priority: Priority::new(3, true).unwrap_or(Priority::DEFAULT),
            deficit: 0,
            queued: None,
            waiter: None,
            sent_waiting: false,
            waits: Waits::default(),
            mp: None,
            cold: None,
        }
    }

    /// The rarely used state (the defaults while there is none).
    pub(crate) fn cold(&self) -> &SendCold {
        self.cold.as_deref().unwrap_or(&SendCold::NONE)
    }

    /// The reset owed or sent, without allocating the rarely used state.
    pub(crate) fn reset_mut(&mut self) -> Option<&mut LocalReset> {
        self.cold.as_deref_mut()?.reset.as_mut()
    }

    /// The rarely used state, allocated on first use.
    pub(crate) fn cold_mut(&mut self) -> &mut SendCold {
        self.cold.get_or_insert_with(|| Box::new(SendCold::NONE))
    }

    /// The Reliable Size of a reset, as a stream offset: `None` for a plain
    /// RESET_STREAM.
    pub(crate) fn reset_reliable(&self) -> Option<u64> {
        let r = self.cold().reset?;
        if r.reliable_app.is_none() && !(r.keep_preamble && self.base > 0) {
            return None;
        }
        Some(self.base + r.reliable_app.unwrap_or(0))
    }

    /// Whether the part has stream bytes or a FIN still to send.
    pub(crate) fn has_pending(&self) -> bool {
        if self.cold().reset.is_some() {
            // Only data below a Reliable Size is still owed.
            return self.reset_reliable().is_some_and(|r| self.offset < r) || self.has_lost();
        }
        self.preamble_left > 0
            || !self.buf.is_empty()
            || (self.fin && !self.fin_sent)
            || self.has_lost()
    }

    /// Whether reinjected data or a FIN waits to be sent again.
    pub(crate) fn has_lost(&self) -> bool {
        self.mp
            .as_deref()
            .is_some_and(|m| !m.lost.is_empty() || m.fin_lost)
    }

    /// The multipath state (empty when none was needed).
    pub(crate) fn mp(&self) -> &SendMp {
        self.mp.as_deref().unwrap_or(&EMPTY_SEND_MP)
    }

    /// The multipath state, created on first use.
    pub(crate) fn mp_mut(&mut self) -> &mut SendMp {
        self.mp.get_or_insert_with(Box::default)
    }

    /// The multipath state in a multipath session (`mp`), created on first
    /// use; outside multipath only the state that exists (normally none).
    pub(crate) fn mp_in(&mut self, mp: bool) -> Option<&mut SendMp> {
        if mp {
            Some(self.mp_mut())
        } else {
            self.mp.as_deref_mut()
        }
    }

    /// The stream offset where the bytes still held start (multipath):
    /// the preamble while it is unacknowledged, then `buf_floor`.
    pub(crate) fn held_from(&self) -> u64 {
        if self.preamble.is_some() && !self.mp().preamble_acked {
            0
        } else {
            self.mp().buf_floor
        }
    }

    /// Sent bytes held for reinjection and not yet acknowledged, each
    /// counted once, the preamble included (multipath): what the
    /// retransmit budget bounds. Bytes held
    /// only because an earlier byte is unacknowledged do not count.
    pub(crate) fn unacked(&self) -> u64 {
        // Nothing is retained without multipath state.
        let Some(m) = self.mp.as_deref() else {
            return 0;
        };
        if self.state.is_terminal() {
            return 0;
        }
        let kept = self.buf.kept();
        let mut n = kept - m.acked.covered(m.buf_floor, m.buf_floor + kept);
        if self.preamble.is_some() && !m.preamble_acked {
            let sent = self.base - self.preamble_left as u64;
            n += sent - m.acked.covered(0, sent);
        }
        n
    }

    /// Redundant copy bytes, queued or sent, whose data is still owed and
    /// not acknowledged on any pipe: what the
    /// copy bound counts. After a reset only data below the Reliable Size
    /// is owed.
    pub(crate) fn copies_outstanding(&self) -> u64 {
        let Some(m) = self.mp.as_deref() else {
            return 0;
        };
        if m.copied.is_empty() || self.state.is_terminal() {
            return 0;
        }
        // Bytes below the ones held are acknowledged: only a reset's
        // Reliable Size cuts the count, at the reset's end of the ranges.
        let owed = self.owed_end();
        let beyond: u64 = m
            .copied
            .within(owed, u64::MAX)
            .map(|(a, b)| (b - a) - m.acked.covered(a, b))
            .sum();
        m.copies_unacked - beyond
    }

    /// The end of the stream bytes still owed: all of them, or after a
    /// reset those below its Reliable Size, the smallest one sent
    /// (multipath).
    pub(crate) fn owed_end(&self) -> u64 {
        match self.cold().reset {
            Some(_) => self
                .reset_reliable()
                .map_or(0, |r| r.min(self.mp().reliable_sent.unwrap_or(r))),
            None => u64::MAX,
        }
    }

    /// The first sent byte at or after `from` that is not acknowledged
    /// (multipath).
    pub(crate) fn first_unacked(&self, from: u64) -> u64 {
        self.mp().acked.contiguous_end(from.max(self.held_from()))
    }

    /// Whether new data (or the FIN) waits to be sent, reinjection aside.
    pub(crate) fn has_fresh(&self) -> bool {
        self.preamble_left > 0
            || !self.buf.is_empty()
            || (self.fin && !self.fin_sent && self.cold().reset.is_none())
    }

    /// Whether only a FIN is owed: a zero-length frame that stream and
    /// session credit and the retransmit budget never hold back (SPEC.md
    /// Section 8.2), as it adds nothing to either sum.
    pub(crate) fn fin_only(&self) -> bool {
        self.preamble_left == 0
            && self.buf.is_empty()
            && self.fin
            && !self.fin_sent
            && self.cold().reset.is_none()
    }

    /// Whether stream credit holds the part back.
    pub(crate) fn credit_blocked(&self) -> bool {
        self.offset >= self.max_data && (self.preamble_left > 0 || !self.buf.is_empty())
    }
}

/// The receiving part of a stream.
#[derive(Debug)]
pub(crate) struct RecvPart {
    pub(crate) state: RecvState,
    /// Unread application data.
    pub(crate) buf: RecvBuf,
    /// Stream offset of the first byte of `buf`.
    pub(crate) read_offset: u64,
    /// The highest offset received so far (the end of the contiguous data
    /// outside multipath).
    pub(crate) received: u64,
    /// The end of the data received without gaps: `buf` holds
    /// `read_offset..contig`.
    pub(crate) contig: u64,
    /// Data and offsets received beyond a gap (multipath only), allocated
    /// when the first gap appears.
    gaps: Option<Box<Gaps>>,
    /// Every byte below this offset arrived (or, once the part discards its
    /// data, counts as arrived): each byte releases session credit once,
    /// when it arrives (SPEC.md Section 8.3).
    pub(crate) arrived_to: u64,
    pub(crate) final_size: Option<u64>,
    /// STOP_SENDING still to write.
    pub(crate) stop_pending: bool,
    /// The application read the end of the stream.
    pub(crate) end_read: bool,
    /// The advertised MAX_STREAM_DATA.
    pub(crate) limit: u64,
    /// The current window (auto-tuned).
    pub(crate) window: u64,
    /// The stream's fixed auto-tuning cap (configured, or set by
    /// `set_receive_window`), or no limit under an automatic cap, which the
    /// session's memory allowance bounds instead (SPEC.md Section 8.3 rule
    /// 4).
    pub(crate) max_window: u64,
    /// Auto-tuning (rule RB).
    pub(crate) tuner: StreamTuner,
    /// A MAX_STREAM_DATA update is owed.
    pub(crate) update_pending: bool,
    /// Preamble size; application data starts here.
    pub(crate) preamble_size: Option<u64>,
    /// MAX_STREAM_DATA was lost with a pipe: send the limit again.
    pub(crate) resend: bool,
    /// Application bytes returned to the application.
    pub(crate) app_read: u64,
    /// The part of a local bidirectional stream counts in the session's
    /// `local_recv_open` until it is terminal.
    pub(crate) counts_open: bool,
    /// The rarely used state of a receiving part: resets, STOP_SENDING, blocked reports.
    cold: Option<Box<RecvCold>>,
}

/// The rarely used state of a receiving part: resets, STOP_SENDING,
/// blocked reports.
#[derive(Debug, Clone)]
pub(crate) struct RecvCold {
    /// A reset released the session credit of every byte from here to the
    /// final size that had not arrived; bytes there release nothing more
    /// and are not tracked.
    pub(crate) released_from: Option<u64>,
    /// The peer's reset: code and Reliable Size (the final size for
    /// RESET_STREAM).
    pub(crate) reset: Option<(u64, u64)>,
    /// The application stopped reading with this code.
    pub(crate) stopped: Option<u64>,
    /// Largest limit reported in STREAM_DATA_BLOCKED (NE-4).
    pub(crate) blocked_seen: Option<u64>,
}

impl RecvCold {
    const NONE: Self = Self {
        released_from: None,
        reset: None,
        stopped: None,
        blocked_seen: None,
    };
}

impl RecvPart {
    /// A receiving part whose data goes into `buf` (an empty buffer, maybe
    /// with capacity from a discarded stream).
    pub(crate) fn with_buf(window: u64, max_window: u64, storage: BytesMut) -> Self {
        let mut buf = RecvBuf::default();
        buf.give_storage(storage);
        Self {
            max_window: max_window.max(window),
            state: RecvState::Recv,
            buf,
            read_offset: 0,
            received: 0,
            contig: 0,
            gaps: None,
            arrived_to: 0,
            final_size: None,
            stop_pending: false,
            end_read: false,
            limit: window,
            window,
            tuner: StreamTuner::default(),
            update_pending: false,
            cold: None,
            preamble_size: None,
            resend: false,
            app_read: 0,
            counts_open: false,
        }
    }

    /// The rarely used state (the defaults while there is none).
    pub(crate) fn cold(&self) -> &RecvCold {
        self.cold.as_deref().unwrap_or(&RecvCold::NONE)
    }

    /// The rarely used state, allocated on first use.
    pub(crate) fn cold_mut(&mut self) -> &mut RecvCold {
        self.cold.get_or_insert_with(|| Box::new(RecvCold::NONE))
    }

    /// Bytes counted against the session window: max(received, final size).
    pub(crate) fn counted(&self) -> u64 {
        self.received.max(self.final_size.unwrap_or(0))
    }

    /// Records the arrival of `[start, end)`. Returns how many of its bytes
    /// arrived for the first time below the range a reset released: the
    /// bytes whose session credit is handled now (SPEC.md Section 8.3).
    /// Bytes beyond a gap are not counted before they arrive.
    pub(crate) fn arrive(&mut self, start: u64, end: u64) -> u64 {
        let end = end.min(self.cold().released_from.unwrap_or(u64::MAX));
        let start = start.max(self.arrived_to);
        if start >= end {
            return 0;
        }
        if start == self.arrived_to && self.gaps.as_ref().is_none_or(|g| g.arrived.is_empty()) {
            // In order: the common case and the only one on a single pipe.
            self.arrived_to = end;
            return end - start;
        }
        let arrived = &mut self.gaps.get_or_insert_with(Box::default).arrived;
        let fresh = arrived.insert(start, end, self.arrived_to);
        if let Some(e) = arrived.advance(self.arrived_to) {
            self.arrived_to = e;
        }
        fresh
    }

    /// Bytes of `[start, end)` that arrived.
    pub(crate) fn arrived_in(&self, start: u64, end: u64) -> u64 {
        if start >= end {
            return 0;
        }
        let below = self.arrived_to.min(end).saturating_sub(start);
        below
            + self
                .gaps
                .as_ref()
                .map_or(0, |g| g.arrived.covered(start.max(self.arrived_to), end))
    }

    /// A reset with this Reliable Size and final size: the bytes of
    /// [Reliable Size, final size) that have not arrived will never be
    /// delivered; returns how many, released now and never again (SPEC.md
    /// Section 8.3). A reset that lowers the Reliable Size releases the
    /// bytes between the two.
    pub(crate) fn credit_reset(&mut self, reliable: u64, final_size: u64) -> u64 {
        let upto = self.cold().released_from.unwrap_or(final_size);
        if reliable >= upto {
            return 0;
        }
        self.cold_mut().released_from = Some(reliable);
        (upto - reliable) - self.arrived_in(reliable, upto)
    }

    /// Bytes below the final size whose credit is not handled: below a
    /// reset's Reliable Size and not arrived yet. Discarding the part
    /// releases them, since they would be discarded on arrival.
    pub(crate) fn credit_owed(&self) -> u64 {
        self.final_size.map_or(0, |fs| {
            let limit = self.cold().released_from.unwrap_or(fs);
            limit - self.arrived_in(0, limit)
        })
    }

    /// Distinct bytes at or beyond `base` that arrived (or counted as
    /// arrived when the part discarded its data); never decreases.
    pub(crate) fn arrived_from(&self, base: u64) -> u64 {
        self.arrived_in(base, u64::MAX)
    }

    /// Stores `data` at stream offset `off` (reassembly by offset, RFC 9000
    /// Section 2.2). Bytes below `contig` or already held are duplicates.
    /// Returns the bytes newly stored.
    pub(crate) fn store(&mut self, off: u64, data: &[u8], src: Option<(&Bytes, Backing)>) -> u64 {
        let end = off + data.len() as u64;
        if end <= self.contig {
            return 0;
        }
        let (off, data) = if off < self.contig {
            let skip = (self.contig - off) as usize;
            (self.contig, &data[skip..])
        } else {
            (off, data)
        };
        // In-order data references the read buffer it arrived in, when the
        // driver handed one over; anything else is copied.
        let push = |buf: &mut RecvBuf, d: &[u8]| match src {
            Some((b, backing)) if within(b, d) => buf.push_shared(b.slice_ref(d), backing),
            _ => buf.push_copy(d),
        };
        if off == self.contig && self.gaps.as_ref().is_none_or(|g| g.held.is_empty()) {
            // In order: the common case and the only one on a single pipe.
            push(&mut self.buf, data);
            self.contig = end;
            return data.len() as u64;
        }
        let mut stored = 0u64;
        let mut rest = (off, data);
        if off == self.contig {
            // Fills the first gap, up to the next held range.
            let next = self
                .gaps
                .as_ref()
                .and_then(|g| g.held.first())
                .map_or(end, |o| o.min(end));
            let k = (next - off) as usize;
            push(&mut self.buf, &data[..k]);
            self.contig = next;
            stored += k as u64;
            rest = (next, &data[k..]);
        }
        if !rest.1.is_empty() {
            // Beyond a gap: held, a large piece of the read buffer
            // referenced as in-order data is.
            let held = &mut self.gaps.get_or_insert_with(Box::default).held;
            stored += held.store(rest.0, rest.1, self.read_offset, src);
        }
        let trimmed = self.pull_ooo();
        debug_assert_eq!(trimmed, 0, "held ranges start beyond the contiguous data");
        stored
    }

    /// Whether any received data, in order or held, references a read
    /// buffer.
    pub(crate) fn references(&self) -> bool {
        self.buf.references() || self.gaps.as_ref().is_some_and(|g| g.held.references())
    }

    /// Bytes of the received data, in order or held, that reference read
    /// buffers.
    pub(crate) fn referenced(&self) -> usize {
        self.buf.referenced()
            + self.gaps.as_ref().map_or(0, |g| {
                usize::try_from(g.held.referenced()).unwrap_or(usize::MAX)
            })
    }

    /// Whether the part is to be listed among those that reference read
    /// buffers: it references one and is not listed yet.
    pub(crate) fn needs_listing(&mut self) -> bool {
        let new = !self.buf.listed() && self.references();
        if new {
            self.buf.set_listed(true);
        }
        new
    }

    /// Calls `f` with each read buffer the received data references and the
    /// bytes it references in it.
    pub(crate) fn tally(&self, f: &mut impl FnMut(Backing, usize)) {
        self.buf.tally(f);
        if let Some(g) = &self.gaps {
            g.held.tally(f);
        }
    }

    /// Copies the received data of the read buffers `out` names into
    /// storage of the stream's own; returns whether it still references a
    /// read buffer (it stays listed).
    pub(crate) fn copy_out(&mut self, out: &impl Fn(u64) -> bool) -> bool {
        self.buf.copy_out(out);
        if let Some(g) = &mut self.gaps {
            g.held.copy_out(out);
        }
        self.keep_listed()
    }

    /// Whether the part stays listed among those that reference read
    /// buffers (it is unlisted when it references none).
    pub(crate) fn keep_listed(&mut self) -> bool {
        let listed = self.references();
        self.buf.set_listed(listed);
        listed
    }

    /// Ranges held beyond a gap.
    #[cfg(test)]
    pub(crate) fn fragments(&self) -> usize {
        self.gaps.as_ref().map_or(0, |g| g.held.ranges())
    }

    /// Moves held ranges that became contiguous into `buf` after the
    /// preamble moved the contiguous end; returns the held bytes that lay
    /// below it (preamble bytes that also arrived in a later frame), which
    /// left the buffers.
    pub(crate) fn pull_held(&mut self) -> u64 {
        self.pull_ooo()
    }

    /// Moves held ranges that became contiguous into `buf`; returns the
    /// held bytes below the contiguous end, dropped.
    fn pull_ooo(&mut self) -> u64 {
        let Some(g) = self.gaps.as_mut() else {
            return 0;
        };
        let (contig, trimmed) = g.held.pull(self.contig, &mut self.buf);
        self.contig = contig;
        trimmed
    }

    /// Heap bytes of the received data held for the application, with
    /// its bookkeeping (SPEC.md Section 9.8).
    pub(crate) fn memory(&self) -> usize {
        self.buf.memory()
            + self.tuner.memory()
            + self.gaps.as_ref().map_or(0, |g| {
                size_of::<Gaps>() + g.held.memory() + g.arrived.memory()
            })
    }

    /// Bytes held for the application, contiguous or not.
    pub(crate) fn held(&self) -> u64 {
        self.buf.len() as u64 + self.gaps.as_ref().map_or(0, |g| g.held.bytes())
    }

    /// Drops held data at or beyond stream offset `limit`; returns the
    /// bytes dropped.
    pub(crate) fn drop_from(&mut self, limit: u64) -> u64 {
        let mut dropped = 0;
        let keep = limit.saturating_sub(self.read_offset);
        if (self.buf.len() as u64) > keep {
            dropped += self.buf.truncate(keep as usize) as u64;
            self.contig = self.contig.min(limit.max(self.read_offset));
        }
        if let Some(g) = self.gaps.as_mut() {
            dropped += g.held.drop_from(limit);
        }
        dropped
    }

    /// Drops all held data; returns the bytes dropped. A large buffer is
    /// released: nothing will be stored in it again.
    pub(crate) fn drop_all(&mut self) -> u64 {
        let n = self.held();
        self.buf.clear(RECV_KEEP);
        if let Some(g) = self.gaps.as_mut() {
            g.held.clear();
        }
        n
    }
}

/// Whether `part` lies within `whole`'s bytes.
fn within(whole: &Bytes, part: &[u8]) -> bool {
    let (w, p) = (whole.as_ptr() as usize, part.as_ptr() as usize);
    p >= w && p + part.len() <= w + whole.len()
}

/// What a receiving part keeps of the data and offsets received beyond a
/// gap (multipath): the data in memory bounded by the span however the
/// peer fragments it (SPEC.md Section 9.8), and the offsets that arrived
/// beyond `arrived_to` (session credit).
#[derive(Debug, Default)]
struct Gaps {
    held: Held,
    arrived: Arrived,
}

/// How the stream is offered to the application.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Offer {
    /// Local stream, owned by the application from creation.
    Local,
    /// Peer stream not offered yet (waits for its preamble or for lower
    /// streams).
    Pending,
    /// In the accept queue.
    Queued,
    /// Accepted by the application.
    Accepted,
    /// Rejected by the stack (GOAWAY): never offered, needs no release.
    Rejected,
}

/// Why a local stream fails after the peer's GOAWAY (EXTENSIONS.md Section
/// 3.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GoAwayFail {
    /// Emitted or pinned, at or above the watermark: the peer does not
    /// process it ("rejected").
    Rejected,
    /// Neither emitted nor pinned when the GOAWAY arrived: it never opens
    /// ("going away").
    GoingAway,
}

impl GoAwayFail {
    /// The error the stream's operations report.
    pub(crate) fn error(self) -> super::StreamError {
        match self {
            Self::Rejected => super::StreamError::Rejected,
            Self::GoingAway => super::StreamError::GoingAway,
        }
    }
}

/// One stream.
#[derive(Debug)]
pub(crate) struct Stream {
    pub(crate) id: Option<u64>,
    pub(crate) dir: Dir,
    pub(crate) local: bool,
    pub(crate) send: Option<SendPart>,
    pub(crate) recv: Option<RecvPart>,
    pub(crate) offer: Offer,
    /// The application released its handles.
    pub(crate) released: bool,
    /// The application dropped its sending handle.
    pub(crate) send_released: bool,
    /// The application dropped its receiving handle.
    pub(crate) recv_released: bool,
    /// The identifier was requested before the first frame (SPEC.md 7.2).
    pub(crate) pinned: bool,
    /// The opening frame of a pinned stream is owed.
    pub(crate) open_pending: bool,
    /// The application declined the stream (EXTENSIONS.md 7.2).
    pub(crate) rejected: bool,
    /// The stream failed because of the peer's GOAWAY.
    pub(crate) goaway: Option<GoAwayFail>,
    /// The stream's datagram flow, from its first datagram: most streams
    /// carry none and pay one pointer for it.
    pub(crate) datagrams: Option<Box<StreamDatagrams>>,
    /// The application byte counters, once a driver or the application
    /// asked for them ([`super::SessionCore::stream_meter`]).
    pub(crate) meter: Option<Arc<Meter>>,
    /// Queued for a control frame.
    pub(crate) ctrl_queued: bool,
    /// Pending readiness notifications.
    pub(crate) notified_readable: bool,
    pub(crate) notified_writable: bool,
    /// The sending direction waits for a custom scheduling decision: in
    /// the multipath pick queue or in the call under way.
    pub(crate) pick_queued: Cell<bool>,
    /// The preamble's contents and the PRIORITY_UPDATE state: most streams have none.
    extra: Option<Box<StreamExtra>>,
}

/// The preamble's contents and the PRIORITY_UPDATE state: most streams have
/// none.
#[derive(Debug, Clone)]
pub(crate) struct StreamExtra {
    /// OPEN_INFO of a peer stream, or the one to send on a local stream.
    pub(crate) open_info: Option<Bytes>,
    /// PRIORITY requested by the peer's preamble (peer streams), or to
    /// request from the peer (local streams, before the first frame).
    pub(crate) peer_priority: Option<Priority>,
    /// PIPE_CARRIER: sent by the peer (bidirectional peer streams), or to
    /// send (local streams).
    pub(crate) pipe_carrier: bool,
    /// Encoded TLVs holding the application TLVs: the peer's preamble body
    /// (peer streams that carried any), or the ones to send (local
    /// streams). Iterated with `AppTlvs`.
    pub(crate) app_tlvs: Option<Bytes>,
    /// Next PRIORITY_UPDATE sequence number to send.
    pub(crate) priority_seq: u64,
    /// PRIORITY_UPDATE to send.
    pub(crate) priority_update: Option<Priority>,
    /// The last PRIORITY_UPDATE sent (multipath: re-sent when lost).
    pub(crate) priority_sent: Option<(u64, Priority)>,
    pub(crate) priority_resend: bool,
}

impl StreamExtra {
    const NONE: Self = Self {
        open_info: None,
        peer_priority: None,
        pipe_carrier: false,
        app_tlvs: None,
        priority_seq: 1,
        priority_update: None,
        priority_sent: None,
        priority_resend: false,
    };
}

/// A stream's datagram flow (datagram flows).
#[derive(Debug, Default)]
pub(crate) struct StreamDatagrams {
    /// Received datagrams, not yet read.
    pub(crate) queue: VecDeque<(u64, Bytes)>,
    /// Counts.
    pub(crate) counts: DatagramCounts,
}

/// The counts of a stream's datagrams.
#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct DatagramCounts {
    pub(crate) sent: u64,
    pub(crate) received: u64,
    pub(crate) dropped_recv: u64,
    pub(crate) bytes_sent: u64,
    pub(crate) bytes_received: u64,
}

impl Stream {
    /// The stream's datagram flow, created on first use.
    pub(crate) fn datagrams_mut(&mut self) -> &mut StreamDatagrams {
        self.datagrams.get_or_insert_default()
    }

    /// The stream's datagram counts.
    pub(crate) fn datagram_counts(&self) -> DatagramCounts {
        self.datagrams
            .as_ref()
            .map(|d| d.counts)
            .unwrap_or_default()
    }

    /// Counts application bytes on the stream's meter, if it has one.
    #[inline]
    pub(crate) fn count(&self, c: Count, n: u64) {
        if let Some(m) = &self.meter {
            m.add(c, n);
        }
    }

    pub(crate) fn new(dir: Dir, local: bool) -> Self {
        Self {
            id: None,
            dir,
            local,
            send: None,
            recv: None,
            offer: if local { Offer::Local } else { Offer::Pending },
            released: false,
            send_released: false,
            recv_released: false,
            pinned: false,
            open_pending: false,
            rejected: false,
            goaway: None,
            extra: None,
            datagrams: None,
            meter: None,
            ctrl_queued: false,
            notified_readable: false,
            notified_writable: false,
            pick_queued: Cell::new(false),
        }
    }

    /// The preamble's contents and the PRIORITY_UPDATE state (the
    /// defaults while there are none).
    pub(crate) fn extra(&self) -> &StreamExtra {
        self.extra.as_deref().unwrap_or(&StreamExtra::NONE)
    }

    /// The sending part, mutable, with the preamble's contents.
    pub(crate) fn send_and_extra(&mut self) -> (Option<&mut SendPart>, &StreamExtra) {
        (
            self.send.as_mut(),
            self.extra.as_deref().unwrap_or(&StreamExtra::NONE),
        )
    }

    /// The preamble's contents and the PRIORITY_UPDATE state, allocated on
    /// first use.
    pub(crate) fn extra_mut(&mut self) -> &mut StreamExtra {
        self.extra
            .get_or_insert_with(|| Box::new(StreamExtra::NONE))
    }

    /// Whether every part is terminal (STATE_MACHINE.md Section 2.3).
    pub(crate) fn parts_terminal(&self) -> bool {
        self.send.as_ref().is_none_or(|s| s.state.is_terminal())
            && self.recv.as_ref().is_none_or(|r| r.state.is_terminal())
    }
}

/// Streams per slab page.
const PAGE: usize = 64;

/// A slot: its generation, whether its key is in the touched list, and
/// the stream it holds.
#[derive(Debug, Default)]
struct Entry {
    generation: u32,
    touched: Cell<bool>,
    stream: Option<Stream>,
}

/// A slab of streams with generation-checked keys. Slots are allocated in
/// pages of [`PAGE`] so that growing never reserves more than a page of
/// unused slots.
///
/// With tracking on (multipath sessions) the slab notes every stream it
/// hands out for change, or removes: the scheduler's running aggregates
/// (`ledger.rs`) bring exactly those up to date before they are read, so
/// no change to a stream can bypass them.
#[derive(Debug, Default)]
pub(crate) struct Slab {
    pages: Vec<Box<[Entry]>>,
    free: Vec<u32>,
    /// Slots handed out so far.
    next: u32,
    len: usize,
    track: bool,
    touched: RefCell<Vec<StreamKey>>,
}

impl Slab {
    fn entry(&self, slot: u32) -> Option<&Entry> {
        let slot = slot as usize;
        self.pages.get(slot / PAGE).map(|p| &p[slot % PAGE])
    }

    fn entry_mut(&mut self, slot: u32) -> Option<&mut Entry> {
        let slot = slot as usize;
        self.pages.get_mut(slot / PAGE).map(|p| &mut p[slot % PAGE])
    }

    pub(crate) fn insert(&mut self, stream: Stream) -> StreamKey {
        self.len += 1;
        let slot = match self.free.pop() {
            Some(slot) => slot,
            None => {
                let slot = self.next;
                self.next += 1;
                if slot as usize / PAGE == self.pages.len() {
                    self.pages
                        .push((0..PAGE).map(|_| Entry::default()).collect());
                }
                slot
            }
        };
        let entry = self.entry_mut(slot).expect("slot allocated");
        entry.generation = entry.generation.wrapping_add(1);
        entry.stream = Some(stream);
        StreamKey {
            slot,
            generation: entry.generation,
        }
    }

    pub(crate) fn get(&self, key: StreamKey) -> Option<&Stream> {
        match self.entry(key.slot) {
            Some(e) if e.generation == key.generation => e.stream.as_ref(),
            _ => None,
        }
    }

    pub(crate) fn get_mut(&mut self, key: StreamKey) -> Option<&mut Stream> {
        let track = self.track;
        let e = self
            .pages
            .get_mut(key.slot as usize / PAGE)
            .map(|p| &mut p[key.slot as usize % PAGE])?;
        if e.generation != key.generation {
            return None;
        }
        let s = e.stream.as_mut()?;
        if track && !e.touched.replace(true) {
            self.touched.get_mut().push(key);
        }
        Some(s)
    }

    pub(crate) fn remove(&mut self, key: StreamKey) -> Option<Stream> {
        let track = self.track;
        let entry = self.entry_mut(key.slot)?;
        if entry.generation != key.generation {
            return None;
        }
        let s = entry.stream.take()?;
        // The key leaves the aggregates; the slot's next stream starts
        // untouched.
        entry.touched.set(false);
        if track {
            self.touched.get_mut().push(key);
        }
        self.free.push(key.slot);
        self.len -= 1;
        Some(s)
    }

    pub(crate) fn len(&self) -> usize {
        self.len
    }

    pub(crate) fn keys(&self) -> impl Iterator<Item = StreamKey> + '_ {
        self.pages
            .iter()
            .flat_map(|p| p.iter())
            .enumerate()
            .filter_map(|(i, e)| {
                e.stream.as_ref().map(|_| StreamKey {
                    slot: i as u32,
                    generation: e.generation,
                })
            })
    }

    /// Starts noting changed streams, every present one first.
    pub(crate) fn track(&mut self) {
        if std::mem::replace(&mut self.track, true) {
            return;
        }
        let keys: Vec<StreamKey> = self.keys().collect();
        for key in keys {
            self.get_mut(key);
        }
    }

    /// Whether streams changed since the last [`Self::take_touched`].
    pub(crate) fn has_touched(&self) -> bool {
        !self.touched.borrow().is_empty()
    }

    /// Calls `f` with every stream changed or removed since the last call
    /// (`None` for a removed one), and forgets them.
    pub(crate) fn take_touched(&self, mut f: impl FnMut(StreamKey, Option<&Stream>)) {
        let mut touched = self.touched.borrow_mut();
        for &key in touched.iter() {
            let e = self
                .entry(key.slot)
                .filter(|e| e.generation == key.generation);
            if let Some(e) = e {
                e.touched.set(false);
            }
            f(key, e.and_then(|e| e.stream.as_ref()));
        }
        touched.clear();
    }

    pub(crate) fn memory(&self) -> usize {
        self.pages.len() * PAGE * size_of::<Entry>()
            + self.pages.capacity() * size_of::<Box<[Entry]>>()
            + self.free.capacity() * 4
            + self.touched.borrow().capacity() * size_of::<StreamKey>()
    }
}

/// The stream index (SPEC.md Section 7.1).
pub(crate) const fn index(id: u64) -> u64 {
    id >> 2
}

/// The stream type of an identifier.
pub(crate) const fn dir_of(id: u64) -> Dir {
    if id & 2 == 0 { Dir::Bidi } else { Dir::Uni }
}

/// Whether the client (initiator) opened the stream.
pub(crate) const fn client_initiated(id: u64) -> bool {
    id & 1 == 0
}

/// The identifier of stream `index` of a type and initiator.
pub(crate) const fn make_id(index: u64, dir: Dir, client: bool) -> u64 {
    (index << 2) | if matches!(dir, Dir::Uni) { 2 } else { 0 } | if client { 0 } else { 1 }
}
