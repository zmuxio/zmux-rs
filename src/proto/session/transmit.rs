//! The batch that `poll_transmit` fills: records whose frame headers and
//! small payloads are copied into one reusable buffer, interleaved with
//! larger payloads that are referenced without copying.

use std::io::IoSlice;

use bytes::Bytes;

use crate::proto::codec::Writer;
use crate::proto::error::EncodeError;
use crate::proto::frame::Frame;
use crate::proto::record::Framing;
use crate::proto::varint;

/// Payloads shorter than this are copied into the batch; longer ones are
/// referenced.
pub const COPY_THRESHOLD: usize = 4096;

/// The default batch limit.
pub const DEFAULT_BATCH: usize = 256 * 1024;

#[derive(Debug, Clone)]
enum Part {
    /// Bytes of `buf`.
    Copied { start: usize, end: usize },
    /// A referenced payload.
    Shared(Bytes),
}

/// A piece of a batch for a carrier that takes owned buffers
/// ([`TransmitBuf::take_pieces`]).
#[derive(Debug)]
pub enum Piece<'a> {
    /// Bytes built into the batch (record headers, frame headers, small
    /// payloads).
    Copied(&'a [u8]),
    /// A payload the batch references, shared without copying.
    Shared(Bytes),
}

/// Where a walk of a batch by [`TransmitBuf::take_pieces`] ended, so that
/// the next one resumes there instead of walking the batch from its start:
/// a batch written in many calls is walked once. A cursor belongs to one
/// [`TransmitBuf`]; it holds for the batch as it was, and once the batch
/// changed (a new `poll_transmit`, a [`TransmitBuf::clear`]) the walk
/// starts over.
#[derive(Debug, Clone, Copy, Default)]
pub struct PieceCursor {
    /// The batch's version.
    version: u64,
    /// A part, and the batch offset of its first byte.
    part: usize,
    at: usize,
}

/// The first allocation of the copied bytes of a batch.
const FIRST_COPY: usize = 1024;

/// The storage of a small batch (a quiet pipe's record or two): its copied
/// bytes, parts and record ends.
type SmallStorage = (Vec<u8>, Vec<Part>, Vec<u64>);

/// Small batch storages a thread keeps for the next small batches: a quiet
/// pipe frees its storage once its batch is written (no pipe holds one while
/// idle), and the next small batch of any pipe takes one back instead of
/// allocating.
const SMALL_SPARE: usize = 8;

/// Small batch storages kept for every thread, beyond a thread's own: a
/// thread that only frees them (a pipe's writes end on it) passes them to
/// a thread that only takes them (the pipe's next batch starts there), so
/// that an exchange between tasks on different threads allocates nothing.
const SMALL_SHARED: usize = 64;

static SHARED_SMALL: std::sync::Mutex<Vec<SmallStorage>> = std::sync::Mutex::new(Vec::new());

/// The most parts a small batch's storage has room for.
const SMALL_PARTS: usize = 16;

thread_local! {
    static SMALL: std::cell::RefCell<Vec<SmallStorage>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

/// One `poll_transmit` batch. Write it completely with
/// [`TransmitBuf::io_slices`] (or [`TransmitBuf::copy_to_vec`]) before the
/// next `poll_transmit` on the same pipe; `poll_transmit` clears it.
#[derive(Debug)]
pub struct TransmitBuf {
    buf: Vec<u8>,
    parts: Vec<Part>,
    len: usize,
    max_len: usize,
    /// The largest message of a message-framed pipe.
    max_message: usize,
    /// The open record: index of its first part, where its Size slot
    /// starts in `buf`, the slot width and the batch length at its start.
    record: Option<(usize, usize, usize, usize)>,
    /// The framing of the pipe the batch is for.
    framing: Framing,
    /// Message lengths, for a message-framed pipe.
    messages: Vec<usize>,
    /// The batch's length in byte-stream form at the end of each record
    /// (positions count messages in that form, MULTIPATH.md Section 2.3).
    record_ends: Vec<u64>,
    stream_len: u64,
    /// Changes with every change of the parts, for [`PieceCursor`]
    /// (starts at 1: a default cursor is never current).
    version: u64,
}

impl Default for TransmitBuf {
    fn default() -> Self {
        Self::with_capacity(DEFAULT_BATCH)
    }
}

impl TransmitBuf {
    /// A batch of at most `max_len` bytes. Buffers grow on demand and are
    /// reused; [`TransmitBuf::shrink`] returns them.
    #[must_use]
    pub fn with_capacity(max_len: usize) -> Self {
        Self {
            buf: Vec::new(),
            parts: Vec::new(),
            len: 0,
            max_len,
            max_message: usize::MAX,
            record: None,
            framing: Framing::ByteStream,
            messages: Vec::new(),
            record_ends: Vec::new(),
            stream_len: 0,
            version: 1,
        }
    }

    /// Total bytes in the batch.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Whether the batch is empty.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The batch limit.
    pub fn max_len(&self) -> usize {
        self.max_len
    }

    /// Sets the batch limit for the next `poll_transmit`, for example to
    /// the room a carrier reports.
    pub fn set_max_len(&mut self, max_len: usize) {
        self.max_len = max_len;
    }

    /// Sets the largest message of the next batches for a message-framed
    /// pipe (SPEC.md Section 3.4), where one write call carries one
    /// message: the write-call bound
    /// ([`SessionCore::write_call_limit`](super::SessionCore::write_call_limit)),
    /// within which the records are then built. A
    /// frame that cannot be split may still exceed it. No limit by default;
    /// the record size limit always applies.
    pub fn set_max_message(&mut self, max_message: usize) {
        self.max_message = max_message;
    }

    /// The largest message of a message-framed pipe.
    pub(crate) fn max_message(&self) -> usize {
        self.max_message
    }

    /// Bytes still allowed in this batch.
    pub(crate) fn room(&self) -> usize {
        self.max_len.saturating_sub(self.len)
    }

    /// Empties the batch, releasing referenced payloads.
    pub fn clear(&mut self) {
        self.version += 1;
        self.buf.clear();
        self.parts.clear();
        self.messages.clear();
        self.record_ends.clear();
        self.stream_len = 0;
        self.len = 0;
        self.record = None;
    }

    /// The batch's length in byte-stream form (a message counts as its
    /// record with a shortest Size field).
    pub fn stream_len(&self) -> u64 {
        self.stream_len
    }

    /// The byte-stream length at the end of each record of the batch.
    pub(crate) fn record_ends(&self) -> &[u64] {
        &self.record_ends
    }

    /// On a message-framed pipe (SPEC.md Section 3.4), the length of each
    /// message of the batch, in order: each is one record's Frames field,
    /// sent without its Size. Empty on a byte-stream pipe.
    pub fn message_lens(&self) -> &[usize] {
        &self.messages
    }

    /// The framing the batch is built for.
    pub(crate) fn set_framing(&mut self, framing: Framing) {
        self.framing = framing;
    }

    /// The width of a record's Size field in this batch (none for
    /// message framing).
    pub(crate) fn size_width(&self, max_body: usize) -> usize {
        match self.framing {
            Framing::ByteStream => varint::len(max_body as u64),
            Framing::Records => 0,
        }
    }

    /// Heap bytes held by the batch's buffers.
    pub fn capacity(&self) -> usize {
        self.buf.capacity()
            + self.parts.capacity() * std::mem::size_of::<Part>()
            + self.messages.capacity() * std::mem::size_of::<usize>()
    }

    /// Whether the batch's storage is that of a small batch, which
    /// [`TransmitBuf::shrink`] keeps for reuse by the thread.
    pub fn is_small(&self) -> bool {
        // A zero-copy batch copies little but has many parts.
        self.buf.capacity() <= FIRST_COPY && self.parts.capacity() <= SMALL_PARTS
    }

    /// Frees the buffers (for idle sessions); small ones go to the
    /// thread's spare storages.
    pub fn shrink(&mut self) {
        self.clear();
        let buf = std::mem::take(&mut self.buf);
        let parts = std::mem::take(&mut self.parts);
        let ends = std::mem::take(&mut self.record_ends);
        self.messages = Vec::new();
        if buf.capacity() > 0 && buf.capacity() <= FIRST_COPY && parts.capacity() <= SMALL_PARTS {
            // The thread's own first, then the shared ones; a thread being
            // torn down keeps nothing.
            let mut spare = Some((buf, parts, ends));
            let _ = SMALL.try_with(|c| {
                if let Ok(mut c) = c.try_borrow_mut()
                    && c.len() < SMALL_SPARE
                {
                    c.extend(spare.take());
                }
            });
            if let Some(spare) = spare
                && let Ok(mut shared) = SHARED_SMALL.lock()
                && shared.len() < SMALL_SHARED
            {
                shared.push(spare);
            }
        }
    }

    /// Room for `total` copied bytes: a small first allocation (a spare
    /// storage of the thread when it has one) while the batch is small,
    /// else once to the batch size, so that a steady transfer never
    /// reallocates.
    fn reserve(&mut self, total: usize) {
        if self.buf.capacity() >= total {
            return;
        }
        if self.buf.capacity() == 0 && total <= FIRST_COPY {
            let spare = SMALL
                .try_with(|c| c.try_borrow_mut().ok().and_then(|mut c| c.pop()))
                .ok()
                .flatten()
                .or_else(|| SHARED_SMALL.lock().ok().and_then(|mut s| s.pop()));
            if let Some((buf, parts, ends)) = spare {
                debug_assert!(buf.is_empty() && parts.is_empty() && ends.is_empty());
                self.buf = buf;
                if self.parts.capacity() == 0 {
                    self.parts = parts;
                }
                if self.record_ends.capacity() == 0 {
                    self.record_ends = ends;
                }
                if self.buf.capacity() >= total {
                    return;
                }
            }
        }
        let want = if total <= FIRST_COPY {
            FIRST_COPY
        } else {
            self.max_len.max(total)
        };
        self.buf.reserve_exact(want - self.buf.len());
    }

    /// The batch as I/O slices for a vectored write.
    pub fn io_slices<'a>(&'a self, out: &mut Vec<IoSlice<'a>>) {
        out.clear();
        for p in &self.parts {
            let s: &[u8] = match p {
                Part::Copied { start, end } => &self.buf[*start..*end],
                Part::Shared(b) => b,
            };
            if !s.is_empty() {
                out.push(IoSlice::new(s));
            }
        }
    }

    /// At most `max` bytes of the batch from byte `offset` on as I/O
    /// slices, as many as fit in `out`; returns how many were filled. For
    /// one bounded call of a vectored write, without allocating.
    pub fn io_slices_from<'a>(
        &'a self,
        offset: usize,
        max: usize,
        out: &mut [IoSlice<'a>],
    ) -> usize {
        let mut skip = offset;
        let mut left = max;
        let mut n = 0;
        for p in &self.parts {
            if n == out.len() || left == 0 {
                break;
            }
            let s: &[u8] = match p {
                Part::Copied { start, end } => &self.buf[*start..*end],
                Part::Shared(b) => b,
            };
            if skip >= s.len() {
                skip -= s.len();
                continue;
            }
            let take = (s.len() - skip).min(left);
            out[n] = IoSlice::new(&s[skip..skip + take]);
            left -= take;
            skip = 0;
            n += 1;
        }
        n
    }

    /// Hands at most `max` bytes of the batch from byte `offset` on to
    /// `take`, piece by piece: built bytes as slices, referenced payloads
    /// as shared [`Bytes`] without copying (for a carrier that takes owned
    /// buffers, such as a stream of another session). `take` returns the
    /// bytes of the piece it took; a piece taken in part ends the walk.
    /// Returns the bytes taken. The walk starts where `cursor` says the
    /// last one ended, when that is at or before `offset` in this batch,
    /// and leaves `cursor` where it ended.
    pub fn take_pieces(
        &self,
        cursor: &mut PieceCursor,
        offset: usize,
        max: usize,
        mut take: impl FnMut(Piece<'_>) -> usize,
    ) -> usize {
        let (first, mut at) = if cursor.version == self.version && cursor.at <= offset {
            (cursor.part, cursor.at)
        } else {
            (0, 0)
        };
        let mut left = max;
        let mut taken = 0;
        let mut part = first;
        for p in self.parts.get(first..).unwrap_or_default() {
            let len = match p {
                Part::Copied { start, end } => end - start,
                Part::Shared(b) => b.len(),
            };
            if left == 0 {
                break;
            }
            let pos = offset + taken;
            if at + len <= pos {
                at += len;
                part += 1;
                continue;
            }
            let skip = pos - at;
            let n = (len - skip).min(left);
            let piece = match p {
                Part::Copied { start, .. } => {
                    Piece::Copied(&self.buf[start + skip..start + skip + n])
                }
                Part::Shared(b) => Piece::Shared(b.slice(skip..skip + n)),
            };
            let t = take(piece).min(n);
            taken += t;
            left -= t;
            if t < n {
                break;
            }
            if skip + t == len {
                at += len;
                part += 1;
            }
        }
        *cursor = PieceCursor {
            version: self.version,
            part,
            at,
        };
        taken
    }

    /// The batch's slices in order.
    pub fn chunks(&self) -> impl Iterator<Item = &[u8]> {
        self.parts.iter().map(|p| match p {
            Part::Copied { start, end } => &self.buf[*start..*end],
            Part::Shared(b) => &b[..],
        })
    }

    /// Appends the batch to `dst`.
    pub fn copy_to_vec(&self, dst: &mut Vec<u8>) {
        dst.reserve(self.len);
        for c in self.chunks() {
            dst.extend_from_slice(c);
        }
    }

    /// Number of separate slices (an estimate of the iovec count).
    pub fn slice_count(&self) -> usize {
        self.parts.len()
    }

    // ---- record building ----------------------------------------------

    /// Whether a record is open.
    pub(crate) fn in_record(&self) -> bool {
        self.record.is_some()
    }

    /// Bytes of frames in the open record.
    pub(crate) fn record_len(&self) -> usize {
        match self.record {
            Some((_, _, width, at)) => self.len - at - width,
            None => 0,
        }
    }

    /// Opens a record whose Frames field will hold at most `max_body`
    /// bytes, reserving room for its Size.
    pub(crate) fn begin_record(&mut self, max_body: usize) {
        debug_assert!(self.record.is_none());
        self.version += 1;
        let width = self.size_width(max_body);
        let start = self.buf.len();
        let at = self.len;
        if width == 0 {
            self.record = Some((self.parts.len(), start, 0, at));
            return;
        }
        self.reserve(start + width);
        self.buf.resize(start + width, 0);
        self.parts.push(Part::Copied {
            start,
            end: start + width,
        });
        self.len += width;
        self.record = Some((self.parts.len() - 1, start, width, at));
    }

    /// Closes the open record, writing its shortest Size. An empty record
    /// is removed. Returns whether a record was completed.
    pub(crate) fn end_record(&mut self) -> bool {
        let Some((part, slot, width, at)) = self.record.take() else {
            return false;
        };
        self.version += 1;
        let body = self.len - at - width;
        if body == 0 {
            self.parts.truncate(part);
            self.buf.truncate(slot);
            self.len = at;
            return false;
        }
        let size_len = varint::len(body as u64);
        self.stream_len += (size_len + body) as u64;
        self.record_ends.push(self.stream_len);
        if width == 0 {
            self.messages.push(body);
            return true;
        }
        let first = slot + width - size_len;
        // Cannot fail: the slot was sized for the largest body.
        let _ = varint::encode(body as u64, &mut self.buf[first..slot + width]);
        if let Some(Part::Copied { start, .. }) = self.parts.get_mut(part) {
            *start = first;
        }
        self.len -= width - size_len;
        true
    }

    /// Extends the last copied part, or starts one, and returns the slice
    /// to fill.
    #[inline]
    fn grow(&mut self, n: usize) -> &mut [u8] {
        self.version += 1;
        let start = self.buf.len();
        self.reserve(start + n);
        self.buf.resize(start + n, 0);
        match self.parts.last_mut() {
            Some(Part::Copied { end, .. }) if *end == start => *end = start + n,
            _ => self.parts.push(Part::Copied {
                start,
                end: start + n,
            }),
        }
        self.len += n;
        &mut self.buf[start..start + n]
    }

    /// Appends an encoded frame to the open record.
    pub(crate) fn push_frame(&mut self, frame: &Frame<'_>) -> Result<(), EncodeError> {
        let n = frame.encoded_len();
        let dst = self.grow(n);
        let mut w = Writer::new(dst);
        frame.write(&mut w)
    }

    /// Appends raw bytes (frame headers, copied payloads).
    pub(crate) fn push_bytes(&mut self, src: &[u8]) {
        self.grow(src.len()).copy_from_slice(src);
    }

    /// Appends `n` bytes produced by `fill` directly in the buffer.
    pub(crate) fn push_with(&mut self, n: usize, fill: impl FnOnce(&mut [u8]) -> usize) {
        let dst = self.grow(n);
        let written = fill(dst);
        debug_assert_eq!(written, n);
    }

    /// Appends a referenced payload.
    pub(crate) fn push_shared(&mut self, payload: Bytes) {
        self.version += 1;
        self.len += payload.len();
        self.parts.push(Part::Shared(payload));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn batch(seed: u8) -> TransmitBuf {
        let mut b = TransmitBuf::default();
        for i in 0..20u8 {
            b.push_bytes(&[seed ^ i; 7]);
            b.push_shared(Bytes::from(vec![seed.wrapping_add(i); 5000]));
        }
        b
    }

    /// Walks the batch in calls of at most `step` bytes, a piece taken in
    /// part every other call, with one cursor or a fresh one each time.
    fn walk(b: &TransmitBuf, cursor: &mut PieceCursor, fresh: bool, step: usize) -> Vec<u8> {
        let mut got = Vec::new();
        let mut partial = false;
        while got.len() < b.len() {
            if fresh {
                *cursor = PieceCursor::default();
            }
            let from = got.len();
            let n = b.take_pieces(cursor, from, step, |piece| {
                let s: &[u8] = match &piece {
                    Piece::Copied(s) => s,
                    Piece::Shared(x) => x,
                };
                partial = !partial;
                let t = if partial {
                    s.len().div_ceil(2)
                } else {
                    s.len()
                };
                got.extend_from_slice(&s[..t]);
                t
            });
            assert!(n > 0);
            assert_eq!(got.len(), from + n);
        }
        got
    }

    #[test]
    fn take_pieces_resumes_at_its_cursor_and_restarts_on_a_new_batch() {
        let a = batch(1);
        let mut want = Vec::new();
        a.copy_to_vec(&mut want);
        let mut cursor = PieceCursor::default();
        for step in [1, 7, 4096, 5003, usize::MAX] {
            assert_eq!(walk(&a, &mut cursor, false, step), want, "step {step}");
            assert_eq!(walk(&a, &mut cursor, true, step), want, "step {step}");
        }
        // The cursor of the batch before it changed is not used.
        let mut b = batch(9);
        let mut cursor = PieceCursor::default();
        let mut want_b = Vec::new();
        b.copy_to_vec(&mut want_b);
        assert_eq!(walk(&b, &mut cursor, false, 3000), want_b);
        b.clear();
        b.push_bytes(&[5; 9]);
        let mut got = Vec::new();
        b.take_pieces(&mut cursor, 0, 100, |piece| match piece {
            Piece::Copied(s) => {
                got.extend_from_slice(s);
                s.len()
            }
            Piece::Shared(x) => {
                got.extend_from_slice(&x);
                x.len()
            }
        });
        assert_eq!(got, [5; 9]);
    }
}
