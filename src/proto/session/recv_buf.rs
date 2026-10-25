//! A stream's received data held for the application: pieces of the driver's
//! read buffers referenced without a
//! copy, and small pieces copied into the stream's own storage.
//!
//! A referenced piece keeps its whole read buffer alive. The session keeps
//! the read buffers the driver has moved on from within twice the bytes
//! the streams reference, copying out the pieces of the least used ones
//! beyond that (`SessionCore::settle_recv_refs`), so that a few bytes of STREAM
//! data in a record of PADDING never keep a whole buffer alive, and a
//! buffer shared by many streams is counted once.

use std::collections::VecDeque;

use bytes::{Buf, Bytes, BytesMut};

/// Pieces below this are copied (the copy
/// threshold).
pub(crate) const REFERENCE_MIN: usize = 4096;

/// The smallest growth of a stream's own storage.
const STORAGE_MIN: usize = 4096;

/// A read buffer of the driver that received data may reference: an
/// identifier that grows with every new buffer of the session, and the
/// bytes the buffer holds alive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Backing {
    /// Grows with every buffer the driver reads into.
    pub id: u64,
    /// The size of the buffer's allocation.
    pub size: usize,
}

/// One piece: its bytes and the read buffer it references, `None` for the
/// stream's own storage.
#[derive(Debug)]
struct Piece {
    bytes: Bytes,
    backing: Option<Backing>,
}

/// The received data of a stream, in order: the pieces, then `tail`.
#[derive(Debug, Default)]
pub(crate) struct RecvBuf {
    pieces: VecDeque<Piece>,
    /// Copied data after every piece, appended while contiguous.
    tail: BytesMut,
    len: usize,
    /// Bytes of the referenced pieces.
    referenced: usize,
    /// In the session's list of streams that reference read buffers.
    listed: bool,
    /// Storage for the pieces copied out, reclaimed in place once they
    /// were read; allocated at the first copy-out.
    spill: Option<Box<BytesMut>>,
}

impl RecvBuf {
    pub(crate) fn len(&self) -> usize {
        self.len
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The stream's own storage, for reuse by another stream.
    pub(crate) fn into_storage(self) -> BytesMut {
        self.tail
    }

    /// Takes `storage` (an emptied buffer) as the stream's own storage when
    /// it has none.
    pub(crate) fn give_storage(&mut self, storage: BytesMut) {
        if self.tail.capacity() == 0 && self.tail.is_empty() {
            self.tail = storage;
        }
    }

    /// Capacity of the stream's own storage.
    pub(crate) fn storage_capacity(&self) -> usize {
        self.tail.capacity()
    }

    /// Appends a copy of `data`.
    pub(crate) fn push_copy(&mut self, data: &[u8]) {
        if data.is_empty() {
            return;
        }

        if self.tail.capacity() - self.tail.len() < data.len() {
            // Room for more small pieces than this one: the storage is
            // reclaimed in place once the pieces frozen from it were read.
            self.tail.reserve(data.len().max(STORAGE_MIN));
        }
        self.tail.extend_from_slice(data);
        self.len += data.len();
    }

    /// Appends `data`, storage of its own (data that was held out of
    /// order): kept as it is when it is large enough, else copied.
    pub(crate) fn push_owned(&mut self, data: Bytes) {
        if data.len() < REFERENCE_MIN {
            self.push_copy(&data);
            return;
        }
        self.freeze_tail();
        self.len += data.len();
        self.pieces.push_back(Piece {
            bytes: data,
            backing: None,
        });
    }

    /// Appends `data`, a piece of the read buffer `backing`: referenced
    /// when it is large enough, else copied.
    pub(crate) fn push_shared(&mut self, data: Bytes, backing: Backing) {
        if data.len() < REFERENCE_MIN {
            self.push_copy(&data);
            return;
        }
        self.freeze_tail();
        self.len += data.len();
        self.referenced += data.len();
        self.pieces.push_back(Piece {
            bytes: data,
            backing: Some(backing),
        });
    }

    /// Moves the copied data into a piece, so that a referenced piece can
    /// follow it.
    fn freeze_tail(&mut self) {
        if !self.tail.is_empty() {
            self.pieces.push_back(Piece {
                bytes: self.tail.split().freeze(),
                backing: None,
            });
        }
    }

    /// Whether any piece references a read buffer.
    pub(crate) fn references(&self) -> bool {
        self.referenced > 0
    }

    /// Bytes of the pieces that reference read buffers.
    pub(crate) fn referenced(&self) -> usize {
        self.referenced
    }

    /// Whether the stream is listed among those that reference read
    /// buffers.
    pub(crate) fn listed(&self) -> bool {
        self.listed
    }

    pub(crate) fn set_listed(&mut self, listed: bool) {
        self.listed = listed;
    }

    /// Calls `f` with each read buffer the pieces reference and the bytes
    /// they reference in it (a run of pieces of one buffer at a time).
    pub(crate) fn tally(&self, f: &mut impl FnMut(Backing, usize)) {
        if self.referenced == 0 {
            return;
        }
        let mut run: Option<(Backing, usize)> = None;
        for p in &self.pieces {
            let Some(k) = p.backing else {
                continue;
            };
            match &mut run {
                Some((rk, n)) if rk.id == k.id => *n += p.bytes.len(),
                _ => {
                    if let Some((rk, n)) = run.replace((k, p.bytes.len())) {
                        f(rk, n);
                    }
                }
            }
        }
        if let Some((rk, n)) = run {
            f(rk, n);
        }
    }

    /// Copies the pieces of the read buffers `out` names into the stream's
    /// storage for copies, each in its place (the session's bound on the
    /// buffers kept alive). Pieces of other
    /// buffers and the stream's own storage stay as they are.
    pub(crate) fn copy_out(&mut self, out: &impl Fn(u64) -> bool) {
        let copied = |p: &Piece| p.backing.is_some_and(|b| out(b.id));
        let total: usize = self
            .pieces
            .iter()
            .filter(|p| copied(p))
            .map(|p| p.bytes.len())
            .sum();
        if total == 0 {
            return;
        }
        let spill = self.spill.get_or_insert_with(Box::default);
        if spill.capacity() - spill.len() < total {
            spill.reserve(total.max(STORAGE_MIN));
        }
        for p in &mut self.pieces {
            if copied(p) {
                spill.extend_from_slice(&p.bytes);
                self.referenced -= p.bytes.len();
                p.bytes = spill.split().freeze();
                p.backing = None;
            }
        }
    }

    /// Takes up to `max` bytes from the front as one piece, without
    /// copying.
    pub(crate) fn take(&mut self, max: usize) -> Bytes {
        let Some(front) = self.pieces.front_mut() else {
            let n = max.min(self.tail.len());
            self.len -= n;
            return self.tail.split_to(n).freeze();
        };
        let n = max.min(front.bytes.len());
        self.len -= n;
        if front.backing.is_some() {
            self.referenced -= n;
        }
        if n < front.bytes.len() {
            return front.bytes.split_to(n);
        }
        self.pieces.pop_front().expect("a front piece").bytes
    }

    /// Copies up to `dst.len()` bytes into `dst`, consuming them.
    pub(crate) fn copy_to(&mut self, dst: &mut [u8]) -> usize {
        let mut done = 0;
        while done < dst.len() && self.len > 0 {
            match self.pieces.front_mut() {
                Some(front) => {
                    let k = (dst.len() - done).min(front.bytes.len());
                    dst[done..done + k].copy_from_slice(&front.bytes[..k]);
                    let _ = self.take(k);
                    done += k;
                }
                None => {
                    let k = (dst.len() - done).min(self.tail.len());
                    dst[done..done + k].copy_from_slice(&self.tail[..k]);
                    self.consume_tail(k);
                    done += k;
                }
            }
        }
        done
    }

    /// Appends up to `max` bytes to `out`, consuming them.
    pub(crate) fn append_to(&mut self, out: &mut Vec<u8>, max: usize) -> usize {
        let mut done = 0;
        while done < max && self.len > 0 {
            match self.pieces.front() {
                Some(front) => {
                    let k = (max - done).min(front.bytes.len());
                    out.extend_from_slice(&front.bytes[..k]);
                    let _ = self.take(k);
                    done += k;
                }
                None => {
                    let k = (max - done).min(self.tail.len());
                    out.extend_from_slice(&self.tail[..k]);
                    self.consume_tail(k);
                    done += k;
                }
            }
        }
        done
    }

    /// Drops `n` bytes from the front of `tail` (no piece precedes it).
    fn consume_tail(&mut self, n: usize) {
        if n == self.tail.len() {
            // Emptied: the whole capacity stays for new data.
            self.tail.clear();
        } else {
            self.tail.advance(n);
        }
        self.len -= n;
    }

    /// Keeps the first `keep` bytes; returns the bytes dropped.
    pub(crate) fn truncate(&mut self, keep: usize) -> usize {
        if keep >= self.len {
            return 0;
        }
        let dropped = self.len - keep;
        let mut left = keep;
        let mut i = 0;
        while i < self.pieces.len() {
            let l = self.pieces[i].bytes.len();
            if left >= l {
                left -= l;
                i += 1;
                continue;
            }
            self.pieces[i].bytes.truncate(left);
            if left > 0 {
                i += 1;
            }
            left = 0;
            break;
        }
        self.pieces.truncate(i);
        self.tail.truncate(left);
        self.len = keep;
        self.referenced = self
            .pieces
            .iter()
            .filter(|p| p.backing.is_some())
            .map(|p| p.bytes.len())
            .sum();
        dropped
    }

    /// Drops all data. Large storage is released.
    pub(crate) fn clear(&mut self, keep_storage: usize) {
        self.pieces.clear();
        self.spill = None;
        if self.tail.capacity() > keep_storage {
            self.tail = BytesMut::new();
        } else {
            self.tail.clear();
        }
        self.len = 0;
        self.referenced = 0;
    }

    /// Heap bytes the data holds: the stream's storage, the piece list and
    /// its share of the read buffers the pieces keep alive, twice the bytes
    /// it references (the session's bound).
    pub(crate) fn memory(&self) -> usize {
        self.tail.capacity()
            + self.spill.as_ref().map_or(0, |s| s.capacity())
            + self.pieces.capacity() * std::mem::size_of::<Piece>()
            + 2 * self.referenced
            + self
                .pieces
                .iter()
                .filter(|p| p.backing.is_none())
                .map(|p| p.bytes.len())
                .sum::<usize>()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn buffer(id: u64, len: usize) -> (Bytes, Backing) {
        (
            Bytes::from(vec![id as u8; len]),
            Backing {
                id,
                size: 128 * 1024,
            },
        )
    }

    /// Copy-out replaces the pieces of the named buffers in place: order,
    /// the other references and the stream's own storage are kept.
    #[test]
    fn copy_out_copies_only_the_named_buffers() {
        let mut r = RecvBuf::default();
        let (b, k) = buffer(1, 8192);
        r.push_shared(b, k);
        r.push_copy(&[9; 100]);
        let (b, k) = buffer(2, 5000);
        r.push_shared(b, k);
        let (b, k) = buffer(1, 6000);
        r.push_shared(b, k);
        let mut seen = Vec::new();
        r.tally(&mut |k, n| seen.push((k.id, n)));
        assert_eq!(seen, vec![(1, 8192), (2, 5000), (1, 6000)]);
        r.copy_out(&|id| id == 1);
        assert!(r.references());
        seen.clear();
        r.tally(&mut |k, n| seen.push((k.id, n)));
        assert_eq!(seen, vec![(2, 5000)]);
        let mut out = vec![0u8; r.len()];
        assert_eq!(r.copy_to(&mut out), 8192 + 100 + 5000 + 6000);
        assert!(out[..8192].iter().all(|&x| x == 1));
        assert!(out[8192..8292].iter().all(|&x| x == 9));
        assert!(out[8292..13292].iter().all(|&x| x == 2));
        assert!(out[13292..].iter().all(|&x| x == 1));
        assert!(!r.references());
    }

    #[test]
    fn truncate_keeps_a_prefix() {
        let mut r = RecvBuf::default();
        let (b, k) = buffer(1, 5000);
        r.push_shared(b, k);
        r.push_copy(&[7; 100]);
        assert_eq!(r.truncate(5050), 50);
        assert_eq!(r.len(), 5050);
        assert_eq!(r.truncate(10), 5040);
        assert_eq!(r.take(usize::MAX).len(), 10);
        assert!(!r.references());
    }
}
