//! The entry list of PIPE_ACK, kept as the received bytes and
//! decoded lazily, so that decoding does not allocate. Entries are in
//! strictly increasing (Pipe ID, Lane) order; anything else, an entry listed
//! twice included, is a FRAME_ENCODING_ERROR, checked in one pass.

use std::fmt;

use super::Fail;
use super::pipe::PipeAckEntry;
use crate::proto::codec::{Cursor, Writer};
use crate::proto::error::{EncodeError, Error};
use crate::proto::varint::len as vlen;

/// A list of entries, either borrowed from a decoded frame (already
/// validated) or supplied by a sender.
#[derive(Clone, Copy)]
pub(super) enum Entries<'a> {
    Wire { count: usize, bytes: &'a [u8] },
    List(&'a [PipeAckEntry]),
}

impl<'a> Entries<'a> {
    pub(super) fn len(&self) -> usize {
        match self {
            Self::Wire { count, .. } => *count,
            Self::List(list) => list.len(),
        }
    }

    pub(super) fn iter(&self) -> EntryIter<'a> {
        match *self {
            Self::Wire { count, bytes } => EntryIter::Wire {
                left: count,
                cursor: Cursor::new(bytes),
            },
            Self::List(list) => EntryIter::List(list.iter()),
        }
    }

    pub(super) fn encoded_len(&self) -> usize {
        match self {
            Self::Wire { count, bytes } => vlen(*count as u64) + bytes.len(),
            Self::List(list) => {
                vlen(list.len() as u64) + list.iter().map(PipeAckEntry::encoded_len).sum::<usize>()
            }
        }
    }

    pub(super) fn write(&self, w: &mut Writer<'_>) -> Result<(), EncodeError> {
        match self {
            Self::Wire { count, bytes } => {
                w.varint(*count as u64)?;
                w.bytes(bytes)
            }
            Self::List(list) => {
                if !strictly_increasing(list.iter().map(PipeAckEntry::key)) {
                    return Err(EncodeError::ValueOutOfRange);
                }
                w.varint(list.len() as u64)?;
                list.iter().try_for_each(|e| e.write(w))
            }
        }
    }

    /// Reads the Entry Count and the entries, and rejects entries that are
    /// not in strictly increasing (Pipe ID, Lane) order with
    /// FRAME_ENCODING_ERROR.
    pub(super) fn read(c: &mut Cursor<'a>, ty: u64, order: &'static str) -> Result<Self, Fail> {
        let count = c.varint()?;
        let mut body = *c;
        let start = c.pos();
        let mut n = 0usize;
        let mut prev: Option<(u64, u64)> = None;
        // Every entry takes at least four bytes, so the loop is bounded by
        // the input length whatever the count says.
        while (n as u64) < count {
            let id = PipeAckEntry::read(c)?.key();
            if prev.is_some_and(|p| id <= p) {
                return Err(Error::frame_encoding(ty, order).into());
            }
            prev = Some(id);
            n += 1;
        }
        let bytes = body.bytes((c.pos() - start) as u64)?;
        Ok(Self::Wire { count: n, bytes })
    }
}

fn strictly_increasing<K: Ord + Copy>(mut ids: impl Iterator<Item = K>) -> bool {
    let Some(mut prev) = ids.next() else {
        return true;
    };
    ids.all(|id| {
        let ok = id > prev;
        prev = id;
        ok
    })
}

impl PartialEq for Entries<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.len() == other.len() && self.iter().eq(other.iter())
    }
}

impl Eq for Entries<'_> {}

impl fmt::Debug for Entries<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.iter()).finish()
    }
}

/// Iterator over the entries of a frame.
#[derive(Clone)]
pub(super) enum EntryIter<'a> {
    Wire { left: usize, cursor: Cursor<'a> },
    List(std::slice::Iter<'a, PipeAckEntry>),
}

impl Iterator for EntryIter<'_> {
    type Item = PipeAckEntry;

    fn next(&mut self) -> Option<PipeAckEntry> {
        match self {
            Self::Wire { left, cursor } => {
                if *left == 0 {
                    return None;
                }
                *left -= 1;
                PipeAckEntry::read(cursor).ok()
            }
            Self::List(it) => it.next().copied(),
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let n = match self {
            Self::Wire { left, .. } => *left,
            Self::List(it) => it.len(),
        };
        (n, Some(n))
    }
}

impl ExactSizeIterator for EntryIter<'_> {}
