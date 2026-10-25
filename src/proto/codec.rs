//! Cursor and writer shared by the frame, parameter and payload codecs.

use super::error::EncodeError;
use super::varint;

/// The input ended before the item being decoded was complete.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Short;

/// A read position over a borrowed byte slice. Reads never panic: running
/// out of input yields [`Short`].
#[derive(Clone, Copy)]
pub(crate) struct Cursor<'a> {
    rest: &'a [u8],
    start_len: usize,
}

impl<'a> Cursor<'a> {
    #[inline]
    pub(crate) const fn new(buf: &'a [u8]) -> Self {
        Self {
            rest: buf,
            start_len: buf.len(),
        }
    }

    /// Bytes consumed so far.
    #[inline]
    pub(crate) const fn pos(&self) -> usize {
        self.start_len - self.rest.len()
    }

    #[inline]
    pub(crate) const fn remaining(&self) -> usize {
        self.rest.len()
    }

    #[inline]
    pub(crate) const fn is_empty(&self) -> bool {
        self.rest.is_empty()
    }

    #[inline]
    pub(crate) fn varint(&mut self) -> Result<u64, Short> {
        self.varint_with_width().map(|(v, _)| v)
    }

    #[inline]
    pub(crate) fn varint_with_width(&mut self) -> Result<(u64, usize), Short> {
        let (v, n) = varint::decode(self.rest).ok_or(Short)?;
        self.advance(n)?;
        Ok((v, n))
    }

    #[inline]
    pub(crate) fn u8(&mut self) -> Result<u8, Short> {
        let (&b, rest) = self.rest.split_first().ok_or(Short)?;
        self.rest = rest;
        Ok(b)
    }

    #[inline]
    pub(crate) fn array<const N: usize>(&mut self) -> Result<&'a [u8; N], Short> {
        let (head, rest) = self.rest.split_first_chunk::<N>().ok_or(Short)?;
        self.rest = rest;
        Ok(head)
    }

    #[inline]
    pub(crate) fn bytes(&mut self, n: u64) -> Result<&'a [u8], Short> {
        let n = usize::try_from(n).map_err(|_| Short)?;
        let (head, rest) = self.rest.split_at_checked(n).ok_or(Short)?;
        self.rest = rest;
        Ok(head)
    }

    /// Takes everything that is left.
    #[inline]
    pub(crate) fn rest(&mut self) -> &'a [u8] {
        std::mem::take(&mut self.rest)
    }

    #[inline]
    pub(crate) fn advance(&mut self, n: usize) -> Result<(), Short> {
        self.rest = self.rest.get(n..).ok_or(Short)?;
        Ok(())
    }

    /// Advances over a run of `byte` and returns its length.
    #[inline]
    pub(crate) fn skip_run(&mut self, byte: u8) -> usize {
        let n = self
            .rest
            .iter()
            .position(|&b| b != byte)
            .unwrap_or(self.rest.len());
        self.rest = self.rest.get(n..).unwrap_or_default();
        n
    }
}

/// A write position over a caller-provided buffer. Writes check capacity and
/// value ranges and never panic.
pub(crate) struct Writer<'b> {
    buf: &'b mut [u8],
    pos: usize,
}

impl<'b> Writer<'b> {
    #[inline]
    pub(crate) fn new(buf: &'b mut [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    #[inline]
    pub(crate) fn pos(&self) -> usize {
        self.pos
    }

    #[inline]
    fn tail(&mut self) -> Result<&mut [u8], EncodeError> {
        self.buf
            .get_mut(self.pos..)
            .ok_or(EncodeError::BufferTooShort)
    }

    #[inline]
    pub(crate) fn varint(&mut self, value: u64) -> Result<(), EncodeError> {
        let n = varint::encode(value, self.tail()?)?;
        self.pos += n;
        Ok(())
    }

    #[inline]
    pub(crate) fn u8(&mut self, b: u8) -> Result<(), EncodeError> {
        *self
            .tail()?
            .first_mut()
            .ok_or(EncodeError::BufferTooShort)? = b;
        self.pos += 1;
        Ok(())
    }

    #[inline]
    pub(crate) fn bytes(&mut self, src: &[u8]) -> Result<(), EncodeError> {
        let dst = self
            .tail()?
            .get_mut(..src.len())
            .ok_or(EncodeError::BufferTooShort)?;
        dst.copy_from_slice(src);
        self.pos += src.len();
        Ok(())
    }

    #[inline]
    pub(crate) fn zeros(&mut self, n: usize) -> Result<(), EncodeError> {
        let dst = self
            .tail()?
            .get_mut(..n)
            .ok_or(EncodeError::BufferTooShort)?;
        dst.fill(0);
        self.pos += n;
        Ok(())
    }
}

/// Whether a list of identifiers contains a value twice. Used for transport
/// parameter IDs, which come in any order: up to 64 unordered IDs are
/// checked on the stack, longer lists in a sorted copy (once per session).
pub(crate) fn has_duplicates<I>(ids: I) -> bool
where
    I: Iterator<Item = u64> + Clone,
{
    let mut prev: Option<u64> = None;
    let mut increasing = true;
    for id in ids.clone() {
        if let Some(p) = prev
            && id <= p
        {
            increasing = false;
            break;
        }
        prev = Some(id);
    }
    if increasing {
        return false;
    }
    let mut small = [0u64; 64];
    let mut n = 0;
    let mut spill: Vec<u64> = Vec::new();
    for id in ids {
        if let Some(slot) = small.get_mut(n) {
            *slot = id;
            n += 1;
        } else {
            // Sorting a copy keeps the check O(n log n) for long blocks.
            if spill.is_empty() {
                spill.extend_from_slice(&small);
            }
            spill.push(id);
        }
    }
    let ids: &mut [u64] = if spill.is_empty() {
        &mut small[..n]
    } else {
        &mut spill
    };
    ids.sort_unstable();
    ids.windows(2).any(|w| w[0] == w[1])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duplicates() {
        assert!(!has_duplicates([1, 2, 5].into_iter()));
        assert!(has_duplicates([1, 2, 2].into_iter()));
        assert!(!has_duplicates([5, 2, 1].into_iter()));
        assert!(has_duplicates([5, 2, 5].into_iter()));
        let long: Vec<u64> = (0..200).rev().chain([7]).collect();
        assert!(has_duplicates(long.iter().copied()));
        let long: Vec<u64> = (0..200).rev().collect();
        assert!(!has_duplicates(long.iter().copied()));
    }
}
