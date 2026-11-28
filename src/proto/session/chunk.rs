//! Write ownership of immutable transport ranges.

use std::ops::{Deref, RangeBounds};
use std::sync::Arc;

use bytes::{Buf, Bytes};

use super::Backing;
use crate::proto::memory::{Ledger, WriteRoot};

/// An immutable range of an allocation whose capacity is known. Slices and
/// clones preserve the backing and any reservation already attached to it.
#[derive(Clone, Debug, Default)]
pub struct Chunk {
    pub(crate) bytes: Bytes,
    pub(crate) backing: Backing,
    pub(crate) write: Option<WriteRoot>,
    #[cfg(all(feature = "tokio", not(loom)))]
    pub(crate) handoff: Option<super::splice_handoff::HandoffSpan>,
}

impl Chunk {
    /// An empty chunk.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            bytes: Bytes::new(),
            backing: Backing { id: 0, size: 0 },
            write: None,
            #[cfg(all(feature = "tokio", not(loom)))]
            handoff: None,
        }
    }

    /// Borrows program-static bytes.
    #[must_use]
    pub fn from_static(data: &'static [u8]) -> Self {
        Self::backed(Bytes::from_static(data), Backing::new(data.len()))
    }

    /// Copies data into a backing with a known capacity. Use this for
    /// externally owned views whose original allocation size is unknown.
    #[must_use]
    pub fn copy_from_slice(data: &[u8]) -> Self {
        Self::from(data.to_vec())
    }

    pub(crate) fn backed(bytes: Bytes, backing: Backing) -> Self {
        Self {
            bytes,
            backing,
            write: None,
            #[cfg(all(feature = "tokio", not(loom)))]
            handoff: None,
        }
    }

    /// Whether no other view owns these bytes.
    pub fn is_unique(&self) -> bool {
        self.bytes.is_unique()
    }

    pub(crate) fn reserve(&mut self, domain: &Arc<Ledger>, previous: Option<&Self>) -> bool {
        if self.is_empty()
            || self
                .write
                .as_ref()
                .is_some_and(|root| root.belongs_to(domain))
        {
            return true;
        }
        let shared = previous
            .filter(|chunk| chunk.backing == self.backing)
            .and_then(|chunk| chunk.write.as_ref())
            .filter(|root| root.belongs_to(domain))
            .cloned();
        let Some(root) = shared.or_else(|| domain.reserve_write_root(self.backing)) else {
            return false;
        };
        self.write = Some(root);
        true
    }

    /// The number of bytes in this view.
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Whether the view is empty.
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// The entire allocation capacity this view can keep alive.
    #[must_use]
    pub fn backing_capacity(&self) -> usize {
        self.backing.size
    }

    /// A subrange of the same backing.
    #[must_use]
    pub fn slice(&self, range: impl RangeBounds<usize>) -> Self {
        let bytes = self.bytes.slice(range);
        #[cfg(all(feature = "tokio", not(loom)))]
        let offset = if self.handoff.is_some() && !bytes.is_empty() {
            bytes.as_ptr() as usize - self.bytes.as_ptr() as usize
        } else {
            0
        };
        self.subrange(
            bytes,
            #[cfg(all(feature = "tokio", not(loom)))]
            offset,
        )
    }

    fn subrange(
        &self,
        bytes: Bytes,
        #[cfg(all(feature = "tokio", not(loom)))] offset: usize,
    ) -> Self {
        if bytes.is_empty() {
            return Self::new();
        }
        #[cfg(all(feature = "tokio", not(loom)))]
        let handoff = self
            .handoff
            .as_ref()
            .map(|span| span.slice(offset, bytes.len()));
        Self {
            bytes,
            backing: self.backing,
            write: self.write.clone(),
            #[cfg(all(feature = "tokio", not(loom)))]
            handoff,
        }
    }

    /// Splits at `at`, keeping the prefix and returning the suffix.
    #[must_use]
    pub fn split_off(&mut self, at: usize) -> Self {
        let bytes = self.bytes.split_off(at);
        let suffix = self.subrange(
            bytes,
            #[cfg(all(feature = "tokio", not(loom)))]
            at,
        );
        if self.bytes.is_empty() {
            *self = Self::new();
        } else {
            #[cfg(all(feature = "tokio", not(loom)))]
            self.keep_receipt(0);
        }
        suffix
    }

    /// Splits at `at`, returning the prefix and keeping the suffix.
    #[must_use]
    pub fn split_to(&mut self, at: usize) -> Self {
        let bytes = self.bytes.split_to(at);
        let prefix = self.subrange(
            bytes,
            #[cfg(all(feature = "tokio", not(loom)))]
            0,
        );
        if self.bytes.is_empty() {
            *self = Self::new();
        } else {
            #[cfg(all(feature = "tokio", not(loom)))]
            self.keep_receipt(at);
        }
        prefix
    }

    #[cfg(all(feature = "tokio", not(loom)))]
    fn keep_receipt(&mut self, offset: usize) {
        if let Some(handoff) = &self.handoff {
            self.handoff = Some(handoff.slice(offset, self.bytes.len()));
        }
    }

    pub(crate) fn truncate(&mut self, len: usize) {
        if len == 0 {
            self.clear();
        } else {
            self.bytes.truncate(len);
            #[cfg(all(feature = "tokio", not(loom)))]
            self.keep_receipt(0);
        }
    }

    /// Releases the current range.
    pub fn clear(&mut self) {
        *self = Self::new();
    }

    /// Hands the bytes to a byte-only transport API. The returned owner
    /// keeps the reservation through cloning, slicing, and transport retention.
    #[must_use]
    pub fn into_bytes(self) -> Bytes {
        if self.write.is_some() {
            Bytes::from_owner(self)
        } else {
            self.bytes
        }
    }
}

impl From<Vec<u8>> for Chunk {
    fn from(data: Vec<u8>) -> Self {
        let backing = Backing::new(data.capacity());
        Self::backed(Bytes::from(data), backing)
    }
}

impl PartialEq for Chunk {
    fn eq(&self, other: &Self) -> bool {
        self.bytes == other.bytes
    }
}

impl Eq for Chunk {}

impl AsRef<[u8]> for Chunk {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl Deref for Chunk {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        self.as_ref()
    }
}

impl Buf for Chunk {
    fn remaining(&self) -> usize {
        self.len()
    }

    fn chunk(&self) -> &[u8] {
        self.as_ref()
    }

    fn advance(&mut self, count: usize) {
        if count == self.len() {
            self.clear();
        } else {
            self.bytes.advance(count);
            #[cfg(all(feature = "tokio", not(loom)))]
            self.keep_receipt(count);
        }
    }

    fn copy_to_bytes(&mut self, len: usize) -> Bytes {
        self.split_to(len).into_bytes()
    }
}

/// A fillable buffer that publishes immutable [`Chunk`] views of one allocation.
///
/// Publishing takes the initialized prefix and leaves any unused tail
/// available for another fill. All published prefixes retain the same
/// backing identity and its complete allocation capacity.
#[derive(Debug, Default)]
pub struct ChunkBuffer {
    pub(crate) bytes: bytes::BytesMut,
    backing: Backing,
    write: Option<WriteRoot>,
    #[cfg(all(feature = "tokio", not(loom)))]
    pub(crate) space: Option<Arc<crate::proto::memory::WriteWorkspace>>,
}

impl ChunkBuffer {
    /// Allocates a buffer for up to `capacity` bytes.
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        let mut buffer = Self::default();
        buffer.replace(Backing::new(capacity), None);
        buffer
    }

    /// Unwritten bytes available in the current tail.
    #[must_use]
    pub fn remaining_capacity(&self) -> usize {
        self.bytes.capacity() - self.bytes.len()
    }

    /// Appends initialized bytes within this allocation.
    ///
    /// # Panics
    ///
    /// Panics if the data exceeds [`Self::remaining_capacity`].
    pub fn extend_from_slice(&mut self, data: &[u8]) {
        assert!(data.len() <= self.remaining_capacity());
        self.bytes.extend_from_slice(data);
    }

    pub(crate) fn prepare(&mut self, size: usize) -> bool {
        if size == 0 || self.bytes.try_reclaim(size) {
            return true;
        }
        let backing = Backing::new(size);
        self.release_storage();
        #[cfg(all(feature = "tokio", not(loom)))]
        let write = if let Some(space) = self.space.as_ref() {
            let Some(write) = space
                .take(backing)
                .or_else(|| space.domain().reserve_write_root(backing))
            else {
                return false;
            };
            Some(write)
        } else {
            None
        };
        #[cfg(not(all(feature = "tokio", not(loom))))]
        let write = None;
        self.replace(backing, write);
        true
    }

    fn replace(&mut self, backing: Backing, write: Option<WriteRoot>) {
        self.bytes = bytes::BytesMut::with_capacity(backing.size);
        assert_eq!(self.bytes.capacity(), backing.size);
        self.backing = backing;
        self.write = write;
    }

    pub(crate) fn release_storage(&mut self) {
        self.bytes = bytes::BytesMut::new();
        self.backing = Backing::default();
        self.write = None;
    }

    /// Takes the initialized prefix as an immutable view.
    #[must_use]
    pub fn publish(&mut self) -> Chunk {
        if self.bytes.is_empty() {
            return Chunk::new();
        }
        Chunk {
            bytes: self.bytes.split().freeze(),
            backing: self.backing,
            write: self.write.clone(),
            #[cfg(all(feature = "tokio", not(loom)))]
            handoff: None,
        }
    }
}

impl AsRef<[u8]> for ChunkBuffer {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slices_and_byte_only_carriers_return_the_entire_root_at_the_last_view() {
        let ledger = Ledger::new(Some(16 * 1024), None);
        let mut data = Vec::with_capacity(8192);
        data.extend_from_slice(&[7; 32]);
        let original = Chunk::from(data);
        let mut first = original.slice(..4);
        let mut second = original.slice(4..8);
        assert!(first.reserve(&ledger, None));
        let used = ledger.snapshot().used;
        assert!(used >= 8192);
        assert!(second.reserve(&ledger, None));
        assert_eq!(ledger.snapshot().used, used);
        let mut carrier = second.into_bytes().slice(1..2);
        first.clear();
        assert_eq!(ledger.snapshot().used, used);
        assert_eq!(carrier.as_ref(), &[7]);
        carrier.clear();
        assert_eq!(ledger.snapshot().used, used - 8192);
        assert_eq!(original.len(), 32);
    }

    #[test]
    fn a_backing_can_cross_domains_while_each_ledger_retains_its_own_grant() {
        let a = Ledger::new(Some(16 * 1024), None);
        let b = Ledger::new(Some(16 * 1024), None);
        let mut root = Chunk::from(vec![1; 4096]);
        assert!(root.reserve(&a, None));
        let mut forwarded = root.clone();
        assert!(forwarded.reserve(&b, None));
        let a_used = a.snapshot().used;
        let b_used = b.snapshot().used;
        drop(root);
        assert_eq!(a.snapshot().used, a_used - 4096);
        assert_eq!(b.snapshot().used, b_used);
        drop(forwarded);
        assert_eq!(b.snapshot().used, b_used - 4096);
    }
}
