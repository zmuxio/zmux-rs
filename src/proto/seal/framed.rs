//! The framing of Sealed records over a carrier, sans I/O: the one definition
//! the drivers' Sealed halves wrap. On a byte stream each record is a 2-byte
//! length and the ciphertext; on a message carrier each message is one
//! record. Authentication publishes only the record's plaintext.

use bytes::BufMut;

use super::{Error, Framing, Opener, Sealer};
use crate::proto::receive::{ReceiveBuffer, ReceivedRecord};

/// The authentication tag of a Sealed record.
pub const SEALED_TAG: u16 = 16;
/// The length prefix of a Sealed record on a byte stream.
pub const SEALED_LEN: u16 = 2;
/// The largest plaintext of a Sealed record: its ciphertext, tag included,
/// fits in 16 bits.
pub const SEALED_MAX_RECORD: usize = u16::MAX as usize - SEALED_TAG as usize;

/// What a Sealed record adds over a carrier with `lower` framing.
#[must_use]
pub fn sealed_overhead(lower: Framing) -> u16 {
    SEALED_TAG
        + if lower == Framing::ByteStream {
            SEALED_LEN
        } else {
            0
        }
}

/// The record limit of a Sealed transform over a carrier limited to `lower`.
#[must_use]
pub fn sealed_max_record(lower: Option<usize>, overhead: u16) -> usize {
    lower.map_or(SEALED_MAX_RECORD, |m| {
        SEALED_MAX_RECORD.min(m.saturating_sub(overhead.into()))
    })
}

/// What [`SealedReader::read`] produced.
#[derive(Debug)]
pub enum Read {
    /// An authenticated record, which may have an empty plaintext.
    Record(ReceivedRecord),
    /// More carrier bytes are needed. Use [`SealedReader::space`] and
    /// [`SealedReader::filled`], or [`SealedReader::eof`].
    More,
    /// The carrier ended at a record boundary.
    End,
}

/// Why a Sealed direction failed for good.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Failure {
    /// Invalid length, authentication failure, or an incomplete message write.
    Invalid,
    /// The carrier ended inside a byte-stream record.
    Cut,
}

/// The receiving direction. Byte-stream ciphertext is read into its final
/// allocation after the fixed header has been checked.
pub struct SealedReader {
    framing: Framing,
    opener: Opener,
    limit: usize,
    prefix: std::io::Cursor<Vec<u8>>,
    head: [u8; SEALED_LEN as usize],
    head_len: usize,
    buffer: ReceiveBuffer,
    filled: usize,
    expected: Option<usize>,
    eof: bool,
    failed: Option<Failure>,
}

impl SealedReader {
    /// Reads Sealed records over `framing`. The optional carrier limit
    /// includes the Sealed overhead. Bytes read during setup are consumed
    /// first. In message mode the nonempty prefix is one message.
    #[must_use]
    pub fn new(
        framing: Framing,
        opener: Opener,
        prefix: Vec<u8>,
        carrier_limit: Option<usize>,
    ) -> Self {
        let prefix_len = if framing == Framing::ByteStream {
            usize::from(SEALED_LEN)
        } else {
            0
        };
        let limit = carrier_limit
            .unwrap_or(usize::MAX)
            .saturating_sub(prefix_len)
            .min(usize::from(u16::MAX));
        Self {
            framing,
            opener,
            limit,
            prefix: std::io::Cursor::new(prefix),
            head: [0; SEALED_LEN as usize],
            head_len: 0,
            buffer: ReceiveBuffer::default(),
            filled: 0,
            expected: None,
            eof: false,
            failed: None,
        }
    }

    /// Takes the next authenticated record, or requests more input.
    ///
    /// # Errors
    ///
    /// Invalid framing or authentication, or EOF inside a record.
    pub fn read(&mut self) -> Result<Read, Failure> {
        use std::io::Read as _;
        if let Some(failure) = self.failed {
            return Err(failure);
        }
        loop {
            if self.framing == Framing::ByteStream
                && self.expected.is_none()
                && self.head_len == self.head.len()
            {
                let len = usize::from(u16::from_be_bytes(self.head));
                if !(usize::from(SEALED_TAG)..=self.limit).contains(&len) {
                    return Err(self.fail(Failure::Invalid));
                }
                self.expected = Some(len);
            }
            if self.expected == Some(self.filled) {
                let buffer = std::mem::take(&mut self.buffer);
                return self.open(buffer, 0, self.filled);
            }
            if self.prefix.position() == self.prefix.get_ref().len() as u64 {
                self.prefix = std::io::Cursor::default();
                if !self.eof {
                    return Ok(Read::More);
                }
                return if self.head_len == 0 && self.expected.is_none() {
                    self.buffer = ReceiveBuffer::default();
                    Ok(Read::End)
                } else {
                    Err(self.fail(Failure::Cut))
                };
            }
            let mut prefix = std::mem::take(&mut self.prefix);
            let offset = usize::try_from(prefix.position()).expect("cursor within its input");
            let remain = prefix.get_ref().len() - offset;
            if self.framing == Framing::Records {
                if !(usize::from(SEALED_TAG)..=self.limit).contains(&remain) {
                    return Err(self.fail(Failure::Invalid));
                }
                return self.open(ReceiveBuffer::from_vec(prefix.into_inner()), offset, remain);
            }
            if self.filled == 0 && self.expected == Some(remain) {
                // The setup reader handed over the final record in its own
                // allocation. Keep the bytes before it outside the view.
                return self.open(ReceiveBuffer::from_vec(prefix.into_inner()), offset, remain);
            }
            let n = prefix.read(self.space()).expect("cursor read");
            self.prefix = prefix;
            self.filled(n)?;
        }
    }

    fn open(&mut self, mut buffer: ReceiveBuffer, start: usize, n: usize) -> Result<Read, Failure> {
        let ciphertext = &mut buffer.space()[start..start + n];
        let plain = self.opener.open_in_place(ciphertext);
        let valid = plain.map_err(|_| self.fail(Failure::Invalid))?.len();
        self.expected = None;
        self.head_len = 0;
        self.filled = 0;
        Ok(Read::Record(buffer.publish(start..start + valid)))
    }

    /// Returns the destination for the next read after [`Read::More`].
    /// Over a message carrier the destination holds one complete ciphertext.
    pub fn space(&mut self) -> &mut [u8] {
        if self.framing == Framing::ByteStream && self.expected.is_none() {
            return &mut self.head[self.head_len..];
        }
        let end = self.expected.unwrap_or(self.limit + 1);
        if self.buffer.is_empty() {
            self.buffer = ReceiveBuffer::take(end);
        }
        &mut self.buffer.space()[self.filled..end]
    }

    /// Records bytes written into the last destination. A zero-length
    /// message is invalid ciphertext. Use [`Self::eof`] for end of input.
    ///
    /// # Errors
    ///
    /// The carrier supplied an invalid length.
    pub fn filled(&mut self, n: usize) -> Result<(), Failure> {
        if self.framing == Framing::Records {
            if !(usize::from(SEALED_TAG)..=self.limit).contains(&n) {
                return Err(self.fail(Failure::Invalid));
            }
            self.expected = Some(n);
        }
        let (filled, limit) = match self.expected {
            Some(len) => (&mut self.filled, len.min(self.buffer.space().len())),
            None => (&mut self.head_len, self.head.len()),
        };
        let Some(end) = filled.checked_add(n).filter(|&end| end <= limit) else {
            return Err(self.fail(Failure::Invalid));
        };
        *filled = end;
        Ok(())
    }

    /// Reports the end of the carrier.
    pub fn eof(&mut self) {
        self.eof = true;
    }

    /// Drops any expanded key and unused read buffer at a record boundary.
    pub fn release_idle(&mut self) {
        if self.at_boundary() {
            self.buffer = ReceiveBuffer::default();
            self.opener.release_idle();
        }
    }

    /// Whether the reader owns resources it can release at a record boundary.
    #[must_use]
    pub fn idle_buffer(&self) -> bool {
        self.at_boundary() && (!self.buffer.is_empty() || self.opener.has_expanded_key())
    }

    fn at_boundary(&self) -> bool {
        self.head_len == 0
            && self.expected.is_none()
            && self.prefix.position() == self.prefix.get_ref().len() as u64
    }

    fn fail(&mut self, failure: Failure) -> Failure {
        self.failed = Some(failure);
        self.buffer = ReceiveBuffer::default();
        self.prefix = std::io::Cursor::default();
        failure
    }
}

/// The writing direction: each record is built whole, then written.
pub struct SealedWriter {
    framing: Framing,
    sealer: Sealer,
    /// Where records are built: once one is written and dropped, its
    /// allocation is taken back for the next.
    unit: crate::proto::session::ChunkBuffer,
    /// The committed record's bytes still to write.
    pending: crate::Chunk,
    held: bool,
}

impl SealedWriter {
    /// A writer of `framing` records.
    #[must_use]
    pub fn new(framing: Framing, sealer: Sealer) -> Self {
        Self {
            framing,
            sealer,
            unit: crate::proto::session::ChunkBuffer::default(),
            pending: crate::Chunk::new(),
            held: false,
        }
    }

    #[cfg(all(feature = "tokio", not(loom)))]
    pub(crate) fn set_workspace(
        &mut self,
        space: Option<std::sync::Arc<crate::proto::memory::WriteWorkspace>>,
    ) {
        self.unit.release_storage();
        self.unit.space = space;
    }

    #[cfg(all(feature = "tokio", not(loom)))]
    pub(crate) fn workspace(
        &self,
    ) -> Option<&std::sync::Arc<crate::proto::memory::WriteWorkspace>> {
        self.unit.space.as_ref()
    }

    pub(crate) fn prepare(&mut self, len: usize) -> bool {
        self.unit.bytes.clear();
        self.unit
            .prepare(len.saturating_add(usize::from(sealed_overhead(self.framing))))
    }

    /// Seals `plain` as the next record: only when nothing is pending. A
    /// record sealed is committed: its nonce is spent, so it must be
    /// written whole ([`Self::pending`], [`Self::wrote`]).
    ///
    /// # Errors
    ///
    /// The plaintext is too large or the direction failed; it fails for good.
    pub fn seal(&mut self, plain: &[u8]) -> Result<(), Error> {
        assert!(
            self.prepare(plain.len()),
            "unmanaged sealing has no shared memory budget"
        );
        self.seal_prepared(plain)
    }

    pub(crate) fn seal_prepared(&mut self, plain: &[u8]) -> Result<(), Error> {
        debug_assert!(self.pending.is_empty());
        let pre = if self.framing == Framing::ByteStream {
            usize::from(SEALED_LEN)
        } else {
            0
        };
        let u = &mut self.unit.bytes;
        u.put_bytes(0, pre);
        u.extend_from_slice(plain);
        u.put_bytes(0, usize::from(SEALED_TAG));
        let sealed = self.sealer.seal_in_place(&mut u[pre..]).and_then(|()| {
            if pre == 0 {
                return Ok(());
            }
            let n = u16::try_from(u.len() - pre).map_err(|_| Error::TooLarge)?;
            u[..pre].copy_from_slice(&n.to_be_bytes());
            Ok(())
        });
        if let Err(e) = sealed {
            u.clear();
            self.sealer.fail();
            return Err(e);
        }
        self.pending = self.unit.publish();
        self.held = true;
        Ok(())
    }

    /// The bytes of the committed record still to write.
    #[must_use]
    pub fn pending(&self) -> &crate::Chunk {
        &self.pending
    }

    /// The carrier took `n` of [`Self::pending`]. On a message carrier a
    /// write is one message: one that took less fails the direction.
    ///
    /// # Errors
    ///
    /// A short write of a message, or no progress.
    pub fn wrote(&mut self, n: usize) -> Result<(), Failure> {
        let left = self.pending.len();
        if n == 0 || n > left || (self.framing == Framing::Records && n != left) {
            self.failed();
            return Err(Failure::Invalid);
        }
        let _ = self.pending.split_to(n);
        if self.pending.is_empty() {
            // Dropped, `unit` takes its allocation back unshared.
            self.pending = crate::Chunk::new();
        }
        Ok(())
    }

    /// The carrier's write failed: a record cut or lost, nothing may follow.
    pub fn failed(&mut self) {
        self.sealer.fail();
        self.pending = crate::Chunk::new();
    }

    /// Whether an idle pipe would free something.
    #[must_use]
    pub fn idle_held(&self) -> bool {
        self.held && self.pending.is_empty()
    }

    /// Frees the record's allocation and the expanded key with nothing pending.
    pub fn release_idle(&mut self) {
        if self.pending.is_empty() {
            self.unit.release_storage();
            self.sealer.release_idle();
            self.held = false;
        }
    }
}

impl std::fmt::Debug for SealedReader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SealedReader").finish_non_exhaustive()
    }
}

impl std::fmt::Debug for SealedWriter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SealedWriter").finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair(framing: Framing) -> (SealedWriter, SealedReader) {
        let c = super::super::aes_256_gcm();
        (
            SealedWriter::new(framing, Sealer::new(c, vec![7; 32])),
            SealedReader::new(framing, Opener::new(c, vec![7; 32]), Vec::new(), None),
        )
    }

    #[test]
    fn validated_ciphertext_is_opened_in_the_published_allocation() {
        let (mut w, mut r) = pair(Framing::ByteStream);
        w.seal(&[5; 1000]).unwrap();
        let (head, ciphertext) = w.pending().split_at(2);
        r.space()[..1].copy_from_slice(&head[..1]);
        r.filled(1).unwrap();
        assert!(matches!(r.read().unwrap(), Read::More));
        r.space().copy_from_slice(&head[1..]);
        r.filled(1).unwrap();
        assert!(matches!(r.read().unwrap(), Read::More));

        let space = r.space();
        let allocation = space.as_ptr();
        space[..1].copy_from_slice(&ciphertext[..1]);
        r.filled(1).unwrap();
        assert!(matches!(r.read().unwrap(), Read::More));
        r.space().copy_from_slice(&ciphertext[1..]);
        r.filled(ciphertext.len() - 1).unwrap();
        let Read::Record(record) = r.read().unwrap() else {
            panic!("complete record");
        };
        assert_eq!(record.as_ref().as_ptr(), allocation);
        assert_eq!(record.as_ref(), &[5; 1000]);
        assert_eq!(record.capacity(), 1024);

        r.eof();
        assert!(matches!(r.read().unwrap(), Read::End));
        assert_eq!(record.as_ref(), &[5; 1000]);
    }

    #[test]
    fn invalid_length_authentication_failure_and_cut_are_terminal() {
        let (mut w, mut r) = pair(Framing::ByteStream);
        w.seal(b"valid").unwrap();
        r.space().copy_from_slice(&[0, 15]);
        r.filled(2).unwrap();
        assert!(matches!(r.read(), Err(Failure::Invalid)));

        let (_, mut r) = pair(Framing::ByteStream);
        r.space()[0] = 0;
        r.filled(1).unwrap();
        r.eof();
        assert!(matches!(r.read(), Err(Failure::Cut)));

        let (_, mut r) = pair(Framing::ByteStream);
        let (head, body) = w.pending().split_at(2);
        r.space().copy_from_slice(head);
        r.filled(2).unwrap();
        assert!(matches!(r.read().unwrap(), Read::More));
        let space = r.space();
        space.copy_from_slice(body);
        space[0] ^= 1;
        r.filled(body.len()).unwrap();
        assert!(matches!(r.read(), Err(Failure::Invalid)));
        assert!(matches!(r.read(), Err(Failure::Invalid)));
    }

    #[test]
    fn prefetched_record_moves_into_the_authenticated_view() {
        for framing in [Framing::Records, Framing::ByteStream] {
            let (mut writer, _) = pair(framing);
            writer.seal(b"prefetched").unwrap();
            let prefix = writer.pending().to_vec();
            let wire_len = prefix.len();
            let plain_start = usize::from(framing == Framing::ByteStream) * usize::from(SEALED_LEN);
            let allocation = prefix[plain_start..].as_ptr();
            let mut reader = SealedReader::new(
                framing,
                Opener::new(super::super::aes_256_gcm(), vec![7; 32]),
                prefix,
                Some(wire_len),
            );
            reader.eof();
            let Read::Record(record) = reader.read().unwrap() else {
                panic!("the setup reader already read the record");
            };
            assert_eq!(record.as_ref().as_ptr(), allocation);
            assert_eq!(record.as_ref(), b"prefetched");
            assert!(matches!(reader.read().unwrap(), Read::End));
        }
    }

    #[test]
    fn a_short_message_write_fails() {
        let (mut w, _) = pair(Framing::Records);
        w.seal(b"abc").unwrap();
        assert_eq!(w.wrote(1), Err(Failure::Invalid));
        assert!(w.seal(b"x").is_err(), "no record follows");
    }
}
