//! The framing of Sealed records over a carrier, sans I/O: the one definition
//! the drivers' Sealed halves wrap. On a byte stream each record is a 2-byte
//! length and the ciphertext; on a message carrier each message is one
//! record. A record's plaintext larger than a read's room stays and is given
//! by the next reads; a record of no bytes is not the carrier's end.

use bytes::{BufMut, Bytes, BytesMut};

use super::{Error, Framing, Opener, Sealer};

/// The authentication tag of a Sealed record.
pub const SEALED_TAG: u16 = 16;
/// The length prefix of a Sealed record on a byte stream.
pub const SEALED_LEN: u16 = 2;
/// The largest plaintext of a Sealed record: its ciphertext, tag included,
/// fits in 16 bits.
pub const SEALED_MAX_RECORD: usize = u16::MAX as usize - SEALED_TAG as usize;

/// The read buffer: a byte-stream record whole, its length prefix included,
/// which also holds the largest message of a message carrier.
const READ_BUF: usize = SEALED_LEN as usize + u16::MAX as usize;

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

/// What [`SealedReader::read`] gave.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Read {
    /// Plaintext bytes copied out.
    Data(usize),
    /// More carrier bytes are needed: [`SealedReader::space`], then
    /// [`SealedReader::filled`].
    More,
    /// The carrier ended at a record boundary.
    End,
}

/// Why a Sealed direction failed for good.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Failure {
    /// A record did not open, or a message carrier gave a short write.
    Invalid,
    /// The carrier ended inside a record.
    Cut,
}

/// The reading direction.
pub struct SealedReader {
    framing: Framing,
    opener: Opener,
    /// Carrier bytes not opened yet: `buf[start..end]` (one message on a
    /// message carrier). Plaintext opened and not given yet: `buf[pa..pb]`.
    buf: Vec<u8>,
    start: usize,
    end: usize,
    pa: usize,
    pb: usize,
    eof: bool,
    failed: Option<Failure>,
}

impl SealedReader {
    /// A reader of `framing` records, with `prefix` already read. On a
    /// message carrier `prefix` is at most one message (the handshakes read
    /// one unit at a time and keep only the rest of the last one), taken as
    /// one record.
    #[must_use]
    pub fn new(framing: Framing, opener: Opener, prefix: Vec<u8>) -> Self {
        // What can be checked of "at most one message": no more than one
        // unit's bytes.
        debug_assert!(
            framing != Framing::Records || prefix.len() <= super::MAX_UNIT,
            "a message carrier's prefix is at most one message"
        );
        let end = prefix.len();
        let mut buf = prefix;
        if end > 0 {
            buf.resize(end.max(READ_BUF), 0);
        }
        Self {
            framing,
            opener,
            buf,
            start: 0,
            end,
            pa: 0,
            pb: 0,
            eof: false,
            failed: None,
        }
    }

    /// Copies plaintext into `out` (at least one byte when it has room).
    ///
    /// # Errors
    ///
    /// The direction's failure, for good.
    pub fn read(&mut self, out: &mut [u8]) -> Result<Read, Failure> {
        if let Some(f) = self.failed {
            return Err(f);
        }
        loop {
            if self.pa < self.pb {
                let n = out.len().min(self.pb - self.pa);
                out[..n].copy_from_slice(&self.buf[self.pa..self.pa + n]);
                self.pa += n;
                return Ok(Read::Data(n));
            }
            let Some((a, b)) = self.cut() else {
                if self.eof {
                    return if self.start == self.end {
                        Ok(Read::End)
                    } else {
                        Err(self.fail(Failure::Cut))
                    };
                }
                return Ok(Read::More);
            };
            match self.opener.open_in_place(&mut self.buf[a..b]) {
                Ok(plain) => (self.pa, self.pb) = (a, a + plain.len()),
                Err(_) => return Err(self.fail(Failure::Invalid)),
            }
        }
    }

    /// Where the next carrier bytes go (one message on a message carrier);
    /// empty while plaintext is held.
    pub fn space(&mut self) -> &mut [u8] {
        if self.pa < self.pb {
            return &mut [];
        }
        if self.start > 0 {
            self.buf.copy_within(self.start..self.end, 0);
            (self.start, self.end) = (0, self.end - self.start);
        }
        if self.buf.is_empty() {
            self.buf.resize(READ_BUF, 0);
        }
        &mut self.buf[self.end..]
    }

    /// `n` bytes were read into [`Self::space`]; 0 is the carrier's end.
    pub fn filled(&mut self, n: usize) {
        if n == 0 {
            self.eof = true;
        }
        self.end += n;
    }

    /// Whether the buffer is held with nothing in it.
    #[must_use]
    pub fn idle_buffer(&self) -> bool {
        self.start == self.end && self.pa == self.pb && self.buf.capacity() > 0
    }

    /// Frees the buffer and the expanded key when nothing is in it.
    pub fn release_idle(&mut self) {
        if self.start == self.end && self.pa == self.pb {
            self.buf = Vec::new();
            (self.start, self.end, self.pa, self.pb) = (0, 0, 0, 0);
            self.opener.release_idle();
        }
    }

    fn fail(&mut self, f: Failure) -> Failure {
        self.failed = Some(f);
        f
    }

    /// The bounds of the next whole record's ciphertext, taken.
    fn cut(&mut self) -> Option<(usize, usize)> {
        let (start, end) = (self.start, self.end);
        if start == end {
            return None;
        }
        if self.framing == Framing::Records {
            self.start = end;
            return Some((start, end));
        }
        let head = self.buf.get(start..end)?.get(..2)?;
        let n = usize::from(u16::from_be_bytes([head[0], head[1]]));
        if end - start < 2 + n {
            return None;
        }
        self.start = start + 2 + n;
        Some((start + 2, start + 2 + n))
    }
}

/// The writing direction: each record is built whole, then written.
pub struct SealedWriter {
    framing: Framing,
    sealer: Sealer,
    /// Where records are built: once one is written and dropped, its
    /// allocation is taken back for the next.
    unit: BytesMut,
    /// The committed record's bytes still to write.
    pending: Bytes,
    held: bool,
}

impl SealedWriter {
    /// A writer of `framing` records.
    #[must_use]
    pub fn new(framing: Framing, sealer: Sealer) -> Self {
        Self {
            framing,
            sealer,
            unit: BytesMut::new(),
            pending: Bytes::new(),
            held: false,
        }
    }

    /// Seals `plain` as the next record: only when nothing is pending. A
    /// record sealed is committed: its nonce is spent, so it must be
    /// written whole ([`Self::pending`], [`Self::wrote`]).
    ///
    /// # Errors
    ///
    /// The plaintext is too large or the direction failed; it fails for good.
    pub fn seal(&mut self, plain: &[u8]) -> Result<(), Error> {
        debug_assert!(self.pending.is_empty());
        let pre = if self.framing == Framing::ByteStream {
            usize::from(SEALED_LEN)
        } else {
            0
        };
        let u = &mut self.unit;
        u.clear();
        u.reserve(pre + plain.len() + usize::from(SEALED_TAG));
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
        self.pending = u.split().freeze();
        self.held = true;
        Ok(())
    }

    /// The bytes of the committed record still to write.
    #[must_use]
    pub fn pending(&self) -> &Bytes {
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
            self.pending = Bytes::new();
        }
        Ok(())
    }

    /// The carrier's write failed: a record cut or lost, nothing may follow.
    pub fn failed(&mut self) {
        self.sealer.fail();
        self.pending = Bytes::new();
    }

    /// Whether an idle pipe would free something.
    #[must_use]
    pub fn idle_held(&self) -> bool {
        self.held && self.pending.is_empty()
    }

    /// Frees the record's allocation and the expanded key with nothing pending.
    pub fn release_idle(&mut self) {
        if self.pending.is_empty() {
            self.unit = BytesMut::new();
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
            SealedReader::new(framing, Opener::new(c, vec![7; 32]), Vec::new()),
        )
    }

    #[test]
    fn a_record_larger_than_the_read_stays_for_the_next_reads() {
        let (mut w, mut r) = pair(Framing::ByteStream);
        w.seal(&[5; 1000]).unwrap();
        let unit = w.pending().to_vec();
        w.wrote(unit.len()).unwrap();
        let space = r.space();
        space[..unit.len()].copy_from_slice(&unit);
        r.filled(unit.len());
        let mut got = 0;
        let mut out = [0; 300];
        while let Read::Data(n) = r.read(&mut out).unwrap() {
            assert!(out[..n].iter().all(|b| *b == 5));
            got += n;
        }
        assert_eq!(got, 1000);
        r.filled(0);
        assert_eq!(r.read(&mut out), Ok(Read::End));
    }

    #[test]
    fn a_short_message_write_fails() {
        let (mut w, _) = pair(Framing::Records);
        w.seal(b"abc").unwrap();
        assert_eq!(w.wrote(1), Err(Failure::Invalid));
        assert!(w.seal(b"x").is_err(), "no record follows");
    }
}
