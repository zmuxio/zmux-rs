//! Sealed records: one direction each, with the implicit counter and rekey.

use super::cipher::{Keyed, TAG_LEN};
use super::{Cipher, Error, Secret};

const RESERVED_NONCE: u64 = u64::MAX;

struct Direction {
    cipher: &'static Cipher,
    key: Secret,
    /// The AEAD with `key` expanded: built for the first record of a key and
    /// kept for the next ones; an idle carrier drops it
    /// ([`Opener::release_idle`]).
    keyed: Option<Keyed>,
    n: u64,
    failed: Option<Error>,
}

impl Direction {
    fn new(cipher: &'static Cipher, key: Secret, n: u64) -> Direction {
        Direction {
            cipher,
            keyed: None,
            key,
            n,
            failed: None,
        }
    }

    fn prepare(&mut self) -> Result<(), Error> {
        if let Some(error) = self.failed {
            return Err(error);
        }
        if self.n == RESERVED_NONCE {
            self.failed = Some(Error::Exhausted);
            return Err(Error::Exhausted);
        }
        if self.n != 0 && self.n.is_multiple_of(self.cipher.rekey_interval()) {
            let zeros = vec![0; self.cipher.key_len()];
            let mut key = Secret::from(self.cipher.seal(&self.key, RESERVED_NONCE, b"", &zeros));
            key.truncate(self.cipher.key_len());
            self.keyed = None;
            self.key = key;
        }
        Ok(())
    }

    /// The AEAD with the current key expanded.
    fn keyed(&mut self) -> &Keyed {
        self.keyed
            .get_or_insert_with(|| self.cipher.keyed(&self.key))
    }
}

/// The sending direction of a Sealed carrier.
pub struct Sealer(Direction);

impl Sealer {
    /// A direction at n = 0.
    pub fn new(cipher: &'static Cipher, key: impl Into<Secret>) -> Sealer {
        Sealer(Direction::new(cipher, key.into(), 0))
    }

    /// Protects one record. A plaintext over the limit is refused without
    /// consuming a nonce and leaves the direction usable.
    pub fn seal(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        let mut out = Vec::with_capacity(plaintext.len() + TAG_LEN);
        self.seal_into(plaintext, &mut out)?;
        Ok(out)
    }

    /// [`Sealer::seal`] appending the record to `out`: no allocation
    /// when `out` has room for the plaintext and the tag. On an error `out`
    /// is as it was.
    pub fn seal_into(&mut self, plaintext: &[u8], out: &mut Vec<u8>) -> Result<(), Error> {
        let at = out.len();
        out.extend_from_slice(plaintext);
        out.resize(at + plaintext.len() + TAG_LEN, 0);
        match self.seal_in_place(&mut out[at..]) {
            Ok(()) => Ok(()),
            Err(e) => {
                out.truncate(at);
                Err(e)
            }
        }
    }

    /// Protects one record in place: `record` holds the plaintext followed
    /// by room for the tag (its last 16 bytes), and holds the
    /// record after. A plaintext over the limit, or a `record` shorter
    /// than the tag, is refused without consuming a nonce.
    pub fn seal_in_place(&mut self, record: &mut [u8]) -> Result<(), Error> {
        let d = &mut self.0;
        let Some(len) = record.len().checked_sub(TAG_LEN) else {
            return Err(Error::TooLarge);
        };
        if d.failed.is_none() && len > d.cipher.max_plaintext() {
            return Err(Error::TooLarge);
        }
        d.prepare()?;
        let (msg, tag) = record.split_at_mut(len);
        let n = d.n;
        tag.copy_from_slice(&d.keyed().seal_in_place(n, msg));
        d.n += 1;
        Ok(())
    }

    /// Drops the expanded key of an idle carrier; the next record expands it
    /// again.
    #[cfg(all(feature = "tokio", not(loom)))]
    pub(crate) fn release_idle(&mut self) {
        self.0.keyed = None;
    }

    /// A short write happened: the carrier has failed for good.
    pub fn fail(&mut self) {
        self.0.failed = Some(Error::Auth);
    }

    /// A direction at an arbitrary state, for the vectors.
    #[cfg(feature = "test-hooks")]
    pub fn at(cipher: &'static Cipher, key: &[u8], n: u64) -> Sealer {
        Sealer(Direction::new(cipher, key.into(), n))
    }

    /// The key in effect and the next counter.
    #[cfg(feature = "test-hooks")]
    pub fn state(&self) -> (&[u8], u64) {
        (&self.0.key, self.0.n)
    }
}

/// The receiving direction of a Sealed carrier.
pub struct Opener(Direction);

impl Opener {
    /// A direction at n = 0.
    pub fn new(cipher: &'static Cipher, key: impl Into<Secret>) -> Opener {
        Opener(Direction::new(cipher, key.into(), 0))
    }

    /// Opens one record. Any failure ends the direction.
    pub fn open(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
        let mut buf = ciphertext.to_vec();
        let len = self.open_in_place(&mut buf)?.len();
        buf.truncate(len);
        Ok(buf)
    }

    /// Opens one record in place: the plaintext, at the front of `record`.
    /// Any failure ends the direction, and `record` then holds nothing to
    /// use.
    pub fn open_in_place<'a>(&mut self, record: &'a mut [u8]) -> Result<&'a [u8], Error> {
        let d = &mut self.0;
        d.prepare()?;
        let Some(len) = record.len().checked_sub(TAG_LEN) else {
            d.failed = Some(Error::Auth);
            return Err(Error::Auth);
        };
        let (msg, tag) = record.split_at_mut(len);
        let tag: &[u8; TAG_LEN] = (&*tag).try_into().expect("split at the tag");
        let n = d.n;
        match d.keyed().open_in_place(n, msg, tag) {
            Ok(()) => {
                d.n += 1;
                Ok(msg)
            }
            Err(error) => {
                d.failed = Some(error);
                Err(error)
            }
        }
    }

    /// Drops the expanded key of an idle carrier; the next record expands it
    /// again.
    #[cfg(all(feature = "tokio", not(loom)))]
    pub(crate) fn release_idle(&mut self) {
        self.0.keyed = None;
    }

    /// A direction at an arbitrary state, for the vectors.
    #[cfg(feature = "test-hooks")]
    pub fn at(cipher: &'static Cipher, key: &[u8], n: u64) -> Opener {
        Opener(Direction::new(cipher, key.into(), n))
    }

    /// The key in effect and the next counter.
    #[cfg(feature = "test-hooks")]
    pub fn state(&self) -> (&[u8], u64) {
        (&self.0.key, self.0.n)
    }
}

/// Shows no state: it may hold keys or locks.
impl std::fmt::Debug for Sealer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Sealer").finish_non_exhaustive()
    }
}

/// Shows no state: it may hold keys or locks.
impl std::fmt::Debug for Opener {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Opener").finish_non_exhaustive()
    }
}
