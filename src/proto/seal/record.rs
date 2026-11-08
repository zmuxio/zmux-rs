//! Sealed records: one direction each, with the implicit counter and rekey.

use super::{Cipher, Error, Secret};

const RESERVED_NONCE: u64 = u64::MAX;

struct Direction {
    cipher: &'static Cipher,
    key: Secret,
    n: u64,
    failed: Option<Error>,
}

impl Direction {
    fn new(cipher: &'static Cipher, key: Secret, n: u64) -> Direction {
        Direction {
            cipher,
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
            self.key = key;
        }
        Ok(())
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
        let d = &mut self.0;
        if d.failed.is_none() && plaintext.len() > d.cipher.max_plaintext() {
            return Err(Error::TooLarge);
        }
        d.prepare()?;
        let out = d.cipher.seal(&d.key, d.n, b"", plaintext);
        d.n += 1;
        Ok(out)
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
        let d = &mut self.0;
        d.prepare()?;
        match d.cipher.open(&d.key, d.n, b"", ciphertext) {
            Ok(plain) => {
                d.n += 1;
                Ok(plain)
            }
            Err(error) => {
                d.failed = Some(error);
                Err(error)
            }
        }
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
