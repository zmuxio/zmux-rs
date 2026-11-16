use std::fmt;
use std::hint::black_box;

pub use crate::util::wipe;
use std::ops::Deref;

/// Key material, overwritten with zeros ([`wipe`]) when dropped. Copies a
/// cipher or hash keeps of its own for the duration of a call are out of
/// reach.
#[derive(Clone, PartialEq, Eq, Default)]
pub struct Secret(Vec<u8>);

impl Secret {
    /// The bytes, to fill in place.
    pub(crate) fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.0
    }

    /// Keeps the first `len` bytes; the others are overwritten.
    pub fn truncate(&mut self, len: usize) {
        if let Some(tail) = self.0.get_mut(len..) {
            wipe(tail);
        }
        self.0.truncate(len);
    }
}

impl From<Vec<u8>> for Secret {
    fn from(bytes: Vec<u8>) -> Secret {
        Secret(bytes)
    }
}

impl From<&[u8]> for Secret {
    fn from(bytes: &[u8]) -> Secret {
        Secret(bytes.to_vec())
    }
}

impl Deref for Secret {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.0
    }
}

impl AsRef<[u8]> for Secret {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Secret({} bytes)", self.0.len())
    }
}

/// Whether `a` and `b` are equal, compared in constant time for their
/// length: the one comparison of secret values (tags, keys, exporter
/// values).
pub(crate) fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && black_box(a.iter().zip(b).fold(0u8, |d, (x, y)| d | (x ^ y))) == 0
}

impl Drop for Secret {
    fn drop(&mut self) {
        wipe(&mut self.0);
    }
}

/// Fills `out` from the operating system's random source.
pub fn fill_random(out: &mut [u8]) -> Result<(), super::Error> {
    getrandom::fill(out).map_err(|_| super::Error::RandomFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncate_keeps_the_head() {
        let mut s = Secret::from(vec![1, 2, 3]);
        s.truncate(2);
        assert_eq!(&*s, &[1, 2]);
        s.truncate(5);
        assert_eq!(&*s, &[1, 2]);
    }

    #[test]
    fn debug_shows_no_bytes() {
        assert_eq!(
            format!("{:?}", Secret::from(vec![0xab; 2])),
            "Secret(2 bytes)"
        );
    }

    #[test]
    fn random_fills() {
        let mut out = [0u8; 32];
        fill_random(&mut out).unwrap();
        assert_ne!(out, [0u8; 32]);
    }
}
