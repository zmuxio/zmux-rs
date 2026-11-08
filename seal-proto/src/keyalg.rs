//! The key algorithms of long-term public keys and their one name, the KeyId, by which a
//! pin and a verdict name a key. A new algorithm is a new row of the table.

use libcrux_ml_dsa::ml_dsa_44;
use zmux::proto::seal::{SHA256, put_varint};

/// A KeyId: SHA-256 of a key with its KeyAlg.
pub type KeyId = [u8; 32];

/// KeyAlg 1, X25519: the static key of Establish.
pub const KEYALG_X25519: u64 = 1;
/// KeyAlg 3, ML-DSA-44: a proof key.
pub const KEYALG_MLDSA44: u64 = 3;

/// FIPS 204 lengths of ML-DSA-44.
pub(crate) const MLDSA44_KEY: usize = 1312;
pub(crate) const MLDSA44_SIG: usize = 2420;

/// What a key of an algorithm is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyUse {
    /// The static key of Establish.
    Static,
    /// A proof key: it signs the handshake transcript.
    Proof,
}

/// `verify(key, message, sig)` of a signing algorithm.
type VerifyFn = fn(&[u8], &[u8], &[u8]) -> bool;

/// One row of the KeyAlg table.
#[derive(Debug)]
pub struct KeyAlg {
    value: u64,
    name: &'static str,
    key_len: usize,
    sig_len: usize,
    pq: bool,
    key_use: KeyUse,
    /// `verify(key, message, sig)` of a signing algorithm; lengths are checked before.
    verify: Option<VerifyFn>,
}

static KEYALGS: [KeyAlg; 2] = [
    KeyAlg {
        value: KEYALG_X25519,
        name: "X25519",
        key_len: 32,
        sig_len: 0,
        pq: false,
        key_use: KeyUse::Static,
        verify: None,
    },
    KeyAlg {
        value: KEYALG_MLDSA44,
        name: "ML-DSA-44",
        key_len: MLDSA44_KEY,
        sig_len: MLDSA44_SIG,
        pq: true,
        key_use: KeyUse::Proof,
        verify: Some(mldsa44_verify),
    },
];

impl KeyAlg {
    /// The KeyAlg with this value; `None` for 0, an unassigned and a private value.
    pub fn from_value(value: u64) -> Option<&'static KeyAlg> {
        KEYALGS.iter().find(|a| a.value == value)
    }

    /// Every KeyAlg, ascending.
    pub fn all() -> impl Iterator<Item = &'static KeyAlg> {
        KEYALGS.iter()
    }

    /// The value.
    pub fn value(&self) -> u64 {
        self.value
    }

    /// The name of the table.
    pub fn name(&self) -> &'static str {
        self.name
    }

    /// The length of the canonical key encoding.
    pub fn key_len(&self) -> usize {
        self.key_len
    }

    /// The length of a signature; 0 for a key that does not sign.
    pub fn sig_len(&self) -> usize {
        self.sig_len
    }

    /// Whether the algorithm resists a quantum adversary: the PQ column.
    pub fn pq(&self) -> bool {
        self.pq
    }

    /// The use of the column.
    pub fn key_use(&self) -> KeyUse {
        self.key_use
    }

    /// Verifies `sig` over `message` with `key`: `false` for a key or a signature of
    /// another length than the table's, and for an algorithm that does not sign.
    pub fn verify(&self, key: &[u8], message: &[u8], sig: &[u8]) -> bool {
        match self.verify {
            Some(f) if key.len() == self.key_len && sig.len() == self.sig_len => {
                f(key, message, sig)
            }
            _ => false,
        }
    }
}

/// Pure ML-DSA-44 with an empty context. Any byte string of the right length is a key.
fn mldsa44_verify(key: &[u8], message: &[u8], sig: &[u8]) -> bool {
    let (Ok(k), Ok(s)) = (
        <[u8; MLDSA44_KEY]>::try_from(key),
        <[u8; MLDSA44_SIG]>::try_from(sig),
    ) else {
        return false;
    };
    ml_dsa_44::portable::verify(
        &ml_dsa_44::MLDSA44VerificationKey::new(k),
        message,
        b"",
        &ml_dsa_44::MLDSA44Signature::new(s),
    )
    .is_ok()
}

/// `KeyId(KeyAlg, key) = SHA-256("zmux-seal key" ‖ varint(KeyAlg) ‖ key)`.
pub fn key_id(key_alg: u64, key: &[u8]) -> KeyId {
    let mut head = b"zmux-seal key".to_vec();
    put_varint(&mut head, key_alg);
    let digest = SHA256.hash(&[&head, key]);
    let mut out = [0; 32];
    out.copy_from_slice(&digest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table() {
        assert_eq!(KeyAlg::from_value(3).unwrap().sig_len(), 2420);
        assert!(KeyAlg::from_value(0).is_none());
        assert!(KeyAlg::from_value(2).is_none());
        assert!(KeyAlg::from_value(1 << 30).is_none());
        assert!(!KeyAlg::from_value(1).unwrap().pq());
        assert!(!KeyAlg::from_value(1).unwrap().verify(&[0; 32], b"m", &[]));
        assert_ne!(key_id(1, &[0; 32]), key_id(3, &[0; 32]));
    }
}
