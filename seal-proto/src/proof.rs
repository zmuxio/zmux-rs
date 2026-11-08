//! The proof, a signature over the handshake transcript, and the post-quantum
//! authentication it gives.

use libcrux_ml_dsa::ml_dsa_44;
use zmux::proto::seal::{Error, Proof, fill_random};

use crate::keyalg::{KEYALG_MLDSA44, KeyAlg, KeyId, KeyUse, key_id};

/// The label of a proof in message 2.
const LABEL_R: &[u8] = b"zmux-seal proof r";
/// The label of a proof in message 3.
const LABEL_I: &[u8] = b"zmux-seal proof i";

/// `M = label ‖ 0x00 ‖ h_p` of a message, 1 for message 2 and 2 for message 3.
pub(crate) fn proof_message(index: usize, h_p: &[u8]) -> Vec<u8> {
    let label = if index == 2 { LABEL_I } else { LABEL_R };
    [label, &[0], h_p].concat()
}

/// The core's check of a message's proof: when the verdict names
/// `proof_key`, the message has a proof, its key has that KeyId and a proof key's KeyAlg,
/// and its signature verifies over `message`, the M of the message. The result is PQ
/// authentication; with `require_pq_auth` its absence fails too. Every
/// failure is `credentials_failed`.
pub fn check_proof(
    proof_key: Option<&KeyId>,
    proof: Option<Proof<'_>>,
    message: &[u8],
    require_pq_auth: bool,
) -> Result<bool, Error> {
    let mut pq = false;
    if let Some(want) = proof_key {
        let p = proof.ok_or(Error::CredentialsFailed)?;
        let alg = KeyAlg::from_value(p.key_alg)
            .filter(|a| a.key_use() == KeyUse::Proof)
            .ok_or(Error::CredentialsFailed)?;
        if key_id(p.key_alg, p.key) != *want || !alg.verify(p.key, message, p.sig) {
            return Err(Error::CredentialsFailed);
        }
        pq = alg.pq();
    }
    if require_pq_auth && !pq {
        return Err(Error::CredentialsFailed);
    }
    Ok(pq)
}

/// The rule of an end that requires PQ authentication: a pin of an X25519 key alone,
/// without a proof key, is `invalid_config`.
pub fn check_pin_pq_auth(require_pq_auth: bool, has_proof_key: bool) -> Result<(), Error> {
    if require_pq_auth && !has_proof_key {
        return Err(Error::InvalidConfig);
    }
    Ok(())
}

/// A proof key's signing half: ML-DSA-44 (KeyAlg 3) from its 32-byte seed ξ.
pub struct SigningKey {
    key: Box<ml_dsa_44::MLDSA44SigningKey>,
    public: Vec<u8>,
}

impl std::fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SigningKey")
            .field("key_id", &self.key_id())
            .finish_non_exhaustive()
    }
}

impl SigningKey {
    /// The key of `key_alg` from its seed; a KeyAlg that is not a proof key's, or a seed
    /// of another length, is `invalid_config`.
    pub fn from_seed(key_alg: u64, seed: &[u8]) -> Result<SigningKey, Error> {
        if key_alg != KEYALG_MLDSA44 {
            return Err(Error::InvalidConfig);
        }
        let seed: [u8; 32] = seed.try_into().map_err(|_| Error::InvalidConfig)?;
        let pair = ml_dsa_44::portable::generate_key_pair(seed);
        Ok(SigningKey {
            public: pair.verification_key.as_slice().to_vec(),
            key: Box::new(pair.signing_key),
        })
    }

    /// A new key of `key_alg` from the operating system's random source.
    pub fn generate(key_alg: u64) -> Result<SigningKey, Error> {
        let mut seed = [0u8; 32];
        fill_random(&mut seed)?;
        let key = Self::from_seed(key_alg, &seed);
        seed.fill(0);
        key
    }

    /// The KeyAlg.
    pub fn key_alg(&self) -> u64 {
        KEYALG_MLDSA44
    }

    /// The public key in its canonical encoding.
    pub fn public(&self) -> &[u8] {
        &self.public
    }

    /// The KeyId of the public key: what a verdict names.
    pub fn key_id(&self) -> KeyId {
        key_id(KEYALG_MLDSA44, &self.public)
    }

    /// Signs `message` hedged, as production signers must.
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        let mut rnd = [0u8; 32];
        fill_random(&mut rnd)?;
        self.sign_with(message, rnd)
    }

    /// Signs with the deterministic variant (zero randomness), for the vectors.
    #[cfg(feature = "test-vectors")]
    pub fn sign_deterministic(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        self.sign_with(message, [0; 32])
    }

    fn sign_with(&self, message: &[u8], rnd: [u8; 32]) -> Result<Vec<u8>, Error> {
        ml_dsa_44::portable::sign(&self.key, message, b"", rnd)
            .map(|s| s.as_slice().to_vec())
            .map_err(|_| Error::InvalidConfig)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_and_check() {
        let k = SigningKey::generate(KEYALG_MLDSA44).unwrap();
        let m = proof_message(1, &[7; 32]);
        let sig = k.sign(&m).unwrap();
        let p = Proof {
            key_alg: 3,
            key: k.public(),
            sig: &sig,
        };
        assert_eq!(check_proof(Some(&k.key_id()), Some(p), &m, true), Ok(true));
        assert_eq!(check_proof(None, Some(p), &m, false), Ok(false));
        let other = proof_message(2, &[7; 32]);
        assert_eq!(
            check_proof(Some(&k.key_id()), Some(p), &other, false),
            Err(Error::CredentialsFailed)
        );
        assert!(SigningKey::from_seed(1, &[0; 32]).is_err());
        assert!(SigningKey::from_seed(3, &[0; 31]).is_err());
    }
}
