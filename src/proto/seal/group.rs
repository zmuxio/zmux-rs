//! The Groups: the key exchanges of Join and of the session epochs, and
//! `Combine`, which folds their shared secrets into a key.

use super::kex::{
    MLKEM768_CT_LEN, MLKEM768_EK_LEN, MLKEM768_RANDOM_LEN, MLKEM768_SEED_LEN, X25519_LEN,
    kem_random, mlkem768_decapsulate, mlkem768_encapsulate, mlkem768_generate, x25519,
    x25519_generate, x25519_public,
};
use super::{Error, Hash, Secret};

/// The values of the Profile, payload type, CredType, Suite, Group and KeyAlg spaces that
/// are private: never assigned, never interpreted, an unknown value of their space.
pub const PRIVATE: std::ops::RangeInclusive<u64> = (1 << 30)..=((1 << 31) - 1);

/// Group 1, X25519.
pub const GROUP_X25519: u64 = 1;
/// Group 2, X25519+MLKEM768.
pub const GROUP_X25519_MLKEM768: u64 = 2;

/// One row of the Group table.
#[derive(Debug)]
pub struct Group {
    value: u64,
    priority: u8,
    kem: bool,
}

static GROUPS: [Group; 2] = [
    Group {
        value: GROUP_X25519,
        priority: 1,
        kem: false,
    },
    Group {
        value: GROUP_X25519_MLKEM768,
        priority: 2,
        kem: true,
    },
];

impl Group {
    /// The Group with this value, if this implementation has it.
    pub fn from_value(value: u64) -> Option<&'static Group> {
        GROUPS.iter().find(|g| g.value == value)
    }

    /// Every Group of this implementation, ascending.
    pub fn all() -> impl Iterator<Item = &'static Group> {
        GROUPS.iter()
    }

    /// The Group value.
    pub fn value(&self) -> u64 {
        self.value
    }

    /// The priority: higher is preferred.
    pub fn priority(&self) -> u8 {
        self.priority
    }

    /// The length of the initiator's share.
    pub fn initiator_share_len(&self) -> usize {
        X25519_LEN + if self.kem { MLKEM768_EK_LEN } else { 0 }
    }

    /// The length of the responder's share.
    pub fn responder_share_len(&self) -> usize {
        X25519_LEN + if self.kem { MLKEM768_CT_LEN } else { 0 }
    }

    /// The share length of a role: `initiator` for the joiner or the offering end.
    pub fn share_len(&self, initiator: bool) -> usize {
        if initiator {
            self.initiator_share_len()
        } else {
            self.responder_share_len()
        }
    }

    /// The usable Group of highest priority among `usable` values.
    pub fn highest(usable: &[u64]) -> Option<&'static Group> {
        usable
            .iter()
            .filter_map(|&v| Group::from_value(v))
            .max_by_key(|g| g.priority)
    }

    /// The initiator's share and private values, from the operating system's random
    /// source.
    pub fn initiate(&'static self) -> Result<(Vec<u8>, GroupInitiator), Error> {
        let x = x25519_generate()?;
        let seed = if self.kem {
            Some(kem_random(MLKEM768_SEED_LEN)?)
        } else {
            None
        };
        self.initiate_from(x, seed)
    }

    /// As [`Group::initiate`] with a fixed X25519 private key and, in Group 2, a fixed
    /// ML-KEM seed `(d, z)`, for the vectors.
    #[cfg(feature = "test-hooks")]
    pub fn initiate_with(
        &'static self,
        x: &[u8],
        kem_seed: &[u8],
    ) -> Result<(Vec<u8>, GroupInitiator), Error> {
        let seed = self.kem.then(|| Secret::from(kem_seed));
        self.initiate_from(Secret::from(x), seed)
    }

    fn initiate_from(
        &'static self,
        x: Secret,
        seed: Option<Secret>,
    ) -> Result<(Vec<u8>, GroupInitiator), Error> {
        let mut share = x25519_public(&x)?;
        let dk = match seed {
            Some(seed) => {
                let (dk, ek) = mlkem768_generate(&seed)?;
                share.extend_from_slice(&ek);
                Some(dk)
            }
            None => None,
        };
        Ok((share, GroupInitiator { group: self, x, dk }))
    }

    /// The responder's side: its share and the shared secrets of a received initiator
    /// share of the right length. An all-zero X25519 output or a refused encapsulation key
    /// is `kex`; the private values are dropped before this returns.
    pub fn respond(&'static self, share: &[u8]) -> Result<(Vec<u8>, SharedSecrets), Error> {
        let x = x25519_generate()?;
        let m = if self.kem {
            Some(kem_random(MLKEM768_RANDOM_LEN)?)
        } else {
            None
        };
        self.respond_from(share, x, m)
    }

    /// As [`Group::respond`] with a fixed X25519 private key and, in Group 2, a fixed
    /// encapsulation randomness `m`, for the vectors.
    #[cfg(feature = "test-hooks")]
    pub fn respond_with(
        &'static self,
        share: &[u8],
        x: &[u8],
        m: &[u8],
    ) -> Result<(Vec<u8>, SharedSecrets), Error> {
        let m = self.kem.then(|| Secret::from(m));
        self.respond_from(share, Secret::from(x), m)
    }

    fn respond_from(
        &'static self,
        share: &[u8],
        x: Secret,
        m: Option<Secret>,
    ) -> Result<(Vec<u8>, SharedSecrets), Error> {
        if share.len() != self.initiator_share_len() {
            return Err(Error::BadField);
        }
        let (e, ek) = share.split_at(X25519_LEN);
        let mut out = x25519_public(&x)?;
        let mut secrets = vec![x25519(&x, e)?];
        drop(x);
        if let Some(m) = m {
            let (ct, ss) = mlkem768_encapsulate(ek, &m)?;
            out.extend_from_slice(&ct);
            secrets.push(ss);
        }
        Ok((out, SharedSecrets(secrets)))
    }
}

/// The initiator's private values, kept until the responder's share arrives. They are
/// dropped, and overwritten, with this value.
pub struct GroupInitiator {
    group: &'static Group,
    x: Secret,
    dk: Option<Secret>,
}

impl std::fmt::Debug for GroupInitiator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GroupInitiator")
            .field("group", &self.group.value)
            .finish_non_exhaustive()
    }
}

impl GroupInitiator {
    /// The Group.
    pub fn group(&self) -> &'static Group {
        self.group
    }

    /// The shared secrets of the responder's share: `bad_field` for another length, `kex`
    /// for an all-zero X25519 output. The ciphertext is checked by its length only.
    pub fn finish(self, share: &[u8]) -> Result<SharedSecrets, Error> {
        if share.len() != self.group.responder_share_len() {
            return Err(Error::BadField);
        }
        let (e, ct) = share.split_at(X25519_LEN);
        let mut secrets = vec![x25519(&self.x, e)?];
        if let Some(dk) = &self.dk {
            secrets.push(mlkem768_decapsulate(dk, ct)?);
        }
        Ok(SharedSecrets(secrets))
    }
}

/// The shared secrets of an exchange, in the order of the Group table, 32 bytes each.
pub struct SharedSecrets(Vec<Secret>);

impl SharedSecrets {
    /// The secrets in order.
    pub fn as_slice(&self) -> &[Secret] {
        &self.0
    }
}

impl std::fmt::Debug for SharedSecrets {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SharedSecrets({})", self.0.len())
    }
}

/// `Combine(salt, ss_1, ..., ss_n)`: each shared secret is the input keying material of
/// one HKDF-Extract of `hash`, with the previous output as salt.
pub fn combine(hash: &Hash, salt: &[u8], secrets: &[impl AsRef<[u8]>]) -> Secret {
    let mut prk = Secret::from(salt);
    for ss in secrets {
        prk = Secret::from(hash.extract(&prk, ss.as_ref()));
    }
    prk
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn both_groups_agree() {
        for g in Group::all() {
            let (share_i, init) = g.initiate().unwrap();
            assert_eq!(share_i.len(), g.initiator_share_len());
            let (share_r, ss_r) = g.respond(&share_i).unwrap();
            assert_eq!(share_r.len(), g.responder_share_len());
            let ss_i = init.finish(&share_r).unwrap();
            assert_eq!(ss_i.as_slice().len(), if g.kem { 2 } else { 1 });
            assert!(
                ss_i.as_slice()
                    .iter()
                    .zip(ss_r.as_slice())
                    .all(|(a, b)| **a == **b)
            );
        }
        assert_eq!(Group::highest(&[1, 2]).unwrap().value(), 2);
        assert_eq!(Group::highest(&[1, 7]).unwrap().value(), 1);
    }

    #[test]
    fn low_order_and_length() {
        let g = Group::from_value(1).unwrap();
        assert_eq!(g.respond(&[0; 32]).err(), Some(Error::Kex));
        assert_eq!(g.respond(&[1; 31]).err(), Some(Error::BadField));
    }
}
