//! `zmux_session_crypto`: an endpoint's Join Suites and Groups,
//! and `session_crypto`, which enters every join key and epoch secret.

use super::group::combine;
use super::group::{GROUP_X25519_MLKEM768, Group};
use super::join::Suite;
use super::wire::{put_varint, read_shortest};
use super::{Error, SHA256, Secret};

/// One endpoint's sets of Suites and Groups, each ascending, holding Suite 1 and Group 2
/// respectively, with no zero and no duplicate.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SessionCrypto {
    /// The Join Suites, ascending.
    pub suites: Vec<u64>,
    /// The Groups, ascending.
    pub groups: Vec<u64>,
}

fn valid_set(set: &[u64], required: u64) -> bool {
    set.first().is_some_and(|&f| f != 0)
        && set.windows(2).all(|w| w[0] < w[1])
        && set.contains(&required)
}

impl SessionCrypto {
    /// Every Suite and Group of this build: an endpoint's sets as locally configured by
    /// default.
    pub fn local() -> SessionCrypto {
        SessionCrypto {
            suites: Suite::all().map(Suite::value).collect(),
            groups: Group::all().map(Group::value).collect(),
        }
    }

    /// Whether both sets follow the rules of the parameter.
    pub fn is_valid(&self) -> bool {
        valid_set(&self.suites, 1) && valid_set(&self.groups, GROUP_X25519_MLKEM768)
    }

    /// Checks a local configuration: valid, and every value one this build implements.
    /// Anything else is `invalid_config`.
    pub fn check_local(&self) -> Result<(), Error> {
        let known = self.suites.iter().all(|&s| Suite::from_value(s).is_some())
            && self.groups.iter().all(|&g| Group::from_value(g).is_some());
        (self.is_valid() && known)
            .then_some(())
            .ok_or(Error::InvalidConfig)
    }

    /// The parameter's value: `SuiteSet ‖ GroupSet`.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.encode_into(&mut out);
        out
    }

    fn encode_into(&self, out: &mut Vec<u8>) {
        for set in [&self.suites, &self.groups] {
            put_varint(out, set.len() as u64);
            for &v in set {
                put_varint(out, v);
            }
        }
    }

    /// The encoded length of the value.
    pub fn encoded_len(&self) -> usize {
        self.encode().len()
    }

    /// Parses a received value: shortest varints, both sets valid, nothing after them.
    pub fn parse(value: &[u8]) -> Result<SessionCrypto, Error> {
        let mut at = 0;
        let mut read = || -> Result<u64, Error> {
            let (v, used, shortest) =
                read_shortest(value.get(at..).ok_or(Error::Malformed)?).ok_or(Error::Malformed)?;
            if !shortest {
                return Err(Error::Malformed);
            }
            at += used;
            Ok(v)
        };
        let mut sets = [Vec::new(), Vec::new()];
        for set in &mut sets {
            let count = read()?;
            for _ in 0..count {
                set.push(read()?);
            }
        }
        let [suites, groups] = sets;
        let out = SessionCrypto { suites, groups };
        if at != value.len() || !out.is_valid() {
            return Err(Error::Malformed);
        }
        Ok(out)
    }

    /// The usable values: the intersection of two sets, ascending.
    pub fn usable(own: &[u64], peer: &[u64]) -> Vec<u64> {
        own.iter().copied().filter(|v| peer.contains(v)).collect()
    }
}

/// `session_crypto` = Value(session initiator) ‖ Value(session responder). Either value
/// breaking the rules of the parameter is `invalid_config`.
pub fn session_crypto(
    initiator: &SessionCrypto,
    responder: &SessionCrypto,
) -> Result<Vec<u8>, Error> {
    if !initiator.is_valid() || !responder.is_valid() {
        return Err(Error::InvalidConfig);
    }
    let mut out = Vec::new();
    initiator.encode_into(&mut out);
    responder.encode_into(&mut out);
    Ok(out)
}

/// `SHA-256(session_crypto)`, which the join keys and epoch secrets take.
pub fn session_crypto_hash(session_crypto: &[u8]) -> Vec<u8> {
    SHA256.hash(&[session_crypto])
}

/// The secret of epoch `next` = e + 1 from that of epoch e, the frames of the exchange,
/// Phase through Locator, and the Group's shared secrets of an epoch:
/// `prk` and then `Combine(prk, ss...)`, both SHA-256. Returns `(prk, epoch_secret)`.
pub fn derive_epoch_secret(
    epoch_secret: &[u8],
    next: u64,
    session_crypto: &[u8],
    offer_body: &[u8],
    answer_body: &[u8],
    secrets: &[impl AsRef<[u8]>],
) -> Result<(Secret, Secret), Error> {
    let mut info = b"zmux epoch".to_vec();
    put_varint(&mut info, next);
    info.extend_from_slice(&SHA256.hash(&[session_crypto]));
    info.extend_from_slice(&SHA256.hash(&[offer_body, answer_body]));
    let prk = Secret::from(SHA256.expand(epoch_secret, &info, 32)?);
    let secret = combine(&SHA256, &prk, secrets);
    Ok((prk, secret))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sc(suites: &[u64], groups: &[u64]) -> SessionCrypto {
        SessionCrypto {
            suites: suites.to_vec(),
            groups: groups.to_vec(),
        }
    }

    #[test]
    fn rules() {
        assert!(sc(&[1], &[2]).is_valid());
        assert!(sc(&[1, 2], &[1, 2]).is_valid());
        assert!(!sc(&[2], &[2]).is_valid());
        assert!(!sc(&[1], &[1]).is_valid());
        assert!(!sc(&[0, 1], &[2]).is_valid());
        assert!(!sc(&[1, 1], &[2]).is_valid());
        assert!(!sc(&[2, 1], &[2]).is_valid());
        let v = sc(&[1, 2], &[1, 2]);
        assert_eq!(v.encode(), [2, 1, 2, 2, 1, 2]);
        assert_eq!(SessionCrypto::parse(&v.encode()).unwrap(), v);
        assert!(SessionCrypto::parse(&[1, 1]).is_err());
        assert!(SessionCrypto::parse(&[1, 1, 1, 2, 0]).is_err());
        assert!(SessionCrypto::parse(&[1, 0x40, 1, 1, 2]).is_err());
    }
}
