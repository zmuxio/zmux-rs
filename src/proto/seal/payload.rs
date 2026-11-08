//! The handshake payload codec.

use super::Error;
use super::wire::{put_varint, read_shortest};

const CREDENTIALS: u64 = 1;
const APP_DATA: u64 = 2;
const FIRST_BYTES: u64 = 3;
const JOIN_PIPE: u64 = 5;
const FRAMES: u64 = 6;
const JOIN_DECISION: u64 = 7;
const PROOF: u64 = 8;
const KEY_SHARE: u64 = 9;

/// A varint inside a payload: value and encoded length. Running out comes before
/// non-shortest.
pub fn get_item_varint(input: &[u8]) -> Result<(u64, usize), Error> {
    let (value, len, shortest) = read_shortest(input).ok_or(Error::TlvTruncated)?;
    if !shortest {
        return Err(Error::TlvNonMinimal);
    }
    Ok((value, len))
}

fn next_item(input: &[u8]) -> Result<(u64, &[u8], &[u8]), Error> {
    let (kind, used) = get_item_varint(input)?;
    let rest = &input[used..];
    let (len, used) = get_item_varint(rest)?;
    let rest = &rest[used..];
    let len = usize::try_from(len).map_err(|_| Error::TlvTruncated)?;
    let (value, rest) = rest.split_at_checked(len).ok_or(Error::TlvTruncated)?;
    Ok((kind, value, rest))
}

/// The credential item: `CredType(varint) ‖ Credential`. An empty value and CredType 0
/// ("no credential") are `tlv_credentials`; the credential itself may be empty.
fn parse_credential(value: &[u8]) -> Result<CredentialEntry<'_>, Error> {
    if value.is_empty() {
        return Err(Error::TlvCredentials);
    }
    let (kind, used) = get_item_varint(value)?;
    if kind == 0 {
        return Err(Error::TlvCredentials);
    }
    Ok(CredentialEntry {
        kind,
        credential: &value[used..],
    })
}

/// The join pipe item.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct JoinPipe {
    /// The Pipe ID.
    pub id: u64,
    /// 0 up, 1 down, 2 bidi.
    pub direction: u8,
    /// The fate group.
    pub fate_group: u64,
    /// The priority.
    pub priority: u64,
    /// Whether the pipe is a standby.
    pub standby: bool,
}

impl JoinPipe {
    /// Decodes the value of the item.
    pub fn decode(value: &[u8]) -> Result<JoinPipe, Error> {
        fn byte(input: &[u8]) -> Result<(u8, &[u8]), Error> {
            input
                .split_first()
                .map(|(b, r)| (*b, r))
                .ok_or(Error::TlvTruncated)
        }
        let (id, used) = get_item_varint(value)?;
        let (direction, rest) = byte(&value[used..])?;
        let (fate_group, used) = get_item_varint(rest)?;
        let rest = &rest[used..];
        let (priority, used) = get_item_varint(rest)?;
        let (standby, rest) = byte(&rest[used..])?;
        if !rest.is_empty() {
            return Err(Error::TlvTruncated);
        }
        if direction > 2 || standby > 1 {
            return Err(Error::BadField);
        }
        Ok(JoinPipe {
            id,
            direction,
            fate_group,
            priority,
            standby: standby == 1,
        })
    }

    /// Encodes the value of the item.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        put_varint(&mut out, self.id);
        out.push(self.direction);
        put_varint(&mut out, self.fate_group);
        put_varint(&mut out, self.priority);
        out.push(u8::from(self.standby));
        out
    }
}

fn check_known_value(kind: u64, value: &[u8]) -> Result<(), Error> {
    match kind {
        CREDENTIALS => parse_credential(value).map(|_| ()),
        PROOF => Proof::parse(value).map(|_| ()),
        JOIN_PIPE => JoinPipe::decode(value).map(|_| ()),
        JOIN_DECISION => match value {
            [0 | 1] => Ok(()),
            _ => Err(Error::BadField),
        },
        KEY_SHARE => get_item_varint(value).map(|_| ()),
        _ => Ok(()),
    }
}

/// A validated handshake payload.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Payload {
    raw: Vec<u8>,
}

impl Payload {
    /// Validates a received payload against the known types of its message.
    /// Padding is known everywhere and not listed.
    pub fn validate(raw: Vec<u8>, known: &[u64]) -> Result<Payload, Error> {
        Self::validate_with(raw, known, |_, _| Ok(()))
    }

    /// As [`Payload::validate`], with `check` run on each item in order, after its syntax
    /// and order and before its type is judged: a message's own rules on an item, which
    /// come in byte order with the rest.
    pub fn validate_with(
        raw: Vec<u8>,
        known: &[u64],
        mut check: impl FnMut(u64, &[u8]) -> Result<(), Error>,
    ) -> Result<Payload, Error> {
        let mut rest = raw.as_slice();
        let mut last = None;
        while !rest.is_empty() {
            let (kind, value, after) = next_item(rest)?;
            if last.is_some_and(|l| kind <= l) {
                return Err(Error::TlvOrder);
            }
            last = Some(kind);
            check(kind, value)?;
            if known.contains(&kind) {
                check_known_value(kind, value)?;
            } else if kind != 0 && kind & 1 == 1 {
                return Err(Error::TlvUnknownCritical);
            }
            rest = after;
        }
        Ok(Payload { raw })
    }

    /// Validates a payload about to be sent: anything the peer would refuse is a
    /// local error, and so is any type this message does not know, odd or even.
    /// Skipping is a receiver's rule only.
    pub fn check_outgoing(raw: &[u8], known: &[u64]) -> Result<(), Error> {
        let parsed = Payload::validate(raw.to_vec(), known).map_err(|_| Error::InvalidConfig)?;
        let mut rest = parsed.raw.as_slice();
        while !rest.is_empty() {
            let (kind, _, after) = next_item(rest).map_err(|_| Error::InvalidConfig)?;
            if kind != 0 && !known.contains(&kind) {
                return Err(Error::InvalidConfig);
            }
            rest = after;
        }
        Ok(())
    }

    fn value(&self, wanted: u64) -> Option<&[u8]> {
        let mut rest = self.raw.as_slice();
        while let Ok((kind, value, after)) = next_item(rest) {
            if kind == wanted {
                return Some(value);
            }
            rest = after;
        }
        None
    }

    /// The encoded payload.
    pub fn as_bytes(&self) -> &[u8] {
        &self.raw
    }

    /// The credential, if the item is present.
    pub fn credential(&self) -> Option<CredentialEntry<'_>> {
        parse_credential(self.value(CREDENTIALS)?).ok()
    }

    /// The proof, where the message knows the type.
    pub fn proof(&self) -> Option<Proof<'_>> {
        Proof::parse(self.value(PROOF)?).ok()
    }

    /// The application's handshake data, where the message knows the type.
    pub fn app_data(&self) -> Option<&[u8]> {
        self.value(APP_DATA)
    }

    /// The start of the sender's zmux byte stream.
    pub fn first_bytes(&self) -> Option<&[u8]> {
        self.value(FIRST_BYTES)
    }

    /// The join pipe, if present and known in this message.
    pub fn join_pipe(&self) -> Option<JoinPipe> {
        JoinPipe::decode(self.value(JOIN_PIPE)?).ok()
    }

    /// Encoded zmux frames, for the session layer.
    pub fn frames(&self) -> Option<&[u8]> {
        self.value(FRAMES)
    }

    /// The key share: its Group and share, where the message knows the type.
    pub fn key_share(&self) -> Option<(u64, &[u8])> {
        let value = self.value(KEY_SHARE)?;
        let (group, used) = get_item_varint(value).ok()?;
        Some((group, &value[used..]))
    }

    /// The join decision: `true` accepts.
    pub fn join_accepted(&self) -> Option<bool> {
        match self.value(JOIN_DECISION)? {
            [0] => Some(true),
            [1] => Some(false),
            _ => None,
        }
    }

    pub(super) fn has(&self, wanted: u64) -> bool {
        self.value(wanted).is_some()
    }
}

/// The value of a proof item (type 8): `KeyAlg ‖ PubLen ‖ Pub ‖ Sig`. The core reads only
/// its structure; the signature is judged against a verdict's proof key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Proof<'a> {
    /// The KeyAlg of `key`.
    pub key_alg: u64,
    /// The public key.
    pub key: &'a [u8],
    /// The signature: the rest of the value.
    pub sig: &'a [u8],
}

impl<'a> Proof<'a> {
    /// The type of the item.
    pub const ITEM: u64 = PROOF;

    /// Parses a value: shortest varints (`tlv_non_minimal`) and `Pub` within the value
    /// (`tlv_truncated`).
    pub fn parse(value: &'a [u8]) -> Result<Proof<'a>, Error> {
        let (key_alg, used) = get_item_varint(value)?;
        let rest = &value[used..];
        let (len, used) = get_item_varint(rest)?;
        let rest = &rest[used..];
        let len = usize::try_from(len).map_err(|_| Error::TlvTruncated)?;
        let (key, sig) = rest.split_at_checked(len).ok_or(Error::TlvTruncated)?;
        Ok(Proof { key_alg, key, sig })
    }

    /// Encodes the value.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.key.len() + self.sig.len() + 8);
        put_varint(&mut out, self.key_alg);
        put_varint(&mut out, self.key.len() as u64);
        out.extend_from_slice(self.key);
        out.extend_from_slice(self.sig);
        out
    }
}

/// Encodes items for a payload, in the order given.
pub fn encode_payload(items: &[(u64, &[u8])]) -> Vec<u8> {
    let mut out = Vec::new();
    for (kind, value) in items {
        put_varint(&mut out, *kind);
        put_varint(&mut out, value.len() as u64);
        out.extend_from_slice(value);
    }
    out
}

/// A credential: its CredType and its bytes, opaque to the core.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CredentialEntry<'a> {
    /// The CredType, never 0.
    pub kind: u64,
    /// The credential, possibly empty.
    pub credential: &'a [u8],
}

pub(super) const JOIN_HELLO_KNOWN: &[u64] = &[JOIN_PIPE, FRAMES, KEY_SHARE];
pub(super) const JOIN_REPLY_KNOWN: &[u64] = &[FRAMES, JOIN_DECISION, KEY_SHARE];
/// The type of the key share item, the last of a Hello's and a Reply's known types.
pub(super) const KEY_SHARE_ITEM: u64 = KEY_SHARE;
pub(super) const JOIN_HELLO_REQUIRED: u64 = JOIN_PIPE;
pub(super) const JOIN_REPLY_REQUIRED: u64 = JOIN_DECISION;

#[cfg(test)]
mod tests {
    use super::*;

    /// Type 4 is unassigned: a receiver skips it (even), a sender never
    /// sends it.
    #[test]
    fn type_4_is_skipped_and_never_sent() {
        let raw = encode_payload(&[(4, &[1, 2][..]), (FRAMES, &[][..])]);
        let p = Payload::validate(raw.clone(), JOIN_REPLY_KNOWN).unwrap();
        assert_eq!(p.frames(), Some(&[][..]));
        assert_eq!(
            Payload::check_outgoing(&raw, JOIN_REPLY_KNOWN),
            Err(Error::InvalidConfig)
        );
    }
}
