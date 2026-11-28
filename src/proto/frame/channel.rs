//! Channel datagrams: one DATAGRAM frame sent on a carrier's own datagram
//! channel instead of in a record, after the Pipe Stream ID on channels
//! that the pipes of a connection share (QUIC, WebTransport), alone where
//! the channel belongs to the pipe.
//!
//! ```text
//! Channel Datagram {
//!   Pipe Stream ID (i),     -- on shared channels only
//!   [PADDING (..)],        -- when negotiated
//!   DATAGRAM Frame (..),    -- type 0x30, no Length field
//! }
//! ```
//!
//! The one place where channel datagrams are encoded and decoded: the
//! session core builds them ([`header_len`], [`encode_header`]) and parses
//! what arrives ([`decode_frame`]), carrier adapters route them by their
//! Pipe Stream ID ([`split`]).

use super::{Datagram, Frame, FrameType, Gates};
use crate::proto::error::{EncodeError, Error};
use crate::proto::varint;

/// A routing varint in the buffer passed to the carrier for one datagram.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Prefix {
    /// This channel belongs to the pipe and needs no routing prefix.
    None,
    /// zmux's Pipe Stream ID on a shared carrier channel.
    Pipe(u64),
    /// A carrier-owned prefix, such as an HTTP Datagram Quarter Stream ID.
    Carrier(u64),
}

impl Prefix {
    /// The varint to encode, if present.
    #[must_use]
    pub const fn id(self) -> Option<u64> {
        match self {
            Self::None => None,
            Self::Pipe(id) | Self::Carrier(id) => Some(id),
        }
    }

    /// The bytes belonging to the framing below zmux.
    #[must_use]
    pub const fn outer_bytes(self) -> usize {
        match self {
            Self::Carrier(id) => varint::len(id),
            _ => 0,
        }
    }
}

impl From<Option<u64>> for Prefix {
    fn from(id: Option<u64>) -> Self {
        id.map_or(Self::None, Self::Pipe)
    }
}

/// Maximum frame area of a channel datagram that carries leading padding.
pub(crate) fn max_padded_frame_len() -> usize {
    crate::util::usize_sat(crate::proto::params::ZMUX_MAX_RECORD_SIZE)
}

/// The bytes before the DATAGRAM frame's data: the Pipe Stream ID `id`
/// when present, and the frame type 0x30.
#[must_use]
pub const fn header_len(id: Option<u64>) -> usize {
    match id {
        Some(id) => varint::len(id) + 1,
        None => 1,
    }
}

/// The length of a channel datagram carrying `data_len` bytes of DATAGRAM
/// data (its flow prefix included), after the Pipe Stream ID `id` when
/// present.
#[must_use]
pub const fn datagram_len(id: Option<u64>, data_len: usize) -> usize {
    header_len(id) + data_len
}

/// The type of a DATAGRAM frame without its Length field, a one-byte
/// varint.
#[allow(
    clippy::cast_possible_truncation,
    reason = "the type is 0x30, below 64"
)]
const DATAGRAM_TYPE: u8 = FrameType::DATAGRAM.0 as u8;

/// Writes the header of a channel datagram ([`header_len`] bytes): the Pipe
/// Stream ID `id` when present, then the type of a DATAGRAM frame without
/// its Length field. The frame's data follows it.
pub fn encode_header(id: Option<u64>, buf: &mut [u8]) -> Result<usize, EncodeError> {
    let mut n = 0;
    if let Some(id) = id {
        n = varint::encode(id, buf)?;
    }
    let b = buf.get_mut(n).ok_or(EncodeError::BufferTooShort)?;
    *b = DATAGRAM_TYPE;
    Ok(n + 1)
}

/// A whole channel datagram carrying `data`.
#[must_use]
pub fn encode(id: Option<u64>, data: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8; datagram_len(id, data.len())];
    let n = encode_header(id, &mut out).unwrap_or(0);
    out[n..].copy_from_slice(data);
    out
}

/// Splits a channel datagram that starts with a Pipe Stream ID into that
/// ID and the frame after it; `None` when the ID is truncated.
#[must_use]
pub fn split(datagram: &[u8]) -> Option<(u64, &[u8])> {
    let (id, n) = varint::decode(datagram)?;
    Some((id, &datagram[n..]))
}

/// Decodes a single Length-less DATAGRAM frame with optional negotiated leading padding.
/// The data borrows from `frame`.
pub fn decode_frame<'a>(
    mut frame: &'a [u8],
    gates: &Gates,
    padding: bool,
) -> Result<Datagram<'a>, Error> {
    const NOT_ONE: &str = "channel datagram is not one DATAGRAM frame without Length";
    let ty = FrameType::DATAGRAM.0;
    if padding && frame.first() == Some(&0) {
        if frame.len() > max_padded_frame_len() {
            return Err(Error::protocol_violation(
                ty,
                "padded channel datagram exceeds 65535 bytes",
            ));
        }
        let start = frame.iter().position(|&b| b != 0).unwrap_or(frame.len());
        frame = &frame[start..];
    }
    if frame.first() != Some(&DATAGRAM_TYPE) {
        return Err(Error::protocol_violation(ty, NOT_ONE));
    }
    match Frame::decode(frame, gates) {
        Ok((Frame::Datagram(d), n)) if n == frame.len() && !d.explicit_len => Ok(d),
        Ok(_) => Err(Error::protocol_violation(ty, NOT_ONE)),
        Err(e) => Err(Error::protocol_violation(ty, e.reason())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let gates = Gates::ALL;
        for id in [0u64, 4, 63, 64, 16383, 16384, 1 << 40] {
            for data in [&[][..], &[0][..], &[9; 1200][..]] {
                let b = encode(Some(id), data);
                assert_eq!(b.len(), datagram_len(Some(id), data.len()));
                let (got, frame) = split(&b).expect("split");
                assert_eq!(got, id);
                let d = decode_frame(frame, &gates, false).expect("decode");
                assert_eq!(d.data, data);
                assert!(!d.explicit_len);
            }
        }
        // Without the Pipe Stream ID: the frame alone.
        assert_eq!(encode(None, b"x"), [0x30, b'x']);
        assert_eq!(datagram_len(None, 1), 2);
        assert_eq!(header_len(Some(64)), 3);
    }

    #[test]
    fn negotiated_padding_is_bounded_and_preserves_the_payload() {
        let gates = Gates::ALL;
        let bytes = [0, 0, 0, 0x30, 0, 0, b'a', 0];
        let (id, frame) = split(&bytes).unwrap();
        assert_eq!(id, 0);
        assert!(decode_frame(frame, &gates, false).is_err());
        assert_eq!(
            decode_frame(frame, &gates, true).unwrap().data,
            [0, 0, b'a', 0]
        );
        assert!(decode_frame(&[0; 3], &gates, true).is_err());
        let mut max = vec![0; max_padded_frame_len()];
        max[max_padded_frame_len() - 1] = 0x30;
        assert!(decode_frame(&max, &gates, true).is_ok());
        max.push(0);
        assert!(decode_frame(&max, &gates, true).is_err());
    }

    #[test]
    fn malformed() {
        assert_eq!(split(&[]), None);
        assert_eq!(split(&[0x40]), None, "truncated Pipe Stream ID");
        let gates = Gates::ALL;
        for (name, b) in [
            ("empty", &[][..]),
            ("with Length", &[0x31, 0x01, b'x'][..]),
            ("Length too short", &[0x31, 0x00, b'x'][..]),
            ("other frame", &[0x01][..]),
            ("padding first", &[0x00, 0x30, b'x'][..]),
            ("non-minimal type", &[0x40, 0x30, b'x'][..]),
            ("stream frame", &[0x08, 0x00, b'x'][..]),
        ] {
            let e = decode_frame(b, &gates, false).expect_err(name);
            assert_eq!(
                e.code(),
                crate::proto::TransportErrorCode::PROTOCOL_VIOLATION,
                "{name}"
            );
        }
        // Not announced, or larger than announced.
        let none = Gates::NONE;
        assert!(decode_frame(&[0x30, 1], &none, false).is_err());
        let small = Gates {
            max_datagram_frame_size: 2,
            ..Gates::ALL
        };
        assert!(decode_frame(&[0x30, 1], &small, false).is_ok());
        assert!(decode_frame(&[0x30, 1, 2], &small, false).is_err());
    }
}
