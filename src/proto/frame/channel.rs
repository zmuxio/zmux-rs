//! Channel datagrams: one DATAGRAM frame sent on a carrier's own datagram
//! channel instead of in a record, after the Pipe Stream ID on channels
//! that the pipes of a connection share (QUIC, WebTransport), alone where
//! the channel belongs to the pipe.
//!
//! ```text
//! Channel Datagram {
//!   Pipe Stream ID (i),     -- on shared channels only
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

/// The bytes before the DATAGRAM frame's data: the Pipe Stream ID `id`
/// when present, and the frame type 0x30.
pub const fn header_len(id: Option<u64>) -> usize {
    match id {
        Some(id) => varint::len(id) + 1,
        None => 1,
    }
}

/// The length of a channel datagram carrying `data_len` bytes of DATAGRAM
/// data (its flow prefix included), after the Pipe Stream ID `id` when
/// present.
pub const fn datagram_len(id: Option<u64>, data_len: usize) -> usize {
    header_len(id) + data_len
}

/// Writes the header of a channel datagram ([`header_len`] bytes): the Pipe
/// Stream ID `id` when present, then the type of a DATAGRAM frame without
/// its Length field. The frame's data follows it.
pub fn encode_header(id: Option<u64>, buf: &mut [u8]) -> Result<usize, EncodeError> {
    let mut n = 0;
    if let Some(id) = id {
        n = varint::encode(id, buf)?;
    }
    let b = buf.get_mut(n).ok_or(EncodeError::BufferTooShort)?;
    *b = FrameType::DATAGRAM.0 as u8;
    Ok(n + 1)
}

/// A whole channel datagram carrying `data`.
pub fn encode(id: Option<u64>, data: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8; datagram_len(id, data.len())];
    let n = encode_header(id, &mut out).unwrap_or(0);
    out[n..].copy_from_slice(data);
    out
}

/// Splits a channel datagram that starts with a Pipe Stream ID into that
/// ID and the frame after it; `None` when the ID is truncated.
pub fn split(datagram: &[u8]) -> Option<(u64, &[u8])> {
    let (id, n) = varint::decode(datagram)?;
    Some((id, &datagram[n..]))
}

/// Decodes the frame of a channel datagram, which must be exactly one
/// DATAGRAM frame of type 0x30 that `gates` accepts; anything else
/// (another or a truncated frame, a Length field, bytes after it) is a
/// PROTOCOL_VIOLATION. The data borrows from `frame`.
pub fn decode_frame<'a>(frame: &'a [u8], gates: &Gates) -> Result<Datagram<'a>, Error> {
    const NOT_ONE: &str = "channel datagram is not one DATAGRAM frame without Length";
    let ty = FrameType::DATAGRAM.0;
    if frame.first() != Some(&(ty as u8)) {
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
                let d = decode_frame(frame, &gates).expect("decode");
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
            let e = decode_frame(b, &gates).expect_err(name);
            assert_eq!(
                e.code(),
                crate::proto::TransportErrorCode::PROTOCOL_VIOLATION,
                "{name}"
            );
        }
        // Not announced, or larger than announced.
        let none = Gates::NONE;
        assert!(decode_frame(&[0x30, 1], &none).is_err());
        let small = Gates {
            max_datagram_frame_size: 2,
            ..Gates::ALL
        };
        assert!(decode_frame(&[0x30, 1], &small).is_ok());
        assert!(decode_frame(&[0x30, 1, 2], &small).is_err());
    }
}
