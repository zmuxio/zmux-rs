//! Framing, Mode, varints and dispatch.

use super::Error;
use crate::proto::ident::{FirstBytes, classify_first_bytes};
use crate::proto::record::Framing;
use crate::proto::varint;

/// The handshake message floor (secure-carrier/SPEC.md Section 4.1): every handshake message
/// is written in at most 8192 bytes, from its first byte through the end of its last unit,
/// the carrier record floor. Receivers accept up to 65535.
pub const HANDSHAKE_MESSAGE_FLOOR: usize = 8192;

/// Frames one unit: a 16-bit length on a byte stream, nothing on a message carrier. `out`
/// holds the header of the message so far: a message that comes to more than
/// [`HANDSHAKE_MESSAGE_FLOOR`] bytes is `too_large`, and nothing is written.
pub fn frame(framing: Framing, out: &mut Vec<u8>, unit: &[u8]) -> Result<(), Error> {
    let len = u16::try_from(unit.len()).map_err(|_| Error::TooLarge)?;
    let prefix = if framing == Framing::ByteStream { 2 } else { 0 };
    if out.len() + prefix + unit.len() > HANDSHAKE_MESSAGE_FLOOR {
        return Err(Error::TooLarge);
    }
    if framing == Framing::ByteStream {
        out.extend_from_slice(&len.to_be_bytes());
    }
    out.extend_from_slice(unit);
    Ok(())
}

/// Cuts the first unit of a byte stream at offset `at`: the unit and the total
/// consumed from the start of `input`.
pub fn cut_frame(input: &[u8], at: usize) -> Result<(&[u8], usize), Error> {
    let rest = input.get(at..).unwrap_or(&[]);
    let Some((len, rest)) = rest.split_first_chunk::<2>() else {
        return Err(Error::Incomplete { need: at + 2 });
    };
    let len = u16::from_be_bytes(*len) as usize;
    let total = at + 2 + len;
    let unit = rest.get(..len).ok_or(Error::Incomplete { need: total })?;
    Ok((unit, total))
}

/// The largest handshake unit, a message of a message carrier or a
/// length-prefixed unit of a byte stream: the one definition the Join and
/// the Establish codecs share.
pub const MAX_UNIT: usize = u16::MAX as usize;

/// Cuts one unit from the start of `input`: a framed unit on a byte stream, the
/// whole message on a message carrier. Returns the unit and the bytes consumed.
pub fn cut_unit(framing: Framing, input: &[u8]) -> Result<(&[u8], usize), Error> {
    message_tail(framing, input, 0, false)
}

/// The failure of a handshake message that ends before `need` bytes:
/// `incomplete` on a byte stream, where more may come, `malformed` on a
/// message carrier, whose message is whole.
#[must_use]
pub fn short(framing: Framing, need: usize) -> Error {
    if framing == Framing::ByteStream {
        Error::Incomplete { need }
    } else {
        Error::Malformed
    }
}

/// The shortest-encoded varint at `at` of a handshake message: its value
/// and width. A cut one is [`short`]; one not in its shortest encoding is
/// `malformed`.
pub fn shortest_varint(framing: Framing, input: &[u8], at: usize) -> Result<(u64, usize), Error> {
    let rest = input.get(at..).unwrap_or(&[]);
    let Some((value, used, shortest)) = read_shortest(rest) else {
        let width = rest.first().map_or(1, |b| 1usize << (b >> 6));
        return Err(short(framing, at + width));
    };
    if !shortest {
        return Err(Error::Malformed);
    }
    Ok((value, used))
}

/// The last unit of a handshake message, from `at`: on a byte stream the
/// framed unit there, which must end `input` when `whole` (a byte past it is
/// `trailing_bytes`); on a message carrier the rest of the message, at most
/// [`MAX_UNIT`]. Returns the unit and the bytes consumed.
pub fn message_tail(
    framing: Framing,
    input: &[u8],
    at: usize,
    whole: bool,
) -> Result<(&[u8], usize), Error> {
    if framing == Framing::ByteStream {
        let (unit, total) = cut_frame(input, at)?;
        if whole && total != input.len() {
            return Err(Error::TrailingBytes);
        }
        return Ok((unit, total));
    }
    let rest = input.get(at..).ok_or(Error::Malformed)?;
    if rest.len() > MAX_UNIT {
        return Err(Error::TooLarge);
    }
    Ok((rest, input.len()))
}

/// How a pipe's records are protected, ordered from the strongest to the
/// weakest. A pipe is joined `Sealed`, `Bound` or `Trusted`; `Unmanaged`
/// is only reported, for a first pipe outside the secure carrier, and no
/// Hello carries it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum RecordMode {
    /// Records protected by the handshake's keys.
    Sealed = 0,
    /// Raw records on a carrier whose exporter is bound into the handshake.
    Bound = 1,
    /// Raw records by explicit configuration of both ends.
    Trusted = 2,
    /// A first pipe outside the secure carrier: reported only, never
    /// chosen for a join.
    Unmanaged = 3,
}

impl RecordMode {
    /// The mode of a Mode field on the wire: `Sealed`, `Bound` or
    /// `Trusted`; any other value, `Unmanaged`'s included, is `bad_flags`.
    pub fn from_byte(byte: u8) -> Result<RecordMode, Error> {
        match byte {
            0 => Ok(RecordMode::Sealed),
            1 => Ok(RecordMode::Bound),
            2 => Ok(RecordMode::Trusted),
            _ => Err(Error::BadFlags),
        }
    }

    /// The value of the Mode field. `Unmanaged` has none that a peer
    /// accepts: its 3 is the reserved value [`Self::from_byte`] refuses;
    /// a configuration that chooses it for a join is refused before
    /// anything is sent.
    #[must_use]
    pub fn byte(self) -> u8 {
        self as u8
    }

    /// Whether a pipe may be joined in this mode: every mode but
    /// `Unmanaged`.
    #[must_use]
    pub fn joinable(self) -> bool {
        self != RecordMode::Unmanaged
    }
}

/// Appends the shortest varint.
pub fn put_varint(out: &mut Vec<u8>, value: u64) {
    let mut buf = [0; 8];
    let len = varint::encode(value, &mut buf).expect("value within the varint range");
    out.extend_from_slice(&buf[..len]);
}

/// Reads a varint: value, length, whether it is shortest. `None` when the input
/// ends inside it.
#[must_use]
pub fn read_shortest(input: &[u8]) -> Option<(u64, usize, bool)> {
    let (value, len) = varint::decode(input)?;
    let mut buf = [0; 8];
    let shortest = varint::encode(value, &mut buf).ok()? == len;
    Some((value, len, shortest))
}

/// What the first bytes of a carrier begin.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Dispatch {
    /// An Establish Hello; its parser may still find an unknown Profile.
    Establish,
    /// A Join Hello.
    Join,
    /// A reserved Profile, treated as unknown.
    Reserved,
    /// A zmux first record.
    Record,
    /// Neither.
    Other,
    /// More bytes are needed.
    Incomplete {
        /// The total length needed.
        need: usize,
    },
}

/// Classifies the first bytes of a carrier.
#[must_use]
pub fn dispatch(framing: Framing, bytes: &[u8]) -> Dispatch {
    match bytes.first() {
        None if framing == Framing::ByteStream => Dispatch::Incomplete { need: 1 },
        None => Dispatch::Other,
        Some(1 | 3 | 4 | 5 | 8) => Dispatch::Establish,
        Some(2) => Dispatch::Join,
        Some(6 | 7) => Dispatch::Reserved,
        Some(_) => match classify_first_bytes(bytes, framing) {
            FirstBytes::Record => Dispatch::Record,
            FirstBytes::NeedMore(need) => Dispatch::Incomplete { need },
            FirstBytes::Other => Dispatch::Other,
        },
    }
}
