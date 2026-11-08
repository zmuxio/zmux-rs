//! Framing, Mode, varints and dispatch.

use super::Error;
use crate::proto::ident::{FirstBytes, classify_first_bytes};
use crate::proto::record::Framing;
use crate::proto::varint;

/// Frames one unit: a 16-bit length on a byte stream, nothing on a message
/// carrier.
pub fn frame(framing: Framing, out: &mut Vec<u8>, unit: &[u8]) -> Result<(), Error> {
    let len = u16::try_from(unit.len()).map_err(|_| Error::TooLarge)?;
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

/// Cuts one unit from the start of `input`: a framed unit on a byte stream, the
/// whole message on a message carrier. Returns the unit and the bytes consumed.
pub fn cut_unit(framing: Framing, input: &[u8]) -> Result<(&[u8], usize), Error> {
    if framing == Framing::ByteStream {
        return cut_frame(input, 0);
    }
    if input.len() > u16::MAX as usize {
        return Err(Error::TooLarge);
    }
    Ok((input, input.len()))
}

/// The record mode of a carrier.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Mode {
    /// Records are protected.
    Sealed = 0,
    /// Raw records on a carrier whose exporter is bound in.
    Bound = 1,
    /// Raw records by explicit configuration of both ends.
    Trusted = 2,
}

impl Mode {
    /// The Mode of a wire byte; any other value is `bad_flags`.
    pub fn from_byte(byte: u8) -> Result<Mode, Error> {
        match byte {
            0 => Ok(Mode::Sealed),
            1 => Ok(Mode::Bound),
            2 => Ok(Mode::Trusted),
            _ => Err(Error::BadFlags),
        }
    }

    /// The wire byte.
    pub fn byte(self) -> u8 {
        self as u8
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
            _ => Dispatch::Other,
        },
    }
}
