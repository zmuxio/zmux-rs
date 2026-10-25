//! QUIC variable-length integers (RFC 9000 Section 16).
//!
//! The two most significant bits of the first byte give the encoded width
//! (1, 2, 4 or 8 bytes); the remaining bits hold the value in network byte
//! order. Values may be encoded in more bytes than necessary everywhere
//! except in frame types (SPEC.md Section 4.1 rule 2), so decoders report the
//! width they saw.

use std::fmt;

use super::error::EncodeError;

/// The largest value a variable-length integer can hold, 2^62 - 1.
pub const MAX: u64 = (1 << 62) - 1;

/// Returns the length of the shortest encoding of `value`.
///
/// Values above [`MAX`] report 8; encoding them fails.
#[inline]
pub const fn len(value: u64) -> usize {
    if value < 1 << 6 {
        1
    } else if value < 1 << 14 {
        2
    } else if value < 1 << 30 {
        4
    } else {
        8
    }
}

/// Returns the encoded width announced by the first byte of a varint.
#[inline]
pub const fn width(first: u8) -> usize {
    1 << (first >> 6)
}

/// Decodes a varint from the start of `buf`.
///
/// Returns the value and the number of bytes it occupied, or `None` when
/// `buf` ends before the varint does.
#[inline]
pub fn decode(buf: &[u8]) -> Option<(u64, usize)> {
    let &first = buf.first()?;
    match first >> 6 {
        0 => Some((u64::from(first), 1)),
        1 => {
            let b = buf.first_chunk::<2>()?;
            Some((u64::from(u16::from_be_bytes(*b) & 0x3fff), 2))
        }
        2 => {
            let b = buf.first_chunk::<4>()?;
            Some((u64::from(u32::from_be_bytes(*b) & 0x3fff_ffff), 4))
        }
        _ => {
            let b = buf.first_chunk::<8>()?;
            Some((u64::from_be_bytes(*b) & MAX, 8))
        }
    }
}

/// Writes the shortest encoding of `value` to the start of `buf`.
///
/// Returns the number of bytes written.
#[inline]
pub fn encode(value: u64, buf: &mut [u8]) -> Result<usize, EncodeError> {
    if value < 1 << 6 {
        *buf.first_mut().ok_or(EncodeError::BufferTooShort)? = value as u8;
        Ok(1)
    } else if value < 1 << 14 {
        *buf.first_chunk_mut::<2>()
            .ok_or(EncodeError::BufferTooShort)? = (value as u16 | 0x4000).to_be_bytes();
        Ok(2)
    } else if value < 1 << 30 {
        *buf.first_chunk_mut::<4>()
            .ok_or(EncodeError::BufferTooShort)? = (value as u32 | 0x8000_0000).to_be_bytes();
        Ok(4)
    } else if value <= MAX {
        *buf.first_chunk_mut::<8>()
            .ok_or(EncodeError::BufferTooShort)? = (value | 0xc000_0000_0000_0000).to_be_bytes();
        Ok(8)
    } else {
        Err(EncodeError::ValueOutOfRange)
    }
}

/// Writes `value` in exactly `width` bytes, which may be more than the
/// shortest encoding (for example to reserve room for a record Size).
///
/// `width` must be 1, 2, 4 or 8 and at least [`len`]`(value)`.
pub fn encode_with_width(value: u64, width: usize, buf: &mut [u8]) -> Result<usize, EncodeError> {
    if value > MAX || width < len(value) {
        return Err(EncodeError::ValueOutOfRange);
    }
    let dst = buf.get_mut(..width).ok_or(EncodeError::BufferTooShort)?;
    let prefix: u8 = match width {
        1 => 0x00,
        2 => 0x40,
        4 => 0x80,
        8 => 0xc0,
        _ => return Err(EncodeError::ValueOutOfRange),
    };
    let be = value.to_be_bytes();
    dst.copy_from_slice(&be[8 - width..]);
    dst[0] |= prefix;
    Ok(width)
}

/// A value that fits in a variable-length integer (0 to 2^62 - 1).
#[derive(Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct VarInt(u64);

impl VarInt {
    /// The largest representable value.
    pub const MAX: Self = Self(MAX);
    /// Zero.
    pub const ZERO: Self = Self(0);

    /// Creates a `VarInt` from a `u32`, which always fits.
    #[inline]
    pub const fn from_u32(value: u32) -> Self {
        Self(value as u64)
    }

    /// Creates a `VarInt` if `value` fits.
    #[inline]
    pub const fn from_u64(value: u64) -> Result<Self, VarIntBoundsExceeded> {
        if value <= MAX {
            Ok(Self(value))
        } else {
            Err(VarIntBoundsExceeded)
        }
    }

    /// Returns the value.
    #[inline]
    pub const fn into_inner(self) -> u64 {
        self.0
    }

    /// Returns the length of the shortest encoding.
    #[inline]
    pub const fn size(self) -> usize {
        len(self.0)
    }
}

impl fmt::Debug for VarInt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl fmt::Display for VarInt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl From<u8> for VarInt {
    fn from(value: u8) -> Self {
        Self(value.into())
    }
}

impl From<u16> for VarInt {
    fn from(value: u16) -> Self {
        Self(value.into())
    }
}

impl From<u32> for VarInt {
    fn from(value: u32) -> Self {
        Self(value.into())
    }
}

impl TryFrom<u64> for VarInt {
    type Error = VarIntBoundsExceeded;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        Self::from_u64(value)
    }
}

impl From<VarInt> for u64 {
    fn from(value: VarInt) -> Self {
        value.0
    }
}

/// A value did not fit in a variable-length integer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VarIntBoundsExceeded;

impl fmt::Display for VarIntBoundsExceeded {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("value exceeds 2^62 - 1")
    }
}

impl std::error::Error for VarIntBoundsExceeded {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc9000_sample_encodings() {
        // RFC 9000 Appendix A.1.
        let cases: [(&[u8], u64); 5] = [
            (
                &[0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c],
                151_288_809_941_952_652,
            ),
            (&[0x9d, 0x7f, 0x3e, 0x7d], 494_878_333),
            (&[0x7b, 0xbd], 15_293),
            (&[0x25], 37),
            (&[0x40, 0x25], 37),
        ];
        for (bytes, value) in cases {
            assert_eq!(decode(bytes), Some((value, bytes.len())));
        }
    }

    #[test]
    fn boundaries_round_trip() {
        for v in [0, 63, 64, 16_383, 16_384, (1 << 30) - 1, 1 << 30, MAX] {
            let mut buf = [0u8; 8];
            let n = encode(v, &mut buf).unwrap();
            assert_eq!(n, len(v));
            assert_eq!(decode(&buf[..n]), Some((v, n)));
            assert_eq!(decode(&buf[..n - 1]), None);
        }
        assert_eq!(
            encode(MAX + 1, &mut [0u8; 8]),
            Err(EncodeError::ValueOutOfRange)
        );
        assert_eq!(encode(64, &mut [0u8; 1]), Err(EncodeError::BufferTooShort));
    }

    #[test]
    fn explicit_width() {
        let mut buf = [0u8; 8];
        assert_eq!(encode_with_width(37, 2, &mut buf), Ok(2));
        assert_eq!(&buf[..2], &[0x40, 0x25]);
        assert_eq!(
            encode_with_width(16_384, 2, &mut buf),
            Err(EncodeError::ValueOutOfRange)
        );
        assert_eq!(
            encode_with_width(1, 3, &mut buf),
            Err(EncodeError::ValueOutOfRange)
        );
    }
}
