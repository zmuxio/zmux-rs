//! Out-of-band join and pairing information on HTTP carriers (SPEC.md
//! Section 6.1.1, MULTIPATH.md Section 5.3): header names and the unpadded
//! base64url encoding (RFC 4648 Section 5) of their values.

use super::error::EncodeError;

/// Request header carrying a PIPE_JOIN frame.
pub const JOIN_HEADER: &str = "Zmux-Pipe-Join";
/// Request header carrying a split-bootstrap pairing token.
pub const PAIR_HEADER: &str = "Zmux-Pipe-Pair";
/// The longest `Zmux-Pipe-Join` value: 64 bytes of frame in base64url.
pub const MAX_JOIN_HEADER_LEN: usize = encoded_len(64);
/// Length of a pairing token.
pub const PAIRING_TOKEN_LEN: usize = 16;

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Length of the unpadded base64url encoding of `n` bytes.
pub const fn encoded_len(n: usize) -> usize {
    (n * 4).div_ceil(3)
}

/// Encodes `input` as unpadded base64url into `out`; returns the length.
pub fn encode(input: &[u8], out: &mut [u8]) -> Result<usize, EncodeError> {
    let len = encoded_len(input.len());
    let out = out.get_mut(..len).ok_or(EncodeError::BufferTooShort)?;
    let mut o = out.iter_mut();
    for chunk in input.chunks(3) {
        let b = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for i in 0..=chunk.len() {
            if let Some(slot) = o.next() {
                *slot = ALPHABET[((n >> (18 - 6 * i)) & 0x3f) as usize];
            }
        }
    }
    Ok(len)
}

/// The value is not canonical unpadded base64url.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidBase64;

impl std::fmt::Display for InvalidBase64 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("invalid base64url value")
    }
}

impl std::error::Error for InvalidBase64 {}

fn sextet(c: u8) -> Option<u32> {
    let v = match c {
        b'A'..=b'Z' => c - b'A',
        b'a'..=b'z' => c - b'a' + 26,
        b'0'..=b'9' => c - b'0' + 52,
        b'-' => 62,
        b'_' => 63,
        _ => return None,
    };
    Some(v.into())
}

/// Decodes unpadded base64url into `out`; returns the length. Padding,
/// other characters, an impossible length or non-zero trailing bits are
/// refused.
pub fn decode(input: &[u8], out: &mut [u8]) -> Result<usize, InvalidBase64> {
    if input.len() % 4 == 1 {
        return Err(InvalidBase64);
    }
    let len = input.len() * 3 / 4;
    let out = out.get_mut(..len).ok_or(InvalidBase64)?;
    let mut o = out.iter_mut();
    for chunk in input.chunks(4) {
        let mut n = 0u32;
        for (i, &c) in chunk.iter().enumerate() {
            n |= sextet(c).ok_or(InvalidBase64)? << (18 - 6 * i);
        }
        let k = chunk.len();
        if k < 4 {
            // The bits of the last sextet that carry no data must be zero.
            let unused = 8 - 2 * k as u32;
            let mask = ((1u32 << unused) - 1) << (24 - 6 * k as u32);
            if n & mask != 0 {
                return Err(InvalidBase64);
            }
        }
        let bytes = k - 1;
        for i in 0..bytes {
            if let Some(slot) = o.next() {
                *slot = (n >> (16 - 8 * i)) as u8;
            }
        }
    }
    Ok(len)
}

/// Encodes `input` in base64url without padding into a new string (for a
/// header value such as [`JOIN_HEADER`]).
pub fn encode_string(input: &[u8]) -> String {
    let mut out = vec![0u8; encoded_len(input.len())];
    let n = encode(input, &mut out).unwrap_or(0);
    out.truncate(n);
    String::from_utf8(out).unwrap_or_default()
}

/// Decodes a base64url value without padding into a new vector.
pub fn decode_vec(input: &[u8]) -> Result<Vec<u8>, InvalidBase64> {
    let mut out = vec![0u8; input.len() * 3 / 4 + 3];
    let n = decode(input, &mut out)?;
    out.truncate(n);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_and_strictness() {
        for n in 0..20usize {
            let data: Vec<u8> = (0..n as u8).map(|b| b.wrapping_mul(37)).collect();
            let mut enc = [0u8; 32];
            let e = encode(&data, &mut enc).unwrap();
            assert_eq!(e, encoded_len(n));
            let mut dec = [0u8; 32];
            let d = decode(&enc[..e], &mut dec).unwrap();
            assert_eq!(&dec[..d], &data[..]);
        }
        assert_eq!(decode(b"QQ==", &mut [0; 4]), Err(InvalidBase64));
        assert_eq!(decode(b"QR", &mut [0; 4]), Err(InvalidBase64));
        assert_eq!(decode(b"Q", &mut [0; 4]), Err(InvalidBase64));
        assert_eq!(decode(b"QQ", &mut [0; 4]), Ok(1));
        assert_eq!(MAX_JOIN_HEADER_LEN, 86);
    }
}
