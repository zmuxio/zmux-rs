//! Small primitives of the exchange carrier: hex encoding, and zmux's
//! HMAC-SHA256 and random `u64`.

pub(crate) use zmux::adapter::{HmacSha256, random_u64};

/// `bytes` in lowercase hex.
pub(crate) fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(char::from(DIGITS[usize::from(b >> 4)]));
        s.push(char::from(DIGITS[usize::from(b & 0x0f)]));
    }
    s
}
