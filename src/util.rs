//! Small primitives zmux uses: HMAC-SHA256 with a prepared key and a
//! random `u64`.

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

/// HMAC-SHA256 under one key, prepared once: each MAC starts from the
/// keyed state. Cheap to clone.
#[derive(Clone)]
pub(crate) struct HmacSha256(Hmac<Sha256>);

impl std::fmt::Debug for HmacSha256 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("HmacSha256(..)")
    }
}

impl HmacSha256 {
    /// The key `key` (any length).
    pub(crate) fn new(key: &[u8]) -> Self {
        Self(Hmac::new_from_slice(key).expect("HMAC takes any key length"))
    }

    fn update(&self, parts: &[&[u8]]) -> Hmac<Sha256> {
        let mut mac = self.0.clone();
        for p in parts {
            mac.update(p);
        }
        mac
    }

    /// The MAC of the concatenation of `parts`.
    pub(crate) fn mac(&self, parts: &[&[u8]]) -> [u8; 32] {
        self.update(parts).finalize().into_bytes().into()
    }

    /// Whether `tag` is the MAC of the concatenation of `parts`, or its
    /// first `tag.len()` bytes (1 to 32), compared in constant time.
    pub(crate) fn verify(&self, parts: &[&[u8]], tag: &[u8]) -> bool {
        self.update(parts).verify_truncated_left(tag).is_ok()
    }
}

/// A random `u64` from the system's source; should that fail, from a
/// process-local randomly seeded one.
pub(crate) fn random_u64() -> u64 {
    getrandom::u64().unwrap_or_else(|_| {
        use std::hash::BuildHasher;
        std::collections::hash_map::RandomState::new().hash_one(0x5a4d_u64)
    })
}
