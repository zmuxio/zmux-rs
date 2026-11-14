//! Small primitives zmux uses: HMAC-SHA256 with a prepared key and a
//! random `u64`.

use std::time::Duration;

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

/// `secs` seconds as a [`Duration`], saturating: a negative or NaN value is
/// zero, one beyond the range of `Duration` is `Duration::MAX`. The
/// panic-free form of `Duration::from_secs_f64` for computed inputs.
pub(crate) fn saturating_secs(secs: f64) -> Duration {
    if secs.is_nan() || secs <= 0.0 {
        return Duration::ZERO;
    }
    Duration::try_from_secs_f64(secs).unwrap_or(Duration::MAX)
}

/// The time `bytes` take at `rate` bytes per second (a rate of 0 counts
/// as 1), saturating at `Duration::MAX`.
pub(crate) fn drain_time(bytes: u64, rate: u64) -> Duration {
    saturating_secs(f64_of(bytes) / f64_of(rate.max(1)))
}

/// A random `u64` from the system's source; should that fail, from a
/// process-local randomly seeded one.
pub(crate) fn random_u64() -> u64 {
    getrandom::u64().unwrap_or_else(|_| {
        use std::hash::BuildHasher;
        std::collections::hash_map::RandomState::new().hash_one(0x5a4d_u64)
    })
}

/// `v` as a `usize`, saturating at `usize::MAX` on targets where `usize` is
/// narrower than 64 bits; the identity (no code) on 64-bit targets. For
/// counts and lengths that index or size memory, where a value beyond the
/// address space can only mean "more than fits".
#[inline]
pub(crate) fn usize_sat(v: u64) -> usize {
    usize::try_from(v).unwrap_or(usize::MAX)
}

/// `v` as an `f64`, rounded to the nearest representable value. For rates,
/// ratios and estimates, where 53 bits of mantissa are more precision than
/// the inputs carry.
#[inline]
#[allow(
    clippy::cast_precision_loss,
    reason = "estimates only; values above 2^53 round to the nearest f64"
)]
pub(crate) fn f64_of(v: u64) -> f64 {
    v as f64
}

/// `v` as a `u64`, truncated toward zero and saturating: a negative or NaN
/// value is 0, one at or above 2^64 is `u64::MAX`. The clamp an estimate
/// converted back to bytes or nanoseconds wants.
#[inline]
#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "`as` from f64 saturates and maps NaN to 0, which is the intended clamp"
)]
pub(crate) fn u64_sat(v: f64) -> u64 {
    v as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations_from_computed_seconds_saturate() {
        assert_eq!(saturating_secs(f64::NAN), Duration::ZERO);
        assert_eq!(saturating_secs(-1.0), Duration::ZERO);
        assert_eq!(saturating_secs(f64::INFINITY), Duration::MAX);
        assert_eq!(saturating_secs(1e300), Duration::MAX);
        assert_eq!(saturating_secs(1.5), Duration::from_millis(1500));
        assert_eq!(drain_time(100, 0), Duration::from_secs(100));
        assert!(drain_time(u64::MAX, 1) > Duration::from_secs(1 << 40));
    }
}
