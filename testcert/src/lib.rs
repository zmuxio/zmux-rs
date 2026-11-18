//! Self-signed certificates for tests, benchmarks and scripted peers; never
//! for production.
//!
//! The one place that decides how a test certificate is valid: from one hour
//! before it is made (a clock a little behind the machine's that made it, or a
//! verifier that reads the time a moment earlier, still accepts it) until 30
//! days after, so that a long-lived test artifact does not trust a
//! certificate forever.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rcgen::{CertificateParams, CertifiedKey, KeyPair};
use time::OffsetDateTime;

/// How long before it is made a certificate is already valid.
pub const VALID_BEFORE: Duration = Duration::from_hours(1);

/// How long after it is made a certificate stays valid.
pub const VALID_AFTER: Duration = Duration::from_hours(30 * 24);

fn at(t: SystemTime) -> OffsetDateTime {
    let secs = match t.duration_since(UNIX_EPOCH) {
        Ok(d) => i64::try_from(d.as_secs()).unwrap_or(i64::MAX),
        Err(e) => -i64::try_from(e.duration().as_secs()).unwrap_or(i64::MAX),
    };
    OffsetDateTime::from_unix_timestamp(secs).expect("a time within the supported range")
}

/// A new key pair and a certificate for `names` signed by it, valid from
/// [`VALID_BEFORE`] ago for [`VALID_AFTER`]: the same as
/// `rcgen::generate_simple_self_signed` with a validity from the present.
///
/// # Errors
///
/// Whatever `rcgen` reports for the names or the key.
pub fn self_signed(names: impl Into<Vec<String>>) -> Result<CertifiedKey<KeyPair>, rcgen::Error> {
    let params = params_at(names.into(), SystemTime::now())?;
    let signing_key = KeyPair::generate()?;
    let cert = params.self_signed(&signing_key)?;
    Ok(CertifiedKey { cert, signing_key })
}

/// The certificate parameters for `names` made at `now`.
fn params_at(names: Vec<String>, now: SystemTime) -> Result<CertificateParams, rcgen::Error> {
    let mut params = CertificateParams::new(names)?;
    params.not_before = at(now - VALID_BEFORE);
    params.not_after = at(now + VALID_AFTER);
    Ok(params)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validity_starts_an_hour_before_and_ends_30_days_after() {
        let now = UNIX_EPOCH + Duration::from_hours(24 * 365);
        let p = params_at(vec!["localhost".to_owned()], now).unwrap();
        assert_eq!(p.not_before, at(now - Duration::from_hours(1)));
        assert_eq!(p.not_after, at(now + Duration::from_hours(24 * 30)));
        // The certificate itself is made.
        self_signed(vec!["localhost".to_owned()]).unwrap();
    }
}
