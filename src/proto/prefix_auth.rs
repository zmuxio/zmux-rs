//! Prefix authentication tokens: an admission
//! function under which a carrier starts with a token both ends compute
//! from a pre-shared key. A token is a random Nonce and a MAC over the
//! sender's time slot, an optional binding to the carrier's TLS handshake
//! and the Nonce:
//!
//! ```text
//! Kp   = HMAC-SHA256(PSK, "zmux-prefix-auth/1")
//! Tag  = HMAC-SHA256(Kp, Slot (64) || Binding Length (8) || Binding || Nonce)[..16]
//! Token = Nonce (128) || Tag (128)
//! ```
//!
//! A carrier decided on its HTTP request head carries the token in a
//! request header field instead, in base64url without padding.
//!
//! [`PrefixAuth`] makes tokens, and is a client's [`Credential`];
//! [`PrefixAuthVerifier`] checks them within a number of slots of its own
//! clock and accepts each Nonce once.

use std::io;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use super::admission::{CarrierInfo, Credential, Verdict};
use super::oob;
use super::replay::{ReplayFilter, ReplayVerdict};
use crate::util::HmacSha256;

/// The length of a token: the admission's prefix length.
pub const PREFIX_TOKEN_LEN: usize = NONCE_LEN + TAG_LEN;
/// The TLS exporter label of a token's binding (32 bytes, empty context).
pub const PREFIX_AUTH_EXPORTER_LABEL: &str = "EXPORTER-zmux-prefix-auth";
/// The length of a binding.
pub const PREFIX_AUTH_BINDING_LEN: usize = 32;
/// The request header field of the header form, unless both ends agree on
/// another ([`PrefixAuth::with_header`]).
pub const PREFIX_AUTH_HEADER: &str = "Zmux-Prefix-Auth";
/// The length of a token in the header form: 32 bytes in base64url
/// without padding.
const HEADER_VALUE_LEN: usize = oob::encoded_len(PREFIX_TOKEN_LEN);

const NONCE_LEN: usize = 16;
const TAG_LEN: usize = 16;
const KEY_LABEL: &[u8] = b"zmux-prefix-auth/1";

/// A [`PrefixAuth`] that cannot be made: an empty key, or a slot length
/// that is not a positive whole number of seconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidPrefixAuth;

impl std::fmt::Display for InvalidPrefixAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("prefix auth needs a non-empty key and a slot of whole seconds")
    }
}

impl std::error::Error for InvalidPrefixAuth {}

/// The parameters both ends of prefix authentication share: the key, the
/// slot length, whether tokens are bound to the carrier's TLS
/// handshake, and the request header field of
/// the header form. Makes tokens; as a [`Credential`], a fresh one for
/// each carrier. Cheap to clone.
#[derive(Clone)]
pub struct PrefixAuth {
    kp: HmacSha256,
    slot: u64,
    bind_tls: bool,
    header: Arc<str>,
}

impl std::fmt::Debug for PrefixAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PrefixAuth")
            .field("slot", &self.slot)
            .field("bind_tls", &self.bind_tls)
            .field("header", &self.header)
            .finish_non_exhaustive()
    }
}

impl PrefixAuth {
    /// Tokens under the pre-shared key `psk` (non-empty) and slots of
    /// `slot` (a positive whole number of seconds); `bind_tls` binds them
    /// to the carrier's TLS handshake. The header form uses
    /// [`PREFIX_AUTH_HEADER`].
    pub fn new(psk: &[u8], slot: Duration, bind_tls: bool) -> Result<Self, InvalidPrefixAuth> {
        if psk.is_empty() || slot.subsec_nanos() != 0 || slot.as_secs() == 0 {
            return Err(InvalidPrefixAuth);
        }
        let kp = HmacSha256::new(psk).mac(&[KEY_LABEL]);
        Ok(Self {
            kp: HmacSha256::new(&kp),
            slot: slot.as_secs(),
            bind_tls,
            header: PREFIX_AUTH_HEADER.into(),
        })
    }

    /// With this request header field for the header form instead of
    /// [`PREFIX_AUTH_HEADER`], where an intermediary strips unknown fields:
    /// a local agreement of both ends. Compared without regard to case.
    #[must_use]
    pub fn with_header(mut self, name: impl Into<String>) -> Self {
        self.header = name.into().into();
        self
    }

    /// Whether tokens are bound to the carrier's TLS handshake.
    pub fn binds_tls(&self) -> bool {
        self.bind_tls
    }

    /// The request header field of the header form.
    pub fn header_name(&self) -> &str {
        &self.header
    }

    /// The binding of a carrier with metadata `info`: its exporter's value
    /// when tokens are bound, else `None`; an error when they are bound
    /// and `info` has no exporter.
    pub fn binding(
        &self,
        info: &CarrierInfo<'_>,
    ) -> io::Result<Option<[u8; PREFIX_AUTH_BINDING_LEN]>> {
        if !self.bind_tls {
            return Ok(None);
        }
        let b = info
            .export(
                PREFIX_AUTH_EXPORTER_LABEL.as_bytes(),
                &[],
                PREFIX_AUTH_BINDING_LEN,
            )
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "bound prefix authentication needs the carrier's TLS exporter",
                )
            })?;
        let mut a = [0u8; PREFIX_AUTH_BINDING_LEN];
        a.copy_from_slice(&b);
        Ok(Some(a))
    }

    /// A token for the current slot of the system clock and a fresh Nonce.
    /// `binding` is the carrier's binding ([`PREFIX_AUTH_EXPORTER_LABEL`])
    /// when tokens are bound, else `None`. Fails only when the system's
    /// random source does.
    pub fn token(
        &self,
        binding: Option<&[u8; PREFIX_AUTH_BINDING_LEN]>,
    ) -> io::Result<[u8; PREFIX_TOKEN_LEN]> {
        let mut nonce = [0u8; NONCE_LEN];
        getrandom::fill(&mut nonce).map_err(io::Error::other)?;
        Ok(self.token_at(binding, unix_now(), nonce))
    }

    /// `token` in the header form: base64url without padding, 43
    /// characters.
    pub fn header_value(token: &[u8; PREFIX_TOKEN_LEN]) -> String {
        oob::encode_string(token)
    }

    /// The token for time `unix` (seconds since the epoch) and `nonce`.
    pub fn token_at(
        &self,
        binding: Option<&[u8; PREFIX_AUTH_BINDING_LEN]>,
        unix: u64,
        nonce: [u8; NONCE_LEN],
    ) -> [u8; PREFIX_TOKEN_LEN] {
        let mut t = [0u8; PREFIX_TOKEN_LEN];
        t[..NONCE_LEN].copy_from_slice(&nonce);
        let binding = binding.map_or(&[][..], |b| &b[..]);
        let hdr = slot_header(unix / self.slot, binding.len());
        let tag = self.kp.mac(&[&hdr, binding, &nonce]);
        t[NONCE_LEN..].copy_from_slice(&tag[..TAG_LEN]);
        t
    }
}

/// Verifies tokens: their tag for a slot within `skew` slots of the
/// verifier's clock, compared in constant time, and a Nonce not seen
/// before. Safe for concurrent use.
pub struct PrefixAuthVerifier {
    auth: PrefixAuth,
    skew: u64,
    record: Option<ReplayFilter>,
}

impl std::fmt::Debug for PrefixAuthVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PrefixAuthVerifier")
            .field("auth", &self.auth)
            .field("skew", &self.skew)
            .finish_non_exhaustive()
    }
}

impl PrefixAuthVerifier {
    /// A verifier of `auth`'s tokens that accepts the slots within `skew`
    /// of its current one and records at most `max_nonces` Nonces; a token
    /// that finds the record full is not accepted.
    pub fn new(auth: PrefixAuth, skew: u32, max_nonces: usize) -> Self {
        let skew = u64::from(skew);
        let slot = auth.slot;
        Self {
            auth,
            skew,
            record: ReplayFilter::new(
                Duration::from_secs((skew + 1).saturating_mul(slot)),
                max_nonces,
            )
            .ok(),
        }
    }

    /// The parameters it verifies.
    pub fn auth(&self) -> &PrefixAuth {
        &self.auth
    }

    /// Whether `token` is valid for `binding` at the system clock and its
    /// Nonce is new; records the Nonce when it is.
    pub fn verify(&self, token: &[u8], binding: Option<&[u8; PREFIX_AUTH_BINDING_LEN]>) -> bool {
        self.verify_at(token, binding, unix_now())
    }

    /// [`PrefixAuthVerifier::verify`] at time `unix` (seconds since the
    /// epoch).
    pub fn verify_at(
        &self,
        token: &[u8],
        binding: Option<&[u8; PREFIX_AUTH_BINDING_LEN]>,
        unix: u64,
    ) -> bool {
        if token.len() != PREFIX_TOKEN_LEN {
            return false;
        }
        let (nonce, tag) = token.split_at(NONCE_LEN);
        let binding = binding.map_or(&[][..], |b| &b[..]);
        let cur = unix / self.auth.slot;
        let low = cur.saturating_sub(self.skew);
        let Some(slot) = (low..=cur.saturating_add(self.skew)).find(|&s| {
            let hdr = slot_header(s, binding.len());
            self.auth.kp.verify(&[&hdr, binding, nonce], tag)
        }) else {
            return false;
        };
        let ms = |secs: u64| i64::try_from(secs.saturating_mul(1000)).unwrap_or(i64::MAX);
        // A slot stands for its start: within (skew + 1) slots of the clock.
        self.record.as_ref().is_some_and(|r| {
            r.check_at(nonce, ms(slot.saturating_mul(self.auth.slot)), ms(unix))
                == ReplayVerdict::Fresh
        })
    }

    /// An admission decision: [`Verdict::Accept`] of the token when it
    /// verifies, with the binding of `info`'s exporter when tokens are
    /// bound, and [`Verdict::Fallback`] for every other outcome. The token
    /// is the prefix ([`PREFIX_TOKEN_LEN`] bytes, accepted with them), or,
    /// on a carrier decided on its request head ([`CarrierInfo::head`]),
    /// the one value of the request header field
    /// ([`PrefixAuth::header_name`]), 43 base64url characters (accepted with
    /// no prefix): a missing, repeated or malformed field fails like a
    /// wrong token.
    pub fn decide(&self, info: &CarrierInfo<'_>, prefix: &[u8]) -> Verdict {
        let header;
        let (token, accept) = if info.head {
            let Some(t) = self.header_token(info) else {
                return Verdict::Fallback;
            };
            header = t;
            (&header[..], 0)
        } else {
            (prefix, PREFIX_TOKEN_LEN)
        };
        let Ok(binding) = self.auth.binding(info) else {
            return Verdict::Fallback;
        };
        if self.verify(token, binding.as_ref()) {
            Verdict::accept(accept)
        } else {
            Verdict::Fallback
        }
    }

    /// The token of the header form: the field's one value, decoded.
    fn header_token(&self, info: &CarrierInfo<'_>) -> Option<[u8; PREFIX_TOKEN_LEN]> {
        let mut value = None;
        let mut fields = 0usize;
        info.for_each_header(|name, v| {
            if name.eq_ignore_ascii_case(&self.auth.header) {
                fields += 1;
                value = Some(v.to_vec());
            }
        });
        let value = value.filter(|v| fields == 1 && v.len() == HEADER_VALUE_LEN)?;
        let mut token = [0u8; PREFIX_TOKEN_LEN];
        match oob::decode(&value, &mut token) {
            Ok(PREFIX_TOKEN_LEN) => Some(token),
            _ => None,
        }
    }
}

impl Credential for PrefixAuth {
    /// A fresh token, bound to the carrier when tokens are bound.
    fn prefix(&self, info: &CarrierInfo<'_>) -> io::Result<Vec<u8>> {
        Ok(self.token(self.binding(info)?.as_ref())?.to_vec())
    }

    /// A fresh token in the header form: [`PrefixAuth::header_name`] and the
    /// token in base64url without padding.
    fn header(&self, info: &CarrierInfo<'_>) -> io::Result<(String, String)> {
        let token = self.token(self.binding(info)?.as_ref())?;
        Ok((self.header.to_string(), Self::header_value(&token)))
    }
}

/// Slot (64) || Binding Length (8).
fn slot_header(slot: u64, binding_len: usize) -> [u8; 9] {
    let mut h = [0u8; 9];
    h[..8].copy_from_slice(&slot.to_be_bytes());
    // A binding is PREFIX_AUTH_BINDING_LEN bytes or empty.
    h[8] = binding_len as u8;
    h
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    const T: u64 = 1_767_225_600;
    const NONCE: [u8; 16] = [
        0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae,
        0xaf,
    ];

    fn binding() -> [u8; 32] {
        std::array::from_fn(|i| i as u8)
    }

    #[test]
    fn spec_vectors() {
        let psk = [0x6b; 32];
        assert_eq!(
            HmacSha256::new(&psk).mac(&[KEY_LABEL]).to_vec(),
            unhex("2eaed9a5e8ca0729884488be9c349871b69823f01876ad48062a8b15c6c1839c")
        );
        let a = PrefixAuth::new(&psk, Duration::from_secs(30), false).unwrap();
        assert_eq!(T / 30, 58_907_520);
        assert_eq!(
            a.token_at(None, T, NONCE).to_vec(),
            unhex("a0a1a2a3a4a5a6a7a8a9aaabacadaeaf3fed5e50dc8fc8fce2e962ddb13dbfae")
        );
        assert_eq!(
            a.token_at(Some(&binding()), T, NONCE).to_vec(),
            unhex("a0a1a2a3a4a5a6a7a8a9aaabacadaeaf36747d163099e42de649d7159d462334")
        );
    }

    #[test]
    fn verifies_within_skew_once() {
        let a = PrefixAuth::new(b"k", Duration::from_secs(30), false).unwrap();
        let v = PrefixAuthVerifier::new(a.clone(), 1, 16);
        let tok = a.token_at(None, T, NONCE);
        assert!(!v.verify_at(&tok, None, T + 60), "two slots later");
        assert!(v.verify_at(&tok, None, T + 30));
        assert!(!v.verify_at(&tok, None, T + 30), "Nonce used");
        let bound = a.token_at(Some(&binding()), T, [1; 16]);
        assert!(!v.verify_at(&bound, None, T), "binding differs");
        assert!(v.verify_at(&bound, Some(&binding()), T));
        let mut bad = a.token_at(None, T, [2; 16]);
        bad[31] ^= 1;
        assert!(!v.verify_at(&bad, None, T));
        assert!(!v.verify_at(&bad[..31], None, T));
    }

    #[test]
    fn full_record_refuses_until_its_slots_expire() {
        let a = PrefixAuth::new(b"k", Duration::from_secs(1), false).unwrap();
        let v = PrefixAuthVerifier::new(a.clone(), 0, 2);
        assert!(v.verify_at(&a.token_at(None, 10, [1; 16]), None, 10));
        assert!(v.verify_at(&a.token_at(None, 10, [2; 16]), None, 10));
        assert!(
            !v.verify_at(&a.token_at(None, 10, [3; 16]), None, 10),
            "full"
        );
        assert!(
            v.verify_at(&a.token_at(None, 12, [3; 16]), None, 12),
            "slot 10 dropped"
        );
    }

    #[test]
    fn header_vectors() {
        let a = PrefixAuth::new(&[0x6b; 32], Duration::from_secs(30), false).unwrap();
        assert_eq!(
            PrefixAuth::header_value(&a.token_at(None, T, NONCE)),
            "oKGio6SlpqeoqaqrrK2urz_tXlDcj8j84uli3bE9v64"
        );
        assert_eq!(
            PrefixAuth::header_value(&a.token_at(Some(&binding()), T, NONCE)),
            "oKGio6SlpqeoqaqrrK2urzZ0fRYwmeQt5knXFZ1GIzQ"
        );
    }

    fn upgrade<'a>(fields: &'a [(&'a str, &'a str)]) -> CarrierInfo<'a> {
        CarrierInfo::new()
            .with_head()
            .with_headers(|| fields.iter().map(|(n, v)| (*n, v.as_bytes())))
    }

    /// The header form of the test vectors verifies at their time,
    /// once, by the configured field; missing, repeated and malformed
    /// fields fail.
    #[test]
    fn header_form_decides() {
        let a = PrefixAuth::new(&[0x6b; 32], Duration::from_secs(30), false).unwrap();
        let v = PrefixAuthVerifier::new(a.clone(), 1, 16);
        let tok = a.token_at(None, unix_now(), NONCE);
        let val = PrefixAuth::header_value(&tok);
        let ok = [("zmux-prefix-auth", val.as_str())];
        assert_eq!(v.decide(&upgrade(&ok), &[]), Verdict::accept(0));
        assert_eq!(
            v.decide(&upgrade(&ok), &[]),
            Verdict::Fallback,
            "Nonce used"
        );
        // The token as a prefix is not looked at on an upgrade.
        assert_eq!(v.decide(&upgrade(&[]), &tok), Verdict::Fallback);
        let tok = a.token_at(None, unix_now(), [7; 16]);
        let val = PrefixAuth::header_value(&tok);
        let twice = [
            (PREFIX_AUTH_HEADER, val.as_str()),
            (PREFIX_AUTH_HEADER, val.as_str()),
        ];
        assert_eq!(v.decide(&upgrade(&twice), &[]), Verdict::Fallback);
        let (padded, plus) = (format!("{val}="), format!("+{}", &val[1..]));
        for bad in [&val[..42], padded.as_str(), plus.as_str()] {
            let f = [(PREFIX_AUTH_HEADER, bad)];
            assert_eq!(v.decide(&upgrade(&f), &[]), Verdict::Fallback, "{bad}");
        }
        let other = PrefixAuthVerifier::new(a.clone().with_header("X-Auth"), 1, 16);
        assert_eq!(
            v.decide(&upgrade(&[("x-auth", val.as_str())]), &[]),
            Verdict::Fallback
        );
        assert_eq!(
            other.decide(&upgrade(&[("x-auth", val.as_str())]), &[]),
            Verdict::accept(0)
        );

        let bound = PrefixAuth::new(&[0x6b; 32], Duration::from_secs(30), true).unwrap();
        let v = PrefixAuthVerifier::new(bound.clone(), 1, 16);
        let exported = |_: &[u8], _: &[u8], out: &mut [u8]| {
            out.copy_from_slice(&binding());
            true
        };
        let info = CarrierInfo::new().with_exporter(exported);
        let (name, value) = bound.header(&info).unwrap();
        assert_eq!(name, PREFIX_AUTH_HEADER);
        let f = [(PREFIX_AUTH_HEADER, value.as_str())];
        assert_eq!(
            v.decide(&upgrade(&f), &[]),
            Verdict::Fallback,
            "no exporter"
        );
        let info = upgrade(&f).with_exporter(exported);
        assert_eq!(v.decide(&info, &[]), Verdict::accept(0));
        assert!(
            bound.prefix(&CarrierInfo::new()).is_err(),
            "bound needs an exporter"
        );
    }

    #[test]
    fn invalid_parameters() {
        assert!(PrefixAuth::new(b"", Duration::from_secs(1), false).is_err());
        assert!(PrefixAuth::new(b"k", Duration::from_millis(1500), false).is_err());
        assert!(PrefixAuth::new(b"k", Duration::ZERO, false).is_err());
    }
}
