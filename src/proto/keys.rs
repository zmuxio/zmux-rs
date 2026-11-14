//! The session secret of Join: the secret sources and the derivations before `join_psk`.

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// TLS exporter label of the session secret input.
pub const EXPORTER_SESSION_LABEL: &str = "EXPORTER-zmux-session";
/// Exporter label of the Binding of a Bound Join.
pub const EXPORTER_JOIN_LABEL: &str = "EXPORTER-zmux-join";
/// Prefix of the HKDF salt.
pub const SALT_PREFIX: &[u8] = b"zmux session";

/// The Secret Flags of `zmux_multipath`.
pub mod secret_flags {
    /// E: TLS exporter of the bootstrap carrier.
    pub const EXPORTER: u8 = 0x01;
    /// P: pre-shared key.
    pub const PSK: u8 = 0x04;
    /// Reserved bits: sent as 0, ignored on receipt.
    pub const RESERVED: u8 = !(EXPORTER | PSK);
}

/// The secret sources a session uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SecretSource {
    /// Whether the exporter value enters the secret.
    pub exporter: bool,
    /// Whether the PSK enters the secret.
    pub psk: bool,
}

/// What both endpoints' Secret Flags mean together. They state a choice and never
/// negotiate it: flags that differ end the session, so that an on-path party that
/// clears one cannot take that source out of the secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SecretFlags {
    /// A side has no source: multipath is not in use.
    NoSource,
    /// Both non-zero and different: a TRANSPORT_PARAMETER_ERROR.
    Differ,
    /// Equal flags select these sources.
    Selected(SecretSource),
}

/// Compares both endpoints' Secret Flags; reserved bits are ignored.
pub const fn select_secret_source(local: u8, peer: u8) -> SecretFlags {
    let (local, peer) = (
        local & !secret_flags::RESERVED,
        peer & !secret_flags::RESERVED,
    );
    if local == 0 || peer == 0 {
        SecretFlags::NoSource
    } else if local != peer {
        SecretFlags::Differ
    } else {
        SecretFlags::Selected(SecretSource {
            exporter: local & secret_flags::EXPORTER != 0,
            psk: local & secret_flags::PSK != 0,
        })
    }
}

/// The public binding value of a session: HKDF-Extract with SHA-256 of the
/// two Session Nonces under a fixed label.
pub fn session_binding(initiator: &[u8; 16], responder: &[u8; 16]) -> [u8; 32] {
    hmac(b"zmux session binding", &[initiator, responder])
}

fn hmac(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    // HMAC accepts keys of any length; the error branch is unreachable.
    let Ok(mut mac) = HmacSha256::new_from_slice(key) else {
        return [0; 32];
    };
    for p in parts {
        mac.update(p);
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&mac.finalize().into_bytes());
    out
}

/// HKDF-Extract with SHA-256 (RFC 5869 Section 2.2).
pub fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> [u8; 32] {
    hmac(salt, &[ikm])
}

/// HKDF-Expand with SHA-256 (RFC 5869 Section 2.3) into `out`. RFC 5869
/// allows at most 255 * 32 bytes; bytes of `out` beyond that are left
/// unwritten. zmux only derives 32-byte keys.
pub fn hkdf_expand(prk: &[u8], info: &[u8], out: &mut [u8]) {
    let mut prev: [u8; 32] = [0; 32];
    for (i, chunk) in out.chunks_mut(32).enumerate().take(255) {
        let counter = [i as u8 + 1];
        let t: &[u8] = if i == 0 { &[] } else { &prev };
        prev = hmac(prk, &[t, info, &counter]);
        chunk.copy_from_slice(&prev[..chunk.len()]);
    }
}

/// The session secret: HKDF-Extract("zmux session" || initiator nonce ||
/// responder nonce, exporter value || psk). Pass empty slices for absent
/// inputs; the exporter value has a fixed length per bootstrap form, so the
/// concatenation is unambiguous.
pub fn session_secret(
    initiator_nonce: &[u8; 16],
    responder_nonce: &[u8; 16],
    exporter: &[u8],
    psk: &[u8],
) -> [u8; 32] {
    let mut salt = [0u8; 44];
    let (prefix, nonces) = salt.split_at_mut(SALT_PREFIX.len());
    prefix.copy_from_slice(SALT_PREFIX);
    let (i, r) = nonces.split_at_mut(16);
    i.copy_from_slice(initiator_nonce);
    r.copy_from_slice(responder_nonce);
    hmac(&salt, &[exporter, psk])
}

/// Whether two Lane Keys are equal, compared in constant time: a reader
/// looks a lane's key up among its sessions this way.
pub fn lane_key_eq(a: &[u8; 16], b: &[u8; 16]) -> bool {
    let diff = a.iter().zip(b).fold(0u8, |d, (x, y)| d | (x ^ y));
    std::hint::black_box(diff) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn rfc5869_case_1() {
        let ikm = [0x0b; 22];
        let salt: Vec<u8> = (0x00..=0x0c).collect();
        let info: Vec<u8> = (0xf0..=0xf9).collect();
        let prk = hkdf_extract(&salt, &ikm);
        assert_eq!(
            hex(&prk),
            "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"
        );
        let mut okm = [0u8; 42];
        hkdf_expand(&prk, &info, &mut okm);
        assert_eq!(
            hex(&okm),
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
        );
    }

    #[test]
    fn secret_selection() {
        use secret_flags::*;
        let both = SecretSource {
            exporter: true,
            psk: true,
        };
        assert_eq!(
            select_secret_source(EXPORTER | PSK, EXPORTER | PSK),
            SecretFlags::Selected(both)
        );
        // Reserved bits select nothing and differ in nothing.
        assert_eq!(select_secret_source(0x02, EXPORTER), SecretFlags::NoSource);
        assert!(matches!(
            select_secret_source(PSK | 0x02, PSK),
            SecretFlags::Selected(_)
        ));
        // Never the intersection: a cleared flag cannot drop a source.
        assert_eq!(
            select_secret_source(EXPORTER | PSK, PSK),
            SecretFlags::Differ
        );
    }
}
