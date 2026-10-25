//! Key schedule for pipe joins (MULTIPATH.md Section 10): secret source
//! selection, the session secret, the join keys and join tokens.

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

use super::frame::JOIN_TOKEN_LEN;

type HmacSha256 = Hmac<Sha256>;

/// TLS exporter label of the session secret input.
pub const EXPORTER_SESSION_LABEL: &str = "EXPORTER-zmux-session";
/// TLS exporter label of a carrier-bound join.
pub const EXPORTER_PIPE_LABEL: &str = "EXPORTER-zmux-pipe";
/// Prefix of the HKDF salt.
pub const SALT_PREFIX: &[u8] = b"zmux session";
/// HKDF label of the initiator's join key.
pub const JOIN_INITIATOR_LABEL: &[u8] = b"zmux join i";
/// HKDF label of the responder's join key.
pub const JOIN_RESPONDER_LABEL: &[u8] = b"zmux join r";

/// The Secret Flags of `zmux_multipath` (MULTIPATH.md Section 3.1).
pub mod secret_flags {
    /// E: TLS exporter of the bootstrap carrier.
    pub const EXPORTER: u8 = 0x01;
    /// P: pre-shared key.
    pub const PSK: u8 = 0x04;
    /// I: insecure join allowed.
    pub const INSECURE: u8 = 0x08;
    /// Reserved bits: sent as 0, ignored on receipt.
    pub const RESERVED: u8 = 0xf2;
}

/// The secret sources both endpoints selected (MULTIPATH.md Section 10.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SecretSource {
    /// Whether the bootstrap exporter value enters the secret.
    pub exporter: bool,
    /// Whether the PSK enters the secret.
    pub psk: bool,
    /// Insecure mode: neither.
    pub insecure: bool,
}

/// Selects the secret sources from both endpoints' Secret Flags, or `None`
/// when there is no source and multipath is not in use.
pub const fn select_secret_source(local: u8, peer: u8) -> Option<SecretSource> {
    let both = local & peer;
    let exporter = both & secret_flags::EXPORTER != 0;
    let psk = both & secret_flags::PSK != 0;
    if exporter || psk {
        return Some(SecretSource {
            exporter,
            psk,
            insecure: false,
        });
    }
    if both & secret_flags::INSECURE != 0 {
        return Some(SecretSource {
            exporter: false,
            psk: false,
            insecure: true,
        });
    }
    None
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
pub fn hkdf_expand(prk: &[u8; 32], info: &[u8], out: &mut [u8]) {
    let mut prev: [u8; 32] = [0; 32];
    for (i, chunk) in out.chunks_mut(32).enumerate().take(255) {
        let counter = [i as u8 + 1];
        let t: &[u8] = if i == 0 { &[] } else { &prev };
        prev = hmac(prk, &[t, info, &counter]);
        chunk.copy_from_slice(&prev[..chunk.len()]);
    }
}

/// The session secret (MULTIPATH.md Section 10.3):
/// HKDF-Extract("zmux session" || initiator nonce || responder nonce,
/// exporter value || psk). Pass empty slices for absent inputs; the exporter
/// value has a fixed length per bootstrap form, so the concatenation is
/// unambiguous.
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

/// The keys derived from the session secret (MULTIPATH.md Section 10.4).
#[derive(Clone, PartialEq, Eq)]
pub struct SessionKeys {
    /// join_key_i.
    pub join_initiator: [u8; 32],
    /// join_key_r.
    pub join_responder: [u8; 32],
}

impl std::fmt::Debug for SessionKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SessionKeys(..)")
    }
}

impl SessionKeys {
    /// Derives the keys from the session secret.
    pub fn derive(secret: &[u8; 32]) -> Self {
        let expand = |label: &[u8]| {
            let mut k = [0u8; 32];
            hkdf_expand(secret, label, &mut k);
            k
        };
        Self {
            join_initiator: expand(JOIN_INITIATOR_LABEL),
            join_responder: expand(JOIN_RESPONDER_LABEL),
        }
    }
}

/// The Join Token (MULTIPATH.md Section 10.5): the first 16 bytes of
/// HMAC-SHA256(join key, frame bytes from Type through Priority ||
/// carrier binding).
pub fn join_token(
    join_key: &[u8; 32],
    frame_without_token: &[u8],
    carrier_binding: &[u8],
) -> [u8; JOIN_TOKEN_LEN] {
    let mac = hmac(join_key, &[frame_without_token, carrier_binding]);
    let mut token = [0u8; JOIN_TOKEN_LEN];
    token.copy_from_slice(&mac[..JOIN_TOKEN_LEN]);
    token
}

/// Computes the token of an encoded PIPE_JOIN frame and writes it into the
/// frame's last 16 bytes. Returns `false` if `frame` is too short.
pub fn sign_join(join_key: &[u8; 32], frame: &mut [u8], carrier_binding: &[u8]) -> bool {
    let Some(split) = frame.len().checked_sub(JOIN_TOKEN_LEN) else {
        return false;
    };
    let (head, token) = frame.split_at_mut(split);
    token.copy_from_slice(&join_token(join_key, head, carrier_binding));
    true
}

/// Verifies the token of a PIPE_JOIN frame as received (`frame` is the whole
/// frame, Type through Join Token), in constant time.
pub fn verify_join(join_key: &[u8; 32], frame: &[u8], carrier_binding: &[u8]) -> bool {
    let Some((head, token)) = frame
        .len()
        .checked_sub(JOIN_TOKEN_LEN)
        .map(|split| frame.split_at(split))
    else {
        return false;
    };
    let Ok(mut mac) = HmacSha256::new_from_slice(join_key) else {
        return false;
    };
    mac.update(head);
    mac.update(carrier_binding);
    mac.verify_truncated_left(token).is_ok()
}

/// Whether two Lane Keys are equal, compared in constant time: a reader
/// looks a lane's key up among its sessions this way (MULTIPATH.md
/// Section 5.8).
pub fn lane_key_eq(a: &[u8; 16], b: &[u8; 16]) -> bool {
    let diff = a.iter().zip(b).fold(0u8, |d, (x, y)| d | (x ^ y));
    std::hint::black_box(diff) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
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
        assert_eq!(
            select_secret_source(EXPORTER | PSK, EXPORTER | PSK),
            Some(SecretSource {
                exporter: true,
                psk: true,
                insecure: false
            })
        );
        // 0x02 is reserved: it selects nothing.
        assert_eq!(select_secret_source(EXPORTER | 0x02, PSK | 0x02), None);
        assert_eq!(
            select_secret_source(INSECURE, INSECURE | RESERVED).map(|s| s.insecure),
            Some(true)
        );
    }
}
