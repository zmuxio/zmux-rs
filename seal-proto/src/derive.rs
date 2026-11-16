//! Derivations of Establish.

use zmux::proto::seal::{Error, SHA256, Secret};

use crate::Profile;

const MIN_SECRET: usize = 16;

/// `exporter_secret` from the final `ck` and `h` of a handshake of `profile`.
///
/// # Errors
///
/// `invalid_config` when `ck` is shorter than the hash output.
pub fn exporter_secret(profile: Profile, ck: &[u8], h: &[u8]) -> Result<Vec<u8>, Error> {
    let hash = profile.0.hash;
    let info = [b"zmux-seal exporter", h].concat();
    hash.expand(ck, &info, hash.out_len())
}

/// A Handle and pre-shared key derived from one secret. The key is a
/// [`Secret`]: cleared when dropped, shown as `..` by `Debug`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HandlePsk {
    /// The 16-byte Handle.
    pub handle: Vec<u8>,
    /// The 32-byte pre-shared key.
    pub psk: Secret,
}

/// Derives a Handle and pre-shared key from a high-entropy secret.
/// `deployment_salt` is optional, empty by default, and keeps a batch of Handles
/// to one deployment.
///
/// # Errors
///
/// `invalid_config` when `secret` is shorter than 16 bytes or `domain`
/// is longer than 65535 bytes.
pub fn derive_handle_psk(
    secret: &[u8],
    domain: &[u8],
    deployment_salt: &[u8],
) -> Result<HandlePsk, Error> {
    if secret.len() < MIN_SECRET {
        return Err(Error::InvalidConfig);
    }
    let domain_len = u16::try_from(domain.len()).map_err(|_| Error::InvalidConfig)?;
    let prk = Secret::from(SHA256.extract(&[b"zmux-seal token", deployment_salt].concat(), secret));
    let derive = |prefix: &[u8], len| {
        SHA256.expand(
            &prk,
            &[prefix, &domain_len.to_be_bytes(), domain].concat(),
            len,
        )
    };
    Ok(HandlePsk {
        handle: derive(b"handle", 16)?,
        psk: Secret::from(derive(b"psk", 32)?),
    })
}
