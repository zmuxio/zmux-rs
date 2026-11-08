//! The zmux secure carrier over zmux carriers (see the zmux specification): the client's
//! [`establish`] and the server's [`ServerConfig::transform`], the trust of [`Verifier`] and
//! [`Gate`], with the built-in [`PinVerifier`]. The result is a carrier
//! for `Session::connect`, or a listener's `inbound_transform`; a session on it takes its
//! secret from the handshake's exporter. Joins are the core's.

#[cfg(feature = "blocking")]
pub mod blocking;
mod carrier;
mod establish;
mod profiles;
mod server;
mod trust;

pub use establish::{ClientConfig, DEFAULT_REPLY_TIMEOUT, NoReply, Peer, establish};
pub use server::{ModeCheck, ServerConfig, ServerOptions, reject_reason};
pub use trust::{
    Admission, AppData, AppDataRequest, AppDataSource, BoxFuture, ConfigError, Credential, Gate,
    KeySigner, PeerRole, PinVerifier, Principal, Signer, Verdict, Verifier, VerifyError,
    VerifyInput, static_key_id, static_public,
};
pub use zmux_seal_proto::{
    DEFAULT_MAX_APP_DATA, Error, HandlePsk, KEYALG_MLDSA44, KEYALG_X25519, KeyAlg, KeyId, KeyUse,
    Profile, SigningKey, derive_handle_psk, key_id,
};

/// The largest handshake unit plus its header.
pub(crate) const MAX_UNIT: usize = u16::MAX as usize + 512;

/// Type 0 of a handshake payload: padding.
pub(crate) const PADDING_ITEM: u64 = 0;

/// Type 1 of a handshake payload: credentials.
pub(crate) const CREDENTIALS_ITEM: u64 = 1;

/// The session exporter's reading of a finished handshake: the only exporter of a secure
/// carrier.
pub(crate) fn exporter_of(
    complete: zmux_seal_proto::HandshakeExporter,
) -> impl Fn(&str, &[u8], &mut [u8]) -> bool + Send + Sync + 'static {
    move |label, context, out| match complete.export(label.as_bytes(), context, out.len()) {
        Ok(v) => {
            out.copy_from_slice(&v);
            true
        }
        Err(_) => false,
    }
}

/// Type 2 of a handshake payload: application data.
pub(crate) const APP_DATA_ITEM: u64 = 2;

/// Type 8 of a handshake payload: a proof.
pub(crate) const PROOF_ITEM: u64 = 8;

/// The items of a message besides padding, in the order of their types: the credential,
/// the application data and the proof, each when present.
pub(crate) fn message_items<'a>(
    credential: &'a [u8],
    app_data: &'a [u8],
    proof: &'a [u8],
) -> Vec<(u64, &'a [u8])> {
    let mut items = Vec::new();
    if !credential.is_empty() {
        items.push((CREDENTIALS_ITEM, credential));
    }
    if !app_data.is_empty() {
        items.push((APP_DATA_ITEM, app_data));
    }
    if !proof.is_empty() {
        items.push((PROOF_ITEM, proof));
    }
    items
}

/// The payload of a handshake message: a padding item of `padding` bytes, if any, zeros
/// or random, then `items`.
pub(crate) fn handshake_payload(
    padding: Option<usize>,
    items: &[(u64, &[u8])],
    random: bool,
) -> Result<Vec<u8>, Error> {
    let mut pad = vec![0; padding.unwrap_or(0)];
    if random {
        zmux::proto::seal::fill_random(&mut pad)?;
    }
    let mut all: Vec<(u64, &[u8])> = Vec::with_capacity(items.len() + 1);
    if padding.is_some() {
        all.push((PADDING_ITEM, &pad));
    }
    all.extend_from_slice(items);
    Ok(zmux::proto::seal::encode_payload(&all))
}

/// Encodes a credential as the value of the credential item: `CredType ‖ Credential`.
pub(crate) fn credential_value(credential: Option<&(u64, Vec<u8>)>) -> Vec<u8> {
    let mut out = Vec::new();
    if let Some((kind, data)) = credential {
        zmux::proto::seal::put_varint(&mut out, *kind);
        out.extend_from_slice(data);
    }
    out
}

/// The value of a proof item of `signer` with a placeholder signature of its length,
/// which gives the message its length before it is signed; empty without a signer.
pub(crate) fn proof_placeholder(signer: Option<&std::sync::Arc<dyn Signer>>) -> Vec<u8> {
    let Some(signer) = signer else {
        return Vec::new();
    };
    let (key_alg, key) = signer.proof_key();
    let sig = vec![0; KeyAlg::from_value(key_alg).map_or(0, KeyAlg::sig_len)];
    zmux::proto::seal::Proof {
        key_alg,
        key,
        sig: &sig,
    }
    .encode()
}
