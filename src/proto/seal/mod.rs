//! The core of the secure carrier, sans-IO: Join, the Suite table, Sealed
//! records, the handshake payload codec, `Export`, dispatch and error classes.
//! Establish and Profiles build on this in the `zmux-seal-proto` crate.

mod cipher;
mod crypto;
mod error;
mod export;
pub mod group;
pub mod join;
pub mod kex;
mod payload;
mod record;
mod secret;
mod wire;

#[cfg(feature = "seal-chacha")]
pub use cipher::chacha20_poly1305;
pub use cipher::{Cipher, Hash, SHA256, aes_256_gcm};
pub use crypto::{SessionCrypto, derive_epoch_secret, session_crypto, session_crypto_hash};
pub use error::Error;
pub use export::{bound_exporter, export};
pub use group::{Group, GroupInitiator, PRIVATE, SharedSecrets, combine};
pub use join::{JoinRole, Suite, derive_join_psk, expand_join_psk, has_aes_hardware};
pub use payload::{CredentialEntry, JoinPipe, Payload, Proof, encode_payload, get_item_varint};
pub use record::{Opener, Sealer};
pub use secret::{Secret, fill_random};
pub use wire::{Dispatch, Mode, cut_frame, cut_unit, dispatch, frame, put_varint, read_shortest};

pub use super::record::Framing;
