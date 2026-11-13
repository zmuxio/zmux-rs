#![warn(missing_debug_implementations)]
//! The Establish handshake of the zmux secure carrier, sans-IO: Profiles, Noise
//! and its payloads. Join, Sealed records, the payload codec, `Export`
//! and the error classes are the core's, in [`zmux::proto::seal`].
//!
//! Each handshake step consumes its state. Ephemeral keys come from the operating
//! system.
//!
//! ```text
//! client: Initiator::new -> write_hello -> AwaitReply::read_reply
//!           -> Verify::check_proof, Verify::accept
//!           -> Finish::write_finish (or write_finish_signed -> SignFinish::finish) -> Complete
//! server: Hello::parse -> Responder::read_hello
//!           -> ResponderReply::write_reply (or write_reply_signed -> SignReply::finish)
//!           -> AwaitFinish::read_finish -> Complete::check_proof
//! ```
//!
//! A proof is signed outside: a signing step returns the M to sign and takes the
//! signature, so a signer may wait on another process.

mod derive;
mod handshake;
mod keyalg;
mod noise;
mod profile;
mod proof;
mod wire;

/// The default largest application data of a received handshake message, in bytes.
pub const DEFAULT_MAX_APP_DATA: usize = 256;

pub use derive::{HandlePsk, derive_handle_psk, exporter_secret};
pub use handshake::{
    AwaitFinish, AwaitReply, Complete, Finish, HandshakeExporter, Initiator, InitiatorConfig,
    Responder, ResponderKeys, ResponderReply, SignFinish, SignReply, Verify, prologue,
};
pub use keyalg::{KEYALG_MLDSA44, KEYALG_X25519, KeyAlg, KeyId, KeyUse, key_id};
pub use profile::{HANDSHAKE_ESTABLISH, Profile};
pub use proof::{SigningKey, check_pin_pq_auth, check_proof};
pub use wire::{HANDLE_LEN, Hello};

pub use zmux::proto::seal::{
    Error, Framing, Opener, Payload, Proof, RecordMode, Sealer, encode_payload,
};
