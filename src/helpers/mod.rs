//! The helper layer (non-normative): conveniences above
//! the public API that drive only its operations and send nothing but what
//! those operations send. Anything they do, an application can do with the
//! session's operations alone.
//!
//! - `maintain_pipes` keeps a pool of pipes up (tokio driver);
//! - `splice` forwards two streams into each other, how a relay connects
//!   them (tokio driver);
//! - `PacketStream` carries packets over a stream, as datagrams or
//!   capsules (EXTENSIONS.md Section 12), and `splice_packets` relays two
//!   of them (tokio driver);
//! - `resolve_duplicate` keeps one of two sessions that connect the same
//!   two endpoints (tokio here, `zmux::blocking::helpers::resolve_duplicate` for the
//!   std driver).

/// How often a redial source (a pool, the std driver's redial hook) looks at its pipes,
/// at most.
#[cfg(any(feature = "tokio", feature = "blocking"))]
pub(crate) const POLL: std::time::Duration = std::time::Duration::from_millis(100);

#[cfg_attr(any(not(feature = "tokio"), loom), allow(dead_code))]
pub(crate) mod capsule;
pub(crate) mod duplicate;
#[cfg(feature = "tokio")]
mod maintain;
#[cfg(feature = "tokio")]
mod policy_exec;

/// Packet streams live in the driver: they read and write with its
/// low-level stream operations.
#[cfg(feature = "tokio")]
pub use crate::driver::packet::{
    DEFAULT_MAX_PACKET, Packet, PacketError, PacketOptions, PacketReceiver, PacketSender,
    PacketStats, PacketStream, SendPolicy, Sent,
};
/// Splicing lives in the driver: it moves the shared chunks of two streams
/// with the drivers' own low-level stream operations.
#[cfg(feature = "tokio")]
pub use crate::driver::splice::{
    SpliceAbort, SpliceDirection, SpliceEnd, SpliceError, SpliceOptions, SpliceResult, splice,
    splice_packets,
};
pub(crate) use duplicate::duplicate_api;
pub use duplicate::{DuplicateError, DuplicateRule};

#[cfg(feature = "tokio")]
duplicate_api!(crate::driver::tokio::Tokio, crate::Session, crate::Dial);
#[cfg(feature = "tokio")]
pub use maintain::{
    AsyncPoolPolicy, MIN_RECHECK, MaintainHandle, OwnedPoolView, PipePool, PolicyError,
    PolicyFuture, PoolDecision, PoolMember, PoolPolicy, PoolView, Rotation, maintain_pipes,
};
#[cfg(feature = "tokio")]
pub(crate) use maintain::{maintain_choice, maintain_redial};
