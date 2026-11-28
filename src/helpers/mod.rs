//! The helper layer (non-normative): conveniences above
//! the public API that drive only its operations and send nothing but what
//! those operations send. Anything they do, an application can do with the
//! session's operations alone.
//!
//! - `splice` forwards two streams into each other, how a relay connects
//!   them (tokio driver);
//! - `PacketStream` carries packets over a stream, as datagrams or
//!   capsules (EXTENSIONS.md Section 12), and `splice_packets` relays two
//!   of them (tokio driver);
//! - `resolve_duplicate` keeps one of two sessions that connect the same
//!   two endpoints (tokio here, `zmux::blocking::helpers::resolve_duplicate` for the
//!   std driver).

#[cfg_attr(any(not(feature = "tokio"), loom), allow(dead_code))]
pub(crate) mod capsule;
pub(crate) mod duplicate;

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
    ControlledSpliceOptions, SpliceAbort, SpliceBudget, SpliceCommandError, SpliceControl,
    SpliceController, SpliceDecision, SpliceDirection, SpliceDisposition, SpliceDropReason,
    SpliceDrops, SpliceEditor, SpliceEnd, SpliceError, SpliceEvent, SpliceEventSink, SpliceHook,
    SpliceHooks, SpliceInjection, SpliceInjectionStatus, SpliceKind, SpliceLimits, SpliceMeta,
    SpliceMirror, SpliceMirrorMode, SpliceMirrorReceiver, SpliceOptions, SplicePause,
    SplicePayloads, SpliceReceipt, SpliceResult, SpliceRoute, SpliceSample, SpliceSignal,
    SpliceUnit, SpliceWait, controlled_splice, controlled_splice_packets, splice, splice_packets,
};
pub(crate) use duplicate::duplicate_api;
pub use duplicate::{DuplicateError, DuplicateRule};

#[cfg(feature = "tokio")]
duplicate_api!(crate::driver::tokio::Tokio, crate::Session, crate::Dial);

#[cfg(all(feature = "tokio", not(loom)))]
pub use crate::proto::session::splice_handoff::{SpliceHandoffStats, SpliceHandoffs};
