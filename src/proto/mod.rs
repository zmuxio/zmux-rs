//! The sans-IO wire layer of zmux.
//!
//! - [`varint`]: QUIC variable-length integers.
//! - [`frame`]: every frame of the zmux registry, decoded zero-copy and
//!   encoded into caller-provided buffers.
//! - [`record`]: the record layer, with an incremental reader for input
//!   split at any byte boundary and message framing.
//! - [`params`]: transport parameters, GREASE and negotiation results.
//! - [`draft`]: the values that depend on the QMux draft version.
//! - [`ident`]: first-record identification and ALPN identifiers.
//! - [`payload`]: the stream preamble and the datagram flow prefix.
//! - [`keys`]: the join and resume key schedule.
//! - [`oob`]: out-of-band join and pairing header values.
//! - [`listener`]: classification and limits of new carriers, join routing.
//! - [`meter`]: the application byte counters of streams and sessions.
//! - [`limit`]: the limiter interface of datagrams and the relay helper.
//! - [`error`]: error codes and the error types of this layer.
//!
//! Nothing in this module performs I/O or panics on peer input, and
//! decoding and encoding allocate nothing.

#![forbid(unsafe_code)]

mod codec;
pub mod draft;
pub mod error;
pub mod frame;
pub mod ident;
pub mod keys;
pub mod limit;
pub mod listener;
pub mod meter;
pub mod oob;
pub mod params;
pub mod payload;
pub mod record;
pub mod varint;

pub mod session;

pub use error::{ApplicationErrorCode, DetailKey, EncodeError, Error, TransportErrorCode};
pub use frame::{Frame, FrameType, Frames, Gates};
pub use params::TransportParameters;
pub use record::{Event, RecordReader};
pub use varint::VarInt;
