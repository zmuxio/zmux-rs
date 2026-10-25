//! The helper layer (non-normative): conveniences above
//! the public API that drive only its operations and send nothing but what
//! those operations send. Anything they do, an application can do with the
//! session's operations alone.
//!
//! - `maintain_pipes` keeps a pool of pipes up (tokio driver);
//! - `splice` forwards two streams into each other, how a relay connects
//!   them (tokio driver);
//! - `resolve_duplicate` keeps one of two sessions that connect the same
//!   two endpoints (tokio here, `zmux::blocking::resolve_duplicate` for the
//!   std driver).

mod duplicate;
#[cfg(feature = "tokio")]
mod maintain;

/// Splicing lives in the driver: it moves the shared chunks of two streams
/// with the drivers' own low-level stream operations.
#[cfg(feature = "tokio")]
pub use crate::driver::splice::{
    Forwarded, SpliceEnd, SpliceError, SpliceOptions, Spliced, splice,
};
pub use duplicate::{DuplicateError, DuplicateRule};
pub(crate) use duplicate::{duplicate_api, resolve};

#[cfg(feature = "tokio")]
duplicate_api!(crate::driver::tokio::Tokio, crate::Session, crate::Dial);
#[cfg(feature = "tokio")]
pub use maintain::{BackoffPolicy, MaintainHandle, PipePool, RotatePolicy, maintain_pipes};
