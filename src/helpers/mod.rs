//! The helper layer (non-normative): conveniences above
//! the public API that drive only its operations and send nothing but what
//! those operations send. Anything they do, an application can do with the
//! session's operations alone.
//!
//! - `maintain_pipes` keeps a pool of pipes up (tokio driver);
//! - `splice` forwards two streams into each other, how a relay connects
//!   them (tokio driver);
//! - `resolve_duplicate` keeps one of two sessions that connect the same
//!   two endpoints (tokio here, `zmux::blocking::helpers::resolve_duplicate` for the
//!   std driver).

/// How often a redial source (a pool, the std driver's redial hook) looks at its pipes,
/// at most.
#[cfg(any(feature = "tokio", feature = "blocking"))]
pub(crate) const POLL: std::time::Duration = std::time::Duration::from_millis(100);

mod backoff;
mod duplicate;
#[cfg(feature = "tokio")]
mod maintain;

/// Splicing lives in the driver: it moves the shared chunks of two streams
/// with the drivers' own low-level stream operations.
#[cfg(feature = "tokio")]
pub use crate::driver::splice::{
    Forwarded, SpliceEnd, SpliceError, SpliceOptions, Spliced, splice,
};
pub use backoff::Backoff;
pub use duplicate::{DuplicateError, DuplicateRule};
pub(crate) use duplicate::{duplicate_api, resolve};

#[cfg(feature = "tokio")]
duplicate_api!(crate::driver::tokio::Tokio, crate::Session, crate::Dial);
#[cfg(feature = "tokio")]
pub use maintain::{
    MaintainHandle, PipePool, PoolDecision, PoolMember, PoolPolicy, PoolView, RECHECK_FLOOR,
    RotatePolicy, maintain_pipes,
};
#[cfg(feature = "tokio")]
pub(crate) use maintain::{maintain_mode, maintain_redial};
