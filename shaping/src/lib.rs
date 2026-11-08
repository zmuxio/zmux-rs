//! Shaping configuration for zmux: a [`zmux::shaping::Shaper`] driven by state machines, the
//! plans of handshake messages and pool policies, read from one JSON format.
//!
//! Every number is an integer: a constant, or a table of weighted segments sampled from an
//! injectable random [`Source`]. Lengths are bytes on the carrier, times microseconds and
//! proportions parts per million.

mod bundle;
mod error;
mod json;
mod limits;
mod machine;
mod pool;
mod random;
mod value;

pub use bundle::{Bundle, Compiled};
pub use error::Error;
pub use limits::parse_limits;
pub use machine::{DEFAULT_MAX_SLOTS, MachineFactory, MachineShaper, Options, SizeLimits};
pub use pool::{MachinePoolPolicy, MemberDecision, PoolMember, pool_policy};
pub use random::Source;
pub use value::{Sampler, Value};
