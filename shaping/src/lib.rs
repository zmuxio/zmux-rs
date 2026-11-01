//! A [`zmux::shaping::Shaper`] driven by state machines read from a
//! [`Definition`].
//!
//! A definition (version [`VERSION`]) holds machines that run side by side
//! on each pipe. Each machine has states, two counters and two timer slots;
//! a state may set record decisions, run actions when entered and move on
//! triggers. Every number is a [`Value`]: a constant, a uniform range or a
//! distribution, sampled per its [`Scope`] from the pipe's random
//! [`Source`].
//!
//! Definitions are read from JSON ([`Definition::from_json`]) or from the
//! compact sequence form ([`parse_sequence`]), validated (fields, ranges,
//! reachability, injections with a zero delay on cycles of transitions
//! taken without an outside trigger) and bounded ([`SizeLimits`]).

mod bound;
mod check;
mod def;
mod json;
mod limits;
mod machine;
mod pool;
mod random;
mod sequence;
mod value;

pub use check::SizeLimits;
pub use def::{
    Action, Comparison, Cond, Definition, Dist, DistKind, Error, Machine, Op, Quantity, Record,
    Scope, State, Transition, Trigger, VERSION, Value,
};
pub use limits::session_limits;
pub use machine::{MachineFactory, MachineShaper, Options};
pub use pool::{MachinePoolPolicy, MemberDecision, PoolMember, pool_policy};
pub use random::Source;
pub use sequence::parse_sequence;
