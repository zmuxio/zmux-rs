//! Drivers: the sans-IO core behind one mutex, with the pipe I/O outside
//! it.
//!
//! | | tokio driver | std driver |
//! |---|---|---|
//! | execution | one task per session owns the pipes | a reader and a writer thread per pipe, a timer thread per session |
//! | waiting | the shared futures, awaited | the shared futures, run on the calling thread, which parks between polls |
//!
//! The application's handles are one generic layer for both drivers
//! (`handle`): each operation locks the core for one command, wakes whoever
//! the command's events concern, and wakes the driver when the command
//! produced output; an operation that must wait is a future that registers
//! its waker under the lock.
//!
//! The rules both drivers keep, by construction where possible:
//!
//! - one lock per session guards the core ([`wake::Locked`]); the pipes'
//!   read and write sides are only ever tried, never waited for, under it
//!   or by the session task ([`through`]), so there is no lock cycle and
//!   the session task is never stalled by an application's fast path;
//! - nothing performs I/O, waits or calls into the application under the
//!   core lock;
//! - wake-ups (tasks and threads alike) are decided under the lock and
//!   delivered after it was released ([`wake`]);
//! - every wait resolves: a wait that is cancelled or times out leaves its
//!   list, and closing the session wakes every wait ([`wait`]);
//! - queues are bounded or drained by the session task, and a peer can
//!   never make a driver panic.
//!
//! The synchronization units are model-checked with loom (`loom.rs`), the
//! std driver's thread protocol with shuttle (`shuttle.rs`).

// Without a driver only the shared types are used (and the units the
// drivers' interface makes public are unreachable).
#![cfg_attr(
    any(not(any(feature = "tokio", feature = "blocking")), loom),
    allow(dead_code, unused_imports, unreachable_pub)
)]

#[cfg(all(feature = "tokio", not(loom)))]
mod account;
#[cfg(all(feature = "blocking", not(loom)))]
pub(crate) mod blocking;
#[cfg(all(feature = "blocking", not(loom)))]
mod context;
#[cfg(all(any(feature = "tokio", feature = "blocking"), not(loom)))]
mod engine;
#[cfg(all(any(feature = "tokio", feature = "blocking"), not(loom)))]
mod events;
#[cfg(all(any(feature = "tokio", feature = "blocking"), not(loom)))]
pub(crate) mod handle;
#[cfg(all(any(feature = "tokio", feature = "blocking"), not(loom)))]
mod hooks;
#[cfg(all(feature = "tokio", not(loom)))]
pub(crate) mod lanes;
#[cfg(all(feature = "tokio", not(loom)))]
pub(crate) mod listen;
#[cfg(all(test, loom))]
mod loom;
#[cfg(all(any(feature = "tokio", feature = "blocking"), not(loom)))]
pub(crate) mod resources;
#[cfg(all(test, shuttle, feature = "blocking", not(loom)))]
mod shuttle;
#[cfg(all(feature = "tokio", not(loom)))]
pub(crate) mod splice;
#[cfg(all(feature = "tokio", not(loom)))]
mod stream_pipe;
mod sync;
#[cfg(all(any(feature = "tokio", feature = "blocking"), not(loom)))]
mod tcp;
#[cfg(any(feature = "tokio", all(test, loom)))]
mod through;
#[cfg(all(feature = "tokio", not(loom)))]
pub(crate) mod tokio;
mod wait;
mod wake;

/// The initial TCP_NOTSENT_LOWAT of a TCP carrier on a single pipe, the
/// floor of the dynamic value, which
/// [`tcp::Probe`] keeps up to date.
#[cfg(any(feature = "tokio", feature = "blocking"))]
pub(crate) const NOTSENT_LOWAT_SINGLE: u64 = 128 * 1024;

/// The initial TCP_NOTSENT_LOWAT of a TCP carrier added to a multipath
/// session, the per-pipe floor: unsent bytes in
/// a carrier can no longer move to another pipe.
#[cfg(any(feature = "tokio", feature = "blocking"))]
pub(crate) const NOTSENT_LOWAT_MULTIPATH: u64 = 32 * 1024;

use std::fmt;

use crate::proto::frame::Dir;
use crate::proto::params::Role;
pub(crate) use crate::proto::session::{GoAway, SessionEvent as Event};

/// The read buffer of a pipe: at least `max_record_size + 4` (65539).
/// Received data references it, so a read buffer is reclaimed only once
/// its data was read: a larger one keeps the reads of a bulk transfer
/// large (256 KiB against 128: multipath 8 to 11 % and single-pipe
/// zero-copy bulk 8 % more throughput on Linux, at less CPU per byte).
pub(crate) const READ_BUFFER: usize = 256 * 1024;

/// A pipe idle this long frees its buffers.
#[cfg(any(feature = "tokio", feature = "blocking"))]
pub(crate) const IDLE_RELEASE: std::time::Duration = std::time::Duration::from_secs(1);

/// Read buffers of idle pipes, shared by every session of the process: an idle
/// pipe gives its buffer back and
/// the next read after idleness takes one, so quiet sessions neither hold
/// a read buffer nor allocate and zero a read buffer for each record. At most
/// [`read_pool::KEEP`] are kept.
#[cfg(all(any(feature = "tokio", feature = "blocking"), not(loom)))]
pub(crate) mod read_pool {
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicU64, Ordering};

    use bytes::BytesMut;

    use crate::proto::session::Backing;

    /// Buffers kept for reuse (4 MiB).
    pub(crate) const KEEP: usize = 16;

    static POOL: Mutex<Vec<BytesMut>> = Mutex::new(Vec::new());

    /// The identifier of the next buffer handed out: they grow with every
    /// buffer, as received data that references one needs
    /// ([`crate::proto::session::SessionCore::receive_shared`]).
    static NEXT: AtomicU64 = AtomicU64::new(1);

    /// An empty read buffer of [`super::READ_BUFFER`] bytes' capacity, and
    /// its identity.
    pub(crate) fn take() -> (BytesMut, Backing) {
        let reused = POOL.lock().ok().and_then(|mut p| p.pop());
        let mut buf = reused.unwrap_or_else(|| BytesMut::with_capacity(super::READ_BUFFER));
        buf.clear();
        let backing = Backing {
            id: NEXT.fetch_add(1, Ordering::Relaxed),
            size: buf.capacity(),
        };
        (buf, backing)
    }

    /// A read buffer of [`super::READ_BUFFER`] initialized bytes, for
    /// readers that need initialized memory (`std::io::Read`).
    #[cfg_attr(not(feature = "blocking"), allow(dead_code))]
    pub(crate) fn take_initialized() -> BytesMut {
        let (mut buf, _) = take();
        buf.resize(super::READ_BUFFER, 0);
        buf
    }

    /// Gives a buffer back, unless received data still references it.
    pub(crate) fn give(mut buf: BytesMut) {
        buf.clear();
        if !buf.try_reclaim(super::READ_BUFFER) || buf.capacity() < super::READ_BUFFER {
            return;
        }
        if let Ok(mut p) = POOL.lock()
            && p.len() < KEEP
        {
            p.push(buf);
        }
    }

    /// Buffers in the pool now.
    #[cfg(feature = "test-hooks")]
    pub(crate) fn len() -> usize {
        POOL.lock().map_or(0, |p| p.len())
    }

    /// A fresh identity for `buf`, a buffer that was reclaimed or grown
    /// in place.
    #[cfg_attr(not(feature = "tokio"), allow(dead_code))]
    pub(crate) fn renew(buf: &BytesMut) -> Backing {
        Backing {
            id: NEXT.fetch_add(1, Ordering::Relaxed),
            size: buf.capacity(),
        }
    }
}

/// The stack buffer an idle pipe reads into before it allocates its read
/// buffer again.
#[cfg(any(feature = "tokio", feature = "blocking"))]
pub(crate) const IDLE_READ: usize = 4096;

/// I/O slices per vectored write.
pub(crate) const MAX_SLICES: usize = 64;

/// A write call limit (the core's `write_call_limit`) reused by the calls
/// of a batch that follow within the session's latency budget, so that a
/// batch written in many short calls does not take the core lock for each:
/// a change of the latency-sensitive state the limit follows is seen one
/// budget later at most, as the bound itself allows.
#[cfg(any(feature = "tokio", feature = "blocking"))]
#[derive(Debug, Default)]
pub(crate) struct CallLimit {
    /// The bound below the bytes left when it was computed, if any.
    bound: Option<usize>,
    /// Computed with input pending.
    input: bool,
    /// Until when it holds; `None`: nothing cached.
    until: Option<std::time::Instant>,
}

#[cfg(any(feature = "tokio", feature = "blocking"))]
impl CallLimit {
    /// The limit for a call with `left` bytes left, while the cached one
    /// holds: not expired, and not computed without input when there is
    /// input now.
    pub(crate) fn get(&self, left: usize, input: bool, now: std::time::Instant) -> Option<usize> {
        let until = self.until?;
        (now < until && (self.input || !input)).then(|| self.bound.map_or(left, |b| b.min(left)))
    }

    /// Caches `limit`, computed under the core lock for `left` bytes at
    /// `now`, for `budget`; returns it.
    pub(crate) fn set(
        &mut self,
        left: usize,
        limit: usize,
        input: bool,
        now: std::time::Instant,
        budget: std::time::Duration,
    ) -> usize {
        self.bound = (limit < left).then_some(limit);
        self.input = input;
        self.until = now.checked_add(budget);
        limit
    }
}

/// A stream identifier (SPEC.md Section 7.1).
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct StreamId(pub(crate) u64);

impl StreamId {
    /// The identifier as an integer.
    pub fn into_inner(self) -> u64 {
        self.0
    }

    /// The stream index within its type and initiator.
    pub fn index(self) -> u64 {
        self.0 >> 2
    }

    /// The stream type.
    pub fn dir(self) -> Dir {
        if self.0 & 2 == 0 { Dir::Bidi } else { Dir::Uni }
    }

    /// Which role opened the stream.
    pub fn initiator(self) -> Role {
        if self.0 & 1 == 0 {
            Role::Initiator
        } else {
            Role::Responder
        }
    }
}

impl From<StreamId> for u64 {
    fn from(id: StreamId) -> u64 {
        id.0
    }
}

impl fmt::Debug for StreamId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "StreamId({})", self.0)
    }
}

impl fmt::Display for StreamId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// The halves of a pipe from the local endpoint's view.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PipeDirection {
    /// The local endpoint reads (for example an HTTP GET response body).
    In,
    /// The local endpoint writes (for example an HTTP POST request body).
    Out,
    /// Both (a bidirectional carrier).
    Bidi,
}

/// What a dial is for: the pipe's direction, and for a pipe the local
/// endpoint only reads (a downlink), the `Zmux-Pipe-Join` header value the
/// carrier's request must carry (MULTIPATH.md Section 5.3); the others join
/// in band. The argument of a [`Dial`](crate::Dial) function.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct DialRequest {
    /// The halves the carrier provides.
    pub direction: PipeDirection,
    /// The out-of-band join of a downlink.
    pub join_header: Option<String>,
}

impl DialRequest {
    /// A request for a carrier with both halves, joined in band (a rejoin,
    /// a pool that is not split).
    pub fn bidi() -> Self {
        Self {
            direction: PipeDirection::Bidi,
            join_header: None,
        }
    }
}

/// A session with role auto: its role depends on the peer, so it cannot
/// send early data.
pub(crate) fn check_peer(config: &crate::Config) -> Result<(), crate::ConnectError> {
    if config.early_data.zmux_peer {
        return Err(crate::ConnectError::InvalidConfig(
            "early_data needs a role that does not depend on the peer: not with role auto",
        ));
    }
    Ok(())
}

/// The marker of an empty message (see [`empty_message`]).
#[derive(Debug)]
struct EmptyMessage;

impl fmt::Display for EmptyMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("an empty message")
    }
}

impl std::error::Error for EmptyMessage {}

/// For message-framed carriers ([`PipeIo::records`](crate::PipeIo::records)):
/// the read result that reports an empty message. A read that returns
/// nothing is the end of the carrier, so a carrier's reader returns this
/// error for a message without bytes instead; the session takes it as an
/// empty record, a no-op charged like a record of PADDING only.
pub fn empty_message() -> std::io::Error {
    std::io::Error::other(EmptyMessage)
}

/// Whether a read error is [`empty_message`].
pub(crate) fn is_empty_message(e: &std::io::Error) -> bool {
    e.get_ref().is_some_and(|i| i.is::<EmptyMessage>())
}
