//! Test-only accounting of the drivers' resources (feature `test-hooks`):
//! process-wide counts of live sessions, session tasks, driver threads,
//! pipes, listeners and their tasks, pipe maintainers and hook contexts,
//! for leak tests that check every
//! count returns to its baseline (CONFORMANCE.md).
//!
//! A driver object that is counted holds a [`Live`] token: it counts one
//! when created and uncounts when dropped, so the counts follow the objects
//! on every exit path, unwinding included. Without the feature the token is
//! an empty type and costs nothing.

#[cfg(feature = "test-hooks")]
use std::sync::atomic::{AtomicUsize, Ordering};

/// What a [`Live`] token counts.
#[derive(Debug, Clone, Copy)]
#[cfg_attr(not(feature = "test-hooks"), allow(dead_code))]
pub(crate) enum Kind {
    /// A session's shared state (either driver), with its core.
    Session,
    /// A tokio session task (with its timer).
    Task,
    /// A std driver thread: reader, writer, timer or hook.
    Thread,
    /// A pipe's I/O in a tokio session task.
    Pipe,
    /// A listener's shared state.
    Listener,
    /// A pipe maintainer (`maintain_pipes`).
    Maintainer,
    /// A session's hook task or thread.
    Hook,
}

#[cfg(feature = "test-hooks")]
static COUNTS: [AtomicUsize; 7] = [const { AtomicUsize::new(0) }; 7];

/// One counted resource, for as long as it lives.
#[derive(Debug)]
pub(crate) struct Live {
    #[cfg(feature = "test-hooks")]
    kind: Kind,
}

impl Live {
    #[cfg_attr(not(feature = "test-hooks"), allow(unused_variables))]
    pub(crate) fn new(kind: Kind) -> Self {
        #[cfg(feature = "test-hooks")]
        COUNTS[kind as usize].fetch_add(1, Ordering::Relaxed);
        Self {
            #[cfg(feature = "test-hooks")]
            kind,
        }
    }
}

#[cfg(feature = "test-hooks")]
impl Drop for Live {
    fn drop(&mut self) {
        COUNTS[self.kind as usize].fetch_sub(1, Ordering::Relaxed);
    }
}

/// Live driver resources of this process (feature `test-hooks`).
#[cfg(feature = "test-hooks")]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Resources {
    /// Sessions whose state is alive (any driver).
    pub sessions: usize,
    /// tokio session tasks alive.
    pub session_tasks: usize,
    /// std driver threads alive (readers, writers, timers, hooks).
    pub threads: usize,
    /// Pipes alive in tokio session tasks.
    pub pipes: usize,
    /// Listeners alive.
    pub listeners: usize,
    /// Pipe maintainers alive.
    pub maintainers: usize,
    /// Hook tasks and threads alive.
    pub hooks: usize,
}

/// A snapshot of the live driver resources of this process.
#[cfg(feature = "test-hooks")]
pub fn resources() -> Resources {
    let n = |k: Kind| COUNTS[k as usize].load(Ordering::Relaxed);
    Resources {
        sessions: n(Kind::Session),
        session_tasks: n(Kind::Task),
        threads: n(Kind::Thread),
        pipes: n(Kind::Pipe),
        listeners: n(Kind::Listener),
        maintainers: n(Kind::Maintainer),
        hooks: n(Kind::Hook),
    }
}

/// The sizes of a session's driver tables (feature `test-hooks`): every
/// one is bounded and returns to zero once the handles and waits it
/// concerns are gone.
#[cfg(feature = "test-hooks")]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Tables {
    /// Registered waits (wakers and wait-list entries).
    pub waits: usize,
    /// Pipe events queued for the application.
    pub pipe_events: usize,
    /// Out-of-band join frames held for reservations.
    pub oob: usize,
    /// Carrier halves waiting to be closed.
    pub closing: usize,
    /// Pipes handed to the session task, not yet taken over.
    pub new_pipes: usize,
    /// The lanes' driver state: one when allocated, plus its lane
    /// requests, lanes not yet taken over, resets and connection claims.
    pub lane_state: usize,
    /// Data bytes the core holds ([`crate::proto::session::SessionCore::held_bytes`]).
    pub held_bytes: u64,
    /// Heap and inline bytes of the core
    /// ([`crate::proto::session::SessionCore::memory_usage`]).
    pub memory_usage: usize,
    /// Streams the core holds.
    pub streams: u64,
}

/// Bytes written by the drivers' write calls: all of them, and those of
/// calls that ended at the write-call bound
/// rather than at the batch's end or the carrier's room.
#[cfg(feature = "test-hooks")]
static WRITE_CALLS: [std::sync::atomic::AtomicU64; 2] =
    [const { std::sync::atomic::AtomicU64::new(0) }; 2];

/// Counts a write call of `bytes` that `bounded` cut short.
#[cfg(feature = "test-hooks")]
pub(crate) fn count_write_call(bytes: usize, bounded: bool) {
    WRITE_CALLS[0].fetch_add(bytes as u64, Ordering::Relaxed);
    if bounded {
        WRITE_CALLS[1].fetch_add(bytes as u64, Ordering::Relaxed);
    }
}

/// The bytes of all write calls of this process and of those that ended
/// at the write-call bound, since the last call (which resets them).
#[cfg(feature = "test-hooks")]
pub fn take_write_call_bytes() -> (u64, u64) {
    (
        WRITE_CALLS[0].swap(0, Ordering::Relaxed),
        WRITE_CALLS[1].swap(0, Ordering::Relaxed),
    )
}
