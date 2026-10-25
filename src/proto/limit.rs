//! The limiter interface: one small interface through
//! which any external limiter, budget or meter acts on bytes that zmux
//! forwards itself, the datagrams of a session and
//! the relay helper, without zmux knowing what it implements.
//!
//! Rate limiting, byte budgets and quotas are not part of zmux: stream
//! I/O is the standard interface of the language, so a general limiter
//! wraps it, and flow control turns a reader it slows into backpressure on
//! the peer. Datagram calls are not stream I/O, so a session takes a
//! limiter for them ([`DatagramLimiter`]).

use std::fmt;
use std::future::Future;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;
use std::task::{Context, Poll};

/// An external limiter.
///
/// Neither call reserves anything: the caller forwards at most the
/// allowance and then calls [`Limiter::charge`] with what it actually
/// forwarded, so a wait that is cancelled leaves no state behind. Callers
/// sharing one limiter may each be allowed the same bytes before any of
/// them charges: a shared limiter can overshoot by up to one allowance per
/// concurrent caller, which the following charges account for; a limiter
/// that must never overshoot hands out allowances it tracks itself. A
/// limiter shared by many streams or sessions (a group or a hierarchy) is
/// the limiter's own business.
///
/// zmux never holds a buffer of its own while it waits in
/// [`Limiter::poll_ready`], and calls every method outside every lock of
/// the session: a limiter may take a lock of its own (one shared by a group
/// of sessions) or call into a session without risking a deadlock against
/// a thread that holds that lock and calls the session. For datagrams, a
/// sender asks [`Limiter::try_ready`] before it takes the session's lock
/// and charges after releasing it, once the datagram is queued; a received
/// datagram passes the limiter on the driver, outside the lock, before it
/// enters the application's queue. [`Limiter::try_ready`] and
/// [`Limiter::charge`] must not block. A panic in them counts as an
/// allowance of 0, and in `charge` is ignored.
pub trait Limiter: Send + Sync {
    /// Waits until the limiter allows at least `min` bytes, or as many as
    /// it can ever allow at once if that is less (its burst), and returns
    /// how many it allows now, at most `max` (1 <= `min` <= `max`). `min`
    /// keeps a caller at the edge of a budget from being fed one byte at a
    /// time.
    fn poll_ready(&self, cx: &mut Context<'_>, min: usize, max: usize) -> Poll<usize>;

    /// The allowance now, at most `max`; 0 when the limiter would have to
    /// wait.
    fn try_ready(&self, max: usize) -> usize;

    /// Accounts for `n` bytes forwarded.
    fn charge(&self, n: usize);
}

/// [`Limiter::poll_ready`] as a future. Dropping it leaves no state in the
/// limiter.
pub fn ready<L: Limiter + ?Sized>(
    limiter: &L,
    min: usize,
    max: usize,
) -> impl Future<Output = usize> + '_ {
    std::future::poll_fn(move |cx| limiter.poll_ready(cx, min, max))
}

/// Polices one datagram of `len` payload bytes: it
/// passes when the limiter, asked without waiting, allows all of it, and
/// is then charged; otherwise it is to be dropped. An empty datagram
/// passes without a call.
pub fn police<L: Limiter + ?Sized>(limiter: &L, len: usize) -> bool {
    let pass = allows(Some(limiter), len);
    if pass {
        charge(Some(limiter), len);
    }
    pass
}

/// Whether a datagram of `len` payload bytes passes `limiter`, asked
/// without waiting and without charging it (a panic allows nothing). No
/// limiter, or an empty datagram, passes without a call.
pub(crate) fn allows<L: Limiter + ?Sized>(limiter: Option<&L>, len: usize) -> bool {
    match limiter {
        Some(l) if len > 0 => {
            catch_unwind(AssertUnwindSafe(|| l.try_ready(len))).unwrap_or(0) >= len
        }
        _ => true,
    }
}

/// Charges `limiter` with `n` bytes (a panic is ignored; nothing for 0).
pub(crate) fn charge<L: Limiter + ?Sized>(limiter: Option<&L>, n: usize) {
    if let Some(l) = limiter
        && n > 0
    {
        let _ = catch_unwind(AssertUnwindSafe(|| l.charge(n)));
    }
}

/// The datagram limiters of a session, one per direction (the hook
/// `datagram_limiter`). Datagram limiting polices and never
/// shapes: a datagram passes when the direction's limiter allows its whole
/// payload at once, and is otherwise dropped and counted
/// (`datagrams_dropped_limit`): on send before it is queued, on receive
/// before it is queued for the application, always outside the session's
/// lock (see [`Limiter`]). Without a limiter (the default) nothing is
/// called; with one, each datagram costs two calls and no allocation.
#[derive(Clone, Default)]
pub struct DatagramLimiter {
    /// Limits the datagrams this endpoint sends, session and stream
    /// datagrams together.
    pub send: Option<Arc<dyn Limiter>>,
    /// Limits the datagrams received from the peer.
    pub receive: Option<Arc<dyn Limiter>>,
}

impl fmt::Debug for DatagramLimiter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DatagramLimiter")
            .field("send", &self.send.is_some())
            .field("receive", &self.receive.is_some())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// A budget of bytes that never refills.
    struct Budget(AtomicUsize);

    impl Limiter for Budget {
        fn poll_ready(&self, _: &mut Context<'_>, _: usize, max: usize) -> Poll<usize> {
            Poll::Ready(self.try_ready(max))
        }
        fn try_ready(&self, max: usize) -> usize {
            self.0.load(Ordering::Relaxed).min(max)
        }
        fn charge(&self, n: usize) {
            self.0.fetch_sub(n, Ordering::Relaxed);
        }
    }

    struct Panics;

    impl Limiter for Panics {
        fn poll_ready(&self, _: &mut Context<'_>, _: usize, _: usize) -> Poll<usize> {
            Poll::Pending
        }
        fn try_ready(&self, _: usize) -> usize {
            panic!("limiter")
        }
        fn charge(&self, _: usize) {}
    }

    #[test]
    fn a_datagram_passes_only_when_its_whole_payload_is_allowed() {
        let b = Budget(AtomicUsize::new(1500));
        assert!(police(&b, 1000));
        assert!(!police(&b, 1000), "500 left: a datagram is never cut");
        assert!(police(&b, 500));
        assert!(police(&b, 0));
        assert_eq!(b.0.load(Ordering::Relaxed), 0);
        assert!(!police(&Panics, 1), "a panic allows nothing");
    }
}
