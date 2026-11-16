//! The answer of a host hook that decides: given at once, or later by a
//! future the driver awaits off every lock, bounded by a deadline of the
//! hook's caller (for the hooks of a carrier's setup, its handshake
//! deadline: a decision that misses it refuses, as an error does).
//!
//! A synchronous hook answers [`Decision::Now`], which costs nothing beyond
//! the call: no allocation, no task. [`Decision::Later`] is for a host that
//! needs I/O or another thread (a language binding) to answer; its future
//! is boxed once per decision.

use std::fmt;
use std::future::Future;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::pin::Pin;
use std::task::{Context, Poll};

/// The future of a [`Decision::Later`].
pub type LaterFuture<T> = Pin<Box<dyn Future<Output = T> + Send + 'static>>;

/// A hook's answer: now, or later.
pub enum Decision<T> {
    /// The answer.
    Now(T),
    /// The answer once the future completes. It is polled outside every
    /// lock of zmux, and dropped unfinished when the caller's deadline
    /// passes or the caller ends (the listener closes, the session ends):
    /// the decision then refuses. A panic while it is polled refuses too.
    Later(LaterFuture<T>),
}

impl<T> Decision<T> {
    /// The answer of `future`, later.
    pub fn later(future: impl Future<Output = T> + Send + 'static) -> Self {
        Self::Later(Box::pin(future))
    }

    /// Calls `f`, the host hook that decides, catching a panic of the call
    /// itself: `None` when it panicked (a panic while a later answer is
    /// polled is caught by [`Decision::settle`]). The one place a hook's
    /// call is guarded, for adapters and bindings as for zmux.
    pub fn catch(f: impl FnOnce() -> Self) -> Option<Self> {
        catch_unwind(AssertUnwindSafe(f)).ok()
    }

    /// Whether the answer is given now.
    #[must_use]
    pub const fn is_now(&self) -> bool {
        matches!(self, Self::Now(_))
    }

    /// The answer mapped by `f`.
    #[must_use]
    pub fn map<U>(self, f: impl FnOnce(T) -> U + Send + 'static) -> Decision<U>
    where
        T: 'static,
    {
        match self {
            Self::Now(v) => Decision::Now(f(v)),
            Self::Later(fut) => Decision::later(async move { f(fut.await) }),
        }
    }

    /// The answer, waiting for a later one without a bound: `None` when its
    /// future panicked (contained). The caller bounds the wait.
    pub async fn settle(self) -> Option<T> {
        match self {
            Self::Now(v) => Some(v),
            Self::Later(fut) => Caught(fut).await,
        }
    }
}

impl<T> From<T> for Decision<T> {
    fn from(v: T) -> Self {
        Self::Now(v)
    }
}

impl<T: fmt::Debug> fmt::Debug for Decision<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Now(v) => f.debug_tuple("Now").field(v).finish(),
            Self::Later(_) => f.write_str("Later(..)"),
        }
    }
}

/// Polls a later answer, a panic giving `None`.
struct Caught<T>(LaterFuture<T>);

impl<T> Future for Caught<T> {
    type Output = Option<T>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<T>> {
        let fut = &mut self.0;
        match catch_unwind(AssertUnwindSafe(|| fut.as_mut().poll(cx))) {
            Ok(Poll::Ready(v)) => Poll::Ready(Some(v)),
            Ok(Poll::Pending) => Poll::Pending,
            Err(_) => Poll::Ready(None),
        }
    }
}

/// Calls a synchronous hook, a panic giving `None`.
pub(crate) fn call<T>(f: impl FnOnce() -> Decision<T>) -> Decision<Option<T>>
where
    T: Send + 'static,
{
    match Decision::catch(f) {
        Some(Decision::Now(v)) => Decision::Now(Some(v)),
        Some(later @ Decision::Later(_)) => Decision::later(later.settle()),
        None => Decision::Now(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn poll_once<F: Future>(f: F) -> Poll<F::Output> {
        let mut f = std::pin::pin!(f);
        f.as_mut()
            .poll(&mut Context::from_waker(std::task::Waker::noop()))
    }

    #[test]
    fn answers_now_later_and_on_panic() {
        assert_eq!(poll_once(Decision::Now(3).settle()), Poll::Ready(Some(3)));
        let later = Decision::later(async { 4 }).map(|v| v + 1);
        assert_eq!(poll_once(later.settle()), Poll::Ready(Some(5)));
        let panics: Decision<u8> = Decision::later(async { panic!("hook") });
        assert_eq!(poll_once(panics.settle()), Poll::Ready(None));
        let d = call::<u8>(|| panic!("hook"));
        assert!(matches!(d, Decision::Now(None)));
    }
}
