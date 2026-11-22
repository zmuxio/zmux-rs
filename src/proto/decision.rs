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
use std::task::Poll;

/// The unwind boundary for a host invocation or one poll of its future.
pub(crate) fn host<T>(call: impl FnOnce() -> T) -> Option<T> {
    protected(call).ok()
}

fn protected<T>(call: impl FnOnce() -> T) -> std::thread::Result<T> {
    crate::lock_scope::assert_none();
    catch_unwind(AssertUnwindSafe(call))
}

pub(crate) async fn host_future<F: Future>(call: impl FnOnce() -> F) -> Option<F::Output> {
    host_result(call).await.ok()
}

/// Preserve the panic until the owner decides how its API reports it.
pub(crate) async fn host_result<F: Future>(
    call: impl FnOnce() -> F,
) -> std::thread::Result<F::Output> {
    struct HostFuture<F>(Option<Pin<Box<F>>>);
    impl<F> HostFuture<F> {
        fn finish(&mut self) -> std::thread::Result<()> {
            let f = self.0.take();
            protected(|| drop(f))
        }
    }
    impl<F> Drop for HostFuture<F> {
        fn drop(&mut self) {
            if self.0.is_some() {
                let _ = self.finish();
            }
        }
    }
    let mut future = HostFuture(Some(Box::pin(protected(call)?)));
    let result = std::future::poll_fn(|cx| {
        match protected(|| {
            future
                .0
                .as_mut()
                .expect("running host future")
                .as_mut()
                .poll(cx)
        }) {
            Ok(p) => p.map(Ok),
            Err(e) => Poll::Ready(Err(e)),
        }
    })
    .await;
    let cleanup = future.finish();
    let output = result?;
    cleanup.map(|()| output)
}

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
        host(f)
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
            Self::Later(fut) => host_future(|| fut).await,
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
    use std::task::Context;

    fn poll_once<F: Future>(f: F) -> Poll<F::Output> {
        let mut f = std::pin::pin!(f);
        f.as_mut()
            .poll(&mut Context::from_waker(std::task::Waker::noop()))
    }

    #[test]
    // HS-07
    fn host_future_destructor_panic_is_contained_on_return_and_cancellation() {
        struct Host(bool);
        impl Drop for Host {
            fn drop(&mut self) {
                panic!("host cleanup");
            }
        }
        impl Future for Host {
            type Output = ();
            fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<()> {
                if self.0 {
                    Poll::Ready(())
                } else {
                    Poll::Pending
                }
            }
        }
        assert_eq!(poll_once(host_future(|| Host(true))), Poll::Ready(None));
        assert_eq!(poll_once(host_future(|| Host(false))), Poll::Pending);
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
