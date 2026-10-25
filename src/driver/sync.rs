//! The synchronization primitives of the drivers' shared units ([`super::wake`],
//! [`super::wait`], [`super::through`]): std's normally, loom's model-checked
//! ones in the loom models (`loom.rs`, `cfg(all(test, loom))`; loom is a
//! dev-dependency).
//!
//! Poisoning is ignored: every critical section of a driver leaves the state
//! it guards consistent before it can panic, so a panic of one holder must not
//! take the session down with it for every other handle.

use std::sync::PoisonError;

#[cfg(all(test, loom))]
pub(crate) use loom::sync::{Mutex, MutexGuard};
#[cfg(all(test, shuttle, not(loom)))]
pub(crate) use shuttle::sync::{Mutex, MutexGuard};
#[cfg(not(any(all(test, loom), all(test, shuttle))))]
pub(crate) use std::sync::{Mutex, MutexGuard};

/// Locks `m`.
pub(crate) fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

#[cfg(any(feature = "tokio", all(test, loom)))]
pub(crate) use side::{
    AtomicBool, AtomicU8, AtomicWaker, Ordering, TryMutex, TryMutexGuard, try_lock_side,
};

/// The primitives of a pipe's sides ([`super::through`]). A side is only
/// ever tried, never waited for: by a holder of the core lock, and by the
/// session task, which skips a busy side.
#[cfg(any(feature = "tokio", all(test, loom)))]
mod side {
    #[cfg(all(test, loom))]
    pub(crate) use super::model::{TryMutex, TryMutexGuard};
    /// One waker slot: `register` keeps the newest waker, `wake` takes and
    /// wakes it; a wake that races a registration wakes the new waker.
    #[cfg(not(all(test, loom)))]
    pub(crate) use atomic_waker::AtomicWaker;
    #[cfg(all(test, loom))]
    pub(crate) use loom::sync::atomic::{AtomicBool, AtomicU8, Ordering};
    #[cfg(not(all(test, loom)))]
    pub(crate) use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
    /// A mutex that is only tried (a pipe's side).
    #[cfg(not(all(test, loom)))]
    pub(crate) use std::sync::{Mutex as TryMutex, MutexGuard as TryMutexGuard};

    /// Locks a side if nobody holds it.
    #[cfg(not(all(test, loom)))]
    pub(crate) fn try_lock_side<T>(m: &TryMutex<T>) -> Option<TryMutexGuard<'_, T>> {
        use std::sync::TryLockError;
        match m.try_lock() {
            Ok(g) => Some(g),
            Err(TryLockError::Poisoned(p)) => Some(p.into_inner()),
            Err(TryLockError::WouldBlock) => None,
        }
    }

    /// The loom stand-in of `atomic_waker::AtomicWaker`: the same
    /// operations over a model mutex (at least its guarantees).
    #[cfg(all(test, loom))]
    #[derive(Default)]
    pub(crate) struct AtomicWaker(loom::sync::Mutex<Option<std::task::Waker>>);

    #[cfg(all(test, loom))]
    impl AtomicWaker {
        pub(crate) fn new() -> Self {
            Self::default()
        }

        pub(crate) fn register(&self, waker: &std::task::Waker) {
            let mut slot = super::lock(&self.0);
            if !slot.as_ref().is_some_and(|w| w.will_wake(waker)) {
                *slot = Some(waker.clone());
            }
        }

        pub(crate) fn wake(&self) {
            let w = super::lock(&self.0).take();
            if let Some(w) = w {
                w.wake();
            }
        }
    }

    /// Locks a side if nobody holds it.
    #[cfg(all(test, loom))]
    pub(crate) fn try_lock_side<T>(m: &TryMutex<T>) -> Option<TryMutexGuard<'_, T>> {
        m.try_lock()
    }
}

#[cfg(all(feature = "blocking", not(loom)))]
pub(crate) use park::{park, thread_waker};

/// Threads of the std driver wait like tasks: each has a `Waker` that
/// unparks it, registered in the same lists and woken the same way (after
/// the lock). Shuttle's threads in its models (`shuttle.rs`).
#[cfg(all(feature = "blocking", not(loom)))]
mod park {
    use std::sync::Arc;
    use std::task::{Wake, Waker};
    use std::time::Instant;

    #[cfg(all(test, shuttle))]
    use shuttle::{thread, thread_local};
    #[cfg(not(all(test, shuttle)))]
    use std::{thread, thread_local};

    struct Unpark(thread::Thread);

    impl Wake for Unpark {
        fn wake(self: Arc<Self>) {
            self.0.unpark();
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.0.unpark();
        }
    }

    thread_local! {
        static THREAD_WAKER: Waker = Waker::from(Arc::new(Unpark(thread::current())));
    }

    /// The current thread's waker (created once per thread).
    pub(crate) fn thread_waker() -> Waker {
        THREAD_WAKER.with(Waker::clone)
    }

    /// Parks the current thread until its waker is woken or `deadline`
    /// passes. It may return early: callers check their condition again. A
    /// wake-up that comes before the park is not lost (it makes the park
    /// return at once).
    pub(crate) fn park(deadline: Option<Instant>) {
        match deadline {
            None => thread::park(),
            Some(d) => thread::park_timeout(d.saturating_duration_since(Instant::now())),
        }
    }
}

/// The side mutex of the loom models. Loom's own mutex treats a `try_lock`
/// that waits to be scheduled while another thread holds the lock as blocked
/// until the lock is released, so a thread that holds the core lock and
/// tries a pipe's side would wait for the side's holder, which waits for the
/// core lock: a deadlock the real `try_lock` cannot have. This one is a
/// model-checked atomic lock bit whose `try_lock` fails at once (sides are
/// never waited for). The data sits in a std mutex that is never contended:
/// the bit is taken before it and released after it.
#[cfg(all(test, loom))]
mod model {
    use std::sync::PoisonError;

    use loom::sync::atomic::{AtomicBool, Ordering};

    #[derive(Default)]
    pub(crate) struct TryMutex<T> {
        locked: AtomicBool,
        data: std::sync::Mutex<T>,
    }

    /// Fields drop in order: the data's guard, then the bit.
    pub(crate) struct TryMutexGuard<'a, T> {
        data: std::sync::MutexGuard<'a, T>,
        _bit: Unlock<'a>,
    }

    struct Unlock<'a>(&'a AtomicBool);

    impl Drop for Unlock<'_> {
        fn drop(&mut self) {
            self.0.store(false, Ordering::Release);
        }
    }

    impl<T> TryMutex<T> {
        pub(crate) fn new(data: T) -> Self {
            Self {
                locked: AtomicBool::new(false),
                data: std::sync::Mutex::new(data),
            }
        }

        pub(crate) fn try_lock(&self) -> Option<TryMutexGuard<'_, T>> {
            self.locked
                .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
                .ok()?;
            Some(TryMutexGuard {
                data: self.data.lock().unwrap_or_else(PoisonError::into_inner),
                _bit: Unlock(&self.locked),
            })
        }
    }

    impl<T> std::ops::Deref for TryMutexGuard<'_, T> {
        type Target = T;

        fn deref(&self) -> &T {
            &self.data
        }
    }

    impl<T> std::ops::DerefMut for TryMutexGuard<'_, T> {
        fn deref_mut(&mut self) -> &mut T {
            &mut self.data
        }
    }
}
