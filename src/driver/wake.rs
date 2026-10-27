//! Wake-ups after unlocking, by construction.
//!
//! A session's state lives behind one mutex (the core lock). Whoever holds it
//! never wakes a task or a thread: a woken task would run on another worker
//! at once and block on the lock its waker still holds. Instead, every
//! wake-up decided under the lock is pushed into the state's [`WakeList`], and
//! [`Locked`], the only way to the state, wakes them after it released the
//! mutex:
//!
//! ```text
//! let mut s = Locked::lock(&mutex);   // lock
//! s.wakes.push(waker);                // decide (under the lock)
//! drop(s);                            // unlock, then wake
//! ```
//!
//! A wake-up decided under the lock is never lost: the list is moved out of
//! the state while the lock is still held, so the next holder starts with an
//! empty list and the wake-ups of each critical section are delivered by the
//! thread that ran it, right after its unlock.

use std::task::Waker;

use super::sync::{Mutex, MutexGuard, lock};

/// Wake-ups an inline buffer holds before the list allocates.
const INLINE: usize = 4;

/// Wakers collected under a lock, to wake once it is released. The first
/// few live inline (a critical section rarely wakes more than the reader of
/// one stream and the session task), so collecting them does not allocate.
/// Dropping the list wakes every waker in it.
#[derive(Default)]
pub(crate) struct WakeList {
    inline: [Option<Waker>; INLINE],
    len: usize,
    more: Vec<Waker>,
}

impl WakeList {
    /// No wake-up is pending.
    pub(crate) fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Adds a wake-up.
    pub(crate) fn push(&mut self, waker: Waker) {
        if let Some(slot) = self.inline.get_mut(self.len) {
            *slot = Some(waker);
        } else {
            self.more.push(waker);
        }
        self.len += 1;
    }

    /// Adds wake-ups.
    pub(crate) fn extend(&mut self, wakers: impl IntoIterator<Item = Waker>) {
        for w in wakers {
            self.push(w);
        }
    }

    /// Wakes everything collected.
    pub(crate) fn wake_all(&mut self) {
        if self.len == 0 {
            return;
        }
        held::assert_none();
        for w in self.inline.iter_mut().filter_map(Option::take) {
            w.wake();
        }
        for w in self.more.drain(..) {
            w.wake();
        }
        self.len = 0;
    }
}

impl Drop for WakeList {
    fn drop(&mut self) {
        self.wake_all();
    }
}

/// State behind a session lock that defers work until the lock is released.
pub trait Defer {
    /// The deferred work; dropping it does the work (wakes the wakers).
    type After;

    /// Moves the deferred work out, `None` when there is none.
    fn take_after(&mut self) -> Option<Self::After>;
}

/// The core lock: a guard of the state that runs the state's deferred work
/// (see [`Defer`]) once the mutex is released. Fields drop in declaration
/// order: `guard` (unlock), then `after` (wake).
pub struct Locked<'a, T: Defer> {
    guard: MutexGuard<'a, T>,
    #[cfg(any(debug_assertions, all(test, loom)))]
    _held: held::Token,
    after: Option<T::After>,
}

impl<'a, T: Defer> Locked<'a, T> {
    /// Locks `mutex`.
    pub(crate) fn lock(mutex: &'a Mutex<T>) -> Self {
        let guard = lock(mutex);
        Self {
            guard,
            #[cfg(any(debug_assertions, all(test, loom)))]
            _held: held::Token::new(),
            after: None,
        }
    }
}

impl<T: Defer> Drop for Locked<'_, T> {
    fn drop(&mut self) {
        // Taken while the lock is held; run when `after` drops, after the
        // guard.
        self.after = self.guard.take_after();
    }
}

impl<T: Defer> std::ops::Deref for Locked<'_, T> {
    type Target = T;

    fn deref(&self) -> &T {
        &self.guard
    }
}

impl<T: Defer> std::ops::DerefMut for Locked<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        &mut self.guard
    }
}

/// Debug check of the rule above: a [`WakeList`] is never woken by a thread
/// that holds a core lock. Counts the core locks the current thread holds.
mod held {
    #[cfg(all(debug_assertions, not(all(test, loom)), not(all(test, shuttle))))]
    thread_local! {
        static HELD: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    }

    // Shuttle runs its threads on one OS thread: a thread-local of its own.
    #[cfg(all(debug_assertions, test, shuttle, not(loom)))]
    shuttle::thread_local! {
        static HELD: std::cell::Cell<usize> = std::cell::Cell::new(0);
    }

    #[cfg(all(test, loom))]
    loom::thread_local! {
        static HELD: std::cell::Cell<usize> = std::cell::Cell::new(0);
    }

    /// One core lock held by this thread, from after locking until after
    /// unlocking.
    #[cfg(any(debug_assertions, all(test, loom)))]
    pub(super) struct Token(());

    #[cfg(any(debug_assertions, all(test, loom)))]
    impl Token {
        pub(super) fn new() -> Self {
            // `try_with`: a lock may be taken while thread-locals are
            // destroyed.
            let _ = HELD.try_with(|h| h.set(h.get() + 1));
            Self(())
        }
    }

    #[cfg(any(debug_assertions, all(test, loom)))]
    impl Drop for Token {
        fn drop(&mut self) {
            let _ = HELD.try_with(|h| h.set(h.get().saturating_sub(1)));
        }
    }

    /// Asserts that this thread holds no core lock.
    pub(super) fn assert_none() {
        #[cfg(any(debug_assertions, all(test, loom)))]
        let _ = HELD.try_with(|h| assert_eq!(h.get(), 0, "woken under a core lock"));
    }

    /// Whether this thread holds a core lock.
    #[cfg(all(test, loom))]
    pub(crate) fn any() -> bool {
        HELD.try_with(|h| h.get() > 0).unwrap_or(false)
    }
}

#[cfg(all(test, loom))]
pub(crate) use held::any as lock_held;

#[cfg(all(test, not(loom)))]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::Wake;

    use super::*;

    /// Counts wake-ups, and checks that the state's mutex is free when woken.
    struct Check {
        woken: AtomicUsize,
        mutex: Arc<Mutex<State>>,
    }

    impl Wake for Check {
        fn wake(self: Arc<Self>) {
            assert!(self.mutex.try_lock().is_ok(), "woken under the lock");
            self.woken.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[derive(Default)]
    struct State {
        wakes: WakeList,
    }

    impl Defer for State {
        type After = WakeList;

        fn take_after(&mut self) -> Option<WakeList> {
            (!self.wakes.is_empty()).then(|| std::mem::take(&mut self.wakes))
        }
    }

    #[test]
    fn wake_ups_run_after_the_unlock_including_overflow() {
        let mutex = Arc::new(Mutex::new(State::default()));
        let check = Arc::new(Check {
            woken: AtomicUsize::new(0),
            mutex: mutex.clone(),
        });
        {
            let mut s = Locked::lock(&mutex);
            for _ in 0..INLINE + 3 {
                s.wakes.push(Waker::from(check.clone()));
            }
            assert_eq!(check.woken.load(Ordering::Relaxed), 0);
        }
        assert_eq!(check.woken.load(Ordering::Relaxed), INLINE + 3);
        // The next holder starts empty.
        assert!(Locked::lock(&mutex).wakes.is_empty());
    }
}
