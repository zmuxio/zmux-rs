//! Tracks the locks across which host calls and wake-ups cannot run.
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
pub(crate) struct Token(());

#[cfg(any(debug_assertions, all(test, loom)))]
impl Token {
    pub(crate) fn new() -> Self {
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
pub(crate) fn assert_none() {
    #[cfg(any(debug_assertions, all(test, loom)))]
    let _ = HELD.try_with(|h| assert_eq!(h.get(), 0, "host code or wake-up under a driver lock"));
}

/// Whether this thread holds a core lock.
#[cfg(all(test, any(debug_assertions, loom)))]
pub(crate) fn any() -> bool {
    HELD.try_with(|h| h.get() > 0).unwrap_or(false)
}
