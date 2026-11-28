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

// Receipt owners may be dropped by either the core or a carrier task.
#[cfg(all(feature = "tokio", not(loom)))]
thread_local! {
    static DEFERRED: std::cell::RefCell<Deferred> = const {
        std::cell::RefCell::new(Deferred { depth: 0, callbacks: Vec::new() })
    };
}

#[cfg(all(feature = "tokio", not(loom)))]
struct Deferred {
    depth: usize,
    callbacks: Vec<Box<dyn FnOnce()>>,
}

#[cfg(all(feature = "tokio", not(loom)))]
pub(crate) struct ReceiptScope;

#[cfg(all(feature = "tokio", not(loom)))]
impl ReceiptScope {
    pub(crate) fn new() -> Self {
        let _ = DEFERRED.try_with(|state| state.borrow_mut().depth += 1);
        Self
    }
}

#[cfg(all(feature = "tokio", not(loom)))]
impl Drop for ReceiptScope {
    fn drop(&mut self) {
        let callbacks = DEFERRED.try_with(|state| {
            let mut state = state.borrow_mut();
            state.depth -= 1;
            (state.depth == 0).then(|| std::mem::take(&mut state.callbacks))
        });
        if let Ok(Some(callbacks)) = callbacks {
            for callback in callbacks {
                callback();
            }
        }
    }
}

#[cfg(all(feature = "tokio", not(loom)))]
pub(crate) fn outside_session(callback: impl FnOnce() + 'static) {
    let mut callback = Some(callback);
    let _ = DEFERRED.try_with(|state| {
        let mut state = state.borrow_mut();
        if state.depth != 0 {
            state
                .callbacks
                .push(Box::new(callback.take().expect("pending callback")));
        }
    });
    if let Some(callback) = callback {
        callback();
    }
}
