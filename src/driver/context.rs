//! Which threads drive sessions: a
//! blocking call made on one fails at once with the `OnDriverThread`
//! variant of its error instead of blocking a thread that sessions need.
//!
//! - Threads of the std driver (readers, writers, timers, hook threads) are
//!   marked for their whole life by a [`DriverThread`] guard; callbacks the
//!   driver runs there (a carrier's `Read` or `Write`, an abort closure)
//!   inherit the mark.
//! - Code inside a tokio runtime (`Handle::try_current` succeeds) may run on
//!   a worker that drives tokio sessions: blocking there is refused too.

use std::cell::Cell;
use std::marker::PhantomData;

thread_local! {
    /// Nesting depth of [`DriverThread`] guards on this thread.
    static DRIVER: Cell<usize> = const { Cell::new(0) };
}

/// Marks the current thread as one that drives sessions until dropped.
/// Neither `Send` nor `Sync`: it unmarks the thread that created it.
#[derive(Debug)]
pub(crate) struct DriverThread {
    _live: super::resources::Live,
    _not_send: PhantomData<*const ()>,
}

impl DriverThread {
    pub(crate) fn enter() -> Self {
        DRIVER.set(DRIVER.get() + 1);
        Self {
            _live: super::resources::Live::new(super::resources::Kind::Thread),
            _not_send: PhantomData,
        }
    }
}

impl Drop for DriverThread {
    fn drop(&mut self) {
        // A thread-local being destroyed has nothing left to unmark.
        let _ = DRIVER.try_with(|d| d.set(d.get().saturating_sub(1)));
    }
}

/// Whether the current thread drives sessions.
pub(crate) fn on_driver_thread() -> bool {
    if DRIVER.try_with(Cell::get).unwrap_or(0) > 0 {
        return true;
    }
    #[cfg(feature = "tokio")]
    if tokio::runtime::Handle::try_current().is_ok() {
        return true;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guards_nest_and_unmark() {
        assert!(!on_driver_thread());
        let a = DriverThread::enter();
        let b = DriverThread::enter();
        assert!(on_driver_thread());
        drop(b);
        assert!(on_driver_thread());
        drop(a);
        assert!(!on_driver_thread());
        // Another thread is not marked.
        let _g = DriverThread::enter();
        std::thread::spawn(|| assert!(!on_driver_thread()))
            .join()
            .unwrap();
    }

    #[cfg(feature = "tokio")]
    #[test]
    fn inside_a_tokio_runtime() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        rt.block_on(async { assert!(on_driver_thread()) });
        assert!(!on_driver_thread());
    }
}
