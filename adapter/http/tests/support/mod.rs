//! A bounded test runner shared by the test binaries of this crate.
//!
//! The body runs on a thread of its own, with its own runtime, and the
//! calling test thread waits for it with a deadline on the wall clock. A body
//! that stalls, or a runtime that cannot be dropped (a task that never
//! yields, a blocking call that never returns), fails its test at the
//! deadline instead of holding the binary: the stuck thread is left behind
//! and ends with the process. The deadline is only the guard against a hang;
//! what a test waits for inside has bounds of its own.

use std::future::Future;
use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};
use std::sync::mpsc::{RecvTimeoutError, channel};
use std::time::Duration;

/// How long dropping the runtime may take after the body ended.
const SHUTDOWN: Duration = Duration::from_secs(10);

/// Runs the future `f` builds on a multi-thread runtime of `workers` threads
/// and fails when it has not finished within `secs` seconds. `f` is called
/// on the runtime's thread, so the future need not be `Send`.
pub(crate) fn run<F, Fut>(workers: usize, secs: u64, f: F)
where
    F: FnOnce() -> Fut + Send + 'static,
    Fut: Future<Output = ()>,
{
    let (done, result) = channel();
    let body = std::thread::Builder::new()
        .name("bounded test".into())
        .spawn(move || {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(workers)
                .enable_all()
                .build()
                .expect("a runtime");
            let r = catch_unwind(AssertUnwindSafe(|| {
                rt.block_on(async {
                    tokio::time::timeout(Duration::from_secs(secs), f())
                        .await
                        .expect("the test did not finish in time");
                });
            }));
            rt.shutdown_timeout(SHUTDOWN);
            let _ = done.send(r);
        })
        .expect("a thread");
    match result.recv_timeout(Duration::from_secs(secs) + SHUTDOWN * 2) {
        Ok(Ok(())) => body.join().expect("the test thread ended"),
        Ok(Err(panic)) => resume_unwind(panic),
        Err(RecvTimeoutError::Timeout) => panic!(
            "the test did not end within {secs} s and its runtime did not stop \
             (the thread is left behind)"
        ),
        Err(RecvTimeoutError::Disconnected) => panic!("the test thread died without a result"),
    }
}
