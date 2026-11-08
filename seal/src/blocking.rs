//! Establish for the std driver (`zmux::blocking`): the same handshake on a thread.

use std::future::Future;
use std::io;
use std::pin::pin;
use std::sync::Arc;
use std::task::{Context, Poll, Wake, Waker};
use std::thread::{self, Thread};
use std::time::Duration;

use zmux::blocking::{InboundTransform, PipeIo};

use crate::establish::{ClientConfig, Peer, run_client};
use crate::server::ServerConfig;

struct Unpark(Thread);

impl Wake for Unpark {
    fn wake(self: Arc<Self>) {
        self.0.unpark();
    }
}

/// Runs a host's Verifier and Gate futures, which wait on their own, on this thread.
fn block_on<F: Future>(f: F) -> F::Output {
    let waker = Waker::from(Arc::new(Unpark(thread::current())));
    let mut cx = Context::from_waker(&waker);
    let mut f = pin!(f);
    loop {
        if let Poll::Ready(v) = f.as_mut().poll(&mut cx) {
            return v;
        }
        thread::park();
    }
}

/// Runs the client's handshake on `p`, as [`crate::establish`] does. Past `timeout` the
/// carrier is shut down, which needs a carrier with a closer.
pub fn establish(
    mut p: PipeIo,
    cfg: &ClientConfig,
    timeout: Option<Duration>,
) -> io::Result<(PipeIo, Peer)> {
    if let Some(t) = timeout {
        p.limit_handshake_wait(t);
    }
    let watchdog = timeout.and_then(|t| p.watchdog(t));
    let r = block_on(run_client(p, cfg));
    if watchdog.is_some_and(|w| w.fired()) {
        return Err(io::ErrorKind::TimedOut.into());
    }
    r
}

impl ServerConfig {
    /// The transform of a `zmux::blocking::Listener`, as [`ServerConfig::transform`] is of
    /// a tokio one.
    pub fn blocking_transform(self) -> InboundTransform {
        InboundTransform::new(move |p, hint| block_on(self.accept(p, hint.source)))
    }
}
