//! Establish for the std driver (`zmux::blocking`): the same handshake on a thread.

use std::io;
use std::time::Duration;

use zmux::blocking::{InboundTransform, PipeIo};

use crate::establish::{ClientConfig, Peer, run_client};
use crate::server::ServerConfig;

/// Runs the client's handshake on `p`, as [`crate::establish`] does. Past `timeout` the
/// carrier is shut down, which needs a carrier with a closer.
///
/// # Errors
///
/// As [`crate::establish`], and `TimedOut` once `timeout` has passed.
pub fn establish(
    mut p: PipeIo,
    cfg: &ClientConfig,
    timeout: Option<Duration>,
) -> io::Result<(PipeIo, Peer)> {
    if let Some(t) = timeout {
        p.limit_handshake_wait(t);
    }
    let watchdog = match timeout {
        Some(t) => p.watchdog(t)?,
        None => None,
    };
    // The host's futures (verifier, app data, signer) do not read the
    // carrier: the timeout drops them.
    let wait = p.handshake_wait();
    let r = wait.block_on(run_client(p, cfg));
    if watchdog.is_some_and(|w| w.fired()) {
        return Err(io::ErrorKind::TimedOut.into());
    }
    r?
}

impl ServerConfig {
    /// The transform of a `zmux::blocking::Listener`, as [`ServerConfig::transform`] is of
    /// a tokio one.
    #[must_use]
    pub fn blocking_transform(self) -> InboundTransform {
        InboundTransform::new(move |p, hint| {
            // Bounded by the listener's handshake timeout, set on the
            // carrier's waits: the host's futures are dropped past it.
            let wait = p.handshake_wait();
            wait.block_on(self.accept(p, hint.source))?
        })
    }
}
