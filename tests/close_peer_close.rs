//! A closing endpoint's linger on a pipe ends once the peer's `CONNECTION_CLOSE` was read on
//! it and its own was handed to the carrier: over a carrier without a half-close (its write
//! side cannot be shut alone, so the peer's end of input never comes) both carriers close at
//! once, not at the linger timeout; a peer that sends nothing more still ends at the linger.
//! Every wait is bounded.

#[path = "common/clock.rs"]
mod clock;

use std::any::Any;
use std::convert::Infallible;
use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, mpsc};
use std::task::{Context, Poll};
use std::time::Duration;

use clock::ManualClock;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{mpsc as async_mpsc, oneshot};
use zmux::{ClockDomain, Config, MonotonicClock, SessionError, SessionState, StreamError, VarInt};

const WATCHDOG: Duration = Duration::from_secs(30);
const LINGER: Duration = Duration::from_secs(2);

fn config(linger: Duration) -> Config {
    let mut c = Config::default();
    c.test_hooks().linger_timeout = Some(linger);
    c
}

fn manual_config() -> (ManualClock, Config) {
    let mut config = config(LINGER);
    let (clock, domain) = ManualClock::domain(Duration::ZERO);
    config.clock_domain = domain;
    (clock, config)
}

fn hint() -> zmux::PipeHint {
    zmux::PipeHint::from_peer(([127, 0, 0, 1], 0).into())
}

fn closed_with_42(e: &SessionError) -> bool {
    matches!(e, SessionError::ApplicationClosed { code, remote: true, .. } if *code == VarInt::from_u32(42))
}

// ---- tokio ------------------------------------------------------------------------------

/// Retains the underlying transports after the driver releases its wrappers,
/// so EOF alone cannot settle the other endpoint's linger.
type Retained = Arc<Mutex<Vec<Box<dyn Any + Send>>>>;

/// The receiver ends when the driver has released every carrier half.
struct CarrierLifetime {
    retained: Retained,
    open: async_mpsc::UnboundedSender<Infallible>,
}

impl CarrierLifetime {
    fn new() -> (Self, async_mpsc::UnboundedReceiver<Infallible>) {
        let (open, remaining) = async_mpsc::unbounded_channel();
        (
            Self {
                retained: Arc::default(),
                open,
            },
            remaining,
        )
    }

    fn retain(self) -> Retained {
        self.retained
    }
}

struct NoHalfClose<T: Send + 'static> {
    io: Option<T>,
    silence: Arc<Silence>,
    retained: Retained,
    _open: async_mpsc::UnboundedSender<Infallible>,
}

impl<T: Send + 'static> NoHalfClose<T> {
    fn new(io: T, silence: &Arc<Silence>, lifetime: &CarrierLifetime) -> Self {
        Self {
            io: Some(io),
            silence: silence.clone(),
            retained: lifetime.retained.clone(),
            _open: lifetime.open.clone(),
        }
    }
}

impl<T: Send + 'static> Drop for NoHalfClose<T> {
    fn drop(&mut self) {
        if let Some(io) = self.io.take() {
            self.retained.lock().unwrap().push(Box::new(io));
        }
    }
}

impl<T: AsyncRead + Unpin + Send + 'static> AsyncRead for NoHalfClose<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.silence.deaf.load(Ordering::SeqCst) {
            // Woken by nothing: the carrier is dropped or it stays silent.
            return Poll::Pending;
        }
        Pin::new(self.io.as_mut().expect("open")).poll_read(cx, buf)
    }
}

impl<T: AsyncWrite + Unpin + Send + 'static> AsyncWrite for NoHalfClose<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(self.io.as_mut().expect("open")).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(self.io.as_mut().expect("open")).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[derive(Default)]
struct WriteFailureGate {
    armed: AtomicBool,
    failed: AtomicBool,
    reader: atomic_waker::AtomicWaker,
}

struct WriteFailsAfterArm {
    io: tokio::io::DuplexStream,
    gate: Arc<WriteFailureGate>,
}

impl AsyncRead for WriteFailsAfterArm {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.gate.armed.load(Ordering::SeqCst) {
            self.gate.reader.register(cx.waker());
            if !self.gate.failed.load(Ordering::SeqCst) {
                return Poll::Pending;
            }
        }
        Pin::new(&mut self.io).poll_read(cx, buf)
    }
}

impl AsyncWrite for WriteFailsAfterArm {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.gate.armed.load(Ordering::SeqCst) {
            self.gate.failed.store(true, Ordering::SeqCst);
            self.gate.reader.wake();
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        Pin::new(&mut self.io).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_shutdown(cx)
    }
}

async fn fail_write_before_reading(peer_closes: bool) -> SessionError {
    tokio::time::timeout(Duration::from_secs(5), async {
        let gate = Arc::new(WriteFailureGate::default());
        let config = config(Duration::from_millis(250));
        let listener =
            zmux::Listener::new(config.clone(), zmux::ListenerConfig::default()).unwrap();
        let (a, b) = tokio::io::duplex(1 << 16);
        let l = listener.clone();
        tokio::spawn(async move {
            let _ = l.handle_pipe(zmux::PipeIo::new(b), hint()).await;
        });
        let client = zmux::Session::connect(
            zmux::PipeIo::new(WriteFailsAfterArm {
                io: a,
                gate: gate.clone(),
            }),
            config,
        )
        .await
        .unwrap();
        let server = listener.accept().await.unwrap();
        let mut stream = client.open_uni().await.unwrap();
        gate.armed.store(true, Ordering::SeqCst);
        if peer_closes {
            server
                .close_with_error(VarInt::from_u32(9), b"peer close")
                .await;
        }
        // The application write may be buffered or may observe the carrier failure.
        let _ = stream.write_all(b"trigger write failure").await;
        let error = client.closed().await;
        assert!(gate.failed.load(Ordering::SeqCst));
        error
    })
    .await
    .expect("the session closes")
}

#[tokio::test]
async fn lane_zero_write_failure_preserves_the_peer_close() {
    let error = fail_write_before_reading(true).await;
    assert!(
        matches!(error, SessionError::ApplicationClosed { code, remote: true, .. }
            if code == VarInt::from_u32(9)),
        "{error:?}"
    );
}

#[tokio::test]
async fn lane_zero_write_failure_with_no_peer_close_keeps_the_write_error() {
    let error = fail_write_before_reading(false).await;
    assert!(
        matches!(
            error,
            SessionError::PipesLost {
                last: Some(zmux::PipeFailure::Carrier(io::ErrorKind::BrokenPipe)),
            }
        ),
        "{error:?}"
    );
}

/// How the two ends of a carrier are made.
#[derive(Clone, Copy, Debug)]
enum Kind {
    Duplex,
    Tcp,
}

struct Pair {
    client: zmux::Session,
    server: zmux::Session,
    silence: Arc<Silence>,
    remaining: async_mpsc::UnboundedReceiver<Infallible>,
    _retained: Retained,
    _listener: zmux::Listener,
}

async fn tokio_pair(kind: Kind, config: Config) -> Pair {
    let silence = Arc::new(Silence::default());
    let (lifetime, remaining) = CarrierLifetime::new();
    let listener = zmux::Listener::new(config.clone(), zmux::ListenerConfig::default())
        .expect("valid listener configuration");
    let never = Arc::new(Silence::default());
    let (client_io, server_io) = match kind {
        Kind::Duplex => {
            let (a, b) = tokio::io::duplex(1 << 16);
            (
                zmux::PipeIo::new(NoHalfClose::new(a, &never, &lifetime)),
                zmux::PipeIo::new(NoHalfClose::new(b, &silence, &lifetime)),
            )
        }
        Kind::Tcp => {
            let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let a = tokio::net::TcpStream::connect(l.local_addr().unwrap())
                .await
                .unwrap();
            let (b, _) = l.accept().await.unwrap();
            (
                zmux::PipeIo::new(NoHalfClose::new(a, &never, &lifetime)),
                zmux::PipeIo::new(NoHalfClose::new(b, &silence, &lifetime)),
            )
        }
    };
    let l = listener.clone();
    tokio::spawn(async move {
        let _ = l.handle_pipe(server_io, hint()).await;
    });
    let client = zmux::Session::connect(client_io, config).await.unwrap();
    let server = listener.accept().await.unwrap();
    Pair {
        client,
        server,
        silence,
        remaining,
        _retained: lifetime.retain(),
        _listener: listener,
    }
}

/// Delivers the application's close code and waits for both carriers to be
/// released without advancing their linger clocks.
async fn tokio_close(mut p: Pair, server_closes: bool) {
    let (closer, other) = if server_closes {
        (&p.server, &p.client)
    } else {
        (&p.client, &p.server)
    };
    let (mut w, mut r) = other.open_bi().await.unwrap();
    w.write_all(b"request").await.unwrap();
    tokio::io::AsyncWriteExt::flush(&mut w).await.unwrap();
    let (_sw, mut sr) = closer.accept_bi().await.unwrap();
    let mut got = [0; 7];
    tokio::io::AsyncReadExt::read_exact(&mut sr, &mut got)
        .await
        .unwrap();
    let closer = closer.clone();
    let closing = tokio::spawn(async move {
        closer.close_with_error(VarInt::from_u32(42), b"done").await;
    });
    let e = r.read_to_end(1 << 10).await.unwrap_err();
    let _ = w.finish();
    match e {
        zmux::ReadToEndError::Read(StreamError::SessionLost(e)) => assert!(closed_with_42(&e)),
        e => panic!("{e}"),
    }
    assert!(p.remaining.recv().await.is_none());
    closing.await.unwrap();
}

async fn tokio_prompt(kind: Kind) {
    for server_closes in [true, false] {
        tokio::time::timeout(WATCHDOG, async {
            let (_, config) = manual_config();
            tokio_close(tokio_pair(kind, config).await, server_closes).await;
        })
        .await
        .expect("both carriers settle while the linger clock is stopped");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_close_without_half_close_ends_at_once_over_a_duplex() {
    tokio_prompt(Kind::Duplex).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_close_without_half_close_ends_at_once_over_tcp() {
    tokio_prompt(Kind::Tcp).await;
}

/// A peer that never sends its `CONNECTION_CLOSE` nor ends its input leaves the linger as the
/// bound, and the carriers close at it.
async fn tokio_silent(kind: Kind) {
    let (clock, config) = manual_config();
    let mut timers = clock.registrations();
    tokio::time::timeout(WATCHDOG, async {
        let mut p = tokio_pair(kind, config).await;
        p.silence.deaf.store(true, Ordering::SeqCst);
        p.server
            .close_with_error(VarInt::from_u32(42), b"done")
            .await;
        assert_eq!(p.server.state(), SessionState::Closing);
        clock.advance(LINGER);
        p.server.closed().await;
        assert!(p.remaining.recv().await.is_none());
    })
    .await
    .unwrap_or_else(|_| {
        let registered: Vec<_> = std::iter::from_fn(|| timers.try_recv().ok()).collect();
        panic!("the silent carrier did not settle at the injected linger deadline; registered timers: {registered:?}");
    });
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_silent_peer_leaves_the_linger_as_the_bound_over_a_duplex() {
    tokio_silent(Kind::Duplex).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_silent_peer_leaves_the_linger_as_the_bound_over_tcp() {
    tokio_silent(Kind::Tcp).await;
}

/// A carrier whose graceful shutdown never completes (its peer went away).
struct NeverShutdown<T>(T);

impl<T: AsyncRead + Unpin> AsyncRead for NeverShutdown<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for NeverShutdown<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Pending
    }
}

/// A carrier whose shutdown never completes is aborted once the session is
/// closed and its last write had the time to finish, not left to hang: the
/// bound is the linger (the close ends at it at the latest) and the final
/// write time after it.
#[tokio::test(start_paused = true)]
async fn a_shutdown_that_never_completes_is_aborted() {
    tokio::time::timeout(WATCHDOG, async {
        let config = config(Duration::from_millis(250));
        let (a, b) = tokio::io::duplex(1 << 16);
        let (abort, aborted) = oneshot::channel();
        let client_io = zmux::PipeIo::new(NeverShutdown(a)).with_abort(move || {
            let _ = abort.send(());
        });
        let (client, _server) = tokio::try_join!(
            zmux::Session::connect(client_io, config.clone()),
            zmux::Session::accept(zmux::PipeIo::new(b), config),
        )
        .unwrap();
        client.close().await;
        aborted.await.expect("the stalled shutdown was aborted");
        client.closed().await;
    })
    .await
    .expect("abort scenario timed out");
}

// ---- std driver -------------------------------------------------------------------------

/// What a silent peer is to a reader: with `deaf` set, what arrives is swallowed and the
/// end of input never comes, until the closer ends the read side.
#[derive(Default)]
struct Silence {
    deaf: AtomicBool,
    ended: Mutex<bool>,
    end_signal: Condvar,
}

impl Silence {
    fn end(&self) {
        *self.ended.lock().unwrap() = true;
        self.end_signal.notify_all();
    }

    fn wait_end(&self) {
        drop(
            self.end_signal
                .wait_while(self.ended.lock().unwrap(), |ended| !*ended)
                .unwrap(),
        );
    }
}

impl<T: Read + Send + 'static> Read for NoHalfClose<T> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            let n = self.io.as_mut().expect("open").read(buf)?;
            if !self.silence.deaf.load(Ordering::SeqCst) {
                return Ok(n);
            }
            if n == 0 {
                self.silence.wait_end();
                return Ok(0);
            }
        }
    }
}

impl<T: Write + Send + 'static> Write for NoHalfClose<T> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.io.as_mut().expect("open").write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.io.as_mut().expect("open").flush()
    }
}

/// A TCP carrier whose write side cannot be shut alone: the closer ignores
/// [`Shutdown::Write`].
fn blocking_carrier(
    s: TcpStream,
    lifetime: &CarrierLifetime,
    silence: &Arc<Silence>,
) -> zmux::blocking::PipeIo {
    let close = zmux::blocking::PipeIo::tcp_closer(s.try_clone().unwrap());
    let silence_c = silence.clone();
    zmux::blocking::PipeIo::from_halves(
        NoHalfClose::new(s.try_clone().unwrap(), silence, lifetime),
        NoHalfClose::new(s, silence, lifetime),
    )
    .with_closer(move |how| {
        if how != Shutdown::Write {
            silence_c.end();
            close(how);
        }
    })
}

fn tcp_pair() -> (TcpStream, TcpStream) {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let a = TcpStream::connect(l.local_addr().unwrap()).unwrap();
    let (b, _) = l.accept().unwrap();
    (a, b)
}

/// Runs a blocking scenario off the test thread so a stalled driver cannot hang the harness.
fn watchdog(f: impl FnOnce() + Send + 'static) {
    let (tx, rx) = mpsc::channel();
    let scenario = std::thread::spawn(move || {
        f();
        let _ = tx.send(());
    });
    if matches!(
        rx.recv_timeout(WATCHDOG),
        Err(mpsc::RecvTimeoutError::Timeout)
    ) {
        panic!("blocking close scenario timed out");
    }
    scenario.join().unwrap();
}

/// A client and the server's session over one TCP carrier; the server's end listens to
/// `silence`.
fn blocking_pair(
    config: Config,
    lifetime: &CarrierLifetime,
    silence: &Arc<Silence>,
) -> (
    zmux::blocking::Session,
    zmux::blocking::Session,
    zmux::blocking::Listener,
) {
    let l = zmux::blocking::Listener::new(config.clone(), zmux::ListenerConfig::default(), None)
        .expect("valid listener configuration");
    let (a, b) = tcp_pair();
    let ca = blocking_carrier(a, lifetime, &Arc::new(Silence::default()));
    let cb = blocking_carrier(b, lifetime, silence);
    let ll = l.clone();
    let t = std::thread::spawn(move || ll.handle_pipe(cb, zmux::blocking::PipeHint::default()));
    let client = zmux::blocking::Session::connect(ca, config).unwrap();
    t.join().unwrap().unwrap();
    let server = l
        .accept_timeout(Duration::from_secs(5))
        .ok()
        .flatten()
        .expect("a session");
    (client, server, l)
}

/// Delivers the close code and waits for both carriers with the linger clock stopped.
fn blocking_close(
    client: &zmux::blocking::Session,
    server: &zmux::blocking::Session,
    server_closes: bool,
    mut remaining: async_mpsc::UnboundedReceiver<Infallible>,
) {
    let (closer, other) = if server_closes {
        (server, client)
    } else {
        (client, server)
    };
    let (mut w, mut r) = other.open_bi().unwrap();
    r.set_read_timeout(Some(Duration::from_secs(5)));
    w.write_all(b"request").unwrap();
    w.flush().unwrap();
    let (_sw, mut sr) = closer.accept_bi().unwrap();
    sr.set_read_timeout(Some(Duration::from_secs(5)));
    let mut got = [0; 7];
    sr.read_exact(&mut got).unwrap();
    let s = closer.clone();
    let closing = std::thread::spawn(move || s.close_with_error(VarInt::from_u32(42), b"done"));
    let e = r.read_to_end(1 << 10).unwrap_err();
    let _ = w.finish();
    match e {
        zmux::blocking::WaitError::Failed(zmux::ReadToEndError::Read(
            StreamError::SessionLost(e),
        )) => assert!(closed_with_42(&e)),
        e => panic!("{e:?}"),
    }
    assert!(remaining.blocking_recv().is_none());
    closing.join().unwrap();
}

#[test]
fn a_blocking_close_without_half_close_ends_at_once_over_tcp() {
    for server_closes in [true, false] {
        watchdog(move || {
            let (_, config) = manual_config();
            let (lifetime, remaining) = CarrierLifetime::new();
            let (client, server, listener) =
                blocking_pair(config, &lifetime, &Arc::new(Silence::default()));
            let _retained = lifetime.retain();
            blocking_close(&client, &server, server_closes, remaining);
            listener.close();
        });
    }
}

#[test]
fn a_blocking_silent_peer_leaves_the_linger_as_the_bound() {
    watchdog(|| {
        let (clock, config) = manual_config();
        let (lifetime, mut remaining) = CarrierLifetime::new();
        let silence = Arc::new(Silence::default());
        let (_client, server, listener) = blocking_pair(config, &lifetime, &silence);
        let _retained = lifetime.retain();
        silence.deaf.store(true, Ordering::SeqCst);
        server.close_with_error(VarInt::from_u32(42), b"done");
        assert_eq!(server.state(), SessionState::Closing);
        clock.advance(LINGER);
        server.closed().unwrap();
        assert!(remaining.blocking_recv().is_none());
        listener.close();
    });
}
