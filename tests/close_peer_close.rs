//! A closing endpoint's linger on a pipe ends once the peer's `CONNECTION_CLOSE` was read on
//! it and its own was handed to the carrier: over a carrier without a half-close (its write
//! side cannot be shut alone, so the peer's end of input never comes) both carriers close at
//! once, not at the linger timeout; a peer that sends nothing more still ends at the linger.
//! Every wait is bounded.

use std::any::Any;
use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use zmux::{Config, SessionError, StreamError, VarInt};

/// The linger of the scenarios that must not wait for it.
const LONG_LINGER: Duration = Duration::from_secs(2);
/// What the carriers need to close once both closes crossed.
const PROMPT: Duration = Duration::from_millis(100);
/// How often each scenario repeats.
const REPEAT: usize = 100;

fn config(linger: Duration) -> Config {
    let mut c = Config::default();
    c.test_hooks().linger_timeout = Some(linger);
    c
}

fn hint() -> zmux::PipeHint {
    zmux::PipeHint::from_peer(([127, 0, 0, 1], 0).into())
}

fn closed_with_42(e: &SessionError) -> bool {
    matches!(e, SessionError::ApplicationClosed { code, remote: true, .. } if *code == VarInt::from_u32(42))
}

// ---- tokio ------------------------------------------------------------------------------

/// One object for both directions whose write side cannot be shut alone: a shutdown does
/// nothing, and the carrier closes only when it is dropped. `deaf` makes the input silent
/// (no byte, no end), as a peer that sends nothing more does. Counts the carriers alive.
struct NoHalfClose<T: Send + 'static> {
    io: Option<T>,
    deaf: Arc<AtomicBool>,
    alive: Arc<AtomicUsize>,
}

/// The objects of dropped carriers, kept open: a peer whose carrier shows no end, so that
/// only the `CONNECTION_CLOSE` can end a linger.
static KEPT: Mutex<Vec<Box<dyn Any + Send>>> = Mutex::new(Vec::new());

impl<T: Send + 'static> NoHalfClose<T> {
    fn new(io: T, deaf: &Arc<AtomicBool>, alive: &Arc<AtomicUsize>) -> Self {
        alive.fetch_add(1, Ordering::SeqCst);
        Self {
            io: Some(io),
            deaf: deaf.clone(),
            alive: alive.clone(),
        }
    }
}

impl<T: Send + 'static> Drop for NoHalfClose<T> {
    fn drop(&mut self) {
        if let Some(io) = self.io.take() {
            KEPT.lock().unwrap().push(Box::new(io));
        }
        self.alive.fetch_sub(1, Ordering::SeqCst);
    }
}

impl<T: AsyncRead + Unpin + Send + 'static> AsyncRead for NoHalfClose<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.deaf.load(Ordering::SeqCst) {
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
    deaf: Arc<AtomicBool>,
    alive: Arc<AtomicUsize>,
    _listener: zmux::Listener,
}

async fn tokio_pair(kind: Kind, linger: Duration) -> Pair {
    let deaf = Arc::new(AtomicBool::new(false));
    let alive = Arc::new(AtomicUsize::new(0));
    let listener = zmux::Listener::new(config(linger), zmux::ListenerConfig::default())
        .expect("valid listener configuration");
    // The server's end is the one that may go deaf; the client's never does.
    let never = Arc::new(AtomicBool::new(false));
    let (client_io, server_io) = match kind {
        Kind::Duplex => {
            let (a, b) = tokio::io::duplex(1 << 16);
            (
                zmux::PipeIo::new(NoHalfClose::new(a, &never, &alive)),
                zmux::PipeIo::new(NoHalfClose::new(b, &deaf, &alive)),
            )
        }
        Kind::Tcp => {
            let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let a = tokio::net::TcpStream::connect(l.local_addr().unwrap())
                .await
                .unwrap();
            let (b, _) = l.accept().await.unwrap();
            (
                zmux::PipeIo::new(NoHalfClose::new(a, &never, &alive)),
                zmux::PipeIo::new(NoHalfClose::new(b, &deaf, &alive)),
            )
        }
    };
    let l = listener.clone();
    tokio::spawn(async move {
        let _ = l.handle_pipe(server_io, hint()).await;
    });
    let client = zmux::Session::connect(client_io, config(linger))
        .await
        .unwrap();
    let server = listener.accept().await.unwrap();
    Pair {
        client,
        server,
        deaf,
        alive,
        _listener: listener,
    }
}

/// Opens a stream, then has one side close with code 42 while the other reads: the code
/// reaches it, and the time until both carriers are gone is returned. The carriers of
/// dropped sessions are kept open (`KEPT`), so that the closing side's own end of input
/// can come only from the peer's `CONNECTION_CLOSE`.
async fn tokio_close(p: &Pair, server_closes: bool) -> Duration {
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
    let began = Instant::now();
    let closing = tokio::spawn(async move {
        closer.close_with_error(VarInt::from_u32(42), b"done").await;
    });
    let e = r.read_to_end(1 << 10).await.unwrap_err();
    let _ = w.finish();
    match e {
        zmux::ReadToEndError::Read(StreamError::SessionLost(e)) => assert!(closed_with_42(&e)),
        e => panic!("{e}"),
    }
    while p.alive.load(Ordering::SeqCst) > 0 {
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    let took = began.elapsed();
    closing.await.unwrap();
    took
}

async fn tokio_prompt(kind: Kind, server_closes: bool) {
    let mut worst = Duration::ZERO;
    for i in 0..REPEAT {
        let took = tokio::time::timeout(Duration::from_secs(10), async {
            let p = tokio_pair(kind, LONG_LINGER).await;
            tokio_close(&p, server_closes).await
        })
        .await
        .unwrap_or_else(|_| panic!("{kind:?} iteration {i} in time"));
        worst = worst.max(took);
        assert!(
            took < PROMPT,
            "{kind:?} iteration {i} (server closes: {server_closes}): {took:?}"
        );
    }
    eprintln!("{kind:?}: worst {worst:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_close_without_half_close_ends_at_once_over_a_duplex() {
    tokio_prompt(Kind::Duplex, true).await;
    tokio_prompt(Kind::Duplex, false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_close_without_half_close_ends_at_once_over_tcp() {
    tokio_prompt(Kind::Tcp, true).await;
    tokio_prompt(Kind::Tcp, false).await;
}

/// A peer that never sends its `CONNECTION_CLOSE` nor ends its input leaves the linger as the
/// bound, and the carriers close at it.
async fn tokio_silent(kind: Kind) {
    let linger = Duration::from_millis(150);
    for i in 0..10 {
        tokio::time::timeout(Duration::from_secs(10), async {
            let p = tokio_pair(kind, linger).await;
            p.deaf.store(true, Ordering::SeqCst);
            let began = Instant::now();
            tokio::time::timeout(
                Duration::from_secs(5),
                p.server.close_with_error(VarInt::from_u32(42), b"done"),
            )
            .await
            .unwrap();
            while p.alive.load(Ordering::SeqCst) > 0 {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
            let took = began.elapsed();
            assert!(
                took >= linger.mul_f32(0.9) && took < linger + Duration::from_secs(2),
                "{kind:?} iteration {i}: {took:?}"
            );
        })
        .await
        .unwrap_or_else(|_| panic!("{kind:?} iteration {i} in time"));
    }
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
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_shutdown_that_never_completes_is_aborted() {
    let linger = Duration::from_millis(250);
    let listener = zmux::Listener::new(config(linger), zmux::ListenerConfig::default())
        .expect("valid listener configuration");
    let (a, b) = tokio::io::duplex(1 << 16);
    let aborted = Arc::new(AtomicBool::new(false));
    let flag = aborted.clone();
    let client_io = zmux::PipeIo::new(NeverShutdown(a)).with_abort(move || {
        flag.store(true, Ordering::SeqCst);
    });
    let l = listener.clone();
    tokio::spawn(async move {
        let _ = l.handle_pipe(zmux::PipeIo::new(b), hint()).await;
    });
    let client = zmux::Session::connect(client_io, config(linger))
        .await
        .unwrap();
    let _server = listener.accept().await.unwrap();
    let began = Instant::now();
    tokio::time::timeout(Duration::from_secs(5), client.close())
        .await
        .expect("the close ends");
    while !aborted.load(Ordering::SeqCst) {
        assert!(
            began.elapsed() < Duration::from_secs(4),
            "the carrier was not aborted"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    tokio::time::timeout(Duration::from_secs(2), client.closed())
        .await
        .expect("the session's task is released");
}

// ---- std driver -------------------------------------------------------------------------

/// What a silent peer is to a reader: with `deaf` set, what arrives is swallowed and the
/// end of input never comes, until the closer ends the read side.
#[derive(Default)]
struct Silence {
    deaf: AtomicBool,
    ended: AtomicBool,
}

/// A half of a carrier, counted while alive.
struct Half<T: Send + 'static> {
    io: Option<T>,
    alive: Arc<AtomicUsize>,
    silence: Arc<Silence>,
}

impl<T: Send + 'static> Half<T> {
    fn new(io: T, alive: &Arc<AtomicUsize>, silence: &Arc<Silence>) -> Self {
        alive.fetch_add(1, Ordering::SeqCst);
        Self {
            io: Some(io),
            alive: alive.clone(),
            silence: silence.clone(),
        }
    }
}

impl<T: Send + 'static> Drop for Half<T> {
    fn drop(&mut self) {
        if let Some(io) = self.io.take() {
            KEPT.lock().unwrap().push(Box::new(io));
        }
        self.alive.fetch_sub(1, Ordering::SeqCst);
    }
}

impl<T: Read + Send + 'static> Read for Half<T> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            let n = self.io.as_mut().expect("open").read(buf)?;
            if !self.silence.deaf.load(Ordering::SeqCst) {
                return Ok(n);
            }
            while n == 0 && !self.silence.ended.load(Ordering::SeqCst) {
                std::thread::sleep(Duration::from_millis(2));
            }
            if n == 0 {
                return Ok(0);
            }
        }
    }
}

impl<T: Write + Send + 'static> Write for Half<T> {
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
    alive: &Arc<AtomicUsize>,
    silence: &Arc<Silence>,
) -> zmux::blocking::PipeIo {
    let close = zmux::blocking::PipeIo::tcp_closer(s.try_clone().unwrap());
    let silence_c = silence.clone();
    zmux::blocking::PipeIo::from_halves(
        Half::new(s.try_clone().unwrap(), alive, silence),
        Half::new(s, alive, silence),
    )
    .with_closer(move |how| {
        if how != Shutdown::Write {
            silence_c.ended.store(true, Ordering::SeqCst);
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

/// Runs `f` on a thread and fails when it does not finish within `secs`.
fn watchdog<T: Send + 'static>(secs: u64, what: &str, f: impl FnOnce() -> T + Send + 'static) -> T {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(f());
    });
    match rx.recv_timeout(Duration::from_secs(secs)) {
        Ok(v) => v,
        Err(mpsc::RecvTimeoutError::Timeout) => panic!("{what}: did not resolve within {secs} s"),
        Err(mpsc::RecvTimeoutError::Disconnected) => panic!("{what}: panicked"),
    }
}

/// A client and the server's session over one TCP carrier; the server's end listens to
/// `silence`.
fn blocking_pair(
    linger: Duration,
    alive: &Arc<AtomicUsize>,
    silence: &Arc<Silence>,
) -> (
    zmux::blocking::Session,
    zmux::blocking::Session,
    zmux::blocking::Listener,
) {
    let l = zmux::blocking::Listener::new(config(linger), zmux::ListenerConfig::default(), None)
        .expect("valid listener configuration");
    let (a, b) = tcp_pair();
    let ca = blocking_carrier(a, alive, &Arc::new(Silence::default()));
    let cb = blocking_carrier(b, alive, silence);
    let ll = l.clone();
    let t = std::thread::spawn(move || ll.handle_pipe(cb, zmux::blocking::PipeHint::default()));
    let client = zmux::blocking::Session::connect(ca, config(linger)).unwrap();
    t.join().unwrap().unwrap();
    let server = l
        .accept_timeout(Duration::from_secs(5))
        .ok()
        .flatten()
        .expect("a session");
    (client, server, l)
}

/// The server closes with 42 while the client reads: the code reaches the client; returns
/// the time until every half of both carriers is dropped.
fn blocking_close(
    client: &zmux::blocking::Session,
    server: &zmux::blocking::Session,
    server_closes: bool,
    alive: &Arc<AtomicUsize>,
) -> Duration {
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
    let began = Instant::now();
    let closing = std::thread::spawn(move || s.close_with_error(VarInt::from_u32(42), b"done"));
    let e = r.read_to_end(1 << 10).unwrap_err();
    let _ = w.finish();
    match e {
        zmux::blocking::WaitError::Failed(zmux::ReadToEndError::Read(
            StreamError::SessionLost(e),
        )) => assert!(closed_with_42(&e)),
        e => panic!("{e:?}"),
    }
    while alive.load(Ordering::SeqCst) > 0 {
        std::thread::sleep(Duration::from_millis(1));
    }
    let took = began.elapsed();
    closing.join().unwrap();
    took
}

#[test]
fn a_blocking_close_without_half_close_ends_at_once_over_tcp() {
    let mut worst = Duration::ZERO;
    for i in 0..REPEAT {
        let server_closes = i % 2 == 0;
        let took = watchdog(10, &format!("iteration {i}"), move || {
            let alive = Arc::new(AtomicUsize::new(0));
            let (client, server, l) =
                blocking_pair(LONG_LINGER, &alive, &Arc::new(Silence::default()));
            let took = blocking_close(&client, &server, server_closes, &alive);
            l.close();
            took
        });
        worst = worst.max(took);
        assert!(
            took < PROMPT,
            "iteration {i} (server closes: {server_closes}): {took:?}"
        );
    }
    eprintln!("blocking: worst {worst:?}");
}

#[test]
fn a_blocking_silent_peer_leaves_the_linger_as_the_bound() {
    let linger = Duration::from_millis(150);
    for i in 0..10 {
        watchdog(10, &format!("iteration {i}"), move || {
            let alive = Arc::new(AtomicUsize::new(0));
            let silence = Arc::new(Silence::default());
            let (client, server, l) = blocking_pair(linger, &alive, &silence);
            silence.deaf.store(true, Ordering::SeqCst);
            let began = Instant::now();
            server.close_with_error(VarInt::from_u32(42), b"done");
            while alive.load(Ordering::SeqCst) > 0 {
                std::thread::sleep(Duration::from_millis(1));
            }
            let took = began.elapsed();
            assert!(
                took >= linger.mul_f32(0.9) && took < linger + Duration::from_secs(2),
                "iteration {i}: {took:?}"
            );
            drop(client);
            l.close();
        });
    }
}
