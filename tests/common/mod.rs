//! Shared harness of the tokio driver's leak, liveness and simulation
//! tests: process-wide resource snapshots, runtimes that hold the
//! serializing lock, seeded randomness and in-memory carriers that count
//! themselves and can fail or stall.

#![allow(dead_code)]

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::Instant;
use zmux::test_hooks::{Resources, resources};
use zmux::{Config, PipeIo, Session};

mod basics;

#[allow(unused_imports)]
pub(crate) use basics::{Rng, open_fds, seeds, serial, small_windows, soak};

// ---- harness -----------------------------------------------------------------------

/// Runs `f` on a fresh multi-thread runtime (real time), holding
/// [`serial`] until the runtime is gone: its own descriptors and threads
/// are part of no other test's baseline.
pub(crate) fn multi_thread<F: Future>(f: F) -> F::Output {
    let _g = serial();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .unwrap();
    let r = rt.block_on(f);
    drop(rt);
    r
}

/// Runs `f` on a fresh single-thread runtime whose clock is paused (it
/// advances when every task waits): deterministic, and timeouts take no
/// real time.
pub(crate) fn paused<F: Future>(f: F) -> F::Output {
    let _g = serial();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .start_paused(true)
        .build()
        .unwrap();
    let r = rt.block_on(f);
    drop(rt);
    r
}

/// Everything that must return to its baseline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Snapshot {
    pub(crate) res: Resources,
    pub(crate) fds: usize,
    pub(crate) carriers: usize,
    /// Tasks alive on the current runtime.
    pub(crate) tasks: usize,
}

pub(crate) fn snapshot() -> Snapshot {
    Snapshot {
        res: resources(),
        fds: open_fds(),
        carriers: CARRIERS.load(Ordering::SeqCst),
        tasks: tokio::runtime::Handle::try_current().map_or(0, |h| h.metrics().num_alive_tasks()),
    }
}

/// Waits until everything is back at `base`, at most `secs` seconds (of the
/// runtime's clock); fails with the difference otherwise.
pub(crate) async fn settle(base: Snapshot, secs: u64, what: &str) {
    let deadline = Instant::now() + Duration::from_secs(secs);
    loop {
        let now = snapshot();
        if now == base {
            return;
        }
        if Instant::now() >= deadline {
            panic!("{what}: resources not released\n  baseline {base:?}\n  now      {now:?}");
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

/// Waits until `f` holds, at most `secs` seconds.
pub(crate) async fn eventually(secs: u64, what: &str, mut f: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(secs);
    while !f() {
        assert!(Instant::now() < deadline, "{what}: not within {secs} s");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

/// Fails the test when `f` does not finish within `secs` seconds.
pub(crate) async fn watchdog<T>(secs: u64, what: &str, f: impl Future<Output = T>) -> T {
    match tokio::time::timeout(Duration::from_secs(secs), f).await {
        Ok(v) => v,
        Err(_) => panic!("{what}: did not resolve within {secs} s"),
    }
}

// ---- carriers ------------------------------------------------------------------------

/// Test carriers alive.
pub(crate) static CARRIERS: AtomicUsize = AtomicUsize::new(0);

/// Controls of an in-memory carrier: fail it (reads and writes error) or
/// stall its writes.
#[derive(Default)]
pub(crate) struct Ctl {
    fail: AtomicBool,
    fail_read: AtomicBool,
    stall: AtomicBool,
    wakers: Mutex<Vec<Waker>>,
}

impl Ctl {
    pub(crate) fn park(&self, w: &Waker) {
        let mut ws = self.wakers.lock().unwrap();
        if !ws.iter().any(|x| x.will_wake(w)) {
            ws.push(w.clone());
        }
    }

    pub(crate) fn wake(&self) {
        for w in self.wakers.lock().unwrap().drain(..) {
            w.wake();
        }
    }

    pub(crate) fn fail(&self) {
        self.fail.store(true, Ordering::SeqCst);
        self.wake();
    }

    /// Reads fail; writes go on (or stay stalled).
    pub(crate) fn fail_reads(&self) {
        self.fail_read.store(true, Ordering::SeqCst);
        self.wake();
    }

    pub(crate) fn stall(&self, on: bool) {
        self.stall.store(on, Ordering::SeqCst);
        self.wake();
    }
}

/// An in-memory carrier that counts itself alive.
pub(crate) struct Carrier {
    io: DuplexStream,
    ctl: Arc<Ctl>,
}

impl Carrier {
    pub(crate) fn new(io: DuplexStream) -> (Self, Arc<Ctl>) {
        CARRIERS.fetch_add(1, Ordering::SeqCst);
        let ctl = Arc::new(Ctl::default());
        (
            Self {
                io,
                ctl: ctl.clone(),
            },
            ctl,
        )
    }

    pub(crate) fn failed(&self) -> io::Error {
        io::Error::new(io::ErrorKind::ConnectionReset, "carrier failed")
    }
}

impl Drop for Carrier {
    fn drop(&mut self) {
        CARRIERS.fetch_sub(1, Ordering::SeqCst);
    }
}

impl AsyncRead for Carrier {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.ctl.fail.load(Ordering::SeqCst) || self.ctl.fail_read.load(Ordering::SeqCst) {
            return Poll::Ready(Err(self.failed()));
        }
        let r = Pin::new(&mut self.io).poll_read(cx, buf);
        if r.is_pending() {
            self.ctl.park(cx.waker());
        }
        r
    }
}

impl AsyncWrite for Carrier {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.ctl.fail.load(Ordering::SeqCst) {
            return Poll::Ready(Err(self.failed()));
        }
        if self.ctl.stall.load(Ordering::SeqCst) {
            self.ctl.park(cx.waker());
            return Poll::Pending;
        }
        let r = Pin::new(&mut self.io).poll_write(cx, buf);
        if r.is_pending() {
            self.ctl.park(cx.waker());
        }
        r
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_shutdown(cx)
    }
}

/// Two connected in-memory carriers and their controls.
pub(crate) fn duplex(cap: usize) -> ((PipeIo, Arc<Ctl>), (PipeIo, Arc<Ctl>)) {
    let (a, b) = tokio::io::duplex(cap);
    let (a, ca) = Carrier::new(a);
    let (b, cb) = Carrier::new(b);
    ((PipeIo::new(a), ca), (PipeIo::new(b), cb))
}

pub(crate) async fn tcp() -> (TcpStream, TcpStream) {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let (a, b) = tokio::join!(TcpStream::connect(addr), l.accept());
    (a.unwrap(), b.unwrap().0)
}

pub(crate) async fn connect(
    a: PipeIo,
    b: PipeIo,
    client: Config,
    server: Config,
) -> (Session, Session) {
    let server = tokio::spawn(accept(b, server));
    let client = Session::connect(a, client).await.expect("connect");
    (client, server.await.unwrap().expect("accept"))
}

/// The accepting side of a session on `pipe`: `Session::accept`, or a
/// listener of its own when `config` offers multipath (which
/// `Session::accept` refuses: it cannot accept joins).
pub(crate) async fn accept(pipe: PipeIo, config: Config) -> Result<Session, zmux::ConnectError> {
    if config.max_pipes == 1 && config.resume_timeout.is_none() {
        return Session::accept(pipe, config).await;
    }
    let listener = zmux::Listener::new(config, zmux::ListenerConfig::default());
    let l = listener.clone();
    tokio::spawn(async move { l.handle_pipe(pipe, zmux::PipeHint::default()).await });
    listener
        .accept()
        .await
        .ok_or(zmux::ConnectError::InvalidConfig("listener closed"))
}

/// A session pair over TCP or in-memory carriers (with their controls).
pub(crate) async fn pair(
    tcp_carrier: bool,
    client: Config,
    server: Config,
) -> (Session, Session, Vec<Arc<Ctl>>) {
    if tcp_carrier {
        let (a, b) = tcp().await;
        let (c, s) = connect(PipeIo::tcp(a), PipeIo::tcp(b), client, server).await;
        (c, s, Vec::new())
    } else {
        let ((a, ca), (b, cb)) = duplex(64 * 1024);
        let (c, s) = connect(a, b, client, server).await;
        (c, s, vec![ca, cb])
    }
}

/// Copies `r` to `w` until the cut, an end or an error; dropping the halves
/// then ends the relayed connection.
async fn pump(
    mut r: tokio::net::tcp::OwnedReadHalf,
    mut w: tokio::net::tcp::OwnedWriteHalf,
    cut: Arc<AtomicBool>,
) {
    let mut buf = vec![0u8; 16 * 1024];
    while !cut.load(Ordering::SeqCst) {
        match tokio::time::timeout(Duration::from_millis(10), r.read(&mut buf)).await {
            Ok(Ok(0)) | Ok(Err(_)) => break,
            Ok(Ok(n)) => {
                if w.write_all(&buf[..n]).await.is_err() {
                    break;
                }
            }
            Err(_) => {}
        }
    }
}

/// A carrier that can be cut: a TCP relay whose cut drops both sockets.
pub(crate) async fn relay(target: std::net::SocketAddr) -> (std::net::SocketAddr, Arc<AtomicBool>) {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let cut = Arc::new(AtomicBool::new(false));
    let c = cut.clone();
    tokio::spawn(async move {
        let Ok((a, _)) = l.accept().await else {
            return;
        };
        let b = TcpStream::connect(target).await.unwrap();
        let (ar, aw) = a.into_split();
        let (br, bw) = b.into_split();
        let t1 = tokio::spawn(pump(ar, bw, c.clone()));
        let t2 = tokio::spawn(pump(br, aw, c));
        let _ = t1.await;
        let _ = t2.await;
    });
    (addr, cut)
}
