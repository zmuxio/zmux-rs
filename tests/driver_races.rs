//! Deadlock and race tests of the tokio driver on a multi-thread runtime:
//! many concurrent readers, writers, openers and acceptors on one session
//! with random cancellation (real parallelism, beside the seeded
//! single-threaded races of `close_races.rs`), carriers that end or fail in
//! the middle of a batch, a session task dropped with its runtime, and a
//! multipath session that loses a pipe during traffic. Every test runs
//! under a watchdog: it fails, rather than hangs, when anything does not
//! resolve in time.

#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "test and bench values are small and bounded; checked conversions would only add noise"
)]
#![allow(
    clippy::similar_names,
    reason = "short conventional names in scenario code"
)]
#![allow(
    clippy::large_futures,
    reason = "scenario code: buffers and futures stay on the stack on purpose, long scripted scenarios read top to bottom"
)]

mod common;
#[path = "common/pending.rs"]
mod pending;

use std::future::Future;
use std::io;
use std::pin::{Pin, pin};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use common::{Rng, connect, relay, small_windows, tcp, watchdog};
use pending::{is_pending, poll_once};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot};
use zmux::Chunk;
use zmux::sched::Scheduler;
use zmux::{
    Config, Listener, ListenerConfig, PipeAuth, PipeHint, PipeIo, PipeOptions, RecvStream,
    SendStream, Session, VarInt,
};

/// [`watchdog`] for `Runtime::block_on`: the timeout is created inside the
/// runtime.
async fn async_watch<T>(secs: u64, what: &str, f: impl Future<Output = T>) -> T {
    watchdog(secs, what, f).await
}

async fn transfers_started(mut progress: mpsc::Receiver<()>, count: usize, description: &str) {
    watchdog(30, description, async {
        for _ in 0..count {
            progress.recv().await.expect("a transfer started");
        }
    })
    .await;
}

async fn tcp_pair(client: Config, server: Config) -> (Session, Session) {
    let (a, b) = tcp().await;
    connect(PipeIo::from_tcp(a), PipeIo::from_tcp(b), client, server).await
}

/// Echoes every bidirectional stream and drains every unidirectional one
/// until the session ends.
fn serve(server: Session) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let uni = {
            let s = server.clone();
            tokio::spawn(async move {
                while let Ok(mut r) = s.accept_uni().await {
                    tokio::spawn(async move {
                        let mut buf = vec![0u8; 16 * 1024];
                        while let Ok(Some(_)) = r.read(&mut buf).await {}
                    });
                }
            })
        };
        while let Ok((mut send, mut recv)) = server.accept_bi().await {
            tokio::spawn(async move {
                let mut buf = vec![0u8; 16 * 1024];
                loop {
                    match recv.read(&mut buf).await {
                        Ok(Some(n)) => {
                            if send.write_all(&buf[..n]).await.is_err() {
                                return;
                            }
                        }
                        Ok(None) => break,
                        Err(_) => return,
                    }
                }
                let _ = send.finish();
            });
        }
        let _ = uni.await;
    })
}

/// Writes `len` bytes and reads them back in full.
async fn echo_once(session: &Session, len: usize, seed: u8) {
    let (mut send, mut recv) = session.open_bi().await.expect("open");
    let data: Vec<u8> = (0..len).map(|i| (i as u8).wrapping_add(seed)).collect();
    let w = {
        let data = data.clone();
        // A failed write shows as a short echo.
        tokio::spawn(async move {
            if send.write_all(&data).await.is_ok() {
                let _ = send.finish();
            }
        })
    };
    let got = recv.read_to_end(len + 1).await.expect("read");
    w.await.unwrap();
    assert!(got == data, "echoed data differs");
}

/// Chooses an operation and cancels it at its first pending poll.
async fn random_op(session: &Session, rng: &mut Rng, kept: &mut Vec<(SendStream, RecvStream)>) {
    match rng.below(9) {
        0 => {
            // Open, write, read some of the echo; each step cancellable.
            if let Poll::Ready(Ok((mut send, mut recv))) = poll_once(pin!(session.open_bi())).await
            {
                let data = vec![7u8; 1 + rng.below(48 * 1024) as usize];
                let _ = poll_once(pin!(send.write_all(&data))).await;
                if rng.below(2) == 0 {
                    let _ = send.finish();
                }
                let mut buf = vec![0u8; 8 * 1024];
                let _ = poll_once(pin!(recv.read(&mut buf))).await;
                if rng.below(4) == 0 && kept.len() < 8 {
                    kept.push((send, recv));
                }
            }
        }
        1 => {
            if let Ok((mut send, mut recv)) = session.try_open_bi() {
                let _ = send.write_all(b"try").await;
                let _ = send.finish();
                let _ = poll_once(pin!(recv.read_to_end(1 << 16))).await;
            }
        }
        2 => {
            if let Poll::Ready(Ok(mut send)) = poll_once(pin!(session.open_uni())).await {
                let chunk = Chunk::from(vec![1u8; 1 + rng.below(32 * 1024) as usize]);
                let _ = poll_once(pin!(send.write_chunk(chunk))).await;
                if rng.below(2) == 0 {
                    let _ = send.finish();
                }
            }
        }
        3 => {
            let _ = poll_once(pin!(session.closing())).await;
        }
        4 => {
            let _ = poll_once(pin!(session.accept_bi())).await;
        }
        5 => {
            let _ = poll_once(pin!(session.accept_uni())).await;
        }
        6 => {
            let _ = poll_once(pin!(session.next_event())).await;
        }
        7 => {
            // Waits on a stream kept from earlier: stopped, read, write.
            if let Some((send, recv)) = kept.last_mut() {
                match rng.below(3) {
                    0 => {
                        let _ = poll_once(pin!(send.stopped())).await;
                    }
                    1 => {
                        let mut buf = [0u8; 512];
                        let _ = poll_once(pin!(recv.read(&mut buf))).await;
                    }
                    _ => {
                        let _ = poll_once(pin!(send.write(&[3u8; 4096]))).await;
                    }
                }
            }
        }
        _ => {
            // Drops a kept stream mid-flight.
            if !kept.is_empty() {
                let i = rng.below(kept.len() as u64) as usize;
                kept.swap_remove(i);
            }
        }
    }
}

/// Many tasks run a seeded mix of operations and cancellations on
/// one session with few streams and small windows. Afterwards the session
/// still works (no wait queue was left wedged by a cancelled waiter), and
/// closing it ends both sides.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn random_cancellation_storm() {
    let mut server_config = small_windows(Config::default());
    server_config.max_incoming_streams = 12;
    server_config.max_incoming_uni_streams = zmux::UniCredit::Limit(6);
    let (client, server) = tcp_pair(small_windows(Config::default()), server_config).await;
    let server_task = serve(server.clone());
    watchdog(60, "random operations", async {
        let tasks: Vec<_> = (0..24)
            .map(|i| {
                let s = client.clone();
                tokio::spawn(async move {
                    let mut rng = Rng::new(i + 1);
                    echo_once(&s, 512, i as u8).await;
                    let mut kept = Vec::new();
                    for _ in 0..60 {
                        random_op(&s, &mut rng, &mut kept).await;
                    }
                })
            })
            .collect();
        for t in tasks {
            t.await.expect("no panic");
        }
    })
    .await;
    // No queue was left wedged: openers and plain echoes still go through.
    watchdog(20, "echo after the storm", async {
        for i in 0..4 {
            echo_once(&client, 100 * 1024, i).await;
        }
    })
    .await;
    client.abort(VarInt::from_u32(7), b"done");
    watchdog(10, "server sees the close", server.closing()).await;
    watchdog(10, "server tasks end", server_task).await.unwrap();
}

/// The carrier ends in the middle of a bulk transfer in both directions:
/// every read, write and wait on both sides resolves.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn carrier_eof_mid_batch() {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = l.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (c, _) = l.accept().await.unwrap();
        Session::accept(PipeIo::from_tcp(c), Config::default())
            .await
            .unwrap()
    });
    let (addr, cut) = relay(target).await;
    let client = Session::connect(
        PipeIo::from_tcp(TcpStream::connect(addr).await.unwrap()),
        Config::default(),
    )
    .await
    .unwrap();
    let server = server.await.unwrap();
    let server_task = serve(server.clone());
    let (transferred, progress) = mpsc::channel(6);
    let jobs: Vec<_> = (0..6)
        .map(|i| {
            let s = client.clone();
            let transferred = transferred.clone();
            tokio::spawn(async move {
                let (mut send, mut recv) = s.open_bi().await.unwrap();
                let w = tokio::spawn(async move {
                    let data = vec![i as u8; 64 * 1024];
                    while send.write_all(&data).await.is_ok() {}
                });
                let mut buf = vec![0u8; 64 * 1024];
                assert!(recv.read(&mut buf).await.unwrap().is_some());
                transferred.send(()).await.unwrap();
                while let Ok(Some(_)) = recv.read(&mut buf).await {}
                let _ = w.await;
            })
        })
        .collect();
    drop(transferred);
    transfers_started(progress, jobs.len(), "echoes before cutting the carrier").await;
    cut.send(()).expect("the relay is forwarding traffic");
    watchdog(40, "transfers after the carrier ended", async {
        for j in jobs {
            j.await.expect("no panic");
        }
    })
    .await;
    watchdog(40, "client closed", client.closing()).await;
    watchdog(40, "server closed", server.closing()).await;
    let _ = watchdog(10, "server tasks", server_task).await;
}

/// A writer that fails after `left` bytes.
struct Failing<W> {
    inner: W,
    left: usize,
}

impl<W: AsyncWrite + Unpin> AsyncWrite for Failing<W> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.left == 0 {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        let n = buf.len().min(self.left);
        let r = Pin::new(&mut self.inner).poll_write(cx, &buf[..n]);
        if let Poll::Ready(Ok(w)) = r {
            self.left -= w;
        }
        r
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// A reader that passes everything through.
struct Plain<R>(R);

impl<R: AsyncRead + Unpin> AsyncRead for Plain<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

/// The carrier's write fails in the middle of a batch (on the
/// write-through path and the session task's alike): every wait resolves.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn carrier_write_error_mid_batch() {
    let (a, b) = tcp().await;
    let (ar, aw) = a.into_split();
    let client_pipe = PipeIo::from_halves(
        Plain(ar),
        Failing {
            inner: aw,
            left: 3 * 1024 * 1024 + 777,
        },
    );
    let (client, server) = connect(
        client_pipe,
        PipeIo::from_tcp(b),
        Config::default(),
        Config::default(),
    )
    .await;
    let server_task = serve(server.clone());
    let jobs: Vec<_> = (0..8)
        .map(|i| {
            let s = client.clone();
            tokio::spawn(async move {
                let Ok((mut send, mut recv)) = s.open_bi().await else {
                    return;
                };
                let w = tokio::spawn(async move {
                    let data = vec![i as u8; 16 * 1024 + i];
                    while send.write_all(&data).await.is_ok() {}
                });
                let mut buf = vec![0u8; 32 * 1024];
                while let Ok(Some(_)) = recv.read(&mut buf).await {}
                let _ = w.await;
            })
        })
        .collect();
    watchdog(40, "transfers after the write failed", async {
        for j in jobs {
            j.await.expect("no panic");
        }
    })
    .await;
    watchdog(40, "client closed", client.closing()).await;
    watchdog(40, "server closed", server.closing()).await;
    let _ = watchdog(10, "server tasks", server_task).await;
}

/// The runtime that runs a session's task shuts down while application
/// tasks on another runtime wait on the session: their waits resolve.
#[test]
fn session_task_dropped_with_its_runtime() {
    let main = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let side = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
        .unwrap();
    let l = main.block_on(TcpListener::bind("127.0.0.1:0")).unwrap();
    let addr = l.local_addr().unwrap();
    let server = main.spawn(async move {
        let (c, _) = l.accept().await.unwrap();
        Session::accept(PipeIo::from_tcp(c), Config::default())
            .await
            .unwrap()
    });
    let client = side.block_on(async {
        let c = TcpStream::connect(addr).await.unwrap();
        Session::connect(PipeIo::from_tcp(c), Config::default())
            .await
            .unwrap()
    });
    let server = main.block_on(server).unwrap();
    let (send, mut recv) = main.block_on(client.open_bi()).unwrap();
    let (waiting, registered) = oneshot::channel();
    let waits = {
        let c = client.clone();
        main.spawn(async move {
            let mut buf = [0u8; 8];
            let mut read = pin!(recv.read(&mut buf));
            let mut accept = pin!(c.accept_bi());
            assert!(is_pending(read.as_mut()).await);
            assert!(is_pending(accept.as_mut()).await);
            waiting.send(()).unwrap();
            let (read, accept) = tokio::join!(read, accept);
            (read.is_err(), accept.is_err())
        })
    };
    main.block_on(async_watch(30, "waits registered", registered))
        .unwrap();
    // The client's session task goes with its runtime.
    drop(side);
    let (read, accept) = main
        .block_on(async_watch(
            5,
            "waits after the session task was dropped",
            waits,
        ))
        .unwrap();
    assert!(read && accept);
    main.block_on(async_watch(5, "closed", client.closing()));
    drop((send, client));
    main.block_on(async_watch(
        40,
        "server sees the carrier end",
        server.closing(),
    ));
}

// ---- multipath --------------------------------------------------------------------

fn mp_config() -> Config {
    let mut c = small_windows(Config::default());
    c.session_policy.limits.steady_attachments = 4;
    c.pipe_auth = PipeAuth::psk(*b"driver-race-psk-0123456789abcdef").with_end_to_end();
    c.scheduler = Scheduler::SpreadEta;
    c.liveness.suspect_floor = Duration::from_millis(100);
    c
}

/// A multipath session over two TCP pipes: concurrent echoes with random
/// cancellation while one pipe is severed and the other is aborted and
/// re-added; the transfers that were not cancelled complete.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn multipath_pipe_loss_under_concurrency() {
    let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = tcp.local_addr().unwrap();
    let listener = Listener::new(mp_config(), ListenerConfig::default())
        .expect("valid listener configuration");
    {
        let l = listener.clone();
        tokio::spawn(async move {
            while let Ok((c, peer)) = tcp.accept().await {
                let l = l.clone();
                tokio::spawn(async move {
                    let _ = l
                        .handle_pipe(PipeIo::from_tcp(c), PipeHint::from_peer(peer))
                        .await;
                });
            }
        });
    }
    let accepted = {
        let l = listener.clone();
        tokio::spawn(async move {
            let s = l.accept().await.unwrap();
            drop(serve(s.clone()));
            s
        })
    };
    let client = Session::connect(
        PipeIo::from_tcp(TcpStream::connect(target).await.unwrap()),
        mp_config(),
    )
    .await
    .unwrap();
    assert_eq!(client.multipath(), zmux::Multipath::InUse);
    let server = watchdog(5, "listener accepts", accepted).await.unwrap();
    let (raddr, cut) = relay(target).await;
    let relayed = client
        .test_begin_join(
            PipeIo::from_tcp(TcpStream::connect(raddr).await.unwrap()),
            PipeOptions::default(),
        )
        .unwrap();
    let third = client
        .test_begin_join(
            PipeIo::from_tcp(TcpStream::connect(target).await.unwrap()),
            PipeOptions::default(),
        )
        .unwrap();
    watchdog(30, "relayed pipe attached", relayed.attached())
        .await
        .unwrap();
    watchdog(30, "third pipe attached", third.attached())
        .await
        .unwrap();

    let recovered = Arc::new(AtomicBool::new(false));
    let (transferred, progress) = mpsc::channel(12);
    let jobs: Vec<_> = (0..12u8)
        .map(|i| {
            let s = client.clone();
            let recovered = recovered.clone();
            let transferred = transferred.clone();
            tokio::spawn(async move {
                if i % 4 == 3 {
                    // Drop an exchange after it has been polled.
                    let _ = is_pending(pin!(echo_once(&s, 256 * 1024, i))).await;
                }
                echo_once(&s, 256 * 1024, i).await;
                transferred.send(()).await.unwrap();
                while !recovered.load(Ordering::SeqCst) {
                    echo_once(&s, 256 * 1024, i).await;
                }
                echo_once(&s, 256 * 1024, i).await;
            })
        })
        .collect();
    drop(transferred);
    transfers_started(
        progress,
        jobs.len(),
        "transfers before cutting the relayed pipe",
    )
    .await;
    cut.send(()).expect("the relay is forwarding traffic");
    let _ = watchdog(30, "relayed pipe closed", relayed.closed()).await;
    third.abort().unwrap();
    let replacement = client
        .test_begin_join(
            PipeIo::from_tcp(TcpStream::connect(target).await.unwrap()),
            PipeOptions::default(),
        )
        .unwrap();
    watchdog(30, "replacement attached", replacement.attached())
        .await
        .unwrap();
    recovered.store(true, Ordering::SeqCst);
    watchdog(60, "echoes after carrier replacement", async {
        for j in jobs {
            j.await.expect("no panic");
        }
    })
    .await;
    client.close().await;
    watchdog(10, "server sees the close", server.closing()).await;
}

/// Send-capacity waits end on the peer's credit, and
/// at once on `STOP_SENDING` and on the session's end, so a relay never
/// waits behind capacity for an error; a cancelled wait leaves nothing
/// registered.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn send_capacity_waits_end_on_credit_stop_close_and_cancellation() {
    watchdog(20, "send capacity", async {
        let (client, server) = tcp_pair(Config::default(), small_windows(Config::default())).await;
        let (mut send, _recv) = client.open_bi().await.unwrap();
        let window = send.send_capacity();
        assert_eq!(window, 16 * 1024, "the peer's stream window");
        send.write_all(&vec![1; window as usize]).await.unwrap();
        assert_eq!(send.send_capacity(), 0);
        let (_ss, mut sr) = server.accept_bi().await.unwrap();

        let before = client.debug_tables().waits;
        {
            let mut cancelled = pin!(send.wait_send_capacity(1));
            assert!(is_pending(cancelled.as_mut()).await, "no credit yet");
        }
        assert_eq!(client.debug_tables().waits, before, "the wait left");

        let got = {
            let mut waiting = pin!(send.wait_send_capacity(1));
            assert!(is_pending(waiting.as_mut()).await);
            let mut buf = vec![0u8; window as usize];
            sr.read_exact(&mut buf).await.unwrap();
            waiting.await.unwrap()
        };
        assert!(got > 0 && got == send.send_capacity(), "{got}");

        send.write_all(&vec![2; got as usize]).await.unwrap();
        let mut stopped = pin!(send.wait_send_capacity(1));
        assert!(is_pending(stopped.as_mut()).await);
        sr.stop(VarInt::from_u32(9)).unwrap();
        assert!(stopped.await.is_err());

        let (mut send2, _recv2) = client.open_bi().await.unwrap();
        send2.write_all(&vec![3; window as usize]).await.unwrap();
        let mut closed = pin!(send2.wait_send_capacity(1));
        assert!(is_pending(closed.as_mut()).await);
        server.close().await;
        assert!(closed.await.is_err());
    })
    .await;
}

/// The application byte counters read from another
/// thread during a transfer never decrease, and end exact: what one end
/// wrote is what the other read.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn application_bytes_read_concurrently_are_monotonic_and_exact() {
    watchdog(30, "meters", async {
        let (client, server) = tcp_pair(Config::default(), Config::default()).await;
        let _serve = serve(server.clone());
        let done = Arc::new(AtomicBool::new(false));
        let reader = {
            let (meter, done) = (client.meter().clone(), done.clone());
            std::thread::spawn(move || {
                let mut last = meter.get();
                while !done.load(Ordering::Relaxed) {
                    let now = meter.get();
                    assert!(now.bytes_written >= last.bytes_written);
                    assert!(now.bytes_read >= last.bytes_read);
                    last = now;
                }
            })
        };
        let len = 4 << 20;
        let (mut send, mut recv) = client.open_bi().await.unwrap();
        let meter = send.meter().clone();
        let writer = tokio::spawn(async move {
            send.write_all(&vec![7; len]).await.unwrap();
            send.finish().unwrap();
            send
        });
        let got = recv.read_to_end(len + 1).await.unwrap();
        let _send = writer.await.unwrap();
        done.store(true, Ordering::Relaxed);
        reader.join().unwrap();
        assert_eq!(got.len(), len);
        let m = meter.get();
        assert_eq!((m.bytes_written, m.bytes_read), (len as u64, len as u64));
        let s = server.meter().get();
        assert_eq!((s.bytes_written, s.bytes_read), (len as u64, len as u64));
        assert_eq!(client.meter().bytes_written(), len as u64);
        client.close().await;
    })
    .await;
}
