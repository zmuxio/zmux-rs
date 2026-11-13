//! The session's carriers, their file descriptors and buffers, go with the
//! session task: an application that keeps stream and session handles after
//! the session closed does not keep the carrier alive (a regression: the
//! bootstrap pipe's sides were held by the handles' fast paths).

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf};
use zmux::{Config, PipeIo, Session};

/// A carrier that counts its live instances.
struct Counted {
    io: DuplexStream,
    live: Arc<AtomicUsize>,
}

impl Counted {
    fn new(io: DuplexStream, live: &Arc<AtomicUsize>) -> Self {
        live.fetch_add(1, Ordering::SeqCst);
        Self {
            io,
            live: live.clone(),
        }
    }
}

impl Drop for Counted {
    fn drop(&mut self) {
        self.live.fetch_sub(1, Ordering::SeqCst);
    }
}

impl AsyncRead for Counted {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_read(cx, buf)
    }
}

impl AsyncWrite for Counted {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.io).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_shutdown(cx)
    }
}

/// Every carrier's writes, on both sides, wait while the gate is shut.
#[derive(Default)]
struct Gate {
    shut: std::sync::atomic::AtomicBool,
    writers: std::sync::Mutex<Vec<std::task::Waker>>,
}

impl Gate {
    fn set(&self, shut: bool) {
        self.shut.store(shut, Ordering::SeqCst);
        if !shut {
            for w in self.writers.lock().unwrap().drain(..) {
                w.wake();
            }
        }
    }

    /// Runs `f` while no carrier can write, then opens the gate again.
    fn shut_for(&self, f: impl FnOnce()) {
        self.set(true);
        f();
        self.set(false);
    }
}

struct Gated(DuplexStream, Arc<Gate>);

impl AsyncRead for Gated {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl AsyncWrite for Gated {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.1.shut.load(Ordering::SeqCst) {
            self.1.writers.lock().unwrap().push(cx.waker().clone());
            if self.1.shut.load(Ordering::SeqCst) {
                return Poll::Pending;
            }
        }
        Pin::new(&mut self.0).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn carriers_go_with_the_session_task() {
    let live = Arc::new(AtomicUsize::new(0));
    let (a, b) = tokio::io::duplex(64 * 1024);
    let (a, b) = (Counted::new(a, &live), Counted::new(b, &live));
    let server =
        tokio::spawn(async move { Session::accept(PipeIo::new(b), Config::default()).await });
    let client = Session::connect(PipeIo::new(a), Config::default())
        .await
        .unwrap();
    let server = server.await.unwrap().unwrap();
    // Read-through and write-through have used the sides.
    let (mut send, mut recv) = client.open_bi().await.unwrap();
    send.write_all(b"ping").await.unwrap();
    let (mut s2, mut r2) = server.accept_bi().await.unwrap();
    let mut buf = [0u8; 4];
    r2.read_exact(&mut buf).await.unwrap();
    s2.write_all(b"pong").await.unwrap();
    recv.read_exact(&mut buf).await.unwrap();
    // Every handle is kept; the sessions close.
    client.close().await;
    client.closing().await;
    server.closing().await;
    let start = Instant::now();
    while live.load(Ordering::SeqCst) != 0 {
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "{} carriers alive with the handles kept",
            live.load(Ordering::SeqCst)
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    drop((send, recv, s2, r2, client, server));
}

/// Dropped stream handles are released by the session, without waiting in the drop, also
/// after pipe 0 failed: the release is not tied to the bootstrap pipe. The drops run while
/// no carrier can write, so a drop that returns waited for no write.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dropped_streams_are_released_after_pipe_0_went() {
    use zmux::{Listener, ListenerConfig, PipeAuth, PipeHint, PipeId, PipeOptions};
    let mut c = Config::default();
    c.max_pipes = 4;
    c.pipe_auth = PipeAuth::psk(*b"carrier-release-0123456789abcdef").with_end_to_end();
    let listener = Listener::new(c.clone(), ListenerConfig::default()).unwrap();
    let gate = Arc::new(Gate::default());
    let carrier = || {
        let (a, b) = tokio::io::duplex(64 * 1024);
        let l = listener.clone();
        let far = Gated(b, gate.clone());
        tokio::spawn(async move {
            let _ = l
                .handle_pipe(
                    PipeIo::new(far),
                    PipeHint::from_peer(([127, 0, 0, 1], 0).into()),
                )
                .await;
        });
        PipeIo::new(Gated(a, gate.clone()))
    };
    let client = Session::connect(carrier(), c).await.unwrap();
    let server = listener.accept().await.unwrap();
    client
        .add_pipe(carrier(), PipeOptions::default())
        .await
        .unwrap();
    client.pipe(PipeId::new(0)).unwrap().abort().unwrap();
    let active = |s: &Session| s.stats().streams_active;
    for round in 0..4 {
        let (mut w, r) = client.open_bi().await.unwrap();
        w.write_all(b"unfinished").await.unwrap();
        let (sw, mut sr) = server.accept_bi().await.unwrap();
        let mut buf = [0; 10];
        sr.read_exact(&mut buf).await.unwrap();
        match round {
            0 => gate.shut_for(|| drop((w, r, sw, sr))),
            1 => gate.shut_for(|| drop((sr, sw, r, w))),
            // On a thread outside the runtime, as a binding's finalizer drops them.
            2 => gate.shut_for(|| {
                std::thread::spawn(move || drop((w, r, sw, sr)))
                    .join()
                    .unwrap();
            }),
            _ => {
                gate.shut_for(|| drop((w, r)));
                assert!(sr.read_to_end(1 << 10).await.is_err());
                gate.shut_for(|| drop((sw, sr)));
            }
        }
        let start = Instant::now();
        while active(&client) + active(&server) > 0 {
            assert!(
                start.elapsed() < Duration::from_secs(3),
                "round {round}: {} and {} streams active",
                active(&client),
                active(&server)
            );
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    }
    client.close().await;
    listener.close();
}
