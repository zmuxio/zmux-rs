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
    client.close(0u32.into(), b"");
    client.closed().await;
    server.closed().await;
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
