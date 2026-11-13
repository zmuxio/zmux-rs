//! A carrier with its own early data, through the tokio driver: what the
//! pipe reads waits for the carrier's verdict.

mod common;

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use common::watchdog;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use zmux::{Config, EarlyData, EarlyDataState, PipeIo, Session};

/// A read half that counts what it delivered.
struct Counted<R> {
    inner: R,
    seen: Arc<AtomicUsize>,
}

impl<R: AsyncRead + Unpin> AsyncRead for Counted<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let polled = Pin::new(&mut self.inner).poll_read(cx, buf);
        self.seen
            .fetch_add(buf.filled().len() - before, Ordering::SeqCst);
        polled
    }
}

/// A write half that discards what it takes until the restart: the rejected
/// early data of a carrier that goes on on the same stream.
struct Discarding<W> {
    inner: W,
    restarted: Arc<AtomicBool>,
}

impl<W: AsyncWrite + Unpin> AsyncWrite for Discarding<W> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if !self.restarted.load(Ordering::SeqCst) {
            return Poll::Ready(Ok(buf.len()));
        }
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

fn carrier_early() -> Config {
    let mut c = Config::default();
    c.early_data = EarlyData::default().with_carrier_early_data(true);
    c
}

/// The server's parameters of an earlier session.
async fn remembered() -> zmux::proto::params::TransportParameters {
    let (a, b) = tokio::io::duplex(1 << 16);
    let (client, server) = tokio::join!(
        Session::connect(PipeIo::new(a), carrier_early()),
        Session::accept(PipeIo::new(b), carrier_early()),
    );
    let (client, server) = (client.unwrap(), server.unwrap());
    let tp = client.parameters_to_remember().unwrap();
    client.close().await;
    server.close().await;
    tp
}

/// Small reads of another session while a first read waits.
async fn other_traffic() {
    let (a, b) = tokio::io::duplex(1 << 16);
    let (client, server) = tokio::join!(
        Session::connect(PipeIo::new(a), Config::default()),
        Session::accept(PipeIo::new(b), Config::default()),
    );
    let (client, server) = (client.unwrap(), server.unwrap());
    let (mut send, _recv) = client.open_bi().await.unwrap();
    send.write_all(&[0xff; 64]).await.unwrap();
    send.finish().unwrap();
    let (_s, mut r) = server.accept_bi().await.unwrap();
    r.read_to_end(1024).await.unwrap();
    client.close().await;
    server.close().await;
}

/// The server speaks before the carrier decided, with less than the client
/// remembers. Rejected early data assumed nothing: the session restarts, and
/// the server gets the client's parameters and the data.
#[test]
fn a_peer_speaking_before_a_rejection_leaves_the_restart() {
    // One thread: the other pipes' small reads share its scratch buffer.
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(watchdog(20, "restart", async {
        let mut remembered = remembered().await;
        remembered.initial_max_data = remembered.initial_max_data.map(|m| m * 2);
        let (a, b) = tokio::io::duplex(1 << 16);
        let (r, w) = tokio::io::split(a);
        let seen = Arc::new(AtomicUsize::new(0));
        let restarted = Arc::new(AtomicBool::new(false));
        let (decide, decided) = tokio::sync::oneshot::channel::<bool>();
        let hook = restarted.clone();
        let pipe = PipeIo::from_halves(
            Counted {
                inner: r,
                seen: seen.clone(),
            },
            Discarding {
                inner: w,
                restarted: restarted.clone(),
            },
        )
        .with_early_data(remembered, async move { decided.await.unwrap_or(false) })
        .with_early_restart(move || {
            hook.store(true, Ordering::SeqCst);
            Ok(())
        });
        let client = Session::connect(pipe, carrier_early()).await.unwrap();
        let (mut send, _recv) = client.open_bi().await.unwrap();
        send.write_all(b"early request").await.unwrap();
        send.finish().unwrap();
        let accepting = tokio::spawn(Session::accept(PipeIo::new(b), Config::default()));
        while seen.load(Ordering::SeqCst) == 0 {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        assert_eq!(client.early_data(), EarlyDataState::Pending);
        other_traffic().await;
        decide.send(false).unwrap();
        let server = accepting.await.unwrap().unwrap();
        let (_s, mut r) = server.accept_bi().await.unwrap();
        assert_eq!(r.read_to_end(1024).await.unwrap(), b"early request");
        assert_eq!(client.early_data(), EarlyDataState::Rejected);
        client.close().await;
        server.close().await;
    }));
}
