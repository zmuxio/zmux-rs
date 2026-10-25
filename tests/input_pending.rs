//! Input counts as pending only while a read may have left bytes in its
//! carrier, so that a bulk sender, which receives acknowledgements and
//! credit in every round, writes whole batches rather than calls cut at
//! the write-call bound. Two and four pipes, `spread-eta`, over loopback
//! TCP and over an in-memory carrier that returns at most one 16 KiB chunk
//! per read (as a TLS layer hands over one record) and says so
//! (`PipeIo::with_partial_reads`).

mod common;

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf};
use tokio::net::TcpListener;
use zmux::test_hooks::take_write_call_bytes;
use zmux::{
    Config, Listener, ListenerConfig, PipeAuth, PipeHint, PipeIo, PipeOptions, Policy, Session,
};

const MIB: usize = 1 << 20;

fn config() -> Config {
    let mut c = Config::default();
    c.max_pipes = 4;
    c.pipe_auth = PipeAuth::psk(*b"input-pending---0123456789abcdef");
    c.scheduler = Policy::SpreadEta;
    c
}

/// An in-memory carrier whose reads return at most 16 KiB.
struct Chunked(DuplexStream);

impl AsyncRead for Chunked {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let mut chunk = [0u8; 16 * 1024];
        let room = buf.remaining().min(chunk.len());
        let mut part = ReadBuf::new(&mut chunk[..room]);
        let r = Pin::new(&mut self.0).poll_read(cx, &mut part);
        buf.put_slice(part.filled());
        r
    }
}

impl AsyncWrite for Chunked {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        b: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, b)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        b: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.0).poll_write_vectored(cx, b)
    }

    fn is_write_vectored(&self) -> bool {
        true
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

/// A carrier pair: loopback TCP, or chunked in-memory pipes.
async fn carriers(tcp: bool, l: Option<&TcpListener>) -> (PipeIo, PipeIo) {
    match l.filter(|_| tcp) {
        Some(l) => {
            let addr = l.local_addr().unwrap();
            let (a, b) = tokio::join!(tokio::net::TcpStream::connect(addr), l.accept());
            (PipeIo::tcp(a.unwrap()), PipeIo::tcp(b.unwrap().0))
        }
        None => {
            let (a, b) = tokio::io::duplex(256 * 1024);
            (
                PipeIo::new(Chunked(a)).with_partial_reads(),
                PipeIo::new(Chunked(b)).with_partial_reads(),
            )
        }
    }
}

/// The share of the bytes written after the first 16 MiB of a 64 MiB bulk
/// transfer over `pipes` pipes in calls cut at the write-call bound.
async fn bounded_share(pipes: usize, tcp: bool) -> f64 {
    let tl = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let listener = Listener::new(config(), ListenerConfig::default());
    let (a, b) = carriers(tcp, Some(&tl)).await;
    let l = listener.clone();
    tokio::spawn(async move { l.handle_pipe(b, PipeHint::default()).await });
    let client = Session::connect(a, config()).await.unwrap();
    let server = listener.accept().await.unwrap();
    for _ in 1..pipes {
        let (a, b) = carriers(tcp, Some(&tl)).await;
        let l = listener.clone();
        tokio::spawn(async move { l.handle_pipe(b, PipeHint::default()).await });
        client.add_pipe(a, PipeOptions::default()).unwrap();
    }
    let total = 64 * MIB;
    let (mut send, _) = client.open_bi().await.unwrap();
    let writer = tokio::spawn(async move {
        let chunk = bytes::Bytes::from(vec![7u8; MIB]);
        for _ in 0..total / MIB {
            send.write_chunk(chunk.clone()).await.unwrap();
        }
        send.finish().unwrap();
        send
    });
    let (_, mut recv) = server.accept_bi().await.unwrap();
    let mut got = 0;
    let mut counting = false;
    let mut buf = vec![0u8; 256 * 1024];
    while let Some(n) = recv.read(&mut buf).await.unwrap() {
        got += n;
        if !counting && got >= 16 * MIB {
            counting = true;
            take_write_call_bytes();
        }
    }
    let (all, bounded) = take_write_call_bytes();
    assert_eq!(got, total);
    drop(writer.await.unwrap());
    client.close(0u32.into(), b"");
    bounded as f64 / all as f64
}

/// A debug build's task is slow enough that reads often find their room
/// full, which is pending input indeed: the share is measured on release
/// builds (`cargo test --release --test input_pending`, as CI does).
#[test]
#[cfg_attr(debug_assertions, ignore = "release builds only")]
fn a_bulk_sender_writes_whole_batches_while_acknowledgements_flow_back() {
    common::multi_thread(async {
        for tcp in [true, false] {
            for pipes in [2, 4] {
                let share = bounded_share(pipes, tcp).await;
                assert!(
                    share <= 0.10,
                    "{pipes} pipes over {}: {:.1} % of the bytes in calls cut at the bound",
                    if tcp { "TCP" } else { "chunked memory" },
                    share * 100.0
                );
            }
        }
    });
}
