//! A pipe whose peer `CONNECTION_CLOSE` was read and whose input then ended, before the local
//! `CONNECTION_CLOSE` finished being written, still gets its own `CONNECTION_CLOSE` written
//! whole and its write side shut down gracefully (SPEC.md Section 6.5), not an abort. Every
//! wait is bounded, and the scenario runs repeatedly under CPU load.

#![allow(
    clippy::many_single_char_names,
    reason = "short conventional names in scenario code"
)]

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use zmux::{Config, VarInt};

const REPEAT: usize = 200;
/// How long the local carrier takes for each write: the local `CONNECTION_CLOSE` is still
/// being written when the peer's close and the carrier's end have been read.
const SLOW_WRITE: Duration = Duration::from_millis(40);
const BOUND: Duration = Duration::from_secs(10);

#[derive(Default)]
struct Seen {
    /// The input ends: the carrier's end of input, as if the peer closed it.
    eof: AtomicBool,
    /// Writes that completed their delay (and were handed on).
    writes_done: AtomicUsize,
    /// The write side was shut down.
    shutdown: AtomicBool,
    /// The carrier was dropped.
    dropped: AtomicBool,
}

/// A carrier whose writes take [`SLOW_WRITE`] and whose input can be ended on demand.
struct Slow {
    io: tokio::io::DuplexStream,
    seen: Arc<Seen>,
    sleep: Option<Pin<Box<tokio::time::Sleep>>>,
}

impl Drop for Slow {
    fn drop(&mut self) {
        self.seen.dropped.store(true, Ordering::SeqCst);
    }
}

impl AsyncRead for Slow {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        match Pin::new(&mut self.io).poll_read(cx, buf) {
            Poll::Ready(Ok(())) if buf.filled().len() > before => Poll::Ready(Ok(())),
            Poll::Ready(r) => Poll::Ready(r),
            Poll::Pending if self.seen.eof.load(Ordering::SeqCst) => Poll::Ready(Ok(())),
            Poll::Pending => {
                // Poll again soon to see the end of input.
                let waker = cx.waker().clone();
                tokio::spawn(async move {
                    tokio::time::sleep(Duration::from_millis(2)).await;
                    waker.wake();
                });
                Poll::Pending
            }
        }
    }
}

impl AsyncWrite for Slow {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let sleep = self
            .sleep
            .get_or_insert_with(|| Box::pin(tokio::time::sleep(SLOW_WRITE)));
        if sleep.as_mut().poll(cx).is_pending() {
            return Poll::Pending;
        }
        self.sleep = None;
        self.seen.writes_done.fetch_add(1, Ordering::SeqCst);
        // The peer may be gone: the bytes were handed to the carrier all the same.
        match Pin::new(&mut self.io).poll_write(cx, buf) {
            Poll::Ready(Err(_)) => Poll::Ready(Ok(buf.len())),
            r => r,
        }
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.seen.shutdown.store(true, Ordering::SeqCst);
        Pin::new(&mut self.io).poll_shutdown(cx)
    }
}

fn config() -> Config {
    let mut c = Config::default();
    c.test_hooks().linger_timeout = Some(Duration::from_secs(5));
    c
}

async fn one() {
    let seen = Arc::new(Seen::default());
    let (a, b) = tokio::io::duplex(1 << 16);
    let listener = zmux::Listener::new(config(), zmux::ListenerConfig::default()).unwrap();
    let l = listener.clone();
    tokio::spawn(async move {
        let _ = l
            .handle_pipe(
                zmux::PipeIo::new(b),
                zmux::PipeHint::from_peer(([127, 0, 0, 1], 0).into()),
            )
            .await;
    });
    let slow = Slow {
        io: a,
        seen: seen.clone(),
        sleep: None,
    };
    let client = zmux::Session::connect(zmux::PipeIo::new(slow), config())
        .await
        .unwrap();
    let server = listener.accept().await.unwrap();
    // Both ends close at once; the server's CONNECTION_CLOSE arrives while the client's is
    // still being written, then the carrier's input ends.
    let before = seen.writes_done.load(Ordering::SeqCst);
    let c = client.clone();
    let closing = tokio::spawn(async move {
        c.close_with_error(VarInt::from_u32(7), b"client").await;
    });
    tokio::time::sleep(Duration::from_millis(5)).await;
    let s = server.clone();
    tokio::spawn(async move {
        s.close_with_error(VarInt::from_u32(8), b"server").await;
    });
    tokio::time::sleep(Duration::from_millis(10)).await;
    seen.eof.store(true, Ordering::SeqCst);
    tokio::time::timeout(BOUND, closing)
        .await
        .expect("close bounded")
        .unwrap();
    tokio::time::timeout(BOUND, client.closed())
        .await
        .expect("closed bounded");
    // The write of CONNECTION_CLOSE ran to its end, and the carrier was ended after it by a
    // shutdown, not abandoned.
    let began = Instant::now();
    while !seen.dropped.load(Ordering::SeqCst) && began.elapsed() < BOUND {
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
    assert!(
        seen.dropped.load(Ordering::SeqCst),
        "the carrier was released"
    );
    assert!(
        seen.writes_done.load(Ordering::SeqCst) > before,
        "the local CONNECTION_CLOSE was written"
    );
    assert!(
        seen.shutdown.load(Ordering::SeqCst),
        "the write side was shut down"
    );
    listener.close();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_peer_close_and_the_carrier_end_do_not_abort_the_local_close() {
    // CPU load: busy threads for the whole run.
    let stop = Arc::new(AtomicBool::new(false));
    let load: Vec<_> = (0..std::thread::available_parallelism().map_or(4, std::num::NonZero::get))
        .map(|_| {
            let stop = stop.clone();
            std::thread::spawn(move || {
                let mut x = 1u64;
                while !stop.load(Ordering::Relaxed) {
                    x = x.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
                    std::hint::black_box(x);
                }
            })
        })
        .collect();
    let r = tokio::time::timeout(Duration::from_secs(180), async {
        for _ in 0..REPEAT {
            one().await;
        }
    })
    .await;
    stop.store(true, Ordering::Relaxed);
    for t in load {
        t.join().unwrap();
    }
    r.expect("every round ends in time");
}

// ---- blocking driver ---------------------------------------------------------------------

mod blocking {
    use std::io::{self, Write};
    use std::net::{Shutdown, TcpListener, TcpStream};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, mpsc};
    use std::time::{Duration, Instant};

    use zmux::VarInt;

    use super::{BOUND, REPEAT, SLOW_WRITE, config};

    #[derive(Default)]
    struct Seen {
        writes_done: AtomicUsize,
        shutdown_write: AtomicBool,
    }

    struct SlowWrite {
        io: TcpStream,
        seen: Arc<Seen>,
    }

    impl Write for SlowWrite {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            std::thread::sleep(SLOW_WRITE);
            self.seen.writes_done.fetch_add(1, Ordering::SeqCst);
            // The peer may be gone: the bytes were handed to the carrier all the same.
            Ok(self.io.write(buf).unwrap_or(buf.len()))
        }
        fn flush(&mut self) -> io::Result<()> {
            self.io.flush()
        }
    }

    fn one() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let a = TcpStream::connect(l.local_addr().unwrap()).unwrap();
        let (b, _) = l.accept().unwrap();
        let seen = Arc::new(Seen::default());
        let closer = zmux::blocking::PipeIo::tcp_closer(a.try_clone().unwrap());
        let seen_c = seen.clone();
        let slow = zmux::blocking::PipeIo::from_halves(
            a.try_clone().unwrap(),
            SlowWrite {
                io: a.try_clone().unwrap(),
                seen: seen.clone(),
            },
        )
        .with_closer(move |how| {
            if how == Shutdown::Write {
                seen_c.shutdown_write.store(true, Ordering::SeqCst);
            }
            closer(how);
        });
        let listener =
            zmux::blocking::Listener::new(config(), zmux::ListenerConfig::default(), None).unwrap();
        let ll = listener.clone();
        let t = std::thread::spawn(move || {
            ll.handle_pipe(
                zmux::blocking::PipeIo::from_tcp(b),
                zmux::blocking::PipeHint::default(),
            )
        });
        let client = zmux::blocking::Session::connect(slow, config()).unwrap();
        t.join().unwrap().ok();
        let server = listener
            .accept_timeout(Duration::from_secs(5))
            .ok()
            .flatten()
            .expect("a session");
        let before = seen.writes_done.load(Ordering::SeqCst);
        let c = client.clone();
        let closing = std::thread::spawn(move || {
            c.close_with_error(VarInt::from_u32(7), b"client");
        });
        std::thread::sleep(Duration::from_millis(5));
        let s = server.clone();
        std::thread::spawn(move || {
            s.close_with_error(VarInt::from_u32(8), b"server");
        });
        std::thread::sleep(Duration::from_millis(10));
        // The carrier's input ends while the local CONNECTION_CLOSE is being written.
        let _ = a.shutdown(Shutdown::Read);
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            closing.join().unwrap();
            let _ = tx.send(());
        });
        rx.recv_timeout(BOUND).expect("close bounded");
        let began = Instant::now();
        while !seen.shutdown_write.load(Ordering::SeqCst) && began.elapsed() < BOUND {
            std::thread::sleep(Duration::from_millis(2));
        }
        assert!(
            seen.writes_done.load(Ordering::SeqCst) > before,
            "the local CONNECTION_CLOSE was written"
        );
        assert!(
            seen.shutdown_write.load(Ordering::SeqCst),
            "the write side was shut down"
        );
        listener.close();
    }

    #[test]
    fn the_peer_close_and_the_carrier_end_do_not_abort_the_local_close() {
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            for _ in 0..REPEAT {
                one();
            }
            let _ = tx.send(());
        });
        rx.recv_timeout(std::time::Duration::from_secs(240))
            .expect("every round ends in time");
    }
}
