//! When the peer's `CONNECTION_CLOSE` and then EOF arrive during the local
//! `CONNECTION_CLOSE` write, the local close is still handed off and the
//! carrier's write side is shut down gracefully.

use std::io::{self, Read, Write};
use std::net::Shutdown;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering::Relaxed};
use std::task::{Context, Poll, ready};
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{mpsc, oneshot};
use zmux::proto::frame::{ConnectionClose, Frame, Frames, Gates};
use zmux::{ClockDomain, Config, MonotonicClock, VarInt};

const WATCHDOG: Duration = Duration::from_secs(30);
const LOCAL_CLOSE: (VarInt, &[u8]) = (VarInt::from_u32(7), b"client");
const PEER_CLOSE: (VarInt, &[u8]) = (VarInt::from_u32(8), b"server");

fn close_frame(record: &[u8]) -> Option<ConnectionClose<'_>> {
    Frames::new(
        record,
        Gates {
            pipe_ack: true,
            ..Gates::NONE
        },
    )
    .find_map(|frame| {
        if let Ok(Frame::ConnectionClose(close)) = frame {
            Some(close)
        } else {
            None
        }
    })
}

fn is_close(record: &[u8], (code, reason): (VarInt, &[u8])) -> bool {
    close_frame(record).is_some_and(|close| {
        close.application && close.error_code == code.into_inner() && close.reason == reason
    })
}

struct StoppedClock(Instant);

impl MonotonicClock for StoppedClock {
    fn now(&self) -> Instant {
        self.0
    }

    fn sleep_until(&self, deadline: Instant) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        if deadline <= self.0 {
            Box::pin(std::future::ready(()))
        } else {
            Box::pin(std::future::pending())
        }
    }
}

fn config() -> Config {
    // Keep handshake, handoff and linger deadlines out of the scenario.
    // The real-time watchdog only detects a stalled test.
    let mut config = Config::default();
    config.clock_domain = ClockDomain::with_source(StoppedClock(Instant::now()));
    config.test_hooks().no_first_ping = true;
    config
}

/// One complete carrier record per channel message. Closing the sender
/// delivers EOF after every record already handed off.
struct Reader {
    wire: mpsc::UnboundedReceiver<Vec<u8>>,
    ended: Option<oneshot::Sender<ReadEnd>>,
    read_end: ReadEnd,
}

#[derive(Default)]
struct ReadEnd {
    peer_close: bool,
    eof: bool,
}

impl Reader {
    fn copy_record(&mut self, record: Option<Vec<u8>>, buf: &mut [u8]) -> usize {
        let Some(record) = record else {
            self.read_end.eof = true;
            return 0;
        };
        if self.ended.is_some() && is_close(&record, PEER_CLOSE) {
            self.read_end.peer_close = true;
        }
        buf[..record.len()].copy_from_slice(&record);
        record.len()
    }
}

impl Drop for Reader {
    fn drop(&mut self) {
        if let Some(ended) = self.ended.take() {
            let _ = ended.send(std::mem::take(&mut self.read_end));
        }
    }
}

impl AsyncRead for Reader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let record = ready!(self.wire.poll_recv(cx));
        let n = self.copy_record(record, buf.initialize_unfilled());
        buf.advance(n);
        Poll::Ready(Ok(()))
    }
}

impl Read for Reader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let record = self.wire.blocking_recv();
        Ok(self.copy_record(record, buf))
    }
}

struct CloseGate {
    started: Option<oneshot::Sender<()>>,
    release: Option<oneshot::Receiver<()>>,
    finished: oneshot::Sender<Vec<u8>>,
}

struct Writer {
    wire: Option<mpsc::UnboundedSender<Vec<u8>>>,
    gate: Option<CloseGate>,
    shutdown: Arc<AtomicBool>,
}

impl Writer {
    fn gate(&mut self, record: &[u8]) -> Option<&mut CloseGate> {
        let gate = self.gate.as_mut()?;
        if !is_close(record, LOCAL_CLOSE) {
            return None;
        }
        if let Some(started) = gate.started.take() {
            let _ = started.send(());
        }
        Some(gate)
    }

    fn write_record(&mut self, record: &[u8], close: bool) -> usize {
        if close {
            let gate = self.gate.take().unwrap();
            let _ = gate.finished.send(record.to_vec());
        }
        if let Some(wire) = &self.wire {
            // A carrier can accept writes after its peer stops reading.
            let _ = wire.send(record.to_vec());
        }
        record.len()
    }
}

impl AsyncWrite for Writer {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        record: &[u8],
    ) -> Poll<io::Result<usize>> {
        let close = if let Some(gate) = self.gate(record) {
            ready!(Pin::new(gate.release.as_mut().unwrap()).poll(cx)).map_err(io::Error::other)?;
            true
        } else {
            false
        };
        Poll::Ready(Ok(self.write_record(record, close)))
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.shutdown.store(true, Relaxed);
        self.wire = None;
        Poll::Ready(Ok(()))
    }
}

impl Write for Writer {
    fn write(&mut self, record: &[u8]) -> io::Result<usize> {
        let close = if let Some(gate) = self.gate(record) {
            gate.release
                .take()
                .unwrap()
                .blocking_recv()
                .map_err(io::Error::other)?;
            true
        } else {
            false
        };
        Ok(self.write_record(record, close))
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct Scenario {
    started: oneshot::Receiver<()>,
    reader_ended: oneshot::Receiver<ReadEnd>,
    release: oneshot::Sender<()>,
    finished: oneshot::Receiver<Vec<u8>>,
    shutdown: Arc<AtomicBool>,
}

type Carrier = (Reader, Writer);

impl Scenario {
    fn new() -> (Self, Carrier, Carrier) {
        let (to_client, client_records) = mpsc::unbounded_channel();
        let (to_server, server_records) = mpsc::unbounded_channel();
        let (reader_ended, ended) = oneshot::channel();
        let (start, started) = oneshot::channel();
        let (release, resume) = oneshot::channel();
        let (finish, finished) = oneshot::channel();
        let shutdown = Arc::new(AtomicBool::new(false));
        (
            Self {
                started,
                reader_ended: ended,
                release,
                finished,
                shutdown: shutdown.clone(),
            },
            (
                Reader {
                    wire: client_records,
                    ended: Some(reader_ended),
                    read_end: ReadEnd::default(),
                },
                Writer {
                    wire: Some(to_server),
                    gate: Some(CloseGate {
                        started: Some(start),
                        release: Some(resume),
                        finished: finish,
                    }),
                    shutdown,
                },
            ),
            (
                Reader {
                    wire: server_records,
                    ended: None,
                    read_end: ReadEnd::default(),
                },
                Writer {
                    wire: Some(to_client),
                    gate: None,
                    shutdown: Arc::default(),
                },
            ),
        )
    }

    async fn check(self, close_peer: impl FnOnce(), closed: impl Future<Output = ()>) {
        self.started.await.expect("the local close write started");
        close_peer();
        let end = self.reader_ended.await.expect("the local reader ended");
        assert!(end.peer_close, "the local reader received the peer close");
        assert!(
            end.eof,
            "the driver consumed EOF before releasing the reader"
        );
        self.release
            .send(())
            .expect("the local close is still being written");
        let record = self.finished.await.expect("the local close was handed off");
        assert!(is_close(&record, LOCAL_CLOSE));
        closed.await;
        assert!(
            self.shutdown.load(Relaxed),
            "the writer was shut down gracefully"
        );
    }
}

#[tokio::test]
async fn the_peer_close_and_the_carrier_end_do_not_abort_the_local_close() {
    tokio::time::timeout(WATCHDOG, async {
        let (scenario, (client_read, client_write), (server_read, server_write)) = Scenario::new();
        let config = config();
        let (client, server) = tokio::try_join!(
            zmux::Session::connect(
                zmux::PipeIo::from_halves(client_read, client_write).records(),
                config.clone()
            ),
            zmux::Session::accept(
                zmux::PipeIo::from_halves(server_read, server_write).records(),
                config
            ),
        )
        .unwrap();

        let local = tokio::spawn(async move {
            client.close_with_error(LOCAL_CLOSE.0, LOCAL_CLOSE.1).await;
            client.closed().await;
        });
        let (close, should_close) = oneshot::channel();
        let peer = tokio::spawn(async move {
            should_close.await.unwrap();
            server.close_with_error(PEER_CLOSE.0, PEER_CLOSE.1).await;
        });
        scenario
            .check(|| close.send(()).unwrap(), async { local.await.unwrap() })
            .await;
        peer.await.unwrap();
    })
    .await
    .expect("close scenario timed out");
}

#[tokio::test]
async fn blocking_peer_close_and_carrier_end_do_not_abort_the_local_close() {
    tokio::time::timeout(WATCHDOG, async {
        use zmux::blocking::{PipeIo, Session};

        let (scenario, (client_read, client_write), (server_read, server_write)) = Scenario::new();
        let shutdown = scenario.shutdown.clone();
        let peer_config = config();
        let client_config = peer_config.clone();
        let (peer_ready, peer_established) = oneshot::channel();
        let (close, should_close) = oneshot::channel();
        let (done, closed) = oneshot::channel();
        let (peer_done, peer_closed) = oneshot::channel();
        let peer = std::thread::spawn(move || {
            let server = Session::accept(
                PipeIo::from_halves(server_read, server_write).records(),
                peer_config,
            )
            .expect("the peer established its session");
            peer_ready.send(()).unwrap();
            should_close.blocking_recv().unwrap();
            server.close_with_error(PEER_CLOSE.0, PEER_CLOSE.1);
            let _ = peer_done.send(());
        });
        let local = std::thread::spawn(move || {
            let pipe = PipeIo::from_halves(client_read, client_write)
                .records()
                .with_closer(move |how| {
                    if how == Shutdown::Write {
                        shutdown.store(true, Relaxed);
                    }
                });
            let client = Session::connect(pipe, client_config)
                .expect("the local endpoint established its session");
            // Receiving the peer's parameters can establish the client before its
            // writer builds the first record. Wait until the peer has consumed
            // our parameters so the close gate cannot hold up its handshake.
            peer_established.blocking_recv().unwrap();
            client.close_with_error(LOCAL_CLOSE.0, LOCAL_CLOSE.1);
            client.closed().unwrap();
            let _ = done.send(());
        });
        scenario
            .check(|| close.send(()).unwrap(), async { closed.await.unwrap() })
            .await;
        peer_closed.await.unwrap();
        local.join().unwrap();
        peer.join().unwrap();
    })
    .await
    .expect("close scenario timed out");
}
