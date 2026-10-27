//! Streams as pipes (EXTENSIONS.md Section 10.2): a
//! nested session over streams of an outer session, single-pipe and
//! multipath; the mapping of every pipe event to a stream operation and
//! back; no carrier capability; the loop check; an outer session without
//! the preamble (a plain QMux peer).

mod common;

use std::future::Future;
use std::io;
use std::pin::{Pin, pin};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use bytes::Bytes;
use common::{connect, duplex, eventually, multi_thread, settle, snapshot, watchdog};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use zmux::proto::{ApplicationErrorCode, TransportParameters};
use zmux::{
    Config, Listener, ListenerConfig, PipeAuth, PipeError, PipeHint, PipeIo, PipeOptions,
    PipeState, RecvStream, RttSource, SendStream, Session, VarInt,
};

fn carrier_failed() -> VarInt {
    VarInt::from_u64(ApplicationErrorCode::ZMUX_CARRIER_FAILED.0).unwrap()
}

fn multipath() -> Config {
    let mut c = Config::default();
    c.max_pipes = 6;
    c.pipe_auth = PipeAuth::psk(*b"nested-psk------0123456789abcdef");
    c
}

/// An outer session pair over an in-memory carrier.
async fn outer(client: Config, server: Config) -> (Session, Session) {
    let ((a, _), (b, _)) = duplex(1 << 20);
    connect(a, b, client, server).await
}

/// Polls `f` once.
fn poll_once<F: Future>(f: F) -> Option<F::Output> {
    let mut f = pin!(f);
    match f.as_mut().poll(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(v) => Some(v),
        Poll::Pending => None,
    }
}

/// Writes `len` bytes of a pattern on a nested stream and checks the echo.
async fn echo(client: &Session, server: &Session, len: usize) {
    let echo = {
        let server = server.clone();
        tokio::spawn(async move {
            let (mut send, mut recv) = server.accept_bi().await.unwrap();
            let data = recv.read_to_end(len).await.unwrap();
            send.write_all(&data).await.unwrap();
            send.finish().unwrap();
        })
    };
    let (mut send, mut recv) = client.open_bi().await.unwrap();
    let data: Vec<u8> = (0..len).map(|i| (i * 7 + i / 251) as u8).collect();
    let writer = {
        let data = data.clone();
        tokio::spawn(async move {
            send.write_all(&data).await.unwrap();
            send.finish().unwrap();
            send
        })
    };
    let back = recv.read_to_end(len).await.unwrap();
    assert!(back == data, "the echo differs");
    drop(writer.await.unwrap());
    echo.await.unwrap();
}

/// The two sides of a nested single-pipe session over one outer stream:
/// the client opens the carrier, the server accepts it.
async fn nested_over(oc: &Session, os: &Session, tlvs: &[(u64, &[u8])]) -> (Session, Session) {
    let accept = {
        let os = os.clone();
        tokio::spawn(async move {
            let (send, recv) = os.accept_bi().await.unwrap();
            let pre = recv.preamble();
            let carrier = pre.is_pipe_carrier();
            let tlvs: Vec<(u64, Bytes)> = pre.tlvs().collect();
            let s = Session::accept(PipeIo::from_stream(send, recv), Config::default())
                .await
                .unwrap();
            (s, carrier, tlvs)
        })
    };
    let pre = tlvs
        .iter()
        .fold(zmux::Preamble::new(), |p, (t, v)| p.with_tlv(*t, v));
    let pipe = oc.open_pipe_stream(&pre).await.unwrap();
    let nc = Session::connect(pipe, Config::default()).await.unwrap();
    let (ns, carrier, got) = accept.await.unwrap();
    assert_eq!(carrier, !oc.is_plain_qmux_peer(), "PIPE_CARRIER");
    let want: Vec<(u64, Bytes)> = tlvs
        .iter()
        .map(|(t, v)| (*t, Bytes::copy_from_slice(v)))
        .collect();
    assert_eq!(got, want, "the application TLVs, in order");
    (nc, ns)
}

#[test]
fn a_nested_session_runs_over_a_stream_and_closes_it_cleanly() {
    multi_thread(async {
        let base = snapshot();
        {
            let (oc, os) = outer(Config::default(), Config::default()).await;
            let (nc, ns) = nested_over(&oc, &os, &[(0x1000, b"dest"), (0x1002, &[7])]).await;
            watchdog(30, "echo", echo(&nc, &ns, 4 << 20)).await;
            // No carrier capability: RTT from the nested session's own
            // samples, never the kernel's.
            let p = nc.pipe_stats().remove(0);
            assert_ne!(p.rtt_source, Some(RttSource::Kernel));
            // No lanes by default over an outer session on one ordered
            // pipe, whose streams share one byte stream.
            assert_eq!((p.lanes_out, p.lanes_in), (1, 1));
            // A graceful close ends the outer stream with a FIN each way:
            // both sides read everything written, nothing was reset.
            nc.close(VarInt::ZERO, b"");
            watchdog(10, "nested closed", ns.closed()).await;
            eventually(10, "outer streams released", || {
                oc.stats().streams_active == 0 && os.stats().streams_active == 0
            })
            .await;
            assert_eq!(oc.meter().bytes_written(), os.meter().bytes_read());
            assert_eq!(os.meter().bytes_written(), oc.meter().bytes_read());
            assert!(oc.close_reason().is_none() && os.close_reason().is_none());
            oc.close(VarInt::ZERO, b"");
        }
        settle(base, 10, "nested over a stream").await;
    });
}

/// A carrier half over a stream whose handle the test keeps: it can
/// finish, reset or stop the stream under a running nested session.
struct Raw<T>(Arc<Mutex<Option<T>>>);

impl<T> Clone for Raw<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<T> Raw<T> {
    fn new(t: T) -> Self {
        Self(Arc::new(Mutex::new(Some(t))))
    }

    fn with<R>(&self, f: impl FnOnce(&mut T) -> R) -> R {
        f(self.0.lock().unwrap().as_mut().expect("present"))
    }
}

fn gone() -> io::Error {
    io::Error::new(io::ErrorKind::NotConnected, "gone")
}

impl AsyncRead for Raw<RecvStream> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.0.lock().unwrap().as_mut() {
            Some(r) => Pin::new(r).poll_read(cx, buf),
            None => Poll::Ready(Err(gone())),
        }
    }
}

impl AsyncWrite for Raw<SendStream> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.0.lock().unwrap().as_mut() {
            Some(w) => Pin::new(w).poll_write(cx, buf),
            None => Poll::Ready(Err(gone())),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.0.lock().unwrap().as_mut() {
            Some(w) => Pin::new(w).poll_shutdown(cx),
            None => Poll::Ready(Ok(())),
        }
    }
}

/// A receiving part that reads nothing more once muted: the session on
/// it sees neither data nor an error.
struct Muted(Raw<RecvStream>, Arc<AtomicBool>);

impl AsyncRead for Muted {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.1.load(Ordering::SeqCst) {
            return Poll::Pending;
        }
        Pin::new(&mut this.0).poll_read(cx, buf)
    }
}

/// A nested multipath session bootstrapped over a direct carrier: the
/// client (X) joins pipes over streams of the outer session; the server
/// (Y) handles them with its nested listener.
struct Nested {
    oc: Session,
    os: Session,
    x: Session,
    y: Session,
    listener: Listener,
}

impl Nested {
    async fn new() -> Self {
        let (oc, os) = outer(Config::default(), Config::default()).await;
        // An instance id exercises the locator prefix on every join.
        let mut limits = ListenerConfig::default();
        limits.instance_id = b"instance".to_vec();
        let listener = Listener::new(multipath(), limits);
        let ((a, _), (b, _)) = duplex(1 << 20);
        {
            let l = listener.clone();
            tokio::spawn(async move {
                let _ = l.handle_pipe(b, PipeHint::default()).await;
            });
        }
        let x = Session::connect(a, multipath()).await.unwrap();
        let y = listener.accept().await.unwrap();
        assert!(x.multipath() == zmux::Multipath::InUse);
        Self {
            oc,
            os,
            x,
            y,
            listener,
        }
    }

    /// Joins a pipe over a new outer stream with the adapter on both sides.
    async fn join_stream(&self) -> zmux::Pipe {
        let l = self.listener.clone();
        let os = self.os.clone();
        tokio::spawn(async move {
            let (send, recv) = os.accept_bi().await.unwrap();
            let _ = l
                .handle_pipe(PipeIo::from_stream(send, recv), PipeHint::default())
                .await;
        });
        let pipe = self
            .oc
            .open_pipe_stream(&zmux::Preamble::new())
            .await
            .unwrap();
        let p = self.x.add_pipe(pipe, PipeOptions::default()).unwrap();
        self.until_active(&p).await;
        p
    }

    /// Joins a pipe over a new outer stream whose server side the test
    /// controls (a plain carrier over the raw stream).
    async fn join_raw(&self) -> (zmux::Pipe, Raw<SendStream>, Raw<RecvStream>) {
        let pipe = self
            .oc
            .open_pipe_stream(&zmux::Preamble::new())
            .await
            .unwrap();
        let p = self.x.add_pipe(pipe, PipeOptions::default()).unwrap();
        let (send, recv) = self.os.accept_bi().await.unwrap();
        let (send, recv) = (Raw::new(send), Raw::new(recv));
        let l = self.listener.clone();
        let carrier = PipeIo::from_halves(recv.clone(), send.clone());
        tokio::spawn(async move {
            let _ = l.handle_pipe(carrier, PipeHint::default()).await;
        });
        self.until_active(&p).await;
        (p, send, recv)
    }

    async fn until_active(&self, p: &zmux::Pipe) {
        eventually(10, "pipe active", || {
            p.stats()
                .is_some_and(|i| i.outbound == Some(PipeState::Active) && !i.in_probation)
        })
        .await;
    }
}

fn state(p: &zmux::Pipe) -> (Option<PipeState>, Option<PipeState>, u64) {
    p.stats().map_or((None, None, 0), |i| {
        (i.inbound, i.outbound, i.failure_count)
    })
}

#[test]
fn a_nested_multipath_session_moves_between_stream_pipes_and_a_direct_carrier() {
    multi_thread(async {
        let base = snapshot();
        {
            let n = Nested::new().await;
            let p1 = n.join_stream().await;
            let _p2 = n.join_stream().await;
            watchdog(30, "echo over three pipes", echo(&n.x, &n.y, 2 << 20)).await;
            let info = p1.stats().unwrap();
            assert_eq!(info.rtt_source, Some(RttSource::Ack), "no carrier RTT");
            // The relayed pipes alone carry the session once the first
            // stream pipe fails.
            p1.abort().unwrap();
            watchdog(30, "echo over the rest", echo(&n.x, &n.y, 1 << 20)).await;
            n.x.close(VarInt::ZERO, b"");
            n.oc.close(VarInt::ZERO, b"");
            n.listener.close();
        }
        settle(base, 10, "nested multipath").await;
    });
}

/// A nested single-pipe session whose client (X) uses the adapter and
/// whose server (Y) runs over the raw stream the test controls.
async fn single_raw(
    oc: &Session,
    os: &Session,
) -> (Session, Session, Raw<SendStream>, Raw<RecvStream>) {
    let pipe = oc.open_pipe_stream(&zmux::Preamble::new()).await.unwrap();
    let x = tokio::spawn(Session::connect(pipe, Config::default()));
    let (send, recv) = os.accept_bi().await.unwrap();
    let (send, recv) = (Raw::new(send), Raw::new(recv));
    let y = Session::accept(
        PipeIo::from_halves(recv.clone(), send.clone()),
        Config::default(),
    )
    .await
    .unwrap();
    let x = x.await.unwrap().unwrap();
    (x, y, send, recv)
}

/// [`single_raw`] whose server reads nothing more once the flag is set.
async fn single_muted(
    oc: &Session,
    os: &Session,
) -> (Session, Session, Raw<RecvStream>, Arc<AtomicBool>) {
    let pipe = oc.open_pipe_stream(&zmux::Preamble::new()).await.unwrap();
    let x = tokio::spawn(Session::connect(pipe, Config::default()));
    let (send, recv) = os.accept_bi().await.unwrap();
    let (send, recv) = (Raw::new(send), Raw::new(recv));
    let mute = Arc::new(AtomicBool::new(false));
    let y = Session::accept(
        PipeIo::from_halves(Muted(recv.clone(), mute.clone()), send),
        Config::default(),
    )
    .await
    .unwrap();
    let x = x.await.unwrap().unwrap();
    (x, y, recv, mute)
}

#[test]
fn stream_events_map_to_pipe_events() {
    multi_thread(async {
        let base = snapshot();
        {
            let (oc, os) = outer(Config::default(), Config::default()).await;
            let code = VarInt::from_u32(7);

            // A FIN received is the graceful end of the inbound pipe:
            // between zmux endpoints (a session with acknowledgement)
            // without CONNECTION_CLOSE, a carrier failure.
            let (x, _y, send, _recv) = single_raw(&oc, &os).await;
            send.with(|s| s.finish()).unwrap();
            let e = watchdog(10, "closed", x.closed()).await;
            assert!(matches!(e, zmux::SessionError::PipesLost { .. }), "{e:?}");

            // A reset received fails the inbound pipe.
            let (x, _y, send, _recv) = single_raw(&oc, &os).await;
            send.with(|s| s.reset(code)).unwrap();
            let e = watchdog(10, "closed", x.closed()).await;
            assert_eq!(
                e,
                zmux::SessionError::PipesLost {
                    last: Some(zmux::PipeFailure::Carrier(io::ErrorKind::ConnectionReset))
                }
            );

            // STOP_SENDING received fails the outbound pipe at once, though
            // the pipe has nothing to write (EXTENSIONS.md Section 10.2).
            // The server reads nothing more, so only the STOP_SENDING can
            // end the client's pipe.
            let (x, _y, recv, mute) = single_muted(&oc, &os).await;
            // The client's early output (its first RTT probe) is out.
            tokio::time::sleep(Duration::from_millis(200)).await;
            mute.store(true, Ordering::SeqCst);
            recv.with(|r| r.stop(code)).unwrap();
            let e = watchdog(2, "closed without a write", x.closed()).await;
            assert_eq!(
                e,
                zmux::SessionError::PipesLost {
                    last: Some(zmux::PipeFailure::Carrier(io::ErrorKind::ConnectionReset))
                }
            );
            assert!(oc.close_reason().is_none() && os.close_reason().is_none());
            oc.close(VarInt::ZERO, b"");

            // In a multipath session: a pipe aborted locally resets and
            // stops its stream with ZMUX_CARRIER_FAILED (the reset keeps
            // the opener's preamble, else the outer session would fail).
            let n = Nested::new().await;
            let (p, send, recv) = n.join_raw().await;
            p.abort().unwrap();
            eventually(10, "reset and stop with ZMUX_CARRIER_FAILED", || {
                let reset = recv.with(|r| poll_once(r.received_reset()));
                let stopped = send.with(|s| poll_once(s.stopped()));
                matches!(reset, Some(Ok(Some(c))) if c == carrier_failed())
                    && matches!(stopped, Some(Ok(Some(c))) if c == carrier_failed())
            })
            .await;
            assert!(n.oc.close_reason().is_none() && n.os.close_reason().is_none());

            // The outer session lost: its stream pipes fail, the nested
            // session continues on its direct carrier.
            let p = n.join_stream().await;
            n.os.close(VarInt::from_u32(3), b"");
            eventually(10, "the stream pipe failed", || {
                matches!(
                    state(&p).1,
                    Some(PipeState::Failed | PipeState::Retired) | None
                )
            })
            .await;
            watchdog(30, "echo on the direct carrier", echo(&n.x, &n.y, 64 << 10)).await;
            n.x.close(VarInt::ZERO, b"");
            n.listener.close();
        }
        settle(base, 10, "mapping").await;
    });
}

/// MULTIPATH.md Section 10.5: a stream of a multiplexed session is never
/// carrier-bound and never offers E from the exporter of a connection
/// below it, which the multiplexer's other carriers share: a stream
/// carrier ignores an exporter, so a nested session whose only secret
/// source is E does not use multipath.
#[test]
fn a_stream_carrier_takes_no_exporter() {
    multi_thread(async {
        let base = snapshot();
        {
            let (oc, os) = outer(Config::default(), Config::default()).await;
            let mut tls = multipath();
            tls.pipe_auth = PipeAuth::tls();
            let accept = {
                let (os, tls) = (os.clone(), tls.clone());
                tokio::spawn(async move {
                    let (send, recv) = os.accept_bi().await.unwrap();
                    let carrier =
                        PipeIo::from_stream(send, recv).with_tls_exporter(|_| Some(vec![7; 32]));
                    common::accept(carrier, tls).await.unwrap()
                })
            };
            let carrier = oc
                .open_pipe_stream(&zmux::Preamble::new())
                .await
                .unwrap()
                .with_tls_exporter(|_| Some(vec![7; 32]));
            let nc = Session::connect(carrier, tls).await.unwrap();
            let ns = accept.await.unwrap();
            assert!(
                nc.multipath() != zmux::Multipath::InUse
                    && ns.multipath() != zmux::Multipath::InUse
            );
            watchdog(30, "echo", echo(&nc, &ns, 64 << 10)).await;
            nc.close(VarInt::ZERO, b"");
            watchdog(10, "nested closed", ns.closed()).await;
            oc.close(VarInt::ZERO, b"");
            watchdog(10, "outer closed", os.closed()).await;
        }
        settle(base, 10, "stream carrier without exporter").await;
    });
}

/// `PipeIo::from_stream` takes the two parts of one stream: the parts of two
/// different streams are refused.
#[test]
fn a_stream_carrier_takes_the_parts_of_one_stream() {
    multi_thread(async {
        let base = snapshot();
        {
            let (oc, os) = outer(Config::default(), Config::default()).await;
            let (s1, r1) = oc.open_bi().await.unwrap();
            let (s2, r2) = oc.open_bi().await.unwrap();
            let mixed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                PipeIo::from_stream(s1, r2)
            }));
            assert!(mixed.is_err(), "the parts of two streams");
            drop((s2, r1));
            oc.close(VarInt::ZERO, b"");
            watchdog(10, "closed", os.closed()).await;
        }
        settle(base, 10, "mixed parts").await;
    });
}

#[test]
fn a_pipe_never_runs_over_its_own_session() {
    multi_thread(async {
        let base = snapshot();
        {
            let n = Nested::new().await;
            let p = n.join_stream().await;
            // The outer session cannot take a pipe over a stream of the
            // nested session that runs over it.
            let looped = n.x.open_pipe_stream(&zmux::Preamble::new()).await.unwrap();
            assert_eq!(
                n.oc.add_pipe(looped, PipeOptions::default()).err(),
                Some(PipeError::CarrierLoop)
            );
            // Nor a session a stream of its own.
            let own = n.x.open_pipe_stream(&zmux::Preamble::new()).await.unwrap();
            assert_eq!(
                n.x.add_pipe(own, PipeOptions::default()).err(),
                Some(PipeError::CarrierLoop)
            );
            // Once the pipe over the outer session is gone, nothing runs
            // over it any more: the refusal, if any, is not a loop.
            p.abort().unwrap();
            eventually(10, "the stream pipe retired", || p.stats().is_none()).await;
            let unlooped = n.x.open_pipe_stream(&zmux::Preamble::new()).await.unwrap();
            assert_ne!(
                n.oc.add_pipe(unlooped, PipeOptions::default()).err(),
                Some(PipeError::CarrierLoop)
            );
            n.x.close(VarInt::ZERO, b"");
            n.oc.close(VarInt::ZERO, b"");
            n.listener.close();
        }
        settle(base, 10, "loop check").await;
    });
}

/// MULTIPATH.md Section 5.4 step 7: a joiner that
/// cannot see the loop (its carrier hides that it is a stream of its own
/// session) joins over a stream of that session; the listener sees that
/// the carrier is a stream of the session it would join, refuses with
/// PIPE_ABANDON(ZMUX_PIPE_RESOURCE_LIMIT), and the joiner backs off.
#[test]
fn the_listener_refuses_a_join_over_a_stream_of_its_own_session() {
    multi_thread(async {
        let base = snapshot();
        {
            let n = Nested::new().await;
            let handled = {
                let (y, l) = (n.y.clone(), n.listener.clone());
                tokio::spawn(async move {
                    let (send, recv) = y.accept_bi().await.unwrap();
                    l.handle_pipe(PipeIo::from_stream(send, recv), PipeHint::default())
                        .await
                })
            };
            let (send, recv) = n.x.open_bi().await.unwrap();
            let hidden = PipeIo::from_halves(Raw::new(recv), Raw::new(send));
            let p = n.x.add_pipe(hidden, PipeOptions::default()).unwrap();
            let handled = watchdog(10, "the join handled", handled).await.unwrap();
            assert_eq!(handled.err(), Some(zmux::HandleError::Rejected));
            eventually(10, "the refusal reached the joiner", || {
                n.x.stats().join_refusals == 1
            })
            .await;
            eventually(10, "the refused pipe retired", || p.stats().is_none()).await;
            assert_eq!(n.y.pipe_stats().len(), 1, "only the direct carrier");
            n.x.close(VarInt::ZERO, b"");
            n.oc.close(VarInt::ZERO, b"");
            n.listener.close();
        }
        settle(base, 10, "looped join").await;
    });
}

/// Streams of a connection that carries no pipe of the listener's
/// sessions are unauthenticated carriers like any other: the pending
/// limits apply to them (MULTIPATH.md Section 5.5).
#[test]
fn streams_of_a_connection_without_our_pipes_are_held_to_the_pending_limits() {
    multi_thread(async {
        let base = snapshot();
        {
            let (oc, os) = outer(Config::default(), Config::default()).await;
            let mut limits = ListenerConfig::default();
            limits.max_pending_per_source = 1;
            let listener = Listener::new(Config::default(), limits);
            let mut held = Vec::new();
            let mut handled = Vec::new();
            for _ in 0..2 {
                // A stream that never completes its first record.
                let (mut send, recv) = oc.open_bi().await.unwrap();
                send.write_all(&[0x40]).await.unwrap();
                held.push((send, recv));
                let (send, recv) = watchdog(10, "accept", os.accept_bi()).await.unwrap();
                let l = listener.clone();
                handled.push(tokio::spawn(async move {
                    l.handle_pipe(PipeIo::from_stream(send, recv), PipeHint::default())
                        .await
                }));
            }
            let second = watchdog(10, "the second refused", handled.pop().unwrap())
                .await
                .unwrap();
            assert_eq!(second.err(), Some(zmux::HandleError::Refused));
            listener.close();
            let _ = watchdog(10, "the first ended", handled.pop().unwrap()).await;
            drop(held);
            oc.close(VarInt::ZERO, b"");
            os.closed().await;
        }
        settle(base, 10, "pending streams").await;
    });
}

/// A connection that carries a pipe of ours lets one new stream per such
/// pipe wait for its first record outside the pending limits (the lane the
/// peer may be opening, MULTIPATH.md Section 5.5): a second one takes a
/// slot like any carrier, and an exempt stream that turns out a new session
/// takes one then, refused when its source has its share.
#[test]
fn a_connection_with_our_pipe_exempts_one_waiting_stream_per_pipe() {
    multi_thread(async {
        let base = snapshot();
        {
            let (oc, os) = outer(Config::default(), Config::default()).await;
            // One pipe of a session of this process on the connection.
            let (nc, ns) = nested_over(&oc, &os, &[]).await;
            let mut limits = ListenerConfig::default();
            limits.max_pending_per_source = 1;
            let listener = Listener::new(Config::default(), limits);
            let handle = |send, recv| {
                let l = listener.clone();
                tokio::spawn(async move {
                    l.handle_pipe(PipeIo::from_stream(send, recv), PipeHint::default())
                        .await
                })
            };
            // A stream that never completes its first record.
            let waiting = || async {
                let (mut send, recv) = oc.open_bi().await.unwrap();
                send.write_all(&[0x40]).await.unwrap();
                let (s, r) = watchdog(10, "accept", os.accept_bi()).await.unwrap();
                ((send, recv), handle(s, r))
            };
            let settle_ms = || tokio::time::sleep(Duration::from_millis(50));
            // The pipe's one exempt stream, then the source's one slot.
            let (b, b_handled) = waiting().await;
            settle_ms().await;
            let (c, c_handled) = waiting().await;
            settle_ms().await;
            // Neither left: refused.
            let (d, d_handled) = waiting().await;
            let r = watchdog(10, "the third refused", d_handled).await.unwrap();
            assert_eq!(r.err(), Some(zmux::HandleError::Refused));
            // The exempt stream goes: the next one is exempt until its
            // first record makes it a new session, which needs the slot C
            // holds.
            drop(b);
            let _ = watchdog(10, "the exempt one ended", b_handled).await;
            let (send, recv) = oc.open_bi().await.unwrap();
            let client = tokio::spawn(async move {
                let _ = Session::connect(PipeIo::from_stream(send, recv), Config::default()).await;
            });
            let (s, r) = watchdog(10, "accept", os.accept_bi()).await.unwrap();
            let r = watchdog(10, "the new session refused", handle(s, r))
                .await
                .unwrap();
            assert_eq!(r.err(), Some(zmux::HandleError::Refused));
            listener.close();
            let _ = watchdog(10, "the slot holder ended", c_handled).await;
            drop((c, d));
            let _ = watchdog(10, "client", client).await;
            nc.close(VarInt::ZERO, b"");
            ns.closed().await;
            oc.close(VarInt::ZERO, b"");
            os.closed().await;
        }
        settle(base, 10, "exempt streams").await;
    });
}

/// A carrier evicted for a newer one when every pending slot is taken is
/// closed at once (MULTIPATH.md Section 5.6), not left to its first-record
/// timeout.
#[test]
fn an_evicted_carrier_is_closed_at_once() {
    multi_thread(async {
        let base = snapshot();
        {
            let (oc, os) = outer(Config::default(), Config::default()).await;
            let mut limits = ListenerConfig::default();
            limits.max_pending = 1;
            limits.first_record_timeout = Duration::from_secs(60);
            let listener = Listener::new(Config::default(), limits);
            let mut held = Vec::new();
            let mut handled = Vec::new();
            for _ in 0..2 {
                let (mut send, recv) = oc.open_bi().await.unwrap();
                send.write_all(&[0x40]).await.unwrap();
                held.push((send, recv));
                let (send, recv) = watchdog(10, "accept", os.accept_bi()).await.unwrap();
                let l = listener.clone();
                handled.push(tokio::spawn(async move {
                    l.handle_pipe(PipeIo::from_stream(send, recv), PipeHint::default())
                        .await
                }));
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            let first = handled.remove(0);
            let r = watchdog(10, "the evicted one closed", first).await.unwrap();
            assert_eq!(r.err(), Some(zmux::HandleError::Refused));
            listener.close();
            let _ = watchdog(10, "the second ended", handled.remove(0)).await;
            drop(held);
            oc.close(VarInt::ZERO, b"");
            os.closed().await;
        }
        settle(base, 10, "evicted carriers").await;
    });
}

#[test]
fn an_outer_session_without_the_preamble_carries_a_pipe_from_offset_zero() {
    multi_thread(async {
        let base = snapshot();
        {
            // The server is a plain QMux peer: no preamble, no
            // RESET_STREAM_AT.
            let mut qmux = Config::default();
            qmux.test_hooks().transport_parameters = Some(TransportParameters {
                initial_max_data: Some(1 << 24),
                initial_max_stream_data_bidi_local: Some(1 << 22),
                initial_max_stream_data_bidi_remote: Some(1 << 22),
                initial_max_stream_data_uni: Some(1 << 22),
                initial_max_streams_bidi: Some(16),
                initial_max_streams_uni: Some(16),
                ..TransportParameters::default()
            });
            let (oc, os) = outer(Config::default(), qmux).await;
            assert!(oc.is_plain_qmux_peer());
            assert!(matches!(
                oc.open_pipe_stream(&zmux::Preamble::new().with_tlv(0x1000, b"x"))
                    .await,
                Err(zmux::OpenError::NotNegotiated)
            ));
            let (nc, ns) = nested_over(&oc, &os, &[]).await;
            watchdog(30, "echo", echo(&nc, &ns, 1 << 20)).await;
            nc.close(VarInt::ZERO, b"");
            watchdog(10, "nested closed", ns.closed()).await;
            oc.close(VarInt::ZERO, b"");
        }
        settle(base, 10, "plain outer").await;
    });
}

#[test]
fn an_unused_carrier_is_aborted_when_dropped() {
    multi_thread(async {
        let (oc, os) = outer(Config::default(), Config::default()).await;
        let pipe = oc.open_pipe_stream(&zmux::Preamble::new()).await.unwrap();
        // Dropped before the nested session wrote anything: the abort of a
        // stream that sent nothing is invisible, it never opened.
        drop(pipe);
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(os.stats().streams_opened_remote, 0);
        oc.close(VarInt::ZERO, b"");
    });
}

/// Lanes over a stream carrier (MULTIPATH.md Section 2.5, EXTENSIONS.md
/// Section 10.2): the nested writer opens further streams of the outer
/// session as lanes once lane 0 is acknowledged, the receiving application
/// routes the streams it accepts with `handle_lane`, and the data of a
/// bulk stream moves to a lane; a stream that names no pipe is refused.
#[test]
fn a_nested_session_spreads_its_pipe_over_lanes_of_the_outer_session() {
    multi_thread(async {
        let base = snapshot();
        {
            let (oc, os) = outer(Config::default(), Config::default()).await;
            // The first stream the server accepts carries the nested
            // session; every later one may be a lane.
            let router = {
                let os = os.clone();
                tokio::spawn(async move {
                    let (send, recv) = os.accept_bi().await.unwrap();
                    let io = PipeIo::from_stream(send, recv).with_lanes(true);
                    let ns = Session::accept(io, Config::default()).await.unwrap();
                    let lanes = tokio::spawn(async move {
                        while let Ok((send, recv)) = os.accept_bi().await {
                            let _ =
                                zmux::carrier::handle_lane(PipeIo::from_stream(send, recv)).await;
                        }
                    });
                    (ns, lanes)
                })
            };
            let pipe = oc
                .open_pipe_stream(&zmux::Preamble::new())
                .await
                .unwrap()
                .with_lanes(true);
            let nc = Session::connect(pipe, Config::default()).await.unwrap();
            let (ns, lanes) = router.await.unwrap();
            // Bulk data: a lane opens and confirms, the stream binds to it.
            watchdog(30, "echo", echo(&nc, &ns, 1 << 20)).await;
            watchdog(30, "echo again", echo(&nc, &ns, 1 << 20)).await;
            let out = nc.pipe_stats().remove(0);
            let inp = ns.pipe_stats().remove(0);
            assert!(out.lanes_out >= 2, "the client opened a lane: {out:?}");
            assert_eq!(out.lanes_refused, 0);
            assert_eq!(inp.lanes_in, out.lanes_out, "the server took every lane");
            let lane1 = out.lanes.iter().find(|l| l.lane.0 == 1).expect("lane 1");
            assert!(
                lane1.position_acked.unwrap_or(0) > 23,
                "data went on lane 1: {lane1:?}"
            );
            // A stream that names no pipe of a session is refused.
            let (stray, _) = oc.open_bi().await.unwrap();
            drop(stray);
            nc.close(VarInt::ZERO, b"");
            watchdog(10, "nested closed", ns.closed()).await;
            oc.close(VarInt::ZERO, b"");
            watchdog(10, "outer closed", os.closed()).await;
            lanes.await.unwrap();
        }
        settle(base, 10, "nested lanes").await;
    });
}

/// The lanes of nested pipes over an outer session hold at most half of
/// the outer peer's initial bidirectional streams, without waiting for
/// its credit (MULTIPATH.md Section 5.8): with 4, two lanes besides each
/// pipe's lane 0, none refused, and the application's own opens go on.
#[test]
fn stream_carrier_lanes_keep_to_half_the_outer_streams() {
    multi_thread(async {
        let base = snapshot();
        {
            let mut server = Config::default();
            server.max_incoming_streams = 4;
            let (oc, os) = outer(Config::default(), server).await;
            let router = {
                let os = os.clone();
                tokio::spawn(async move {
                    let (send, recv) = os.accept_bi().await.unwrap();
                    let io = PipeIo::from_stream(send, recv).with_lanes(true);
                    let ns = Session::accept(io, Config::default()).await.unwrap();
                    let lanes = tokio::spawn(async move {
                        while let Ok((send, recv)) = os.accept_bi().await {
                            let _ =
                                zmux::carrier::handle_lane(PipeIo::from_stream(send, recv)).await;
                        }
                    });
                    (ns, lanes)
                })
            };
            let pipe = oc
                .open_pipe_stream(&zmux::Preamble::new())
                .await
                .unwrap()
                .with_lanes(true);
            let nc = Session::connect(pipe, Config::default()).await.unwrap();
            let (ns, lanes) = router.await.unwrap();
            // Several bulk streams at once want a lane each.
            let mut echoes = Vec::new();
            for _ in 0..8 {
                let (nc, ns) = (nc.clone(), ns.clone());
                echoes.push(tokio::spawn(async move { echo(&nc, &ns, 4 << 20).await }));
            }
            for e in echoes {
                watchdog(30, "echo", e).await.unwrap();
            }
            let out = nc.pipe_stats().remove(0);
            assert!(out.lanes_out <= 3, "lane 0 and at most two: {out:?}");
            assert_eq!(out.lanes_refused, 0);
            assert!(oc.stats().streams_opened_local <= 3);
            nc.close(VarInt::ZERO, b"");
            watchdog(10, "nested closed", ns.closed()).await;
            oc.close(VarInt::ZERO, b"");
            watchdog(10, "outer closed", os.closed()).await;
            lanes.await.unwrap();
        }
        settle(base, 10, "outer lane share").await;
    });
}

/// A nested session's pipe with lanes over an outer session, ended at any
/// point (closed from either side, or its runtime shut down mid-transfer):
/// the lanes' streams are the outer session's, and dropping one takes that
/// session's lock and wakes its tasks, so the inner session gives up its
/// lanes, pipes and released sides only after its own core lock. The
/// debug builds' check of that rule fails the test.
#[test]
fn lanes_ended_at_any_point_wake_nothing_under_a_core_lock() {
    // The other tests' resource counts see no sessions of this one.
    let _g = common::serial();
    static UNDER_LOCK: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        if info.to_string().contains("woken under a core lock") {
            UNDER_LOCK.fetch_add(1, Ordering::SeqCst);
        }
        prev(info);
    }));
    async fn echo_any(client: Session, server: Session, len: usize) {
        let echo = tokio::spawn(async move {
            let Ok((mut send, mut recv)) = server.accept_bi().await else {
                return;
            };
            if let Ok(data) = recv.read_to_end(len).await {
                let _ = send.write_all(&data).await;
                let _ = send.finish();
            }
        });
        let Ok((mut send, mut recv)) = client.open_bi().await else {
            return;
        };
        tokio::spawn(async move {
            let _ = send.write_all(&vec![7; len]).await;
            let _ = send.finish();
        });
        let _ = recv.read_to_end(len).await;
        let _ = echo.await;
    }
    for i in 0..40u64 {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(4)
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async move {
            let mut server = Config::default();
            if i % 2 == 1 {
                // Lanes held to their share of the outer streams.
                server.max_incoming_streams = 4;
            }
            let (oc, os) = outer(Config::default(), server).await;
            let router = tokio::spawn(async move {
                let (send, recv) = os.accept_bi().await.ok()?;
                let io = PipeIo::from_stream(send, recv).with_lanes(true);
                let ns = Session::accept(io, Config::default()).await.ok()?;
                tokio::spawn(async move {
                    while let Ok((send, recv)) = os.accept_bi().await {
                        let _ = zmux::carrier::handle_lane(PipeIo::from_stream(send, recv)).await;
                    }
                });
                Some(ns)
            });
            let Ok(pipe) = oc.open_pipe_stream(&zmux::Preamble::new()).await else {
                return;
            };
            let Ok(nc) = Session::connect(pipe.with_lanes(true), Config::default()).await else {
                return;
            };
            let Ok(Some(ns)) = router.await else {
                return;
            };
            for _ in 0..6 {
                tokio::spawn(echo_any(nc.clone(), ns.clone(), 2 << 20));
            }
            tokio::time::sleep(Duration::from_millis(5 + (i * 37) % 120)).await;
            match i % 3 {
                0 => nc.close(VarInt::ZERO, b""),
                1 => oc.close(VarInt::ZERO, b""),
                _ => {}
            }
            tokio::time::sleep(Duration::from_millis((i * 13) % 7)).await;
        });
        rt.shutdown_timeout(Duration::from_secs(5));
    }
    // The default hook again for the tests that run after this one.
    drop(std::panic::take_hook());
    assert_eq!(
        UNDER_LOCK.load(Ordering::SeqCst),
        0,
        "woken under a core lock"
    );
}
