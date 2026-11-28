//! `Session::close` returns once `CONNECTION_CLOSE` is handed to the
//! carriers and their input drained, within its bound, and
//! Join progress distinguishes a verified Reply from peer attachment.

#![allow(
    clippy::many_single_char_names,
    reason = "short conventional names in scenario code"
)]
#![allow(
    clippy::large_stack_arrays,
    reason = "scenario code: buffers and futures stay on the stack on purpose, long scripted scenarios read top to bottom"
)]

#[path = "common/pending.rs"]
mod pending;

use std::io;
use std::pin::Pin;
use std::pin::pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use tokio::io::AsyncWriteExt as _;

use pending::is_pending;
use tokio::io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf};
use zmux::{
    Config, Listener, ListenerConfig, OutboundState, PipeAuth, PipeError, PipeHint, PipeIo,
    PipeOptions, Session, SessionError, VarInt,
};

fn config() -> Config {
    let mut c = Config::default();
    c.session_policy.limits.steady_attachments = 6;
    c.pipe_auth = PipeAuth::psk(*b"close-handoff---0123456789abcdef").with_end_to_end();
    c
}

/// Longer than any test runs: a call that returns did not wait for it.
const HOUR: Duration = Duration::from_secs(3600);

/// The bound of a wait for something that happens at once, not the time it
/// may take: it only keeps a broken build from hanging the run.
const GUARD: Duration = Duration::from_secs(30);

/// `c` whose close would wait an hour for the hand-off and for the linger,
/// so that a close that returns waited for neither.
fn untimed_close(mut c: Config) -> Config {
    c.test_hooks().close_handoff_limit = Some(HOUR);
    c.test_hooks().linger_timeout = Some(HOUR);
    c
}

fn hint() -> PipeHint {
    PipeHint::from_peer(([127, 0, 0, 1], 0).into())
}

/// A carrier whose writes can be stalled. A held Join lets its first write
/// (Init) pass, then stalls Confirm until the test releases it.
struct Held {
    io: DuplexStream,
    stall: Arc<Stall>,
    first: bool,
    hold_after_first: bool,
    /// The shutdown under way, while `Stall::slow_shutdown` delays it.
    shutting: Option<Pin<Box<tokio::time::Sleep>>>,
}

#[derive(Default)]
struct Stall {
    on: AtomicBool,
    writer: Mutex<Option<Waker>>,
    write_blocked: tokio::sync::Notify,
    /// The write side's shutdown takes 50 ms (a TLS `close_notify`, say).
    slow_shutdown: AtomicBool,
    hold_shutdown: AtomicBool,
    shutdown_entered: tokio::sync::Notify,
    shutdown_finished: tokio::sync::Notify,
    /// The write side was shut.
    shut: AtomicBool,
    /// Nothing arrives any more, the end of input included: the peer keeps its write side
    /// open and sends no more.
    mute: AtomicBool,
    /// The held writes go on now, however long their hold.
    released: AtomicBool,
}

impl Stall {
    fn release(&self) {
        self.released.store(true, Ordering::SeqCst);
        if let Some(w) = self.writer.lock().unwrap().take() {
            w.wake();
        }
    }

    fn set(&self, on: bool) {
        self.on.store(on, Ordering::SeqCst);
        if let Some(w) = self.writer.lock().unwrap().take() {
            w.wake();
        }
    }
}

impl AsyncRead for Held {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let r = Pin::new(&mut self.io).poll_read(cx, buf);
        if matches!(r, Poll::Ready(Ok(()))) && self.stall.mute.load(Ordering::SeqCst) {
            // The peer sends nothing more, neither its `CONNECTION_CLOSE` (which would end
            // the linger) nor the end of input: the session's linger timer ends the wait.
            buf.set_filled(before);
            return Poll::Pending;
        }
        r
    }
}

impl AsyncWrite for Held {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let blocked = || {
            self.stall.on.load(Ordering::SeqCst)
                || (self.hold_after_first
                    && !self.first
                    && !self.stall.released.load(Ordering::SeqCst))
        };
        if blocked() {
            *self.stall.writer.lock().unwrap() = Some(cx.waker().clone());
            if blocked() {
                self.stall.write_blocked.notify_one();
                return Poll::Pending;
            }
        }
        let written = Pin::new(&mut self.io).poll_write(cx, buf);
        if written.is_ready() {
            self.first = false;
        }
        written
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.stall.hold_shutdown.load(Ordering::SeqCst) {
            *self.stall.writer.lock().unwrap() = Some(cx.waker().clone());
            self.stall.shutdown_entered.notify_one();
            if self.stall.hold_shutdown.load(Ordering::SeqCst) {
                return Poll::Pending;
            }
        }
        if self.stall.slow_shutdown.load(Ordering::SeqCst) {
            let delay = self
                .shutting
                .get_or_insert_with(|| Box::pin(tokio::time::sleep(Duration::from_millis(50))));
            if delay.as_mut().poll(cx).is_pending() {
                return Poll::Pending;
            }
        }
        let r = Pin::new(&mut self.io).poll_shutdown(cx);
        if r.is_ready() {
            self.stall.shut.store(true, Ordering::SeqCst);
            self.stall.shutdown_finished.notify_one();
        }
        r
    }
}

/// A carrier to `listener`, its writes held as [`Held`] says.
fn carrier(listener: &Listener, stall: &Arc<Stall>, hold_after_first: bool) -> PipeIo {
    let (a, b) = tokio::io::duplex(256 * 1024);
    let l = listener.clone();
    tokio::spawn(async move {
        let _ = l.handle_pipe(PipeIo::new(b), hint()).await;
    });
    PipeIo::new(Held {
        io: a,
        stall: stall.clone(),
        first: true,
        hold_after_first,
        shutting: None,
    })
}

async fn setup(c: Config) -> (Session, Session, Listener, Arc<Stall>) {
    setup_client(c.clone(), c).await
}

/// [`setup`] with the client's own configuration.
async fn setup_client(server: Config, client: Config) -> (Session, Session, Listener, Arc<Stall>) {
    let listener =
        Listener::new(server, ListenerConfig::default()).expect("valid listener configuration");
    let stall = Arc::new(Stall::default());
    let client = Session::connect(carrier(&listener, &stall, false), client)
        .await
        .unwrap();
    let server = listener.accept().await.unwrap();
    (client, server, listener, stall)
}

fn closed_by_peer(e: &SessionError, want: u32) -> bool {
    matches!(e, SessionError::ApplicationClosed { code, remote: true, .. } if *code == VarInt::from_u32(want))
}

/// A process that exits right after `close` returned: the peer, which
/// holds a session whose carrier ended for its resume timeout, learns of
/// the close and ends at once.
#[test]
fn close_hands_off_before_the_process_ends() {
    let mut c = config();
    c.resume_timeout = Some(Duration::from_secs(60));
    let server_rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let (addr, listener) = server_rt.block_on(async {
        let tcp = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = tcp.local_addr().unwrap();
        let listener = Listener::new(c.clone(), ListenerConfig::default())
            .expect("valid listener configuration");
        let l = listener.clone();
        tokio::spawn(async move {
            while let Ok((s, peer)) = tcp.accept().await {
                let l = l.clone();
                tokio::spawn(async move {
                    let _ = l
                        .handle_pipe(PipeIo::from_tcp(s), PipeHint::from_peer(peer))
                        .await;
                });
            }
        });
        (addr, listener)
    });
    for _ in 0..3 {
        // The client's own runtime ends right after the close: nothing of
        // the client runs on.
        let client_rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        // Neither the hand-off nor the linger timer ends the close: it
        // returns once the carrier took CONNECTION_CLOSE and the peer ended it.
        let cc = untimed_close(c.clone());
        let client = client_rt.block_on(async move {
            let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
            let s = Session::connect(PipeIo::from_tcp(tcp), cc).await.unwrap();
            let (mut w, _r) = s.open_bi().await.unwrap();
            w.write_all(b"hello").await.unwrap();
            s
        });
        let server = server_rt.block_on(async {
            tokio::time::timeout(Duration::from_secs(5), listener.accept())
                .await
                .unwrap()
                .unwrap()
        });
        client_rt
            .block_on(async { tokio::time::timeout(GUARD, client.close()).await })
            .expect("close waited for a timer");
        drop(client_rt);
        drop(client);
        let e = server_rt.block_on(async {
            tokio::time::timeout(Duration::from_secs(5), server.closing())
                .await
                .expect("the peer learnt of the close")
        });
        assert!(closed_by_peer(&e, 0), "{e:?}");
    }
    listener.close();
}

/// A carrier that takes nothing holds a close at most its bound; repeated
/// and concurrent calls return no later than the first, and a call on an
/// ended session at once.
#[tokio::test(start_paused = true)]
async fn close_is_bounded_when_a_carrier_takes_nothing() {
    for limit in [Some(Duration::from_millis(200)), None] {
        let mut c = config();
        c.test_hooks().close_handoff_limit = limit;
        let bound = limit.unwrap_or(Duration::from_secs(1));
        let (client, _server, listener, stall) = setup(c).await;
        stall.set(true);
        let mut first = pin!(client.close());
        assert!(is_pending(first.as_mut()).await);
        write_is_blocked(&stall).await;
        tokio::time::advance(bound / 2).await;
        client.abort(VarInt::from_u32(4), b"again");
        tokio::time::advance((bound / 2).checked_sub(Duration::from_millis(1)).unwrap()).await;
        assert!(is_pending(first.as_mut()).await);
        tokio::time::advance(Duration::from_millis(1)).await;
        tokio::time::timeout(GUARD, first)
            .await
            .expect("the hand-off deadline ended the close");
        // The session ended locally, with the first call's error.
        tokio::time::timeout(Duration::from_secs(2), client.closing())
            .await
            .unwrap();
        assert!(matches!(
            client.close_reason(),
            Some(SessionError::ApplicationClosed { remote: false, code, .. }) if code == VarInt::ZERO
        ));
        // Ready at its first poll: nothing is waited for.
        assert!(
            tokio::time::timeout(Duration::ZERO, client.close())
                .await
                .is_ok(),
            "a close of an ended session waited"
        );
        listener.close();
    }
}

/// A healthy carrier takes the close at once: `close` does not wait for
/// the peer.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn close_returns_once_the_carrier_took_it() {
    let (client, server, listener, _stall) = setup_client(config(), untimed_close(config())).await;
    tokio::time::timeout(GUARD, client.close())
        .await
        .expect("close waited for a timer");
    let e = tokio::time::timeout(Duration::from_secs(2), server.closing())
        .await
        .unwrap();
    assert!(closed_by_peer(&e, 0), "{e:?}");
    listener.close();
}

/// `close` returns once `CONNECTION_CLOSE` was handed to the carrier, without
/// waiting for the peer; the write side is then shut in the background, and
/// `wait` returns once that and the drain are done.
#[tokio::test(start_paused = true)]
async fn close_hands_over_and_shuts_in_the_background() {
    for slow in [false, true] {
        let (client, server, listener, stall) = setup(config()).await;
        stall.slow_shutdown.store(slow, Ordering::SeqCst);
        tokio::time::timeout(GUARD, client.close())
            .await
            .expect("close waited for a timer");
        let e = tokio::time::timeout(Duration::from_secs(2), server.closing())
            .await
            .unwrap();
        assert!(closed_by_peer(&e, 0), "{e:?}");
        tokio::time::timeout(Duration::from_secs(5), client.closed())
            .await
            .expect("the session ended");
        assert!(
            stall.shut.load(Ordering::SeqCst)
                || (slow
                    && client
                        .pipe_stats()
                        .iter()
                        .all(|p| p.inbound == Some(zmux::InboundState::Ended))),
            "slow shutdown {slow}"
        );
        listener.close();
    }
}

/// A silent peer leaves the read drain active until the linger deadline.
#[tokio::test(start_paused = true)]
async fn the_drain_goes_on_after_close_returned() {
    let linger = Duration::from_millis(250);
    let mut c = config();
    c.test_hooks().linger_timeout = Some(linger);
    let (client, _server, listener, stall) = setup(c).await;
    stall.mute.store(true, Ordering::SeqCst);
    tokio::time::timeout(GUARD, client.close())
        .await
        .expect("the carrier accepted the close");
    let mut closed = pin!(client.closed());
    assert!(is_pending(closed.as_mut()).await);
    tokio::time::advance(linger).await;
    tokio::time::timeout(GUARD, closed)
        .await
        .expect("the linger deadline ended the drain");
    assert!(stall.shut.load(Ordering::SeqCst));
    listener.close();
}

/// The graceful shutdown's fallback after cancellation is the same close:
/// awaiting `close` then waits for its hand-off.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_cancelled_shutdown_closes() {
    let (client, server, listener, _stall) = setup(config()).await;
    // An open stream holds the shutdown.
    let (mut w, _r) = client.open_bi().await.unwrap();
    w.write_all(b"x").await.unwrap();
    {
        let mut shutdown = pin!(client.shutdown(VarInt::from_u32(2), b"later"));
        assert!(is_pending(shutdown.as_mut()).await);
    }
    client.abort(VarInt::from_u32(2), b"later");
    let e = tokio::time::timeout(Duration::from_secs(2), server.closing())
        .await
        .unwrap();
    assert!(closed_by_peer(&e, 2), "{e:?}");
    listener.close();
}

#[tokio::test]
async fn shutdown_waits_for_connection_close_on_each_joined_carrier() {
    let (client, server, listener, first) = setup(untimed_close(config())).await;
    let second = Arc::new(Stall::default());
    let joined = client
        .test_join(carrier(&listener, &second, false), PipeOptions::new())
        .await
        .unwrap();
    joined.attached().await.unwrap();
    for stall in [&first, &second] {
        stall.hold_shutdown.store(true, Ordering::SeqCst);
    }
    let mut shutdown = std::pin::pin!(client.shutdown(VarInt::ZERO, b"done"));
    assert!(is_pending(shutdown.as_mut()).await);
    tokio::time::timeout(GUARD, async {
        first.shutdown_entered.notified().await;
        second.shutdown_entered.notified().await;
    })
    .await
    .unwrap();
    assert!(is_pending(shutdown.as_mut()).await);
    first.hold_shutdown.store(false, Ordering::SeqCst);
    first.release();
    tokio::time::timeout(GUARD, first.shutdown_finished.notified())
        .await
        .unwrap();
    assert!(is_pending(shutdown.as_mut()).await);
    second.hold_shutdown.store(false, Ordering::SeqCst);
    second.release();
    let result = tokio::time::timeout(Duration::from_secs(5), shutdown).await;
    assert!(
        result.is_ok(),
        "state={:?}, first={}, second={}, pipes={:?}",
        client.state(),
        first.shut.load(Ordering::SeqCst),
        second.shut.load(Ordering::SeqCst),
        client.pipe_stats()
    );
    result.unwrap().unwrap();
    let peer = tokio::time::timeout(GUARD, server.closing()).await.unwrap();
    assert!(closed_with(&peer, 0, b"done"), "{peer:?}");
    assert!(first.shut.load(Ordering::SeqCst));
    assert!(second.shut.load(Ordering::SeqCst));
    listener.close();
}

/// The joiner's pipes other than pipe 0 that are still live.
#[tokio::test]
async fn a_graceful_pipe_keeps_its_writer_until_the_carrier_accepts_shutdown() {
    tokio::time::timeout(GUARD, async {
        let (client, server, listener, _) = setup(config()).await;
        let stalled = Arc::new(Stall::default());
        let local = client
            .test_join(carrier(&listener, &stalled, false), PipeOptions::new())
            .await
            .unwrap();
        let remote = server.pipe(local.id()).expect("attached on the peer");

        stalled.hold_shutdown.store(true, Ordering::SeqCst);
        local.close().unwrap();
        stalled.shutdown_entered.notified().await;
        assert!(client.pipe(local.id()).is_some());
        let mut closed = std::pin::pin!(remote.closed());
        assert!(is_pending(closed.as_mut()).await);
        stalled.hold_shutdown.store(false, Ordering::SeqCst);
        stalled.release();
        stalled.shutdown_finished.notified().await;
        closed.await.unwrap();
        local.closed().await.unwrap();
    })
    .await
    .unwrap();
}

fn live_joins(s: &Session) -> usize {
    s.pipe_stats()
        .iter()
        .filter(|p| p.pipe.get() != 0)
        .filter(|p| {
            matches!(
                p.outbound,
                Some(OutboundState::Joining | OutboundState::Active | OutboundState::Suspect)
            )
        })
        .count()
}

async fn until(what: &str, secs: u64, mut f: impl FnMut() -> bool) {
    tokio::time::timeout(Duration::from_secs(secs), async {
        while !f() {
            tokio::time::advance(Duration::from_millis(1)).await;
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("timed out: {what}"));
}

async fn write_is_blocked(stall: &Stall) {
    tokio::time::timeout(GUARD, stall.write_blocked.notified())
        .await
        .expect("the carrier write reached its gate");
}

/// A late Confirm separates the verified Reply from peer attachment.
#[tokio::test]
async fn add_pipe_waits_for_the_attachment() {
    let (client, _server, listener, _) = setup(config()).await;
    let stall = Arc::new(Stall::default());
    let mut joining = pin!(client.test_join(carrier(&listener, &stall, true), PipeOptions::new(),));
    assert!(is_pending(joining.as_mut()).await);
    write_is_blocked(&stall).await;
    assert!(is_pending(joining.as_mut()).await);
    stall.release();
    let pipe = tokio::time::timeout(GUARD, joining).await.unwrap().unwrap();
    assert!(!is_pending(pin!(pipe.attached())).await);

    let stall = Arc::new(Stall::default());
    let pipe = client
        .test_begin_join(carrier(&listener, &stall, true), PipeOptions::new())
        .unwrap();
    tokio::time::timeout(GUARD, pipe.joined())
        .await
        .unwrap()
        .unwrap();
    write_is_blocked(&stall).await;
    assert!(is_pending(pin!(pipe.attached())).await);
    stall.release();
    tokio::time::timeout(GUARD, pipe.attached())
        .await
        .unwrap()
        .unwrap();
    client.close().await;
    listener.close();
}

/// The handshake timeout bounds the whole call: a pipe not attached by
/// then is aborted and the call times out, leaving no pipe.
#[tokio::test(start_paused = true)]
async fn add_pipe_times_out_and_leaves_no_pipe() {
    let mut c = config();
    c.handshake_timeout = None;
    c.join_timeout = Duration::from_millis(600);
    let limit = c.join_timeout;
    let (client, server, listener, _) = setup(c).await;
    let stall = Arc::new(Stall::default());
    let mut joining = pin!(client.test_join(carrier(&listener, &stall, true), PipeOptions::new()));
    assert!(is_pending(joining.as_mut()).await);
    write_is_blocked(&stall).await;
    tokio::time::advance(limit.checked_sub(Duration::from_millis(1)).unwrap()).await;
    assert!(is_pending(joining.as_mut()).await);
    tokio::time::advance(Duration::from_millis(1)).await;
    let r = tokio::time::timeout(GUARD, joining).await.unwrap();
    assert!(matches!(
        r.err(),
        Some(PipeError::Failed(zmux::PipeFailure::JoinTimedOut))
    ));
    assert_eq!(live_joins(&client), 0);
    // The session goes on over pipe 0.
    let (mut w, _r) = client.open_bi().await.unwrap();
    w.write_all(b"still").await.unwrap();
    w.finish().unwrap();
    let (_w, mut r) = server.accept_bi().await.unwrap();
    assert_eq!(r.read_to_end(16).await.unwrap(), b"still");
    client.close().await;
    listener.close();
}

/// A cancelled call (its future dropped) aborts the pipe it started.
#[tokio::test]
async fn a_cancelled_add_pipe_aborts_the_pipe() {
    let (client, _server, listener, _) = setup(config()).await;
    let stall = Arc::new(Stall::default());
    {
        let mut joining =
            pin!(client.test_join(carrier(&listener, &stall, true), PipeOptions::new()));
        assert!(is_pending(joining.as_mut()).await);
        write_is_blocked(&stall).await;
        assert!(is_pending(joining.as_mut()).await);
    }
    assert_eq!(live_joins(&client), 0);
    client.close().await;
    listener.close();
}

/// A pipe removed before the peer attached it fails the call with the
/// pipe-gone error, the session's end with the session's error.
#[tokio::test]
async fn add_pipe_fails_when_the_pipe_or_the_session_goes() {
    let (client, _server, listener, _) = setup(config()).await;
    let stall = Arc::new(Stall::default());
    let mut joining = pin!(client.test_join(carrier(&listener, &stall, true), PipeOptions::new()));
    assert!(is_pending(joining.as_mut()).await);
    write_is_blocked(&stall).await;
    let pipe = client
        .pipes()
        .into_iter()
        .find(|p| p.id().get() != 0)
        .unwrap();
    pipe.close().unwrap();
    let e = tokio::time::timeout(GUARD, joining)
        .await
        .unwrap()
        .unwrap_err();
    assert!(
        matches!(e, PipeError::Failed(_) | PipeError::UnknownPipe),
        "{e:?}"
    );

    let stall = Arc::new(Stall::default());
    let mut joining = pin!(client.test_join(carrier(&listener, &stall, true), PipeOptions::new()));
    assert!(is_pending(joining.as_mut()).await);
    write_is_blocked(&stall).await;
    client.abort(VarInt::from_u32(1), b"");
    let e = tokio::time::timeout(GUARD, joining)
        .await
        .unwrap()
        .unwrap_err();
    assert!(matches!(e, PipeError::SessionLost(_)), "{e:?}");
    listener.close();
}

/// Shutdown and a concurrent close both finish within the hand-off bound
/// when a carrier takes nothing.
#[tokio::test(start_paused = true)]
async fn close_after_a_shutdown_is_bounded() {
    let mut c = untimed_close(config());
    c.test_hooks().close_handoff_limit = Some(Duration::from_millis(200));
    let goaway_final = Arc::new(AtomicBool::new(false));
    let mut cc = c.clone();
    cc.test_hooks().goaway_final = Some(goaway_final.clone());
    let (client, server, listener, stall) = setup_client(c, cc).await;
    // The peer's open stream holds the shutdown while its GOAWAY goes out.
    let mut w = server.open_uni().await.unwrap();
    w.write_all(b"x").await.unwrap();
    let mut r = client.accept_uni().await.unwrap();
    let s = client.clone();
    let shut = tokio::spawn(async move { s.shutdown(VarInt::from_u32(3), b"bye").await });
    // GOAWAY's phase 2 is done: only the stream holds the shutdown now.
    until("the final GOAWAY", 10, || {
        goaway_final.load(Ordering::SeqCst)
    })
    .await;
    // The carrier now takes nothing: the shutdown's CONNECTION_CLOSE, sent
    // once the stream ended, stays with it.
    stall.set(true);
    w.finish().unwrap();
    assert_eq!(r.read_to_end(16).await.unwrap(), b"x");
    drop(r);
    tokio::time::timeout(GUARD, client.closing())
        .await
        .expect("the shutdown closed");
    assert_eq!(client.state(), zmux::SessionState::Closing);
    // The linger is an hour: a close that returns waited for neither it
    // nor the stalled carrier.
    tokio::time::timeout(GUARD, client.close())
        .await
        .expect("close waited past its hand-off limit");
    tokio::time::timeout(GUARD, shut)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    listener.close();
}

/// Whether `e` is the peer's application close with `code` and `reason`.
fn closed_with(e: &SessionError, want: u32, why: &[u8]) -> bool {
    matches!(e, SessionError::ApplicationClosed { code, reason, remote: true }
        if *code == VarInt::from_u32(want) && reason.as_ref() == why)
}

/// N17: a coded close followed at once by an abort with another code ends
/// the flush at once, and the peer sees the close's code: the first call
/// decides.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_abort_ends_a_coded_close_s_flush_and_the_close_decides() {
    let (client, server, listener, stall) = setup_client(config(), untimed_close(config())).await;
    let (mut w, _r) = client.open_bi().await.unwrap();
    // The carrier takes nothing: what it was not given of the written
    // data (within the peer's window, more than a batch) holds the flush.
    stall.set(true);
    w.write_all(&[7; 128 * 1024]).await.unwrap();
    let mut closing = pin!(client.close_with_error(VarInt::from_u32(0x2a), b"bye"));
    assert!(
        is_pending(closing.as_mut()).await,
        "the flush waits for the carrier"
    );
    client.abort(VarInt::from_u32(7), b"other");
    // The close's hand-off limit is an hour and the carrier still takes
    // nothing: only the abort can have ended it.
    tokio::time::timeout(GUARD, closing)
        .await
        .expect("the abort ended the flush");
    assert!(!stall.shut.load(Ordering::SeqCst));
    assert!(matches!(
        client.close_reason(),
        Some(SessionError::ApplicationClosed { code, remote: false, .. })
            if code == VarInt::from_u32(0x2a)
    ));
    stall.set(false);
    let e = tokio::time::timeout(GUARD, server.closing()).await.unwrap();
    assert!(closed_with(&e, 0x2a, b"bye"), "{e:?}");
    listener.close();
}

/// N17: an abort then a coded close: the close returns at once and sends
/// nothing more; the peer sees the abort's code.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_close_after_an_abort_returns_at_once_and_changes_nothing() {
    let (client, server, listener, _stall) = setup(config()).await;
    client.abort(VarInt::from_u32(7), b"gone");
    tokio::time::timeout(
        Duration::ZERO,
        client.close_with_error(VarInt::from_u32(0x2a), b"bye"),
    )
    .await
    .expect("a close after an abort waits for nothing");
    let e = tokio::time::timeout(GUARD, server.closing()).await.unwrap();
    assert!(closed_with(&e, 7, b"gone"), "{e:?}");
    // A second close after the first changes neither code nor reason.
    client.close().await;
    assert!(matches!(
        client.close_reason(),
        Some(SessionError::ApplicationClosed { code, .. }) if code == VarInt::from_u32(7)
    ));
    listener.close();
}

/// N17: a coded close whose data a carrier does not take gives the data up
/// at its 1 s bound, and the peer still sees the code once the carrier
/// takes the close. Runs on paused time: the bound passes when the runtime
/// is idle, and the carrier is released within the close's second bound
/// (the one `CONNECTION_CLOSE` has after the first returned the call) at the
/// same virtual instant, so no scheduling delay under load can end it.
#[tokio::test(start_paused = true)]
async fn a_coded_close_gives_up_unsent_data_at_one_second() {
    let mut c = config();
    c.test_hooks().linger_timeout = Some(HOUR);
    let (client, server, listener, stall) = setup_client(config(), c).await;
    let (mut w, _r) = client.open_bi().await.unwrap();
    stall.set(true);
    w.write_all(&[7; 64 * 1024]).await.unwrap();
    // Returns while the carrier still takes nothing: the hand-off bound gave
    // the data up, nothing was delivered.
    tokio::time::timeout(
        GUARD,
        client.close_with_error(VarInt::from_u32(0x2a), b"bye"),
    )
    .await
    .expect("the bound ended the close");
    assert!(!stall.shut.load(Ordering::SeqCst));
    assert!(server.close_reason().is_none(), "nothing reached the peer");
    stall.set(false);
    let e = tokio::time::timeout(GUARD, server.closing()).await.unwrap();
    assert!(closed_with(&e, 0x2a, b"bye"), "{e:?}");
    listener.close();
}

/// After the peer's close, what arrived on an accepted stream that the peer
/// never finished stays readable until read; the session is CLOSED once it
/// was, within the linger timeout.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn data_before_a_peer_close_stays_readable_until_read() {
    let (client, server, listener, _stall) = setup_client(long_linger(config()), config()).await;
    let (mut w, _r) = client.open_bi().await.unwrap();
    w.write_all(&[3; 100_000]).await.unwrap();
    let (_sw, mut r) = server.accept_bi().await.unwrap();
    client
        .close_with_error(VarInt::from_u32(0x2a), b"bye")
        .await;
    let e = tokio::time::timeout(GUARD, server.closing()).await.unwrap();
    assert!(closed_with(&e, 0x2a, b"bye"), "{e:?}");
    // The peer close arrived before the application starts reading.
    let mut got = 0;
    let end = loop {
        match r.read_chunk(1 << 20).await {
            Ok(Some(b)) => got += b.len(),
            Ok(None) => panic!("no end of stream was sent"),
            Err(e) => break e,
        }
    };
    assert_eq!(got, 100_000);
    assert!(matches!(end, zmux::StreamError::SessionLost(_)), "{end:?}");
    tokio::time::timeout(GUARD, server.closed()).await.unwrap();
    listener.close();
}

/// A configuration whose linger lasts an hour: a session that ends ended
/// for another reason.
fn long_linger(mut c: Config) -> Config {
    c.test_hooks().linger_timeout = Some(HOUR);
    c
}

/// After the peer's close, an application that stops or drops an unread
/// stream ends the read drain: the session is CLOSED at once, not at the
/// linger deadline; a stop and a reset then fail with the session's error.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dropping_unread_data_after_a_peer_close_ends_the_session() {
    for drop_it in [false, true] {
        let (client, server, listener, _stall) =
            setup_client(long_linger(config()), config()).await;
        let (mut w, _r) = client.open_bi().await.unwrap();
        w.write_all(&[3; 10_000]).await.unwrap();
        let (mut sw, mut r) = server.accept_bi().await.unwrap();
        client
            .close_with_error(VarInt::from_u32(0x2a), b"bye")
            .await;
        tokio::time::timeout(GUARD, server.closing()).await.unwrap();
        // The drain: a pending local write fails with the session's error.
        assert!(matches!(
            sw.reset(VarInt::from_u32(1)),
            Err(zmux::StreamError::SessionLost(_))
        ));
        if drop_it {
            drop(r);
        } else {
            assert!(matches!(
                r.stop(VarInt::from_u32(1)),
                Err(zmux::StreamError::SessionLost(_))
            ));
        }
        tokio::time::timeout(GUARD, server.closed())
            .await
            .expect("the drain ended with the discard, not the hour's linger");
        listener.close();
    }
}

/// The close-code hook is told every end: the session's code after a coded
/// close (at both ends), 0 for a pipe removed while its session goes on, and
/// 0 for a carrier dropped unused.
#[tokio::test(start_paused = true)]
async fn the_close_code_hook_hears_every_end() {
    let told = |slot: &Arc<Mutex<Vec<u64>>>| {
        let slot = slot.clone();
        move |c: VarInt| slot.lock().unwrap().push(c.into_inner())
    };
    let unused = Arc::new(Mutex::new(Vec::new()));
    drop(PipeIo::new(tokio::io::duplex(64).0).with_close_code(told(&unused)));
    assert_eq!(*unused.lock().unwrap(), [0]);

    let listener =
        Listener::new(config(), ListenerConfig::default()).expect("valid listener configuration");
    let (first, removed, server_side) = (
        Arc::new(Mutex::new(Vec::new())),
        Arc::new(Mutex::new(Vec::new())),
        Arc::new(Mutex::new(Vec::new())),
    );
    let (a, b) = tokio::io::duplex(1 << 20);
    let l = listener.clone();
    let hook = told(&server_side);
    tokio::spawn(async move {
        l.handle_pipe(PipeIo::new(b).with_close_code(hook), hint())
            .await
    });
    let client = Session::connect(PipeIo::new(a).with_close_code(told(&first)), config())
        .await
        .unwrap();
    let server = listener.accept().await.unwrap();
    let (a, b) = tokio::io::duplex(1 << 20);
    let l = listener.clone();
    tokio::spawn(async move { l.handle_pipe(PipeIo::new(b), hint()).await });
    let pipe = client
        .test_join(
            PipeIo::new(a).with_close_code(told(&removed)),
            PipeOptions::default(),
        )
        .await
        .unwrap();
    pipe.close().unwrap();
    until("the removed pipe told", 10, || {
        !removed.lock().unwrap().is_empty()
    })
    .await;
    assert_eq!(*removed.lock().unwrap(), [0]);
    assert!(first.lock().unwrap().is_empty());
    client
        .close_with_error(VarInt::from_u32(0x2a), b"bye")
        .await;
    tokio::time::timeout(GUARD, client.closed()).await.unwrap();
    tokio::time::timeout(GUARD, server.closed()).await.unwrap();
    assert_eq!(*first.lock().unwrap(), [0x2a]);
    assert_eq!(*server_side.lock().unwrap(), [0x2a]);
    listener.close();
}

/// A carrier that records its drop.
struct Dropped(DuplexStream, Arc<AtomicBool>);

impl Drop for Dropped {
    fn drop(&mut self) {
        self.1.store(true, Ordering::SeqCst);
    }
}

impl AsyncRead for Dropped {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl AsyncWrite for Dropped {
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
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

/// The close-code hook is called once the carrier is released: for a
/// pipe removed while its session goes on and for the session's end.
#[tokio::test(start_paused = true)]
async fn the_close_code_hook_follows_the_carriers_release() {
    let listener =
        Listener::new(config(), ListenerConfig::default()).expect("valid listener configuration");
    let hooked = |gone: &Arc<AtomicBool>, seen: &Arc<Mutex<Vec<bool>>>| {
        let (gone, seen) = (gone.clone(), seen.clone());
        move |_: VarInt| seen.lock().unwrap().push(gone.load(Ordering::SeqCst))
    };
    let (a, b) = tokio::io::duplex(1 << 20);
    let l = listener.clone();
    tokio::spawn(async move { l.handle_pipe(PipeIo::new(b), hint()).await });
    let (first_gone, first) = (
        Arc::new(AtomicBool::new(false)),
        Arc::new(Mutex::new(Vec::new())),
    );
    let client = Session::connect(
        PipeIo::new(Dropped(a, first_gone.clone())).with_close_code(hooked(&first_gone, &first)),
        config(),
    )
    .await
    .unwrap();
    let server = listener.accept().await.unwrap();
    let (a, b) = tokio::io::duplex(1 << 20);
    let l = listener.clone();
    tokio::spawn(async move { l.handle_pipe(PipeIo::new(b), hint()).await });
    let (gone, removed) = (
        Arc::new(AtomicBool::new(false)),
        Arc::new(Mutex::new(Vec::new())),
    );
    let pipe = client
        .test_join(
            PipeIo::new(Dropped(a, gone.clone())).with_close_code(hooked(&gone, &removed)),
            PipeOptions::default(),
        )
        .await
        .unwrap();
    pipe.close().unwrap();
    until("the removed pipe told", 10, || {
        !removed.lock().unwrap().is_empty()
    })
    .await;
    assert_eq!(
        *removed.lock().unwrap(),
        [true],
        "told before its carrier went"
    );
    client.close_with_error(VarInt::from_u32(7), b"bye").await;
    tokio::time::timeout(GUARD, client.closed()).await.unwrap();
    tokio::time::timeout(GUARD, server.closed()).await.unwrap();
    assert_eq!(
        *first.lock().unwrap(),
        [true],
        "told before its carrier went"
    );
    listener.close();
}

/// A local close still flushing when the peer's close arrives: once its
/// hand-off limit passed, what the peer sent before its close stays
/// readable until the linger deadline, not discarded with the hand-off.
#[tokio::test(start_paused = true)]
async fn a_peer_close_during_a_flush_keeps_the_read_drain() {
    let mut c = config();
    c.test_hooks().linger_timeout = Some(Duration::from_secs(5));
    let (client, server, listener, stall) = setup_client(config(), c).await;
    let (mut sw, _sr) = server.open_bi().await.unwrap();
    sw.write_all(&[9; 50_000]).await.unwrap();
    sw.flush().await.unwrap();
    let (mut w, mut r) = client.accept_bi().await.unwrap();
    // The client's close flushes behind a carrier that takes nothing.
    stall.set(true);
    w.write_all(&[7; 128 * 1024]).await.unwrap();
    let mut closing = pin!(client.close_with_error(VarInt::from_u32(1), b"mine"));
    assert!(is_pending(closing.as_mut()).await);
    server
        .close_with_error(VarInt::from_u32(0x2a), b"bye")
        .await;
    let e = tokio::time::timeout(GUARD, client.closing()).await.unwrap();
    assert!(closed_with(&e, 0x2a, b"bye"), "{e:?}");
    tokio::time::timeout(GUARD, closing).await.unwrap();
    // Past the hand-off limit of the stalled close.
    tokio::time::advance(Duration::from_millis(1300)).await;
    let mut got = 0;
    while let Ok(Some(b)) = r.read_chunk(1 << 20).await {
        got += b.len();
    }
    assert_eq!(got, 50_000);
    listener.close();
}

/// A carrier whose writes never complete, a stream write queued ahead of
/// the close: an abort and an idle timeout's close each end the session
/// within the close bounds, though `CONNECTION_CLOSE` never leaves.
#[tokio::test(start_paused = true)]
async fn a_close_behind_a_stuck_write_still_ends() {
    for idle in [false, true] {
        let mut c = config();
        if idle {
            c.max_idle_timeout = Some(Duration::from_millis(300));
            c.liveness.keep_alive_period = None;
        }
        let (client, _server, listener, stall) = setup(c).await;
        stall.set(true);
        let (mut w, _r) = client.open_bi().await.unwrap();
        w.write_all(&[1; 1000]).await.unwrap();
        write_is_blocked(&stall).await;
        if !idle {
            client.abort(VarInt::from_u32(3), b"gone");
        }
        tokio::time::timeout(GUARD, client.closed())
            .await
            .unwrap_or_else(|_| panic!("idle {idle}: the session never ended"));
        listener.close();
    }
}
