//! `Session::close` returns once CONNECTION_CLOSE is handed to the
//! carriers and their input drained, within its bound, and
//! `Session::add_pipe` returns once the
//! peer attached the pipe unless `return_on_reply`.

use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf};
use zmux::{
    Config, Listener, ListenerConfig, OutboundState, PipeAuth, PipeError, PipeHint, PipeIo,
    PipeOptions, Session, SessionError, VarInt,
};

fn config() -> Config {
    let mut c = Config::default();
    c.max_pipes = 6;
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

/// A carrier whose writes wait while it is stalled, or, with `hold`, its
/// writes after the first until `hold` passed (a joiner's Confirm arrives
/// late, after the joiner is ACTIVE).
struct Held {
    io: DuplexStream,
    stall: Arc<Stall>,
    first: bool,
    hold: Option<Pin<Box<tokio::time::Sleep>>>,
    /// The shutdown under way, while `Stall::slow_shutdown` delays it.
    shutting: Option<Pin<Box<tokio::time::Sleep>>>,
}

#[derive(Default)]
struct Stall {
    on: AtomicBool,
    writer: Mutex<Option<Waker>>,
    /// The write side's shutdown takes 50 ms (a TLS close_notify, say).
    slow_shutdown: AtomicBool,
    /// The write side was shut.
    shut: AtomicBool,
    /// The end of input never arrives: the peer keeps its write side open.
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
        if matches!(r, Poll::Ready(Ok(())))
            && buf.filled().len() == before
            && buf.remaining() > 0
            && self.stall.mute.load(Ordering::SeqCst)
        {
            // The peer's end of input never arrives: the session's linger
            // timer ends the wait.
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
        if self.stall.on.load(Ordering::SeqCst) {
            *self.stall.writer.lock().unwrap() = Some(cx.waker().clone());
            if self.stall.on.load(Ordering::SeqCst) {
                return Poll::Pending;
            }
        }
        let first = std::mem::replace(&mut self.first, false);
        if !first
            && !self.stall.released.load(Ordering::SeqCst)
            && let Some(h) = self.hold.as_mut()
            && h.as_mut().poll(cx).is_pending()
        {
            *self.stall.writer.lock().unwrap() = Some(cx.waker().clone());
            if !self.stall.released.load(Ordering::SeqCst) {
                return Poll::Pending;
            }
        }
        Pin::new(&mut self.io).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
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
        }
        r
    }
}

/// A carrier to `listener`, its writes held as [`Held`] says.
fn carrier(listener: &Listener, stall: &Arc<Stall>, hold: Option<Duration>) -> PipeIo {
    let (a, b) = tokio::io::duplex(256 * 1024);
    let l = listener.clone();
    tokio::spawn(async move {
        let _ = l.handle_pipe(PipeIo::new(b), hint()).await;
    });
    PipeIo::new(Held {
        io: a,
        stall: stall.clone(),
        first: true,
        hold: hold.map(|d| Box::pin(tokio::time::sleep(d))),
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
    let client = Session::connect(carrier(&listener, &stall, None), client)
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
    let server_rt = tokio::runtime::Runtime::new().unwrap();
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
                        .handle_pipe(PipeIo::tcp(s), PipeHint::from_peer(peer))
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
            let s = Session::connect(PipeIo::tcp(tcp), cc).await.unwrap();
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
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn close_is_bounded_when_a_carrier_takes_nothing() {
    for limit in [Some(Duration::from_millis(200)), None] {
        let mut c = config();
        c.test_hooks().close_handoff_limit = limit;
        let bound = limit.unwrap_or(Duration::from_secs(1));
        let (client, _server, listener, stall) = setup(c).await;
        stall.set(true);
        let start = Instant::now();
        let first = {
            let s = client.clone();
            tokio::spawn(async move {
                s.close().await;
                Instant::now()
            })
        };
        tokio::time::sleep(bound / 2).await;
        client.abort(VarInt::from_u32(4), b"again");
        let second = Instant::now();
        let first = first.await.unwrap();
        assert!(
            first - start >= bound - Duration::from_millis(20),
            "{:?}",
            first - start
        );
        // A guard against a hang only, not the time the bound may take.
        assert!(
            first - start < bound * 3 + Duration::from_secs(1),
            "{:?}",
            first - start
        );
        assert!(second <= first + Duration::from_millis(50));
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

/// `close` returns once CONNECTION_CLOSE was handed to the carrier, without
/// waiting for the peer; the write side is then shut in the background, and
/// `wait` returns once that and the drain are done.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
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
        tokio::time::timeout(Duration::from_secs(5), client.wait())
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

/// While the peer keeps its write side open, the drain lasts until the
/// linger timeout (at least 250 ms) in the background: `close` returns at
/// the hand-off, and `wait` once the drain ended.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_drain_goes_on_after_close_returned() {
    let (client, _server, listener, stall) = setup(config()).await;
    stall.mute.store(true, Ordering::SeqCst);
    let start = Instant::now();
    tokio::time::timeout(GUARD, client.close())
        .await
        .expect("close waited for a timer");
    tokio::time::timeout(Duration::from_secs(5), client.wait())
        .await
        .expect("the session ended");
    let took = start.elapsed();
    assert!(stall.shut.load(Ordering::SeqCst));
    assert!(took >= Duration::from_millis(240), "{took:?}");
    // A guard against a hang only: three linger periods and a second.
    assert!(took < Duration::from_millis(1750), "{took:?}");
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
    let r = tokio::time::timeout(
        Duration::from_millis(100),
        client.shutdown(VarInt::from_u32(2), b"later"),
    )
    .await;
    assert!(r.is_err());
    client.abort(VarInt::from_u32(2), b"later");
    let e = tokio::time::timeout(Duration::from_secs(2), server.closing())
        .await
        .unwrap();
    assert!(closed_by_peer(&e, 2), "{e:?}");
    listener.close();
}

/// The joiner's pipes other than pipe 0 that are still live.
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
    let start = Instant::now();
    while !f() {
        assert!(
            start.elapsed() < Duration::from_secs(secs),
            "timed out: {what}"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

/// By default `add_pipe` returns once the acceptor attached the pipe, which
/// a late Confirm delays past the verified Reply; with `return_on_reply`
/// it returns at the Reply.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn add_pipe_waits_for_the_attachment() {
    let (client, _server, listener, stall) = setup(config()).await;
    let hold = Duration::from_millis(400);
    let start = Instant::now();
    let pipe = client
        .add_pipe(carrier(&listener, &stall, Some(hold)), PipeOptions::new())
        .await
        .unwrap();
    assert!(start.elapsed() >= hold - Duration::from_millis(20));
    assert!(
        tokio::time::timeout(Duration::ZERO, pipe.attached())
            .await
            .is_ok_and(|r| r.is_ok())
    );

    // The Confirm is held until released: a call that returns did not wait
    // for the attachment.
    let opts = PipeOptions::new().with_return_on_reply(true);
    let pipe = tokio::time::timeout(
        GUARD,
        client.add_pipe(carrier(&listener, &stall, Some(HOUR)), opts),
    )
    .await
    .expect("add_pipe waited for the attachment")
    .unwrap();
    assert!(pipe.options().unwrap().return_on_reply);
    assert!(
        tokio::time::timeout(Duration::ZERO, pipe.attached())
            .await
            .is_err()
    );
    stall.release();
    tokio::time::timeout(Duration::from_secs(5), pipe.attached())
        .await
        .unwrap()
        .unwrap();
    client.close().await;
    listener.close();
}

/// The handshake timeout bounds the whole call: a pipe not attached by
/// then is aborted and the call times out, leaving no pipe.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn add_pipe_times_out_and_leaves_no_pipe() {
    let mut c = config();
    c.handshake_timeout = None;
    c.join_timeout = Duration::from_millis(600);
    let (client, server, listener, stall) = setup(c).await;
    let start = Instant::now();
    let r = client
        .add_pipe(
            carrier(&listener, &stall, Some(Duration::from_secs(30))),
            PipeOptions::new(),
        )
        .await;
    assert_eq!(r.err(), Some(PipeError::TimedOut));
    let took = start.elapsed();
    assert!(took >= Duration::from_millis(580), "{took:?}");
    // A guard against a hang only: three join timeouts and a second.
    assert!(took < Duration::from_millis(2800), "{took:?}");
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
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_cancelled_add_pipe_aborts_the_pipe() {
    let (client, _server, listener, stall) = setup(config()).await;
    let r = tokio::time::timeout(
        Duration::from_millis(200),
        client.add_pipe(
            carrier(&listener, &stall, Some(Duration::from_secs(30))),
            PipeOptions::new(),
        ),
    )
    .await;
    assert!(r.is_err());
    assert_eq!(live_joins(&client), 0);
    client.close().await;
    listener.close();
}

/// A pipe removed before the peer attached it fails the call with the
/// pipe-gone error, the session's end with the session's error.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn add_pipe_fails_when_the_pipe_or_the_session_goes() {
    let (client, _server, listener, stall) = setup(config()).await;
    let s = client.clone();
    let io = carrier(&listener, &stall, Some(Duration::from_secs(30)));
    let call = tokio::spawn(async move { s.add_pipe(io, PipeOptions::new()).await });
    until("the join", 5, || live_joins(&client) == 1).await;
    let pipe = client
        .pipes()
        .into_iter()
        .find(|p| p.id().get() != 0)
        .unwrap();
    pipe.joined().await.unwrap();
    pipe.close().unwrap();
    let e = tokio::time::timeout(Duration::from_secs(5), call)
        .await
        .unwrap()
        .unwrap()
        .unwrap_err();
    assert!(
        matches!(e, PipeError::Failed(_) | PipeError::UnknownPipe),
        "{e:?}"
    );

    let s = client.clone();
    let io = carrier(&listener, &stall, Some(Duration::from_secs(30)));
    let call = tokio::spawn(async move { s.add_pipe(io, PipeOptions::new()).await });
    until("the second join", 5, || live_joins(&client) == 1).await;
    client.abort(VarInt::from_u32(1), b"");
    let e = tokio::time::timeout(Duration::from_secs(5), call)
        .await
        .unwrap()
        .unwrap()
        .unwrap_err();
    assert!(matches!(e, PipeError::SessionLost(_)), "{e:?}");
    listener.close();
}

/// A session already closing, by a shutdown whose CONNECTION_CLOSE has no
/// hand-off limit, still bounds `close` by the hand-off limit when the
/// carrier takes nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
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
    shut.abort();
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
    let s = client.clone();
    let closing =
        tokio::spawn(async move { s.close_with_error(VarInt::from_u32(0x2a), b"bye").await });
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(!closing.is_finished(), "the flush waits for the carrier");
    client.abort(VarInt::from_u32(7), b"other");
    // The close's hand-off limit is an hour and the carrier still takes
    // nothing: only the abort can have ended it.
    tokio::time::timeout(GUARD, closing)
        .await
        .expect("the abort ended the flush")
        .unwrap();
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
/// takes the close.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
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
    let (client, server, listener, _stall) = setup(config()).await;
    let (mut w, _r) = client.open_bi().await.unwrap();
    w.write_all(&[3; 100_000]).await.unwrap();
    let (_sw, mut r) = server.accept_bi().await.unwrap();
    client
        .close_with_error(VarInt::from_u32(0x2a), b"bye")
        .await;
    let e = tokio::time::timeout(GUARD, server.closing()).await.unwrap();
    assert!(closed_with(&e, 0x2a, b"bye"), "{e:?}");
    // The reader starts after the close arrived.
    tokio::time::sleep(Duration::from_millis(50)).await;
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
    tokio::time::timeout(GUARD, server.wait()).await.unwrap();
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
        tokio::time::timeout(GUARD, server.wait())
            .await
            .expect("the drain ended with the discard, not the hour's linger");
        listener.close();
    }
}

/// The close-code hook is told every end: the session's code after a coded
/// close (at both ends), 0 for a pipe removed while its session goes on, and
/// 0 for a carrier dropped unused.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
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
        .add_pipe(
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
    tokio::time::timeout(GUARD, client.wait()).await.unwrap();
    tokio::time::timeout(GUARD, server.wait()).await.unwrap();
    assert_eq!(*first.lock().unwrap(), [0x2a]);
    assert_eq!(*server_side.lock().unwrap(), [0x2a]);
    listener.close();
}

/// A local close still flushing when the peer's close arrives: once its
/// hand-off limit passed, what the peer sent before its close stays
/// readable until the linger deadline, not discarded with the hand-off.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
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
    let s = client.clone();
    let closing =
        tokio::spawn(async move { s.close_with_error(VarInt::from_u32(1), b"mine").await });
    tokio::time::sleep(Duration::from_millis(100)).await;
    server
        .close_with_error(VarInt::from_u32(0x2a), b"bye")
        .await;
    let e = tokio::time::timeout(GUARD, client.closing()).await.unwrap();
    assert!(closed_with(&e, 0x2a, b"bye"), "{e:?}");
    tokio::time::timeout(GUARD, closing).await.unwrap().unwrap();
    // Past the hand-off limit of the stalled close.
    tokio::time::sleep(Duration::from_millis(1300)).await;
    let mut got = 0;
    while let Ok(Some(b)) = r.read_chunk(1 << 20).await {
        got += b.len();
    }
    assert_eq!(got, 50_000);
    listener.close();
}
