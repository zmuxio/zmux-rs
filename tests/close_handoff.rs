//! `Session::close` returns once CONNECTION_CLOSE is handed to the
//! carriers and their input drained, within its bound, and
//! `Session::add_pipe` returns once the
//! peer attached the pipe unless `no_wait_attached`.

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
}

impl Stall {
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
            && let Some(h) = self.hold.as_mut()
            && h.as_mut().poll(cx).is_pending()
        {
            return Poll::Pending;
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
    let listener =
        Listener::new(c.clone(), ListenerConfig::default()).expect("valid listener configuration");
    let stall = Arc::new(Stall::default());
    let client = Session::connect(carrier(&listener, &stall, None), c)
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
        let cc = c.clone();
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
        let start = Instant::now();
        client_rt.block_on(client.close(VarInt::from_u32(7), b"bye"));
        assert!(start.elapsed() < Duration::from_millis(900));
        drop(client_rt);
        drop(client);
        let e = server_rt.block_on(async {
            tokio::time::timeout(Duration::from_secs(5), server.closed())
                .await
                .expect("the peer learnt of the close")
        });
        assert!(closed_by_peer(&e, 7), "{e:?}");
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
                s.close(VarInt::from_u32(3), b"stalled").await;
                Instant::now()
            })
        };
        tokio::time::sleep(bound / 2).await;
        client.close(VarInt::from_u32(4), b"again").await;
        let second = Instant::now();
        let first = first.await.unwrap();
        assert!(
            first - start >= bound - Duration::from_millis(20),
            "{:?}",
            first - start
        );
        assert!(
            first - start < bound + Duration::from_millis(500),
            "{:?}",
            first - start
        );
        assert!(second <= first + Duration::from_millis(50));
        // The session ended locally, with the first call's error.
        tokio::time::timeout(Duration::from_secs(2), client.closed())
            .await
            .unwrap();
        assert!(matches!(
            client.close_reason(),
            Some(SessionError::ApplicationClosed { remote: false, code, .. }) if code == VarInt::from_u32(3)
        ));
        let again = Instant::now();
        client.close(VarInt::from_u32(5), b"").await;
        assert!(again.elapsed() < Duration::from_millis(50));
        listener.close();
    }
}

/// A healthy carrier takes the close at once: `close` does not wait for
/// the peer.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn close_returns_once_the_carrier_took_it() {
    let (client, server, listener, _stall) = setup(config()).await;
    let start = Instant::now();
    client.close(VarInt::from_u32(9), b"done").await;
    assert!(start.elapsed() < Duration::from_millis(500));
    let e = tokio::time::timeout(Duration::from_secs(2), server.closed())
        .await
        .unwrap();
    assert!(closed_by_peer(&e, 9), "{e:?}");
    listener.close();
}

/// `close` returns only once the carrier's write side is shut after
/// CONNECTION_CLOSE, or, while a slow shutdown is still under way, once the peer
/// ended the carrier (its input read to the end, so nothing unread is left to reset
/// it): a process that exits then leaves no carrier half written.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn close_returns_after_the_write_side_is_shut() {
    for slow in [false, true] {
        let (client, server, listener, stall) = setup(config()).await;
        stall.slow_shutdown.store(slow, Ordering::SeqCst);
        client.close(VarInt::from_u32(4), b"bye").await;
        let shut = stall.shut.load(Ordering::SeqCst);
        assert!(
            shut || (slow
                && client
                    .pipe_stats()
                    .iter()
                    .all(|p| p.inbound == Some(zmux::InboundState::Ended))),
            "slow shutdown {slow}"
        );
        let e = tokio::time::timeout(Duration::from_secs(2), server.closed())
            .await
            .unwrap();
        assert!(closed_by_peer(&e, 4), "{e:?}");
        listener.close();
    }
}

/// `close` returns only once the input was drained: while the peer keeps
/// its write side open, until the linger timeout (at least 250 ms). A
/// process that exited at the hand-off would close a carrier that may
/// still hold unread input, which resets it, and the peer would lose
/// CONNECTION_CLOSE with what it had not read yet.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn close_waits_for_the_drain() {
    let (client, _server, listener, stall) = setup(config()).await;
    stall.mute.store(true, Ordering::SeqCst);
    let start = Instant::now();
    client.close(VarInt::from_u32(4), b"bye").await;
    let took = start.elapsed();
    assert!(stall.shut.load(Ordering::SeqCst));
    assert!(took >= Duration::from_millis(240), "{took:?}");
    assert!(took < Duration::from_millis(1500), "{took:?}");
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
    client.close(VarInt::from_u32(2), b"later").await;
    let e = tokio::time::timeout(Duration::from_secs(2), server.closed())
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
/// a late Confirm delays past the verified Reply; with `no_wait_attached`
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

    let start = Instant::now();
    let opts = PipeOptions::new().with_no_wait_attached(true);
    let pipe = client
        .add_pipe(carrier(&listener, &stall, Some(hold)), opts)
        .await
        .unwrap();
    assert!(start.elapsed() < hold - Duration::from_millis(100));
    assert!(pipe.options().unwrap().no_wait_attached);
    assert!(
        tokio::time::timeout(Duration::from_millis(50), pipe.attached())
            .await
            .is_err()
    );
    tokio::time::timeout(Duration::from_secs(5), pipe.attached())
        .await
        .unwrap()
        .unwrap();
    client.close(VarInt::ZERO, b"").await;
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
    assert!(took < Duration::from_millis(1500), "{took:?}");
    assert_eq!(live_joins(&client), 0);
    // The session goes on over pipe 0.
    let (mut w, _r) = client.open_bi().await.unwrap();
    w.write_all(b"still").await.unwrap();
    w.finish().unwrap();
    let (_w, mut r) = server.accept_bi().await.unwrap();
    assert_eq!(r.read_to_end(16).await.unwrap(), b"still");
    client.close(VarInt::ZERO, b"").await;
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
    client.close(VarInt::ZERO, b"").await;
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
    client.close(VarInt::from_u32(1), b"").await;
    let e = tokio::time::timeout(Duration::from_secs(5), call)
        .await
        .unwrap()
        .unwrap()
        .unwrap_err();
    assert!(matches!(e, PipeError::SessionLost(_)), "{e:?}");
    listener.close();
}
