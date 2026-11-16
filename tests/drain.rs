//! `PipeIo::with_drain`: the future runs after the carrier's graceful end,
//! bounded by its limit, and is dropped unrun after any other end.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use tokio::time::Instant;
use zmux::{Config, PipeIo, Session};

/// What a drain holds (the connection, in an adapter): `gone` once it is
/// dropped, `ran` once the drain was polled.
#[derive(Default)]
struct Held {
    ran: AtomicBool,
    gone: AtomicBool,
}

struct Guard(Arc<Held>);

impl Drop for Guard {
    fn drop(&mut self) {
        self.0.gone.store(true, Ordering::SeqCst);
    }
}

/// A drain that never ends, like the wait for a response its server never
/// ends.
fn endless(held: &Arc<Held>) -> impl Future<Output = ()> + Send + 'static {
    let guard = Guard(held.clone());
    async move {
        guard.0.ran.store(true, Ordering::SeqCst);
        std::future::pending::<()>().await;
    }
}

async fn wait_gone(held: &Held) {
    while !held.gone.load(Ordering::SeqCst) {
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
}

const LIMIT: Duration = Duration::from_secs(3);

#[tokio::test(start_paused = true)]
async fn a_drain_that_never_ends_is_dropped_at_its_limit() {
    let held = Arc::new(Held::default());
    let (a, b) = tokio::io::duplex(1 << 16);
    let a = PipeIo::new(a).with_drain(endless(&held), LIMIT);
    let server = tokio::spawn(Session::accept(PipeIo::new(b), Config::default()));
    let client = Session::connect(a, Config::default()).await.unwrap();
    let server = server.await.unwrap().unwrap();
    client.close().await;
    client.closed().await;
    let ended = Instant::now();
    wait_gone(&held).await;
    assert!(held.ran.load(Ordering::SeqCst), "the drain did not run");
    let waited = ended.elapsed();
    assert!(
        waited >= LIMIT && waited <= LIMIT + Duration::from_millis(50),
        "the drain was dropped after {waited:?}, not at its limit"
    );
    drop(server);
}

/// A carrier whose graceful end fails.
struct FailingEnd(tokio::io::DuplexStream);

impl tokio::io::AsyncRead for FailingEnd {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for FailingEnd {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.0).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Err(std::io::ErrorKind::BrokenPipe.into()))
    }
}

#[tokio::test(start_paused = true)]
async fn a_carrier_whose_end_failed_drops_its_drain_unrun() {
    let held = Arc::new(Held::default());
    let (a, b) = tokio::io::duplex(1 << 16);
    let a = PipeIo::new(FailingEnd(a)).with_drain(endless(&held), LIMIT);
    let server = tokio::spawn(Session::accept(PipeIo::new(b), Config::default()));
    let client = Session::connect(a, Config::default()).await.unwrap();
    let server = server.await.unwrap().unwrap();
    client.close().await;
    client.closed().await;
    tokio::time::timeout(Duration::from_millis(100), wait_gone(&held))
        .await
        .expect("the drain was kept");
    assert!(
        !held.ran.load(Ordering::SeqCst),
        "a failed carrier's drain ran"
    );
    drop(server);
}

#[tokio::test(start_paused = true)]
async fn an_unused_carrier_drops_its_drain_unrun() {
    let held = Arc::new(Held::default());
    let (a, _b) = tokio::io::duplex(1 << 16);
    drop(PipeIo::new(a).with_drain(endless(&held), LIMIT));
    assert!(held.gone.load(Ordering::SeqCst));
    assert!(!held.ran.load(Ordering::SeqCst));
}

#[tokio::test(start_paused = true)]
async fn a_drain_that_ends_releases_at_once() {
    let held = Arc::new(Held::default());
    let guard = Guard(held.clone());
    let (a, b) = tokio::io::duplex(1 << 16);
    let a = PipeIo::new(a).with_drain(
        async move {
            guard.0.ran.store(true, Ordering::SeqCst);
        },
        LIMIT,
    );
    let server = tokio::spawn(Session::accept(PipeIo::new(b), Config::default()));
    let client = Session::connect(a, Config::default()).await.unwrap();
    let server = server.await.unwrap().unwrap();
    client.close().await;
    client.closed().await;
    let ended = Instant::now();
    wait_gone(&held).await;
    assert!(held.ran.load(Ordering::SeqCst));
    assert!(ended.elapsed() < Duration::from_millis(50));
    drop(server);
}

/// Two drains on one carrier (`with_drain` twice) both run after its
/// graceful end, each dropped at its own limit.
#[tokio::test(start_paused = true)]
async fn joined_drains_each_keep_their_limit() {
    let (short, long) = (Arc::new(Held::default()), Arc::new(Held::default()));
    let (a, b) = tokio::io::duplex(1 << 16);
    let a = PipeIo::new(a)
        .with_drain(endless(&short), Duration::from_secs(1))
        .with_drain(endless(&long), LIMIT);
    let server = tokio::spawn(Session::accept(PipeIo::new(b), Config::default()));
    let client = Session::connect(a, Config::default()).await.unwrap();
    let server = server.await.unwrap().unwrap();
    client.close().await;
    client.closed().await;
    let ended = Instant::now();
    wait_gone(&short).await;
    let first = ended.elapsed();
    wait_gone(&long).await;
    let second = ended.elapsed();
    assert!(short.ran.load(Ordering::SeqCst) && long.ran.load(Ordering::SeqCst));
    assert!(
        first >= Duration::from_secs(1) && first < LIMIT,
        "the short drain ended after {first:?}"
    );
    assert!(second >= LIMIT, "the long drain ended after {second:?}");
    drop(server);
}

/// An aborted carrier has no graceful end: its drain is dropped unrun.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_aborted_carrier_drops_its_drain_unrun() {
    use zmux::{Listener, ListenerConfig, PipeAuth, PipeHint, PipeId, PipeOptions};
    let held = Arc::new(Held::default());
    let mut config = Config::default();
    config.max_pipes = 4;
    config.pipe_auth = PipeAuth::psk(*b"drain-abort-test-0123456789abcde").with_end_to_end();
    let listener = Listener::new(config.clone(), ListenerConfig::default()).unwrap();
    let carrier = |drain: Option<&Arc<Held>>| {
        let (a, b) = tokio::io::duplex(1 << 16);
        let l = listener.clone();
        tokio::spawn(async move {
            let _ = l
                .handle_pipe(
                    PipeIo::new(b),
                    PipeHint::from_peer(([127, 0, 0, 1], 0).into()),
                )
                .await;
        });
        let io = PipeIo::new(a).with_abort(|| {});
        match drain {
            Some(h) => io.with_drain(endless(h), LIMIT),
            None => io,
        }
    };
    let client = Session::connect(carrier(Some(&held)), config)
        .await
        .unwrap();
    let server = listener.accept().await.unwrap();
    client
        .add_pipe(carrier(None), PipeOptions::default())
        .await
        .unwrap();
    client.pipe(PipeId::new(0)).unwrap().abort().unwrap();
    tokio::time::timeout(Duration::from_secs(5), wait_gone(&held))
        .await
        .expect("the drain was kept");
    assert!(
        !held.ran.load(Ordering::SeqCst),
        "an aborted carrier's drain ran"
    );
    drop((client, server));
}

/// A joined pipe that only reads ends its unused sending half gracefully at
/// the join (`end_unused`): its drain runs once the pipe is gone.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_joined_carriers_unused_half_arms_its_drain() {
    use zmux::{Listener, ListenerConfig, PipeAuth, PipeDirection, PipeHint, PipeOptions};
    let held = Arc::new(Held::default());
    let mut config = Config::default();
    config.max_pipes = 4;
    config.pipe_auth = PipeAuth::psk(*b"drain-unused-test-0123456789abcd").with_end_to_end();
    let listener = Listener::new(config.clone(), ListenerConfig::default()).unwrap();
    let carrier = || {
        let (a, b) = tokio::io::duplex(1 << 16);
        let l = listener.clone();
        tokio::spawn(async move {
            let _ = l
                .handle_pipe(
                    PipeIo::new(b),
                    PipeHint::from_peer(([127, 0, 0, 1], 0).into()),
                )
                .await;
        });
        PipeIo::new(a)
    };
    let client = Session::connect(carrier(), config).await.unwrap();
    let server = listener.accept().await.unwrap();
    let mut only_in = PipeOptions::default();
    only_in.direction = PipeDirection::In;
    client
        .add_pipe(
            carrier().with_drain(endless(&held), Duration::from_millis(200)),
            only_in,
        )
        .await
        .unwrap();
    client.close().await;
    client.closed().await;
    tokio::time::timeout(Duration::from_secs(5), wait_gone(&held))
        .await
        .expect("the drain was kept");
    assert!(held.ran.load(Ordering::SeqCst), "the drain did not run");
    drop(server);
}
