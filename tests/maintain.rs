//! `helpers::maintain_pipes` over in-memory carriers:
//! redials after failures with backoff, rotates by bytes and by age make
//! before break (nothing reinjected), and ends when stopped or when the
//! session closes.

use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf};
use zmux::DialRequest;
use zmux::helpers::{BackoffPolicy, PipePool, RotatePolicy};
use zmux::{
    Config, Listener, ListenerConfig, PipeAuth, PipeDirection, PipeHint, PipeIo, PipeState, Session,
};

fn config() -> Config {
    let mut c = Config::default();
    c.max_pipes = 6;
    c.pipe_auth = PipeAuth::psk(*b"maintain-psk----0123456789abcdef");
    c
}

/// A kill switch of a carrier: wakes its pending read.
#[derive(Default)]
struct Kill {
    killed: AtomicBool,
    reader: Mutex<Option<std::task::Waker>>,
}

impl Kill {
    fn kill(&self) {
        self.killed.store(true, Ordering::SeqCst);
        let w = self.reader.lock().unwrap().take();
        if let Some(w) = w {
            w.wake();
        }
    }
}

/// A carrier that fails both ways once killed.
struct Killable {
    io: DuplexStream,
    kill: Arc<Kill>,
}

fn dead() -> io::Error {
    io::Error::new(io::ErrorKind::ConnectionReset, "killed")
}

impl AsyncRead for Killable {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        *self.kill.reader.lock().unwrap() = Some(cx.waker().clone());
        if self.kill.killed.load(Ordering::SeqCst) {
            return Poll::Ready(Err(dead()));
        }
        Pin::new(&mut self.io).poll_read(cx, buf)
    }
}

impl AsyncWrite for Killable {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.kill.killed.load(Ordering::SeqCst) {
            return Poll::Ready(Err(dead()));
        }
        Pin::new(&mut self.io).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_shutdown(cx)
    }
}

/// Dials in-memory carriers to the listener; can fail dials and kill
/// carriers.
#[derive(Clone)]
struct Dialer {
    listener: Listener,
    dials: Arc<AtomicUsize>,
    fail_next: Arc<Mutex<usize>>,
    kills: Arc<Mutex<Vec<Arc<Kill>>>>,
    times: Arc<Mutex<Vec<Instant>>>,
    /// The one-way carriers of a split pool, by direction.
    one_way: Arc<Mutex<Vec<OneWay>>>,
}

/// A one-way carrier of a split pool: its direction and its switch.
type OneWay = (PipeDirection, Arc<Kill>);

impl Dialer {
    fn new(listener: &Listener) -> Self {
        Self {
            listener: listener.clone(),
            dials: Arc::default(),
            fail_next: Arc::default(),
            kills: Arc::default(),
            times: Arc::default(),
            one_way: Arc::default(),
        }
    }

    fn carrier(&self) -> PipeIo {
        let (a, b) = tokio::io::duplex(256 * 1024);
        let l = self.listener.clone();
        tokio::spawn(async move {
            let _ = l
                .handle_pipe(PipeIo::new(b), PipeHint::from_addr([127, 0, 0, 1].into()))
                .await;
        });
        let kill = Arc::new(Kill::default());
        self.kills.lock().unwrap().push(kill.clone());
        PipeIo::new(Killable { io: a, kill })
    }

    /// A one-way carrier for a split pool: an uplink joins in band, a
    /// downlink with the join header of its request.
    fn one_way(&self, req: &DialRequest) -> PipeIo {
        let (a, b) = tokio::io::duplex(256 * 1024);
        let l = self.listener.clone();
        let kill = Arc::new(Kill::default());
        self.kills.lock().unwrap().push(kill.clone());
        self.one_way
            .lock()
            .unwrap()
            .push((req.direction, kill.clone()));
        let mine = Killable { io: a, kill };
        let hint = PipeHint::from_addr([127, 0, 0, 1].into());
        match req.direction {
            PipeDirection::Out => {
                tokio::spawn(async move {
                    let _ = l.handle_pipe(PipeIo::reader(b), hint).await;
                });
                PipeIo::writer(mine)
            }
            PipeDirection::In => {
                let hint = hint.with_join_header(req.join_header.as_deref().unwrap_or(""));
                tokio::spawn(async move {
                    let _ = l.handle_pipe(PipeIo::writer(b), hint).await;
                });
                PipeIo::reader(mine)
            }
            PipeDirection::Bidi => unreachable!("a split pool dials one-way carriers"),
        }
    }

    fn split_pool(&self, count: usize) -> PipePool {
        let d = self.clone();
        let mut pool = PipePool::new(count, move |req: DialRequest| {
            let d = d.clone();
            async move {
                d.dials.fetch_add(1, Ordering::SeqCst);
                d.times.lock().unwrap().push(Instant::now());
                Ok(d.one_way(&req))
            }
        });
        pool.options.probation = Some(Duration::from_millis(50));
        pool.split = true;
        pool
    }

    fn pool(&self, count: usize) -> PipePool {
        let d = self.clone();
        let mut pool = PipePool::new(count, move |_| {
            let d = d.clone();
            async move {
                d.dials.fetch_add(1, Ordering::SeqCst);
                d.times.lock().unwrap().push(Instant::now());
                let fail = {
                    let mut n = d.fail_next.lock().unwrap();
                    let fail = *n > 0;
                    *n = n.saturating_sub(1);
                    fail
                };
                if fail {
                    return Err(io::Error::other("dial refused"));
                }
                Ok(d.carrier())
            }
        });
        // Probation of 50 ms keeps the tests short.
        pool.options.probation = Some(Duration::from_millis(50));
        pool.backoff = BackoffPolicy {
            initial: Duration::from_millis(50),
            max: Duration::from_millis(200),
            jitter: 0.0,
        };
        pool
    }
}

async fn setup() -> (Session, Session, Dialer) {
    let listener = Listener::new(config(), ListenerConfig::default());
    let dialer = Dialer::new(&listener);
    let client = Session::connect(dialer.carrier(), config()).await.unwrap();
    let server = listener.accept().await.unwrap();
    (client, server, dialer)
}

/// Pipes of the client whose outbound is active and out of probation,
/// the bootstrap pipe excluded.
fn usable(s: &Session) -> usize {
    s.pipe_stats()
        .iter()
        .filter(|p| p.pipe.0 != 0)
        .filter(|p| p.outbound == Some(PipeState::Active) && !p.in_probation)
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn keeps_count_pipes_and_redials_failures() {
    let (client, _server, dialer) = setup().await;
    let handle = zmux::helpers::maintain_pipes(&client, dialer.pool(2));
    until("two usable pipes", 10, || usable(&client) == 2).await;
    // Kill one pool carrier (index 0 is the bootstrap's).
    let kill = dialer.kills.lock().unwrap()[1].clone();
    kill.kill();
    until("a redial", 10, || dialer.dials.load(Ordering::SeqCst) >= 3).await;
    until("two usable pipes again", 10, || usable(&client) == 2).await;
    assert_eq!(dialer.dials.load(Ordering::SeqCst), 3);
    handle.stop();
    until("stopped", 5, || handle.is_finished()).await;
    client.close(0u32.into(), b"");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn failed_dials_back_off() {
    let (client, _server, dialer) = setup().await;
    *dialer.fail_next.lock().unwrap() = 4;
    let handle = zmux::helpers::maintain_pipes(&client, dialer.pool(1));
    until("one usable pipe", 10, || usable(&client) == 1).await;
    let times = dialer.times.lock().unwrap().clone();
    assert_eq!(times.len(), 5);
    // 50, 100, 200, 200 ms between the attempts.
    let gaps: Vec<Duration> = times.windows(2).map(|w| w[1] - w[0]).collect();
    for (gap, want) in gaps.iter().zip([50, 100, 200, 200]) {
        assert!(*gap >= Duration::from_millis(want), "{gaps:?}");
    }
    drop(handle);
    client.close(0u32.into(), b"");
}

/// Writes `len` bytes to the server and reads them back to the end.
async fn transfer(client: &Session, server: &Session, len: usize) {
    let (mut send, _r) = client.open_bi().await.unwrap();
    let writer = tokio::spawn(async move {
        let chunk = vec![5u8; 64 * 1024];
        let mut sent = 0;
        while sent < len {
            send.write_all(&chunk).await.unwrap();
            sent += chunk.len();
            // Paced, so that rotations happen during the transfer.
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        send.finish().unwrap();
    });
    let (_s, mut recv) = server.accept_bi().await.unwrap();
    let mut buf = vec![0u8; 256 * 1024];
    let mut got = 0;
    while let Some(n) = tokio::time::timeout(Duration::from_secs(5), recv.read(&mut buf))
        .await
        .expect("no stall")
        .unwrap()
    {
        got += n;
    }
    assert_eq!(got, len);
    writer.await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rotates_by_bytes_make_before_break() {
    let (client, server, dialer) = setup().await;
    let mut pool = dialer.pool(1);
    pool.rotate = Some(RotatePolicy {
        max_bytes: Some(1 << 20),
        max_age: None,
        jitter: 0.0,
    });
    let handle = zmux::helpers::maintain_pipes(&client, pool);
    until("one usable pipe", 10, || usable(&client) == 1).await;
    // The bootstrap pipe is the fallback tier: the stream's data goes on
    // the pool's pipes, whose bytes rotate them (affinity alone may bind
    // the stream to pipe 0, and then nothing rotates).
    client
        .pipe(zmux::PipeId(0))
        .unwrap()
        .set_send_priority(10)
        .unwrap();
    transfer(&client, &server, 8 << 20).await;
    let stats = client.stats();
    // The maintainer looks every 100 ms: the last rotation may be seen
    // after the transfer ended.
    until("rotated", 10, || dialer.dials.load(Ordering::SeqCst) >= 2).await;
    assert_eq!(stats.bytes_reinjected, 0, "{stats:?}");
    // Not asserted: `pipe_failures`. The peer's PIPE_ABANDON of a graceful
    // removal may travel on another pipe and arrive after the old pipe's
    // end, which MULTIPATH.md Section 7.3 then calls unexpected (an open
    // spec issue); nothing is lost or re-sent either way.
    until("one pool pipe left", 10, || {
        client
            .pipe_stats()
            .iter()
            .filter(|p| p.pipe.0 != 0 && p.outbound == Some(PipeState::Active))
            .count()
            == 1
    })
    .await;
    drop(handle);
    client.close(0u32.into(), b"");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rotates_by_age() {
    let (client, server, dialer) = setup().await;
    let mut pool = dialer.pool(1);
    pool.rotate = Some(RotatePolicy {
        max_bytes: None,
        max_age: Some(Duration::from_millis(300)),
        jitter: 0.1,
    });
    let handle = zmux::helpers::maintain_pipes(&client, pool);
    until("three rotations", 10, || {
        dialer.dials.load(Ordering::SeqCst) >= 4
    })
    .await;
    transfer(&client, &server, 1 << 20).await;
    let stats = client.stats();
    assert_eq!(stats.bytes_reinjected, 0, "{stats:?}");
    // Not asserted: `pipe_failures`. The peer's PIPE_ABANDON of a graceful
    // removal may travel on another pipe and arrive after the old pipe's
    // end, which MULTIPATH.md Section 7.3 then calls unexpected (an open
    // spec issue); nothing is lost or re-sent either way.
    // Make before break: the pool never ran without a usable pipe after
    // the first one (checked by the transfer); old pipes are closed.
    until("old pipes retired", 10, || {
        client
            .pipe_stats()
            .iter()
            .filter(|p| p.pipe.0 != 0 && p.outbound == Some(PipeState::Active))
            .count()
            <= 2
    })
    .await;
    handle.stop();
    until("stopped", 5, || handle.is_finished()).await;
    client.close(0u32.into(), b"");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ends_with_the_session() {
    let (client, _server, dialer) = setup().await;
    let handle = zmux::helpers::maintain_pipes(&client, dialer.pool(1));
    until("one usable pipe", 10, || usable(&client) == 1).await;
    client.close(0u32.into(), b"");
    until("finished", 5, || handle.is_finished()).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn single_pipe_sessions_end_it_at_once() {
    let (a, b) = tokio::io::duplex(64 * 1024);
    let server =
        tokio::spawn(async move { Session::accept(PipeIo::new(b), Config::default()).await });
    let client = Session::connect(PipeIo::new(a), Config::default())
        .await
        .unwrap();
    let _server = server.await.unwrap().unwrap();
    let dials = Arc::new(AtomicUsize::new(0));
    let d = dials.clone();
    let handle = zmux::helpers::maintain_pipes(
        &client,
        PipePool::new(1, move |_| {
            d.fetch_add(1, Ordering::SeqCst);
            let (x, _y) = tokio::io::duplex(1024);
            async move { Ok(PipeIo::new(x)) }
        }),
    );
    until("finished", 5, || handle.is_finished()).await;
    // Without multipath nothing is dialled.
    assert_eq!(dials.load(Ordering::SeqCst), 0);
}

/// A split pool (RESUME.md Section 4.3): one uplink and one downlink,
/// dialled in parallel at the start and again, together, when both are lost.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn split_pool_dials_both_directions_in_parallel() {
    let (client, _server, dialer) = setup().await;
    let handle = zmux::helpers::maintain_pipes(&client, dialer.split_pool(1));
    let halves = |s: &Session| {
        let pipes = s.pipe_stats();
        let up = pipes
            .iter()
            .filter(|p| p.pipe.0 != 0 && p.outbound == Some(PipeState::Active))
            .count();
        let down = pipes
            .iter()
            .filter(|p| p.pipe.0 != 0 && p.inbound == Some(PipeState::Open))
            .count();
        (up, down)
    };
    until("an uplink and a downlink", 10, || halves(&client) == (1, 1)).await;
    {
        let times = dialer.times.lock().unwrap();
        assert_eq!(times.len(), 2);
        assert!(times[1] - times[0] < Duration::from_millis(20), "{times:?}");
    }
    // Both carriers die (not the bootstrap's, the first): both directions
    // are dialled again at once.
    for k in dialer.kills.lock().unwrap().iter().skip(1) {
        k.kill();
    }
    until("redialled", 10, || dialer.dials.load(Ordering::SeqCst) >= 4).await;
    {
        let times = dialer.times.lock().unwrap();
        assert!(times[3] - times[2] < Duration::from_millis(20), "{times:?}");
    }
    until("both halves again", 10, || halves(&client) == (1, 1)).await;
    drop(handle);
    client.close(0u32.into(), b"");
}

/// The downlinks a split pool dialled so far.
fn downlinks(dialer: &Dialer) -> Vec<Arc<Kill>> {
    dialer
        .one_way
        .lock()
        .unwrap()
        .iter()
        .filter(|(d, _)| *d == PipeDirection::In)
        .map(|(_, k)| k.clone())
        .collect()
}

/// Downlinks are judged by their inbound state: one that dies is redialled
/// alone, without a backoff, and the uplink stays.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn split_pool_redials_a_lost_downlink() {
    let (client, _server, dialer) = setup().await;
    let handle = zmux::helpers::maintain_pipes(&client, dialer.split_pool(1));
    let open_in = |s: &Session| {
        s.pipe_stats()
            .iter()
            .filter(|p| p.pipe.0 != 0 && p.inbound == Some(PipeState::Open))
            .count()
    };
    until("a downlink", 10, || open_in(&client) == 1).await;
    for k in downlinks(&dialer) {
        k.kill();
    }
    until("a second downlink", 10, || downlinks(&dialer).len() == 2).await;
    until("open again", 10, || open_in(&client) == 1).await;
    // Only the downlink was dialled again.
    assert_eq!(dialer.dials.load(Ordering::SeqCst), 3);
    drop(handle);
    client.close(0u32.into(), b"");
}

/// A downlink rotates by age like any pipe of the pool.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn split_pool_rotates_a_downlink() {
    let (client, _server, dialer) = setup().await;
    let mut pool = dialer.split_pool(1);
    pool.rotate = Some(RotatePolicy {
        max_bytes: None,
        max_age: Some(Duration::from_millis(300)),
        jitter: 0.0,
    });
    let handle = zmux::helpers::maintain_pipes(&client, pool);
    until("a downlink rotated twice", 10, || {
        downlinks(&dialer).len() >= 3
    })
    .await;
    handle.stop();
    until("stopped", 5, || handle.is_finished()).await;
    client.close(0u32.into(), b"");
}
