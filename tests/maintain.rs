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
use zmux::helpers::{Backoff, PipePool, PoolDecision, PoolView, RotatePolicy};
use zmux::{
    Config, InboundState, Listener, ListenerConfig, OutboundState, PipeAuth, PipeDirection,
    PipeHint, PipeIo, Session,
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
                .handle_pipe(
                    PipeIo::new(b),
                    PipeHint::from_peer(([127, 0, 0, 1], 0).into()),
                )
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
        let hint = PipeHint::from_peer(([127, 0, 0, 1], 0).into());
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

    /// A pool whose members are split carriers: a downlink and an uplink
    /// joined together ([`zmux::join_split`]).
    fn split_pool(&self, count: usize) -> PipePool {
        let d = self.clone();
        let mut pool = PipePool::join(count, move |session: Session, options| {
            let d = d.clone();
            async move {
                let dial = |req: DialRequest| {
                    d.dials.fetch_add(1, Ordering::SeqCst);
                    d.times.lock().unwrap().push(Instant::now());
                    d.one_way(&req)
                };
                zmux::join_split(
                    &session,
                    options,
                    |join| {
                        let io = dial(DialRequest::new(PipeDirection::In, Some(join)));
                        async move { Ok(io) }
                    },
                    || {
                        let io = dial(DialRequest::new(PipeDirection::Out, None));
                        async move { Ok(io) }
                    },
                )
                .await
            }
        });
        pool.options.probation = Some(Duration::from_millis(50));
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
        pool.backoff = Backoff::new(Duration::from_millis(50), Duration::from_millis(200));
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
        .filter(|p| p.pipe.get() != 0)
        .filter(|p| p.outbound == Some(OutboundState::Active) && !p.in_probation)
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
    pool.rotate = Some(RotatePolicy::new().with_max_bytes(1 << 20));
    let handle = zmux::helpers::maintain_pipes(&client, pool);
    until("one usable pipe", 10, || usable(&client) == 1).await;
    // The bootstrap pipe is the fallback tier: the stream's data goes on
    // the pool's pipes, whose bytes rotate them (affinity alone may bind
    // the stream to pipe 0, and then nothing rotates).
    client
        .pipe(zmux::PipeId::new(0))
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
            .filter(|p| p.pipe.get() != 0 && p.outbound == Some(OutboundState::Active))
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
    pool.rotate = Some(
        RotatePolicy::new()
            .with_max_age(Duration::from_millis(300))
            .with_jitter(0.1),
    );
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
            .filter(|p| p.pipe.get() != 0 && p.outbound == Some(OutboundState::Active))
            .count()
            <= 2
    })
    .await;
    handle.stop();
    until("stopped", 5, || handle.is_finished()).await;
    client.close(0u32.into(), b"");
}

/// Stopping the pool closes a replacement still being rotated in; the
/// member it would replace stays.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stop_closes_a_replacement_being_rotated_in() {
    let (client, _server, dialer) = setup().await;
    let mut pool = dialer.pool(1);
    pool.rotate = Some(RotatePolicy::new().with_max_age(Duration::from_millis(1)));
    let handle = zmux::helpers::maintain_pipes(&client, pool);
    until("a replacement dialled", 10, || {
        dialer.dials.load(Ordering::SeqCst) >= 3
    })
    .await;
    handle.stop();
    until("stopped", 5, || handle.is_finished()).await;
    let pool_pipes = || {
        client
            .pipe_stats()
            .iter()
            .filter(|p| p.pipe.get() != 0 && p.outbound == Some(OutboundState::Active))
            .count()
    };
    until("one pool pipe left", 10, || pool_pipes() == 1).await;
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
            .filter(|p| p.pipe.get() != 0 && p.outbound == Some(OutboundState::Active))
            .count();
        let down = pipes
            .iter()
            .filter(|p| p.pipe.get() != 0 && p.inbound == Some(InboundState::Open))
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

/// Downlinks are judged by their inbound state: a split member whose
/// downlink dies is closed and redialled whole, without a backoff.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn split_pool_redials_a_member_whole() {
    let (client, _server, dialer) = setup().await;
    let handle = zmux::helpers::maintain_pipes(&client, dialer.split_pool(1));
    let open_in = |s: &Session| {
        s.pipe_stats()
            .iter()
            .filter(|p| p.pipe.get() != 0 && p.inbound == Some(InboundState::Open))
            .count()
    };
    until("a downlink", 10, || open_in(&client) == 1).await;
    for k in downlinks(&dialer) {
        k.kill();
    }
    until("a second downlink", 10, || downlinks(&dialer).len() == 2).await;
    until("open again", 10, || open_in(&client) == 1).await;
    // Both halves were dialled again.
    until("both halves", 10, || {
        dialer.dials.load(Ordering::SeqCst) == 4
    })
    .await;
    drop(handle);
    client.close(0u32.into(), b"");
}

/// A split member rotates by age like any member of the pool.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn split_pool_rotates_a_downlink() {
    let (client, _server, dialer) = setup().await;
    let mut pool = dialer.split_pool(1);
    pool.rotate = Some(RotatePolicy::new().with_max_age(Duration::from_millis(300)));
    let handle = zmux::helpers::maintain_pipes(&client, pool);
    until("a downlink rotated twice", 10, || {
        downlinks(&dialer).len() >= 3
    })
    .await;
    handle.stop();
    until("stopped", 5, || handle.is_finished()).await;
    client.close(0u32.into(), b"");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn policy_count_replaces_the_pool_count() {
    let (client, _server, dialer) = setup().await;
    let pool = dialer
        .pool(1)
        .with_policy(|_: &PoolView<'_>, d: &mut PoolDecision| d.count = Some(3));
    let handle = zmux::helpers::maintain_pipes(&client, pool);
    until("three usable pipes", 10, || usable(&client) == 3).await;
    assert_eq!(dialer.dials.load(Ordering::SeqCst), 3);
    handle.stop();
    until("stopped", 5, || handle.is_finished()).await;
    client.close(0u32.into(), b"");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn policy_count_of_zero_keeps_one_pipe() {
    let (client, _server, dialer) = setup().await;
    let pool = dialer
        .pool(2)
        .with_policy(|_: &PoolView<'_>, d: &mut PoolDecision| d.count = Some(0));
    let handle = zmux::helpers::maintain_pipes(&client, pool);
    until("one usable pipe", 10, || usable(&client) == 1).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(dialer.dials.load(Ordering::SeqCst), 1);
    drop(handle);
    client.close(0u32.into(), b"");
}

/// A dial held by the policy starts at the policy's time, and a time
/// beyond the backoff's max holds it only that long.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn policy_next_dial_at_holds_dials_within_the_backoff_max() {
    let (client, _server, dialer) = setup().await;
    let start = Instant::now();
    let hold = start + Duration::from_millis(150);
    let pool = dialer
        .pool(1)
        .with_policy(move |_: &PoolView<'_>, d: &mut PoolDecision| d.next_dial_at = Some(hold));
    let handle = zmux::helpers::maintain_pipes(&client, pool);
    until("one usable pipe", 10, || usable(&client) == 1).await;
    let first = dialer.times.lock().unwrap()[0];
    assert!(first >= hold, "{:?}", first - start);
    drop(handle);

    // A second maintainer keeps a pipe of its own: its first dial is held
    // for the backoff's max (200 ms), not until the policy's time.
    let far = Instant::now() + Duration::from_secs(3600);
    let pool = dialer
        .pool(1)
        .with_policy(move |_: &PoolView<'_>, d: &mut PoolDecision| d.next_dial_at = Some(far));
    let held = Instant::now();
    let handle = zmux::helpers::maintain_pipes(&client, pool);
    until("a second dial", 10, || {
        dialer.dials.load(Ordering::SeqCst) >= 2
    })
    .await;
    let waited = dialer.times.lock().unwrap()[1] - held;
    assert!(
        waited >= Duration::from_millis(190) && waited < Duration::from_secs(2),
        "{waited:?}"
    );
    drop(handle);
    client.close(0u32.into(), b"");
}

/// The policy replaces a pipe, make before break, at the time it names.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn policy_rotate_replaces_the_named_pipe() {
    let (client, server, dialer) = setup().await;
    let mut asked = false;
    let pool = dialer
        .pool(1)
        .with_policy(move |v: &PoolView<'_>, d: &mut PoolDecision| {
            if !asked && let Some(p) = v.members.iter().find(|p| p.usable) {
                asked = true;
                d.rotate.push((p.id, v.now));
            }
        });
    let handle = zmux::helpers::maintain_pipes(&client, pool);
    until("one rotation", 10, || {
        dialer.dials.load(Ordering::SeqCst) >= 2
    })
    .await;
    until("one pool pipe left", 10, || {
        client
            .pipe_stats()
            .iter()
            .filter(|p| p.pipe.get() != 0 && p.outbound == Some(OutboundState::Active))
            .count()
            == 1
    })
    .await;
    transfer(&client, &server, 1 << 20).await;
    assert_eq!(client.stats().bytes_reinjected, 0);
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(dialer.dials.load(Ordering::SeqCst), 2);
    drop(handle);
    client.close(0u32.into(), b"");
}

/// Counts the policy's decisions over `window` once the pool is up, the
/// policy asking to be consulted again within `recheck`.
async fn decisions_with_recheck(recheck: Duration, window: Duration) -> usize {
    let (client, _server, dialer) = setup().await;
    let calls = Arc::new(AtomicUsize::new(0));
    let n = calls.clone();
    let pool = dialer
        .pool(1)
        .with_policy(move |_: &PoolView<'_>, d: &mut PoolDecision| {
            n.fetch_add(1, Ordering::SeqCst);
            d.recheck = Some(recheck);
        });
    let handle = zmux::helpers::maintain_pipes(&client, pool);
    until("one usable pipe", 10, || usable(&client) == 1).await;
    let before = calls.load(Ordering::SeqCst);
    tokio::time::sleep(window).await;
    let got = calls.load(Ordering::SeqCst) - before;
    drop(handle);
    client.close(0u32.into(), b"");
    got
}

/// A recheck shorter than the maintainer's own interval (100 ms) brings
/// the next decision forward, with no event in the pool.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn policy_recheck_shortens_the_interval() {
    let got = decisions_with_recheck(Duration::from_millis(20), Duration::from_secs(1)).await;
    // At most 10 decisions a second without it; about 50 with it.
    assert!(got >= 25, "{got}");
}

/// A recheck below the floor is lengthened to it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn policy_recheck_is_floored() {
    assert_eq!(zmux::helpers::RECHECK_FLOOR, Duration::from_millis(10));
    let got = decisions_with_recheck(Duration::from_nanos(1), Duration::from_secs(1)).await;
    assert!((20..=130).contains(&got), "{got}");
}

/// A policy's next dial replaces the backoff: failed dials are retried by
/// the policy's 10 ms, not after the backoff's 50, 100 and 200 ms.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn policy_dial_time_replaces_the_backoff() {
    let (client, _server, dialer) = setup().await;
    *dialer.fail_next.lock().unwrap() = 3;
    let pool = dialer
        .pool(1)
        .with_policy(|v: &PoolView<'_>, d: &mut PoolDecision| {
            d.next_dial_at = v.last_dial_at.map(|t| t + Duration::from_millis(10));
        });
    let handle = zmux::helpers::maintain_pipes(&client, pool);
    until("one usable pipe", 10, || usable(&client) == 1).await;
    let times = dialer.times.lock().unwrap().clone();
    assert_eq!(times.len(), 4);
    for w in times.windows(2) {
        let gap = w[1] - w[0];
        assert!(
            gap >= Duration::from_millis(10) && gap < Duration::from_millis(50),
            "{gap:?}"
        );
    }
    drop(handle);
    client.close(0u32.into(), b"");
}

/// The policy's probe settings go to the pipes added after the decision
/// that sets them; a pipe added before keeps the pool's options.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn policy_probe_settings_apply_to_later_pipes() {
    // Both ends probe their pipe pairs only every minute by default.
    let slow = || {
        let mut c = config();
        c.probe_interval = Some(Duration::from_secs(60));
        c.standby_probe = None;
        c
    };
    let listener = Listener::new(slow(), ListenerConfig::default());
    let dialer = Dialer::new(&listener);
    let client = Session::connect(dialer.carrier(), slow()).await.unwrap();
    let _server = listener.accept().await.unwrap();
    let fast = Arc::new(AtomicBool::new(false));
    let f = fast.clone();
    let pool = dialer
        .pool(2)
        .with_policy(move |_: &PoolView<'_>, d: &mut PoolDecision| {
            // One pipe first, then a second with a 1 s probe interval.
            d.count = Some(1);
            if f.load(Ordering::SeqCst) {
                d.count = Some(2);
                d.set_probe_interval(Duration::from_secs(1)).unwrap();
                d.set_probe_jitter(0.0).unwrap();
            }
        });
    let handle = zmux::helpers::maintain_pipes(&client, pool);
    until("one usable pipe", 10, || usable(&client) >= 1).await;
    let first = client
        .pipe_stats()
        .iter()
        .map(|p| p.pipe)
        .filter(|p| p.get() != 0)
        .min()
        .unwrap();
    fast.store(true, Ordering::SeqCst);
    until("two usable pipes", 10, || usable(&client) == 2).await;
    let pings = |id: zmux::PipeId| {
        client
            .pipe_stats()
            .iter()
            .find(|p| p.pipe == id)
            .map_or(0, |p| p.pings_sent)
    };
    let second = client
        .pipe_stats()
        .iter()
        .map(|p| p.pipe)
        .filter(|p| p.get() != 0 && *p != first)
        .min()
        .unwrap();
    let before = pings(second);
    tokio::time::sleep(Duration::from_secs(4)).await;
    let b = pings(second) - before;
    assert!(b >= 3, "{b} probes on the later pipe");
    // Alone, the earlier pipe keeps the minute (the later pipe's probes
    // also brought PIPE_PINGs with acknowledgements on it, MULTIPATH.md
    // Section 6.5).
    handle.stop();
    until("stopped", 5, || handle.is_finished()).await;
    client.pipe(second).unwrap().close().unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;
    let before = pings(first);
    tokio::time::sleep(Duration::from_secs(4)).await;
    let a = pings(first) - before;
    assert!(a <= 1, "{a} probes on the earlier pipe");
    drop(handle);
    client.close(0u32.into(), b"");
}

/// A handwritten decision's probe settings are checked when they are set:
/// an interval below 1 s and a jitter outside [0, 1) are the pipe options'
/// error.
#[test]
fn handwritten_probe_settings_are_checked() {
    let mut d = PoolDecision::default();
    for bad in [Duration::from_nanos(1), Duration::from_millis(999)] {
        assert_eq!(
            d.set_probe_interval(bad),
            Err(zmux::PipeError::InvalidOptions)
        );
    }
    for bad in [-0.1, 1.0, f64::NAN] {
        assert_eq!(
            d.set_probe_jitter(bad),
            Err(zmux::PipeError::InvalidOptions)
        );
    }
    assert_eq!((d.probe_interval(), d.probe_jitter()), (None, None));
    assert_eq!(
        d.set_probe_interval(Duration::ZERO),
        Err(zmux::PipeError::InvalidOptions)
    );
    d.set_probe_interval(zmux::Period::Off).unwrap();
    assert_eq!(d.probe_interval(), Some(zmux::Period::Off));
    d.set_probe_interval(Duration::from_secs(1)).unwrap();
    d.set_probe_jitter(0.0).unwrap();
    assert_eq!(
        (d.probe_interval(), d.probe_jitter()),
        (Some(zmux::Period::Every(Duration::from_secs(1))), Some(0.0))
    );
}

/// The redial backoff counts from the start of the previous attempt, not
/// from its failure: a dial that fails after 300 ms is followed 500 ms
/// after it started.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn backoff_counts_from_the_start_of_the_attempt() {
    let (client, _server, _dialer) = setup().await;
    let starts = Arc::new(Mutex::new(Vec::new()));
    let s = starts.clone();
    let pool = PipePool::new(1, move |_| {
        let s = s.clone();
        async move {
            s.lock().unwrap().push(Instant::now());
            tokio::time::sleep(Duration::from_millis(300)).await;
            Err::<PipeIo, _>(io::Error::other("refused"))
        }
    })
    .with_backoff(Backoff::new(
        Duration::from_millis(500),
        Duration::from_millis(500),
    ));
    let handle = zmux::helpers::maintain_pipes(&client, pool);
    until("three attempts", 10, || starts.lock().unwrap().len() >= 3).await;
    let t = starts.lock().unwrap().clone();
    for w in t.windows(2) {
        let gap = w[1] - w[0];
        assert!(
            gap >= Duration::from_millis(480) && gap < Duration::from_millis(700),
            "{t:?}"
        );
    }
    drop(handle);
    client.close(0u32.into(), b"");
}

/// A dial that succeeded backs off too: the next dial, after its member
/// fails, starts the backoff's initial delay after it started, not at once.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn backoff_follows_a_successful_dial() {
    let (client, _server, dialer) = setup().await;
    let pool = dialer.pool(1).with_backoff(Backoff::new(
        Duration::from_millis(800),
        Duration::from_secs(2),
    ));
    let handle = zmux::helpers::maintain_pipes(&client, pool);
    until("one usable pipe", 10, || usable(&client) == 1).await;
    // Past the maintainer's next look (100 ms): it saw the member usable.
    tokio::time::sleep(Duration::from_millis(250)).await;
    let kill = dialer.kills.lock().unwrap()[1].clone();
    kill.kill();
    until("a redial", 10, || dialer.dials.load(Ordering::SeqCst) >= 2).await;
    let t = dialer.times.lock().unwrap().clone();
    assert!(t[1] - t[0] >= Duration::from_millis(790), "{t:?}");
    drop(handle);
    client.close(0u32.into(), b"");
}

/// A split bootstrap's carrier makes pipe pair 0 only: adding it as a
/// further pipe is refused with the options error.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_split_bootstrap_carrier_cannot_join() {
    let (client, _server, _dialer) = setup().await;
    let (a, _b) = tokio::io::duplex(1024);
    let (c, _d) = tokio::io::duplex(1024);
    let io = PipeIo::split_bootstrap(PipeIo::writer(a), PipeIo::reader(c));
    assert_eq!(
        client.add_pipe(io, zmux::PipeOptions::new()).err(),
        Some(zmux::PipeError::InvalidOptions)
    );
    client.close(0u32.into(), b"");
}
