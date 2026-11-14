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
use zmux::Backoff;
use zmux::helpers::{PipePool, PoolDecision, PoolView, RotatePolicy};
use zmux::{
    Config, InboundState, Listener, ListenerConfig, OutboundState, PipeAuth, PipeDirection,
    PipeHint, PipeIo, Session,
};

fn config() -> Config {
    let mut c = Config::default();
    c.max_pipes = 6;
    c.pipe_auth = PipeAuth::psk(*b"maintain-psk----0123456789abcdef").with_end_to_end();
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
    /// The join of a split pool each one-way carrier was dialled in, in dial order.
    join_of: Arc<Mutex<Vec<usize>>>,
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
            join_of: Arc::default(),
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

    /// A one-way carrier of a split pool's member, paired at the listener by `token`.
    fn one_way(&self, direction: PipeDirection, token: [u8; 16], join: usize) -> PipeIo {
        self.join_of.lock().unwrap().push(join);
        self.dials.fetch_add(1, Ordering::SeqCst);
        self.times.lock().unwrap().push(Instant::now());
        let (a, b) = tokio::io::duplex(256 * 1024);
        let l = self.listener.clone();
        let kill = Arc::new(Kill::default());
        self.kills.lock().unwrap().push(kill.clone());
        self.one_way.lock().unwrap().push((direction, kill.clone()));
        let mine = Killable { io: a, kill };
        let mut hint = PipeHint::from_peer(([127, 0, 0, 1], 0).into());
        hint.pair = Some(token.to_vec());
        match direction {
            PipeDirection::Out => {
                tokio::spawn(async move {
                    let _ = l.handle_pipe(PipeIo::reader(b), hint).await;
                });
                PipeIo::writer(mine)
            }
            PipeDirection::In => {
                tokio::spawn(async move {
                    let _ = l.handle_pipe(PipeIo::writer(b), hint).await;
                });
                PipeIo::reader(mine)
            }
            PipeDirection::Bidi => unreachable!("a split pool dials one-way carriers"),
        }
    }

    /// A pool whose members are split carriers: a downlink and an uplink
    /// paired into one join.
    fn split_pool(&self, count: usize) -> PipePool {
        let d = self.clone();
        let joins = Arc::new(AtomicUsize::new(0));
        let mut pool = PipePool::join(count, move |session: Session, options| {
            let d = d.clone();
            let join = joins.fetch_add(1, Ordering::SeqCst);
            async move {
                // The pool's joins do not wait for the attachment.
                assert!(options.return_on_reply);
                let mut token = [0; 16];
                getrandom::fill(&mut token).map_err(io::Error::other)?;
                let up = d.one_way(PipeDirection::Out, token, join);
                let down = d.one_way(PipeDirection::In, token, join);
                let pipe = session
                    .begin_add_pipe(PipeIo::paired_join(up, down), options)
                    .map_err(io::Error::other)?;
                Ok(vec![pipe])
            }
        });
        pool.options.probation =
            zmux::Change::Set(Some(zmux::Cap::Fixed(Duration::from_millis(50))));
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
        pool.options.probation =
            zmux::Change::Set(Some(zmux::Cap::Fixed(Duration::from_millis(50))));
        pool.backoff = fixed_backoff(Duration::from_millis(50), Duration::from_millis(200));
        pool
    }
}

async fn setup() -> (Session, Session, Dialer) {
    let listener =
        Listener::new(config(), ListenerConfig::default()).expect("valid listener configuration");
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

/// The starts of the pool's dials as the pool counts them (a view's
/// `last_dial_at`), which its waits count from. A dial function reads the
/// clock only once its future runs, later by the scheduler's delay, so the
/// gaps between such readings can fall short of the waits.
#[derive(Clone, Default)]
struct Starts(Arc<Mutex<Vec<Instant>>>);

impl Starts {
    /// Notes the last dial's start; a policy calls it at each look.
    fn see(&self, v: &PoolView<'_>) {
        if let Some(t) = v.last_dial_at {
            let mut s = self.0.lock().unwrap();
            if s.last() != Some(&t) {
                s.push(t);
            }
        }
    }

    /// A policy that only notes the starts: it decides nothing.
    fn policy(&self) -> impl FnMut(&PoolView<'_>, &mut PoolDecision) + Send + 'static {
        let s = self.clone();
        move |v: &PoolView<'_>, _: &mut PoolDecision| s.see(v)
    }

    /// The starts once `n` were seen (the last one at the look after it).
    async fn wait(&self, n: usize) -> Vec<Instant> {
        until("dial starts seen", 10, || self.0.lock().unwrap().len() >= n).await;
        self.0.lock().unwrap().clone()
    }
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
    let handle = zmux::helpers::maintain_pipes(&client, dialer.pool(2)).expect("valid pool");
    until("two usable pipes", 10, || usable(&client) == 2).await;
    // Kill one pool carrier (index 0 is the bootstrap's).
    let kill = dialer.kills.lock().unwrap()[1].clone();
    kill.kill();
    until("a redial", 10, || dialer.dials.load(Ordering::SeqCst) >= 3).await;
    until("two usable pipes again", 10, || usable(&client) == 2).await;
    assert_eq!(dialer.dials.load(Ordering::SeqCst), 3);
    handle.stop();
    until("stopped", 5, || handle.is_finished()).await;
    client.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn failed_dials_back_off() {
    let (client, _server, dialer) = setup().await;
    *dialer.fail_next.lock().unwrap() = 4;
    let starts = Starts::default();
    let pool = dialer.pool(1).with_policy(starts.policy());
    let handle = zmux::helpers::maintain_pipes(&client, pool).expect("valid pool");
    until("one usable pipe", 10, || usable(&client) == 1).await;
    let times = starts.wait(5).await;
    assert_eq!(dialer.dials.load(Ordering::SeqCst), 5);
    // 50, 100, 200, 200 ms between the attempts.
    let gaps: Vec<Duration> = times.windows(2).map(|w| w[1] - w[0]).collect();
    for (gap, want) in gaps.iter().zip([50, 100, 200, 200]) {
        assert!(*gap >= Duration::from_millis(want), "{gaps:?}");
    }
    drop(handle);
    client.close().await;
}

/// Checks that a make-before-break replacement re-sent no stream data of
/// its own: it suspends nothing, and its old pipe closes once its data is
/// acknowledged. Stream data is re-sent only for the two causes that a
/// pipe's delay alone triggers (MULTIPATH.md Sections 7.4 and 7.5.1), both
/// seen on a loaded host where acknowledgements wait for the scheduler:
/// - opportunistic reinjection: the peer's flow control (or a binding that
///   moves) holds the stream back and its data on one pipe is acknowledged
///   later than `max(2 x srtt_f + max_ack_delay, min(PTO_p, 2E))` (seen: 75
///   to 112 ms for a threshold of 70 to 97 ms): one copy goes on another
///   pipe, the slow pipe is penalized, and the penalty re-sends the stream's
///   unacknowledged data on it. Each penalty follows a copy;
/// - an ack stall of `T_suspect` on a pipe, which makes it suspect and
///   reinjects what it holds.
fn assert_no_replacement_reinjection(client: &Session) {
    let stats = client.stats();
    assert_eq!(stats.suspensions, 0, "{stats:?}");
    if stats.penalties > 0 {
        assert!(stats.bytes_opportunistic > 0, "{stats:?}");
    }
    // Counted in the same step as the reinjection it causes; a DRAINING
    // pipe's suspicion has no `PipeSuspect` event.
    let suspects = zmux::test_hooks::suspects(client);
    assert!(
        stats.bytes_reinjected == 0 || stats.penalties > 0 || suspects > 0,
        "reinjected without a penalty or a suspect pipe: {stats:?}"
    );
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
    let handle = zmux::helpers::maintain_pipes(&client, pool).expect("valid pool");
    until("one usable pipe", 10, || usable(&client) == 1).await;
    // The bootstrap pipe is the fallback tier: the stream's data goes on
    // the pool's pipes, whose bytes rotate them (affinity alone may bind
    // the stream to pipe 0, and then nothing rotates).
    client
        .pipe(zmux::PipeId::new(0))
        .unwrap()
        .update(&zmux::PipeUpdate {
            send_priority: zmux::Change::Set(10),
            ..Default::default()
        })
        .unwrap();
    transfer(&client, &server, 8 << 20).await;
    // The maintainer looks every 100 ms: the last rotation may be seen
    // after the transfer ended.
    until("rotated", 10, || dialer.dials.load(Ordering::SeqCst) >= 2).await;
    assert_no_replacement_reinjection(&client);
    // Not asserted: `pipe_failures`. The peer's PIPE_ABANDON of a graceful
    // removal may travel on another pipe and arrive after the old pipe's
    // end, which the receiver then treats as
    // unexpected; nothing is lost or re-sent either way.
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
    client.close().await;
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
    let handle = zmux::helpers::maintain_pipes(&client, pool).expect("valid pool");
    until("three rotations", 10, || {
        dialer.dials.load(Ordering::SeqCst) >= 4
    })
    .await;
    transfer(&client, &server, 1 << 20).await;
    assert_no_replacement_reinjection(&client);
    // Not asserted: `pipe_failures`. The peer's PIPE_ABANDON of a graceful
    // removal may travel on another pipe and arrive after the old pipe's
    // end, which the receiver then treats as
    // unexpected; nothing is lost or re-sent either way.
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
    client.close().await;
}

/// Stopping the pool closes a replacement still being rotated in; the
/// member it would replace stays.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stop_closes_a_replacement_being_rotated_in() {
    let (client, _server, dialer) = setup().await;
    let mut pool = dialer.pool(1);
    pool.rotate = Some(RotatePolicy::new().with_max_age(Duration::from_millis(1)));
    let handle = zmux::helpers::maintain_pipes(&client, pool).expect("valid pool");
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
    client.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ends_with_the_session() {
    let (client, _server, dialer) = setup().await;
    let handle = zmux::helpers::maintain_pipes(&client, dialer.pool(1)).expect("valid pool");
    until("one usable pipe", 10, || usable(&client) == 1).await;
    client.close().await;
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
    )
    .expect("valid pool");
    until("finished", 5, || handle.is_finished()).await;
    // Without multipath nothing is dialled.
    assert_eq!(dials.load(Ordering::SeqCst), 0);
}

/// A split pool: one uplink and one downlink,
/// dialled in parallel at the start and again, together, when both are lost.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn split_pool_dials_both_directions_in_parallel() {
    let (client, _server, dialer) = setup().await;
    let handle = zmux::helpers::maintain_pipes(&client, dialer.split_pool(1)).expect("valid pool");
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
    // Both directions are dialled by one join, together.
    {
        let joins = dialer.join_of.lock().unwrap();
        assert_eq!(joins.len(), 2);
        assert_eq!(joins[0], joins[1], "{joins:?}");
    }
    // Both carriers die (not the bootstrap's, the first): both directions
    // are dialled again at once.
    for k in dialer.kills.lock().unwrap().iter().skip(1) {
        k.kill();
    }
    until("redialled", 10, || dialer.dials.load(Ordering::SeqCst) >= 4).await;
    {
        let joins = dialer.join_of.lock().unwrap();
        assert_eq!(joins[2], joins[3], "{joins:?}");
        assert_ne!(joins[1], joins[2], "{joins:?}");
    }
    until("both halves again", 10, || halves(&client) == (1, 1)).await;
    drop(handle);
    client.close().await;
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
    let handle = zmux::helpers::maintain_pipes(&client, dialer.split_pool(1)).expect("valid pool");
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
    client.close().await;
}

/// A split member rotates by age like any member of the pool.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn split_pool_rotates_a_downlink() {
    let (client, _server, dialer) = setup().await;
    let mut pool = dialer.split_pool(1);
    pool.rotate = Some(RotatePolicy::new().with_max_age(Duration::from_millis(300)));
    let handle = zmux::helpers::maintain_pipes(&client, pool).expect("valid pool");
    until("a downlink rotated twice", 10, || {
        downlinks(&dialer).len() >= 3
    })
    .await;
    handle.stop();
    until("stopped", 5, || handle.is_finished()).await;
    client.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn policy_count_replaces_the_pool_count() {
    let (client, _server, dialer) = setup().await;
    let pool = dialer
        .pool(1)
        .with_policy(|_: &PoolView<'_>, d: &mut PoolDecision| d.count = Some(3));
    let handle = zmux::helpers::maintain_pipes(&client, pool).expect("valid pool");
    until("three usable pipes", 10, || usable(&client) == 3).await;
    assert_eq!(dialer.dials.load(Ordering::SeqCst), 3);
    handle.stop();
    until("stopped", 5, || handle.is_finished()).await;
    client.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn policy_count_of_zero_keeps_one_pipe() {
    let (client, _server, dialer) = setup().await;
    let pool = dialer
        .pool(2)
        .with_policy(|_: &PoolView<'_>, d: &mut PoolDecision| d.count = Some(0));
    let handle = zmux::helpers::maintain_pipes(&client, pool).expect("valid pool");
    until("one usable pipe", 10, || usable(&client) == 1).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(dialer.dials.load(Ordering::SeqCst), 1);
    drop(handle);
    client.close().await;
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
    let handle = zmux::helpers::maintain_pipes(&client, pool).expect("valid pool");
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
    let handle = zmux::helpers::maintain_pipes(&client, pool).expect("valid pool");
    until("a second dial", 10, || {
        dialer.dials.load(Ordering::SeqCst) >= 2
    })
    .await;
    let waited = dialer.times.lock().unwrap()[1] - held;
    // The upper bound guards against a hang only (three waits and a second).
    assert!(
        waited >= Duration::from_millis(190) && waited < Duration::from_secs(2),
        "{waited:?}"
    );
    drop(handle);
    client.close().await;
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
    let handle = zmux::helpers::maintain_pipes(&client, pool).expect("valid pool");
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
    assert_no_replacement_reinjection(&client);
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(dialer.dials.load(Ordering::SeqCst), 2);
    drop(handle);
    client.close().await;
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
    let handle = zmux::helpers::maintain_pipes(&client, pool).expect("valid pool");
    until("one usable pipe", 10, || usable(&client) == 1).await;
    let before = calls.load(Ordering::SeqCst);
    tokio::time::sleep(window).await;
    let got = calls.load(Ordering::SeqCst) - before;
    drop(handle);
    client.close().await;
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
/// the policy's 10 ms, not after the backoff, which is an hour here: every
/// retry that comes at all came by the policy.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn policy_dial_time_replaces_the_backoff() {
    let (client, _server, dialer) = setup().await;
    *dialer.fail_next.lock().unwrap() = 3;
    let hour = Duration::from_secs(3600);
    let starts = Starts::default();
    let seen = starts.clone();
    let pool = dialer
        .pool(1)
        .with_backoff(fixed_backoff(hour, hour))
        .with_policy(move |v: &PoolView<'_>, d: &mut PoolDecision| {
            seen.see(v);
            d.next_dial_at = v.last_dial_at.map(|t| t + Duration::from_millis(10));
        });
    let handle = zmux::helpers::maintain_pipes(&client, pool).expect("valid pool");
    until("one usable pipe", 10, || usable(&client) == 1).await;
    let times = starts.wait(4).await;
    assert_eq!(dialer.dials.load(Ordering::SeqCst), 4);
    for w in times.windows(2) {
        let gap = w[1] - w[0];
        assert!(gap >= Duration::from_millis(10), "{gap:?}");
    }
    drop(handle);
    client.close().await;
}

/// The policy's probe settings go to the pipes added after the decision
/// that sets them; a pipe added before keeps the pool's options.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn policy_probe_settings_apply_to_later_pipes() {
    // Both ends probe their pipe pairs only every minute by default.
    let slow = || {
        let mut c = config();
        c.liveness.probe_interval = Some(Duration::from_secs(60));
        c.liveness.standby_probe = None;
        c
    };
    let listener =
        Listener::new(slow(), ListenerConfig::default()).expect("valid listener configuration");
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
                d.set_liveness(zmux::PipeLiveness {
                    probe_interval: zmux::Inherit::Set(Some(Duration::from_secs(1))),
                    probe_jitter: zmux::Inherit::Set(0.0),
                    ..Default::default()
                })
                .unwrap();
            }
        });
    let handle = zmux::helpers::maintain_pipes(&client, pool).expect("valid pool");
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
    // also brought PIPE_PINGs with acknowledgements on it).
    handle.stop();
    until("stopped", 5, || handle.is_finished()).await;
    client.pipe(second).unwrap().close().unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;
    let before = pings(first);
    tokio::time::sleep(Duration::from_secs(4)).await;
    let a = pings(first) - before;
    assert!(a <= 1, "{a} probes on the earlier pipe");
    drop(handle);
    client.close().await;
}

/// A handwritten decision's liveness settings are checked when they are set:
/// an interval below 1 s and a jitter outside [0, 1) are the pipe options'
/// error, and change nothing.
#[test]
fn handwritten_liveness_settings_are_checked() {
    let mut d = PoolDecision::default();
    let with = |interval, jitter| zmux::PipeLiveness {
        probe_interval: interval,
        probe_jitter: jitter,
        ..Default::default()
    };
    for bad in [
        Duration::ZERO,
        Duration::from_nanos(1),
        Duration::from_millis(999),
    ] {
        assert!(matches!(
            d.set_liveness(with(zmux::Inherit::Set(Some(bad)), zmux::Inherit::Session)),
            Err(zmux::PipeError::InvalidOptions(_))
        ));
    }
    for bad in [-0.1, 1.0, f64::NAN] {
        assert!(matches!(
            d.set_liveness(with(zmux::Inherit::Session, zmux::Inherit::Set(bad))),
            Err(zmux::PipeError::InvalidOptions(_))
        ));
    }
    assert_eq!(d.liveness(), None);
    let off = with(zmux::Inherit::Set(None), zmux::Inherit::Session);
    d.set_liveness(off).unwrap();
    assert_eq!(d.liveness(), Some(off));
    let fixed = with(
        zmux::Inherit::Set(Some(Duration::from_secs(1))),
        zmux::Inherit::Set(0.0),
    );
    d.set_liveness(fixed).unwrap();
    assert_eq!(d.liveness(), Some(fixed));
}

/// The redial backoff counts from the start of the previous attempt, not
/// from its failure: a dial that fails after 300 ms is followed 500 ms
/// after it started.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn backoff_counts_from_the_start_of_the_attempt() {
    let (client, _server, _dialer) = setup().await;
    let starts = Starts::default();
    let pool = PipePool::new(1, move |_| async move {
        tokio::time::sleep(Duration::from_millis(300)).await;
        Err::<PipeIo, _>(io::Error::other("refused"))
    })
    .with_backoff(fixed_backoff(
        Duration::from_millis(500),
        Duration::from_millis(500),
    ))
    .with_policy(starts.policy());
    let handle = zmux::helpers::maintain_pipes(&client, pool).expect("valid pool");
    let t = starts.wait(3).await;
    for w in t.windows(2) {
        let gap = w[1] - w[0];
        assert!(
            // The upper bound guards against a hang only (three backoffs and a second).
            gap >= Duration::from_millis(480) && gap < Duration::from_millis(2500),
            "{t:?}"
        );
    }
    drop(handle);
    client.close().await;
}

/// A dial that succeeded backs off too: the next dial, after its member
/// fails, starts the backoff's initial delay after it started, not at once.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn backoff_follows_a_successful_dial() {
    let (client, _server, dialer) = setup().await;
    let starts = Starts::default();
    let pool = dialer
        .pool(1)
        .with_backoff(fixed_backoff(
            Duration::from_millis(800),
            Duration::from_secs(2),
        ))
        .with_policy(starts.policy());
    let handle = zmux::helpers::maintain_pipes(&client, pool).expect("valid pool");
    until("one usable pipe", 10, || usable(&client) == 1).await;
    // Past the maintainer's next look (100 ms): it saw the member usable.
    tokio::time::sleep(Duration::from_millis(250)).await;
    let kill = dialer.kills.lock().unwrap()[1].clone();
    kill.kill();
    let t = starts.wait(2).await;
    assert!(t[1] - t[0] >= Duration::from_millis(790), "{t:?}");
    drop(handle);
    client.close().await;
}

/// A split bootstrap's carrier makes pipe pair 0 only: adding it as a
/// further pipe is refused: the carrier cannot be used so.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_split_bootstrap_carrier_cannot_join() {
    let (client, _server, _dialer) = setup().await;
    let (a, _b) = tokio::io::duplex(1024);
    let (c, _d) = tokio::io::duplex(1024);
    let io = PipeIo::split_bootstrap(PipeIo::writer(a), PipeIo::reader(c));
    assert!(matches!(
        client.begin_add_pipe(io, zmux::PipeOptions::new()).err(),
        Some(zmux::PipeError::InvalidArgument)
    ));
    client.close().await;
}

/// A carrier whose writes after the first wait until `hold` passed: the
/// joiner's Confirm reaches the acceptor late, while the joiner is
/// already ACTIVE, which the secure carrier allows.
struct LateConfirm {
    io: Killable,
    first: bool,
    hold: Pin<Box<tokio::time::Sleep>>,
}

impl AsyncRead for LateConfirm {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_read(cx, buf)
    }
}

impl AsyncWrite for LateConfirm {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if !std::mem::replace(&mut self.first, false) && self.hold.as_mut().poll(cx).is_pending() {
            return Poll::Pending;
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

/// A replacement counts as usable only once the acceptor attached it: an
/// old member closed while the acceptor still waits for the replacement's
/// Confirm would leave the acceptor with no live pipe, and it would end
/// the session.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rotation_waits_for_the_acceptor_to_attach() {
    let (client, server, dialer) = setup().await;
    let late = Arc::new(AtomicBool::new(false));
    let d = dialer.clone();
    let l = late.clone();
    let mut pool = PipePool::new(1, move |_| {
        let d = d.clone();
        let late = l.load(Ordering::SeqCst);
        async move {
            d.dials.fetch_add(1, Ordering::SeqCst);
            let (a, b) = tokio::io::duplex(256 * 1024);
            let listener = d.listener.clone();
            tokio::spawn(async move {
                let _ = listener
                    .handle_pipe(
                        PipeIo::new(b),
                        PipeHint::from_peer(([127, 0, 0, 1], 0).into()),
                    )
                    .await;
            });
            let kill = Arc::new(Kill::default());
            d.kills.lock().unwrap().push(kill.clone());
            let io = Killable { io: a, kill };
            if !late {
                return Ok(PipeIo::new(io));
            }
            Ok(PipeIo::new(LateConfirm {
                io,
                first: true,
                hold: Box::pin(tokio::time::sleep(Duration::from_millis(300))),
            }))
        }
    });
    // No probation: a replacement is usable as soon as it is attached.
    pool.options.probation = zmux::Change::Set(None);
    pool.rotate = Some(RotatePolicy::new().with_max_age(Duration::from_millis(400)));
    let handle = zmux::helpers::maintain_pipes(&client, pool).expect("valid pool");
    until("one pool pipe", 10, || usable(&client) == 1).await;
    // Pipe 0 goes only once the acceptor attached the member: before, the
    // acceptor would be left with no live pipe and end the session.
    for p in client.pipes().into_iter().filter(|p| p.id().get() != 0) {
        tokio::time::timeout(Duration::from_secs(10), p.attached())
            .await
            .expect("the member attached")
            .unwrap();
    }
    // The pool's member is the session's only pipe.
    dialer.kills.lock().unwrap()[0].kill();
    until("pipe 0 gone", 10, || {
        client
            .pipe_stats()
            .iter()
            .all(|p| p.pipe.get() != 0 || p.outbound != Some(OutboundState::Active))
    })
    .await;
    late.store(true, Ordering::SeqCst);
    until("rotated", 10, || dialer.dials.load(Ordering::SeqCst) >= 2).await;
    tokio::time::sleep(Duration::from_millis(600)).await;
    transfer(&client, &server, 64 << 10).await;
    handle.stop();
    until("stopped", 5, || handle.is_finished()).await;
    client.close().await;
}

/// Pipe 0 and a pipe the peer joined are attached from the start; one of
/// our joins only once the acceptor showed it attached it, which a late
/// Confirm delays past `joined`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn attached_waits_for_the_acceptor() {
    let (client, server, dialer) = setup().await;
    let soon = |p: &zmux::Pipe| {
        let p = p.clone();
        async move { tokio::time::timeout(Duration::from_secs(5), p.attached()).await }
    };
    let zero = |s: &Session| s.pipes().into_iter().find(|p| p.id().get() == 0).unwrap();
    soon(&zero(&client)).await.unwrap().unwrap();
    soon(&zero(&server)).await.unwrap().unwrap();

    let (a, b) = tokio::io::duplex(256 * 1024);
    let listener = dialer.listener.clone();
    tokio::spawn(async move {
        let _ = listener
            .handle_pipe(
                PipeIo::new(b),
                PipeHint::from_peer(([127, 0, 0, 1], 0).into()),
            )
            .await;
    });
    let io = LateConfirm {
        io: Killable {
            io: a,
            kill: Arc::new(Kill::default()),
        },
        first: true,
        hold: Box::pin(tokio::time::sleep(Duration::from_millis(400))),
    };
    let pipe = client
        .begin_add_pipe(PipeIo::new(io), zmux::PipeOptions::new())
        .unwrap();
    tokio::time::timeout(Duration::from_secs(5), pipe.joined())
        .await
        .unwrap()
        .unwrap();
    // The Confirm is still held: the acceptor has not attached it.
    assert!(
        tokio::time::timeout(Duration::from_millis(50), pipe.attached())
            .await
            .is_err()
    );
    soon(&pipe).await.unwrap().unwrap();
    let accepted = server
        .pipes()
        .into_iter()
        .find(|p| p.id() == pipe.id())
        .unwrap();
    soon(&accepted).await.unwrap().unwrap();
    client.close().await;
}

/// `replace_pipes` advances the epoch and replaces every pipe, make before break, with
/// one dialled through the redial hook and joined in the new epoch.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn replace_pipes_replaces_every_pipe() {
    // No exchange of the policy's own, so the advance starts at Stable(0).
    let manual = || {
        let mut c = config();
        c.epoch_policy = zmux::EpochPolicy::MANUAL;
        c
    };
    let listener =
        Listener::new(manual(), ListenerConfig::default()).expect("valid listener configuration");
    let dialer = Dialer::new(&listener);
    let dials = Arc::new(AtomicUsize::new(0));
    let mut cc = manual();
    let (l, d) = (listener.clone(), dials.clone());
    cc.redial = Some(zmux::Redial::new(move |_req| {
        let l = l.clone();
        d.fetch_add(1, Ordering::SeqCst);
        async move {
            let (a, b) = tokio::io::duplex(256 * 1024);
            tokio::spawn(async move {
                let _ = l
                    .handle_pipe(
                        PipeIo::new(b),
                        PipeHint::from_peer(([127, 0, 0, 1], 0).into()),
                    )
                    .await;
            });
            Ok(PipeIo::new(a))
        }
    }));
    let client = Session::connect(dialer.carrier(), cc).await.unwrap();
    let server = listener.accept().await.unwrap();
    assert_eq!(client.epoch(), Some(0));
    // The exchange runs over a pipe joined Sealed or Bound.
    client
        .add_pipe(dialer.carrier(), zmux::PipeOptions::new())
        .await
        .expect("joined");
    let before: Vec<_> = client.pipes().iter().map(|p| p.id()).collect();
    tokio::time::timeout(Duration::from_secs(20), client.replace_pipes())
        .await
        .expect("replaced in time")
        .expect("replaced");
    assert_eq!(client.epoch(), Some(1));
    assert!(dials.load(Ordering::SeqCst) >= before.len());
    let live: Vec<_> = client
        .pipe_stats()
        .into_iter()
        .filter(|p| p.outbound == Some(OutboundState::Active))
        .collect();
    assert!(!live.is_empty());
    for p in &live {
        assert!(!before.contains(&p.pipe), "{p:?}");
        assert_eq!(p.epoch, Some(1), "{p:?}");
    }
    transfer(&client, &server, 1 << 16).await;
    client.close().await;
}

/// Without the redial hook `replace_pipes` is the configuration error.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn replace_pipes_needs_the_redial_hook() {
    let (client, _server, _dialer) = setup().await;
    assert!(matches!(
        client.replace_pipes().await,
        Err(zmux::PipeError::InvalidOptions(e)) if e.field() == "redial"
    ));
    client.close().await;
}

/// A backoff without jitter, so that its delays are exact lower bounds.
fn fixed_backoff(min: Duration, max: Duration) -> Backoff {
    let mut b = Backoff::new(min, max);
    b.jitter = 0.0;
    b
}
