//! Regression baselines of the idle footprint rows: the live heap of idle
//! sessions, streams and multipath
//! sessions, counted by a global allocator by the requested layout sizes
//! (independent of the allocator's size classes). Each row fails above the
//! specification's bound, and above this implementation's own baseline by
//! more than the run-to-run variation; an improvement moves the baseline down here.
//!
//! Release builds only (futures are larger in debug builds): CI runs
//! `cargo test --release --test footprint`. Measurement: N sessions after a
//! warm-up, both ends in this process, the carrier's user-space state
//! included (in-memory pipes' buffers, or TCP sockets on loopback), no idle
//! timeout or keep-alive, after the idle pipes gave their buffers back.

// A global allocator can only be implemented with unsafe code.
#![allow(unsafe_code)]

#[path = "common/core_pair.rs"]
mod core_pair;

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering::Relaxed};
use std::time::{Duration, Instant};

use zmux::proto::frame::Dir;
use zmux::proto::record::Framing;
use zmux::proto::session::{self as core, PipeId, RoleConfig};
use zmux::{
    Config, Listener, ListenerConfig, PipeAuth, PipeHint, PipeIo, PipeOptions, PipeState, Policy,
    Session,
};

struct Counting;

static LIVE: AtomicI64 = AtomicI64::new(0);

// SAFETY: forwards to the system allocator unchanged.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        LIVE.fetch_add(l.size() as i64, Relaxed);
        // SAFETY: forwarded unchanged.
        unsafe { System.alloc(l) }
    }

    unsafe fn alloc_zeroed(&self, l: Layout) -> *mut u8 {
        LIVE.fetch_add(l.size() as i64, Relaxed);
        // SAFETY: forwarded unchanged.
        unsafe { System.alloc_zeroed(l) }
    }

    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        LIVE.fetch_sub(l.size() as i64, Relaxed);
        // SAFETY: forwarded unchanged.
        unsafe { System.dealloc(p, l) }
    }

    unsafe fn realloc(&self, p: *mut u8, l: Layout, n: usize) -> *mut u8 {
        LIVE.fetch_add(n as i64 - l.size() as i64, Relaxed);
        // SAFETY: forwarded unchanged.
        unsafe { System.realloc(p, l, n) }
    }
}

#[global_allocator]
static GLOBAL: Counting = Counting;

/// The live heap, without the buffers of the process-wide read pool (a
/// shared pool is not any session's footprint).
fn live() -> i64 {
    let pool = zmux::test_hooks::read_pool_buffers() as i64 * READ_BUFFER;
    LIVE.load(Relaxed) - pool
}

/// The capacity of a read buffer of the pool.
const READ_BUFFER: i64 = 256 * 1024;

/// A footprint row: the specification's bound, this implementation's baseline
/// on this platform and its
/// run-to-run variation.
struct Row {
    name: &'static str,
    bound: f64,
    baseline: f64,
    /// Relative variation between runs of one version.
    noise: f64,
}

impl Row {
    fn check(&self, measured: f64) {
        println!(
            "FOOTPRINT {} measured={measured:.0} B baseline={:.0} B bound={:.0} B",
            self.name, self.baseline, self.bound
        );
        if std::env::var_os("FOOTPRINT_REPORT").is_some() {
            return;
        }
        assert!(
            measured <= self.bound,
            "{}: {measured:.0} B above the bound of {:.0} B",
            self.name,
            self.bound
        );
        assert!(
            // Two bytes for allocations of other threads meanwhile.
            measured <= self.baseline * (1.0 + self.noise) + 2.0,
            "{}: {measured:.0} B, a regression from the baseline of {:.0} B",
            self.name,
            self.baseline
        );
    }
}

/// The baseline of this platform: Linux, else Apple platforms (other
/// platforms report against the Linux values).
const fn base(linux: f64, apple: f64) -> f64 {
    if cfg!(target_vendor = "apple") {
        apple
    } else {
        linux
    }
}

/// The core of a session (one end, single pipe): deterministic.
const CORE: Row = Row {
    name: "idle core per session",
    bound: f64::INFINITY,
    baseline: 3808.0,
    noise: 0.0,
};

/// An idle stream, per end (both ends: bound 1.5 KiB).
const STREAM: Row = Row {
    name: "idle stream per end",
    bound: 768.0,
    baseline: 669.0,
    noise: 0.01,
};

/// An idle session, both ends, over an in-memory pipe (its buffers
/// counted), N = 200 after a warm-up. Variation within a version <= 30 B.
const PAIR_MEMORY: Row = Row {
    name: "idle session pair, in-memory pipe",
    bound: 17_408.0,
    baseline: base(16_000.0, 16_659.0),
    noise: 0.005,
};

/// The same over loopback TCP (the sockets' user-space state counted).
const PAIR_TCP: Row = Row {
    name: "idle session pair, loopback TCP",
    bound: 17_408.0,
    baseline: base(15_230.0, 15_830.0),
    noise: 0.01,
};

/// An idle multipath session, both ends, two pipe pairs (the second
/// standby) after the join, over in-memory pipes, N = 200 after a warm-up,
/// measured alone (the sessions of the rows before it released).
const MULTIPATH: Row = Row {
    name: "idle multipath session pair, two pipes",
    bound: 45_056.0,
    baseline: base(40_590.0, 42_558.0),
    noise: 0.02,
};

/// One configuration for every session, as an application with many
/// sessions shares it.
fn config() -> Arc<Config> {
    static C: std::sync::LazyLock<Arc<Config>> = std::sync::LazyLock::new(|| {
        let mut c = Config::default();
        c.max_idle_timeout = Duration::ZERO;
        c.keep_alive_period = None;
        Arc::new(c)
    });
    C.clone()
}

fn mp_config() -> Arc<Config> {
    static C: std::sync::LazyLock<Arc<Config>> = std::sync::LazyLock::new(|| {
        let mut c = Config::default();
        c.max_idle_timeout = Duration::ZERO;
        c.keep_alive_period = None;
        c.max_pipes = 8;
        c.pipe_auth = PipeAuth::psk(*b"footprint-psk---0123456789abcdef");
        c.probation = Some(Duration::ZERO);
        // As the measurement the bound was set from (`scale` in
        // benches/session.rs).
        c.scheduler = Policy::Affinity;
        Arc::new(c)
    });
    C.clone()
}

fn core_rows() {
    let n = 1000;
    let config = Arc::new(Config::default());
    let now = Instant::now();
    let before = live();
    let mut v = Vec::with_capacity(n);
    for _ in 0..n {
        let mut s =
            core::SessionCore::new(config.clone(), RoleConfig::Initiator, None, now).unwrap();
        s.attach_pipe(PipeId(0), Framing::ByteStream, now);
        v.push(s);
    }
    CORE.check((live() - before) as f64 / n as f64);
    drop(v);

    let mut config = Config::default();
    config.max_incoming_streams = 20_000;
    let mut p = core_pair::CorePair::new(config.clone(), config);
    let (mut opened, mut accepted) = (Vec::with_capacity(10_000), Vec::with_capacity(10_000));
    let before = live();
    // As `idle-core` in benches/session.rs: 10 000 attempts.
    for _ in 0..10_000 {
        match p.a.open(Dir::Bidi) {
            Ok(k) => {
                p.a.stream_id(k).unwrap();
                opened.push(k);
            }
            Err(_) => {
                p.pump();
            }
        }
        if opened.len() % 200 == 0 {
            p.pump();
            while let Ok(Some(k)) = p.b.accept(Dir::Bidi) {
                accepted.push(k);
            }
        }
    }
    p.pump();
    while let Ok(Some(k)) = p.b.accept(Dir::Bidi) {
        accepted.push(k);
    }
    STREAM.check((live() - before) as f64 / (opened.len() + accepted.len()) as f64);
}

async fn tcp_pair(l: &tokio::net::TcpListener) -> (PipeIo, PipeIo) {
    let addr = l.local_addr().unwrap();
    let (a, b) = tokio::join!(tokio::net::TcpStream::connect(addr), l.accept());
    (PipeIo::tcp(a.unwrap()), PipeIo::tcp(b.unwrap().0))
}

/// Idle single-pipe session pairs over in-memory pipes or loopback TCP.
async fn pairs(n: usize, tcp: Option<&tokio::net::TcpListener>) -> Vec<(Session, Session)> {
    let mut v = Vec::with_capacity(n);
    for _ in 0..n {
        let (a, b) = match tcp {
            Some(l) => tcp_pair(l).await,
            None => {
                let (a, b) = tokio::io::duplex(1 << 20);
                (PipeIo::new(a), PipeIo::new(b))
            }
        };
        let server = tokio::spawn(Session::accept(b, config()));
        let client = Session::connect(a, config()).await.unwrap();
        v.push((client, server.await.unwrap().unwrap()));
    }
    v
}

/// The heap per idle pair of `make`'s sessions, after a warm-up (the
/// runtime's and the read pool's process-wide state is not theirs) and
/// after the idle pipes gave their buffers back.
async fn per_pair<F, Fut, T>(n: usize, settle: Duration, make: F) -> f64
where
    F: Fn(usize) -> Fut,
    Fut: std::future::Future<Output = Vec<T>>,
{
    let warm = make(n).await;
    tokio::time::sleep(Duration::from_millis(1500)).await;
    drop(warm);
    quiesce().await;
    let before = live();
    let v = make(n).await;
    still(settle).await;
    let heap = (live() - before) as f64 / n as f64;
    drop(v);
    quiesce().await;
    heap
}

/// Waits `at_least`, then until the heap is still: idle timers that free
/// buffers fire at slightly different times run to run, and a measurement
/// taken while some of them are still due varies by their buffers.
async fn still(at_least: Duration) {
    tokio::time::sleep(at_least).await;
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut last = live();
    loop {
        tokio::time::sleep(Duration::from_millis(200)).await;
        let now = live();
        if now == last || Instant::now() >= deadline {
            return;
        }
        last = now;
    }
}

/// Waits until every session of the process is gone (closing sessions
/// free their state over their linger time) and the heap is still.
async fn quiesce() {
    let deadline = Instant::now() + Duration::from_secs(20);
    while zmux::test_hooks::resources().sessions > 0 {
        assert!(Instant::now() < deadline, "sessions did not end");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let mut last = live();
    loop {
        tokio::time::sleep(Duration::from_millis(100)).await;
        let now = live();
        if now == last {
            return;
        }
        last = now;
    }
}

/// Multipath session pairs over in-memory pipes: the bootstrap pipe and a
/// standby pipe pair joined through a listener.
async fn mp_pairs(
    listener: &Listener,
    n: usize,
    tcp: Option<&tokio::net::TcpListener>,
) -> Vec<(Session, Session)> {
    let carriers = async || match tcp {
        Some(l) => tcp_pair(l).await,
        None => {
            let (a, b) = tokio::io::duplex(64 * 1024);
            (PipeIo::new(a), PipeIo::new(b))
        }
    };
    let mut v = Vec::with_capacity(n);
    for _ in 0..n {
        let (a, b) = carriers().await;
        let l = listener.clone();
        tokio::spawn(async move { l.handle_pipe(b, PipeHint::default()).await });
        let client = Session::connect(a, mp_config()).await.unwrap();
        let server = listener.accept().await.unwrap();
        let (c, d) = carriers().await;
        let l = listener.clone();
        tokio::spawn(async move { l.handle_pipe(d, PipeHint::default()).await });
        let mut opts = PipeOptions::default();
        opts.send_standby = Some(true);
        opts.receive_standby = true;
        client.add_pipe(c, opts).unwrap();
        v.push((client, server));
    }
    let active = |x: &Session| {
        x.pipe_stats()
            .iter()
            .filter(|i| i.outbound == Some(PipeState::Active))
            .count()
    };
    let deadline = Instant::now() + Duration::from_secs(30);
    for (c, s) in &v {
        while active(c) < 2 || active(s) < 2 {
            let _ = tokio::time::timeout(Duration::from_millis(50), c.ping()).await;
            assert!(Instant::now() < deadline, "standby pipes did not join");
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    }
    v
}

#[test]
#[cfg_attr(debug_assertions, ignore = "release builds only")]
fn idle_footprint_stays_within_its_bounds_and_baselines() {
    core_rows();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        // Idle pipes free their read and write buffers after a second.
        let idle = Duration::from_millis(1500);
        PAIR_MEMORY.check(per_pair(200, idle, |n| pairs(n, None)).await);
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        PAIR_TCP.check(per_pair(200, idle, |n| pairs(n, Some(&l))).await);
        // Quiet-session probing ends 15 s after the join.
        // Each round with its own listener, made before it is measured.
        let warm = Listener::new(mp_config(), ListenerConfig::default());
        let v = mp_pairs(&warm, 200, None).await;
        tokio::time::sleep(idle).await;
        drop((v, warm));
        quiesce().await;
        let listener = Listener::new(mp_config(), ListenerConfig::default());
        let before = live();
        let v = mp_pairs(&listener, 200, None).await;
        // Quiet-session probing ends 15 s after the join.
        still(Duration::from_secs(16)).await;
        MULTIPATH.check((live() - before) as f64 / v.len() as f64);
    });
}
