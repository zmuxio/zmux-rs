//! Session benchmarks of the stated targets: bulk throughput (core only,
//! TCP loopback), small-message latency (idle, and under a bulk transfer),
//! allocations per frame, idle memory, and the multipath spread over 2 and
//! 4 TCP loopback pipes. Run with `cargo bench --bench session [--
//! <filter>]` (`core-bulk`, `tcp-bulk`, `rr-under-bulk`, `latency`, `idle`,
//! `mp-spread`; `scale`, `wan-bulk`, `wake` and the churn `soak` only when
//! named); each line is one result, and `mp-spread` ends with a table.
//! `ZMUX_BENCH_SPLIT=1` splits `rr-under-bulk` into the forward and back
//! delays. `latency` and `rr-under-bulk` first report the host's
//! cross-thread wake-up round trip (`wake`).

#![allow(missing_docs, unsafe_code)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering::Relaxed};
use std::time::{Duration, Instant};

use bytes::Bytes;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use zmux::proto::frame::Dir;
use zmux::proto::record::Framing;
use zmux::proto::session::{self as core, PipeId, RoleConfig};
use zmux::{
    Config, Listener, ListenerConfig, PipeAuth, PipeHint, PipeIo, PipeOptions, PipeState, Policy,
    Session, SessionStats,
};

static BASE: std::sync::LazyLock<Instant> = std::sync::LazyLock::new(Instant::now);

struct Counting;

static ALLOCS: AtomicU64 = AtomicU64::new(0);
static LIVE: AtomicI64 = AtomicI64::new(0);
/// The largest `LIVE` since the last [`reset_peak`].
static PEAK: AtomicI64 = AtomicI64::new(0);

fn grow(by: i64) {
    let now = LIVE.fetch_add(by, Relaxed) + by;
    PEAK.fetch_max(now, Relaxed);
}

// SAFETY: forwards to the system allocator unchanged.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        ALLOCS.fetch_add(1, Relaxed);
        grow(l.size() as i64);
        // SAFETY: forwarded unchanged.
        unsafe { System.alloc(l) }
    }

    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        LIVE.fetch_sub(l.size() as i64, Relaxed);
        // SAFETY: forwarded unchanged.
        unsafe { System.dealloc(p, l) }
    }

    unsafe fn realloc(&self, p: *mut u8, l: Layout, n: usize) -> *mut u8 {
        ALLOCS.fetch_add(1, Relaxed);
        grow(n as i64 - l.size() as i64);
        // SAFETY: forwarded unchanged.
        unsafe { System.realloc(p, l, n) }
    }
}

#[global_allocator]
static GLOBAL: Counting = Counting;

const P0: PipeId = PipeId(0);

fn gbps(bytes: u64, d: Duration) -> f64 {
    bytes as f64 / d.as_secs_f64() / 1e9
}

// ---- core only -------------------------------------------------------------------

#[path = "../tests/common/core_pair.rs"]
mod core_pair;

/// Two cores in memory ([`core_pair::CorePair`]) with the time spent on the
/// return path (B writing, A reading: the acknowledgements and credit of a
/// transfer from A), its batches, and the bytes of them.
struct CorePair {
    pair: core_pair::CorePair,
    back: Duration,
    back_batches: u64,
    back_bytes: u64,
}

impl std::ops::Deref for CorePair {
    type Target = core_pair::CorePair;

    fn deref(&self) -> &Self::Target {
        &self.pair
    }
}

impl std::ops::DerefMut for CorePair {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.pair
    }
}

impl CorePair {
    fn new() -> Self {
        // Unidirectional streams at once (no lazy credit).
        let mut config = Config::default();
        config.max_incoming_uni_streams = Some(256);
        Self::with(config)
    }

    fn with(config: Config) -> Self {
        Self {
            pair: core_pair::CorePair::new(config.clone(), config),
            back: Duration::ZERO,
            back_batches: 0,
            back_bytes: 0,
        }
    }

    fn pump(&mut self) {
        loop {
            let forth = self.pair.send(true);
            let t = Instant::now();
            let (mut batches, mut bytes) = (0, 0);
            let back = self.pair.send_with(false, |w| {
                batches += 1;
                bytes += w.len() as u64;
            });
            self.back += t.elapsed();
            self.back_batches += batches;
            self.back_bytes += bytes;
            self.pair.drain_events();
            if forth + back == 0 {
                return;
            }
        }
    }
}

/// Bulk transfer between two cores in memory: the protocol cost alone.
fn core_bulk(zero_copy: bool) {
    let mut p = CorePair::new();
    let send = p.a.open(Dir::Uni).unwrap();
    let data = [5u8; 64 * 1024];
    let shared = Bytes::from(vec![5u8; 1 << 20]);
    let _keep = shared.clone();
    let mut sink = vec![0u8; 256 * 1024];
    let mut recv = None;
    let mut run = |total: u64, p: &mut CorePair| {
        let (mut written, mut read) = (0u64, 0u64);
        while read < total {
            while written < total {
                let n = if zero_copy {
                    p.a.write_chunk(send, shared.clone()).unwrap()
                } else {
                    p.a.write(send, &data).unwrap()
                };
                if n == 0 {
                    break;
                }
                written += n as u64;
            }
            p.pump();
            let k = *recv.get_or_insert_with(|| p.b.accept(Dir::Uni).unwrap().unwrap());
            while let Some((n, _)) = p.b.read(k, &mut sink).unwrap() {
                if n == 0 {
                    break;
                }
                read += n as u64;
            }
            p.pump();
        }
        read
    };
    run(256 << 20, &mut p);
    let allocs = ALLOCS.load(Relaxed);
    let records = p.a.stats().records_sent;
    let (back, back_batches, back_bytes) = (p.back, p.back_batches, p.back_bytes);
    let t = Instant::now();
    let total = run(8 << 30, &mut p);
    let d = t.elapsed();
    let allocs = ALLOCS.load(Relaxed) - allocs;
    let records = p.a.stats().records_sent - records;
    let back = p.back - back;
    let back_batches = p.back_batches - back_batches;
    let gb = total as f64 / 1e9;
    println!(
        "RESULT scen=core-bulk path={} GBps={:.2} records={} allocs_per_frame={:.4} return_path_ms_per_GB={:.2} return_batches_per_GB={:.0} return_bytes_per_GB={:.0} return_ns_per_batch={:.0}",
        if zero_copy { "zero-copy" } else { "copy" },
        gbps(total, d),
        records,
        allocs as f64 / records as f64,
        back.as_secs_f64() * 1e3 / gb,
        back_batches as f64 / gb,
        (p.back_bytes - back_bytes) as f64 / gb,
        back.as_nanos() as f64 / back_batches.max(1) as f64,
    );
    // A timer wake-up that finds nothing due: its fixed cost (the limiter
    // paces in quanta of at most 1000 wake-ups a second, SCHEDULER 9.1).
    let n = 100_000;
    let t = Instant::now();
    for i in 0..n {
        let at = p.now + Duration::from_nanos(i);
        std::hint::black_box(p.a.poll_timeout());
        p.a.handle_timeout(at);
    }
    println!(
        "RESULT scen=core-timer path={} ns_per_timer_wakeup={:.0}",
        if zero_copy { "zero-copy" } else { "copy" },
        t.elapsed().as_nanos() as f64 / n as f64
    );
}

// ---- drivers ---------------------------------------------------------------------------

async fn tcp_pair() -> (TcpStream, TcpStream) {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let (a, b) = tokio::join!(TcpStream::connect(addr), l.accept());
    (a.unwrap(), b.unwrap().0)
}

/// The bench's configuration, one for every session of the process, as an
/// application with many sessions shares it (`Arc<Config>`).
fn shared_config() -> Arc<Config> {
    static CONFIG: std::sync::LazyLock<Arc<Config>> =
        std::sync::LazyLock::new(|| Arc::new(bench_config()));
    CONFIG.clone()
}

async fn session_pair(tcp: bool) -> (Session, Session) {
    let (pa, pb) = if tcp {
        let (a, b) = tcp_pair().await;
        (PipeIo::tcp(a), PipeIo::tcp(b))
    } else {
        let (a, b) = tokio::io::duplex(1 << 20);
        (PipeIo::new(a), PipeIo::new(b))
    };
    let server = tokio::spawn(Session::accept(pb, shared_config()));
    let client = Session::connect(pa, shared_config()).await.unwrap();
    (client, server.await.unwrap().unwrap())
}

/// TLS 1.3 over loopback TCP with a self-signed certificate: a carrier
/// without the TCP capabilities (no kernel RTT, no low-water mark).
async fn tls_pair() -> (
    tokio_rustls::client::TlsStream<TcpStream>,
    tokio_rustls::server::TlsStream<TcpStream>,
) {
    use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert_der = cert.cert.der().clone();
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()));
    let server = rustls::ServerConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der.clone()], key)
        .unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert_der).unwrap();
    let client = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let (a, b) = tcp_pair().await;
    a.set_nodelay(true).unwrap();
    b.set_nodelay(true).unwrap();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(client));
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server));
    let name = ServerName::try_from("localhost").unwrap();
    let (c, s) = tokio::join!(connector.connect(name, a), acceptor.accept(b));
    (c.unwrap(), s.unwrap())
}

/// `ZMUX_BENCH_SHAPE=<Mbit/s>,<one-way ms>[,<queue MiB>]`: the path of
/// the `shaped` carrier (default queue: 2 x the bandwidth-delay product).
fn shape() -> (f64, Duration, usize) {
    let v = std::env::var("ZMUX_BENCH_SHAPE").unwrap_or_else(|_| "10000,50".into());
    let f: Vec<f64> = v.split(',').map(|x| x.trim().parse().unwrap()).collect();
    let rate = f[0] * 1e6 / 8.0;
    let owd = Duration::from_secs_f64(f[1] / 1e3);
    let queue = f
        .get(2)
        .map_or(2.0 * rate * 2.0 * owd.as_secs_f64(), |m| m * 1048576.0);
    (rate, owd, queue as usize)
}

/// One direction of the `shaped` carrier: a bottleneck of `rate` bytes per
/// second with a FIFO of at most `queue` bytes, then `owd` of propagation.
/// It reads eagerly while its queue has room, so the sender's TCP below
/// stays empty: like a deep router buffer behind the link, the queue is
/// invisible to the sender's carrier.
async fn delay_line(
    mut src: tokio::net::tcp::OwnedReadHalf,
    mut dst: tokio::net::tcp::OwnedWriteHalf,
    rate: f64,
    owd: Duration,
    queue: usize,
) {
    let held = Arc::new(AtomicU64::new(0));
    let room = Arc::new(tokio::sync::Notify::new());
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<(Instant, Vec<u8>)>();
    let (h, r) = (held.clone(), room.clone());
    let writer = tokio::spawn(async move {
        while let Some((at, v)) = rx.recv().await {
            tokio::time::sleep_until(at.into()).await;
            if dst.write_all(&v).await.is_err() {
                return;
            }
            h.fetch_sub(v.len() as u64, Relaxed);
            r.notify_one();
        }
        let _ = dst.shutdown().await;
    });
    let mut last = Instant::now();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        while held.load(Relaxed) as usize > queue {
            room.notified().await;
        }
        let n = match src.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        let now = Instant::now();
        last = last.max(now) + Duration::from_secs_f64(n as f64 / rate);
        held.fetch_add(n as u64, Relaxed);
        if tx.send((last + owd, buf[..n].to_vec())).is_err() {
            break;
        }
    }
    drop(tx);
    let _ = writer.await;
}

/// Two TCP loopback carriers joined by a user-space shaper of
/// [`shape`] (both directions): a long fat path where `tc netem` is not
/// available. The endpoints see plain byte streams: no kernel RTT of the
/// path and no low-water mark that would reflect the shaper's queue.
async fn shaped_pair() -> (TcpStream, TcpStream) {
    let (rate, owd, queue) = shape();
    let (a, ra) = tcp_pair().await;
    let (rb, b) = tcp_pair().await;
    for s in [&a, &ra, &rb, &b] {
        s.set_nodelay(true).unwrap();
    }
    let (ra_r, ra_w) = ra.into_split();
    let (rb_r, rb_w) = rb.into_split();
    tokio::spawn(delay_line(ra_r, rb_w, rate, owd, queue));
    tokio::spawn(delay_line(rb_r, ra_w, rate, owd, queue));
    (a, b)
}

/// A session pair over the named carrier: `tcp`, `tls`, `unix`, `mem` or
/// `shaped` ([`shaped_pair`]).
async fn carrier_pair(carrier: &str) -> (Session, Session) {
    let (pa, pb) = match carrier {
        "shaped" => {
            let (a, b) = shaped_pair().await;
            (PipeIo::new(a), PipeIo::new(b))
        }
        "tcp" => return session_pair(true).await,
        "mem" => return session_pair(false).await,
        "unix" => {
            let (a, b) = tokio::net::UnixStream::pair().unwrap();
            (PipeIo::new(a), PipeIo::new(b))
        }
        "tls" => {
            let (a, b) = tls_pair().await;
            (PipeIo::new(a), PipeIo::new(b))
        }
        other => panic!("unknown carrier {other}"),
    };
    let server = tokio::spawn(Session::accept(pb, shared_config()));
    let client = Session::connect(pa, shared_config()).await.unwrap();
    (client, server.await.unwrap().unwrap())
}

/// The default configuration; `ZMUX_BENCH_B=<us>` overrides the auto-tuning
/// latency budget for experiments, and `ZMUX_BENCH_MP=1` makes the session
/// a multipath one on its single pipe, whose carrier queue limiter paces
/// carriers without a low-water mark.
fn bench_config() -> Config {
    let mut c = Config::default();
    if std::env::var("ZMUX_BENCH_MP").is_ok() {
        c.max_pipes = 2;
        c.pipe_auth = PipeAuth::psk(*b"0123456789abcdef0123456789abcdef");
    }
    if let Some(us) = std::env::var("ZMUX_BENCH_B")
        .ok()
        .and_then(|v| v.parse().ok())
    {
        c.latency_budget = Duration::from_micros(us);
    }
    if let Some(kib) = std::env::var("ZMUX_BENCH_WMAX")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
    {
        c.max_stream_receive_window = zmux::Cap::Fixed(kib * 1024);
        c.initial_stream_receive_window = c.initial_stream_receive_window.min(kib * 1024);
    }
    c
}

/// One stream, 64 KiB writes, the receiver reading into a buffer.
async fn driver_bulk(zero_copy: bool) {
    let (client, server) = session_pair(true).await;
    let total: u64 = 8 << 30;
    let reader = tokio::spawn(async move {
        let mut r = server.accept_uni().await.unwrap();
        let mut buf = vec![0u8; 256 * 1024];
        let mut n = 0u64;
        while let Some(k) = r.read(&mut buf).await.unwrap() {
            n += k as u64;
        }
        (n, server)
    });
    let mut s = client.open_uni().await.unwrap();
    let data = vec![1u8; 64 * 1024];
    let chunk = Bytes::from(data.clone());
    let _keep = chunk.clone();
    // Warm up, then measure.
    let warm = 256u64 << 20;
    let mut sent = 0u64;
    let mut t = Instant::now();
    let mut allocs = 0;
    let mut records = 0;
    let mut cpu0 = None;
    while sent < total + warm {
        if sent == warm {
            t = Instant::now();
            cpu0 = cpu_secs();
            allocs = ALLOCS.load(Relaxed);
            records = client.stats().records_sent;
        }
        if zero_copy {
            s.write_chunk(chunk.clone()).await.unwrap();
        } else {
            s.write_all(&data).await.unwrap();
        }
        sent += data.len() as u64;
    }
    s.finish().unwrap();
    let (n, _server) = reader.await.unwrap();
    let d = t.elapsed();
    let cpu = cpu0
        .zip(cpu_secs())
        .map(|(a, b)| (b - a) / (total as f64 / 1e9));
    let allocs = ALLOCS.load(Relaxed) - allocs;
    let records = client.stats().records_sent - records;
    assert_eq!(n, total + warm);
    println!(
        "RESULT scen=bulk carrier=tcp path={} GBps={:.2} Gbps={:.1} cpu_s_per_GB={} allocs_per_frame={:.4}",
        if zero_copy { "zero-copy" } else { "copy" },
        gbps(total, d),
        gbps(total, d) * 8.0,
        cpu.map_or("-".into(), |c| format!("{c:.3}")),
        allocs as f64 / records.max(1) as f64
    );
}

/// One stream over the `shaped` carrier for `ZMUX_BENCH_SECS` seconds
/// (default 20): throughput per second, the mean of the last 5 s, and the
/// time to 90 % of the link (the long-path rows of CONFORMANCE.md).
async fn wan_bulk() {
    let (rate, owd, queue) = shape();
    let secs: u64 = std::env::var("ZMUX_BENCH_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(20);
    let (client, server) = carrier_pair("shaped").await;
    let counted = Arc::new(AtomicU64::new(0));
    let stop = Arc::new(AtomicBool::new(false));
    let c = counted.clone();
    let receiver = server.clone();
    let reader = tokio::spawn(async move {
        let mut r = server.accept_uni().await.unwrap();
        let mut buf = vec![0u8; 256 * 1024];
        while let Ok(Some(k)) = r.read(&mut buf).await {
            c.fetch_add(k as u64, Relaxed);
        }
        server
    });
    let st = stop.clone();
    let cl = client.clone();
    let writer = tokio::spawn(async move {
        let mut s = cl.open_uni().await.unwrap();
        let chunk = Bytes::from(vec![1u8; 64 * 1024]);
        while !st.load(Relaxed) {
            if s.write_chunk(chunk.clone()).await.is_err() {
                return;
            }
        }
        let _ = s.finish();
    });
    let t0 = Instant::now();
    let cpu0 = cpu_secs();
    let mut per_sec = Vec::new();
    let mut prev = 0;
    for _ in 0..secs {
        tokio::time::sleep_until((t0 + Duration::from_secs(per_sec.len() as u64 + 1)).into()).await;
        let now = counted.load(Relaxed);
        per_sec.push((now - prev) as f64 * 8.0 / 1e9);
        prev = now;
        if std::env::var("ZMUX_BENCH_TRACE").is_ok()
            && let Some(i) = client.pipe_stats().first()
        {
            println!(
                "TRACE t={} rate_Mbps={:?} srtt={:?} min_rtt={:?} in_flight={:?} writable={}",
                per_sec.len(),
                i.delivery_rate.map(|r| r * 8 / 1_000_000),
                i.smoothed_rtt,
                i.min_rtt,
                i.bytes_in_flight,
                i.writable
            );
        }
    }
    let cpu = cpu0
        .zip(cpu_secs())
        .map(|(a, b)| (b - a) / (prev as f64 / 1e9));
    stop.store(true, Relaxed);
    let link = rate * 8.0 / 1e9;
    let last: f64 = per_sec.iter().rev().take(5).sum::<f64>() / per_sec.len().min(5) as f64;
    let to90 = per_sec.iter().position(|&g| g >= 0.9 * link).map(|i| i + 1);
    println!(
        "RESULT scen=wan-bulk link_Gbps={link:.2} owd_ms={} queue_MB={:.0} per_s_Gbps={:?} last5_Gbps={last:.2} last5_pct={:.1} to90_s={} cpu_s_per_GB={} recv_window_growth_MB={:.1}",
        owd.as_millis(),
        queue as f64 / 1e6,
        per_sec
            .iter()
            .map(|g| (g * 100.0).round() / 100.0)
            .collect::<Vec<_>>(),
        last * 100.0 / link,
        to90.map_or("-".into(), |s| s.to_string()),
        cpu.map_or("-".into(), |c| format!("{c:.3}")),
        receiver.window_growth() as f64 / 1e6,
    );
    client.close(zmux::VarInt::from_u32(0), b"");
    let _ = writer.await;
    let _ = reader.await;
}

/// `scale`: `ZMUX_BENCH_SCALE_N` (default 10 000) quiet sessions over
/// in-memory pipes, single-pipe and multipath (two pipe pairs, the second
/// standby), both ends in this process (CONFORMANCE.md scale rows): live heap
/// per session (both ends, the
/// in-memory pipes' buffers included), then the process CPU over
/// `ZMUX_BENCH_SCALE_SECS` (default 30) of silence, as a share of one core.
/// No idle timeout and no keep-alive, as the measurement method says;
/// `ZMUX_BENCH_SCALE_KEEPALIVE=<s>` adds keep-alive.
async fn scale(multipath: bool) {
    let n: usize = std::env::var("ZMUX_BENCH_SCALE_N")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(10_000);
    let secs: u64 = std::env::var("ZMUX_BENCH_SCALE_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(30);
    let keep_alive = std::env::var("ZMUX_BENCH_SCALE_KEEPALIVE")
        .ok()
        .and_then(|v| v.parse().ok())
        .map(Duration::from_secs);
    let config = || {
        let mut c = if multipath {
            mp_config(&Policy::Affinity)
        } else {
            Config::default()
        };
        c.max_idle_timeout = Duration::ZERO;
        c.keep_alive_period = keep_alive;
        c
    };
    if !multipath && std::env::var("ZMUX_BENCH_SCALE_DUPLEX").is_ok() {
        // The in-memory pipes alone, after a handshake's worth of bytes.
        let before = live();
        let mut v = Vec::with_capacity(n);
        for _ in 0..n {
            let (mut a, mut b) = tokio::io::duplex(64 * 1024);
            let mut buf = [0u8; 512];
            a.write_all(&[1u8; 300]).await.unwrap();
            b.read_exact(&mut buf[..300]).await.unwrap();
            b.write_all(&[1u8; 300]).await.unwrap();
            a.read_exact(&mut buf[..300]).await.unwrap();
            v.push((a, b));
        }
        println!(
            "RESULT scen=scale-duplex heap_B_per_pipe_pair={:.0}",
            (live() - before) as f64 / n as f64
        );
    }
    // One configuration for every session, as an application with many
    // sessions shares it.
    let shared = Arc::new(config());
    let config = || shared.clone();
    let listener = multipath.then(|| Listener::new(config(), ListenerConfig::default()));
    let before = live();
    let mut pairs = Vec::with_capacity(n);
    for _ in 0..n {
        let (a, b) = tokio::io::duplex(64 * 1024);
        let (client, server) = match &listener {
            None => {
                let server = tokio::spawn(Session::accept(PipeIo::new(b), config()));
                let client = Session::connect(PipeIo::new(a), config()).await.unwrap();
                (client, server.await.unwrap().unwrap())
            }
            Some(l) => {
                let l2 = l.clone();
                tokio::spawn(
                    async move { l2.handle_pipe(PipeIo::new(b), PipeHint::default()).await },
                );
                let client = Session::connect(PipeIo::new(a), config()).await.unwrap();
                let server = l.accept().await.unwrap();
                let (c, d) = tokio::io::duplex(64 * 1024);
                let l2 = l.clone();
                tokio::spawn(
                    async move { l2.handle_pipe(PipeIo::new(d), PipeHint::default()).await },
                );
                let mut opts = PipeOptions::default();
                opts.send_standby = Some(true);
                opts.receive_standby = true;
                client.add_pipe(PipeIo::new(c), opts).unwrap();
                (client, server)
            }
        };
        pairs.push((client, server));
    }
    if multipath {
        // Every standby pipe active at both ends.
        let deadline = Instant::now() + Duration::from_secs(60);
        for (c, s) in &pairs {
            let active = |x: &Session| {
                x.pipe_stats()
                    .iter()
                    .filter(|i| i.outbound == Some(PipeState::Active))
                    .count()
            };
            while active(c) < 2 || active(s) < 2 {
                // Joins are confirmed by the peer's first record.
                let _ = tokio::time::timeout(Duration::from_millis(50), c.ping()).await;
                assert!(Instant::now() < deadline, "standby pipes did not join");
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        }
    }
    // Transient buffers go back (idle pipes release theirs after a second;
    // the busy window of quiet-session probing is 15 s).
    tokio::time::sleep(Duration::from_secs(16)).await;
    let heap = (live() - before) as f64 / n as f64;
    let records = |p: &[(Session, Session)]| -> u64 {
        p.iter()
            .map(|(c, s)| c.stats().records_sent + s.stats().records_sent)
            .sum()
    };
    let r0 = records(&pairs);
    let (t0, cpu0) = (Instant::now(), cpu_secs());
    tokio::time::sleep(Duration::from_secs(secs)).await;
    let cpu = cpu0
        .zip(cpu_secs())
        .map(|(a, b)| (b - a) / t0.elapsed().as_secs_f64() * 100.0);
    let quiet = (records(&pairs) - r0) as f64 / t0.elapsed().as_secs_f64() / n as f64;
    println!(
        "RESULT scen=scale kind={} sessions={n} heap_B_per_session_both_ends={heap:.0} quiet_cpu_pct_of_one_core={} quiet_records_per_s_per_session={quiet:.3} keep_alive={:?}",
        if multipath {
            "multipath-2pairs-standby"
        } else {
            "single-pipe"
        },
        cpu.map_or("-".into(), |c| format!("{c:.3}")),
        keep_alive,
    );
    for (c, _) in &pairs {
        c.close(zmux::VarInt::from_u32(0), b"");
    }
    drop(pairs);
    // The next measurement starts once these sessions are gone: closing
    // ones free their state over their linger time, which would otherwise
    // be subtracted from the next one's.
    while zmux::test_hooks::resources().sessions > 0 {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    tokio::time::sleep(Duration::from_millis(500)).await;
}

/// The carrier alone: TCP loopback with 64 KiB writes.
async fn raw_tcp_bulk() {
    let (mut a, mut b) = tcp_pair().await;
    let total: u64 = 8 << 30;
    let reader = tokio::spawn(async move {
        let mut buf = vec![0u8; 256 * 1024];
        let mut n = 0u64;
        loop {
            let k = b.read(&mut buf).await.unwrap();
            if k == 0 {
                break;
            }
            n += k as u64;
        }
        n
    });
    let data = vec![1u8; 64 * 1024];
    let t = Instant::now();
    let cpu0 = cpu_secs();
    let mut sent = 0u64;
    while sent < total {
        a.write_all(&data).await.unwrap();
        sent += data.len() as u64;
    }
    a.shutdown().await.unwrap();
    assert_eq!(reader.await.unwrap(), total);
    let cpu = cpu0
        .zip(cpu_secs())
        .map(|(a, b)| (b - a) / (total as f64 / 1e9));
    println!(
        "RESULT scen=bulk carrier=tcp path=raw GBps={:.2} Gbps={:.1} cpu_s_per_GB={}",
        gbps(total, t.elapsed()),
        gbps(total, t.elapsed()) * 8.0,
        cpu.map_or("-".into(), |c| format!("{c:.3}"))
    );
}

/// Request-response latency: 64-byte messages, one at a time, each on a
/// new stream (open, write, FIN; echo; read to end).
async fn latency(msg: usize, new_stream: bool) {
    let (client, server) = session_pair(true).await;
    let echo = tokio::spawn(async move {
        if new_stream {
            while let Ok((mut s, mut r)) = server.accept_bi().await {
                let data = r.read_to_end(1 << 20).await.unwrap();
                s.write_all(&data).await.unwrap();
                s.finish().unwrap();
            }
        } else {
            let (mut s, mut r) = server.accept_bi().await.unwrap();
            let mut buf = vec![0u8; msg];
            while r.read_exact(&mut buf).await.is_ok() {
                s.write_all(&buf).await.unwrap();
            }
        }
    });
    let data = vec![3u8; msg];
    let mut samples = Vec::with_capacity(20_000);
    let mut persistent = if new_stream {
        None
    } else {
        Some(client.open_bi().await.unwrap())
    };
    let mut buf = vec![0u8; msg];
    let allocs = ALLOCS.load(Relaxed);
    let total_start = Instant::now();
    let rounds = 20_000;
    for _ in 0..rounds {
        let t = Instant::now();
        match &mut persistent {
            None => {
                let (mut s, mut r) = client.open_bi().await.unwrap();
                s.write_all(&data).await.unwrap();
                s.finish().unwrap();
                let back = r.read_to_end(1 << 20).await.unwrap();
                assert_eq!(back.len(), msg);
            }
            Some((s, r)) => {
                s.write_all(&data).await.unwrap();
                r.read_exact(&mut buf).await.unwrap();
            }
        }
        samples.push(t.elapsed());
    }
    let elapsed = total_start.elapsed();
    let allocs = ALLOCS.load(Relaxed) - allocs;
    samples.sort();
    let p = |q: f64| {
        samples[((samples.len() as f64 * q) as usize).min(samples.len() - 1)].as_secs_f64() * 1e6
    };
    println!(
        "RESULT scen=rr msg={msg} stream={} ops_per_s={:.0} p50_us={:.1} p99_us={:.1} p999_us={:.1} allocs_per_op={:.1}",
        if new_stream { "new" } else { "same" },
        rounds as f64 / elapsed.as_secs_f64(),
        p(0.5),
        p(0.99),
        p(0.999),
        allocs as f64 / rounds as f64
    );
    drop(persistent);
    drop(client);
    echo.abort();
}

/// 64-byte requests and responses on one stream while another stream
/// carries bulk data the same way over the same TCP session: the latency of
/// the requests, and the bulk rate against the bulk rate alone
/// (windows must not fill the carrier's
/// buffers).
async fn rr_under_bulk(secs: f64) {
    async fn bulk_rate(
        client: &Session,
        server: &Session,
        secs: f64,
        rr: bool,
    ) -> (f64, Vec<Duration>) {
        let srv = server.clone();
        let reader = tokio::spawn(async move {
            let mut r = srv.accept_uni().await.unwrap();
            let mut buf = vec![0u8; 256 * 1024];
            let mut n = 0u64;
            while let Some(k) = r.read(&mut buf).await.unwrap() {
                n += k as u64;
            }
            n
        });
        let srv = server.clone();
        // Split timing (ZMUX_BENCH_SPLIT): the request carries its send
        // time, the echo records the forward delay and stamps the reply.
        let base = *BASE;
        let fwd = Arc::new(std::sync::Mutex::new(Vec::<Duration>::new()));
        let fwd2 = fwd.clone();
        let echo = tokio::spawn(async move {
            let Ok((mut s, mut r)) = srv.accept_bi().await else {
                return;
            };
            let mut buf = [0u8; 64];
            while r.read_exact(&mut buf).await.is_ok() {
                let now = base.elapsed().as_nanos() as u64;
                let sent = u64::from_le_bytes(buf[..8].try_into().unwrap());
                if sent > 0 {
                    fwd2.lock()
                        .unwrap()
                        .push(Duration::from_nanos(now.saturating_sub(sent)));
                    buf[8..16].copy_from_slice(&base.elapsed().as_nanos().to_le_bytes()[..8]);
                }
                if s.write_all(&buf).await.is_err() {
                    return;
                }
            }
        });
        let mut s = client.open_uni().await.unwrap();
        let chunk = Bytes::from(vec![1u8; 64 * 1024]);
        let stop = Arc::new(AtomicBool::new(false));
        let stop2 = stop.clone();
        let writer = tokio::spawn(async move {
            let mut sent = 0u64;
            let t = Instant::now();
            while !stop2.load(Relaxed) {
                s.write_chunk(chunk.clone()).await.unwrap();
                sent += chunk.len() as u64;
            }
            s.finish().unwrap();
            (sent, t.elapsed())
        });
        let start = Instant::now();
        let mut samples = Vec::new();
        if rr {
            let client = client.clone();
            let fwd = fwd.clone();
            let rr_loop = async move {
                let mut samples = Vec::new();
                let (mut s, mut r) = client.open_bi().await.unwrap();
                let msg = [0u8; 64];
                let mut buf = [0u8; 64];
                // Let the bulk stream fill the pipeline first.
                tokio::time::sleep(Duration::from_millis(200)).await;
                let split = std::env::var("ZMUX_BENCH_SPLIT").is_ok();
                let mut back = Vec::new();
                let mut msg = msg;
                while start.elapsed().as_secs_f64() < secs {
                    let t = Instant::now();
                    if split {
                        msg[..8].copy_from_slice(&(base.elapsed().as_nanos() as u64).to_le_bytes());
                    }
                    s.write_all(&msg).await.unwrap();
                    r.read_exact(&mut buf).await.unwrap();
                    samples.push(t.elapsed());
                    if split {
                        let echoed = u64::from_le_bytes(buf[8..16].try_into().unwrap());
                        let now = base.elapsed().as_nanos() as u64;
                        back.push(Duration::from_nanos(now.saturating_sub(echoed)));
                    }
                }
                if split {
                    let mut f = fwd.lock().unwrap().clone();
                    f.sort();
                    back.sort();
                    let q = |v: &[Duration], x: f64| {
                        v[((v.len() as f64 * x) as usize).min(v.len().saturating_sub(1))]
                            .as_secs_f64()
                            * 1e6
                    };
                    if !f.is_empty() && !back.is_empty() {
                        println!(
                            "SPLIT forward p50_us={:.1} p99_us={:.1} back p50_us={:.1} p99_us={:.1}",
                            q(&f, 0.5),
                            q(&f, 0.99),
                            q(&back, 0.5),
                            q(&back, 0.99)
                        );
                    }
                }
                samples
            };
            // `ZMUX_BENCH_RR_TASK`: the request-response client runs as a
            // runtime task instead of on the thread that blocks on the bench.
            samples = if std::env::var("ZMUX_BENCH_RR_TASK").is_ok() {
                tokio::spawn(rr_loop).await.unwrap()
            } else {
                rr_loop.await
            };
        } else {
            tokio::time::sleep(Duration::from_secs_f64(secs)).await;
        }
        stop.store(true, Relaxed);
        let (sent, d) = writer.await.unwrap();
        let n = reader.await.unwrap();
        assert_eq!(n, sent);
        echo.abort();
        (sent as f64 / d.as_secs_f64() / 1e9, samples)
    }
    // `ZMUX_BENCH_CARRIER`: `tcp` (default), `tls` (TLS over TCP), `unix`
    // (a Unix stream socket) or `mem` (an in-process pipe): the latency
    // target holds whatever the carrier, with zmux's own signals where it
    // offers none.
    let carrier = std::env::var("ZMUX_BENCH_CARRIER").unwrap_or_else(|_| "tcp".into());
    let (client, server) = carrier_pair(&carrier).await;
    // The relative target's terms from the same run: the idle request-response
    // p99 over the same session,
    // the raw TCP one, and the host's wake-up p99.
    let idle = {
        let srv = server.clone();
        let echo = tokio::spawn(async move {
            let (mut s, mut r) = srv.accept_bi().await.unwrap();
            let mut buf = [0u8; 64];
            while r.read_exact(&mut buf).await.is_ok() {
                if s.write_all(&buf).await.is_err() {
                    return;
                }
            }
        });
        let (mut s, mut r) = client.open_bi().await.unwrap();
        let mut buf = [0u8; 64];
        let mut samples = Vec::with_capacity(20_000);
        for _ in 0..20_000 {
            let t = Instant::now();
            s.write_all(&[5u8; 64]).await.unwrap();
            r.read_exact(&mut buf).await.unwrap();
            samples.push(t.elapsed());
        }
        echo.abort();
        samples.sort();
        samples[samples.len() * 99 / 100].as_secs_f64() * 1e6
    };
    let tcp = raw_latency(64).await;
    let q = bench_q();
    let (_, w) = wake_latency(q).await;
    let (alone, _) = bulk_rate(&client, &server, secs, false).await;
    let (with_rr, mut samples) = bulk_rate(&client, &server, secs, true).await;
    samples.sort();
    let p = |q: f64| {
        samples[((samples.len() as f64 * q) as usize).min(samples.len() - 1)].as_secs_f64() * 1e6
    };
    println!(
        "RESULT scen=rr-under-bulk carrier={carrier} msg=64 rounds={} p50_us={:.1} p99_us={:.1} p999_us={:.1} bulk_alone_GBps={:.2} bulk_with_rr_GBps={:.2} ratio={:.2}",
        samples.len(),
        p(0.5),
        p(0.99),
        p(0.999),
        alone,
        with_rr,
        with_rr / alone
    );
    let q_us = q.as_secs_f64() * 1e6;
    let base = idle.min(2.0 * tcp) + w;
    let load = std::fs::read_to_string("/proc/loadavg")
        .ok()
        .and_then(|l| l.split_whitespace().next().map(str::to_owned))
        .unwrap_or_else(|| "-".into());
    let cores = std::thread::available_parallelism().map_or(0, |n| n.get());
    let workers = std::env::var("ZMUX_BENCH_WORKERS").unwrap_or_else(|_| "-".into());
    println!(
        "RESULT scen=at1 carrier={carrier} p99_us={:.1} p99_idle_us={idle:.1} p99_tcp_us={tcp:.1} w_us={w:.1} q_us={q_us:.0} target_us={:.1} gate_us={:.1} pass_target={} pass_gate={} load={load} cores={cores} workers={workers}",
        p(0.99),
        base + 1.9 * q_us,
        base + 2.4 * q_us,
        p(0.99) <= base + 1.9 * q_us,
        p(0.99) <= base + 2.4 * q_us,
    );
}

/// Raw TCP request-response, the carrier's own latency.
/// The host's wake-up p99 `w` of the relative latency target: the thread that
/// blocks on the bench (where
/// the request-response client runs) and a runtime task (where the echo
/// runs) take turns through a `Notify` each way; the side that holds the
/// turn spins for 2 x `q`, reads the clock and wakes the other, which reads
/// the clock as soon as it runs. `ZMUX_BENCH_WAKE_N` wake-ups (default
/// 100 000). Returns the p50 and p99 in microseconds.
async fn wake_latency(q: Duration) -> (f64, f64) {
    use tokio::sync::Notify;
    let n: usize = std::env::var("ZMUX_BENCH_WAKE_N")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(100_000);
    let spin = |d: Duration| {
        let t = Instant::now();
        while t.elapsed() < d {
            std::hint::spin_loop();
        }
    };
    let base = Instant::now();
    let stamp = Arc::new(AtomicU64::new(0));
    let (to_task, to_client) = (Arc::new(Notify::new()), Arc::new(Notify::new()));
    let rounds = n / 2;
    let task = {
        let (stamp, to_task, to_client) = (stamp.clone(), to_task.clone(), to_client.clone());
        tokio::spawn(async move {
            let mut samples = Vec::with_capacity(rounds);
            for _ in 0..rounds {
                to_task.notified().await;
                let woke = base.elapsed().as_nanos() as u64;
                samples.push(woke.saturating_sub(stamp.load(Relaxed)));
                spin(2 * q);
                stamp.store(base.elapsed().as_nanos() as u64, Relaxed);
                to_client.notify_one();
            }
            samples
        })
    };
    let mut samples = Vec::with_capacity(n);
    for _ in 0..rounds {
        spin(2 * q);
        stamp.store(base.elapsed().as_nanos() as u64, Relaxed);
        to_task.notify_one();
        to_client.notified().await;
        let woke = base.elapsed().as_nanos() as u64;
        samples.push(woke.saturating_sub(stamp.load(Relaxed)));
    }
    samples.extend(task.await.unwrap());
    samples.sort_unstable();
    let p =
        |x: f64| samples[((samples.len() as f64 * x) as usize).min(samples.len() - 1)] as f64 / 1e3;
    let (p50, p99) = (p(0.5), p(0.99));
    println!(
        "RESULT scen=wake wakeups={} spin_us={} p50_us={p50:.1} p99_us={p99:.1} p999_us={:.1}",
        samples.len(),
        (2 * q).as_micros(),
        p(0.999)
    );
    (p50, p99)
}

/// The window span Q = max(B, K x RTT_min) of the bench's configuration on
/// loopback: B.
fn bench_q() -> Duration {
    std::env::var("ZMUX_BENCH_B")
        .ok()
        .and_then(|v| v.parse().ok())
        .map(Duration::from_micros)
        .unwrap_or(Config::default().latency_budget)
}

async fn raw_latency(msg: usize) -> f64 {
    let (mut a, mut b) = tcp_pair().await;
    a.set_nodelay(true).unwrap();
    b.set_nodelay(true).unwrap();
    let echo = tokio::spawn(async move {
        let mut buf = vec![0u8; msg];
        while b.read_exact(&mut buf).await.is_ok() {
            b.write_all(&buf).await.unwrap();
        }
    });
    let data = vec![3u8; msg];
    let mut buf = vec![0u8; msg];
    let mut samples = Vec::with_capacity(20_000);
    for _ in 0..20_000 {
        let t = Instant::now();
        a.write_all(&data).await.unwrap();
        a.read_exact(&mut buf).await.unwrap();
        samples.push(t.elapsed());
    }
    samples.sort();
    let p = |q: f64| samples[(samples.len() as f64 * q) as usize].as_secs_f64() * 1e6;
    println!(
        "RESULT scen=rr msg={msg} stream=raw-tcp p50_us={:.1} p99_us={:.1}",
        p(0.5),
        p(0.99)
    );
    drop(a);
    echo.abort();
    p(0.99)
}

// ---- memory -----------------------------------------------------------------------------

fn live() -> i64 {
    LIVE.load(Relaxed)
}

/// Heap held by idle cores and by idle streams in a core.
fn core_memory() {
    let n = 1000;
    // Sessions share their configuration, as a listener's do.
    let config = Arc::new(Config::default());
    let before = live();
    let now = Instant::now();
    let mut v = Vec::with_capacity(n);
    for _ in 0..n {
        let mut s =
            core::SessionCore::new(config.clone(), RoleConfig::Initiator, None, now).unwrap();
        s.attach_pipe(P0, Framing::ByteStream, now);
        v.push(s);
    }
    let per_session = (live() - before) as f64 / n as f64;
    let inline = v[0].memory_usage();
    // Idle streams: opened by the peer, accepted, nothing buffered.
    let mut config = Config::default();
    config.max_incoming_streams = 20_000;
    let mut p = CorePair::with(config);
    let streams = 10_000;
    let mut keys = Vec::with_capacity(streams);
    let mut accepted = Vec::with_capacity(streams);
    let before = live();
    for _ in 0..streams {
        match p.a.open(Dir::Bidi) {
            Ok(k) => {
                p.a.stream_id(k).unwrap();
                keys.push(k);
            }
            Err(_) => {
                p.pump();
            }
        }
        if keys.len() % 200 == 0 {
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
    let per_stream = (live() - before) as f64 / (keys.len() + accepted.len()) as f64;
    println!(
        "RESULT scen=idle-core heap_B_per_session={per_session:.0} core_B_per_session={inline} size_of_session={} heap_B_per_stream_end={per_stream:.0} streams={}",
        size_of::<core::SessionCore>(),
        keys.len()
    );
    drop(v);
}

/// Heap held by idle driver sessions (both ends of an in-memory pipe).
async fn driver_memory() {
    let n = 200;
    // Warm-up: the process-wide state (the runtime's, the pool of read
    // buffers) is not the sessions'.
    let warm: Vec<_> = futures_pairs(n).await;
    tokio::time::sleep(Duration::from_millis(1500)).await;
    drop(warm);
    tokio::time::sleep(Duration::from_millis(50)).await;
    let before = live();
    let mut v = Vec::with_capacity(n);
    for _ in 0..n {
        v.push(session_pair(false).await);
    }
    tokio::time::sleep(Duration::from_millis(50)).await;
    let active = (live() - before) as f64 / n as f64;
    // Idle sessions free their read and write buffers after a second.
    tokio::time::sleep(Duration::from_millis(1500)).await;
    let idle = (live() - before) as f64 / n as f64;
    println!(
        "RESULT scen=idle-driver heap_B_per_session_pair_active={active:.0} heap_B_per_session_pair_idle={idle:.0} (both ends and the in-memory pipe)"
    );
    drop(v);
}

// ---- soak ------------------------------------------------------------------------------

fn env_or<T: std::str::FromStr>(name: &str, default: T) -> T {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

/// The process's resident set (Linux: `/proc/self/statm`), in bytes.
fn rss() -> Option<i64> {
    let statm = std::fs::read_to_string("/proc/self/statm").ok()?;
    let pages: i64 = statm.split_whitespace().nth(1)?.parse().ok()?;
    // SAFETY: sysconf has no preconditions.
    let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    Some(pages * page as i64)
}

/// A seeded xorshift64* generator for the soak's choices.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

#[derive(Default)]
struct SoakCounts {
    sessions: AtomicU64,
    streams: AtomicU64,
    bytes: AtomicU64,
    joins: AtomicU64,
    pipe_failures: AtomicU64,
    errors: AtomicU64,
}

/// The soak's shared state: whether streams run (the idle phases stop
/// them, the sessions stay open), whether the churn is over, and counts.
struct Soak {
    active: AtomicBool,
    stop: AtomicBool,
    counts: SoakCounts,
    /// The open sessions (both ends), by `stable_id`.
    open: std::sync::Mutex<std::collections::HashMap<usize, Session>>,
}

impl Soak {
    /// The open sessions' core memory (`memory_usage`) and held data bytes.
    fn core_bytes(&self) -> (usize, u64) {
        let open = self.open.lock().unwrap();
        open.values().fold((0, 0), |(m, h), s| {
            let t = s.debug_tables();
            (m + t.memory_usage, h + t.held_bytes)
        })
    }

    /// Waits for an active phase; `false` once the churn is over.
    async fn wait_active(&self) -> bool {
        while !self.active.load(Relaxed) {
            if self.stop.load(Relaxed) {
                return false;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        !self.stop.load(Relaxed)
    }
}

/// The server side of a soak session: each bidirectional stream's request
/// is read to its end; small requests are echoed, larger ones answered
/// with their length.
async fn soak_serve(server: Session, soak: Arc<Soak>) {
    while let Ok((mut send, mut recv)) = server.accept_bi().await {
        let soak = soak.clone();
        tokio::spawn(async move {
            let mut n = 0usize;
            let mut small = [0u8; 64];
            loop {
                match recv.read_chunk(64 * 1024).await {
                    Ok(Some(c)) => {
                        if n + c.len() <= small.len() {
                            small[n..n + c.len()].copy_from_slice(&c);
                        }
                        n += c.len();
                    }
                    Ok(None) => break,
                    Err(_) => {
                        soak.counts.errors.fetch_add(1, Relaxed);
                        return;
                    }
                }
            }
            let reply = if n <= small.len() {
                send.write_all(&small[..n]).await
            } else {
                send.write_all(&(n as u64).to_le_bytes()).await
            };
            if reply.is_err() || send.finish().is_err() {
                soak.counts.errors.fetch_add(1, Relaxed);
            }
        });
    }
}

/// One request-response of `len` bytes on a new stream.
async fn soak_exchange(client: &Session, payload: &Bytes, len: usize) -> bool {
    let Ok((mut send, mut recv)) = client.open_bi().await else {
        return false;
    };
    let mut left = len;
    while left > 0 {
        let k = left.min(payload.len());
        if send.write_chunk(payload.slice(..k)).await.is_err() {
            return false;
        }
        left -= k;
    }
    if send.finish().is_err() {
        return false;
    }
    match recv.read_to_end(1024).await {
        Ok(r) => r.len() == if len <= 64 { len } else { 8 },
        Err(_) => false,
    }
}

/// A slot of the soak: session pairs one after the other until the churn
/// ends. Odd slots use multipath sessions, routed by the slot's listener,
/// whose extra pipes join and fail while streams run.
async fn soak_slot(
    slot: u64,
    soak: Arc<Soak>,
    single: Arc<Config>,
    mp: Arc<Config>,
    payload: Bytes,
) {
    let mut rng = Rng(0x9e37_79b9_7f4a_7c15 ^ (slot + 1).wrapping_mul(0x1234_5678_9abc_def1));
    let multipath = slot % 2 == 1;
    let listener = multipath.then(|| Listener::new(mp.clone(), ListenerConfig::default()));
    let workers: usize = env_or("ZMUX_SOAK_STREAMS", 3);
    while soak.wait_active().await {
        let (a, b) = tokio::io::duplex(64 * 1024);
        let (client, server) = match &listener {
            None => {
                let server = tokio::spawn(Session::accept(PipeIo::new(b), single.clone()));
                let Ok(client) = Session::connect(PipeIo::new(a), single.clone()).await else {
                    soak.counts.errors.fetch_add(1, Relaxed);
                    continue;
                };
                let Ok(Ok(server)) = server.await else {
                    soak.counts.errors.fetch_add(1, Relaxed);
                    continue;
                };
                (client, server)
            }
            Some(l) => {
                let l2 = l.clone();
                tokio::spawn(
                    async move { l2.handle_pipe(PipeIo::new(b), PipeHint::default()).await },
                );
                let Ok(client) = Session::connect(PipeIo::new(a), mp.clone()).await else {
                    soak.counts.errors.fetch_add(1, Relaxed);
                    continue;
                };
                let Some(server) = l.accept().await else {
                    return;
                };
                (client, server)
            }
        };
        soak.counts.sessions.fetch_add(1, Relaxed);
        for s in [&client, &server] {
            soak.open.lock().unwrap().insert(s.stable_id(), s.clone());
        }
        let serving = tokio::spawn(soak_serve(server.clone(), soak.clone()));
        // A lifetime of 0.5 to 15 s.
        let life = Duration::from_millis(500 + rng.below(14_500));
        let end = Instant::now() + life;
        let mut tasks = Vec::new();
        for w in 0..workers {
            let client = client.clone();
            let soak = soak.clone();
            let payload = payload.clone();
            let mut rng = Rng(rng.next() | 1);
            tasks.push(tokio::spawn(async move {
                while Instant::now() < end && soak.wait_active().await {
                    // 64 B request-response mostly, 256 KiB often, a few
                    // multi-MiB transfers.
                    let len = match rng.below(100) {
                        0..80 => 64,
                        80..97 => 256 * 1024,
                        _ => (2 + rng.below(4) as usize) << 20,
                    };
                    if soak_exchange(&client, &payload, len).await {
                        soak.counts.streams.fetch_add(1, Relaxed);
                        soak.counts.bytes.fetch_add(len as u64, Relaxed);
                    } else {
                        soak.counts.errors.fetch_add(1, Relaxed);
                        return;
                    }
                    if w == 0 && len == 64 {
                        // Think time: some request-responses come alone.
                        tokio::time::sleep(Duration::from_millis(rng.below(20))).await;
                    }
                }
            }));
        }
        if let Some(l) = &listener {
            // Extra pipes join and fail while the streams run.
            while Instant::now() < end && soak.wait_active().await {
                let (c, d) = tokio::io::duplex(64 * 1024);
                let l2 = l.clone();
                tokio::spawn(
                    async move { l2.handle_pipe(PipeIo::new(d), PipeHint::default()).await },
                );
                match client.add_pipe(PipeIo::new(c), PipeOptions::default()) {
                    Ok(pipe) => {
                        soak.counts.joins.fetch_add(1, Relaxed);
                        tokio::time::sleep(Duration::from_millis(500 + rng.below(3000))).await;
                        if pipe.abort().is_ok() {
                            soak.counts.pipe_failures.fetch_add(1, Relaxed);
                        }
                    }
                    Err(_) => {
                        soak.counts.errors.fetch_add(1, Relaxed);
                    }
                }
                tokio::time::sleep(Duration::from_millis(rng.below(1500))).await;
            }
        }
        for t in tasks {
            let _ = t.await;
        }
        // Some sessions stay open and quiet for a while before they close.
        if rng.below(3) == 0 && !soak.stop.load(Relaxed) {
            tokio::time::sleep(Duration::from_millis(1500 + rng.below(3000))).await;
        }
        for s in [&client, &server] {
            soak.open.lock().unwrap().remove(&s.stable_id());
        }
        client.close(zmux::VarInt::from_u32(0), b"");
        let _ = tokio::time::timeout(Duration::from_secs(5), client.closed()).await;
        server.close(zmux::VarInt::from_u32(0), b"");
        let _ = tokio::time::timeout(Duration::from_secs(5), serving).await;
    }
    if let Some(l) = listener {
        l.close();
    }
}

/// `soak`: a bounded churn of `ZMUX_SOAK_SECS` (default 600) with
/// `ZMUX_SOAK_SLOTS` (default 32) concurrent session slots over in-memory
/// pipes (half single-pipe, half multipath through a listener, with
/// extra pipes joining and failing), `ZMUX_SOAK_STREAMS` (default 3)
/// streams at a time per session of mixed sizes (64 B request-response,
/// 256 KiB, 2 to 5 MiB), and cycles of `ZMUX_SOAK_ACTIVE` s (default 40)
/// of streams and `ZMUX_SOAK_IDLE` s (default 8) of open, quiet sessions
/// (the idle-release paths run). Every `ZMUX_SOAK_EVERY` s (default 5) it
/// prints the live heap (the counting allocator), the resident set and
/// their ratio, and the read-buffer pool; after the churn it closes every
/// session and watches `ZMUX_SOAK_SETTLE` s (default 30) of silence.
/// Run under any allocator by `LD_PRELOAD`: the counting allocator
/// forwards to the system one.
async fn soak() {
    let secs: u64 = env_or("ZMUX_SOAK_SECS", 600);
    let slots: u64 = env_or("ZMUX_SOAK_SLOTS", 32);
    let active_s: u64 = env_or("ZMUX_SOAK_ACTIVE", 40);
    let idle_s: u64 = env_or("ZMUX_SOAK_IDLE", 8);
    let every: u64 = env_or("ZMUX_SOAK_EVERY", 5);
    let settle: u64 = env_or("ZMUX_SOAK_SETTLE", 30);
    let alloc = std::env::var("LD_PRELOAD")
        .ok()
        .and_then(|p| {
            std::path::Path::new(&p)
                .file_name()
                .map(|f| f.to_string_lossy().into_owned())
        })
        .unwrap_or_else(|| "system".into());
    let mut single = Config::default();
    single.max_idle_timeout = Duration::ZERO;
    let mut mp = mp_config(&Policy::SpreadEta);
    mp.max_idle_timeout = Duration::ZERO;
    let (single, mp) = (Arc::new(single), Arc::new(mp));
    let soak = Arc::new(Soak {
        active: AtomicBool::new(true),
        stop: AtomicBool::new(false),
        counts: SoakCounts::default(),
        open: Default::default(),
    });
    let t0 = Instant::now();
    let sample = |phase: &str, series: &mut Vec<(f64, i64, i64)>| {
        let (l, r) = (live(), rss().unwrap_or(0));
        let c = &soak.counts;
        let ratio = if l > 0 { r as f64 / l as f64 } else { 0.0 };
        let (core, held) = soak.core_bytes();
        println!(
            "SOAK alloc={alloc} t={:.0} phase={phase} live_KiB={} rss_KiB={} rss_per_live={ratio:.2} open={} core_KiB={} held_KiB={} read_pool={} sessions={} streams={} MiB={} joins={} pipe_failures={} errors={}",
            t0.elapsed().as_secs_f64(),
            l / 1024,
            r / 1024,
            soak.open.lock().unwrap().len(),
            core / 1024,
            held / 1024,
            zmux::test_hooks::read_pool_buffers(),
            c.sessions.load(Relaxed),
            c.streams.load(Relaxed),
            c.bytes.load(Relaxed) >> 20,
            c.joins.load(Relaxed),
            c.pipe_failures.load(Relaxed),
            c.errors.load(Relaxed),
        );
        series.push((t0.elapsed().as_secs_f64(), l, r));
    };
    // The requests' bytes, shared by every stream.
    let payload = Bytes::from(vec![0x5au8; 1 << 20]);
    let mut series = Vec::new();
    sample("start", &mut series);
    let start = (live(), rss().unwrap_or(0));
    let handles: Vec<_> = (0..slots)
        .map(|s| {
            tokio::spawn(soak_slot(
                s,
                soak.clone(),
                single.clone(),
                mp.clone(),
                payload.clone(),
            ))
        })
        .collect();
    let deadline = t0 + Duration::from_secs(secs);
    let mut next_sample = t0 + Duration::from_secs(every);
    let mut phase_end = t0 + Duration::from_secs(active_s);
    let mut idle_samples = Vec::new();
    let mut idle_since = None;
    while Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(100)).await;
        let now = Instant::now();
        if now >= phase_end {
            let was = soak.active.load(Relaxed);
            soak.active.store(!was, Relaxed);
            idle_since = was.then_some(now);
            phase_end = now + Duration::from_secs(if was { idle_s } else { active_s });
        }
        if now >= next_sample {
            next_sample += Duration::from_secs(every);
            let active = soak.active.load(Relaxed);
            sample(if active { "active" } else { "idle" }, &mut series);
            // Idle samples once the idle-release paths had time to run.
            if idle_since.is_some_and(|t| now - t >= Duration::from_secs(3)) {
                idle_samples.push(*series.last().unwrap());
            }
        }
    }
    soak.stop.store(true, Relaxed);
    soak.active.store(true, Relaxed);
    for h in handles {
        let _ = tokio::time::timeout(Duration::from_secs(60), h).await;
    }
    let churn_end = series.len();
    let settle_end = Instant::now() + Duration::from_secs(settle);
    while Instant::now() < settle_end {
        tokio::time::sleep(Duration::from_secs(every)).await;
        sample("settle", &mut series);
    }
    let end = *series.last().unwrap();
    let peak_live = series.iter().map(|s| s.1).max().unwrap_or(0);
    let peak_rss = series.iter().map(|s| s.2).max().unwrap_or(0);
    // The trend over the idle samples (3 s or more into an idle phase) of
    // the first and the second half of the churn: comparable states, open
    // quiet sessions.
    let ratio = |v: &[(f64, i64, i64)]| {
        let r: Vec<f64> = v
            .iter()
            .filter(|s| s.1 > 0)
            .map(|s| s.2 as f64 / s.1 as f64)
            .collect();
        if r.is_empty() {
            0.0
        } else {
            r.iter().sum::<f64>() / r.len() as f64
        }
    };
    let half = idle_samples.partition_point(|s| s.0 < secs as f64 / 2.0);
    let idle_live = |v: &[(f64, i64, i64)]| {
        if v.is_empty() {
            0
        } else {
            v.iter().map(|s| s.1).sum::<i64>() / v.len() as i64 / 1024
        }
    };
    let idle_rss = |v: &[(f64, i64, i64)]| {
        if v.is_empty() {
            0
        } else {
            v.iter().map(|s| s.2).sum::<i64>() / v.len() as i64 / 1024
        }
    };
    println!(
        "RESULT scen=soak alloc={alloc} secs={secs} slots={slots} start_live_KiB={} start_rss_KiB={} peak_live_KiB={} peak_rss_KiB={} idle_live_KiB_1st_half={} idle_live_KiB_2nd_half={} idle_rss_KiB_1st_half={} idle_rss_KiB_2nd_half={} idle_rss_per_live_1st_half={:.2} idle_rss_per_live_2nd_half={:.2} end_live_KiB={} end_rss_KiB={} churn_samples={churn_end} sessions={} streams={} MiB={} joins={} pipe_failures={} errors={}",
        start.0 / 1024,
        start.1 / 1024,
        peak_live / 1024,
        peak_rss / 1024,
        idle_live(&idle_samples[..half]),
        idle_live(&idle_samples[half..]),
        idle_rss(&idle_samples[..half]),
        idle_rss(&idle_samples[half..]),
        ratio(&idle_samples[..half]),
        ratio(&idle_samples[half..]),
        end.1 / 1024,
        end.2 / 1024,
        soak.counts.sessions.load(Relaxed),
        soak.counts.streams.load(Relaxed),
        soak.counts.bytes.load(Relaxed) >> 20,
        soak.counts.joins.load(Relaxed),
        soak.counts.pipe_failures.load(Relaxed),
        soak.counts.errors.load(Relaxed),
    );
}

/// `n` idle session pairs.
async fn futures_pairs(n: usize) -> Vec<(Session, Session)> {
    let mut v = Vec::with_capacity(n);
    for _ in 0..n {
        v.push(session_pair(false).await);
    }
    v
}

// ---- multipath ---------------------------------------------------------------------

fn reset_peak() {
    PEAK.store(live(), Relaxed);
}

/// User and system CPU seconds of the process (both ends of a pair).
#[cfg(unix)]
fn cpu_secs() -> Option<f64> {
    let mut ru = std::mem::MaybeUninit::<libc::rusage>::zeroed();
    // SAFETY: getrusage fills the struct it is given.
    if unsafe { libc::getrusage(libc::RUSAGE_SELF, ru.as_mut_ptr()) } != 0 {
        return None;
    }
    // SAFETY: initialized by the successful call.
    let ru = unsafe { ru.assume_init() };
    let tv = |t: libc::timeval| t.tv_sec as f64 + t.tv_usec as f64 / 1e6;
    Some(tv(ru.ru_utime) + tv(ru.ru_stime))
}

#[cfg(not(unix))]
fn cpu_secs() -> Option<f64> {
    None
}

fn policy_name(p: &Policy) -> &'static str {
    match p {
        Policy::Affinity => "affinity",
        Policy::SpreadEta => "eta",
        Policy::SpreadRoundRobin => "rr",
        Policy::SpreadRateWeighted => "rw",
        Policy::SessionAffinity => "session",
        _ => "custom",
    }
}

fn mp_config(policy: &Policy) -> Config {
    let mut c = Config::default();
    c.max_pipes = 8;
    c.pipe_auth = PipeAuth::psk(*b"bench-multipath-psk-0123456789ab");
    c.scheduler = policy.clone();
    // Loopback pipes are trusted: a new pipe carries data at once instead
    // of after a second of probation.
    c.probation = Some(Duration::ZERO);
    c
}

/// A session pair over TCP loopback: one plain single-pipe session, or a
/// multipath session over `pipes` carriers (the bootstrap pipe and joins
/// routed by a [`Listener`]).
struct Pair {
    client: Session,
    server: Session,
    pipes: usize,
    policy: Option<Policy>,
    addr: Option<std::net::SocketAddr>,
    listener: Option<Listener>,
    acceptor: Option<tokio::task::JoinHandle<()>>,
}

impl Pair {
    async fn plain() -> Self {
        let (client, server) = session_pair(true).await;
        Self {
            client,
            server,
            pipes: 1,
            policy: None,
            addr: None,
            listener: None,
            acceptor: None,
        }
    }

    async fn multipath(pipes: usize, policy: &Policy) -> Self {
        let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = tcp.local_addr().unwrap();
        let listener = Listener::new(mp_config(policy), ListenerConfig::default());
        let l = listener.clone();
        let acceptor = tokio::spawn(async move {
            while let Ok((c, peer)) = tcp.accept().await {
                let l = l.clone();
                tokio::spawn(async move {
                    let _ = l
                        .handle_pipe(PipeIo::tcp(c), PipeHint::from_addr(peer.ip()))
                        .await;
                });
            }
        });
        let c = TcpStream::connect(addr).await.unwrap();
        let client = Session::connect(PipeIo::tcp(c), mp_config(policy))
            .await
            .unwrap();
        let server = listener.accept().await.unwrap();
        let mut pair = Self {
            client,
            server,
            pipes: 1,
            policy: Some(policy.clone()),
            addr: Some(addr),
            listener: Some(listener),
            acceptor: Some(acceptor),
        };
        pair.add_pipes(pipes - 1).await;
        pair
    }

    /// Joins `n` more pipes and waits until both ends use all of them.
    async fn add_pipes(&mut self, n: usize) {
        let addr = self.addr.expect("multipath pair");
        for _ in 0..n {
            let c = TcpStream::connect(addr).await.unwrap();
            self.client
                .add_pipe(PipeIo::tcp(c), PipeOptions::default())
                .unwrap();
        }
        self.pipes += n;
        let active = |s: &Session| {
            s.pipe_stats()
                .iter()
                .filter(|i| i.outbound == Some(PipeState::Active))
                .count()
        };
        let deadline = Instant::now() + Duration::from_secs(5);
        while active(&self.client) < self.pipes || active(&self.server) < self.pipes {
            // Joins are confirmed by the peer's first record.
            let _ = tokio::join!(self.client.ping(), self.server.ping());
            assert!(Instant::now() < deadline, "pipes did not become active");
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    fn label(&self) -> String {
        match &self.policy {
            None => "plain".to_string(),
            Some(p) => policy_name(p).to_string(),
        }
    }

    /// Bytes each client pipe sent so far.
    fn pipe_bytes(&self) -> Vec<u64> {
        self.client
            .pipe_stats()
            .iter()
            .map(|i| i.bytes_sent)
            .collect()
    }

    fn close(self) {
        self.client.close(0u32.into(), b"");
        self.server.close(0u32.into(), b"");
        if let Some(l) = &self.listener {
            l.close();
        }
        if let Some(a) = &self.acceptor {
            a.abort();
        }
    }
}

/// `streams` unidirectional streams from client to server, each writing
/// `per_stream` bytes (or until `stop`) in shared 64 KiB chunks; the server
/// adds what it reads to `counted`. Returns the writers and readers.
async fn spawn_bulk(
    pair: &Pair,
    streams: usize,
    per_stream: Option<u64>,
    stop: &Arc<AtomicBool>,
    counted: &Arc<AtomicU64>,
) -> (
    Vec<tokio::task::JoinHandle<u64>>,
    tokio::task::JoinHandle<Vec<Duration>>,
) {
    let server = pair.server.clone();
    let c = counted.clone();
    let start = Instant::now();
    let readers = tokio::spawn(async move {
        let mut tasks = Vec::new();
        for _ in 0..streams {
            let mut r = server.accept_uni().await.unwrap();
            let c = c.clone();
            tasks.push(tokio::spawn(async move {
                let mut buf = vec![0u8; 256 * 1024];
                while let Some(k) = r.read(&mut buf).await.unwrap() {
                    c.fetch_add(k as u64, Relaxed);
                }
                start.elapsed()
            }));
        }
        let mut done = Vec::new();
        for t in tasks {
            done.push(t.await.unwrap());
        }
        done
    });
    let chunk = Bytes::from(vec![1u8; 64 * 1024]);
    let mut writers = Vec::new();
    for _ in 0..streams {
        let mut s = pair.client.open_uni().await.unwrap();
        let chunk = chunk.clone();
        let stop = stop.clone();
        writers.push(tokio::spawn(async move {
            let mut sent = 0u64;
            while per_stream.is_none_or(|p| sent < p) && !stop.load(Relaxed) {
                s.write_chunk(chunk.clone()).await.unwrap();
                sent += chunk.len() as u64;
            }
            s.finish().unwrap();
            sent
        }));
    }
    (writers, readers)
}

/// Moves `bytes` over one stream: warms the pipes' estimates and windows.
async fn warm_up(pair: &Pair, bytes: u64) {
    let stop = Arc::new(AtomicBool::new(false));
    let counted = Arc::new(AtomicU64::new(0));
    let (writers, readers) = spawn_bulk(pair, 1, Some(bytes), &stop, &counted).await;
    for w in writers {
        w.await.unwrap();
    }
    readers.await.unwrap();
}

#[derive(Debug)]
struct BulkRow {
    label: String,
    pipes: usize,
    streams: usize,
    gbps: f64,
    cpu_per_gb: Option<f64>,
    /// Percent of the bytes each pipe sent.
    split: Vec<f64>,
    live_avg: f64,
    live_max: i64,
    peak: i64,
    after_drain: i64,
    client: SessionStats,
    server: SessionStats,
}

/// Bulk throughput for `secs`: writers run until stopped, the server counts
/// what it reads in the window. Memory is the process's live heap above
/// what it was before the pair existed, without the benchmark's own
/// buffers: sampled every 20 ms during the window, its peak, and after the
/// streams ended and idle buffers were returned.
async fn mp_bulk(pipes: usize, policy: Option<&Policy>, streams: usize, secs: f64) -> BulkRow {
    let base = live();
    let pair = match policy {
        None => Pair::plain().await,
        Some(p) => Pair::multipath(pipes, p).await,
    };
    warm_up(&pair, 128 << 20).await;
    let stop = Arc::new(AtomicBool::new(false));
    let counted = Arc::new(AtomicU64::new(0));
    let (writers, readers) = spawn_bulk(&pair, streams, None, &stop, &counted).await;
    // The benchmark's own buffers during the window: a 256 KiB read buffer
    // per stream and the shared 64 KiB chunk.
    let app = streams as i64 * 256 * 1024 + 64 * 1024;
    tokio::time::sleep(Duration::from_millis(200)).await;
    let split0 = pair.pipe_bytes();
    let (b0, t0, cpu0) = (counted.load(Relaxed), Instant::now(), cpu_secs());
    reset_peak();
    let mut samples = Vec::new();
    let mut mid = None;
    while t0.elapsed().as_secs_f64() < secs {
        tokio::time::sleep(Duration::from_millis(20)).await;
        samples.push(live() - base - app);
        if mid.is_none() && t0.elapsed().as_secs_f64() >= secs / 2.0 {
            mid = Some((pair.client.stats(), pair.server.stats()));
        }
    }
    let (b1, d, cpu1) = (counted.load(Relaxed), t0.elapsed(), cpu_secs());
    let peak = PEAK.load(Relaxed) - base - app;
    let split1 = pair.pipe_bytes();
    stop.store(true, Relaxed);
    for w in writers {
        w.await.unwrap();
    }
    readers.await.unwrap();
    // Idle pipes return their buffers after a second.
    tokio::time::sleep(Duration::from_millis(1300)).await;
    let after_drain = live() - base;
    let bytes = b1 - b0;
    let deltas: Vec<u64> = split1
        .iter()
        .zip(split0.iter().chain(std::iter::repeat(&0)))
        .map(|(a, b)| a - b)
        .collect();
    let total: u64 = deltas.iter().sum::<u64>().max(1);
    let (client, server) = mid.expect("sampled");
    let row = BulkRow {
        label: pair.label(),
        pipes,
        streams,
        gbps: bytes as f64 * 8.0 / d.as_secs_f64() / 1e9,
        cpu_per_gb: cpu0.zip(cpu1).map(|(a, b)| (b - a) / (bytes as f64 / 1e9)),
        split: deltas
            .iter()
            .map(|&x| x as f64 * 100.0 / total as f64)
            .collect(),
        live_avg: samples.iter().sum::<i64>() as f64 / samples.len().max(1) as f64,
        live_max: samples.iter().copied().max().unwrap_or(0),
        peak,
        after_drain,
        client,
        server,
    };
    pair.close();
    tokio::time::sleep(Duration::from_millis(50)).await;
    println!(
        "RESULT scen=mp-bulk policy={} pipes={} streams={} Gbps={:.2} cpu_s_per_GB={} split={:?} live_avg_KB={:.0} live_max_KB={} peak_KB={} after_drain_KB={} retained_KB={} send_buffered_KB={} recv_buffered_KB={}",
        row.label,
        row.pipes,
        row.streams,
        row.gbps,
        row.cpu_per_gb.map_or("-".into(), |c| format!("{c:.3}")),
        row.split
            .iter()
            .map(|p| p.round() as u32)
            .collect::<Vec<_>>(),
        row.live_avg / 1024.0,
        row.live_max / 1024,
        row.peak / 1024,
        row.after_drain / 1024,
        row.client.retained / 1024,
        row.client.send_buffered / 1024,
        row.server.recv_buffered / 1024,
    );
    row
}

fn kb(b: i64) -> String {
    format!("{:.0}", b as f64 / 1024.0)
}

/// The multipath cases, with a table at the end.
async fn multipath() {
    // `ZMUX_BENCH_MP_CASE=<pipes>,<streams>[,plain]` runs one case for
    // `ZMUX_BENCH_SECS` (default 10) seconds, for profiling.
    if let Ok(case) = std::env::var("ZMUX_BENCH_MP_CASE") {
        let f: Vec<&str> = case.split(',').collect();
        let pipes: usize = f[0].parse().unwrap();
        let streams: usize = f[1].parse().unwrap();
        let secs = std::env::var("ZMUX_BENCH_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(10.0);
        let policy = (f.get(2) != Some(&"plain")).then_some(Policy::SpreadEta);
        mp_bulk(pipes, policy.as_ref(), streams, secs).await;
        return;
    }
    let secs = 1.5;
    // One pipe for reference, then the spread over 2 and 4 pipes with one
    // stream and with two per pipe.
    let mut bulk = vec![
        mp_bulk(1, None, 1, secs).await,
        mp_bulk(1, Some(&Policy::SpreadEta), 1, secs).await,
    ];
    for pipes in [2, 4] {
        bulk.push(mp_bulk(pipes, Some(&Policy::SpreadEta), 1, secs).await);
        bulk.push(mp_bulk(pipes, Some(&Policy::SpreadEta), 2 * pipes, secs).await);
    }
    {
        let plain = bulk.iter().find(|r| r.label == "plain").map(|r| r.gbps);
        println!("\nmultipath bulk (TCP loopback, 64 KiB zero-copy writes, {secs} s windows)");
        println!(
            "{:<8} {:>5} {:>7} {:>7} {:>6} {:>8} {:<16} {:>8} {:>8} {:>8} {:>8} {:>8} {:>8}",
            "policy",
            "pipes",
            "streams",
            "Gbit/s",
            "x1pipe",
            "CPU s/GB",
            "split %",
            "live KB",
            "max KB",
            "peak KB",
            "drained",
            "retainKB",
            "recvbufKB"
        );
        for r in &bulk {
            println!(
                "{:<8} {:>5} {:>7} {:>7.2} {:>6} {:>8} {:<16} {:>8.0} {:>8} {:>8} {:>8} {:>8} {:>8}",
                r.label,
                r.pipes,
                r.streams,
                r.gbps,
                plain.map_or("-".into(), |p| format!("{:.2}", r.gbps / p)),
                r.cpu_per_gb.map_or("-".into(), |c| format!("{c:.3}")),
                r.split
                    .iter()
                    .map(|p| format!("{:.0}", p))
                    .collect::<Vec<_>>()
                    .join("/"),
                r.live_avg / 1024.0,
                kb(r.live_max),
                kb(r.peak),
                kb(r.after_drain),
                r.client.retained / 1024,
                r.server.recv_buffered / 1024,
            );
        }
    }
}

fn main() {
    let filter: Vec<String> = std::env::args()
        .skip(1)
        .filter(|a| !a.starts_with('-'))
        .collect();
    let want = |name: &str| filter.is_empty() || filter.iter().any(|f| name.contains(f.as_str()));
    let workers = std::env::var("ZMUX_BENCH_WORKERS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(4);
    let mut builder = tokio::runtime::Builder::new_multi_thread();
    if let Some(n) = std::env::var("ZMUX_BENCH_EVENT_INTERVAL")
        .ok()
        .and_then(|v| v.parse().ok())
    {
        builder.event_interval(n);
    }
    let rt = builder
        .worker_threads(workers)
        .enable_all()
        .build()
        .unwrap();
    if want("core-bulk") {
        core_bulk(false);
        core_bulk(true);
    }
    if want("tcp-bulk") {
        rt.block_on(raw_tcp_bulk());
        rt.block_on(driver_bulk(false));
        rt.block_on(driver_bulk(true));
    }
    if want("scale") && !filter.is_empty() {
        rt.block_on(scale(false));
        rt.block_on(scale(true));
    }
    if want("wan-bulk") && !filter.is_empty() {
        rt.block_on(wan_bulk());
    }
    if want("rr-under-bulk") {
        rt.block_on(rr_under_bulk(3.0));
    }
    if want("wake") && !filter.is_empty() {
        rt.block_on(wake_latency(bench_q()));
    }
    if want("latency") {
        rt.block_on(raw_latency(64));
        rt.block_on(latency(64, false));
        rt.block_on(latency(64, true));
    }
    if want("idle") {
        core_memory();
        rt.block_on(driver_memory());
    }
    if want("mp-spread") {
        rt.block_on(multipath());
    }
    if want("soak") && !filter.is_empty() {
        rt.block_on(soak());
    }
}
