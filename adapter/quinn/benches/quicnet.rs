//! zmux over real QUIC (quinn) through an emulated path, all in user space
//! on loopback: a UDP relay that limits the rate, queues up to a limit,
//! delays and drops packets at random (both directions), and a TCP relay
//! with rate and delay for a second path. Nothing on the host is changed.
//!
//! Scenarios (`cargo bench -p zmux-quinn --bench quicnet -- <name> ...`):
//!
//! - `flows`: one QUIC path, a multipath session on one pipe; every 10 ms a
//!   1 KiB urgent message (urgency 0), and flows of 16 KiB / 256 KiB / 4 MiB
//!   (70 / 25 / 5 %) arriving at random at 60 % of the path rate. Reports
//!   the urgent p99 / p99.9 and the 16 KiB, 256 KiB and 4 MiB completion
//!   p99, with lanes and without (`QN_LANES=on|off|both`).
//! - `bulk`: the same path, 16 bulk streams and the urgent messages:
//!   goodput and urgent p99.
//! - `failover`: a TCP pipe (bootstrap, PSK) through the TCP relay and a
//!   QUIC pipe joined carrier-bound (its binding from the connection's
//!   exporter), 16 bulk streams and the urgent messages; the QUIC path goes
//!   dark at `QN_CUT` seconds: the longest gap in urgent deliveries, the
//!   urgent p99 after the cut, the goodput before and after.
//!
//! Environment: `QN_RATE_MBIT` (100), `QN_RTT_MS` (50), `QN_LOSS` (percent
//! list, "0,0.1,1"), `QN_SECS` (20), `QN_SEEDS` (1), `QN_QUEUE_BDP` (1.0),
//! `QN_LANES` (both), `QN_TCP_RATE_MBIT` (50), `QN_TCP_RTT_MS` (80),
//! `QN_CUT` (10), `QN_CC` (cubic|bbr), `QN_LOAD` (flows' share of the
//! rate, 0.6), `QN_SEND_WINDOW` (quinn's send window, bytes),
//! `QN_WORKERS` (4), `QN_SEED0` (the first seed, 1); `QN_TRACE=1` prints the pipe's and the connection's
//! estimates during `bulk`.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::time::Instant;
use zmux::{
    Config, Listener, ListenerConfig, PipeAuth, PipeHint, PipeIo, PipeOptions, PipeState, Policy,
    Priority, Session,
};
use zmux_quinn::{Options, QuicCarrier};

fn env<T: std::str::FromStr>(name: &str, default: T) -> T {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

/// A seeded xorshift64* generator.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    fn unit(&mut self) -> f64 {
        (self.next() >> 11) as f64 / (1u64 << 53) as f64
    }
}

// ---- the emulated path -------------------------------------------------------------

/// One direction of a path: a bottleneck of `rate` bytes per second with a
/// drop-tail queue of `queue` bytes, then `delay`; random loss before it.
#[derive(Clone, Copy)]
struct Link {
    rate: f64,
    delay: Duration,
    loss: f64,
    queue: f64,
}

/// The bottleneck's state: when the link is free again.
struct Shaper {
    link: Link,
    free_at: Instant,
    rng: Rng,
    /// Records the queueing of the client-to-server direction.
    record: bool,
}

/// The client end of the last QUIC connection, for traces.
static CLIENT_CONN: Mutex<Option<quinn::Connection>> = Mutex::new(None);

/// The bottleneck queue waits (ms) of the client-to-server direction, and
/// its drops at a full queue, since the last [`take_queue`].
static QUEUE: Mutex<(Vec<f32>, u64)> = Mutex::new((Vec::new(), 0));

/// The p50 / p99 queue wait (ms) and the full-queue drops.
fn take_queue() -> (f64, f64, u64) {
    let (waits, drops) = std::mem::take(&mut *QUEUE.lock().unwrap());
    let mut w: Vec<f64> = waits.into_iter().map(f64::from).collect();
    (pct(&mut w, 0.5), pct(&mut w, 0.99), drops)
}

impl Shaper {
    fn new(link: Link, seed: u64, record: bool) -> Self {
        Self {
            link,
            free_at: Instant::now(),
            rng: Rng(seed | 1),
            record,
        }
    }

    /// When a packet of `len` bytes arriving now is delivered, or `None`
    /// when it is lost or the queue is full.
    fn admit(&mut self, len: usize, now: Instant) -> Option<Instant> {
        if self.link.loss > 0.0 && self.rng.unit() < self.link.loss {
            return None;
        }
        let start = self.free_at.max(now);
        let backlog = start.saturating_duration_since(now).as_secs_f64() * self.link.rate;
        if backlog > self.link.queue {
            if self.record {
                QUEUE.lock().unwrap().1 += 1;
            }
            return None;
        }
        if self.record {
            let wait = start.saturating_duration_since(now).as_secs_f32() * 1e3;
            QUEUE.lock().unwrap().0.push(wait);
        }
        self.free_at = start + Duration::from_secs_f64(len as f64 / self.link.rate);
        Some(self.free_at + self.link.delay)
    }
}

/// A UDP relay between a client and `server`: the address the client
/// sends to, and the switch that blackholes the path.
async fn udp_relay(
    server: SocketAddr,
    up: Link,
    down: Link,
    seed: u64,
) -> (SocketAddr, Arc<AtomicBool>) {
    let front = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let back = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    back.connect(server).await.unwrap();
    let addr = front.local_addr().unwrap();
    let dark = Arc::new(AtomicBool::new(false));
    let client: Arc<Mutex<Option<SocketAddr>>> = Arc::default();
    // Client to server.
    {
        let (front, back, dark, client) =
            (front.clone(), back.clone(), dark.clone(), client.clone());
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<(Instant, Bytes)>();
        tokio::spawn(deliver(rx, move |p| {
            let back = back.clone();
            async move {
                let _ = back.send(&p).await;
            }
        }));
        tokio::spawn(async move {
            let mut shaper = Shaper::new(up, seed, true);
            let mut buf = vec![0u8; 65536];
            while let Ok((n, from)) = front.recv_from(&mut buf).await {
                *client.lock().unwrap() = Some(from);
                if dark.load(Ordering::Relaxed) {
                    continue;
                }
                if let Some(at) = shaper.admit(n, Instant::now()) {
                    let _ = tx.send((at, Bytes::copy_from_slice(&buf[..n])));
                }
            }
        });
    }
    // Server to client.
    {
        let (front, dark, client) = (front.clone(), dark.clone(), client.clone());
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<(Instant, Bytes)>();
        tokio::spawn(deliver(rx, move |p| {
            let (front, to) = (front.clone(), *client.lock().unwrap());
            async move {
                if let Some(to) = to {
                    let _ = front.send_to(&p, to).await;
                }
            }
        }));
        tokio::spawn(async move {
            let mut shaper = Shaper::new(down, seed.rotate_left(17), false);
            let mut buf = vec![0u8; 65536];
            while let Ok(n) = back.recv(&mut buf).await {
                if dark.load(Ordering::Relaxed) {
                    continue;
                }
                if let Some(at) = shaper.admit(n, Instant::now()) {
                    let _ = tx.send((at, Bytes::copy_from_slice(&buf[..n])));
                }
            }
        });
    }
    (addr, dark)
}

/// Sends each packet at its time (they come in time order).
async fn deliver<F, Fut>(mut rx: tokio::sync::mpsc::UnboundedReceiver<(Instant, Bytes)>, send: F)
where
    F: Fn(Bytes) -> Fut,
    Fut: Future<Output = ()>,
{
    while let Some((at, p)) = rx.recv().await {
        tokio::time::sleep_until(at).await;
        send(p).await;
    }
}

/// A TCP relay to `server` with `link` each way (no loss; a full queue
/// holds the reader back): the address to connect to.
///
/// The relay's own sockets keep small buffers (64 KiB), so that what the
/// emulated bottleneck holds back stays in the sender's socket, where its
/// unsent count and low-water mark see it, rather than in a deep loopback
/// buffer no real path has.
async fn tcp_relay(server: SocketAddr, link: Link) -> SocketAddr {
    const BUF: u32 = 64 * 1024;
    let socket = tokio::net::TcpSocket::new_v4().unwrap();
    socket.set_recv_buffer_size(BUF).unwrap();
    socket.bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let l = socket.listen(64).unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((a, _)) = l.accept().await {
            let out = tokio::net::TcpSocket::new_v4().unwrap();
            out.set_send_buffer_size(BUF).unwrap();
            out.set_recv_buffer_size(BUF).unwrap();
            let b = out.connect(server).await.unwrap();
            let _ = (a.set_nodelay(true), b.set_nodelay(true));
            let (ar, aw) = a.into_split();
            let (br, bw) = b.into_split();
            tokio::spawn(pump(ar, bw, link));
            tokio::spawn(pump(br, aw, link));
        }
    });
    addr
}

async fn pump(
    mut r: tokio::net::tcp::OwnedReadHalf,
    mut w: tokio::net::tcp::OwnedWriteHalf,
    link: Link,
) {
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<(Instant, Bytes)>();
    let writer = tokio::spawn(async move {
        while let Some((at, p)) = rx.recv().await {
            tokio::time::sleep_until(at).await;
            if w.write_all(&p).await.is_err() {
                return;
            }
        }
        let _ = w.shutdown().await;
    });
    let mut free_at = Instant::now();
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        // Backpressure: read only while the queue has room.
        let now = Instant::now();
        let backlog = free_at.saturating_duration_since(now).as_secs_f64() * link.rate;
        if backlog > link.queue {
            tokio::time::sleep(Duration::from_secs_f64((backlog - link.queue) / link.rate)).await;
            continue;
        }
        let n = match r.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        let now = Instant::now();
        free_at = free_at.max(now) + Duration::from_secs_f64(n as f64 / link.rate);
        if tx
            .send((free_at + link.delay, Bytes::copy_from_slice(&buf[..n])))
            .is_err()
        {
            break;
        }
    }
    drop(tx);
    let _ = writer.await;
}

// ---- QUIC endpoints ------------------------------------------------------------------

struct Quic {
    server: quinn::Endpoint,
    client: quinn::Endpoint,
}

impl Quic {
    fn new() -> Self {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let der = CertificateDer::from(cert.cert.der().to_vec());
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()));
        let tls = rustls::ServerConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![der.clone()], key)
            .unwrap();
        let mut server_config =
            quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(tls).unwrap()));
        server_config.transport_config(transport());
        let server =
            quinn::Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(der).unwrap();
        let tls = rustls::ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let mut client_config =
            quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(tls).unwrap()));
        client_config.transport_config(transport());
        let mut client = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        client.set_default_client_config(client_config);
        Self { server, client }
    }

    /// A connection through the path at `addr` (a relay to the server).
    async fn connect(&self, addr: SocketAddr) -> (quinn::Connection, quinn::Connection) {
        let (c, s) = tokio::join!(
            async {
                self.client
                    .connect(addr, "localhost")
                    .unwrap()
                    .await
                    .unwrap()
            },
            async { self.server.accept().await.unwrap().await.unwrap() }
        );
        (c, s)
    }
}

fn transport() -> Arc<quinn::TransportConfig> {
    let mut t = quinn::TransportConfig::default();
    t.max_idle_timeout(Some(Duration::from_secs(60).try_into().unwrap()));
    if std::env::var("QN_CC").as_deref() == Ok("bbr") {
        t.congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default()));
    }
    Arc::new(t)
}

fn options() -> Options {
    let mut o = Options::default();
    // As the simulated rows (16 lanes).
    o.lanes = 16;
    o
}

fn mp_config() -> Config {
    let mut c = Config::default();
    c.max_pipes = 4;
    c.pipe_auth = PipeAuth::psk(*b"quicnet-bench-psk-0123456789abcd");
    c.scheduler = Policy::SpreadEta;
    c
}

// ---- workloads -----------------------------------------------------------------------

/// Delivery records of the receiving end.
#[derive(Default)]
struct Records {
    /// (sent at, latency) of urgent messages, seconds since the start.
    urgent: Vec<(f64, f64)>,
    /// (size, completion time) of flows.
    flows: Vec<(usize, f64)>,
    /// Bulk bytes received after the warm-up, before and after the cut.
    bulk: [u64; 2],
}

const URGENT: u8 = b'U';
const FLOW: u8 = b'F';
const BULK: u8 = b'B';

/// Accepts every stream of `s` and records what arrives.
fn receiver(s: Session, t0: Instant, cut: f64, warm: f64) -> Arc<Mutex<Records>> {
    let rec: Arc<Mutex<Records>> = Arc::default();
    let r = rec.clone();
    tokio::spawn(async move {
        while let Ok(mut recv) = s.accept_uni().await {
            let r = r.clone();
            tokio::spawn(async move {
                let mut head = [0u8; 9];
                if recv.read_exact(&mut head).await.is_err() {
                    return;
                }
                let sent = f64::from_bits(u64::from_be_bytes(head[1..9].try_into().unwrap()));
                let first = t0.elapsed().as_secs_f64() - sent;
                match head[0] {
                    URGENT | FLOW => {
                        let Ok(rest) = recv.read_to_end(64 << 20).await else {
                            return;
                        };
                        let now = t0.elapsed().as_secs_f64();
                        let mut r = r.lock().unwrap();
                        if head[0] == URGENT {
                            r.urgent.push((sent, now - sent));
                        } else {
                            r.flows.push((rest.len() + 9, now - sent));
                            if std::env::var("QN_TRACE").is_ok()
                                && now - sent > 0.3
                                && rest.len() < 20000
                            {
                                eprintln!(
                                    "TRACE flow sent={sent:.2} first_byte_ms={:.0} done_ms={:.0}",
                                    first * 1e3,
                                    (now - sent) * 1e3
                                );
                            }
                        }
                    }
                    _ => {
                        let mut buf = vec![0u8; 256 * 1024];
                        while let Ok(Some(n)) = recv.read(&mut buf).await {
                            let now = t0.elapsed().as_secs_f64();
                            if now >= warm {
                                r.lock().unwrap().bulk[usize::from(now >= cut)] += n as u64;
                            }
                        }
                    }
                }
            });
        }
    });
    rec
}

fn header(kind: u8, t0: Instant) -> Vec<u8> {
    let mut h = vec![kind];
    h.extend_from_slice(&t0.elapsed().as_secs_f64().to_bits().to_be_bytes());
    h
}

/// A 1 KiB urgent message every 10 ms until `end`.
async fn urgent(s: Session, t0: Instant, end: f64) {
    let mut tick = tokio::time::interval(Duration::from_millis(10));
    while t0.elapsed().as_secs_f64() < end {
        tick.tick().await;
        let Ok(mut send) = s.open_uni().await else {
            return;
        };
        let _ = send.set_priority(Priority::new(0, false).unwrap());
        let mut msg = header(URGENT, t0);
        msg.resize(1024, 0x55);
        tokio::spawn(async move {
            let _ = send.write_all(&msg).await;
            let _ = send.finish();
        });
    }
}

/// Flows of 16 KiB / 256 KiB / 4 MiB (70 / 25 / 5 %) arriving at random at
/// `load` bytes per second until `end`.
async fn flows(s: Session, t0: Instant, end: f64, load: f64, seed: u64) {
    let mut rng = Rng(seed | 1);
    let mean = 0.70 * 16384.0 + 0.25 * 262_144.0 + 0.05 * 4_194_304.0;
    let rate = load / mean;
    let mut next = 0.5;
    while next < end {
        tokio::time::sleep_until(t0 + Duration::from_secs_f64(next)).await;
        let u = rng.unit();
        let size = if u < 0.70 {
            16384
        } else if u < 0.95 {
            262_144
        } else {
            4_194_304
        };
        let s = s.clone();
        tokio::spawn(async move {
            let Ok(mut send) = s.open_uni().await else {
                return;
            };
            let mut data = header(FLOW, t0);
            data.resize(size, 0x46);
            let _ = send.write_chunk(Bytes::from(data)).await;
            let _ = send.finish();
        });
        next += -rng.unit().max(1e-12).ln() / rate;
    }
}

/// `n` bulk streams writing until `end`.
async fn bulk(s: Session, t0: Instant, end: f64, n: usize) {
    let chunk = Bytes::from(vec![0x42u8; 64 * 1024]);
    let mut tasks = Vec::new();
    for _ in 0..n {
        let (s, chunk) = (s.clone(), chunk.clone());
        tasks.push(tokio::spawn(async move {
            let Ok(mut send) = s.open_uni().await else {
                return;
            };
            if send.write_all(&header(BULK, t0)).await.is_err() {
                return;
            }
            while t0.elapsed().as_secs_f64() < end {
                if send.write_chunk(chunk.clone()).await.is_err() {
                    return;
                }
            }
            let _ = send.finish();
        }));
    }
    for t in tasks {
        let _ = t.await;
    }
}

fn pct(v: &mut [f64], p: f64) -> f64 {
    if v.is_empty() {
        return f64::NAN;
    }
    v.sort_by(f64::total_cmp);
    v[((v.len() as f64 * p).ceil() as usize).clamp(1, v.len()) - 1]
}

// ---- scenarios -----------------------------------------------------------------------

struct Path {
    rate: f64,
    rtt: Duration,
    queue: f64,
}

impl Path {
    fn from_env() -> Self {
        let rate = env("QN_RATE_MBIT", 100.0) * 1e6 / 8.0;
        let rtt = Duration::from_millis(env("QN_RTT_MS", 50));
        let queue = env("QN_QUEUE_BDP", 1.0) * rate * rtt.as_secs_f64();
        Self { rate, rtt, queue }
    }

    fn link(&self, loss: f64) -> Link {
        Link {
            rate: self.rate,
            delay: self.rtt / 2,
            loss,
            queue: self.queue,
        }
    }
}

/// A multipath session on one QUIC pipe through the emulated path: the
/// client session, the server session, and the endpoints.
async fn quic_pair(loss: f64, lanes: bool, seed: u64) -> (Session, Session, Quic) {
    let path = Path::from_env();
    let quic = Quic::new();
    let (relay, _dark) = udp_relay(
        quic.server.local_addr().unwrap(),
        path.link(loss),
        path.link(loss),
        seed,
    )
    .await;
    let (cc, sc) = quic.connect(relay).await;
    if let Some(w) = std::env::var("QN_SEND_WINDOW")
        .ok()
        .and_then(|v| v.parse().ok())
    {
        cc.set_send_window(w);
        sc.set_send_window(w);
    }
    *CLIENT_CONN.lock().unwrap() = Some(cc.clone());
    let client = QuicCarrier::new(cc, options());
    let server = QuicCarrier::new(sc, options());
    let accept = tokio::spawn(async move {
        let io = server.accept_pipe().await.unwrap().with_lanes(lanes);
        Session::accept(io, mp_config()).await.unwrap()
    });
    let io = client.open_pipe().await.unwrap().with_lanes(lanes);
    let cs = Session::connect(io, mp_config()).await.unwrap();
    let ss = accept.await.unwrap();
    (cs, ss, quic)
}

async fn run_flows(loss: f64, lanes: bool, seed: u64, secs: f64) {
    let (cs, ss, quic) = quic_pair(loss, lanes, seed).await;
    let t0 = Instant::now();
    take_queue();
    let rec = receiver(ss.clone(), t0, f64::INFINITY, 0.0);
    let load = env("QN_LOAD", 0.6) * Path::from_env().rate;
    let u = tokio::spawn(urgent(cs.clone(), t0, secs));
    flows(cs.clone(), t0, secs, load, seed).await;
    let _ = u.await;
    // Late flows finish (at most 10 s).
    tokio::time::sleep(Duration::from_secs(3)).await;
    let (q50, q99, qdrops) = take_queue();
    // The client's lanes: the unidirectional streams of its connection
    // (the next one's index counts them).
    let conn = CLIENT_CONN.lock().unwrap().clone();
    let mut lanes_opened = None;
    if let Some(c) = conn
        && let Ok(Ok(s)) = tokio::time::timeout(Duration::from_secs(1), c.open_uni()).await
    {
        lanes_opened = Some(s.id().index());
    }
    {
        let r = rec.lock().unwrap();
        if std::env::var("QN_TRACE").is_ok() {
            for &(size, t) in r.flows.iter().filter(|&&(s, t)| s == 16384 && t > 0.3) {
                eprintln!("TRACE slow flow size={size} ms={:.0}", t * 1e3);
            }
        }
        let mut urg: Vec<f64> = r.urgent.iter().map(|&(_, l)| l * 1e3).collect();
        let by = |size: usize| -> Vec<f64> {
            r.flows
                .iter()
                .filter(|&&(s, _)| s == size)
                .map(|&(_, t)| t * 1e3)
                .collect()
        };
        let (mut f16, mut f256, mut f4m) = (by(16384), by(262_144), by(4_194_304));
        println!(
            "RESULT scen=flows loss_pct={} lanes={lanes} seed={seed} urgent_n={} urgent_p99_ms={:.1} urgent_p999_ms={:.1} f16k_n={} f16k_p99_ms={:.1} f256k_p99_ms={:.1} f4m_n={} f4m_p99_ms={:.1} queue_p50_ms={q50:.1} queue_p99_ms={q99:.1} queue_drops={qdrops} lanes_opened={lanes_opened:?}",
            loss * 100.0,
            urg.len(),
            pct(&mut urg, 0.99),
            pct(&mut urg, 0.999),
            f16.len(),
            pct(&mut f16, 0.99),
            pct(&mut f256, 0.99),
            f4m.len(),
            pct(&mut f4m, 0.99),
        );
    }
    end(cs, ss, quic).await;
}

/// Closes a run's sessions, then its endpoints.
async fn end(cs: Session, ss: Session, quic: Quic) {
    cs.close(0u32.into(), b"");
    let _ = tokio::time::timeout(Duration::from_secs(2), ss.closed()).await;
    drop((cs, ss));
    quic.client.close(0u32.into(), b"");
    quic.server.close(0u32.into(), b"");
}

async fn run_bulk(loss: f64, lanes: bool, seed: u64, secs: f64) {
    let (cs, ss, quic) = quic_pair(loss, lanes, seed).await;
    let t0 = Instant::now();
    let warm = 3.0;
    take_queue();
    let rec = receiver(ss.clone(), t0, f64::INFINITY, warm);
    if std::env::var("QN_TRACE").is_ok() {
        let cs = cs.clone();
        tokio::spawn(async move {
            while t0.elapsed().as_secs_f64() < secs {
                tokio::time::sleep(Duration::from_millis(500)).await;
                if let Some(c) = CLIENT_CONN.lock().unwrap().as_ref() {
                    let st = c.stats();
                    eprintln!(
                        "TRACE quic rtt={:?} cwnd={} lost={} sent_pkts={}",
                        c.rtt(),
                        st.path.cwnd,
                        st.path.lost_packets,
                        st.path.sent_packets
                    );
                }
                for p in cs.pipe_stats() {
                    eprintln!(
                        "TRACE t={:.1} pipe={} queued={} qdelay={:?} rate={:?} srtt={:?} inflight={:?} writable={}",
                        t0.elapsed().as_secs_f64(),
                        p.pipe.0,
                        p.queued_bytes,
                        p.queue_delay,
                        p.delivery_rate,
                        p.smoothed_rtt,
                        p.bytes_in_flight,
                        p.writable
                    );
                }
            }
        });
    }
    let u = tokio::spawn(urgent(cs.clone(), t0, secs));
    bulk(cs.clone(), t0, secs, 16).await;
    let _ = u.await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    let (q50, q99, qdrops) = take_queue();
    {
        let r = rec.lock().unwrap();
        let mut urg: Vec<f64> = r.urgent.iter().map(|&(_, l)| l * 1e3).collect();
        println!(
            "RESULT scen=bulk loss_pct={} lanes={lanes} seed={seed} goodput_mbit={:.1} urgent_n={} urgent_p99_ms={:.1} urgent_p999_ms={:.1} queue_p50_ms={q50:.1} queue_p99_ms={q99:.1} queue_drops={qdrops}",
            loss * 100.0,
            r.bulk[0] as f64 * 8.0 / (secs - warm) / 1e6,
            urg.len(),
            pct(&mut urg, 0.99),
            pct(&mut urg, 0.999),
        );
    }
    end(cs, ss, quic).await;
}

/// TCP pipe 0 through the TCP relay (PSK), a QUIC pipe with lanes joined
/// carrier-bound; the QUIC path goes dark at `cut`.
async fn run_failover(loss: f64, seed: u64, secs: f64) {
    let path = Path::from_env();
    let tcp_rate = env("QN_TCP_RATE_MBIT", 50.0) * 1e6 / 8.0;
    let tcp_rtt = Duration::from_millis(env("QN_TCP_RTT_MS", 80));
    let tcp_link = Link {
        rate: tcp_rate,
        delay: tcp_rtt / 2,
        loss: 0.0,
        queue: tcp_rate * tcp_rtt.as_secs_f64(),
    };
    let cut = env("QN_CUT", 10.0);
    let listener = Listener::new(mp_config(), ListenerConfig::default());
    // TCP: server side.
    let tl = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let tcp_server = tl.local_addr().unwrap();
    {
        let l = listener.clone();
        tokio::spawn(async move {
            while let Ok((c, _)) = tl.accept().await {
                let l = l.clone();
                tokio::spawn(
                    async move { l.handle_pipe(PipeIo::tcp(c), PipeHint::default()).await },
                );
            }
        });
    }
    let tcp_addr = tcp_relay(tcp_server, tcp_link).await;
    let client = Session::connect(
        PipeIo::tcp(TcpStream::connect(tcp_addr).await.unwrap()),
        mp_config(),
    )
    .await
    .unwrap();
    let server = listener.accept().await.unwrap();
    // QUIC: the server's carrier hands its streams to the listener.
    let quic = Quic::new();
    let (relay, dark) = udp_relay(
        quic.server.local_addr().unwrap(),
        path.link(loss),
        path.link(loss),
        seed,
    )
    .await;
    let (cc, sc) = quic.connect(relay).await;
    let _server_quic = QuicCarrier::with_listener(sc, &listener, options());
    let client_quic = QuicCarrier::new(cc, options());
    let pipe = client
        .add_pipe(
            client_quic.open_pipe().await.unwrap(),
            PipeOptions::default(),
        )
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    while pipe.stats().and_then(|i| i.outbound) != Some(PipeState::Active) {
        assert!(
            Instant::now() < deadline,
            "the carrier-bound QUIC join failed"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    let t0 = Instant::now();
    let warm = 3.0;
    let rec = receiver(server.clone(), t0, cut, warm);
    {
        let dark = dark.clone();
        tokio::spawn(async move {
            tokio::time::sleep_until(t0 + Duration::from_secs_f64(cut)).await;
            dark.store(true, Ordering::Relaxed);
        });
    }
    let u = tokio::spawn(urgent(client.clone(), t0, secs));
    bulk(client.clone(), t0, secs, 16).await;
    let _ = u.await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    {
        let r = rec.lock().unwrap();
        // Urgent deliveries in arrival order: the longest gap after the cut.
        let mut arrivals: Vec<f64> = r.urgent.iter().map(|&(s, l)| s + l).collect();
        arrivals.sort_by(f64::total_cmp);
        let gap = arrivals
            .windows(2)
            .filter(|w| w[1] >= cut)
            .map(|w| w[1] - w[0])
            .fold(0.0, f64::max);
        let mut after: Vec<f64> = r
            .urgent
            .iter()
            .filter(|&&(s, _)| s >= cut)
            .map(|&(_, l)| l * 1e3)
            .collect();
        let mut before: Vec<f64> = r
            .urgent
            .iter()
            .filter(|&&(s, _)| s < cut)
            .map(|&(_, l)| l * 1e3)
            .collect();
        let quic_state = pipe.stats().and_then(|i| i.outbound);
        println!(
            "RESULT scen=failover loss_pct={} seed={seed} goodput_before_mbit={:.1} goodput_after_mbit={:.1} urgent_p99_before_ms={:.1} urgent_p99_after_ms={:.1} urgent_max_gap_ms={:.0} urgent_n={} quic_pipe={quic_state:?}",
            loss * 100.0,
            r.bulk[0] as f64 * 8.0 / (cut - warm) / 1e6,
            r.bulk[1] as f64 * 8.0 / (secs - cut) / 1e6,
            pct(&mut before, 0.99),
            pct(&mut after, 0.99),
            gap * 1e3,
            r.urgent.len(),
        );
    }
    end(client, server, quic).await;
}

fn main() {
    let args: Vec<String> = std::env::args()
        .skip(1)
        .filter(|a| !a.starts_with('-'))
        .collect();
    let want = |s: &str| args.is_empty() || args.iter().any(|a| a == s);
    let losses: Vec<f64> = std::env::var("QN_LOSS")
        .unwrap_or_else(|_| "0,0.1,1".into())
        .split(',')
        .filter_map(|v| v.parse::<f64>().ok())
        .map(|p| p / 100.0)
        .collect();
    let lanes: Vec<bool> = match std::env::var("QN_LANES").as_deref() {
        Ok("on") => vec![true],
        Ok("off") => vec![false],
        _ => vec![false, true],
    };
    let secs: f64 = env("QN_SECS", 20.0);
    let seeds: u64 = env("QN_SEEDS", 1);
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(env("QN_WORKERS", 4))
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let first: u64 = env("QN_SEED0", 1);
        for seed in first..first + seeds {
            for &loss in &losses {
                for &l in &lanes {
                    if want("flows") {
                        run_flows(loss, l, seed, secs).await;
                    }
                    if want("bulk") {
                        run_bulk(loss, l, seed, secs).await;
                    }
                }
                if want("failover") && !args.is_empty() {
                    run_failover(loss, seed, secs).await;
                }
            }
        }
    });
    // Sessions and relays of the runs are left to the process's end.
    rt.shutdown_timeout(Duration::from_secs(1));
}
