//! Heap per idle connection pair (both ends in this process) of the
//! carriers zmux runs over, and of zmux sessions over them: TCP loopback,
//! TLS 1.3 over TCP (rustls), a QUIC connection (quinn), and zmux over
//! each (over a QUIC bidirectional stream for QUIC), plus zmux over an
//! in-memory pipe. A zmux pair carries one request-response stream of
//! 300 bytes each way first (`ZMUX_CARRIER_NO_STREAM=1`: none, the
//! handshake only). Each row: `ZMUX_CARRIER_N` (default 200) pairs after a
//! warm-up of as many, established and with a small exchange each way,
//! the live heap above what it was before them, once right away and once
//! after `ZMUX_CARRIER_IDLE_MS` (default 1500) of idleness (zmux's idle
//! pipes give their buffers back after a second). Kernel socket memory is
//! not heap and not counted.
//!
//!   cargo run --release --manifest-path interop/carrier-mem/Cargo.toml [-- <row>...]

use std::alloc::{GlobalAlloc, Layout, System};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering::Relaxed};
use std::time::Duration;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use zmux::{Config, PipeIo, Session};

struct Counting;

static LIVE: AtomicI64 = AtomicI64::new(0);

// SAFETY: forwards to the system allocator unchanged.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        LIVE.fetch_add(l.size() as i64, Relaxed);
        // SAFETY: forwarded unchanged.
        unsafe { System.alloc(l) }
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

fn live() -> i64 {
    LIVE.load(Relaxed)
}

/// A self-signed certificate for `localhost`, and the TLS configurations
/// of both ends (TLS 1.3 only, ring).
struct Tls {
    server: Arc<rustls::ServerConfig>,
    client: Arc<rustls::ClientConfig>,
    cert: CertificateDer<'static>,
    key: PrivatePkcs8KeyDer<'static>,
}

impl Tls {
    fn new() -> Self {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let cert_der = cert.cert.der().clone();
        let key = PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der());
        let mut server = rustls::ServerConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![cert_der.clone()],
                PrivateKeyDer::Pkcs8(key.clone_key()),
            )
            .unwrap();
        server.alpn_protocols = vec![b"zmux".to_vec()];
        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert_der.clone()).unwrap();
        let mut client = rustls::ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        client.alpn_protocols = vec![b"zmux".to_vec()];
        Self {
            server: Arc::new(server),
            client: Arc::new(client),
            cert: cert_der,
            key,
        }
    }
}

/// Both ends of a QUIC bidirectional stream: (receive, send) each.
type QuicStreams = (
    (quinn::RecvStream, quinn::SendStream),
    (quinn::RecvStream, quinn::SendStream),
);

async fn tcp_pair(l: &TcpListener) -> (TcpStream, TcpStream) {
    let addr = l.local_addr().unwrap();
    let (a, b) = tokio::join!(TcpStream::connect(addr), l.accept());
    let (a, b) = (a.unwrap(), b.unwrap().0);
    a.set_nodelay(true).unwrap();
    b.set_nodelay(true).unwrap();
    (a, b)
}

/// 300 bytes each way, as a handshake's worth of traffic.
async fn exchange<A, B>(a: &mut A, b: &mut B)
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let mut buf = [0u8; 300];
    a.write_all(&[1; 300]).await.unwrap();
    a.flush().await.unwrap();
    b.read_exact(&mut buf).await.unwrap();
    b.write_all(&[2; 300]).await.unwrap();
    b.flush().await.unwrap();
    a.read_exact(&mut buf).await.unwrap();
}

/// The carriers and their shared state (listeners, endpoints, configs).
struct Env {
    tcp: TcpListener,
    connector: tokio_rustls::TlsConnector,
    acceptor: tokio_rustls::TlsAcceptor,
    quic_server: quinn::Endpoint,
    quic_client: quinn::Endpoint,
    zmux: Arc<Config>,
}

impl Env {
    async fn new() -> Self {
        let tls = Tls::new();
        let connector = tokio_rustls::TlsConnector::from(tls.client.clone());
        let acceptor = tokio_rustls::TlsAcceptor::from(tls.server.clone());
        let server_config = quinn::ServerConfig::with_single_cert(
            vec![tls.cert.clone()],
            PrivateKeyDer::Pkcs8(tls.key.clone_key()),
        )
        .unwrap();
        let quic_server =
            quinn::Endpoint::server(server_config, (Ipv4Addr::LOCALHOST, 0).into()).unwrap();
        let mut quic_client = quinn::Endpoint::client((Ipv4Addr::LOCALHOST, 0).into()).unwrap();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(tls.cert.clone()).unwrap();
        quic_client.set_default_client_config(
            quinn::ClientConfig::with_root_certificates(Arc::new(roots)).unwrap(),
        );
        Self {
            tcp: TcpListener::bind("127.0.0.1:0").await.unwrap(),
            connector,
            acceptor,
            quic_server,
            quic_client,
            zmux: Arc::new(Config::default()),
        }
    }

    async fn tls_pair(
        &self,
    ) -> (
        tokio_rustls::client::TlsStream<TcpStream>,
        tokio_rustls::server::TlsStream<TcpStream>,
    ) {
        let (a, b) = tcp_pair(&self.tcp).await;
        let name = ServerName::try_from("localhost").unwrap();
        let (c, s) = tokio::join!(self.connector.connect(name, a), self.acceptor.accept(b));
        (c.unwrap(), s.unwrap())
    }

    async fn quic_pair(&self) -> (quinn::Connection, quinn::Connection) {
        let addr: SocketAddr = self.quic_server.local_addr().unwrap();
        let connecting = self.quic_client.connect(addr, "localhost").unwrap();
        let (c, s) = tokio::join!(connecting, async {
            self.quic_server.accept().await.unwrap().await
        });
        (c.unwrap(), s.unwrap())
    }

    /// A new connection and a bidirectional stream of it, after 300
    /// bytes went each way on the stream (the server sees a stream once
    /// it has data).
    async fn quic_streams(&self) -> (quinn::Connection, quinn::Connection, QuicStreams) {
        let (c, s) = self.quic_pair().await;
        let mut buf = [0u8; 300];
        let (mut cs, mut cr) = c.open_bi().await.unwrap();
        cs.write_all(&[1; 300]).await.unwrap();
        let (mut ss, mut sr) = s.accept_bi().await.unwrap();
        sr.read_exact(&mut buf).await.unwrap();
        ss.write_all(&[2; 300]).await.unwrap();
        cr.read_exact(&mut buf).await.unwrap();
        (c, s, ((cr, cs), (sr, ss)))
    }

    async fn zmux_pair(&self, a: PipeIo, b: PipeIo) -> (Session, Session) {
        let server = tokio::spawn(Session::accept(b, self.zmux.clone()));
        let client = Session::connect(a, self.zmux.clone()).await.unwrap();
        let server = server.await.unwrap().unwrap();
        if std::env::var("ZMUX_CARRIER_NO_STREAM").is_ok() {
            return (client, server);
        }
        // A request-response, as the carrier rows' exchange.
        let (mut send, mut recv) = client.open_bi().await.unwrap();
        send.write_all(&[1; 300]).await.unwrap();
        send.finish().unwrap();
        let (mut ssend, mut srecv) = server.accept_bi().await.unwrap();
        srecv.read_to_end(1024).await.unwrap();
        ssend.write_all(&[2; 300]).await.unwrap();
        ssend.finish().unwrap();
        recv.read_to_end(1024).await.unwrap();
        (client, server)
    }

    /// One established, idle pair of `row`, kept alive by the returned
    /// value.
    async fn pair(&self, row: &str) -> Box<dyn std::any::Any + Send> {
        match row {
            "tcp" => {
                let (mut a, mut b) = tcp_pair(&self.tcp).await;
                exchange(&mut a, &mut b).await;
                Box::new((a, b))
            }
            "tls" => {
                let (mut a, mut b) = self.tls_pair().await;
                exchange(&mut a, &mut b).await;
                Box::new((a, b))
            }
            "quic" => Box::new(self.quic_streams().await),
            "zmux-mem" => {
                let (a, b) = tokio::io::duplex(1 << 20);
                Box::new(self.zmux_pair(PipeIo::new(a), PipeIo::new(b)).await)
            }
            "zmux-tcp" => {
                let (a, b) = tcp_pair(&self.tcp).await;
                Box::new(self.zmux_pair(PipeIo::tcp(a), PipeIo::tcp(b)).await)
            }
            "zmux-tls" => {
                let (a, b) = self.tls_pair().await;
                Box::new(self.zmux_pair(PipeIo::new(a), PipeIo::new(b)).await)
            }
            "zmux-quic" => {
                let (c, s, ((cr, cs), (sr, ss))) = self.quic_streams().await;
                let pair = self
                    .zmux_pair(PipeIo::from_halves(cr, cs), PipeIo::from_halves(sr, ss))
                    .await;
                Box::new((c, s, pair))
            }
            other => panic!("unknown row {other}"),
        }
    }
}

const ROWS: [&str; 7] = [
    "tcp",
    "tls",
    "quic",
    "zmux-mem",
    "zmux-tcp",
    "zmux-tls",
    "zmux-quic",
];

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() {
    let n: usize = std::env::var("ZMUX_CARRIER_N")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(200);
    let idle_ms: u64 = std::env::var("ZMUX_CARRIER_IDLE_MS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(1500);
    let filter: Vec<String> = std::env::args().skip(1).collect();
    let env = Env::new().await;
    for row in ROWS {
        if !filter.is_empty() && !filter.iter().any(|f| row == f) {
            continue;
        }
        // Warm-up: process-wide state (the runtime's, pools) is not the
        // pairs'.
        let mut warm = Vec::with_capacity(n);
        for _ in 0..n {
            warm.push(env.pair(row).await);
        }
        tokio::time::sleep(Duration::from_millis(1500)).await;
        drop(warm);
        tokio::time::sleep(Duration::from_millis(200)).await;
        let before = live();
        let mut v = Vec::with_capacity(n);
        for _ in 0..n {
            v.push(env.pair(row).await);
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
        let active = (live() - before) as f64 / n as f64;
        tokio::time::sleep(Duration::from_millis(idle_ms)).await;
        let idle = (live() - before) as f64 / n as f64;
        println!(
            "RESULT scen=carrier-mem row={row} pairs={n} heap_B_per_pair_active={active:.0} heap_B_per_pair_idle={idle:.0}"
        );
        drop(v);
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}
