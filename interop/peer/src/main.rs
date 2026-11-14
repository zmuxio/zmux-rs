//! A scripted zmux responder for interoperability tests with the other
//! zmux implementations (Java, Go) over TCP.
//!
//! Usage: `zmux-interop-peer server [addr]` (prints `LISTEN <addr>`, serves
//! one session) or `zmux-interop-peer client <addr>`; `mp-server`/`mp-client`
//! for multipath over TCP; `quic-server [n]` (serves `n` sessions over QUIC,
//! 0-RTT for resumed ones) and `quic-client <addr>` (a session, then a
//! resumed one whose first stream, OPEN_INFO `early`, goes in 0-RTT); both
//! take a last argument `exporter` for the join secret from the exporter
//! alone, and then print `KEYS <hex>` for each session.
//!
//! `wss-server` and `wss-client <addr>` run the TLS modes' sessions over
//! WebSocket over TLS 1.3 (`wss://<addr>/zmux`), the join a further
//! WebSocket.
//!
//! `seal-server <profiles> [addr]` serves one session over the secure
//! carrier's Establish on TCP, accepting the comma-separated Profiles, those
//! without a pre-shared key included; `seal-client <addr> <profile>` runs
//! Establish with that Profile alone and prints `PROFILE <n>`; both print
//! `KEYS <hex>`.
//! The node's static key is 32 bytes of 0x5a, pinned by the client; the Handle
//! and pre-shared key derive from the multipath test PSK with domain `interop`.
//!
//! `matrix-server <scenario>` and `matrix-client <scenario> <addr> [...]` run
//! one scenario of the secure carrier's matrix, as
//! `zmux-spec/interop/seal-matrix/matrix.py` defines them (`src/matrix.rs`).
//!
//! The peer under test drives; this side answers. A bidirectional stream
//! carries its command in the stream preamble (OPEN_INFO):
//!
//! - `echo`: echo the data, then FIN;
//! - `info`: reply with `info=<open info>;prio=<u>,<i>` (the PRIORITY TLV);
//! - `reset`: read until the peer's reset and reply `reset=<code>`;
//! - `stop:<code>`: stop reading with `code`, then reply `stopped`;
//! - `sendreset:<code>`: write 1000 bytes, then reset with `code`;
//! - `open-bidi:<text>`: open a bidirectional stream with OPEN_INFO `back`,
//!   write `<text>`, FIN, read the answer and reply `opened=<answer>`;
//! - `open-uni:<text>`: open a unidirectional stream carrying `<text>`;
//! - `dgram`: echo the stream's datagrams (context + 1) until FIN;
//! - `goaway:<code>`: start a graceful shutdown with `code`; reply `draining`;
//! - `early`: reply `early=<data>;replayable=<bool>`;
//! - `close:<code>:<reason>`: consume FIN, then close without a stream reply
//!   (QUIC modes: reply `closing` first).
//!
//! Unidirectional streams are echoed on a new unidirectional stream, and
//! session datagrams are echoed. The process exits when the session ends and
//! prints `CLOSED <reason>`.

mod matrix;

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use bytes::Bytes;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use zmux::sched::Scheduler;
use zmux::{
    Config, Listener, ListenerConfig, PipeAuth, PipeOptions, Preamble, RecvStream, SendStream,
    Session, StreamError, VarInt,
};

fn config(multipath: bool) -> Config {
    let mut c = Config::default();
    c.enable_datagrams = true;
    c.max_incoming_uni_streams = zmux::UniCredit::Limit(16);
    if multipath {
        c.max_pipes = 4;
        c.pipe_auth = PipeAuth::psk(b"zmux interop pre-shared key 0123".to_vec()).with_end_to_end();
        c.allow_record_mode = Some(zmux::proto::session::AllowRecordMode::new(|_, _, _| true));
    }
    c
}

/// The QUIC modes' sessions: multipath (PSK), carrier early data.
fn quic_config(exporter: bool) -> Config {
    let mut c = config(true);
    c.early_data = zmux::EarlyData::for_zmux_peer().with_carrier_early_data(true);
    if exporter {
        c.pipe_auth = PipeAuth::exporter().with_end_to_end();
        c.allow_record_mode = Some(zmux::proto::session::AllowRecordMode::new(|_, _, _| true));
    }
    c
}

fn quic_options(memory: &zmux_quinn::ParameterMemory) -> zmux_quinn::Options {
    zmux_quinn::Options::new()
        .with_windows(zmux_quinn::LaneWindows::default().with_lanes(64))
        .with_zero_rtt(memory.clone())
}

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// Whether `close` replies `closing` before it closes (the QUIC drivers'
/// contract).
static CLOSE_REPLY: AtomicBool = AtomicBool::new(false);

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() {
    tokio::time::timeout(Duration::from_secs(90), run())
        .await
        .expect("interop peer deadline");
}

async fn run() {
    let args: Vec<String> = std::env::args().collect();
    let mode = args.get(1).map(String::as_str).unwrap_or("server");
    let mut endpoint = None;
    let mut serving = None;
    let session = match mode {
        "matrix-server" | "matrix-client" => {
            matrix::main(mode == "matrix-server", &args[2..]).await
        }
        "quic-server" => {
            let n: usize = args.get(2).and_then(|a| a.parse().ok()).unwrap_or(1);
            return quic_server(n, args.get(3).is_some_and(|a| a == "exporter")).await;
        }
        "quic-client" => {
            let addr = args.get(2).expect("address").parse().expect("address");
            return quic_client(addr, args.get(3).is_some_and(|a| a == "exporter")).await;
        }
        "server" => {
            let addr = args.get(2).map(String::as_str).unwrap_or("127.0.0.1:0");
            let listener = TcpListener::bind(addr).await.expect("bind");
            println!("LISTEN {}", listener.local_addr().expect("addr"));
            let (tcp, _) = listener.accept().await.expect("accept");
            Session::accept(zmux::PipeIo::from_tcp(tcp), config(false))
                .await
                .expect("establish")
        }
        "client" => {
            let addr = args.get(2).expect("address");
            let tcp = TcpStream::connect(addr).await.expect("connect");
            Session::connect(zmux::PipeIo::from_tcp(tcp), config(false))
                .await
                .expect("establish")
        }
        "mp-server" => {
            let addr = args.get(2).map(String::as_str).unwrap_or("127.0.0.1:0");
            let tcp = TcpListener::bind(addr).await.expect("bind");
            println!("LISTEN {}", tcp.local_addr().expect("addr"));
            let listener = Listener::new(config(true), ListenerConfig::default())
                .expect("valid listener configuration");
            let task = tokio::spawn(listener.clone().serve(tcp));
            let session = listener.accept().await.expect("accept session");
            endpoint = Some(listener);
            serving = Some(task);
            session
        }
        "mp-client" => {
            let addr = args.get(2).expect("address");
            let tcp = TcpStream::connect(addr).await.expect("connect");
            let session = Session::connect(zmux::PipeIo::from_tcp(tcp), config(true))
                .await
                .expect("establish");
            let joined = TcpStream::connect(addr).await.expect("connect joined pipe");
            let pipe = session
                .begin_add_pipe(
                    zmux::PipeIo::from_tcp(joined),
                    PipeOptions::default().with_record_mode(zmux::proto::seal::RecordMode::Trusted),
                )
                .expect("add pipe");
            let ready = tokio::time::timeout(Duration::from_secs(5), async {
                loop {
                    if pipe
                        .stats()
                        .is_some_and(|p| p.outbound == Some(zmux::OutboundState::Active))
                    {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(2)).await;
                }
            })
            .await;
            assert!(
                ready.is_ok(),
                "joined pipe not active: {:?}",
                session.pipe_stats()
            );
            session
        }
        "seal-server" => {
            let profiles = args.get(2).expect("profiles");
            let addr = args.get(3).map(String::as_str).unwrap_or("127.0.0.1:0");
            let (session, listener, task) = seal_server(profiles, addr).await;
            endpoint = Some(listener);
            serving = Some(task);
            session
        }
        "seal-client" => {
            let addr = args.get(2).expect("address");
            let profile = args.get(3).expect("profile").parse().expect("profile");
            seal_client(addr, profile).await
        }
        "tls-server" => {
            let (session, listener) = tls_server().await;
            endpoint = Some(listener);
            session
        }
        "tls-client" | "tls-split-client" => {
            let addr = args.get(2).expect("address");
            tls_client(addr, mode == "tls-split-client").await
        }
        "wss-server" => {
            let (session, listener, task) = wss_server().await;
            endpoint = Some(listener);
            serving = Some(task);
            session
        }
        "wss-client" => {
            let addr = args.get(2).expect("address");
            wss_client(addr).await
        }
        other => panic!("unknown mode {other}"),
    };
    serve(session).await;
    if let Some(listener) = endpoint {
        listener.close();
    }
    if let Some(task) = serving {
        task.await.expect("listener task");
    }
}

async fn quic_server(n: usize, exporter: bool) {
    CLOSE_REPLY.store(true, Ordering::Relaxed);
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).expect("cert");
    let der = CertificateDer::from(cert.cert.der().to_vec());
    let key = PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der());
    let mut tls = rustls::ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("tls")
        .with_no_client_auth()
        .with_single_cert(vec![der], PrivateKeyDer::Pkcs8(key))
        .expect("tls");
    tls.alpn_protocols = zmux::alpn_protocols(&[]);
    let opts = quic_options(&zmux_quinn::ParameterMemory::new());
    let sc = zmux_quinn::server_config(tls, &opts).expect("server config");
    let ep = quinn::Endpoint::server(sc, "127.0.0.1:0".parse().unwrap()).expect("bind");
    println!("LISTEN {}", ep.local_addr().expect("addr"));
    let listener = Listener::new(quic_config(exporter), ListenerConfig::default())
        .expect("valid listener configuration");
    let task = tokio::spawn(zmux_quinn::serve(listener.clone(), ep.clone(), opts, None));
    for _ in 0..n {
        let s = listener.accept().await.expect("accept session");
        if exporter {
            print_keys_when_ready(s.clone());
        }
        serve(s).await;
    }
    listener.close();
    task.abort();
    linger(ep).await;
}

async fn quic_client(addr: SocketAddr, exporter: bool) {
    CLOSE_REPLY.store(true, Ordering::Relaxed);
    let mut tls = rustls::ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("tls")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerify))
        .with_no_client_auth();
    tls.alpn_protocols = zmux::alpn_protocols(&[]);
    let memory = zmux_quinn::ParameterMemory::new();
    let opts = quic_options(&memory);
    let mut ep = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).expect("bind");
    ep.set_default_client_config(zmux_quinn::client_config(tls, &opts).expect("client config"));
    let s = zmux_quinn::connect(&ep, addr, "localhost", &opts, quic_config(exporter))
        .await
        .expect("connect");
    if exporter {
        print_keys_when_ready(s.clone());
    }
    serve(s).await;
    let (s, report) =
        zmux_quinn::connect_with_report(&ep, addr, "localhost", &opts, quic_config(exporter))
            .await
            .expect("connect resumed");
    if exporter {
        print_keys_when_ready(s.clone());
    }
    let (mut send, mut recv) = s
        .open_bi_with(&Preamble::new().with_info(Bytes::from_static(b"early")))
        .await
        .expect("open");
    send.write_all(b"early-data").await.expect("write");
    send.finish().expect("finish");
    let got = recv.read_to_end(1 << 20).await.unwrap_or_default();
    println!(
        "EARLY sent={} accepted={:?} reply={}",
        report.sent(),
        report.accepted(),
        String::from_utf8_lossy(&got)
    );
    serve(s).await;
    linger(ep).await;
}

/// The TLS modes' sessions: multipath, the join secret from the exporter of
/// the bootstrap carrier alone.
fn tls_config() -> Config {
    let mut c = config(true);
    c.pipe_auth = PipeAuth::exporter().with_end_to_end();
    c.allow_record_mode = Some(zmux::proto::session::AllowRecordMode::new(|_, _, _| true));
    c
}

/// The pairing token of the split bootstrap of the TLS modes. Each TCP
/// connection's first byte in TLS says what it is: `B` a bootstrap carrier,
/// `J` a join, `U` the uplink and `D` the downlink of a split bootstrap.
const PAIR: &[u8; 16] = b"zmux split pair!";

/// The host's exporter label: both ends print and compare its value.
const APP_LABEL: &str = "EXPORTER-interop-app";

/// The exporter of a half that left its connection (the connection stays
/// with the half's reader or writer): the values the session asks for,
/// read after the handshake.
fn half_exporter<C>(
    conn: &rustls::ConnectionCommon<C>,
) -> impl Fn(&str, &[u8], &mut [u8]) -> bool + Send + Sync + 'static {
    let value = |label: &str, len: usize| {
        let mut out = vec![0; len];
        conn.export_keying_material(&mut out, label.as_bytes(), Some(b""))
            .expect("exporter");
        out
    };
    let session = value("EXPORTER-zmux-session", 32);
    let app = value(APP_LABEL, 16);
    move |label, context, out| {
        assert!(context.is_empty());
        let v = match label {
            "EXPORTER-zmux-session" => &session,
            APP_LABEL => &app,
            other => panic!("exporter label {other}"),
        };
        out.copy_from_slice(v);
        true
    }
}

fn print_keys(session: &Session) {
    let v = session
        .export_keying_material(APP_LABEL, b"", 16)
        .expect("export");
    let hex: String = v.iter().map(|b| format!("{b:02x}")).collect();
    println!("KEYS {hex}");
}

/// Prints the keys once the carrier's handshake gives them (a session on
/// early data starts before it completes).
fn print_keys_when_ready(session: Session) {
    tokio::spawn(async move {
        while session.export_keying_material(APP_LABEL, b"", 16).is_err() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        print_keys(&session);
    });
}

const SEAL_NODE: [u8; 32] = [0x5a; 32];

fn seal_keys() -> zmux_seal::HandlePsk {
    zmux_seal::derive_handle_psk(b"zmux interop pre-shared key 0123", b"interop", b"")
        .expect("derive")
}

/// The secure carrier gives the session its secret: no pipe authentication is set.
fn seal_config() -> Config {
    config(false)
}

struct SealGate;

impl zmux_seal::Gate for SealGate {
    fn resolve<'a>(
        &'a self,
        handle: &'a [u8],
        _: Option<SocketAddr>,
    ) -> zmux_seal::BoxFuture<'a, Result<Vec<u8>, zmux_seal::VerifyError>> {
        Box::pin(async move {
            let k = seal_keys();
            if handle == k.handle {
                Ok(k.psk)
            } else {
                Err(zmux_seal::VerifyError::rejected("unknown handle"))
            }
        })
    }
    fn credential<'a>(
        &'a self,
        _: &'a [u8],
        _: zmux_seal::Profile,
        _: &'a [u8],
        _: Option<SocketAddr>,
    ) -> zmux_seal::BoxFuture<'a, Result<Option<zmux_seal::Credential>, zmux_seal::VerifyError>>
    {
        Box::pin(async { Ok(None) })
    }
    fn commit<'a>(
        &'a self,
        _: zmux_seal::Admission<'a>,
        _: Option<SocketAddr>,
    ) -> zmux_seal::BoxFuture<'a, Result<zmux::AdmittedValue, zmux_seal::VerifyError>> {
        Box::pin(async { Ok(Arc::new(()) as zmux::AdmittedValue) })
    }
}

async fn seal_server(
    profiles: &str,
    addr: &str,
) -> (Session, Listener, tokio::task::JoinHandle<()>) {
    let server = zmux_seal::ServerConfig::new(
        Arc::new(SealGate),
        SEAL_NODE,
        zmux_seal::ServerOptions {
            accepted_profiles: profiles
                .split(',')
                .map(|p| p.parse().expect("profile"))
                .collect(),
            ..Default::default()
        },
    )
    .expect("valid server configuration");
    let tcp = TcpListener::bind(addr).await.expect("bind");
    println!("LISTEN {}", tcp.local_addr().expect("addr"));
    let mut lc = ListenerConfig::default();
    lc.inbound_transform = Some(server.transform());
    let listener = Listener::new(seal_config(), lc).expect("listener");
    let task = tokio::spawn(listener.clone().serve(tcp));
    let session = listener.accept().await.expect("accept session");
    print_keys_when_ready(session.clone());
    (session, listener, task)
}

async fn seal_client(addr: &str, profile: u64) -> Session {
    let node = x25519_dalek_public(SEAL_NODE);
    let profile_has_psk = zmux_seal::Profile::from_value(profile)
        .expect("profile")
        .psk_len()
        .is_some();
    let k = seal_keys();
    let pin = zmux_seal::PinVerifier::new(zmux_seal::key_id(1, &node));
    let mut cfg = zmux_seal::ClientConfig {
        verifier: Some(Arc::new(pin)),
        allowed_profiles: vec![profile],
        ..Default::default()
    };
    if profile_has_psk {
        cfg.handle = k.handle;
        cfg.psk = k.psk;
    }
    let tcp = TcpStream::connect(addr).await.expect("connect");
    let (p, peer) = zmux_seal::establish(zmux::PipeIo::from_tcp(tcp), &cfg)
        .await
        .expect("seal establish");
    println!("PROFILE {}", peer.profile);
    let session = Session::connect(p, seal_config()).await.expect("establish");
    print_keys_when_ready(session.clone());
    session
}

/// The X25519 public key of a static secret: the node's key as a client pins it.
fn x25519_dalek_public(secret: [u8; 32]) -> Vec<u8> {
    x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(secret))
        .as_bytes()
        .to_vec()
}

/// A listener for the TLS modes, and the session it starts: on a
/// bidirectional bootstrap carrier and a join, or a split bootstrap and a
/// join, as the client's first bytes say.
async fn tls_server() -> (Session, Listener) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).expect("cert");
    let der = CertificateDer::from(cert.cert.der().to_vec());
    let key = PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der());
    let tls = rustls::ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("tls")
        .with_no_client_auth()
        .with_single_cert(vec![der], PrivateKeyDer::Pkcs8(key))
        .expect("tls");
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls));
    let tcp = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    println!("LISTEN {}", tcp.local_addr().expect("addr"));
    let listener = Listener::new(tls_config(), ListenerConfig::default())
        .expect("valid listener configuration");
    let handler = listener.clone();
    tokio::spawn(async move {
        while let Ok((tcp, peer)) = tcp.accept().await {
            let (acceptor, listener) = (acceptor.clone(), handler.clone());
            tokio::spawn(async move {
                let mut tls = acceptor.accept(tcp).await.expect("handshake");
                let mut kind = [0];
                tls.read_exact(&mut kind).await.expect("kind");
                let mut hint = zmux::PipeHint::from_peer(peer);
                let io = match kind[0] {
                    k @ (b'U' | b'D') => {
                        hint.pair = Some(PAIR.to_vec());
                        let exporter = half_exporter(tls.get_ref().1);
                        let (r, w) = tokio::io::split(tls);
                        let io = if k == b'U' {
                            zmux::PipeIo::reader(r).with_partial_reads()
                        } else {
                            zmux::PipeIo::writer(w)
                        };
                        io.with_exporter(exporter)
                    }
                    _ => zmux_rustls::over_tcp(tls),
                };
                let _ = listener.handle_pipe(io, hint).await;
            });
        }
    });
    let session = listener.accept().await.expect("accept session");
    session.established().await.expect("established");
    print_keys(&session);
    (session, listener)
}

/// A self-signed certificate for `localhost`, offering `alpn`.
fn tls_server_config(alpn: &[&[u8]]) -> rustls::ServerConfig {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).expect("cert");
    let der = CertificateDer::from(cert.cert.der().to_vec());
    let key = PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der());
    let mut tls = rustls::ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("tls")
        .with_no_client_auth()
        .with_single_cert(vec![der], PrivateKeyDer::Pkcs8(key))
        .expect("tls");
    tls.alpn_protocols = alpn.iter().map(|a| a.to_vec()).collect();
    tls
}

/// TLS 1.3 to a self-signed peer, unverified, offering `alpn`.
fn tls_client_config(alpn: &[&[u8]]) -> rustls::ClientConfig {
    let mut tls = rustls::ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("tls")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerify))
        .with_no_client_auth();
    tls.alpn_protocols = alpn.iter().map(|a| a.to_vec()).collect();
    tls
}

/// WebSocket over TLS 1.3 (`wss://`, any path): a listener whose carriers
/// have their connection's exporter, the TLS modes' configuration, and
/// the session it starts; a join arrives as a further WebSocket.
async fn wss_server() -> (Session, Listener, tokio::task::JoinHandle<()>) {
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls_server_config(&[b"http/1.1"])));
    let tcp = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    println!("LISTEN {}", tcp.local_addr().expect("addr"));
    let listener = Listener::new(tls_config(), ListenerConfig::default())
        .expect("valid listener configuration");
    let task = tokio::spawn(zmux_websocket::serve_tls(
        listener.clone(),
        tcp,
        acceptor,
        zmux_websocket::Options::default(),
    ));
    let session = listener.accept().await.expect("accept session");
    session.established().await.expect("established");
    print_keys(&session);
    (session, listener, task)
}

/// A session over `wss://<addr>/zmux` to a WebSocket peer, with a Bound
/// join on a further WebSocket.
async fn wss_client(addr: &str) -> Session {
    let tls = tokio_rustls::TlsConnector::from(Arc::new(tls_client_config(&[b"http/1.1"])));
    let url = format!("wss://{addr}/zmux");
    let options = zmux_websocket::Options::default();
    let boot = zmux_websocket::dial_tls(url.as_str(), &tls, &options)
        .await
        .expect("dial");
    let session = Session::connect(boot, tls_config())
        .await
        .expect("establish");
    session.established().await.expect("established");
    print_keys(&session);
    let join = zmux_websocket::dial_tls(url.as_str(), &tls, &options)
        .await
        .expect("dial join");
    let pipe = session
        .begin_add_pipe(
            join,
            PipeOptions::default().with_record_mode(zmux::proto::seal::RecordMode::Bound),
        )
        .expect("add pipe");
    tokio::time::timeout(Duration::from_secs(10), pipe.joined())
        .await
        .expect("joined in time")
        .expect("joined");
    session
}

/// A session over TLS to a `tls` peer, with a Bound join on a
/// further connection.
async fn tls_client(addr: &str, split: bool) -> Session {
    let tls = Arc::new(
        rustls::ClientConfig::builder_with_provider(provider())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .expect("tls")
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerify))
            .with_no_client_auth(),
    );
    let dial = async |kind: u8| {
        let tcp = TcpStream::connect(addr).await.expect("connect");
        let name = rustls::pki_types::ServerName::try_from("localhost").expect("name");
        let mut s = tokio_rustls::TlsConnector::from(tls.clone())
            .connect(name, tcp)
            .await
            .expect("handshake");
        s.write_all(&[kind]).await.expect("kind");
        s
    };
    let boot = if split {
        let up = dial(b'U').await;
        let down = dial(b'D').await;
        let (up_exporter, down_exporter) = (
            half_exporter(up.get_ref().1),
            half_exporter(down.get_ref().1),
        );
        let (_, up_w) = tokio::io::split(up);
        let (down_r, _) = tokio::io::split(down);
        zmux::PipeIo::split_bootstrap(
            zmux::PipeIo::writer(up_w).with_exporter(up_exporter),
            zmux::PipeIo::reader(down_r)
                .with_partial_reads()
                .with_exporter(down_exporter),
        )
    } else {
        zmux_rustls::over_tcp(dial(b'B').await)
    };
    let session = Session::connect(boot, tls_config())
        .await
        .expect("establish");
    session.established().await.expect("established");
    print_keys(&session);
    let pipe = session
        .begin_add_pipe(
            zmux_rustls::over_tcp(dial(b'J').await),
            PipeOptions::default().with_record_mode(zmux::proto::seal::RecordMode::Bound),
        )
        .expect("add pipe");
    tokio::time::timeout(Duration::from_secs(10), pipe.joined())
        .await
        .expect("joined in time")
        .expect("joined");
    session
}

/// Closes the endpoint once the last session's close had time to reach the
/// peer: closing the connections at once would overtake it.
async fn linger(ep: quinn::Endpoint) {
    tokio::time::sleep(Duration::from_millis(300)).await;
    ep.close(0u32.into(), b"");
    ep.wait_idle().await;
}

/// Accepts the server's certificate unverified: a self-signed one of a
/// local test.
#[derive(Debug)]
struct NoVerify;

impl rustls::client::danger::ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &rustls::pki_types::ServerName<'_>,
        _: &[u8],
        _: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            m,
            c,
            d,
            &provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            m,
            c,
            d,
            &provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Answers the session's streams and datagrams until it ends.
async fn serve(session: Session) {
    println!("ESTABLISHED");
    {
        let s = session.clone();
        tokio::spawn(async move {
            while let Ok((send, recv)) = s.accept_bi().await {
                let s = s.clone();
                tokio::spawn(async move { bidi(s, send, recv).await });
            }
        });
    }
    {
        let s = session.clone();
        tokio::spawn(async move {
            while let Ok(mut recv) = s.accept_uni().await {
                let s = s.clone();
                tokio::spawn(async move {
                    if let Ok(data) = recv.read_to_end(1 << 24).await
                        && let Ok(mut send) = s.open_uni().await
                    {
                        let _ = send.write_all(&data).await;
                        let _ = send.finish();
                        let _ = send.stopped().await;
                    }
                });
            }
        });
    }
    {
        let s = session.clone();
        tokio::spawn(async move {
            while let Ok(d) = s.read_datagram().await {
                let _ = s.send_datagram(d);
            }
        });
    }
    // `wait` resolves once the session ended entirely (CONNECTION_CLOSE
    // written, the carriers half-closed and drained): exiting earlier could
    // reset a carrier before the peer read CONNECTION_CLOSE.
    let reason = session.closed().await;
    println!("CLOSED {reason}");
}

async fn reply(send: &mut SendStream, text: &str) {
    let _ = send.write_all(text.as_bytes()).await;
    let _ = send.finish();
    let _ = send.stopped().await;
}

async fn bidi(session: Session, mut send: SendStream, mut recv: RecvStream) {
    let cmd = recv
        .preamble()
        .info()
        .map(|b| String::from_utf8_lossy(b).into_owned())
        .unwrap_or_default();
    let (name, arg) = cmd.split_once(':').unwrap_or((cmd.as_str(), ""));
    match name {
        "echo" => {
            let mut buf = vec![0u8; 64 * 1024];
            loop {
                match recv.read(&mut buf).await {
                    Ok(Some(n)) => {
                        if send.write_all(&buf[..n]).await.is_err() {
                            return;
                        }
                    }
                    Ok(None) => break,
                    Err(_) => return,
                }
            }
            let _ = send.finish();
            let _ = send.stopped().await;
        }
        "info" => {
            let prio = recv
                .requested_priority()
                .map(|p| format!("{},{}", p.urgency(), p.incremental()))
                .unwrap_or_else(|| "none".into());
            let _ = recv.read_to_end(1 << 20).await;
            reply(&mut send, &format!("info={cmd};prio={prio}")).await;
        }
        "reset" => {
            let mut buf = vec![0u8; 4096];
            let text = loop {
                match recv.read(&mut buf).await {
                    Ok(Some(_)) => continue,
                    Ok(None) => break "fin".to_string(),
                    Err(StreamError::Reset { code, .. }) => break format!("reset={code}"),
                    Err(e) => break format!("error={e}"),
                }
            };
            reply(&mut send, &text).await;
        }
        "stop" => {
            let code: u64 = arg.parse().unwrap_or(0);
            let _ = recv.stop(VarInt::from_u64(code).unwrap_or(VarInt::ZERO));
            reply(&mut send, "stopped").await;
        }
        "sendreset" => {
            let code: u64 = arg.parse().unwrap_or(0);
            let _ = send.write_all(&[7u8; 1000]).await;
            tokio::time::sleep(Duration::from_millis(20)).await;
            let _ = send.reset(VarInt::from_u64(code).unwrap_or(VarInt::ZERO));
            let _ = recv.read_to_end(1 << 20).await;
        }
        "open-bidi" => {
            let text = match session
                .open_bi_with(&Preamble::new().with_info(Bytes::from_static(b"back")))
                .await
            {
                Ok((mut s2, mut r2)) => {
                    let _ = s2.write_all(arg.as_bytes()).await;
                    let _ = s2.finish();
                    match r2.read_to_end(1 << 20).await {
                        Ok(d) => format!("opened={}", String::from_utf8_lossy(&d)),
                        Err(e) => format!("error={e}"),
                    }
                }
                Err(e) => format!("error={e}"),
            };
            reply(&mut send, &text).await;
        }
        "open-uni" => {
            if let Ok(mut s2) = session.open_uni().await {
                let _ = s2.write_all(arg.as_bytes()).await;
                let _ = s2.finish();
                let _ = s2.stopped().await;
            }
            reply(&mut send, "sent").await;
        }
        "dgram" => {
            // Echoes `arg` stream datagrams (context + 1), then answers.
            let n: u64 = arg.parse().unwrap_or(1);
            for _ in 0..n {
                match recv.read_datagram().await {
                    Ok(d) => {
                        if send.send_datagram(d.context + 1, d.payload).is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
            let _ = recv.read_to_end(1 << 20).await;
            reply(&mut send, "dgram-done").await;
        }
        "schedule" => {
            assert_eq!(arg, "round-robin", "unknown scheduler");
            session.set_scheduler(Scheduler::SpreadRoundRobin);
            reply(&mut send, "scheduled").await;
        }
        "drop-bootstrap" => {
            let pipe = session
                .pipes()
                .into_iter()
                .find(|pipe| pipe.id().get() == 0)
                .expect("bootstrap pipe");
            pipe.abort().expect("abort bootstrap");
            reply(&mut send, "dropped").await;
        }
        "early" => {
            let replayable = recv.is_replayable();
            let d = recv.read_to_end(1 << 20).await.unwrap_or_default();
            reply(
                &mut send,
                &format!(
                    "early={};replayable={replayable}",
                    String::from_utf8_lossy(&d)
                ),
            )
            .await;
        }
        "goaway" => {
            let code: u64 = arg.parse().unwrap_or(0);
            let s = session.clone();
            tokio::spawn(async move {
                let _ = s
                    .shutdown(VarInt::from_u64(code).unwrap_or(VarInt::ZERO), b"drain")
                    .await;
            });
            let _ = recv.read_to_end(1 << 20).await;
            reply(&mut send, "draining").await;
        }
        "close" => {
            let (code, reason) = arg.split_once(':').unwrap_or((arg, ""));
            let code: u64 = code.parse().unwrap_or(0);
            let _ = recv.read_to_end(1 << 20).await;
            if CLOSE_REPLY.load(Ordering::Relaxed) {
                // The reply's FIN written before the close: QUIC streams
                // are independent, so the close could otherwise overtake it.
                reply(&mut send, "closing").await;
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            session.abort(
                VarInt::from_u64(code).unwrap_or(VarInt::ZERO),
                reason.as_bytes(),
            );
            // Returns once the abort's CONNECTION_CLOSE has been handed over.
            session.close().await;
        }
        other => {
            reply(&mut send, &format!("unknown={other}")).await;
        }
    }
}
