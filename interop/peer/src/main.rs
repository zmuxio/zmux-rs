//! A scripted zmux responder for interoperability tests with the other
//! zmux implementations (Java, Go) over TCP.
//!
//! Usage: `zmux-interop-peer server [addr]` (prints `LISTEN <addr>`, serves
//! one session) or `zmux-interop-peer client <addr>`; `mp-server`/`mp-client`
//! for multipath over TCP; `quic-server [n]` (serves `n` sessions over QUIC,
//! 0-RTT for resumed ones) and `quic-client <addr>` (a session, then a
//! resumed one whose first stream, OPEN_INFO `early`, goes in 0-RTT).
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

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use bytes::Bytes;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::net::{TcpListener, TcpStream};
use zmux::{
    Config, Listener, ListenerConfig, PipeAuth, PipeOptions, Policy, Preamble, RecvStream,
    SendStream, Session, StreamError, VarInt,
};

fn config(multipath: bool) -> Config {
    let mut c = Config::default();
    c.enable_datagrams = true;
    c.max_incoming_uni_streams = Some(16);
    if multipath {
        c.max_pipes = 4;
        c.pipe_auth = PipeAuth::psk(b"zmux interop pre-shared key 0123".to_vec());
    }
    c
}

/// The QUIC modes' sessions: multipath (PSK), carrier early data.
fn quic_config() -> Config {
    let mut c = config(true);
    c.early_data = zmux::EarlyData::for_zmux_peer().with_carrier_early_data(true);
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
        "quic-server" => {
            let n: usize = args.get(2).and_then(|a| a.parse().ok()).unwrap_or(1);
            return quic_server(n).await;
        }
        "quic-client" => {
            let addr = args.get(2).expect("address").parse().expect("address");
            return quic_client(addr).await;
        }
        "server" => {
            let addr = args.get(2).map(String::as_str).unwrap_or("127.0.0.1:0");
            let listener = TcpListener::bind(addr).await.expect("bind");
            println!("LISTEN {}", listener.local_addr().expect("addr"));
            let (tcp, _) = listener.accept().await.expect("accept");
            Session::accept(zmux::PipeIo::tcp(tcp), config(false))
                .await
                .expect("establish")
        }
        "client" => {
            let addr = args.get(2).expect("address");
            let tcp = TcpStream::connect(addr).await.expect("connect");
            Session::connect(zmux::PipeIo::tcp(tcp), config(false))
                .await
                .expect("establish")
        }
        "mp-server" => {
            let addr = args.get(2).map(String::as_str).unwrap_or("127.0.0.1:0");
            let tcp = TcpListener::bind(addr).await.expect("bind");
            println!("LISTEN {}", tcp.local_addr().expect("addr"));
            let listener = Listener::new(config(true), ListenerConfig::default());
            let task = tokio::spawn(listener.clone().serve(tcp));
            let session = listener.accept().await.expect("accept session");
            endpoint = Some(listener);
            serving = Some(task);
            session
        }
        "mp-client" => {
            let addr = args.get(2).expect("address");
            let tcp = TcpStream::connect(addr).await.expect("connect");
            let session = Session::connect(zmux::PipeIo::tcp(tcp), config(true))
                .await
                .expect("establish");
            let joined = TcpStream::connect(addr).await.expect("connect joined pipe");
            let pipe = session
                .add_pipe(zmux::PipeIo::tcp(joined), PipeOptions::default())
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

async fn quic_server(n: usize) {
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
    let listener = Listener::new(quic_config(), ListenerConfig::default());
    let task = tokio::spawn(zmux_quinn::serve(listener.clone(), ep.clone(), opts, None));
    for _ in 0..n {
        serve(listener.accept().await.expect("accept session")).await;
    }
    listener.close();
    task.abort();
    linger(ep).await;
}

async fn quic_client(addr: SocketAddr) {
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
    let s = zmux_quinn::connect(&ep, addr, "localhost", &opts, quic_config())
        .await
        .expect("connect");
    serve(s).await;
    let (s, report) = zmux_quinn::connect_with_report(&ep, addr, "localhost", &opts, quic_config())
        .await
        .expect("connect resumed");
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
                    Ok((ctx, d)) => {
                        if send.send_datagram(ctx + 1, d).is_err() {
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
            session.set_scheduler(Policy::SpreadRoundRobin);
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
            session.close(
                VarInt::from_u64(code).unwrap_or(VarInt::ZERO),
                reason.as_bytes(),
            );
        }
        other => {
            reply(&mut send, &format!("unknown={other}")).await;
        }
    }
}
