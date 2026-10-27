//! QUIC 0-RTT as carrier early data (SPEC.md Section 6.1.2): a client
//! that resumes a TLS session sends its first records as 0-RTT data under
//! the server's remembered parameters; the server sees the streams opened
//! in it as replayable until the handshake completes; a server that
//! rejects 0-RTT (here, a new server that cannot read the ticket) gets
//! everything again on a new stream, and no stream fails.

use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use zmux::{Config, EarlyData, Listener, ListenerConfig, Session};
use zmux_quinn::{Options, ParameterMemory};

struct Tls {
    der: CertificateDer<'static>,
    key: PrivatePkcs8KeyDer<'static>,
}

fn tls() -> Tls {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    Tls {
        der: CertificateDer::from(cert.cert.der().to_vec()),
        key: PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()),
    }
}

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

fn early() -> Config {
    let mut c = Config::default();
    c.early_data = EarlyData::default().with_carrier_early_data(true);
    c
}

/// A server on `addr` (any port when 0) that accepts 0-RTT for sessions
/// allowing carrier early data.
fn server(t: &Tls, addr: std::net::SocketAddr, opts: &Options) -> (quinn::Endpoint, Listener) {
    let tls = rustls::ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![t.der.clone()], PrivateKeyDer::Pkcs8(t.key.clone_key()))
        .unwrap();
    let config = zmux_quinn::server_config(tls, opts).unwrap();
    // A fixed address may still be held for a moment by the tasks of a
    // server just closed on it.
    let mut tries = 0;
    let ep = loop {
        match quinn::Endpoint::server(config.clone(), addr) {
            Ok(ep) => break ep,
            Err(e) if e.kind() == std::io::ErrorKind::AddrInUse && tries < 100 => {
                tries += 1;
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(e) => panic!("bind {addr}: {e}"),
        }
    };
    let listener = Listener::new(early(), ListenerConfig::default());
    tokio::spawn(zmux_quinn::serve(
        listener.clone(),
        ep.clone(),
        opts.clone(),
    ));
    (ep, listener)
}

fn client(t: &Tls, opts: &Options) -> quinn::Endpoint {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(t.der.clone()).unwrap();
    let tls = rustls::ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let mut ep = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    ep.set_default_client_config(zmux_quinn::client_config(tls, opts).unwrap());
    ep
}

/// A request and its echo over a new stream; returns whether the server's
/// stream was replayable when it took it.
async fn exchange(c: &Session, s: &Listener, msg: &[u8]) -> bool {
    let (mut send, mut recv) = c.open_bi().await.unwrap();
    send.write_all(msg).await.unwrap();
    send.finish().unwrap();
    let server = tokio::time::timeout(Duration::from_secs(5), s.accept())
        .await
        .unwrap()
        .unwrap();
    let (mut ss, mut sr) = server.accept_bi().await.unwrap();
    let replayable = sr.is_replayable();
    let got = sr.read_to_end(1 << 16).await.unwrap();
    assert_eq!(got, msg);
    ss.write_all(&got).await.unwrap();
    ss.finish().unwrap();
    assert_eq!(recv.read_to_end(1 << 16).await.unwrap(), msg);
    // Once the handshake completed, nothing is replayable any more.
    tokio::time::timeout(Duration::from_secs(5), async {
        while sr.is_replayable() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    replayable
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn resumed_connections_send_0rtt_and_streams_are_replayable() {
    let t = tls();
    let memory = ParameterMemory::new();
    let opts = Options::default().with_zero_rtt(memory.clone());
    let (ep, listener) = server(&t, "127.0.0.1:0".parse().unwrap(), &opts);
    let addr = ep.local_addr().unwrap();
    let c_ep = client(&t, &opts);
    // A full handshake: the server's parameters are kept.
    let (first, report) = zmux_quinn::connect_with_report(&c_ep, addr, "localhost", &opts, early())
        .await
        .unwrap();
    assert!(!report.sent() && report.accepted().is_none());
    assert!(!exchange(&first, &listener, b"first").await);
    assert!(memory.get("localhost").is_some());
    first.close(0u32.into(), b"");
    // Resumed: the request goes as 0-RTT data.
    let (second, report) =
        zmux_quinn::connect_with_report(&c_ep, addr, "localhost", &opts, early())
            .await
            .unwrap();
    assert!(exchange(&second, &listener, b"second, in 0-RTT").await);
    assert!(report.sent() && report.accepted() == Some(true) && !report.rewritten());
    second.close(0u32.into(), b"");
    listener.close();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_rejected_0rtt_is_sent_again_and_no_stream_fails() {
    let t = tls();
    let memory = ParameterMemory::new();
    let opts = Options::default().with_zero_rtt(memory.clone());
    let (ep, listener) = server(&t, "127.0.0.1:0".parse().unwrap(), &opts);
    let addr = ep.local_addr().unwrap();
    let c_ep = client(&t, &opts);
    let first = zmux_quinn::connect(&c_ep, addr, "localhost", &opts, early())
        .await
        .unwrap();
    exchange(&first, &listener, b"first").await;
    first.close(0u32.into(), b"");
    listener.close();
    ep.close(0u32.into(), b"");
    ep.wait_idle().await;
    drop(ep);
    // A new server on the same address cannot read the old ticket: it
    // rejects the 0-RTT data.
    let (_ep2, listener2) = server(&t, addr, &opts);
    let (second, report) =
        zmux_quinn::connect_with_report(&c_ep, addr, "localhost", &opts, early())
            .await
            .unwrap();
    assert!(!exchange(&second, &listener2, b"sent again after the rejection").await);
    assert!(report.sent() && report.accepted() == Some(false) && report.rewritten());
    second.close(0u32.into(), b"");
    listener2.close();
}

#[test]
fn parameter_memory_capacity_forgets_the_oldest_name() {
    let tp = zmux::proto::session::SessionCore::new(
        Config::default(),
        zmux::proto::session::RoleConfig::Initiator,
        None,
        std::time::Instant::now(),
    )
    .unwrap()
    .local_parameters();
    let m = ParameterMemory::with_capacity(2);
    m.set("a", tp.clone());
    m.set("b", tp.clone());
    m.set("a", tp.clone());
    m.set("c", tp.clone());
    assert_eq!(m.len(), 2);
    assert!(m.get("b").is_none() && m.get("a").is_some() && m.get("c").is_some());
    m.clear();
    assert!(m.is_empty());
}
