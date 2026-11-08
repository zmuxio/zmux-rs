//! QUIC 0-RTT as carrier early data: a client
//! that resumes a TLS session sends its first records as 0-RTT data under
//! the server's remembered parameters; the server sees the streams opened
//! in it as replayable until the handshake completes; a server that
//! rejects 0-RTT (here, a new server that cannot read the ticket) gets
//! everything again on a new stream, and no stream fails.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
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

/// Carrier early data in a session offering multipath (PSK joins).
fn early_multipath() -> Config {
    let mut c = early();
    c.max_pipes = 4;
    c.pipe_auth =
        zmux::PipeAuth::psk(b"zero-rtt test pre-shared key 012".to_vec()).with_end_to_end();
    c
}

/// Carrier early data in a single-pipe session offering resume.
fn early_resume() -> Config {
    let mut c = early();
    c.resume_timeout = Some(Duration::from_secs(5));
    c.pipe_auth =
        zmux::PipeAuth::psk(b"zero-rtt test pre-shared key 012".to_vec()).with_end_to_end();
    c
}

/// A server on `addr` (any port when 0) that accepts 0-RTT for sessions
/// allowing carrier early data.
fn server(
    t: &Tls,
    addr: std::net::SocketAddr,
    opts: &Options,
    cfg: fn() -> Config,
) -> (quinn::Endpoint, Listener) {
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
    let listener =
        Listener::new(cfg(), ListenerConfig::default()).expect("valid listener configuration");
    tokio::spawn(zmux_quinn::serve(
        listener.clone(),
        ep.clone(),
        opts.clone(),
        None,
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
    // How the stream arrived stays true after the handshake.
    assert_eq!(sr.is_replayable(), replayable);
    replayable
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn resumed_connections_send_and_accept_0rtt() {
    let t = tls();
    let memory = ParameterMemory::new();
    let opts = Options::default().with_zero_rtt(memory.clone());
    let (ep, listener) = server(&t, "127.0.0.1:0".parse().unwrap(), &opts, early);
    let addr = ep.local_addr().unwrap();
    let c_ep = client(&t, &opts);
    // A full handshake: the server's parameters are kept.
    let (first, report) = zmux_quinn::connect_with_report(&c_ep, addr, "localhost", &opts, early())
        .await
        .unwrap();
    assert!(!report.sent() && report.accepted().is_none());
    assert!(!exchange(&first, &listener, b"first").await);
    assert!(memory.get("localhost").is_some());
    first.close(0u32.into(), b"").await;
    // Resumed: the request goes as 0-RTT data.
    let (second, report) =
        zmux_quinn::connect_with_report(&c_ep, addr, "localhost", &opts, early())
            .await
            .unwrap();
    // The handshake may complete before the application takes the stream.
    // Its current replayability is not evidence of whether 0-RTT was sent.
    exchange(&second, &listener, b"second, in 0-RTT").await;
    assert!(report.sent() && report.accepted() == Some(true) && !report.rewritten());
    second.close(0u32.into(), b"").await;
    listener.close();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_rejected_0rtt_is_sent_again_and_no_stream_fails() {
    rejected_0rtt_sent_again(early).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_rejected_0rtt_is_sent_again_with_multipath() {
    rejected_0rtt_sent_again(early_multipath).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_rejected_0rtt_is_sent_again_with_resume() {
    rejected_0rtt_sent_again(early_resume).await;
}

/// A server that cannot read the ticket rejects the 0-RTT data.
async fn rejected_0rtt_sent_again(cfg: fn() -> Config) {
    let t = tls();
    let memory = ParameterMemory::new();
    let opts = Options::default().with_zero_rtt(memory.clone());
    let (ep, listener) = server(&t, "127.0.0.1:0".parse().unwrap(), &opts, cfg);
    let addr = ep.local_addr().unwrap();
    let c_ep = client(&t, &opts);
    let first = zmux_quinn::connect(&c_ep, addr, "localhost", &opts, cfg())
        .await
        .unwrap();
    exchange(&first, &listener, b"first").await;
    first.close(0u32.into(), b"").await;
    listener.close();
    ep.close(0u32.into(), b"");
    ep.wait_idle().await;
    drop(ep);
    // A new server on the same address cannot read the old ticket: it
    // rejects the 0-RTT data.
    let (_ep2, listener2) = server(&t, addr, &opts, cfg);
    let (second, report) = zmux_quinn::connect_with_report(&c_ep, addr, "localhost", &opts, cfg())
        .await
        .unwrap();
    assert!(!exchange(&second, &listener2, b"sent again after the rejection").await);
    assert!(report.sent() && report.accepted() == Some(false) && report.rewritten());
    second.close(0u32.into(), b"").await;
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

/// Two servers sharing one TLS session store: `a` accepts 0-RTT, `b`
/// resumes the same sessions but refuses their early data.
/// Also returns how many sessions were resumed from the store.
fn sharing_servers(
    t: &Tls,
    opts: &Options,
    cfg: fn() -> Config,
) -> ([(quinn::Endpoint, Listener); 2], Arc<AtomicUsize>) {
    let store = Arc::new(Store {
        inner: rustls::server::ServerSessionMemoryCache::new(64),
        resumed: Arc::default(),
    });
    let resumed = store.resumed.clone();
    let make = |early: bool| {
        let mut tls = rustls::ServerConfig::builder_with_provider(provider())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![t.der.clone()], PrivateKeyDer::Pkcs8(t.key.clone_key()))
            .unwrap();
        tls.session_storage = store.clone();
        tls.max_early_data_size = if early { u32::MAX } else { 0 };
        let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls).unwrap();
        let mut c = quinn::ServerConfig::with_crypto(Arc::new(crypto));
        c.transport_config(Arc::new(opts.transport_config()));
        let ep = quinn::Endpoint::server(c, "127.0.0.1:0".parse().unwrap()).unwrap();
        let listener =
            Listener::new(cfg(), ListenerConfig::default()).expect("valid listener configuration");
        tokio::spawn(zmux_quinn::serve(
            listener.clone(),
            ep.clone(),
            opts.clone(),
            None,
        ));
        (ep, listener)
    };
    ([make(true), make(false)], resumed)
}

/// A session store counting the sessions it gave back for resumption.
#[derive(Debug)]
struct Store {
    inner: Arc<dyn rustls::server::StoresServerSessions>,
    resumed: Arc<AtomicUsize>,
}

impl rustls::server::StoresServerSessions for Store {
    fn put(&self, key: Vec<u8>, value: Vec<u8>) -> bool {
        self.inner.put(key, value)
    }
    fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.hit(self.inner.get(key))
    }
    fn take(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.hit(self.inner.take(key))
    }
    fn can_cache(&self) -> bool {
        self.inner.can_cache()
    }
}

impl Store {
    fn hit(&self, v: Option<Vec<u8>>) -> Option<Vec<u8>> {
        if v.is_some() {
            self.resumed.fetch_add(1, Ordering::Relaxed);
        }
        v
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_resumed_session_whose_0rtt_is_refused_carries_early_streams_once() {
    refused_carries_early_streams_once(early).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_refused_0rtt_with_multipath_carries_early_streams_once() {
    refused_carries_early_streams_once(early_multipath).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_refused_0rtt_with_resume_carries_early_streams_once() {
    refused_carries_early_streams_once(early_resume).await;
}

/// A server that resumes the TLS session but refuses its early data.
async fn refused_carries_early_streams_once(cfg: fn() -> Config) {
    let t = tls();
    let opts = Options::default().with_zero_rtt(ParameterMemory::new());
    let ([(a_ep, a), (b_ep, b)], resumed) = sharing_servers(&t, &opts, cfg);
    let c_ep = client(&t, &opts);
    let first = zmux_quinn::connect(&c_ep, a_ep.local_addr().unwrap(), "localhost", &opts, cfg())
        .await
        .unwrap();
    exchange(&first, &a, b"first").await;
    first.close(0u32.into(), b"").await;
    // `b` resumes the session of `a` and refuses its 0-RTT data.
    let (second, report) = zmux_quinn::connect_with_report(
        &c_ep,
        b_ep.local_addr().unwrap(),
        "localhost",
        &opts,
        cfg(),
    )
    .await
    .unwrap();
    // Streams written while 0-RTT is undecided: data and FIN, data and a
    // reset, data alone.
    let (mut fin, mut fin_r) = second.open_bi().await.unwrap();
    fin.write_all(b"data then fin").await.unwrap();
    fin.finish().unwrap();
    let (mut rst, _rst_r) = second.open_bi().await.unwrap();
    rst.write_all(b"data then reset").await.unwrap();
    let (mut open, mut open_r) = second.open_bi().await.unwrap();
    open.write_all(b"data, still open").await.unwrap();
    let server = tokio::time::timeout(Duration::from_secs(5), b.accept())
        .await
        .expect("no session on the refusing server")
        .unwrap();
    // The streams of a rejected 0-RTT are written again and may arrive in any order:
    // each is told by the start of its data, and `seen` holds them as the FIN stream,
    // the reset one and the open one.
    let mut seen: [Option<(_, _, [u8; 11])>; 3] = [None, None, None];
    for _ in 0..3 {
        let (ss, mut sr) = tokio::time::timeout(Duration::from_secs(5), server.accept_bi())
            .await
            .unwrap()
            .unwrap();
        let mut head = [0u8; 11];
        sr.read_exact(&mut head).await.unwrap();
        let at = match &head {
            b"data then f" => 0,
            b"data then r" => 1,
            b"data, still" => 2,
            other => panic!("an unknown stream: {other:?}"),
        };
        assert!(seen[at].is_none(), "stream {at} arrived twice");
        seen[at] = Some((ss, sr, head));
    }
    let mut seen = seen.map(Option::unwrap);
    // The rest of the data of each; the reset only after its data arrived, so the data
    // is known to be delivered before it.
    for (i, rest) in [&b"in"[..], b"eset", b" open"].into_iter().enumerate() {
        let mut buf = vec![0; rest.len()];
        seen[i].1.read_exact(&mut buf).await.unwrap();
        assert_eq!(buf, rest);
    }
    rst.reset(7u32.into()).unwrap();
    // FIN: nothing more after the data.
    assert_eq!(seen[0].1.read_to_end(1 << 16).await.unwrap(), b"");
    // Reset: the reading side sees it.
    assert!(seen[1].1.read_to_end(1 << 16).await.is_err());
    open.finish().unwrap();
    assert_eq!(seen[2].1.read_to_end(1 << 16).await.unwrap(), b"");
    // Replies prove each stream lives once on the server.
    for (i, (ss, _, _)) in seen.iter_mut().enumerate() {
        if i != 1 {
            ss.write_all(b"ok").await.unwrap();
            ss.finish().unwrap();
        }
    }
    assert_eq!(fin_r.read_to_end(16).await.unwrap(), b"ok");
    assert_eq!(open_r.read_to_end(16).await.unwrap(), b"ok");
    // Nothing arrived twice: no further stream, no second session.
    assert!(
        tokio::time::timeout(Duration::from_millis(300), server.accept_bi())
            .await
            .is_err()
    );
    // `accept` ends only by a session (the listener stays open), so the
    // timeout is the one way to see none; an extra session is reported with
    // what it carries.
    if let Ok(extra) = tokio::time::timeout(Duration::from_millis(300), b.accept()).await {
        let extra = extra.expect("the listener stays open");
        let streams = tokio::time::timeout(Duration::from_millis(300), extra.accept_bi()).await;
        panic!(
            "a second session on the refusing server; its first stream: {:?}",
            streams.map(|r| r.map(|_| ()))
        );
    }
    assert!(report.sent() && report.accepted() == Some(false) && report.rewritten());
    second.close(0u32.into(), b"").await;
    // `b` resumed the session of `a`; it was not a full handshake.
    assert_eq!(resumed.load(Ordering::Relaxed), 1);
    a.close();
    b.close();
}
