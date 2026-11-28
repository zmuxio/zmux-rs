//! QUIC 0-RTT as carrier early data: a client
//! that resumes a TLS session sends its first records as 0-RTT data under
//! the server's remembered parameters; the server sees the streams opened
//! in it as replayable until the handshake completes; a server that
//! rejects 0-RTT (here, a new server that cannot read the ticket) gets
//! everything again on a new stream, and no stream fails.

#![cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]

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
    let cert = zmux_testcert::self_signed(vec!["localhost".into()]).unwrap();
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

fn plain_early() -> Config {
    use zmux::proto::params::TransportParameters;

    let mut config = early();
    config.test_hooks().transport_parameters = Some(TransportParameters {
        initial_max_data: Some(1 << 20),
        initial_max_stream_data_bidi_local: Some(1 << 16),
        initial_max_stream_data_bidi_remote: Some(1 << 16),
        initial_max_streams_bidi: Some(16),
        ..TransportParameters::default()
    });
    config
}

/// Carrier early data in a session offering multipath (PSK joins).
fn early_multipath() -> Config {
    let mut c = early();
    c.session_policy.limits.steady_attachments = 4;
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

fn server_tls(t: &Tls) -> rustls::ServerConfig {
    rustls::ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![t.der.clone()], PrivateKeyDer::Pkcs8(t.key.clone_key()))
        .unwrap()
}

fn server_config(t: &Tls, opts: &Options) -> quinn::ServerConfig {
    zmux_quinn::server_config(server_tls(t), opts).unwrap()
}

fn serve(
    endpoint: &quinn::Endpoint,
    opts: &Options,
    cfg: fn() -> Config,
) -> (Listener, tokio::task::JoinHandle<()>) {
    let listener =
        Listener::new(cfg(), ListenerConfig::default()).expect("valid listener configuration");
    let serving = tokio::spawn(zmux_quinn::serve(
        listener.clone(),
        endpoint.clone(),
        opts.clone(),
    ));
    (listener, serving)
}

fn server(
    t: &Tls,
    opts: &Options,
    cfg: fn() -> Config,
) -> (quinn::Endpoint, Listener, tokio::task::JoinHandle<()>) {
    let endpoint =
        quinn::Endpoint::server(server_config(t, opts), "127.0.0.1:0".parse().unwrap()).unwrap();
    let (listener, serving) = serve(&endpoint, opts, cfg);
    (endpoint, listener, serving)
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

/// What became of the 0-RTT data of a resumed connection that the server
/// `accepts` or refuses: accepted as it is, or refused and written again. A
/// handshake that completed before the session's first stream was opened (a
/// loaded host may run the connection that far first) left nothing to send
/// as 0-RTT data: the session started on a 1-RTT stream, once.
fn settled(report: &zmux_quinn::ZeroRtt, accepts: bool) {
    if report.sent() {
        assert_eq!(report.accepted(), Some(accepts), "{report:?}");
        assert_eq!(report.rewritten(), !accepts, "{report:?}");
    } else {
        assert!(
            report.accepted().is_none() && !report.rewritten(),
            "{report:?}"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn resumed_connections_send_and_accept_0rtt() {
    let t = tls();
    let memory = ParameterMemory::new();
    let opts = Options::default().with_zero_rtt(memory.clone());
    let (ep, listener, serving) = server(&t, &opts, plain_early);
    let addr = ep.local_addr().unwrap();
    let c_ep = client(&t, &opts);
    // A full handshake: the server's parameters are kept.
    let (first, report) =
        zmux_quinn::connect_with_report(&c_ep, addr, "localhost", &opts, plain_early())
            .await
            .unwrap();
    assert!(!report.sent() && report.accepted().is_none());
    assert!(!exchange(&first, &listener, b"first").await);
    assert!(memory.get("localhost").is_some());
    first.close().await;
    // Resumed: the request goes as 0-RTT data.
    let (second, report) =
        zmux_quinn::connect_with_report(&c_ep, addr, "localhost", &opts, plain_early())
            .await
            .unwrap();
    // The handshake may complete before the application takes the stream.
    // Its current replayability is not evidence of whether 0-RTT was sent.
    exchange(&second, &listener, b"second, in 0-RTT").await;
    settled(&report, true);
    second.close().await;
    listener.close();
    serving.await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_rejected_0rtt_is_sent_again_and_no_stream_fails() {
    rejected_0rtt_sent_again(plain_early).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn zmux_family_cannot_authorize_0rtt() {
    let t = tls();
    for config in [early, early_multipath, early_resume] {
        let memory = ParameterMemory::new();
        let opts = Options::default().with_zero_rtt(memory.clone());
        let (ep, listener, serving) = server(&t, &opts, config);
        let addr = ep.local_addr().unwrap();
        let c_ep = client(&t, &opts);
        for _ in 0..2 {
            let (session, report) =
                zmux_quinn::connect_with_report(&c_ep, addr, "localhost", &opts, config())
                    .await
                    .unwrap();
            assert!(!report.sent());
            assert!(!exchange(&session, &listener, b"same family").await);
            assert!(memory.get("localhost").is_none());
            session.close().await;
        }
        listener.close();
        serving.await.unwrap();
    }
}

/// A server that cannot read the ticket rejects the 0-RTT data.
async fn rejected_0rtt_sent_again(cfg: fn() -> Config) {
    let t = tls();
    let memory = ParameterMemory::new();
    let opts = Options::default().with_zero_rtt(memory.clone());
    let (ep, listener, serving) = server(&t, &opts, cfg);
    let addr = ep.local_addr().unwrap();
    let c_ep = client(&t, &opts);
    let first = zmux_quinn::connect(&c_ep, addr, "localhost", &opts, cfg())
        .await
        .unwrap();
    exchange(&first, &listener, b"first").await;
    first.close().await;
    first.closed().await;
    listener.close();
    serving.await.unwrap();
    ep.wait_idle().await;
    // The fresh server configuration cannot read the old ticket.
    ep.set_server_config(Some(server_config(&t, &opts)));
    let (listener2, serving) = serve(&ep, &opts, cfg);
    let (second, report) = zmux_quinn::connect_with_report(&c_ep, addr, "localhost", &opts, cfg())
        .await
        .unwrap();
    assert!(!exchange(&second, &listener2, b"sent again after the rejection").await);
    settled(&report, false);
    second.close().await;
    listener2.close();
    serving.await.unwrap();
}

#[test]
fn parameter_memory_capacity_forgets_the_oldest_name() {
    let tp = zmux::proto::session::SessionCore::new(
        Config::default(),
        zmux::Role::Client,
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
    refused_carries_early_streams_once(plain_early).await;
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
    first.close().await;
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
    settled(&report, false);
    second.close().await;
    tokio::time::timeout(Duration::from_secs(60), server.closed())
        .await
        .expect("the server did not see the close");
    assert!(server.accept_bi().await.is_err(), "a stream arrived twice");
    assert_eq!(b.stats().sessions, 1, "a second session arrived");
    // `b` resumed the session of `a`; it was not a full handshake.
    assert_eq!(resumed.load(Ordering::Relaxed), 1);
    a.close();
    b.close();
}

#[path = "../../test-support/ticket.rs"]
mod ticket;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn prefix_ticket_adoption_reports_missing_early_data_tracking() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let t = tls();
        let tls = quinn::crypto::rustls::QuicServerConfig::try_from(server_tls(&t)).unwrap();
        let endpoint = quinn::Endpoint::server(
            quinn::ServerConfig::with_crypto(Arc::new(tls)),
            "127.0.0.1:0".parse().unwrap(),
        )
        .unwrap();
        let mut opts = Options::default();
        opts.windows = opts
            .windows
            .with_established_receive_window(opts.windows.receive_window());
        let dialer = client(&t, &opts);
        let connecting = dialer
            .connect(endpoint.local_addr().unwrap(), "localhost")
            .unwrap();
        let joining = async { endpoint.accept().await.unwrap().await.unwrap() };
        let (client, conn) = tokio::join!(connecting, joining);
        let _client = client.unwrap();
        let (_, verifier) = ticket::fixture(zmux::PrefixBinding::Encrypted);
        let mut limits = ListenerConfig::default();
        limits.admission = Some(zmux::Admission::prefix_auth(
            verifier,
            zmux::PrefixRejection::Close,
        ));
        let listener = Listener::new(Config::default(), limits).unwrap();
        let error = zmux_quinn::adopt_connection(&listener, conn, &opts)
            .err()
            .expect("untracked QUIC metadata must fail");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
        assert!(
            error
                .to_string()
                .contains("requires track_server_early_data")
        );
    })
    .await
    .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn prefix_ticket_refuses_quic_early_data_after_the_handshake() {
    tokio::time::timeout(Duration::from_secs(12), async {
        let t = tls();
        let opts = Options::default().with_zero_rtt(ParameterMemory::new());
        let (endpoint, plain, serving) = server(&t, &opts, plain_early);
        let addr = endpoint.local_addr().unwrap();
        let client_ep = client(&t, &opts);
        let one = zmux_quinn::connect(&client_ep, addr, "localhost", &opts, plain_early())
            .await
            .unwrap();
        exchange(&one, &plain, b"obtain a resumption ticket").await;
        one.close().await;
        plain.close();
        serving.await.unwrap();

        let (presenter, verifier) = ticket::fixture(zmux::PrefixBinding::Encrypted);
        let token = presenter
            .token(&zmux::CarrierInfo::new().with_encrypted())
            .unwrap();
        let (reported, mut report) = tokio::sync::mpsc::unbounded_channel();
        let mut limits = ListenerConfig::default();
        limits.admission = Some(zmux::Admission::prefix_auth(
            verifier,
            zmux::PrefixRejection::Fallback,
        ));
        limits.fallback = Some(zmux::Fallback::new(move |carrier| {
            let reported = reported.clone();
            async move {
                let conn = zmux_quinn::takeover_connection(&carrier).unwrap();
                let early = carrier.info().is_early_data();
                let prefix = carrier.replayed().to_vec();
                carrier.detach().unwrap();
                reported
                    .send((early, prefix, conn, carrier.into_pipe()))
                    .unwrap();
            }
        }));
        let protected = Listener::new(Config::default(), limits).unwrap();
        let (resumed, settled) = client_ep
            .connect(addr, "localhost")
            .unwrap()
            .into_0rtt()
            .unwrap_or_else(|_| panic!("missing QUIC resumption ticket"));
        let (mut send, _recv) = resumed.open_bi().await.unwrap();
        send.write_all(&token).await.unwrap();
        // Keep the server from completing the handshake before the test
        // actually sends a 0-RTT stream frame.
        while resumed.stats().frame_tx.stream == 0 {
            tokio::task::yield_now().await;
        }
        let serving = tokio::spawn(zmux_quinn::serve(protected.clone(), endpoint, opts.clone()));
        assert!(settled.await);
        let (early, replayed, server, _first_pipe) = report.recv().await.unwrap();
        assert!(early);
        assert_eq!(replayed, token.to_vec());

        // Hand the same connection back for its next stream. A 1-RTT
        // presentation must pass even after actually receiving early bytes.
        let options = opts.clone().with_windows(
            opts.windows
                .with_established_receive_window(opts.windows.receive_window()),
        );
        let service = zmux_quinn::adopt_connection(&protected, server, &options)
            .unwrap()
            .unwrap();
        let pipe = zmux_quinn::Carrier::new(resumed, &options)
            .unwrap()
            .open_pipe_with_prefix(&token)
            .await
            .unwrap();
        let session = Session::connect(pipe, Config::default()).await.unwrap();
        assert_eq!(
            protected.accept().await.unwrap().bound_prefix_principal(),
            None
        );
        session.close().await;
        service.stop_admission();
        service.admission_stopped().await;
        protected.close();
        serving.await.unwrap();
    })
    .await
    .unwrap();
}
