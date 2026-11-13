//! TLS carriers end to end over loopback TCP: one-step `connect` and
//! `serve` with zmux's ALPN identifiers configured, and none filled in
//! when none is configured, a Bound join made with the
//! adapter's exporter is accepted, a carrier without an exporter announces
//! no binding, a carrier that announces one is refused by an end that
//! cannot check it (which shows the binding was announced), a lost
//! connection is a failure, never a clean end, and the PROXY protocol
//! header of a trusted intermediary is read before the handshake.

use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, TlsConnector, client, server};
use zmux::RecordMode;
use zmux::{
    Config, Listener, ListenerConfig, OutboundState, PipeAuth, PipeHint, PipeIo, PipeOptions,
    Session, SessionEvent,
};

struct Tls {
    connector: TlsConnector,
    acceptor: TlsAcceptor,
    tcp: TcpListener,
}

/// A client and a server configuration for "localhost", with `alpn`.
fn configs(alpn: &[&[u8]]) -> (Arc<rustls::ClientConfig>, Arc<rustls::ServerConfig>) {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let der = CertificateDer::from(cert.cert.der().to_vec());
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()));
    let mut server = rustls::ServerConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![der.clone()], key)
        .unwrap();
    server.alpn_protocols = alpn.iter().map(|a| a.to_vec()).collect();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(der).unwrap();
    let mut client = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    client.alpn_protocols = alpn.iter().map(|a| a.to_vec()).collect();
    (Arc::new(client), Arc::new(server))
}

/// A TCP proxy to `to` that forwards one connection until `cut` is
/// called, then drops both sockets.
async fn proxy(to: std::net::SocketAddr) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    let front = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = front.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let (mut a, _) = front.accept().await.unwrap();
        let mut b = TcpStream::connect(to).await.unwrap();
        let _ = tokio::io::copy_bidirectional(&mut a, &mut b).await;
    });
    (addr, task)
}

impl Tls {
    async fn new() -> Self {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let der = CertificateDer::from(cert.cert.der().to_vec());
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()));
        let mut server = rustls::ServerConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![der.clone()], key)
            .unwrap();
        server.alpn_protocols = vec![b"zmux".to_vec()];
        let mut roots = rustls::RootCertStore::empty();
        roots.add(der).unwrap();
        let mut client = rustls::ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        client.alpn_protocols = vec![b"zmux".to_vec()];
        Self {
            connector: TlsConnector::from(Arc::new(client)),
            acceptor: TlsAcceptor::from(Arc::new(server)),
            tcp: TcpListener::bind("127.0.0.1:0").await.unwrap(),
        }
    }

    /// A TLS connection over loopback TCP: both ends.
    async fn pair(&self) -> (client::TlsStream<TcpStream>, server::TlsStream<TcpStream>) {
        let addr = self.tcp.local_addr().unwrap();
        let name = ServerName::try_from("localhost").unwrap();
        let (c, s) = tokio::join!(
            async {
                let tcp = TcpStream::connect(addr).await.unwrap();
                self.connector.connect(name, tcp).await.unwrap()
            },
            async {
                let (tcp, _) = self.tcp.accept().await.unwrap();
                self.acceptor.accept(tcp).await.unwrap()
            }
        );
        (c, s)
    }
}

fn config(auth: PipeAuth) -> Config {
    let mut c = Config::default();
    c.max_pipes = 4;
    c.pipe_auth = auth.with_end_to_end();
    c.allow_record_mode = Some(zmux::AllowRecordMode::new(|_, _, _| true));
    c
}

/// A client session and the server session a listener accepted for it,
/// over a TLS bootstrap carrier made by the adapter at both ends.
async fn sessions(tls: &Tls, auth: PipeAuth) -> (Session, Session, Listener) {
    let listener = Listener::new(config(auth.clone()), ListenerConfig::default())
        .expect("valid listener configuration");
    let (c, s) = tls.pair().await;
    let l = listener.clone();
    tokio::spawn(async move {
        l.handle_pipe(zmux_rustls::over_tcp(s), PipeHint::default())
            .await
    });
    let client = Session::connect(zmux_rustls::over_tcp(c), config(auth))
        .await
        .unwrap();
    let server = listener.accept().await.unwrap();
    assert!(
        client.multipath() == zmux::Multipath::InUse
            && server.multipath() == zmux::Multipath::InUse
    );
    assert_eq!(client.protocol().as_deref(), Some("zmux"));
    (client, server, listener)
}

/// Joins a second pipe over a new TLS connection, the carriers made by
/// `client` and `server`; whether the join was accepted.
async fn join(
    tls: &Tls,
    session: &Session,
    listener: &Listener,
    client: impl FnOnce(client::TlsStream<TcpStream>) -> PipeIo,
    server: impl FnOnce(server::TlsStream<TcpStream>) -> PipeIo + Send + 'static,
) -> bool {
    let (c, s) = tls.pair().await;
    let l = listener.clone();
    let handled = tokio::spawn(async move { l.handle_pipe(server(s), PipeHint::default()).await });
    let pipe = session
        .begin_add_pipe(
            client(c),
            PipeOptions::default().with_record_mode(RecordMode::Bound),
        )
        .unwrap();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        let state = pipe.stats().and_then(|i| i.outbound);
        if state == Some(OutboundState::Active) {
            return true;
        }
        if handled.is_finished() || tokio::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

/// Echoes a transfer over the session's pipes.
async fn transfer(client: &Session, server: &Session) {
    let server = server.clone();
    let echo = tokio::spawn(async move {
        let (mut send, mut recv) = server.accept_bi().await.unwrap();
        let data = recv.read_to_end(4 << 20).await.unwrap();
        send.write_all(&data).await.unwrap();
        send.finish().unwrap();
    });
    let (mut send, mut recv) = client.open_bi().await.unwrap();
    let data: Vec<u8> = (0..(1 << 20)).map(|i| (i % 251) as u8).collect();
    let d = data.clone();
    let writer = tokio::spawn(async move {
        send.write_all(&d).await.unwrap();
        send.finish().unwrap();
        send
    });
    assert_eq!(recv.read_to_end(4 << 20).await.unwrap(), data);
    drop(writer.await.unwrap());
    echo.await.unwrap();
}

/// The failed join authentications the server reported.
fn auth_failures(server: &Session) -> usize {
    let mut failed = 0;
    while let Some(Some(e)) = futures_now(server.next_event()) {
        if let SessionEvent::JoinAuthFailed { .. } = e {
            failed += 1;
        }
    }
    failed
}

/// Polls `f` once.
fn futures_now<F: Future>(f: F) -> Option<F::Output> {
    let mut f = std::pin::pin!(f);
    match f
        .as_mut()
        .poll(&mut std::task::Context::from_waker(std::task::Waker::noop()))
    {
        std::task::Poll::Ready(v) => Some(v),
        std::task::Poll::Pending => None,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_bound_join_with_the_session_secret_from_the_exporter() {
    let tls = Tls::new().await;
    // The session secret comes from the bootstrap carrier's exporter alone.
    let (client, server, listener) = sessions(&tls, PipeAuth::exporter()).await;
    assert!(
        join(
            &tls,
            &client,
            &listener,
            zmux_rustls::over_tcp,
            zmux_rustls::over_tcp
        )
        .await,
        "a Bound join over TLS"
    );
    transfer(&client, &server).await;
    assert_eq!(auth_failures(&server), 0);
    client.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bound_needs_an_exporter_at_both_ends() {
    let tls = Tls::new().await;
    let auth = PipeAuth::psk(*b"zmux-rustls-test-psk-0123456789a").with_end_to_end();
    let (client, server, listener) = sessions(&tls, auth).await;
    // The joiner's carrier has no exporter (as behind a TLS-terminating intermediary):
    // Bound fails at once at the joiner, without a byte.
    let (c, _s) = tls.pair().await;
    assert_eq!(
        client
            .begin_add_pipe(
                PipeIo::new(c),
                PipeOptions::default().with_record_mode(RecordMode::Bound)
            )
            .unwrap_err(),
        zmux::PipeError::InvalidArgument
    );
    // A joiner with an exporter binds its Hello: an acceptor whose carrier has none refuses
    // it as an authentication failure.
    assert!(
        !join(&tls, &client, &listener, zmux_rustls::over_tcp, PipeIo::new).await,
        "a bound join where the acceptor has no exporter"
    );
    assert_eq!(auth_failures(&server), 1);
    client.close().await;
}

/// One step from an address to a session, and from a TCP listener to its
/// sessions: zmux's ALPN identifiers, configured on both ends, are
/// negotiated and reported by the sessions, and a stream goes both ways.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn connect_and_serve_with_zmux_alpn() {
    let alpn = zmux::alpn_protocols(&[]);
    let alpn: Vec<&[u8]> = alpn.iter().map(Vec::as_slice).collect();
    let (client_tls, server_tls) = configs(&alpn);
    let listener = Listener::new(Config::default(), ListenerConfig::default())
        .expect("valid listener configuration");
    let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = tcp.local_addr().unwrap();
    let serving = tokio::spawn(zmux_rustls::serve(listener.clone(), tcp, server_tls));
    let client = zmux_rustls::connect(
        addr,
        "localhost",
        client_tls,
        &zmux_rustls::Options::new(),
        Config::default(),
    )
    .await
    .unwrap();
    let server = listener.accept().await.unwrap();
    assert_eq!(client.protocol().as_deref(), Some("qmux-02"));
    assert_eq!(server.protocol().as_deref(), Some("qmux-02"));
    transfer(&client, &server).await;
    client.close().await;
    assert!(matches!(
        server.closing().await,
        zmux::SessionError::ApplicationClosed { remote: true, .. }
    ));
    listener.close();
    serving.await.unwrap();
}

/// A TLS connection that ends without close_notify (here a proxy that
/// drops both sockets) is a carrier failure: the session ends with
/// `PipesLost`, never with the peer's clean idle close.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_lost_connection_is_a_failure_not_a_clean_end() {
    let (client_tls, server_tls) = configs(&[]);
    let listener = Listener::new(Config::default(), ListenerConfig::default())
        .expect("valid listener configuration");
    let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = tcp.local_addr().unwrap();
    tokio::spawn(zmux_rustls::serve(listener.clone(), tcp, server_tls));
    let (front, proxy) = proxy(addr).await;
    let client = zmux_rustls::connect(
        front,
        "localhost",
        client_tls,
        &zmux_rustls::Options::new(),
        Config::default(),
    )
    .await
    .unwrap();
    let server = listener.accept().await.unwrap();
    transfer(&client, &server).await;
    proxy.abort();
    for s in [&client, &server] {
        let e = tokio::time::timeout(Duration::from_secs(10), s.closing())
            .await
            .expect("ended");
        assert!(
            matches!(
                e,
                zmux::SessionError::PipesLost {
                    last: Some(zmux::PipeFailure::Carrier(_))
                }
            ),
            "{e:?}"
        );
    }
    listener.close();
}

/// Without configured identifiers no ALPN is negotiated: neither end
/// fills any in.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn no_alpn_is_filled_in() {
    let (client_tls, server_tls) = configs(&[]);
    let listener = Listener::new(Config::default(), ListenerConfig::default())
        .expect("valid listener configuration");
    let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = tcp.local_addr().unwrap();
    tokio::spawn(zmux_rustls::serve(listener.clone(), tcp, server_tls));
    let client = zmux_rustls::connect(
        addr,
        "localhost",
        client_tls,
        &zmux_rustls::Options::new(),
        Config::default(),
    )
    .await
    .unwrap();
    let server = listener.accept().await.unwrap();
    assert_eq!(client.protocol(), None);
    assert_eq!(server.protocol(), None);
    listener.close();
}

/// The bytes a client session sends first on a carrier.
async fn first_record() -> Vec<u8> {
    use tokio::io::AsyncReadExt;
    let (a, mut b) = tokio::io::duplex(64 * 1024);
    let client = tokio::spawn(Session::connect(PipeIo::new(a), Config::default()));
    let mut buf = vec![0u8; 4096];
    let n = tokio::time::timeout(Duration::from_secs(5), b.read(&mut buf))
        .await
        .unwrap()
        .unwrap();
    client.abort();
    let _ = client.await;
    buf.truncate(n);
    assert!(n > 0);
    buf
}

/// An admitted server with bound prefix authentication tokens: a client
/// with a valid token reaches the listener and its session works. A
/// replayed token, the token of another carrier, a truncated token, random
/// bytes and a first record without a token each reach the fallback with
/// exactly the bytes sent, and nothing else is written; without a fallback
/// they are stalled: nothing is written, and the connection ends with an
/// orderly close once the stall has lasted its duration (a truncated token
/// not ended is closed at the peek timeout).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn admission_by_bound_prefix_auth() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    const LIMIT: Duration = Duration::from_secs(10);
    const STALL_MIN: Duration = Duration::from_millis(50);
    let (client_tls, server_tls) = configs(&[b"zmux"]);
    let auth = zmux::PrefixAuth::new(b"k", Duration::from_secs(30), true).unwrap();
    let verifier = Arc::new(zmux::PrefixAuthVerifier::new(auth.clone(), 1, 1024));
    let admission = zmux::Admission::prefix_auth(verifier)
        .with_peek_timeout(Duration::from_millis(300))
        .with_stall_interval(STALL_MIN, Duration::from_millis(100));
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let fallback = zmux::Fallback::new(move |mut conn, _| {
        let tx = tx.clone();
        async move {
            let mut got = Vec::new();
            let _ = conn.read_to_end(&mut got).await;
            let _ = tx.send(got);
            let _ = conn.write_all(b"fallback").await;
            let _ = conn.shutdown().await;
        }
    });
    let serve = async |fallback| {
        let mut limits = ListenerConfig::default();
        limits.admission = Some(admission.clone());
        limits.fallback = fallback;
        let listener =
            Listener::new(Config::default(), limits).expect("valid listener configuration");
        let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = tcp.local_addr().unwrap();
        let task = tokio::spawn(zmux_rustls::serve(
            listener.clone(),
            tcp,
            server_tls.clone(),
        ));
        (addr, listener, task)
    };
    let dial = async |addr| {
        let tcp = TcpStream::connect(addr).await.unwrap();
        TlsConnector::from(client_tls.clone())
            .connect(ServerName::try_from("localhost").unwrap(), tcp)
            .await
            .unwrap()
    };
    let token = |tls: &client::TlsStream<TcpStream>| {
        let b = tls
            .get_ref()
            .1
            .export_keying_material(
                [0u8; 32],
                zmux::PREFIX_AUTH_EXPORTER_LABEL.as_bytes(),
                Some(&[]),
            )
            .unwrap();
        auth.token(Some(&b)).unwrap().to_vec()
    };
    let (addr, listener, with_fallback) = serve(Some(fallback)).await;
    let (stalling, stalling_listener, without_fallback) = serve(None).await;

    let body = async {
        // A valid carrier.
        let mut tls = dial(addr).await;
        let tok = token(&tls);
        tls.write_all(&tok).await.unwrap();
        let client = Session::connect(zmux_rustls::over_tcp(tls), Config::default())
            .await
            .unwrap();
        let server = listener.accept().await.unwrap();
        transfer(&client, &server).await;
        client
            .shutdown(zmux::VarInt::from_u32(0), b"")
            .await
            .unwrap();
        server.closing().await;

        // The dialer's credential: a bound token of its own connection.
        let client = zmux_rustls::connect(
            addr,
            "localhost",
            client_tls.clone(),
            &zmux_rustls::Options::new().with_carrier_credential(Arc::new(auth.clone())),
            Config::default(),
        )
        .await
        .unwrap();
        let server = listener.accept().await.unwrap();
        transfer(&client, &server).await;
        client
            .shutdown(zmux::VarInt::from_u32(0), b"")
            .await
            .unwrap();
        server.closing().await;

        let record = first_record().await;
        let mut random = vec![0u8; 64];
        rustls::crypto::ring::default_provider()
            .secure_random
            .fill(&mut random)
            .unwrap();
        let mut other = dial(addr).await;
        let valid = token(&other);
        other.shutdown().await.unwrap();
        drop(other);
        // The other carrier ended without a byte.
        let got = rx.recv().await.unwrap();
        assert!(got.is_empty(), "fallback got {got:x?}");
        let cases: [(&str, &[u8]); 5] = [
            ("replayed", &tok),
            ("other carrier", &valid),
            ("truncated", &valid[..zmux::PREFIX_TOKEN_LEN / 2]),
            ("random", &random),
            ("record", &record),
        ];
        for (name, send) in cases {
            let mut tls = dial(addr).await;
            tls.write_all(send).await.unwrap();
            tls.shutdown().await.unwrap();
            let mut reply = Vec::new();
            let _ = tls.read_to_end(&mut reply).await;
            assert_eq!(reply, b"fallback", "{name}: reply");
            let got = rx.recv().await.unwrap();
            assert_eq!(got, send, "{name}: fallback bytes");
        }

        // No fallback: stalled; a truncated token left open is a prefix
        // that does not arrive, closed at the peek timeout.
        for (name, send) in cases {
            let mut tls = dial(stalling).await;
            tls.write_all(send).await.unwrap();
            let start = tokio::time::Instant::now();
            let mut reply = Vec::new();
            let n = tls.read_to_end(&mut reply).await;
            if name == "truncated" {
                assert!(reply.is_empty() && n.is_err(), "{name}: {reply:x?}, {n:?}");
                continue;
            }
            assert!(
                matches!(n, Ok(0)),
                "{name}: stalled carrier answered {reply:x?}, {n:?}"
            );
            let lasted = start.elapsed();
            assert!(
                lasted >= STALL_MIN - Duration::from_millis(10),
                "{name}: closed after {lasted:?}"
            );
        }
        assert_eq!(listener.stats().sessions, 2);
    };
    tokio::time::timeout(Duration::from_secs(20), body)
        .await
        .expect("admission test timed out");
    listener.close();
    stalling_listener.close();
    for task in [with_fallback, without_fallback] {
        tokio::time::timeout(LIMIT, task).await.unwrap().unwrap();
    }
}

/// Behind an intermediary the listener trusts to send the PROXY protocol,
/// `serve` reads its header before the TLS handshake, with or without an
/// admission:
/// the session works over the rest of the connection, and the admission
/// sees the client the header reports.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn behind_a_proxy_protocol_intermediary() {
    use tokio::io::AsyncWriteExt;
    const HEADER: &[u8] = b"PROXY TCP4 198.51.100.7 10.0.0.1 4000 443\r\n";
    tokio::time::timeout(Duration::from_secs(20), async {
        let (client_tls, server_tls) = configs(&[b"zmux"]);
        let proxies = zmux::TrustedProxies::new()
            .with_net("127.0.0.0/8".parse().unwrap())
            .with_proxy_protocol(true);
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let tx = std::sync::Mutex::new(tx);
        let admission = zmux::Admission::new(0, move |info, _| {
            let _ = tx.lock().unwrap().send(info.source);
            zmux::AdmissionVerdict::accept(0)
        });
        let listener = |admission| {
            let mut limits = ListenerConfig::default();
            limits.trusted_proxies = proxies.clone();
            limits.admission = admission;
            Listener::new(Config::default(), limits).expect("valid listener configuration")
        };
        let listeners = [listener(None), listener(Some(admission))];
        let plain = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let admitted = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addrs = [plain.local_addr().unwrap(), admitted.local_addr().unwrap()];
        let serving = [
            tokio::spawn(zmux_rustls::serve(
                listeners[0].clone(),
                plain,
                server_tls.clone(),
            )),
            tokio::spawn(zmux_rustls::serve(
                listeners[1].clone(),
                admitted,
                server_tls,
            )),
        ];
        for (addr, listener) in addrs.into_iter().zip(&listeners) {
            let mut tcp = TcpStream::connect(addr).await.unwrap();
            tcp.write_all(HEADER).await.unwrap();
            let tls = TlsConnector::from(client_tls.clone())
                .connect(ServerName::try_from("localhost").unwrap(), tcp)
                .await
                .unwrap();
            let client = Session::connect(zmux_rustls::over_tcp(tls), Config::default())
                .await
                .unwrap();
            let server = listener.accept().await.unwrap();
            transfer(&client, &server).await;
            client.close().await;
            server.closing().await;
        }
        let seen = rx.recv().await.unwrap().unwrap();
        assert_eq!(seen.to_string(), "198.51.100.7:4000");
        for listener in &listeners {
            listener.close();
        }
        for s in serving {
            s.await.unwrap();
        }
    })
    .await
    .unwrap();
}

/// The admission's More reads on through TLS, with the handshake's metadata
/// given to every decision.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn more_reads_on_through_tls() {
    use tokio::io::AsyncWriteExt;
    use zmux::{Admission, AdmissionVerdict};
    let (client_tls, server_tls) = configs(&[b"x"]);
    let admission = Admission::new(2, |info, p| {
        assert_eq!(info.alpn, Some(&b"x"[..]));
        if p.len() < 5 {
            AdmissionVerdict::More { need: 5 }
        } else if p == b"token" {
            AdmissionVerdict::accept(5)
        } else {
            AdmissionVerdict::Close
        }
    })
    .with_max_peek(8);
    let mut limits = ListenerConfig::default();
    limits.admission = Some(admission);
    let listener = Listener::new(Config::default(), limits).expect("valid listener configuration");
    let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = tcp.local_addr().unwrap();
    tokio::spawn(zmux_rustls::serve(listener.clone(), tcp, server_tls));
    let name = ServerName::try_from("localhost").unwrap();
    let raw = TcpStream::connect(addr).await.unwrap();
    let mut tls = TlsConnector::from(client_tls)
        .connect(name, raw)
        .await
        .unwrap();
    tls.write_all(b"to").await.unwrap();
    tls.flush().await.unwrap();
    tokio::time::sleep(Duration::from_millis(20)).await;
    tls.write_all(b"ken").await.unwrap();
    let client = tokio::time::timeout(
        Duration::from_secs(10),
        Session::connect(zmux_rustls::over_tcp(tls), Config::default()),
    )
    .await
    .unwrap()
    .unwrap();
    let server = tokio::time::timeout(Duration::from_secs(10), listener.accept())
        .await
        .unwrap()
        .unwrap();
    transfer(&client, &server).await;
    assert_eq!(listener.stats().admission.accepted, 1);
    listener.close();
}

// ---- N16: close delivery ---------------------------------------------------------------

/// N16 on one carrier class: the client writes 1 MiB on a stream it
/// finishes and a few bytes on a second one it leaves open, then closes
/// with `code` and `reason` (code 0 and no reason: the plain close) and
/// waits for the whole end. The server reads the whole 1 MiB in order and
/// ends with the client's code and reason; the close returned within its
/// guard; the wait, under a client linger of an hour, returned once the
/// server read the close and ended its side; the open
/// stream failed locally with the session's error. `slow`: the server starts
/// reading only after a pause, so the close arrives before it read everything.
/// `c` with a linger of an hour: a session that ends ended at the peer's end
/// of its side.
fn lingering(mut c: Config) -> Config {
    c.test_hooks().linger_timeout = Some(Duration::from_secs(3600));
    c
}

async fn close_delivery(client: &Session, server: &Session, code: u32, reason: &[u8], slow: bool) {
    let data: Vec<u8> = (0..(1 << 20)).map(|i| (i % 251) as u8).collect();
    let reader = {
        let (server, data) = (server.clone(), data.clone());
        tokio::spawn(async move {
            let (_s, mut r) = server.accept_bi().await.unwrap();
            if slow {
                // A slow reader: the close arrives while data waits unread.
                tokio::time::sleep(Duration::from_millis(300)).await;
            }
            assert_eq!(r.read_to_end(2 << 20).await.unwrap(), data);
            server.closing().await
        })
    };
    let (mut w, _r) = client.open_bi().await.unwrap();
    w.write_all(&data).await.unwrap();
    w.finish().unwrap();
    let (mut open, _r2) = client.open_bi().await.unwrap();
    open.write_all(b"left open").await.unwrap();
    let start = std::time::Instant::now();
    let code = zmux::VarInt::from_u32(code);
    if code == zmux::VarInt::ZERO && reason.is_empty() {
        client.close().await;
    } else {
        client.close_with_error(code, reason).await;
    }
    // A guard only: the server's delivery below shows the close completed
    // normally.
    let closed = start.elapsed();
    assert!(closed < Duration::from_secs(3), "{closed:?}");
    // The client lingers an hour (`lingering`): a wait that returns within
    // its guard returned at the server's end of its side, after it read the
    // close.
    let end = tokio::time::timeout(Duration::from_secs(5), client.wait())
        .await
        .expect("the server ended its side after the close");
    assert!(
        matches!(&end, zmux::SessionError::ApplicationClosed { code: c, remote: false, .. } if *c == code),
        "{end:?}"
    );
    let seen = tokio::time::timeout(Duration::from_secs(5), reader)
        .await
        .expect("the server read everything")
        .unwrap();
    assert!(
        matches!(&seen, zmux::SessionError::ApplicationClosed { code: c, reason: r, remote: true }
            if *c == code && r.as_ref() == reason),
        "{seen:?}"
    );
    let e = open.write_all(b"more").await.unwrap_err();
    assert!(
        matches!(&e, zmux::StreamError::SessionLost(zmux::SessionError::ApplicationClosed { code: c, remote: false, .. }) if *c == code),
        "{e:?}"
    );
}

/// N16 over TCP and over TLS, through the adapter's `connect` and `serve`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_close_is_delivered_with_its_code_over_tcp_and_tls() {
    for (code, reason, slow) in [
        (0x2a, &b"bye"[..], false),
        (0, &b""[..], false),
        (0x2a, &b"bye"[..], true),
    ] {
        // TCP.
        let listener = Listener::new(Config::default(), ListenerConfig::default())
            .expect("valid listener configuration");
        let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = tcp.local_addr().unwrap();
        let l = listener.clone();
        let serving = tokio::spawn(async move {
            let (s, peer) = tcp.accept().await.unwrap();
            l.handle_pipe(PipeIo::tcp(s), PipeHint::from_peer(peer))
                .await
        });
        let client = Session::connect(
            PipeIo::tcp(TcpStream::connect(addr).await.unwrap()),
            lingering(Config::default()),
        )
        .await
        .unwrap();
        let server = listener.accept().await.unwrap();
        close_delivery(&client, &server, code, reason, slow).await;
        let _ = serving.await;
        listener.close();

        // TLS.
        let alpn = zmux::alpn_protocols(&[]);
        let alpn: Vec<&[u8]> = alpn.iter().map(Vec::as_slice).collect();
        let (client_tls, server_tls) = configs(&alpn);
        let listener = Listener::new(Config::default(), ListenerConfig::default())
            .expect("valid listener configuration");
        let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = tcp.local_addr().unwrap();
        let serving = tokio::spawn(zmux_rustls::serve(listener.clone(), tcp, server_tls));
        let client = zmux_rustls::connect(
            addr,
            "localhost",
            client_tls,
            &zmux_rustls::Options::new(),
            lingering(Config::default()),
        )
        .await
        .unwrap();
        let server = listener.accept().await.unwrap();
        close_delivery(&client, &server, code, reason, slow).await;
        listener.close();
        serving.await.unwrap();
    }
}
