//! TLS carriers end to end over loopback TCP: one-step `connect` and
//! `serve` with the default ALPN, a carrier-bound join made with the
//! adapter's exporter is accepted, a carrier without an exporter announces
//! no binding, a carrier that announces one is refused by an end that
//! cannot check it (which shows the binding was announced), and a lost
//! connection is a failure, never a clean end.

use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, TlsConnector, client, server};
use zmux::{
    Config, Listener, ListenerConfig, PipeAuth, PipeHint, PipeIo, PipeOptions, PipeState, Session,
    SessionEvent,
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
    c.pipe_auth = auth;
    c
}

/// A client session and the server session a listener accepted for it,
/// over a TLS bootstrap carrier made by the adapter at both ends.
async fn sessions(tls: &Tls, auth: PipeAuth) -> (Session, Session, Listener) {
    let listener = Listener::new(config(auth.clone()), ListenerConfig::default());
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
    let pipe = session.add_pipe(client(c), PipeOptions::default()).unwrap();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        let state = pipe.stats().and_then(|i| i.outbound);
        if state == Some(PipeState::Active) {
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
    assert!(recv.read_to_end(4 << 20).await.unwrap() == data);
    drop(writer.await.unwrap());
    echo.await.unwrap();
}

/// The failed join authentications the server reported, by whether the
/// token was carrier-bound.
fn auth_failures(server: &Session) -> Vec<bool> {
    let mut failed = Vec::new();
    while let Some(Some(e)) = futures_now(server.next_event()) {
        if let SessionEvent::JoinAuthFailed { carrier_bound, .. } = e {
            failed.push(carrier_bound);
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
async fn a_carrier_bound_join_with_the_session_secret_from_the_exporter() {
    let tls = Tls::new().await;
    // The session secret comes from the bootstrap carrier's exporter alone.
    let (client, server, listener) = sessions(&tls, PipeAuth::tls()).await;
    assert!(
        join(
            &tls,
            &client,
            &listener,
            zmux_rustls::over_tcp,
            zmux_rustls::over_tcp
        )
        .await,
        "a carrier-bound join over TLS"
    );
    transfer(&client, &server).await;
    assert!(auth_failures(&server).is_empty());
    client.close(0u32.into(), b"");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_carrier_without_an_exporter_announces_no_binding() {
    let tls = Tls::new().await;
    let auth = PipeAuth::psk(*b"zmux-rustls-test-psk-0123456789a");
    let (client, server, listener) = sessions(&tls, auth).await;
    // The joiner's carrier has no exporter (as behind a TLS-terminating
    // intermediary): its token binds nothing, and the acceptor, which has
    // one, accepts it.
    assert!(
        join(&tls, &client, &listener, PipeIo::new, zmux_rustls::over_tcp).await,
        "an unbound join"
    );
    transfer(&client, &server).await;
    // A joiner with an exporter binds its token: an acceptor whose carrier
    // has none cannot check it and refuses it.
    assert!(
        !join(&tls, &client, &listener, zmux_rustls::over_tcp, PipeIo::new).await,
        "a bound join where the acceptor has no exporter"
    );
    assert_eq!(auth_failures(&server), [true]);
    client.close(0u32.into(), b"");
}

/// One step from an address to a session, and from a TCP listener to its
/// sessions: the default ALPN identifiers are offered and accepted, the
/// session reports the negotiated one, and a stream goes both ways.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn connect_and_serve_with_the_default_alpn() {
    let (client_tls, server_tls) = configs(&[]);
    let listener = Listener::new(Config::default(), ListenerConfig::default());
    let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = tcp.local_addr().unwrap();
    let serving = tokio::spawn(zmux_rustls::serve(listener.clone(), tcp, server_tls));
    let client = zmux_rustls::connect(addr, "localhost", client_tls, Config::default())
        .await
        .unwrap();
    let server = listener.accept().await.unwrap();
    assert_eq!(client.protocol().as_deref(), Some("qmux-02"));
    assert_eq!(server.protocol().as_deref(), Some("qmux-02"));
    transfer(&client, &server).await;
    client.close(0u32.into(), b"bye");
    assert!(matches!(
        server.closed().await,
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
    let listener = Listener::new(Config::default(), ListenerConfig::default());
    let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = tcp.local_addr().unwrap();
    tokio::spawn(zmux_rustls::serve(listener.clone(), tcp, server_tls));
    let (front, proxy) = proxy(addr).await;
    let client = zmux_rustls::connect(front, "localhost", client_tls, Config::default())
        .await
        .unwrap();
    let server = listener.accept().await.unwrap();
    transfer(&client, &server).await;
    proxy.abort();
    for s in [&client, &server] {
        let e = tokio::time::timeout(Duration::from_secs(10), s.closed())
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
