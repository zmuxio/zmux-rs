//! The Bound contract of carriers on TLS this process terminates: a
//! bidirectional carrier over HTTP/1.1 or HTTP/2 on a `TlsConnection` is
//! secure with the connection's exporter, shared by the streams of one
//! HTTP/2 connection; split halves, h2c and an http origin are not.

mod support;

#[path = "../../test-support/ticket.rs"]
mod ticket;

use std::sync::Arc;
use std::time::Duration;

use tokio::net::{TcpListener, TcpStream};
use zmux::{Config, Listener, ListenerConfig, PipeAuth, PipeIo, PipeOptions, RecordMode, Session};
use zmux_http::{Http2Connection, Options};
use zmux_rustls::TlsConnection;

#[tokio::test]
async fn ticket_protected_endpoint_checks_exchange_and_pair_configuration() {
    use zmux_http::{Endpoint, ExchangeOptions, ExchangeServer, PairField};
    let (presenter, verifier) = ticket::fixture(zmux::PrefixBinding::Encrypted);
    let exchange_listener = Listener::new(Config::default(), ListenerConfig::default()).unwrap();
    let mut limits = ListenerConfig::default();
    limits.admission = Some(zmux::Admission::prefix_auth(
        verifier,
        zmux::PrefixRejection::Close,
    ));
    let protected = Listener::new(Config::default(), limits).unwrap();
    let exchange = ExchangeServer::new(
        &exchange_listener,
        ExchangeOptions::default().with_unauthenticated(),
    )
    .unwrap();
    assert!(
        Endpoint::new(
            exchange_listener.clone(),
            Options::default().with_exchange(exchange.clone())
        )
        .is_ok()
    );
    let error = Endpoint::new(
        protected.clone(),
        Options::default().with_exchange(exchange),
    )
    .unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
    assert!(
        error
            .to_string()
            .contains("requires PSK-authenticated exchange")
    );
    let authenticated = ExchangeServer::new(
        &exchange_listener,
        ExchangeOptions::default().with_psk(b"test PSK"),
    )
    .unwrap();
    assert!(Endpoint::new(protected, Options::default().with_exchange(authenticated)).is_ok());

    let (_, verifier) = ticket::fixture(zmux::PrefixBinding::Encrypted);
    let verifier = Arc::try_unwrap(verifier)
        .unwrap()
        .with_header("X-Ticket")
        .unwrap();
    let mut limits = ListenerConfig::default();
    limits.admission = Some(zmux::Admission::prefix_auth(
        Arc::new(verifier),
        zmux::PrefixRejection::Close,
    ));
    let protected = Listener::new(Config::default(), limits).unwrap();
    let error = Endpoint::new(
        protected,
        Options::default().with_pair_field(PairField::new("x-ticket").unwrap()),
    )
    .unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
    assert!(
        error
            .to_string()
            .contains("conflicts with the HTTP pairing field")
    );

    let options = ExchangeOptions::default()
        .with_psk(b"test PSK")
        .with_carrier_credential(Arc::new(presenter));
    let error = zmux_http::dial_exchange("localhost:1234", &options).unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
    assert!(error.to_string().contains("does not accept PrefixAuth"));
}

/// TLS 1.3 configurations whose ALPN offers `h2` and `http/1.1`.
fn tls() -> (tokio_rustls::TlsConnector, tokio_rustls::TlsAcceptor) {
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let cert = zmux_testcert::self_signed(vec!["localhost".into()]).unwrap();
    let der = CertificateDer::from(cert.cert.der().to_vec());
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()));
    let mut server = rustls::ServerConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![der.clone()], key)
        .unwrap();
    server.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let mut roots = rustls::RootCertStore::empty();
    roots.add(der).unwrap();
    let client = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    (
        tokio_rustls::TlsConnector::from(Arc::new(client)),
        tokio_rustls::TlsAcceptor::from(Arc::new(server)),
    )
}

/// Bound joins only on a carrier declared secure.
fn config(pipe_auth: PipeAuth) -> Config {
    let mut c = Config::multipath(pipe_auth);
    c.allow_record_mode = Some(zmux::AllowRecordMode::new(|c, mode, _| {
        mode != RecordMode::Bound || c.secure
    }));
    c
}

/// A TLS server whose connections are `TlsConnections`, routed by `endpoint`.
async fn tls_server(
    endpoint: zmux_http::Endpoint,
    acceptor: tokio_rustls::TlsAcceptor,
) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = tcp.local_addr().unwrap();
    let serving = tokio::spawn(async move {
        endpoint
            .serve_with(
                || tcp.accept(),
                move |conn, _| {
                    let accepted = acceptor.accept(conn);
                    async move { accepted.await.map(TlsConnection::new) }
                },
            )
            .await;
    });
    (addr, serving)
}

async fn tls_conn(
    connector: &tokio_rustls::TlsConnector,
    addr: std::net::SocketAddr,
    alpn: &[u8],
) -> TlsConnection {
    let mut c = (**connector.config()).clone();
    c.alpn_protocols = vec![alpn.to_vec()];
    let connector = tokio_rustls::TlsConnector::from(Arc::new(c));
    let name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
    let tcp = TcpStream::connect(addr).await.unwrap();
    TlsConnection::new(connector.connect(name, tcp).await.unwrap())
}

async fn joined_bound(session: &Session, io: PipeIo) -> Result<(), String> {
    let pipe = session
        .test_begin_join(io, PipeOptions::new().with_record_mode(RecordMode::Bound))
        .map_err(|e| e.to_string())?;
    tokio::time::timeout(Duration::from_secs(10), pipe.joined())
        .await
        .map_err(|_| "join timed out".to_owned())?
        .map(drop)
        .map_err(|e| e.to_string())
}

/// Over HTTP/2 and HTTP/1.1 on TLS both ends terminate, a bidirectional
/// carrier bootstraps with the connection's exporter and a further one
/// joins Bound; the streams of one HTTP/2 connection share its Binding,
/// and its split halves have none.
#[test]
fn bound_over_tls() {
    support::run(2, 90, || async {
        let (connector, acceptor) = tls();
        let config = config(PipeAuth::exporter().with_end_to_end());
        let listener = Listener::new(config.clone(), ListenerConfig::default()).unwrap();
        let endpoint = zmux_http::Endpoint::new(listener.clone(), Options::default()).unwrap();
        let (addr, serving) = tls_server(endpoint, acceptor).await;
        let https = Options::default().with_https(true);

        // HTTP/2.
        let h2 = Http2Connection::handshake(
            tls_conn(&connector, addr, b"h2").await,
            "localhost",
            https.clone(),
        )
        .await
        .unwrap();
        let first = h2.open_pipe().await.unwrap();
        let binding = first.bound_exporter().expect("a bound HTTP/2 stream");
        let cs = Session::connect(first, config.clone()).await.unwrap();
        let ss = listener.accept().await.unwrap();
        assert_eq!(
            cs.export_keying_material("app", b"", 16).unwrap(),
            ss.export_keying_material("app", b"", 16).unwrap()
        );
        let second = h2.open_pipe().await.unwrap();
        assert_eq!(
            second.bound_exporter(),
            Some(binding),
            "one Binding per connection"
        );
        joined_bound(&cs, second).await.unwrap();
        let split = h2.open_split().await.unwrap();
        assert!(
            split.bound_exporter().is_none(),
            "split halves are not Bound"
        );
        drop(split);

        // HTTP/1.1, each carrier on a connection of its own.
        let io = zmux_http::dial_http1_over(
            tls_conn(&connector, addr, b"http/1.1").await,
            "localhost",
            &https,
        )
        .await
        .unwrap();
        assert!(io.bound_exporter().is_some(), "a bound HTTP/1.1 carrier");
        joined_bound(&cs, io).await.unwrap();

        // An http origin over the same TLS: not declared.
        let io = zmux_http::dial_http1_over(
            tls_conn(&connector, addr, b"http/1.1").await,
            "localhost",
            &Options::default(),
        )
        .await
        .unwrap();
        assert!(io.bound_exporter().is_none(), "an http origin");
        drop(io);

        cs.close().await;
        drop(ss);
        listener.close();
        serving.await.unwrap();
    });
}

/// Without TLS terminated here (h2c, as behind a front that ends TLS) the
/// server's carrier is not secure: a join that claims Bound fails.
#[test]
fn not_bound_over_h2c() {
    support::run(2, 90, || async {
        let config = config(PipeAuth::psk([7u8; 32]));
        let listener = Listener::new(config.clone(), ListenerConfig::default()).unwrap();
        let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = tcp.local_addr().unwrap().to_string();
        let serving = tokio::spawn(zmux_http::serve(listener.clone(), tcp, Options::default()));
        let h2 = Http2Connection::connect(&addr, Options::default())
            .await
            .unwrap();
        let first = h2.open_pipe().await.unwrap();
        assert!(first.bound_exporter().is_none());
        let cs = Session::connect(first, config).await.unwrap();
        let ss = listener.accept().await.unwrap();
        for session in [&cs, &ss] {
            let sample = session.pipe_stats().remove(0).carrier_sample.unwrap();
            assert_eq!(sample.source, zmux::CarrierSource::Unknown);
            assert_eq!(sample.counts, None);
        }
        // A client that claims the contract on its own.
        let claimed = h2
            .open_pipe()
            .await
            .unwrap()
            .with_carrier_secure()
            .with_exporter(|_, _, out| {
                out.fill(7);
                true
            });
        assert!(joined_bound(&cs, claimed).await.is_err());
        cs.close().await;
        drop(ss);
        listener.close();
        serving.await.unwrap();
    });
}

/// A WebSocket over an HTTP/2 stream (RFC 8441 extended `CONNECT`) on TLS
/// the server terminates declares the connection's Binding: a client that
/// declares the same joins Bound.
#[cfg(feature = "websocket")]
#[test]
fn bound_websocket_over_h2() {
    support::run(2, 90, || async {
        use hyper_util::rt::{TokioExecutor, TokioIo};
        use tokio_tungstenite::WebSocketStream;
        use tokio_tungstenite::tungstenite::protocol::Role;

        let (connector, acceptor) = tls();
        let config = config(PipeAuth::exporter().with_end_to_end());
        let listener = Listener::new(config.clone(), ListenerConfig::default()).unwrap();
        let endpoint = zmux_http::Endpoint::new(listener.clone(), Options::default())
            .unwrap()
            .with_websocket(zmux_websocket::Options::default());
        let (addr, serving) = tls_server(endpoint, acceptor).await;
        let https = Options::default().with_https(true);
        let h2 =
            Http2Connection::handshake(tls_conn(&connector, addr, b"h2").await, "localhost", https)
                .await
                .unwrap();
        let cs = Session::connect(h2.open_pipe().await.unwrap(), config.clone())
            .await
            .unwrap();
        let ss = listener.accept().await.unwrap();

        // The WebSocket on a TLS connection of its own, declared by the client.
        let conn = tls_conn(&connector, addr, b"h2").await;
        let binding = conn.binding();
        let (mut sender, driver) =
            hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(conn))
                .await
                .unwrap();
        tokio::spawn(driver);
        let mut req = http::Request::builder()
            .method(http::Method::CONNECT)
            .uri(format!("https://localhost:{}/zmux", addr.port()))
            .header("sec-websocket-version", "13")
            .header("sec-websocket-protocol", "qmux-02")
            .body(zmux_http::PipeBody::empty())
            .unwrap();
        req.extensions_mut()
            .insert(hyper::ext::Protocol::from_static("websocket"));
        let resp = sender.send_request(req).await.unwrap();
        assert_eq!(resp.status(), http::StatusCode::OK);
        let upgraded = hyper::upgrade::on(resp).await.unwrap();
        let ws = WebSocketStream::from_raw_socket(TokioIo::new(upgraded), Role::Client, None).await;
        let io = binding.apply(zmux_websocket::pipe(ws, Some("qmux-02".into())));
        assert!(io.bound_exporter().is_some());
        joined_bound(&cs, io).await.unwrap();

        cs.close().await;
        drop(ss);
        listener.close();
        serving.await.unwrap();
    });
}

/// A credential bound to the TLS connection (prefix authentication with a
/// TLS binding) passes the HTTP server's admission over HTTP/2 and
/// HTTP/1.1: both ends read the connection's metadata from its one source,
/// `TlsBinding::info`.
#[test]
fn a_bound_prefix_token_passes_over_tls() {
    support::run(2, 90, || async {
        let (connector, acceptor) = tls();
        let (auth, verifier) = ticket::fixture(zmux::PrefixBinding::Bound);
        let mut limits = ListenerConfig::default();
        limits.admission = Some(zmux::Admission::prefix_auth(
            verifier,
            zmux::PrefixRejection::Fallback,
        ));
        let listener = Listener::new(Config::default(), limits).unwrap();
        let endpoint = zmux_http::Endpoint::new(listener.clone(), Options::default()).unwrap();
        let (addr, serving) = tls_server(endpoint, acceptor).await;
        let https = Options::default()
            .with_https(true)
            .with_carrier_credential(Arc::new(auth));
        let h2 = Http2Connection::handshake(
            tls_conn(&connector, addr, b"h2").await,
            "localhost",
            https.clone(),
        )
        .await
        .unwrap();
        let cs = Session::connect(h2.open_pipe().await.unwrap(), Config::default())
            .await
            .unwrap();
        let ss = tokio::time::timeout(Duration::from_secs(10), listener.accept())
            .await
            .unwrap()
            .unwrap();
        let io = zmux_http::dial_http1_over(
            tls_conn(&connector, addr, b"http/1.1").await,
            "localhost",
            &https,
        )
        .await
        .unwrap();
        let cs1 = Session::connect(io, Config::default()).await.unwrap();
        assert_eq!(listener.stats().admission.accepted, 2);
        drop((cs, cs1, ss));
        listener.close();
        serving.await.unwrap();
    });
}
