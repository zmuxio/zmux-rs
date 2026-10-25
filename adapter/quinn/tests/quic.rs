//! QUIC carriers over loopback: a session's lanes on further streams of
//! its connection, a carrier-bound join over a second connection through a
//! listener, and a connection that closes once nothing of zmux holds it.

use std::sync::Arc;
use std::time::Duration;

use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use zmux::{
    Config, Listener, ListenerConfig, PipeAuth, PipeOptions, PipeState, Session, SessionEvent,
};
use zmux_quinn::{Options, QuicCarrier};

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
        let mut tls = rustls::ServerConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![der.clone()], key)
            .unwrap();
        tls.alpn_protocols = vec![b"zmux".to_vec()];
        let server_config =
            quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(tls).unwrap()));
        let server =
            quinn::Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(der).unwrap();
        let mut tls = rustls::ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        tls.alpn_protocols = vec![b"zmux".to_vec()];
        let mut client = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        client.set_default_client_config(quinn::ClientConfig::new(Arc::new(
            QuicClientConfig::try_from(tls).unwrap(),
        )));
        Self { server, client }
    }

    /// A connection: the client's end and the server's.
    async fn connect(&self) -> (quinn::Connection, quinn::Connection) {
        let addr = self.server.local_addr().unwrap();
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

fn config(auth: PipeAuth) -> Config {
    let mut c = Config::default();
    c.max_pipes = 4;
    c.pipe_auth = auth;
    c
}

/// Sends `n` streams of `len` bytes each from `from` to `to` at once and
/// checks every byte.
async fn transfer(from: &Session, to: &Session, n: usize, len: usize) {
    let receiver = {
        let to = to.clone();
        tokio::spawn(async move {
            let mut readers = Vec::new();
            for _ in 0..n {
                let mut recv = to.accept_uni().await.unwrap();
                readers.push(tokio::spawn(async move {
                    recv.read_to_end(len + 1).await.unwrap()
                }));
            }
            for r in readers {
                let data = r.await.unwrap();
                assert_eq!(data.len(), len);
                assert!(data.iter().enumerate().all(|(i, &b)| b == (i % 251) as u8));
            }
        })
    };
    let data = bytes::Bytes::from((0..len).map(|i| (i % 251) as u8).collect::<Vec<_>>());
    let mut writers = Vec::new();
    for _ in 0..n {
        let mut send = from.open_uni().await.unwrap();
        let data = data.clone();
        writers.push(tokio::spawn(async move {
            send.write_chunk(data).await.unwrap();
            send.finish().unwrap();
            send
        }));
    }
    for w in writers {
        drop(w.await.unwrap());
    }
    receiver.await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn lanes_ride_further_streams_and_the_connection_closes_once_unused() {
    let quic = Quic::new();
    let (cc, sc) = quic.connect().await;
    let client = QuicCarrier::new(cc.clone(), Options::default());
    let server = QuicCarrier::new(sc.clone(), Options::default());
    let accept = {
        let server = server.clone();
        tokio::spawn(async move {
            Session::accept(server.accept_pipe().await.unwrap(), Config::default())
                .await
                .unwrap()
        })
    };
    let cs = Session::connect(client.open_pipe().await.unwrap(), Config::default())
        .await
        .unwrap();
    let ss = accept.await.unwrap();
    // The pipes keep their carriers (the lane opener, the accept loop that
    // routes the lanes) alive without the application's handles.
    drop((client, server));
    transfer(&cs, &ss, 8, 4 << 20).await;
    // The client opened lanes: further unidirectional streams of the
    // connection (the next one's index counts them).
    let next = cc.open_uni().await.unwrap();
    assert!(next.id().index() >= 1, "no lane was opened");
    drop((next, cc));

    // Nothing of zmux keeps the connection once the sessions and their
    // pipes are gone: it closes, and the server sees it.
    cs.close(0u32.into(), b"");
    drop(cs);
    tokio::time::timeout(Duration::from_secs(10), sc.closed())
        .await
        .expect("the client's connection closed");
    drop(ss);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_carrier_bound_join_over_a_second_connection() {
    let quic = Quic::new();
    let listener = Listener::new(config(PipeAuth::tls()), ListenerConfig::default());
    let (c1, s1) = quic.connect().await;
    let (c2, s2) = quic.connect().await;
    let _s1 = QuicCarrier::with_listener(s1, &listener, Options::default());
    let _s2 = QuicCarrier::with_listener(s2, &listener, Options::default());
    let q1 = QuicCarrier::new(c1, Options::default());
    let q2 = QuicCarrier::new(c2, Options::default());
    // The session secret comes from the first connection's exporter.
    let client = Session::connect(q1.open_pipe().await.unwrap(), config(PipeAuth::tls()))
        .await
        .unwrap();
    let server = listener.accept().await.unwrap();
    assert!(client.multipath() == zmux::Multipath::InUse);
    let pipe = client
        .add_pipe(q2.open_pipe().await.unwrap(), PipeOptions::default())
        .unwrap();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while pipe.stats().and_then(|i| i.outbound) != Some(PipeState::Active) {
        assert!(tokio::time::Instant::now() < deadline, "the join failed");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    transfer(&client, &server, 4, 1 << 20).await;
    while let Ok(Some(e)) = tokio::time::timeout(Duration::ZERO, server.next_event()).await {
        assert!(!matches!(e, SessionEvent::JoinAuthFailed { .. }), "{e:?}");
    }
    client.close(0u32.into(), b"");
}

/// A rustls configuration pair for "localhost" without ALPN identifiers.
fn plain_tls() -> (rustls::ClientConfig, rustls::ServerConfig) {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let der = CertificateDer::from(cert.cert.der().to_vec());
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()));
    let server = rustls::ServerConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![der.clone()], key)
        .unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(der).unwrap();
    let client = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    (client, server)
}

/// One step from an endpoint to a session and from an endpoint to its
/// sessions: the configurations get zmux's ALPN identifiers and the
/// carrier's transport parameters, the session reports the negotiated
/// identifier, and streams go both ways (with lanes).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn connect_and_serve_with_the_default_alpn() {
    let (client_tls, server_tls) = plain_tls();
    let opts = Options::default();
    let server_ep = quinn::Endpoint::server(
        zmux_quinn::server_config(server_tls, &opts).unwrap(),
        "127.0.0.1:0".parse().unwrap(),
    )
    .unwrap();
    let addr = server_ep.local_addr().unwrap();
    let listener = Listener::new(Config::default(), ListenerConfig::default());
    let serving = tokio::spawn(zmux_quinn::serve(listener.clone(), server_ep, opts.clone()));
    let mut client_ep = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    client_ep.set_default_client_config(zmux_quinn::client_config(client_tls, &opts).unwrap());
    let client = zmux_quinn::connect(&client_ep, addr, "localhost", &opts, Config::default())
        .await
        .unwrap();
    let server = listener.accept().await.unwrap();
    assert_eq!(client.protocol().as_deref(), Some("qmux-02"));
    assert_eq!(server.protocol().as_deref(), Some("qmux-02"));
    transfer(&client, &server, 4, 1 << 20).await;
    transfer(&server, &client, 4, 1 << 20).await;
    client.close(0u32.into(), b"bye");
    assert!(matches!(
        server.closed().await,
        zmux::SessionError::ApplicationClosed { remote: true, .. }
    ));
    listener.close();
    serving.await.unwrap();
}

/// A connection that is lost (here closed under the session) is a failure
/// of the pipes on it, never their clean end.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_lost_connection_is_a_failure_not_a_clean_end() {
    let quic = Quic::new();
    let (cc, sc) = quic.connect().await;
    let client = QuicCarrier::new(cc, Options::default());
    let server = QuicCarrier::new(sc, Options::default());
    let accept = {
        let server = server.clone();
        tokio::spawn(async move {
            Session::accept(server.accept_pipe().await.unwrap(), Config::default())
                .await
                .unwrap()
        })
    };
    let cs = Session::connect(client.open_pipe().await.unwrap(), Config::default())
        .await
        .unwrap();
    let ss = accept.await.unwrap();
    transfer(&cs, &ss, 2, 64 << 10).await;
    client.connection().close(7u32.into(), b"gone");
    for s in [&cs, &ss] {
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
}
