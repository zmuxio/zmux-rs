//! Connections under a listener admission: a bound prefix authentication
//! token on the first stream, the fallback handler, the close without one,
//! and streams held back until the first stream is accepted.

use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::io::AsyncReadExt;
use zmux::{
    Admission, Config, Listener, ListenerConfig, OutboundState, PipeAuth, PipeOptions, PrefixAuth,
    PrefixAuthVerifier, Session, Verdict,
};
use zmux_quinn::{Options, QuicCarrier, QuicFallback};

const LIMIT: Duration = Duration::from_secs(20);

struct Server {
    addr: std::net::SocketAddr,
    listener: Listener,
    client: quinn::Endpoint,
    serving: tokio::task::JoinHandle<()>,
}

impl Server {
    fn new(admission: Admission, fallback: Option<QuicFallback>) -> Self {
        Self::with(admission, fallback, false)
    }

    /// With `one_by_one`, the host accepts each connection itself and
    /// hands it over with `serve_connection`.
    fn with(admission: Admission, fallback: Option<QuicFallback>, one_by_one: bool) -> Self {
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
        tls.alpn_protocols = zmux::alpn_protocols(&[]);
        let opts = Options::default();
        let endpoint = quinn::Endpoint::server(
            zmux_quinn::server_config(tls, &opts).unwrap(),
            "127.0.0.1:0".parse().unwrap(),
        )
        .unwrap();
        let addr = endpoint.local_addr().unwrap();
        let mut c = Config::default();
        c.max_pipes = 4;
        c.pipe_auth = PipeAuth::tls();
        let mut lc = ListenerConfig::default();
        lc.admission = Some(admission);
        let listener = Listener::new(c, lc);
        let serving = if one_by_one {
            let (l, opts) = (listener.clone(), opts.clone());
            tokio::spawn(async move {
                let closed = l.closed();
                let mut closed = std::pin::pin!(closed);
                loop {
                    let incoming = tokio::select! {
                        i = endpoint.accept() => i,
                        () = &mut closed => return,
                    };
                    let Some(incoming) = incoming else { return };
                    let Ok(conn) = incoming.await else { continue };
                    let (l, opts, f) = (l.clone(), opts.clone(), fallback.clone());
                    tokio::spawn(async move {
                        let _ = zmux_quinn::serve_connection(&l, conn, &opts, f.as_ref()).await;
                    });
                }
            })
        } else {
            tokio::spawn(zmux_quinn::serve(
                listener.clone(),
                endpoint,
                opts.clone(),
                fallback,
            ))
        };
        let mut roots = rustls::RootCertStore::empty();
        roots.add(der).unwrap();
        let mut tls = rustls::ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        tls.alpn_protocols = zmux::alpn_protocols(&[]);
        let mut client = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        client.set_default_client_config(zmux_quinn::client_config(tls, &opts).unwrap());
        Self {
            addr,
            listener,
            client,
            serving,
        }
    }

    async fn connect(&self) -> quinn::Connection {
        self.client
            .connect(self.addr, "localhost")
            .unwrap()
            .await
            .unwrap()
    }

    async fn stop(self) {
        self.listener.close();
        self.serving.await.unwrap();
    }
}

fn auth() -> PrefixAuth {
    PrefixAuth::new(b"key", Duration::from_secs(30), true).unwrap()
}

fn admission() -> Admission {
    Admission::prefix_auth(Arc::new(PrefixAuthVerifier::new(auth(), 1, 1024)))
        .with_peek_timeout(Duration::from_secs(5))
        .with_stall_interval(Duration::from_millis(10), Duration::from_millis(20))
}

/// The bound token of a client's connection.
fn token(conn: &quinn::Connection) -> [u8; zmux::PREFIX_TOKEN_LEN] {
    let mut binding = [0u8; zmux::PREFIX_AUTH_BINDING_LEN];
    conn.export_keying_material(
        &mut binding,
        zmux::PREFIX_AUTH_EXPORTER_LABEL.as_bytes(),
        b"",
    )
    .unwrap();
    auth().token(Some(&binding)).unwrap()
}

/// Streams of `len` bytes from `from` to `to`, every byte checked.
async fn transfer(from: &Session, to: &Session, n: usize, len: usize) {
    let to = to.clone();
    let receiver = tokio::spawn(async move {
        for _ in 0..n {
            let mut recv = to.accept_uni().await.unwrap();
            let data = recv.read_to_end(len + 1).await.unwrap();
            assert_eq!(data.len(), len);
            assert!(data.iter().enumerate().all(|(i, &b)| b == (i % 251) as u8));
        }
    });
    let data = bytes::Bytes::from((0..len).map(|i| (i % 251) as u8).collect::<Vec<_>>());
    for _ in 0..n {
        let mut send = from.open_uni().await.unwrap();
        send.write_chunk(data.clone()).await.unwrap();
        send.finish().unwrap();
    }
    receiver.await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_bound_token_is_accepted_and_the_connection_carries_further_pipes() {
    for one_by_one in [false, true] {
        bound_token(Server::with(admission(), None, one_by_one)).await;
    }
}

async fn bound_token(server: Server) {
    let conn = server.connect().await;
    let carrier = QuicCarrier::new(conn.clone(), Options::default());
    let pipe = carrier.open_pipe_with_prefix(&token(&conn)).await.unwrap();
    let mut config = Config::default();
    config.max_pipes = 4;
    config.pipe_auth = PipeAuth::tls();
    let client = Session::connect(pipe, config).await.unwrap();
    let accepted = tokio::time::timeout(LIMIT, server.listener.accept())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(accepted.protocol().as_deref(), Some("qmux-02"));
    transfer(&client, &accepted, 8, 1 << 20).await;
    transfer(&accepted, &client, 2, 1 << 16).await;
    // A further pipe on the same connection joins without a token.
    let joined = client
        .add_pipe(carrier.open_pipe().await.unwrap(), PipeOptions::default())
        .unwrap();
    let deadline = tokio::time::Instant::now() + LIMIT;
    while joined.stats().and_then(|i| i.outbound) != Some(OutboundState::Active) {
        assert!(tokio::time::Instant::now() < deadline, "the join failed");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    transfer(&client, &accepted, 4, 1 << 18).await;
    assert_eq!(server.listener.stats().setup_failures, 0);
    client.close(0u32.into(), b"");
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_wrong_token_goes_to_the_fallback_with_every_byte() {
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let fallback = QuicFallback::new(move |conn, _send, mut recv| {
        let tx = tx.clone();
        async move {
            let mut got = Vec::new();
            recv.read_to_end(&mut got).await.unwrap();
            let _ = tx.send(got);
            conn.close(0u32.into(), b"");
        }
    });
    let server = Server::new(admission(), Some(fallback));
    let conn = server.connect().await;
    let (mut send, _recv) = conn.open_bi().await.unwrap();
    let sent: Vec<u8> = (0..100u8).collect();
    send.write_all(&sent).await.unwrap();
    send.finish().unwrap();
    let got = tokio::time::timeout(LIMIT, rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(got, sent);
    tokio::time::timeout(LIMIT, conn.closed()).await.unwrap();
    assert_eq!(server.listener.stats().sessions, 0);
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn without_a_fallback_a_wrong_token_closes_the_connection() {
    let server = Server::new(admission(), None);
    let conn = server.connect().await;
    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    send.write_all(&[0u8; zmux::PREFIX_TOKEN_LEN])
        .await
        .unwrap();
    tokio::time::timeout(LIMIT, conn.closed()).await.unwrap();
    let mut buf = Vec::new();
    let _ = AsyncReadExt::read_to_end(&mut recv, &mut buf).await;
    assert!(buf.is_empty(), "nothing is written before acceptance");
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn streams_reach_the_listener_only_after_the_first_is_accepted() {
    let admission = Admission::new(4, |_, prefix| {
        if prefix == b"open" {
            Verdict::accept(4)
        } else {
            Verdict::Close
        }
    })
    .with_peek_timeout(Duration::from_secs(10));
    let server = Server::new(admission, None);
    let conn = server.connect().await;
    // Stream 0: the first bidirectional stream, its prefix not sent yet.
    let (mut first, _first_recv) = conn.open_bi().await.unwrap();
    // A session started on stream 4, and a unidirectional stream.
    let carrier = QuicCarrier::new(conn.clone(), Options::default());
    let mut config = Config::default();
    config.max_pipes = 4;
    config.pipe_auth = PipeAuth::tls();
    let pipe = carrier.open_pipe().await.unwrap();
    let connecting = tokio::spawn(Session::connect(pipe, config));
    let mut uni = conn.open_uni().await.unwrap();
    uni.write_all(b"not a lane").await.unwrap();
    let early = tokio::time::timeout(Duration::from_millis(500), server.listener.accept()).await;
    assert!(
        early.is_err(),
        "a session before the first stream was accepted"
    );
    let stats = server.listener.stats();
    assert_eq!((stats.sessions, stats.refused), (0, 0));
    assert_eq!(stats.admission, zmux::AdmissionStats::default());
    first.write_all(b"open").await.unwrap();
    let accepted = tokio::time::timeout(LIMIT, server.listener.accept())
        .await
        .unwrap()
        .unwrap();
    let client = connecting.await.unwrap().unwrap();
    transfer(&client, &accepted, 2, 1 << 16).await;
    client.close(0u32.into(), b"");
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_credential_writes_a_bound_token_on_the_first_stream() {
    let server = Server::new(admission(), None);
    let options = Options::default().with_credential(Arc::new(auth()));
    let mut config = Config::default();
    config.pipe_auth = PipeAuth::tls();
    let client = zmux_quinn::connect(&server.client, server.addr, "localhost", &options, config)
        .await
        .unwrap();
    let accepted = tokio::time::timeout(LIMIT, server.listener.accept())
        .await
        .unwrap()
        .unwrap();
    transfer(&client, &accepted, 2, 1 << 16).await;
    client.close(0u32.into(), b"");
    server.stop().await;
}
