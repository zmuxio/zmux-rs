//! Connections under a listener admission: a bound prefix authentication
//! token on the first stream, the listener's fallback taking the first
//! stream over, the close without one, and streams held back until the
//! first stream is accepted.

use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use zmux::{
    Admission, AdmissionVerdict, Config, Fallback, Listener, ListenerConfig, OutboundState,
    PipeAuth, PipeOptions, PrefixAuth, PrefixAuthVerifier, Session, Takeover,
};
use zmux_quinn::{Carrier, Options};

const LIMIT: Duration = Duration::from_secs(20);

struct Server {
    addr: std::net::SocketAddr,
    listener: Listener,
    client: quinn::Endpoint,
    serving: tokio::task::JoinHandle<()>,
}

impl Server {
    fn new(admission: Admission, fallback: Option<Fallback>) -> Self {
        Self::with(admission, fallback, false)
    }

    /// With `one_by_one`, the host accepts each connection itself and
    /// hands it over with `serve_connection`.
    fn with(admission: Admission, fallback: Option<Fallback>, one_by_one: bool) -> Self {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let cert = zmux_testcert::self_signed(vec!["localhost".into()]).unwrap();
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
        c.pipe_auth = PipeAuth::exporter().with_end_to_end();
        let mut lc = ListenerConfig::default();
        lc.admission = Some(admission);
        lc.fallback = fallback;
        let listener = Listener::new(c, lc).expect("valid listener configuration");
        let serving = if one_by_one {
            let (l, opts) = (listener.clone(), opts.clone());
            tokio::spawn(async move {
                let closed = l.adapter().closed();
                let mut closed = std::pin::pin!(closed);
                loop {
                    let incoming = tokio::select! {
                        i = endpoint.accept() => i,
                        () = &mut closed => return,
                    };
                    let Some(incoming) = incoming else { return };
                    let Ok(conn) = incoming.await else { continue };
                    let (l, opts) = (l.clone(), opts.clone());
                    tokio::spawn(async move {
                        let _ = zmux_quinn::serve_connection(&l, conn, &opts).await;
                    });
                }
            })
        } else {
            tokio::spawn(zmux_quinn::serve(listener.clone(), endpoint, opts.clone()))
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
    Admission::prefix_auth(Arc::new(PrefixAuthVerifier::new(auth(), 1, 1024).unwrap()))
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
            assert!(
                data.iter()
                    .enumerate()
                    .all(|(i, &b)| b == u8::try_from(i % 251).unwrap())
            );
        }
    });
    let data = bytes::Bytes::from(
        (0..len)
            .map(|i| u8::try_from(i % 251).unwrap())
            .collect::<Vec<_>>(),
    );
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
    let carrier = Carrier::new(conn.clone(), Options::default());
    let pipe = carrier.open_pipe_with_prefix(&token(&conn)).await.unwrap();
    let mut config = Config::default();
    config.max_pipes = 4;
    config.pipe_auth = PipeAuth::exporter().with_end_to_end();
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
        .begin_add_pipe(carrier.open_pipe().await.unwrap(), PipeOptions::default())
        .unwrap();
    let deadline = tokio::time::Instant::now() + LIMIT;
    while joined.stats().and_then(|i| i.outbound) != Some(OutboundState::Active) {
        assert!(tokio::time::Instant::now() < deadline, "the join failed");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    transfer(&client, &accepted, 4, 1 << 18).await;
    assert_eq!(server.listener.stats().setup_failures, 0);
    client.close().await;
    server.stop().await;
}

/// The listener's fallback takes the first stream over, every byte read
/// replayed, with the connection; its answer reaches the client, and the
/// connection is closed once the fallback completed. Served one by one
/// too.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_wrong_token_goes_to_the_fallback_with_every_byte() {
    for one_by_one in [false, true] {
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let fallback = Fallback::new(move |t: Takeover| {
            let tx = tx.clone();
            async move {
                let conn = zmux_quinn::takeover_connection(&t).expect("a QUIC connection");
                let replayed = t.replayed().len();
                let mut stream = t.into_stream().expect("the first stream");
                let mut got = Vec::new();
                stream.read_to_end(&mut got).await.unwrap();
                stream.write_all(b"not zmux").await.unwrap();
                stream.shutdown().await.unwrap();
                let _ = tx.send((got, replayed, conn.remote_address()));
                // Served until the client has read the reply: it says so on
                // a stream of its own; the library closes the connection.
                let _ = tokio::time::timeout(LIMIT, conn.accept_uni()).await;
            }
        });
        let server = Server::with(admission(), Some(fallback), one_by_one);
        let conn = server.connect().await;
        let (mut send, mut recv) = conn.open_bi().await.unwrap();
        let payload: Vec<u8> = (0..100u8).collect();
        send.write_all(&payload).await.unwrap();
        send.finish().unwrap();
        let (got, replayed, peer) = tokio::time::timeout(LIMIT, rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(got, payload);
        assert_eq!(replayed, zmux::PREFIX_TOKEN_LEN);
        assert_eq!(peer, server.client.local_addr().unwrap());
        let reply = tokio::time::timeout(LIMIT, recv.read_to_end(64))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(reply, b"not zmux");
        let mut done = conn.open_uni().await.unwrap();
        done.write_all(b"read").await.unwrap();
        done.finish().unwrap();
        let closed = tokio::time::timeout(LIMIT, conn.closed()).await.unwrap();
        assert!(
            matches!(closed, quinn::ConnectionError::ApplicationClosed(_)),
            "{closed:?}"
        );
        let st = server.listener.stats();
        assert_eq!((st.sessions, st.admission.fallback), (0, 1));
        server.stop().await;
    }
}

/// A detached takeover keeps its QUIC connection past the fallback's
/// future: the host serves the stream and opens another on the connection
/// afterwards, and the library never closes it; the host does.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_detached_takeover_keeps_its_connection() {
    let fallback = Fallback::new(|t: Takeover| async move {
        t.detach().unwrap();
        let conn = zmux_quinn::takeover_connection(&t).expect("a QUIC connection");
        let mut stream = t.into_stream().expect("the first stream");
        tokio::spawn(async move {
            // Served once the future completed and its entry moved on.
            tokio::time::sleep(Duration::from_millis(100)).await;
            let mut got = Vec::new();
            stream.read_to_end(&mut got).await.unwrap();
            stream.write_all(&got).await.unwrap();
            stream.shutdown().await.unwrap();
            let mut more = conn.open_uni().await.unwrap();
            more.write_all(b"later").await.unwrap();
            more.finish().unwrap();
            // Done once the client has read it: it says so.
            let _ = tokio::time::timeout(LIMIT, conn.accept_uni()).await;
            conn.close(quinn::VarInt::from_u32(7), b"host");
        });
    });
    let server = Server::new(admission(), Some(fallback));
    let conn = server.connect().await;
    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    let payload = vec![9u8; zmux::PREFIX_TOKEN_LEN + 10];
    send.write_all(&payload).await.unwrap();
    send.finish().unwrap();
    let echo = tokio::time::timeout(LIMIT, recv.read_to_end(1024))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(echo, payload);
    let mut later = tokio::time::timeout(LIMIT, conn.accept_uni())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(later.read_to_end(64).await.unwrap(), b"later");
    let mut done = conn.open_uni().await.unwrap();
    done.write_all(b"read").await.unwrap();
    done.finish().unwrap();
    let closed = tokio::time::timeout(LIMIT, conn.closed()).await.unwrap();
    match closed {
        quinn::ConnectionError::ApplicationClosed(c) => assert_eq!(c.error_code.into_inner(), 7),
        e => panic!("{e:?}"),
    }
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
            AdmissionVerdict::accept(4)
        } else {
            AdmissionVerdict::Close
        }
    })
    .with_peek_timeout(Duration::from_secs(10));
    let server = Server::new(admission, None);
    let conn = server.connect().await;
    // Stream 0: the first bidirectional stream, its prefix not sent yet.
    let (mut first, _first_recv) = conn.open_bi().await.unwrap();
    // A session started on stream 4, and a unidirectional stream.
    let carrier = Carrier::new(conn.clone(), Options::default());
    let mut config = Config::default();
    config.max_pipes = 4;
    config.pipe_auth = PipeAuth::exporter().with_end_to_end();
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
    client.close().await;
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_credential_writes_a_bound_token_on_the_first_stream() {
    let server = Server::new(admission(), None);
    let options = Options::default().with_carrier_credential(Arc::new(auth()));
    let mut config = Config::default();
    config.pipe_auth = PipeAuth::exporter().with_end_to_end();
    let client = zmux_quinn::connect(&server.client, server.addr, "localhost", &options, config)
        .await
        .unwrap();
    let accepted = tokio::time::timeout(LIMIT, server.listener.accept())
        .await
        .unwrap()
        .unwrap();
    transfer(&client, &accepted, 2, 1 << 16).await;
    client.close().await;
    server.stop().await;
}
