//! Connections under a listener admission: a bound prefix authentication
//! token on the first stream, the listener's fallback taking the first
//! stream over, the close without one, and streams held back until the
//! first stream is accepted.

#![cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]

mod common;

#[path = "../../test-support/ticket.rs"]
mod ticket;

use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use zmux::{
    Admission, AdmissionVerdict, Config, Fallback, Listener, ListenerConfig, PipeAuth, PipeOptions,
    PrefixAuth, Session, Takeover,
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
        let opts = common::adopted_options(Options::default());
        let (endpoint, client) = common::endpoints(
            zmux::alpn_protocols(&[]),
            opts.transport_config(),
            opts.transport_config(),
        );
        let addr = endpoint.local_addr().unwrap();
        let mut c = Config::default();
        c.session_policy.limits.steady_attachments = 4;
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
    ticket::fixture(zmux::PrefixBinding::Bound).0
}

fn admission() -> Admission {
    Admission::prefix_auth(
        ticket::fixture(zmux::PrefixBinding::Bound).1,
        zmux::PrefixRejection::Fallback,
    )
    .with_peek_timeout(Duration::from_secs(5))
    .with_stall_interval(Duration::from_millis(10), Duration::from_millis(20))
}

/// The bound token of a client's connection.
fn token(conn: &quinn::Connection) -> [u8; zmux::PREFIX_TOKEN_LEN] {
    auth()
        .token(&zmux_quinn::Handshake::of(conn).carrier_info(conn))
        .unwrap()
}

#[path = "../../test-support/transfer.rs"]
mod streams;
use streams::transfer;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_bound_token_is_accepted_and_the_connection_carries_further_pipes() {
    for one_by_one in [false, true] {
        bound_token(Server::with(admission(), None, one_by_one)).await;
    }
}

async fn bound_token(server: Server) {
    let conn = server.connect().await;
    let carrier = Carrier::new(conn.clone(), &common::adopted_options(Options::default())).unwrap();
    let pipe = carrier.open_pipe_with_prefix(&token(&conn)).await.unwrap();
    let mut config = Config::default();
    config.session_policy.limits.steady_attachments = 4;
    config.pipe_auth = PipeAuth::exporter().with_end_to_end();
    let client = Session::connect(pipe, config).await.unwrap();
    let accepted = tokio::time::timeout(LIMIT, server.listener.accept())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(accepted.protocol().as_deref(), Some("qmux-02"));
    assert_eq!(accepted.bound_prefix_principal(), Some(ticket::ID));
    transfer(&client, &accepted, 8, 1 << 20).await;
    transfer(&accepted, &client, 2, 1 << 16).await;
    // A further pipe on the same connection joins without a token.
    let joined = client
        .test_begin_join(carrier.open_pipe().await.unwrap(), PipeOptions::default())
        .unwrap();
    tokio::time::timeout(LIMIT, joined.joined())
        .await
        .unwrap()
        .unwrap();
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
    tokio::time::timeout(LIMIT, async {
        let (detached, mut taken) = tokio::sync::mpsc::unbounded_channel();
        let fallback = Fallback::new(move |t: Takeover| {
            let detached = detached.clone();
            async move {
                t.detach().unwrap();
                let conn = zmux_quinn::takeover_connection(&t).unwrap();
                let stream = t.into_stream().unwrap();
                let (release, keep) = tokio::sync::oneshot::channel();
                detached.send(release).unwrap();
                let _ = keep.await;
                let mut stream = stream;
                let mut got = Vec::new();
                stream.read_to_end(&mut got).await.unwrap();
                stream.write_all(&got).await.unwrap();
                stream.shutdown().await.unwrap();
                let mut more = conn.open_uni().await.unwrap();
                more.write_all(b"later").await.unwrap();
                more.finish().unwrap();
                let mut done = conn.accept_uni().await.unwrap();
                assert_eq!(done.read_to_end(16).await.unwrap(), b"read");
                conn.close(quinn::VarInt::from_u32(7), b"host");
            }
        });
        let server = Server::with(admission(), Some(fallback), true);
        let conn = server.connect().await;
        let (mut send, mut recv) = conn.open_bi().await.unwrap();
        let payload = vec![9u8; zmux::PREFIX_TOKEN_LEN + 10];
        send.write_all(&payload).await.unwrap();
        send.finish().unwrap();
        let release = taken.recv().await.unwrap();
        server.listener.close();
        release.send(()).unwrap();
        assert_eq!(recv.read_to_end(1024).await.unwrap(), payload);
        let mut later = conn.accept_uni().await.unwrap();
        assert_eq!(later.read_to_end(64).await.unwrap(), b"later");
        let mut done = conn.open_uni().await.unwrap();
        done.write_all(b"read").await.unwrap();
        done.finish().unwrap();
        match conn.closed().await {
            quinn::ConnectionError::ApplicationClosed(c) => {
                assert_eq!(c.error_code.into_inner(), 7);
            }
            e => panic!("{e:?}"),
        }
        server.stop().await;
    })
    .await
    .unwrap();
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
    let carrier = Carrier::new(conn.clone(), &common::adopted_options(Options::default())).unwrap();
    let mut config = Config::default();
    config.session_policy.limits.steady_attachments = 4;
    config.pipe_auth = PipeAuth::exporter().with_end_to_end();
    let pipe = carrier.open_pipe().await.unwrap();
    let connecting = tokio::spawn(Session::connect(pipe, config));
    let mut uni = conn.open_uni().await.unwrap();
    uni.write_all(b"not a lane").await.unwrap();
    {
        let mut early = std::pin::pin!(server.listener.accept());
        assert!(
            std::future::Future::poll(
                early.as_mut(),
                &mut std::task::Context::from_waker(std::task::Waker::noop()),
            )
            .is_pending()
        );
    }
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
