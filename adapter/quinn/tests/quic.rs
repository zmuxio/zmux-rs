//! QUIC carriers over loopback: a session's lanes on further streams of
//! its connection, a Bound join over a second connection through a
//! listener, and a connection that closes once nothing of zmux holds it.

use std::sync::Arc;
use std::time::Duration;

use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use zmux::{
    Config, Listener, ListenerConfig, OutboundState, PipeAuth, PipeOptions, Session, SessionEvent,
};
use zmux_quinn::{Carrier, Options};

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
    c.pipe_auth = auth.with_end_to_end();
    c.allow_record_mode = Some(zmux::AllowRecordMode::new(|_, _, _| true));
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
    let client = Carrier::new(cc.clone(), Options::default());
    let server = Carrier::new(sc.clone(), Options::default());
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
    cs.close().await;
    drop(cs);
    tokio::time::timeout(Duration::from_secs(10), sc.closed())
        .await
        .expect("the client's connection closed");
    drop(ss);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_bound_join_over_a_second_connection() {
    let quic = Quic::new();
    let listener = Listener::new(config(PipeAuth::exporter()), ListenerConfig::default())
        .expect("valid listener configuration");
    let (c1, s1) = quic.connect().await;
    let (c2, s2) = quic.connect().await;
    let _s1 = Carrier::with_listener(s1, &listener, Options::default());
    let _s2 = Carrier::with_listener(s2, &listener, Options::default());
    let q1 = Carrier::new(c1, Options::default());
    let q2 = Carrier::new(c2, Options::default());
    // The session secret comes from the first connection's exporter.
    let client = Session::connect(q1.open_pipe().await.unwrap(), config(PipeAuth::exporter()))
        .await
        .unwrap();
    let server = listener.accept().await.unwrap();
    assert_eq!(client.multipath(), zmux::Multipath::InUse);
    let pipe = client
        .begin_add_pipe(
            q2.open_pipe().await.unwrap(),
            PipeOptions::default().with_record_mode(zmux::RecordMode::Bound),
        )
        .unwrap();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while pipe.stats().and_then(|i| i.outbound) != Some(OutboundState::Active) {
        assert!(tokio::time::Instant::now() < deadline, "the join failed");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    transfer(&client, &server, 4, 1 << 20).await;
    assert_kind([&client, &server], zmux::CarrierKind::Quic);
    for s in [&client, &server] {
        let joined = s.pipe(pipe.id()).unwrap().stats().unwrap();
        assert_eq!(joined.carrier, Some(zmux::CarrierKind::Quic));
    }
    while let Ok(Some(e)) = tokio::time::timeout(Duration::ZERO, server.next_event()).await {
        assert!(!matches!(e, SessionEvent::JoinAuthFailed { .. }), "{e:?}");
    }
    client.close().await;
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
/// sessions: the configurations keep the ALPN identifiers configured and
/// get the carrier's transport parameters, the session reports the
/// negotiated identifier, and streams go both ways (with lanes).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn connect_and_serve_with_zmux_alpn() {
    let (mut client_tls, mut server_tls) = plain_tls();
    client_tls.alpn_protocols = zmux::alpn_protocols(&[]);
    server_tls.alpn_protocols = zmux::alpn_protocols(&[]);
    let opts = Options::default();
    let server_ep = quinn::Endpoint::server(
        zmux_quinn::server_config(server_tls, &opts).unwrap(),
        "127.0.0.1:0".parse().unwrap(),
    )
    .unwrap();
    let addr = server_ep.local_addr().unwrap();
    let listener = Listener::new(Config::default(), ListenerConfig::default())
        .expect("valid listener configuration");
    let serving = tokio::spawn(zmux_quinn::serve(
        listener.clone(),
        server_ep,
        opts.clone(),
        None,
    ));
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
    client.close().await;
    assert!(matches!(
        server.closing().await,
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
    let client = Carrier::new(cc, Options::default());
    let server = Carrier::new(sc, Options::default());
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
}

/// Pipe 0 of each session is of carrier kind `kind`.
fn assert_kind(sessions: [&Session; 2], kind: zmux::CarrierKind) {
    for s in sessions {
        let p = s.pipe(zmux::PipeId::new(0)).unwrap();
        assert_eq!(p.stats().unwrap().carrier, Some(kind));
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_pipe_dropped_unfinished_resets_its_stream() {
    let quic = Quic::new();
    let (cc, sc) = quic.connect().await;
    let client = Carrier::new(cc, Options::default());
    let pipe = client.open_pipe_with_prefix(b"x").await.unwrap();
    let (_send, mut recv) = sc.accept_bi().await.unwrap();
    drop(pipe);
    let read = tokio::time::timeout(Duration::from_secs(10), recv.read_to_end(1 << 10))
        .await
        .expect("ended");
    assert!(
        matches!(read, Err(quinn::ReadToEndError::Read(quinn::ReadError::Reset(code)))
            if code.into_inner() == zmux::proto::ApplicationErrorCode::ZMUX_CARRIER_FAILED.0),
        "{read:?}"
    );
    drop(client);
}

/// The ends a session makes on purpose finish their streams: a pipe closed
/// gracefully, its lanes, and the pipes of a closed session reach the peer
/// as a clean end (FIN), never as a reset that fails them.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn graceful_ends_finish_their_streams() {
    let quic = Quic::new();
    let (cc, sc) = quic.connect().await;
    let listener = Listener::new(config(PipeAuth::exporter()), ListenerConfig::default())
        .expect("valid listener configuration");
    let _server_carrier = Carrier::with_listener(sc, &listener, Options::default());
    let carrier = Carrier::new(cc, Options::default());
    let client = Session::connect(
        carrier.open_pipe().await.unwrap(),
        config(PipeAuth::exporter()),
    )
    .await
    .unwrap();
    let server = listener.accept().await.unwrap();
    let pipe = client
        .add_pipe(carrier.open_pipe().await.unwrap(), PipeOptions::default())
        .await
        .unwrap();
    // Lanes on both pipes.
    transfer(&client, &server, 8, 1 << 20).await;
    let clean = |s: &Session| {
        s.pipe_stats()
            .iter()
            .all(|p| p.failure.is_none() && p.failure_count == 0)
    };
    pipe.close().unwrap();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while server
        .pipe(pipe.id())
        .and_then(|p| p.stats())
        .is_some_and(|p| p.inbound != Some(zmux::InboundState::Ended))
    {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the pipe did not end"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert!(clean(&server), "{:?}", server.pipe_stats());
    transfer(&client, &server, 4, 256 << 10).await;
    client.close().await;
    let e = tokio::time::timeout(Duration::from_secs(10), server.closed())
        .await
        .expect("the session ended");
    assert!(
        matches!(
            e,
            zmux::SessionError::ApplicationClosed { remote: true, .. }
        ),
        "{e:?}"
    );
    assert!(clean(&server), "{:?}", server.pipe_stats());
    while let Ok(Some(e)) = tokio::time::timeout(Duration::ZERO, server.next_event()).await {
        assert!(!matches!(e, SessionEvent::PipeFailed { .. }), "{e:?}");
    }
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
    let end = tokio::time::timeout(Duration::from_secs(5), client.closed())
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

/// N16 over QUIC: as on the other carriers, and the QUIC connection is
/// closed after the zmux close was read, with the same application code
/// (0 for the plain close). The server keeps its carrier, as `serve` does
/// while the connection is open, so the client's adapter closes it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_close_is_delivered_with_its_code_and_ends_the_connection_with_it() {
    for (code, reason, slow) in [
        (0x2a, &b"bye"[..], false),
        (0, &b""[..], false),
        (0x2a, &b"bye"[..], true),
    ] {
        let quic = Quic::new();
        let (cc, sc) = quic.connect().await;
        let client = Carrier::new(cc, Options::default());
        let server = Carrier::new(sc.clone(), Options::default());
        let accept = {
            let server = server.clone();
            tokio::spawn(async move {
                Session::accept(server.accept_pipe().await.unwrap(), Config::default())
                    .await
                    .unwrap()
            })
        };
        let cs = Session::connect(
            client.open_pipe().await.unwrap(),
            lingering(Config::default()),
        )
        .await
        .unwrap();
        drop(client);
        let ss = accept.await.unwrap();
        close_delivery(&cs, &ss, code, reason, slow).await;
        drop(cs);
        let end = tokio::time::timeout(Duration::from_secs(5), sc.closed())
            .await
            .expect("the client's adapter closed the connection");
        match end {
            quinn::ConnectionError::ApplicationClosed(c) => {
                assert_eq!(c.error_code, quinn::VarInt::from_u32(code));
            }
            other => panic!("{other:?}"),
        }
        drop((server, ss));
    }
}

/// An abort keeps the order: the connection closes with the abort's code
/// once the peer ended its side, never before the peer read the close.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_abort_ends_the_connection_with_its_code_after_the_close() {
    let quic = Quic::new();
    let (cc, sc) = quic.connect().await;
    let client = Carrier::new(cc, Options::default());
    let server = Carrier::new(sc.clone(), Options::default());
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
    drop(client);
    let ss = accept.await.unwrap();
    cs.abort(zmux::VarInt::from_u32(9), b"gone");
    let seen = tokio::time::timeout(Duration::from_secs(5), ss.closing())
        .await
        .unwrap();
    assert!(
        matches!(&seen, zmux::SessionError::ApplicationClosed { code, remote: true, .. } if *code == zmux::VarInt::from_u32(9)),
        "{seen:?}"
    );
    drop(cs);
    match tokio::time::timeout(Duration::from_secs(5), sc.closed())
        .await
        .expect("the connection closed")
    {
        quinn::ConnectionError::ApplicationClosed(c) => {
            assert_eq!(c.error_code, quinn::VarInt::from_u32(9));
        }
        other => panic!("{other:?}"),
    }
    drop((server, ss));
}
