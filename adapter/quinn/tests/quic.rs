//! QUIC carriers over loopback: a session's lanes on further streams of
//! its connection, a Bound join over a second connection through a
//! listener, and a connection that closes once nothing of zmux holds it.

#![cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]

mod common;

use std::sync::Arc;
use std::time::Duration;

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
        Self::with_transport(Options::default().transport_config())
    }

    /// With the server's transport configuration `transport`.
    fn with_transport(transport: quinn::TransportConfig) -> Self {
        let (server, client) = common::endpoints(
            vec![b"zmux".to_vec()],
            transport,
            Options::default().transport_config(),
        );
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
    c.session_policy.limits.steady_attachments = 4;
    c.pipe_auth = auth.with_end_to_end();
    c.allow_record_mode = Some(zmux::AllowRecordMode::new(|_, _, _| true));
    c
}

#[path = "../../test-support/transfer.rs"]
mod streams;
use streams::transfer;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn lanes_ride_further_streams_and_the_connection_closes_once_unused() {
    let quic = Quic::new();
    let (cc, sc) = quic.connect().await;
    let client = Carrier::new(cc.clone(), &common::adopted_options(Options::default())).unwrap();
    let server = Carrier::new(sc.clone(), &common::adopted_options(Options::default())).unwrap();
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
    // An additional lane may occupy the last QUIC unidirectional stream
    // slot. Observe the lanes of the transfer without waiting for a new slot.
    assert!(cs.pipe_stats().iter().any(|pipe| pipe.lanes_out > 1));
    drop(cc);

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
    let _s1 = Carrier::with_listener(s1, &listener, &common::adopted_options(Options::default()))
        .unwrap();
    let _s2 = Carrier::with_listener(s2, &listener, &common::adopted_options(Options::default()))
        .unwrap();
    let q1 = Carrier::new(c1, &common::adopted_options(Options::default())).unwrap();
    let q2 = Carrier::new(c2, &common::adopted_options(Options::default())).unwrap();
    // The session secret comes from the first connection's exporter.
    let client = Session::connect(q1.open_pipe().await.unwrap(), config(PipeAuth::exporter()))
        .await
        .unwrap();
    let server = listener.accept().await.unwrap();
    assert_eq!(client.multipath(), zmux::Multipath::InUse);
    let pipe = client
        .test_begin_join(
            q2.open_pipe().await.unwrap(),
            PipeOptions::default().with_record_mode(zmux::RecordMode::Bound),
        )
        .unwrap();
    tokio::time::timeout(Duration::from_secs(60), pipe.attached())
        .await
        .expect("the pipe did not attach")
        .unwrap();
    assert_eq!(
        pipe.stats().and_then(|i| i.outbound),
        Some(OutboundState::Active)
    );
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn default_memory_budget_admits_sixty_four_full_receive_windows() {
    const SESSIONS: usize = 64;
    const WINDOW: usize = 1 << 20;

    tokio::time::timeout(Duration::from_secs(120), async {
        let quic = Quic::new();
        let mut config = config(PipeAuth::exporter());
        config.initial_stream_receive_window = 2 * WINDOW as u64;
        // FIN on the same ordered lane establishes that the window arrived.
        config.max_lanes = std::num::NonZeroU64::MIN;
        let limits = ListenerConfig::default();
        assert_eq!(limits.limits.memory_budget, Some(1 << 30));
        let listener = Listener::new(config.clone(), limits).unwrap();

        let payload = vec![42; WINDOW];
        let mut sessions = Vec::with_capacity(SESSIONS);
        for _ in 0..SESSIONS {
            let (c, s) = quic.connect().await;
            let _server_carrier =
                Carrier::with_listener(s, &listener, &common::adopted_options(Options::default()))
                    .unwrap();
            let carrier = Carrier::new(c, &common::adopted_options(Options::default())).unwrap();
            let client = Session::connect(carrier.open_pipe().await.unwrap(), config.clone())
                .await
                .unwrap();
            let server = listener.accept().await.unwrap();
            let (mut send, response) = client.open_bi().await.unwrap();
            send.write_all(&payload).await.unwrap();
            send.finish().unwrap();
            let (reply, mut recv) = server.accept_bi().await.unwrap();
            assert_eq!(recv.received_reset().await.unwrap(), None);
            assert_eq!(recv.stats().recv_buffered, WINDOW as u64);
            sessions.push((client, server, send, response, reply, recv));
        }

        let (c, s) = quic.connect().await;
        let _server_carrier =
            Carrier::with_listener(s, &listener, &common::adopted_options(Options::default()))
                .unwrap();
        let carrier = Carrier::new(c, &common::adopted_options(Options::default())).unwrap();
        let pipe = sessions[0]
            .0
            .test_begin_join(
                carrier.open_pipe().await.unwrap(),
                PipeOptions::default().with_record_mode(zmux::RecordMode::Bound),
            )
            .unwrap();
        pipe.attached().await.unwrap();
        for (_, _, _, _, _, recv) in &sessions {
            assert_eq!(recv.stats().recv_buffered, WINDOW as u64);
        }
    })
    .await
    .expect("session or Join did not complete");
}

/// A rustls configuration pair for "localhost" without ALPN identifiers.
fn plain_tls() -> (rustls::ClientConfig, rustls::ServerConfig) {
    common::tls_configs("localhost", Vec::new())
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
    let client = Carrier::new(cc, &common::adopted_options(Options::default())).unwrap();
    let server = Carrier::new(sc, &common::adopted_options(Options::default())).unwrap();
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
    let client = Carrier::new(cc, &common::adopted_options(Options::default())).unwrap();
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
    let _server_carrier =
        Carrier::with_listener(sc, &listener, &common::adopted_options(Options::default()))
            .unwrap();
    let carrier = Carrier::new(cc, &common::adopted_options(Options::default())).unwrap();
    let client = Session::connect(
        carrier.open_pipe().await.unwrap(),
        config(PipeAuth::exporter()),
    )
    .await
    .unwrap();
    let server = listener.accept().await.unwrap();
    let pipe = client
        .test_join(carrier.open_pipe().await.unwrap(), PipeOptions::default())
        .await
        .unwrap();
    for session in [&client, &server] {
        let stats = tokio::time::timeout(Duration::from_secs(60), async {
            loop {
                let stats = session.pipe_stats();
                if stats.iter().all(|pipe| pipe.carrier_sample.is_some()) {
                    break stats;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the requested shared native sample was never published");
        assert_eq!(stats.len(), 2);
        let sample = stats[0].carrier_sample.as_ref().unwrap();
        assert_eq!(sample.generation, 0);
        assert_eq!(sample.source, zmux::CarrierSource::Quinn);
        assert!(
            matches!(sample.counts, Some(zmux::CarrierCounts::Quic { packets_sent, .. }) if packets_sent > 0)
        );
        assert_eq!(stats[1].carrier_sample.as_ref(), Some(sample));
    }
    // Lanes on both pipes.
    transfer(&client, &server, 8, 1 << 20).await;
    let clean = |s: &Session| {
        s.pipe_stats()
            .iter()
            .all(|p| p.failure.is_none() && p.failure_count == 0)
    };
    pipe.close().unwrap();
    tokio::time::timeout(Duration::from_secs(60), async {
        while server
            .pipe(pipe.id())
            .and_then(|p| p.stats())
            .is_some_and(|p| p.inbound != Some(zmux::InboundState::Ended))
        {
            let event = server
                .next_event()
                .await
                .expect("session closed before its pipe");
            assert!(
                !matches!(event, SessionEvent::PipeFailed { .. }),
                "{event:?}"
            );
        }
    })
    .await
    .expect("the pipe did not end");
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

#[path = "../../test-support/close_delivery.rs"]
mod close_delivery;
use close_delivery::{close_delivery, lingering};

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
        let client = Carrier::new(cc, &common::adopted_options(Options::default())).unwrap();
        let server =
            Carrier::new(sc.clone(), &common::adopted_options(Options::default())).unwrap();
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
    let client = Carrier::new(cc, &common::adopted_options(Options::default())).unwrap();
    let server = Carrier::new(sc.clone(), &common::adopted_options(Options::default())).unwrap();
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

/// A dial to a server that grants no stream fails within its timeout
/// instead of waiting for stream credit for ever.
#[tokio::test]
async fn a_dial_without_stream_credit_times_out() {
    let mut t = Options::default().transport_config();
    t.max_concurrent_bidi_streams(0u32.into());
    let q = Quic::with_transport(t);
    let addr = q.server.local_addr().unwrap();
    let server = q.server.clone();
    let held = tokio::spawn(async move { server.accept().await.unwrap().await.unwrap() });
    let r = zmux_quinn::dial(
        &q.client,
        addr,
        "localhost",
        &Options::default().with_timeout(Duration::from_millis(300)),
    )
    .await;
    assert_eq!(r.unwrap_err().kind(), std::io::ErrorKind::TimedOut);
    drop(held.await.unwrap());
}

/// Hold the acknowledgement wait of each finished QUIC lane. Lane zero
/// is an in-memory duplex with no drain, so only lanes can hold completion.
#[tokio::test]
async fn closed_waits_for_finished_quic_lanes() {
    use std::io;
    use std::pin::{Pin, pin};
    use std::task::{Context, Poll, Waker};
    use tokio::io::AsyncWrite;
    use zmux::adapter::CarrierConnId;
    use zmux_quinn::parts::{self, SendPart};

    struct Send {
        stream: quinn::SendStream,
        draining: Arc<tokio::sync::Notify>,
        gate: tokio::sync::watch::Receiver<bool>,
    }
    impl SendPart for Send {
        fn poll_write(&mut self, cx: &mut Context<'_>, bytes: &[u8]) -> Poll<io::Result<usize>> {
            AsyncWrite::poll_write(Pin::new(&mut self.stream), cx, bytes)
        }

        fn poll_send_bytes(
            &mut self,
            cx: &mut Context<'_>,
            chunks: &mut [bytes::Bytes],
        ) -> Poll<io::Result<usize>> {
            pin!(self.stream.write_chunks(chunks))
                .poll(cx)
                .map_ok(|r| r.bytes)
                .map_err(Into::into)
        }
        fn poll_flush(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            AsyncWrite::poll_flush(Pin::new(&mut self.stream), cx)
        }
        fn poll_finish(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            AsyncWrite::poll_shutdown(Pin::new(&mut self.stream), cx)
        }
        fn reset(&mut self) {
            let _ = self.stream.reset(0u32.into());
        }
        fn stopped(&self) -> impl Future<Output = ()> + std::marker::Send + 'static {
            let stopped = self.stream.stopped();
            let draining = self.draining.clone();
            let mut gate = self.gate.clone();
            async move {
                draining.notify_one();
                let _ = gate.wait_for(|open| *open).await;
                let _ = stopped.await;
            }
        }
    }

    let quic = Quic::new();
    let (cc, sc) = quic.connect().await;
    let peer = CarrierConnId::new(&Arc::new(()));
    let (a, b) = tokio::io::duplex(1 << 16);
    let server = tokio::spawn(Session::accept(
        zmux::PipeIo::new(b)
            .with_carrier_conn(peer.clone())
            .with_lanes(true),
        Config::default(),
    ));
    let draining = Arc::new(tokio::sync::Notify::new());
    let entered = draining.clone();
    let (release, gate) = tokio::sync::watch::channel(false);
    let io = zmux::PipeIo::new(a)
        .with_carrier_conn(CarrierConnId::new(&Arc::new(())))
        .with_lane_opener(move || {
            let (cc, sc, peer, draining, gate) = (
                cc.clone(),
                sc.clone(),
                peer.clone(),
                entered.clone(),
                gate.clone(),
            );
            async move {
                let stream = cc.open_uni().await.map_err(io::Error::other)?;
                tokio::spawn(async move {
                    if let Ok(recv) = sc.accept_uni().await {
                        let _ = zmux::adapter::handle_lane(
                            zmux::PipeIo::reader(recv).with_carrier_conn(peer),
                        )
                        .await;
                    }
                });
                Ok(parts::lane(
                    Send {
                        stream,
                        draining,
                        gate,
                    },
                    Arc::new(cc),
                ))
            }
        });
    let client = Session::connect(io, Config::default()).await.unwrap();
    let server = server.await.unwrap().unwrap();
    transfer(&client, &server, 3, 512 << 10).await;
    let pipe = client.pipe(zmux::PipeId::new(0)).unwrap();
    client.close().await;
    tokio::time::timeout(Duration::from_secs(2), draining.notified())
        .await
        .expect("lane started its acknowledgement wait");
    client.closed().await;
    let mut closed = pin!(pipe.closed());
    assert!(
        closed
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending()
    );
    release.send(true).unwrap();
    assert!(matches!(closed.await, Err(zmux::PipeError::SessionLost(_))));
}

#[tokio::test]
// HS-57
async fn a_connection_without_a_first_stream_releases_its_entry_at_setup_deadline() {
    let quic = Quic::new();
    let (_client, server) = quic.connect().await;
    let peer = server.remote_address();
    let mut config = ListenerConfig::default();
    config.handshake_timeout = Duration::from_secs(4);
    config.limits.max_pending_per_source = 2;
    let listener = Listener::new(Config::default(), config).unwrap();
    let _other = listener.adapter().enter(peer, None).unwrap();
    let options = common::adopted_options(Options::default());
    tokio::time::pause();
    let mut serving = Box::pin(zmux_quinn::serve_connection(&listener, server, &options));
    assert!(
        serving
            .as_mut()
            .poll(&mut std::task::Context::from_waker(std::task::Waker::noop()))
            .is_pending()
    );
    assert!(listener.adapter().enter(peer, None).is_none());
    tokio::time::advance(Duration::from_secs(4)).await;
    serving.await.unwrap();
    assert!(listener.adapter().enter(peer, None).is_some());
    assert_eq!(listener.stats().sessions, 0);
}
