//! Native datagram routing and capacity on real Quinn connections.

mod common;

use std::net::SocketAddr;
use std::time::Duration;

use bytes::Bytes;
use zmux::adapter::{ChannelReceiver, DatagramChannel};
use zmux::{Config, Session};
use zmux_quinn::{Carrier, Options};

/// Every test has a hard deadline.
const DEADLINE: Duration = Duration::from_secs(60);

struct Quic {
    server: quinn::Endpoint,
    client: quinn::Endpoint,
}

impl Quic {
    /// Endpoints with the carrier's transport configuration; `client_dgrams`
    /// false: the client's connections take no QUIC datagrams.
    fn new(client_dgrams: bool) -> Self {
        let mut transport = Options::default().transport_config();
        if !client_dgrams {
            transport.datagram_receive_buffer_size(None);
        }
        let (server, client) = common::endpoints(
            vec![b"zmux".to_vec()],
            Options::default().transport_config(),
            transport,
        );
        Self { server, client }
    }

    /// A connection to `addr` (the server's own, or a relay's): the
    /// client's end and the server's.
    async fn connect(&self, addr: SocketAddr) -> (quinn::Connection, quinn::Connection) {
        tokio::join!(
            async {
                self.client
                    .connect(addr, "localhost")
                    .unwrap()
                    .await
                    .unwrap()
            },
            async { self.server.accept().await.unwrap().await.unwrap() }
        )
    }
}

fn dgram_config() -> Config {
    let mut c = Config::default();
    c.enable_datagrams = true;
    c
}

/// A session over one QUIC connection: the client's and the server's.
async fn sessions(cc: quinn::Connection, sc: quinn::Connection) -> (Session, Session, Carrier) {
    let client = Carrier::new(cc, &common::adopted_options(Options::default())).unwrap();
    let server = Carrier::new(sc, &common::adopted_options(Options::default())).unwrap();
    let (client, accepted) = open_session(&client, &server).await;
    (client, accepted, server)
}

async fn open_session(client: &Carrier, server: &Carrier) -> (Session, Session) {
    let (client, accepted) = tokio::join!(
        async { Session::connect(client.open_pipe().await.unwrap(), dgram_config()).await },
        async { Session::accept(server.accept_pipe().await.unwrap(), dgram_config()).await },
    );
    (client.unwrap(), accepted.unwrap())
}

#[tokio::test]
async fn borrowed_connections_share_routing_and_leave_close_to_the_host() {
    tokio::time::timeout(DEADLINE, async {
        let quic = Quic::new(true);
        let (host, peer) = quic.connect(quic.server.local_addr().unwrap()).await;
        let options = common::adopted_options(Options::default());
        let server = Carrier::new(peer.clone(), &options).unwrap();
        let (first, second) = tokio::join!(
            Carrier::borrow(&host, &options),
            Carrier::borrow(&host, &options),
        );
        let (first, second) = (first.unwrap(), second.unwrap());
        assert!(std::sync::Arc::ptr_eq(
            first.datagrams(),
            second.datagrams()
        ));
        assert!(first.accept_pipe().await.is_none());
        let different = options
            .clone()
            .with_windows(options.windows.with_lanes(options.windows.lanes + 1));
        assert_eq!(
            Carrier::borrow(&host, &different).await.unwrap_err().kind(),
            std::io::ErrorKind::InvalidInput
        );
        let (client_a, peer_a) = open_session(&first, &server).await;
        let (client_b, peer_b) = open_session(&second, &server).await;
        drop((first, second));
        for (session, payload) in [
            (&peer_a, b"first".as_slice()),
            (&peer_b, b"second".as_slice()),
        ] {
            assert!(session.datagram_path().native_payload.is_some());
            session.send_datagram(Bytes::from_static(payload)).unwrap();
        }
        let (a, b) = tokio::join!(client_a.read_datagram(), client_b.read_datagram());
        assert_eq!(a.unwrap(), b"first".as_slice());
        assert_eq!(b.unwrap(), b"second".as_slice());

        let (mut send, _recv) = peer.open_bi().await.unwrap();
        send.write_all(b"host stream").await.unwrap();
        send.finish().unwrap();
        let (_send, mut recv) = host.accept_bi().await.unwrap();
        assert_eq!(recv.read_to_end(64).await.unwrap(), b"host stream");

        tokio::join!(client_a.close(), client_b.close());
        tokio::join!(peer_a.closed(), peer_b.closed());
        drop((client_a, client_b, peer_a, peer_b));
        // Borrow again after the old lane and datagram receivers have gone.
        let rebound = Carrier::borrow(&host, &options).await.unwrap();
        assert_eq!(rebound.connection().stable_id(), host.stable_id());
        drop(rebound);
        assert!(host.close_reason().is_none());
        host.close(23u32.into(), b"host close");
        assert_eq!(
            Carrier::borrow(&host, &options).await.unwrap_err().kind(),
            std::io::ErrorKind::NotConnected
        );
        assert!(matches!(
            peer.closed().await,
            quinn::ConnectionError::ApplicationClosed(close) if close.error_code.into_inner() == 23
        ));
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn native_datagram_capacity_routing_and_cancellation() {
    tokio::time::timeout(DEADLINE, async {
        let quic = Quic::new(true);
        let (cc, sc) = quic.connect(quic.server.local_addr().unwrap()).await;
        let client =
            Carrier::new(cc.clone(), &common::adopted_options(Options::default())).unwrap();
        let server =
            Carrier::new(sc.clone(), &common::adopted_options(Options::default())).unwrap();
        let outbound = client.datagrams().channel(64);
        let inbound = server.datagrams().channel(64);
        let (arrived, mut received) = tokio::sync::mpsc::unbounded_channel();
        let _registration = inbound.receive(ChannelReceiver::new(move |frame| {
            let _ = arrived.send(frame);
        }));

        let (limit, room) = outbound.datagram_capacity();
        assert_eq!(limit, room);
        assert_eq!(Some(room), cc.max_datagram_size());
        let payload = vec![0xa5; limit - 3];
        let frame = Bytes::from(zmux::proto::frame::channel::encode(Some(64), &payload));
        assert_eq!(frame.len(), limit);
        assert!(
            outbound
                .send(Bytes::from(vec![0; limit + 1]))
                .await
                .is_err()
        );
        outbound.send(frame.clone()).await.unwrap();
        let received = received.recv().await.unwrap();
        assert_eq!(&received[..], &frame[2..]);
        assert_eq!(cc.stats().frame_tx.datagram, 1);
        assert_eq!(sc.stats().frame_rx.datagram, 1);

        // This runtime has one thread. No background task can drain the
        // transport queue while we fill it and poll the waiting send.
        while cc.datagram_send_buffer_space() >= limit {
            cc.send_datagram(frame.clone()).unwrap();
        }
        let space = cc.datagram_send_buffer_space();
        let mut sending = outbound.send(frame);
        assert!(
            std::future::Future::poll(
                sending.as_mut(),
                &mut std::task::Context::from_waker(std::task::Waker::noop())
            )
            .is_pending()
        );
        drop(sending);
        assert_eq!(cc.datagram_send_buffer_space(), space);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn bound_pipe_datagrams_use_its_physical_quic_connection() {
    tokio::time::timeout(DEADLINE, async {
        let quic = Quic::new(true);
        let address = quic.server.local_addr().unwrap();
        let (initial, initial_peer) = quic.connect(address).await;
        let (bound, bound_peer) = quic.connect(address).await;
        let mut config = dgram_config();
        config.session_policy.limits.steady_attachments = 2;
        config.pipe_auth = zmux::PipeAuth::exporter().with_end_to_end();
        config.allow_record_mode = Some(zmux::AllowRecordMode::new(|_, _, _| true));
        let listener =
            zmux::Listener::new(config.clone(), zmux::ListenerConfig::default()).unwrap();
        let _initial_service = Carrier::with_listener(
            initial_peer,
            &listener,
            &common::adopted_options(Options::default()),
        )
        .unwrap();
        let _bound_service = Carrier::with_listener(
            bound_peer.clone(),
            &listener,
            &common::adopted_options(Options::default()),
        )
        .unwrap();
        let first = Carrier::new(
            initial.clone(),
            &common::adopted_options(Options::default()),
        )
        .unwrap();
        let next =
            Carrier::new(bound.clone(), &common::adopted_options(Options::default())).unwrap();
        let sender = Session::connect(first.open_pipe().await.unwrap(), config)
            .await
            .unwrap();
        let receiver = listener.accept().await.unwrap();

        let pipe = sender
            .test_join(
                next.open_pipe().await.unwrap(),
                zmux::PipeOptions::default().with_record_mode(zmux::RecordMode::Bound),
            )
            .await
            .unwrap();
        pipe.attached().await.unwrap();
        assert_eq!(
            pipe.stats().unwrap().record_mode,
            Some(zmux::RecordMode::Bound)
        );
        assert_eq!(
            receiver
                .pipe(pipe.id())
                .unwrap()
                .stats()
                .unwrap()
                .record_mode,
            Some(zmux::RecordMode::Bound)
        );
        let bootstrap = sender.pipe(zmux::PipeId::new(0)).unwrap();
        bootstrap.close().unwrap();
        bootstrap.closed().await.unwrap();
        let data = Bytes::from_static(b"bound datagram");
        sender.send_datagram(data.clone()).unwrap();
        assert_eq!(receiver.read_datagram().await.unwrap(), data);
        assert_eq!(sender.stats().datagrams_sent_channel, 1);
        assert_eq!(receiver.stats().datagrams_received_channel, 1);
        assert_eq!(initial.stats().frame_tx.datagram, 0);
        assert_eq!(bound.stats().frame_tx.datagram, 1);
        assert_eq!(bound_peer.stats().frame_rx.datagram, 1);
        sender.close().await;
    })
    .await
    .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn quic_datagrams_disabled_locally_fall_back_to_records() {
    tokio::time::timeout(DEADLINE, async {
        let quic = Quic::new(false);
        let (cc, sc) = quic.connect(quic.server.local_addr().unwrap()).await;
        let (cs, ss, _server) = sessions(cc, sc).await;
        for i in 0..20u8 {
            cs.send_datagram(Bytes::from(vec![i; 100])).unwrap();
            ss.send_datagram(Bytes::from(vec![i; 100])).unwrap();
            let (a, b) = tokio::join!(ss.read_datagram(), cs.read_datagram());
            assert_eq!(a.unwrap()[0], i);
            assert_eq!(b.unwrap()[0], i);
        }
        let (c, s) = (cs.stats(), ss.stats());
        // The client's datagrams take the server's QUIC datagrams; the
        // client's connection takes none, so the server's go in records.
        // quinn sends no QUIC datagrams where its own configuration takes
        // none: both directions go in records.
        assert_eq!((c.datagrams_sent_channel, s.datagrams_sent_channel), (0, 0));
        assert_eq!(
            (s.datagrams_received_channel, c.datagrams_received_channel),
            (0, 0)
        );
        assert!(c.datagrams_dropped_send == 0 && s.datagrams_dropped_send == 0);
        assert_eq!((c.datagrams_received, s.datagrams_received), (20, 20));
        cs.close().await;
    })
    .await
    .expect("deadline");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sessions_sharing_a_connection_get_their_own_channel_datagrams() {
    tokio::time::timeout(DEADLINE, async {
        let quic = Quic::new(true);
        let (cc, sc) = quic.connect(quic.server.local_addr().unwrap()).await;
        let client = Carrier::new(cc, &common::adopted_options(Options::default())).unwrap();
        let server = Carrier::new(sc, &common::adopted_options(Options::default())).unwrap();
        let mut pairs = Vec::new();
        for _ in 0..3 {
            let accept = {
                let server = server.clone();
                tokio::spawn(async move {
                    Session::accept(server.accept_pipe().await.unwrap(), dgram_config())
                        .await
                        .unwrap()
                })
            };
            let cs = Session::connect(client.open_pipe().await.unwrap(), dgram_config())
                .await
                .unwrap();
            pairs.push((cs, accept.await.unwrap()));
        }
        for round in 0..10u8 {
            for (i, (cs, ss)) in pairs.iter().enumerate() {
                cs.send_datagram(Bytes::from(vec![u8::try_from(i).unwrap(), round]))
                    .unwrap();
                ss.send_datagram(Bytes::from(vec![u8::try_from(i).unwrap(), round, 1]))
                    .unwrap();
            }
            for (i, (cs, ss)) in pairs.iter().enumerate() {
                let d = ss.read_datagram().await.unwrap();
                assert_eq!(&d[..], [u8::try_from(i).unwrap(), round]);
                let d = cs.read_datagram().await.unwrap();
                assert_eq!(&d[..], [u8::try_from(i).unwrap(), round, 1]);
            }
        }
        for (cs, ss) in &pairs {
            assert_eq!(cs.stats().datagrams_received_channel, 10);
            assert_eq!(ss.stats().datagrams_received_channel, 10);
        }
        assert_eq!(client.datagrams().dropped(), 0);
        assert_eq!(server.datagrams().dropped(), 0);
        // A closed session's pipe names no pipe any more: the peer's
        // datagrams for it are dropped and counted by the connection.
        let (cs, ss) = pairs.remove(0);
        cs.close().await;
        let _ = ss.closing().await;
        let _ = cs.closing().await;
        let _ = ss.closed().await;
        client
            .connection()
            .send_datagram(Bytes::from(zmux::proto::frame::channel::encode(
                Some(0),
                &[0],
            )))
            .unwrap();
        while server.datagrams().dropped() == 0 {
            tokio::task::yield_now().await;
        }
        let (cs, ss) = &pairs[0];
        cs.send_datagram(Bytes::from_static(b"still")).unwrap();
        assert_eq!(&ss.read_datagram().await.unwrap()[..], b"still");
    })
    .await
    .expect("deadline");
}
