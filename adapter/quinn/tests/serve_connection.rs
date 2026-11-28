//! `serve_connection` hands one established connection to a listener
//! without holding its caller beyond the connection: a connection refused
//! at a limit is closed, counted and the call succeeds; a closed listener
//! fails the call with `NotConnected`; the call resolves when the connection
//! ends; dropping it stops the delivery of streams and leaves the connection.

#![allow(
    clippy::many_single_char_names,
    reason = "c, s, l and o name the client and server connection, listener and options throughout"
)]
#![cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]

mod common;

use std::time::Duration;

use zmux::{Admission, AdmissionVerdict, Config, Listener, ListenerConfig, Session};
use zmux_quinn::{Carrier, Options, adopt_connection, serve_connection};

const LIMIT: Duration = Duration::from_secs(20);

struct Rig {
    server: quinn::Endpoint,
    client: quinn::Endpoint,
    addr: std::net::SocketAddr,
    listener: Listener,
    opts: Options,
}

impl Rig {
    fn new(admission: Option<Admission>, per_source: usize) -> Self {
        let mut lc = ListenerConfig::default();
        lc.admission = admission;
        lc.limits.max_pending_per_source = per_source;
        Self::with_listener(lc)
    }

    fn with_listener(lc: ListenerConfig) -> Self {
        let opts = common::adopted_options(Options::default());
        let (server, client) = common::endpoints(
            zmux::alpn_protocols(&[]),
            opts.transport_config(),
            opts.transport_config(),
        );
        let addr = server.local_addr().unwrap();
        let listener = Listener::new(Config::default(), lc).expect("valid listener configuration");
        Self {
            server,
            client,
            addr,
            listener,
            opts,
        }
    }

    /// A connection: the client's and the server's side of it.
    async fn connect(&self) -> (quinn::Connection, quinn::Connection) {
        let connecting = self.client.connect(self.addr, "localhost").unwrap();
        let incoming = self.server.accept().await.unwrap();
        let (c, s) = tokio::join!(connecting, incoming);
        (c.unwrap(), s.unwrap())
    }
}

#[tokio::test]
async fn adopting_requires_the_hosts_actual_window() {
    let mut limits = ListenerConfig::default();
    let options = Options::default();
    let window = options.windows.receive_window();
    limits.limits.memory_budget = Some(window);
    let rig = Rig::with_listener(limits);
    let (_client, host) = tokio::time::timeout(LIMIT, rig.connect()).await.unwrap();
    for options in [
        options.clone(),
        options
            .clone()
            .with_windows(options.windows.with_established_receive_window(u64::MAX)),
    ] {
        let err = adopt_connection(&rig.listener, host.clone(), &options)
            .err()
            .unwrap();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    }
    assert!(host.close_reason().is_none());
    let options = options.clone().with_windows(
        options
            .windows
            .with_lanes(1)
            .with_established_receive_window(window),
    );
    let service = adopt_connection(&rig.listener, host, &options)
        .unwrap()
        .unwrap();
    assert!(rig.listener.adapter().reserve_memory(1).is_err());
    service.stop_admission();
    tokio::time::timeout(LIMIT, service.admission_stopped())
        .await
        .unwrap();
    assert!(rig.listener.adapter().reserve_memory(window).is_ok());
}

/// A listener at a limit closes the connection, counts it as refused and
/// the call succeeds.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_connection_refused_at_a_limit_is_closed_counted_and_ok() {
    // The source's two slots, held by entries of the same source.
    let admission = Admission::new(4, |_, _| AdmissionVerdict::Close);
    let rig = Rig::new(Some(admission), 2);
    let peer: std::net::SocketAddr = "127.0.0.1:1".parse().unwrap();
    let _held = [
        rig.listener.adapter().enter(peer, None).unwrap(),
        rig.listener.adapter().enter(peer, None).unwrap(),
    ];
    assert_eq!(rig.listener.stats().refused, 0);
    let (c, s) = rig.connect().await;
    let r = tokio::time::timeout(LIMIT, serve_connection(&rig.listener, s, &rig.opts))
        .await
        .expect("the refused connection ends the call");
    r.expect("refused at a limit is not an error");
    tokio::time::timeout(LIMIT, c.closed()).await.unwrap();
    assert_eq!(rig.listener.stats().refused, 1);
}

/// A closed listener closes the connection and fails the call.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_closed_listener_fails_the_call_with_not_connected() {
    let rig = Rig::new(None, 8);
    let (c, s) = rig.connect().await;
    rig.listener.close();
    let r = serve_connection(&rig.listener, s, &rig.opts).await;
    assert_eq!(r.unwrap_err().kind(), std::io::ErrorKind::NotConnected);
    tokio::time::timeout(LIMIT, c.closed()).await.unwrap();
}

/// The call resolves when the connection ends.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_call_resolves_when_the_connection_ends() {
    let rig = Rig::new(None, 8);
    let (c, s) = rig.connect().await;
    let (l, o) = (rig.listener.clone(), rig.opts.clone());
    let call = tokio::spawn(async move { serve_connection(&l, s, &o).await });
    c.close(0u32.into(), b"");
    tokio::time::timeout(LIMIT, call)
        .await
        .expect("resolves with the connection")
        .unwrap()
        .unwrap();
}

/// A blocked new pipe and an authenticated lane belong to different lifetimes.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stopping_admission_reaps_setup_and_keeps_existing_lanes() {
    tokio::time::timeout(Duration::from_secs(60), async {
        let (entered, mut pending) = tokio::sync::mpsc::unbounded_channel();
        let mut config = ListenerConfig::default();
        config.inbound_transform = Some(zmux::InboundTransform::new({
            let count = std::sync::atomic::AtomicUsize::new(0);
            move |pipe, _| {
                let block = count.fetch_add(1, std::sync::atomic::Ordering::Relaxed) == 1;
                let entered = entered.clone();
                async move {
                    if block {
                        let (held, released) = tokio::sync::oneshot::channel::<()>();
                        entered.send(released).unwrap();
                        std::future::pending::<()>().await;
                        drop(held);
                    }
                    Ok(pipe)
                }
            }
        }));
        let rig = Rig::with_listener(config);
        let (connection, server) = rig.connect().await;
        let mut service = adopt_connection(&rig.listener, server, &rig.opts)
            .unwrap()
            .unwrap();
        let carrier = Carrier::new(connection.clone(), &rig.opts).unwrap();
        let client = Session::connect(carrier.open_pipe().await.unwrap(), Config::default())
            .await
            .unwrap();
        let accepted = rig.listener.accept().await.unwrap();
        assert_eq!(accepted.pipe_stats()[0].lanes_in, 1);

        let (mut send, mut recv) = connection.open_bi().await.unwrap();
        send.write_all(b"blocked setup").await.unwrap();
        let released = pending.recv().await.unwrap();
        service.stop_admission();
        service.stop_admission();
        service.admission_stopped().await;
        assert!(released.await.is_err());
        assert!(matches!(
            recv.read(&mut [0]).await,
            Err(quinn::ReadError::Reset(_))
        ));
        assert!(connection.close_reason().is_none());

        // Exercise QUIC stream flow control so the sender opens a real lane.
        let data = zmux::Chunk::from(vec![0xa7; 4 << 20]);
        let transfer = async {
            let mut streams = tokio::task::JoinSet::new();
            for _ in 0..8 {
                let mut send = client.open_uni().await.unwrap();
                let data = data.clone();
                streams.spawn(async move {
                    send.write_chunk(data).await.unwrap();
                    send.finish().unwrap();
                });
            }
            while let Some(result) = streams.join_next().await {
                result.unwrap();
            }
        };
        let receive = async {
            let mut streams = tokio::task::JoinSet::new();
            for _ in 0..8 {
                let mut recv = accepted.accept_uni().await.unwrap();
                streams.spawn(async move { recv.read_to_end((4 << 20) + 1).await.unwrap() });
            }
            while let Some(result) = streams.join_next().await {
                assert_eq!(result.unwrap().as_slice(), data.as_ref());
            }
        };
        tokio::join!(transfer, receive);
        assert!(accepted.pipe_stats()[0].lanes_in > 1);

        // A later bidirectional stream can reach QUIC's bounded queue. It
        // never reaches the listener, and closing the final pipe reaps it.
        let (mut late, _recv) = connection.open_bi().await.unwrap();
        late.write_all(b"after admission").await.unwrap();
        let mut next = std::pin::pin!(rig.listener.accept());
        assert!(
            std::future::Future::poll(
                next.as_mut(),
                &mut std::task::Context::from_waker(std::task::Waker::noop())
            )
            .is_pending()
        );
        assert_eq!(rig.listener.stats().sessions, 1);
        client.close().await;
        let _ = accepted.closed().await;
        service.wait().await.unwrap();
        let _ = connection.closed().await;
    })
    .await
    .unwrap();
}
