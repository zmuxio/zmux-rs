//! HTTP/3 request carriers over loopback: one-step `connect` and `serve`
//! with streams both ways and a close the peer sees, client lanes on
//! further requests and a second pipe on another request of the same
//! connection (each pipe a request body paired with its response body),
//! and a lost connection that is a failure of its pipes, never their clean
//! end.

#![cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]

#[path = "../../test-support/ticket.rs"]
mod ticket;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Buf;
use zmux::{
    Admission, AdmissionVerdict, Config, Listener, ListenerConfig, PipeAuth, PipeFailure,
    PipeOptions, PrefixAuth, Session, SessionError,
};
use zmux_h3::{Carrier, Fallback, Options};

use net::endpoints;

mod net {
    include!("common/net.rs");
}

/// A served HTTP/3 endpoint and a client endpoint for it over loopback.
struct H3 {
    client: quinn::Endpoint,
    addr: SocketAddr,
    uri: http::Uri,
    listener: Listener,
    serving: tokio::task::JoinHandle<()>,
}

fn adopted_options(options: Options) -> Options {
    let windows = options.windows;
    options.with_windows(windows.with_established_receive_window(windows.receive_window()))
}

impl H3 {
    fn new(config: Config, opts: &Options) -> Self {
        Self::with_listener(config, ListenerConfig::default(), opts)
    }

    fn admitted(config: Config, admission: Admission, opts: &Options) -> Self {
        let mut lc = ListenerConfig::default();
        lc.admission = Some(admission);
        Self::with_listener(config, lc, opts)
    }

    fn with_listener(config: Config, lc: ListenerConfig, opts: &Options) -> Self {
        let (server, client, addr) = endpoints(opts);
        let listener = Listener::new(config, lc).expect("valid listener configuration");
        let serving = tokio::spawn(zmux_h3::serve(listener.clone(), server, opts.clone()));
        Self {
            client,
            addr,
            uri: format!("https://127.0.0.1:{}/zmux", addr.port())
                .parse()
                .unwrap(),
            listener,
            serving,
        }
    }

    /// A client of a new connection.
    async fn h3_client(&self, opts: &Options) -> Carrier {
        let conn = self
            .client
            .connect(self.addr, "127.0.0.1")
            .unwrap()
            .await
            .unwrap();
        Carrier::new(conn, self.uri.clone(), &adopted_options(opts.clone()))
            .await
            .unwrap()
    }

    async fn stop(self) {
        self.listener.close();
        self.serving.await.unwrap();
    }
}

#[path = "../../test-support/transfer.rs"]
mod streams;
use streams::transfer;

/// One step from an endpoint to a session and from an endpoint to its
/// sessions: streams go both ways over the request body and the response
/// body of one request, and a close reaches the peer.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn connect_and_serve() {
    let opts = Options::default();
    let h3 = H3::new(Config::default(), &opts);
    let client = zmux_h3::connect(
        &h3.client,
        h3.addr,
        h3.uri.clone(),
        &opts,
        Config::default(),
    )
    .await
    .unwrap();
    let server = h3.listener.accept().await.unwrap();
    assert_kind([&client, &server], zmux::CarrierKind::Http3);
    transfer(&client, &server, 2, 256 << 10).await;
    transfer(&server, &client, 2, 256 << 10).await;
    client.close().await;
    let e = tokio::time::timeout(Duration::from_secs(10), server.closing())
        .await
        .expect("closed");
    assert!(
        matches!(e, SessionError::ApplicationClosed { remote: true, .. }),
        "{e:?}"
    );
    h3.stop().await;
}

/// The client opens lanes as further requests of its connection, which
/// the listener routes to the pipe; the server, which cannot open
/// requests, keeps its direction on the pipe's own response body. A second
/// pipe on another request of the connection joins the session.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn client_lanes_and_a_second_pipe_on_further_requests() {
    let opts = Options::default();
    let config =
        Config::multipath(PipeAuth::psk(*b"zmux-h3-adapter-test-psk-0123456").with_end_to_end());
    let h3 = H3::new(config.clone(), &opts);
    let client = h3.h3_client(&opts).await;
    let cs = Session::connect(client.open_pipe().await.unwrap(), config)
        .await
        .unwrap();
    let ss = h3.listener.accept().await.unwrap();
    assert_eq!(cs.multipath(), zmux::Multipath::InUse);
    transfer(&cs, &ss, 8, 1 << 20).await;
    assert!(cs.pipe_stats()[0].lanes_out > 1, "no lane was opened");
    assert!(ss.pipe_stats()[0].lanes_in > 1, "no lane was accepted");
    assert_eq!(ss.pipe_stats()[0].lanes_out, 1, "a server opens no lanes");
    let pipe = cs
        .test_begin_join(client.open_pipe().await.unwrap(), PipeOptions::new())
        .unwrap();
    tokio::time::timeout(Duration::from_secs(10), pipe.joined())
        .await
        .expect("joined in time")
        .unwrap();
    transfer(&ss, &cs, 4, 256 << 10).await;
    cs.close().await;
    h3.stop().await;
}

/// A Bound join over a further request of the connection: the carrier declares the Bound
/// contract and its Binding is the connection's.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_bound_join_on_a_further_request() {
    let opts = Options::default();
    let mut config = Config::multipath(PipeAuth::exporter().with_end_to_end());
    // Bound joins only when the carrier says it is secure.
    config.allow_record_mode = Some(zmux::AllowRecordMode::new(|c, mode, _| {
        mode != zmux::RecordMode::Bound || c.secure
    }));
    let h3 = H3::new(config.clone(), &opts);
    let client = h3.h3_client(&opts).await;
    let cs = Session::connect(client.open_pipe().await.unwrap(), config)
        .await
        .unwrap();
    let ss = h3.listener.accept().await.unwrap();
    let pipe = cs
        .test_begin_join(
            client.open_pipe().await.unwrap(),
            PipeOptions::new().with_record_mode(zmux::RecordMode::Bound),
        )
        .unwrap();
    tokio::time::timeout(Duration::from_secs(10), pipe.joined())
        .await
        .expect("joined in time")
        .unwrap();
    transfer(&ss, &cs, 4, 256 << 10).await;
    cs.close().await;
    h3.stop().await;
}

#[path = "../../test-support/resources.rs"]
mod resource_wait;

async fn exporter_goes_away(session: &Session) {
    resource_wait::wait_for_resources(
        "the exporter kept the connection",
        || session.export_keying_material("app", b"", 16),
        |value| *value == Err(zmux::ExportError::Unavailable),
    )
    .await;
}

/// The exporter gives the connection's value while it lives, the same at
/// both ends, and does not keep it: a session handle outlives it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_exporter_does_not_keep_the_connection() {
    let opts = Options::default();
    let config = Config::multipath(PipeAuth::exporter().with_end_to_end());
    let h3 = H3::new(config.clone(), &opts);
    let client = h3.h3_client(&opts).await;
    let cs = Session::connect(client.open_pipe().await.unwrap(), config)
        .await
        .unwrap();
    let ss = h3.listener.accept().await.unwrap();
    assert_eq!(
        cs.export_keying_material("app", b"", 16).unwrap(),
        ss.export_keying_material("app", b"", 16).unwrap()
    );
    drop(client);
    cs.close().await;
    exporter_goes_away(&cs).await;
    exporter_goes_away(&ss).await;
    h3.stop().await;
}

/// A connection lost under the session is a failure of its pipe at both
/// ends.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_lost_connection_is_a_failure_not_a_clean_end() {
    let opts = Options::default();
    let h3 = H3::new(Config::default(), &opts);
    let client = h3.h3_client(&opts).await;
    let cs = Session::connect(client.open_pipe().await.unwrap(), Config::default())
        .await
        .unwrap();
    let ss = h3.listener.accept().await.unwrap();
    transfer(&cs, &ss, 2, 64 << 10).await;
    client.connection().close(7u32.into(), b"gone");
    for s in [&cs, &ss] {
        let e = tokio::time::timeout(Duration::from_secs(10), s.closing())
            .await
            .expect("ended");
        assert!(
            matches!(
                e,
                SessionError::PipesLost {
                    last: Some(PipeFailure::Carrier(_))
                }
            ),
            "{e:?}"
        );
    }
    h3.stop().await;
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
    .with_stall_interval(Duration::from_millis(300), Duration::from_millis(300))
}

/// A plain HTTP/3 request to the server with `body`, ended when `end`; the
/// response's status, or `None` when the request fails.
async fn raw_request(h3: &H3, body: &[u8], end: bool) -> Option<http::StatusCode> {
    raw_request_with(h3, &[], body, end).await
}

/// [`raw_request`] with request header fields.
async fn raw_request_with(
    h3: &H3,
    fields: &[(&str, &str)],
    body: &[u8],
    end: bool,
) -> Option<http::StatusCode> {
    let conn = h3
        .client
        .connect(h3.addr, "127.0.0.1")
        .unwrap()
        .await
        .unwrap();
    let (mut driver, mut send) = h3::client::new(h3_quinn::Connection::new(conn.clone()))
        .await
        .unwrap();
    let drive = tokio::spawn(async move {
        let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
    });
    let mut request = http::Request::post(h3.uri.clone());
    for (n, v) in fields {
        request = request.header(*n, *v);
    }
    let mut stream = send.send_request(request.body(()).unwrap()).await.unwrap();
    // The server may answer first and stop the body: the answer still reads.
    let _ = stream.send_data(bytes::Bytes::copy_from_slice(body)).await;
    if end {
        let _ = stream.finish().await;
    }
    let status = tokio::time::timeout(Duration::from_secs(60), stream.recv_response())
        .await
        .expect("answered or ended in time")
        .ok()
        .map(|r| r.status());
    drive.abort();
    conn.close(0u32.into(), b"");
    status
}

/// With an admission of bound prefix authentication tokens, a client with
/// the same `PrefixAuth` writes a token first on every request body, its
/// pipe's and its lanes', and both are accepted.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn admitted_requests_with_tokens_on_pipes_and_lanes() {
    let config =
        Config::multipath(PipeAuth::psk(*b"zmux-h3-adapter-test-psk-0123456").with_end_to_end());
    let h3 = H3::admitted(config.clone(), admission(), &Options::default());
    let client = h3
        .h3_client(&Options::default().with_carrier_credential(Arc::new(auth())))
        .await;
    let cs = Session::connect(client.open_pipe().await.unwrap(), config)
        .await
        .unwrap();
    let ss = tokio::time::timeout(Duration::from_secs(10), h3.listener.accept())
        .await
        .unwrap()
        .unwrap();
    transfer(&cs, &ss, 8, 1 << 20).await;
    assert!(ss.pipe_stats()[0].lanes_in > 1, "no lane was accepted");
    transfer(&ss, &cs, 2, 64 << 10).await;
    cs.close().await;
    h3.stop().await;
}

/// A request whose body does not start with a valid token goes to the
/// fallback handler with every body byte read, unanswered before.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_request_without_a_token_goes_to_the_fallback_with_its_bytes() {
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let fallback = Fallback::new(move |mut req| {
        let tx = tx.clone();
        async move {
            let mut body = req.prefix.to_vec();
            while let Ok(Some(mut d)) = req.recv.recv_data().await {
                body.extend_from_slice(&d.copy_to_bytes(d.remaining()));
            }
            let _ = tx.send(body);
            let mut resp = http::Response::new(());
            *resp.status_mut() = http::StatusCode::IM_A_TEAPOT;
            req.send.send_response(resp).await.unwrap();
            req.send.finish().await.unwrap();
        }
    });
    let opts = Options::default().with_fallback(fallback);
    let h3 = H3::admitted(Config::default(), admission(), &opts);
    let body: Vec<u8> = (0..40u8).collect();
    let status = raw_request(&h3, &body, true).await;
    assert_eq!(status, Some(http::StatusCode::IM_A_TEAPOT));
    assert_eq!(rx.recv().await.unwrap(), body);
    h3.stop().await;
}

// HS-14
#[tokio::test]
async fn closing_listener_ends_only_the_fallback_request_body() {
    let entered = Arc::new(tokio::sync::Notify::new());
    let ended = Arc::new(tokio::sync::Notify::new());
    let (start, done) = (entered.clone(), ended.clone());
    let opts = Options::default().with_fallback(Fallback::new(move |mut req| {
        let (start, done) = (start.clone(), done.clone());
        async move {
            let mut read = std::pin::pin!(req.recv.recv_data());
            let result = std::future::poll_fn(|cx| {
                let result = Future::poll(read.as_mut(), cx);
                if result.is_pending() {
                    start.notify_one();
                }
                result
            })
            .await;
            assert!(matches!(result, Ok(None)));
            done.notify_one();
            req.send
                .send_response(http::Response::new(()))
                .await
                .unwrap();
            req.send.finish().await.unwrap();
        }
    }));
    let mut limits = ListenerConfig::default();
    limits.handshake_timeout = Duration::MAX;
    limits.admission = Some(Admission::new(0, |_, _| AdmissionVerdict::fallback()));
    let h3 = H3::with_listener(Config::default(), limits, &opts);
    tokio::time::timeout(Duration::from_secs(5), async {
        let conn = h3
            .client
            .connect(h3.addr, "127.0.0.1")
            .unwrap()
            .await
            .unwrap();
        let (mut driver, mut send) = h3::client::new(h3_quinn::Connection::new(conn.clone()))
            .await
            .unwrap();
        let drive =
            tokio::spawn(async move { std::future::poll_fn(|cx| driver.poll_close(cx)).await });
        let mut request = send
            .send_request(http::Request::post(h3.uri.clone()).body(()).unwrap())
            .await
            .unwrap();
        entered.notified().await;
        h3.listener.close();
        ended.notified().await;
        assert!(request.recv_response().await.unwrap().status().is_success());
        assert!(conn.close_reason().is_none());
        drive.abort();
    })
    .await
    .unwrap();
    h3.stop().await;
}

/// A stalled request whose body stays open is not answered: it ends
/// without a response once the stall is over.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_stalled_request_ends_without_a_response() {
    let adm = Admission::new(4, |_, _| AdmissionVerdict::Stall)
        .with_peek_timeout(Duration::from_secs(5))
        .with_stall_interval(Duration::from_millis(300), Duration::from_millis(300));
    let h3 = H3::admitted(Config::default(), adm, &Options::default());
    let status = raw_request(&h3, b"abcd", false).await;
    assert_eq!(status, None);
    assert_eq!(h3.listener.stats().admission.stalled, 1);
    h3.stop().await;
}

/// Without an admission, a request the listener does not take, with
/// nothing written on it, is answered by the fallback: 404 without one.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_request_the_listener_does_not_take_is_answered_with_404() {
    let h3 = H3::new(Config::default(), &Options::default());
    let status = raw_request(&h3, b"GET / HTTP/1.1\r\n\r\n", true).await;
    assert_eq!(status, Some(http::StatusCode::NOT_FOUND));
    h3.stop().await;
}

/// A request stream whose HEADERS frame claims more than the field section
/// bound is stopped (`H3_EXCESSIVE_LOAD`) as soon as its frame header
/// arrives: the server does not buffer the frame while the peer keeps
/// sending it within the head timeout.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_oversized_request_head_is_refused_before_it_is_buffered() {
    let h3 = H3::new(Config::default(), &Options::default());
    let conn = h3
        .client
        .connect(h3.addr, "127.0.0.1")
        .unwrap()
        .await
        .unwrap();
    let (mut send, _recv) = conn.open_bi().await.unwrap();
    // HEADERS (0x01) claiming 1 MiB and none of its payload: the frame
    // header alone is refused (unbounded, the server would wait for the
    // payload until the head timeout).
    send.write_all(&[0x01, 0x80, 0x10, 0x00, 0x00])
        .await
        .unwrap();
    let stopped = tokio::time::timeout(Duration::from_secs(5), send.stopped())
        .await
        .expect("stopped in time");
    assert_eq!(stopped.unwrap(), Some(0x0107u32.into()));
    // The connection itself stays usable.
    let status = raw_request(&h3, b"x", true).await;
    assert_eq!(status, Some(http::StatusCode::NOT_FOUND));
    conn.close(0u32.into(), b"");
    h3.stop().await;
}

/// A request whose head does not arrive within the listener's handshake
/// timeout is dropped, and a connection without a resolved request is
/// closed by then.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_request_head_and_the_first_request_are_bounded_in_time() {
    let mut lc = ListenerConfig::default();
    lc.handshake_timeout = Duration::from_millis(300);
    let h3 = H3::with_listener(Config::default(), lc, &Options::default());
    let conn = h3
        .client
        .connect(h3.addr, "127.0.0.1")
        .unwrap()
        .await
        .unwrap();
    let (mut send, _recv) = conn.open_bi().await.unwrap();
    // The start of a HEADERS frame, never completed.
    send.write_all(&[0x01, 0x10]).await.unwrap();
    let closed = tokio::time::timeout(Duration::from_secs(5), conn.closed())
        .await
        .expect("closed in time");
    assert!(
        matches!(closed, quinn::ConnectionError::ApplicationClosed(ref c) if c.error_code == 0x0100u32.into()),
        "{closed:?}"
    );
    h3.stop().await;
}

/// A request forwarded from TLS early data is answered 425 and counted as
/// a setup failure.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn early_data_is_too_early_and_a_setup_failure() {
    let h3 = H3::new(Config::default(), &Options::default());
    let status = raw_request_with(&h3, &[("early-data", "1")], b"", true).await;
    assert_eq!(status, Some(http::StatusCode::TOO_EARLY));
    assert_eq!(h3.listener.stats().setup_failures, 1);
    h3.stop().await;
}

#[tokio::test]
async fn host_connections_bind_request_identity_across_reuse_and_migration() {
    tokio::time::timeout(Duration::from_secs(45), async {
        let options = adopted_options(Options::default());
        let (server, endpoint, addr) = endpoints(&options);
        let listener = Listener::new(Config::default(), ListenerConfig::default()).unwrap();
        let connect = || async {
            tokio::join!(
                async { endpoint.connect(addr, "127.0.0.1").unwrap().await.unwrap() },
                async { server.accept().await.unwrap().await.unwrap() },
            )
        };
        let (host, peer) = connect().await;
        let (other_host, other_peer) = connect().await;
        assert_eq!(peer.remote_address(), other_peer.remote_address());
        assert_ne!(host.stable_id(), other_host.stable_id());
        let serve = |conn| {
            let (listener, options) = (listener.clone(), options.clone());
            tokio::spawn(async move { zmux_h3::serve_connection(&listener, conn, &options).await })
        };
        let first_serving = serve(peer.clone());
        let other_serving = serve(other_peer.clone());
        let origin = format!("https://127.0.0.1:{}", addr.port());
        let (one, two) = tokio::join!(
            Carrier::new(
                host.clone(),
                format!("{origin}/one").parse().unwrap(),
                &options
            ),
            Carrier::new(
                host.clone(),
                format!("{origin}/two").parse().unwrap(),
                &options
            ),
        );
        let (one, two) = (one.unwrap(), two.unwrap());
        assert!(Arc::ptr_eq(one.datagrams(), two.datagrams()));
        assert_eq!(one.connection().stable_id(), host.stable_id());
        let wrong_origin = Carrier::new(
            host.clone(),
            "https://localhost/wrong".parse().unwrap(),
            &options,
        )
        .await
        .unwrap_err();
        assert_eq!(wrong_origin.kind(), std::io::ErrorKind::InvalidInput);

        let other = Carrier::new(other_host.clone(), origin.parse().unwrap(), &options)
            .await
            .unwrap();
        let attach = |carrier: Carrier| {
            let listener = listener.clone();
            async move {
                let pipe = carrier.open_pipe().await.unwrap();
                let session = Session::connect(pipe, Config::default()).await.unwrap();
                let accepted = listener.accept().await.unwrap();
                (session, accepted)
            }
        };
        let (first, first_remote) = attach(one.clone()).await;
        let (second, second_remote) = attach(two.clone()).await;
        let (third, third_remote) = attach(other.clone()).await;
        let first_sample = carrier_sample(&first).await;
        let second_sample = carrier_sample(&second).await;
        let remote_sample = carrier_sample(&first_remote).await;
        assert_eq!(first_sample.carrier_id, second_sample.carrier_id);
        assert_eq!(
            remote_sample.carrier_id,
            carrier_sample(&second_remote).await.carrier_id
        );
        assert_ne!(
            first_sample.carrier_id,
            carrier_sample(&third).await.carrier_id
        );
        assert_ne!(
            remote_sample.carrier_id,
            carrier_sample(&third_remote).await.carrier_id
        );

        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let migrated = socket.local_addr().unwrap();
        endpoint.rebind(socket).unwrap();
        transfer(&first, &first_remote, 1, 128).await;
        assert_eq!(peer.remote_address(), migrated);
        assert_eq!(one.connection().stable_id(), host.stable_id());
        assert_eq!(
            carrier_sample(&first).await.carrier_id,
            first_sample.carrier_id
        );
        assert_eq!(
            carrier_sample(&first_remote).await.carrier_id,
            remote_sample.carrier_id
        );

        first.close().await;
        let _ = first.closed().await;
        drop(one);
        assert!(host.close_reason().is_none());
        transfer(&second, &second_remote, 1, 128).await;
        second.close().await;
        third.close().await;
        let _ = tokio::join!(second.closed(), third.closed());
        drop((two, other));
        assert!(host.close_reason().is_none());

        host.close(0x100u32.into(), b"owner");
        other_host.close(0x100u32.into(), b"owner");
        let _ = tokio::join!(first_serving, other_serving);
    })
    .await
    .unwrap();
}

async fn carrier_sample(session: &Session) -> zmux::CarrierSample {
    loop {
        if let Some(sample) = session
            .pipe_stats()
            .into_iter()
            .find_map(|stats| stats.carrier_sample)
            && matches!(sample.counts, Some(zmux::CarrierCounts::Quic { packets_sent, .. }) if packets_sent > 0)
        {
            assert_eq!(sample.source, zmux::CarrierSource::Quinn);
            assert_eq!(sample.direction, zmux::PipeDirection::Out);
            return sample;
        }
        tokio::task::yield_now().await;
    }
}

/// A session with datagrams enabled sends them as HTTP Datagrams of its
/// request stream, the pipe's datagram channel, both ways.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn datagrams_ride_http_datagrams_of_the_request() {
    tokio::time::timeout(Duration::from_secs(60), async {
        let mut config = Config::default();
        config.enable_datagrams = true;
        let opts = Options::default();
        let h3 = H3::new(config.clone(), &opts);
        let carrier = h3.h3_client(&opts).await;
        let client = Session::connect(carrier.open_pipe().await.unwrap(), config)
            .await
            .unwrap();
        let server = h3.listener.accept().await.unwrap();
        while !carrier.http_datagrams() {
            tokio::task::yield_now().await;
        }
        // The core refreshes the cached native size when a datagram wakes
        // the channel task. Observe a native delivery in each direction
        // before measuring the next batch.
        for (sender, receiver) in [(&client, &server), (&server, &client)] {
            while receiver.stats().datagrams_received_channel == 0 {
                let probe = bytes::Bytes::from_static(b"channel ready");
                sender.send_datagram(probe.clone()).unwrap();
                assert_eq!(receiver.read_datagram().await.unwrap(), probe);
            }
        }
        let (before_client, before_server) = (client.stats(), server.stats());
        let before_native = carrier.connection().stats();
        for i in 0..20u8 {
            client
                .send_datagram(bytes::Bytes::from(vec![i; 300]))
                .unwrap();
            assert_eq!(server.read_datagram().await.unwrap()[..], [i; 300]);
            server
                .send_datagram(bytes::Bytes::from(vec![i; 30]))
                .unwrap();
            assert_eq!(client.read_datagram().await.unwrap()[..], [i; 30]);
        }
        let (c, s) = (client.stats(), server.stats());
        let native = carrier.connection().stats();
        assert_eq!(
            c.datagrams_sent_channel - before_client.datagrams_sent_channel,
            20
        );
        assert_eq!(
            s.datagrams_sent_channel - before_server.datagrams_sent_channel,
            20
        );
        assert_eq!(
            c.datagrams_received_channel - before_client.datagrams_received_channel,
            20
        );
        assert_eq!(
            s.datagrams_received_channel - before_server.datagrams_received_channel,
            20
        );
        assert_eq!(
            native.frame_tx.datagram - before_native.frame_tx.datagram,
            20
        );
        assert_eq!(
            native.frame_rx.datagram - before_native.frame_rx.datagram,
            20
        );
        client.close().await;
        let _ = server.closing().await;
        h3.stop().await;
    })
    .await
    .expect("deadline");
}

/// Behind a trusted proxy, the source of a request is the client its
/// forwarding header field reports: the admission sees it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_source_behind_a_trusted_proxy_is_the_forwarded_client() {
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let admission = Admission::new(0, move |info, _| {
        let _ = tx.send(info.source);
        AdmissionVerdict::Close
    });
    let mut lc = ListenerConfig::default();
    lc.trusted_proxies = zmux::TrustedProxies::new()
        .with_net(zmux::IpNet::new("127.0.0.1".parse().unwrap(), 32).unwrap())
        .with_forwarded_header("x-forwarded-for");
    lc.admission = Some(admission);
    let h3 = H3::with_listener(Config::default(), lc, &Options::default());
    // A closed carrier may end a request before its decision: repeated.
    let source = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let _ = raw_request_with(&h3, &[("x-forwarded-for", "192.0.2.7")], b"x", true).await;
            if let Ok(s) = tokio::time::timeout(Duration::from_secs(1), rx.recv()).await {
                return s.unwrap();
            }
        }
    })
    .await
    .unwrap();
    assert_eq!(source, Some("192.0.2.7:0".parse().unwrap()));
    // Without the field: the connection's peer.
    while rx.try_recv().is_ok() {}
    let source = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let _ = raw_request(&h3, b"x", true).await;
            if let Ok(s) = tokio::time::timeout(Duration::from_secs(1), rx.recv()).await {
                return s.unwrap();
            }
        }
    })
    .await
    .unwrap()
    .unwrap();
    assert_eq!(
        source.ip(),
        "127.0.0.1".parse::<std::net::IpAddr>().unwrap()
    );
    h3.stop().await;
}

/// Pipe 0 of each session is of carrier kind `kind`.
fn assert_kind(sessions: [&Session; 2], kind: zmux::CarrierKind) {
    for s in sessions {
        let p = s.pipe(zmux::PipeId::new(0)).unwrap();
        assert_eq!(p.stats().unwrap().carrier, Some(kind));
    }
}

/// `serve_connection` reports only the end of the HTTP/3 connection: a close
/// with `H3_NO_ERROR` is success, any other code the connection's error.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn serve_connection_reports_only_the_connection_end() {
    for (code, ok) in [(0x100u32, true), (7, false)] {
        let opts = adopted_options(Options::default());
        let (server, client, addr) = endpoints(&opts);
        let listener = Listener::new(Config::default(), ListenerConfig::default()).unwrap();
        let l = listener.clone();
        let o = opts.clone();
        let serving = tokio::spawn(async move {
            let conn = server.accept().await.unwrap().await.unwrap();
            zmux_h3::serve_connection(&l, conn, &o).await
        });
        let uri: http::Uri = format!("https://127.0.0.1:{}/zmux", addr.port())
            .parse()
            .unwrap();
        let conn = client.connect(addr, "127.0.0.1").unwrap().await.unwrap();
        let carrier = Carrier::new(conn, uri, &opts).await.unwrap();
        // A request the listener answers by itself while it is closed does
        // not end the call.
        listener.close();
        let pipe = carrier.open_pipe().await.unwrap();
        let _ = Session::connect(pipe, Config::default()).await;
        assert!(!serving.is_finished(), "a closed listener ends no call");
        carrier.connection().close(code.into(), b"done");
        let r = tokio::time::timeout(Duration::from_secs(10), serving)
            .await
            .expect("ended")
            .unwrap();
        assert_eq!(r.is_ok(), ok, "{r:?}");
    }
}

/// A request carrier decided on its body with a fallback verdict, given
/// to the listener's fallback: answered 200, `detach` the host's or not.
/// Returns what the host read after the replay and how the client's
/// response body ended (its data, and whether it failed), and whether the
/// client's request body was stopped.
async fn request_takeover(detach: bool) -> (Vec<u8>, Vec<u8>, bool, bool) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    // The client read the head and "pong": the future may return (a reset
    // before would discard them).
    let (go_tx, go) = tokio::sync::oneshot::channel::<()>();
    let go = std::sync::Mutex::new(Some(go));
    let fallback = zmux::Fallback::new(move |t: zmux::Takeover| {
        let tx = tx.clone();
        let go = go.lock().unwrap().take().unwrap();
        async move {
            assert_eq!(t.info().stage, zmux::AdmissionStage::Carrier);
            if detach {
                t.detach().unwrap();
            }
            let mut s = t.into_pipe().into_stream();
            let mut head = [0; 8];
            s.read_exact(&mut head).await.unwrap();
            s.write_all(b"pong").await.unwrap();
            s.flush().await.unwrap();
            if detach {
                // Served on after the future; ended by the host.
                tokio::spawn(async move {
                    go.await.unwrap();
                    let mut probe = [0];
                    s.read_exact(&mut probe).await.unwrap();
                    assert_eq!(&probe, b"x");
                    s.write_all(b"!").await.unwrap();
                    s.shutdown().await.unwrap();
                    let _ = tx.send((head.to_vec(), Some(s)));
                });
            } else {
                // Kept past the future, never ended.
                let _ = tx.send((head.to_vec(), Some(s)));
                let _ = go.await;
            }
        }
    });
    let mut go_tx = Some(go_tx);
    let admission = Admission::new(4, |_, p: &[u8]| {
        if p == b"HELO" {
            AdmissionVerdict::takeover()
        } else {
            AdmissionVerdict::Close
        }
    });
    let mut lc = ListenerConfig::default();
    lc.admission = Some(admission);
    lc.fallback = Some(fallback);
    let h3 = H3::with_listener(Config::default(), lc, &Options::default());
    let conn = h3
        .client
        .connect(h3.addr, "127.0.0.1")
        .unwrap()
        .await
        .unwrap();
    let (mut driver, mut send) = h3::client::new(h3_quinn::Connection::new(conn.clone()))
        .await
        .unwrap();
    let drive = tokio::spawn(async move {
        let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
    });
    let request = http::Request::post(h3.uri.clone()).body(()).unwrap();
    let stream = send.send_request(request).await.unwrap();
    let (mut req, mut resp) = stream.split();
    req.send_data(bytes::Bytes::from_static(b"HELOping"))
        .await
        .unwrap();
    let r = tokio::time::timeout(Duration::from_secs(60), resp.recv_response())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(r.status(), http::StatusCode::OK);
    let mut got = Vec::new();
    let failed = tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            match resp.recv_data().await {
                Ok(Some(mut b)) => {
                    while b.has_remaining() {
                        let c = b.chunk();
                        got.extend_from_slice(c);
                        let n = c.len();
                        b.advance(n);
                    }
                    if got.len() >= 4
                        && let Some(go) = go_tx.take()
                    {
                        if detach {
                            req.send_data(bytes::Bytes::from_static(b"x"))
                                .await
                                .unwrap();
                        }
                        go.send(()).unwrap();
                    }
                }
                Ok(None) => return false,
                Err(_) => return true,
            }
        }
    })
    .await
    .expect("the response ended or failed");
    let (head, kept) = tokio::time::timeout(Duration::from_secs(60), rx.recv())
        .await
        .unwrap()
        .unwrap();
    // For a detached request the host already read the probe. Otherwise wait
    // for the peer to process STOP_SENDING, which can follow the response reset.
    let stopped = if detach {
        false
    } else {
        tokio::time::timeout(Duration::from_secs(60), async {
            while req.send_data(bytes::Bytes::from_static(b"x")).await.is_ok() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the request was not stopped");
        true
    };
    drop(kept);
    drive.abort();
    conn.close(0u32.into(), b"");
    h3.stop().await;
    (head, got, failed, stopped)
}

/// A detached request carrier is the host's after the fallback's future:
/// it reads the replayed body bytes first, answers, and ends the response.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_detached_request_carrier_is_served_after_the_fallback() {
    let (head, got, failed, stopped) = request_takeover(true).await;
    assert_eq!(head, b"HELOping");
    assert_eq!(got, b"pong!");
    assert!(!failed, "the response ended gracefully");
    assert!(!stopped, "the request body is the host's");
}

/// A request carrier not detached is cut when the fallback's future
/// returns, though the host keeps its pipe: the response not ended is
/// reset and the request body stopped.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_undetached_request_carrier_is_reset_when_the_fallback_returns() {
    let (head, got, failed, stopped) = request_takeover(false).await;
    assert_eq!(head, b"HELOping");
    assert!(b"pong".starts_with(&got), "{got:?}");
    assert!(failed, "the response is reset, not ended");
    assert!(stopped, "the request body is stopped");
}

#[tokio::test]
// HS-05
async fn request_cancellation_releases_an_admitted_setup() {
    for stop_response in [true, false] {
        for admission in [false, true] {
            cancelled_setup(stop_response, admission).await;
        }
    }
}

async fn cancelled_setup(stop_response: bool, admission: bool) {
    let mut limits = ListenerConfig::default();
    limits.admission = Some(Admission::new(0, |_, _| AdmissionVerdict::accept(0)));
    limits.limits.max_pending = Some(1);
    limits.handshake_timeout = Duration::from_secs(60);
    let entered = Arc::new(tokio::sync::Notify::new());
    let started = entered.clone();
    let (held, dropped) = tokio::sync::oneshot::channel::<()>();
    let lifetime = std::sync::Mutex::new(Some(held));
    if admission {
        struct Pending(
            Arc<tokio::sync::Notify>,
            std::sync::Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
        );
        impl zmux::Decide for Pending {
            fn decide(
                &self,
                _: zmux::CarrierInfo,
                _: &[u8],
            ) -> zmux::Decision<zmux::AdmissionDecision> {
                let guard = self.1.lock().unwrap().take();
                self.0.notify_one();
                zmux::Decision::later(async move {
                    std::future::pending::<()>().await;
                    drop(guard);
                    AdmissionVerdict::Close.into()
                })
            }
        }
        limits.admission = Some(Admission::with_decider(0, Pending(started, lifetime)));
    } else {
        limits.inbound_transform = Some(zmux::InboundTransform::new(
            move |io, _: &zmux::PipeHint| {
                let guard = lifetime.lock().unwrap().take();
                let started = started.clone();
                async move {
                    started.notify_one();
                    std::future::pending::<()>().await;
                    drop(guard);
                    Ok(io)
                }
            },
        ));
    }
    let h3 = H3::with_listener(Config::default(), limits, &Options::default());
    let conn = h3
        .client
        .connect(h3.addr, &h3.addr.ip().to_string())
        .unwrap()
        .await
        .unwrap();
    let (mut driver, mut requests) = h3::client::new(h3_quinn::Connection::new(conn.clone()))
        .await
        .unwrap();
    let drive = tokio::spawn(async move { std::future::poll_fn(|cx| driver.poll_close(cx)).await });
    let request = http::Request::post(h3.uri.clone()).body(()).unwrap();
    let mut stream = requests.send_request(request).await.unwrap();
    if !admission {
        assert!(stream.recv_response().await.unwrap().status().is_success());
    }
    entered.notified().await;
    assert!(h3.listener.adapter().enter(h3.addr, None).is_none());
    if stop_response {
        stream.stop_sending(h3::error::Code::H3_REQUEST_CANCELLED);
    } else {
        stream.stop_stream(h3::error::Code::H3_REQUEST_CANCELLED);
    }
    tokio::time::timeout(Duration::from_secs(2), dropped)
        .await
        .unwrap()
        .unwrap_err();
    assert!(h3.listener.adapter().enter(h3.addr, None).is_some());
    drive.abort();
    conn.close(0u32.into(), b"");
    h3.stop().await;
}

/// Read only one byte of the response HEADERS frame, then withhold the
/// remaining stream credit. The accepted head still belongs to setup.
#[tokio::test]
// HS-15, HS-16
async fn a_flow_controlled_response_head_ends_with_setup() {
    for takeover in [false, true] {
        for stop in [false, true] {
            tokio::time::timeout(Duration::from_secs(8), async {
                let opts = Options::default()
                    .with_windows(zmux_h3::LaneWindows::new().with_stream_window(1));
                let mut config = ListenerConfig::default();
                config.handshake_timeout = Duration::from_secs(3);
                config.limits.max_pending = Some(1);
                config.admission = Some(Admission::new(0, move |_, _| {
                    if takeover {
                        AdmissionVerdict::takeover()
                    } else {
                        AdmissionVerdict::accept(0)
                    }
                }));
                let handed = Arc::new(std::sync::atomic::AtomicBool::new(false));
                let observed = handed.clone();
                config.fallback = Some(zmux::Fallback::new(move |_| {
                    observed.store(true, std::sync::atomic::Ordering::Release);
                    std::future::ready(())
                }));
                let h3 = H3::with_listener(Config::default(), config, &opts);
                let conn = h3
                    .client
                    .connect(h3.addr, &h3.addr.ip().to_string())
                    .unwrap()
                    .await
                    .unwrap();
                // The peer consumes control streams normally, but never gives the
                // response enough credit to finish its head.
                let control = conn.clone();
                let draining = tokio::spawn(async move {
                    while let Ok(mut stream) = control.accept_uni().await {
                        tokio::spawn(async move {
                            let _ = stream.read_to_end(4096).await;
                        });
                    }
                });
                let (mut request, mut response) = conn.open_bi().await.unwrap();
                request
                    .write_all(&[
                        1, 16, 0, 0, 0xd4, 0xd7, 0xc1, 0x50, 9, b'l', b'o', b'c', b'a', b'l', b'h',
                        b'o', b's', b't',
                    ])
                    .await
                    .unwrap();
                let mut first = [0];
                response.read_exact(&mut first).await.unwrap();
                assert_eq!(first, [1]);
                assert!(h3.listener.adapter().enter(h3.addr, None).is_none());
                if stop {
                    h3.listener.close();
                } else {
                    tokio::time::pause();
                    tokio::time::advance(Duration::from_secs(3)).await;
                    tokio::time::resume();
                }
                // The dropped request reader sends STOP without reading more
                // response bytes or closing the shared QUIC connection.
                request.stopped().await.unwrap();
                assert!(conn.close_reason().is_none());
                assert!(!handed.load(std::sync::atomic::Ordering::Acquire));
                if takeover {
                    let stats = h3.listener.stats().admission;
                    assert_eq!(
                        (stats.closed, stats.peek_timed_out, stats.handshake_failed),
                        (u64::from(stop), u64::from(!stop), 0)
                    );
                }
                if !stop {
                    assert!(h3.listener.adapter().enter(h3.addr, None).is_some());
                }
                conn.close(0u32.into(), b"");
                draining.await.unwrap();
                h3.stop().await;
            })
            .await
            .unwrap();
        }
    }
}
