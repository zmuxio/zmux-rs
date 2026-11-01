//! HTTP/3 request carriers over loopback: one-step `connect` and `serve`
//! with streams both ways and a close the peer sees, client lanes on
//! further requests and a second pipe on another request of the same
//! connection (each pipe a request body paired with its response body),
//! and a lost connection that is a failure of its pipes, never their clean
//! end.

use std::sync::Arc;
use std::time::Duration;

use bytes::Buf;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use zmux::{
    Admission, Config, Listener, ListenerConfig, PipeAuth, PipeFailure, PipeOptions, PrefixAuth,
    PrefixAuthVerifier, Session, SessionError, Verdict,
};
use zmux_h3::{H3Client, H3Fallback, Options};

/// A served HTTP/3 endpoint and a client endpoint for it over loopback.
struct H3 {
    client: quinn::Endpoint,
    addr: std::net::SocketAddr,
    uri: http::Uri,
    listener: Listener,
    serving: tokio::task::JoinHandle<()>,
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
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let cert = rcgen::generate_simple_self_signed(vec!["127.0.0.1".into()]).unwrap();
        let der = CertificateDer::from(cert.cert.der().to_vec());
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()));
        let tls = rustls::ServerConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![der.clone()], key)
            .unwrap();
        // The configuration helpers add `h3`.
        let server_config = zmux_h3::server_config(tls, opts).unwrap();
        let server =
            quinn::Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
        let addr = server.local_addr().unwrap();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(der).unwrap();
        let tls = rustls::ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let client_config = zmux_h3::client_config(tls, opts).unwrap();
        let mut client = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        client.set_default_client_config(client_config);
        let listener = Listener::new(config, lc);
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
    async fn h3_client(&self, opts: &Options) -> H3Client {
        let conn = self
            .client
            .connect(self.addr, "127.0.0.1")
            .unwrap()
            .await
            .unwrap();
        H3Client::new(conn, self.uri.clone(), opts).await.unwrap()
    }

    async fn stop(self) {
        self.listener.close();
        self.serving.await.unwrap();
    }
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
    client.close(0u32.into(), b"bye");
    let e = tokio::time::timeout(Duration::from_secs(10), server.closed())
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
    let config = Config::multipath(PipeAuth::psk(*b"zmux-h3-adapter-test-psk-0123456"));
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
        .add_pipe(client.open_pipe().await.unwrap(), PipeOptions::new())
        .unwrap();
    tokio::time::timeout(Duration::from_secs(10), pipe.joined())
        .await
        .expect("joined in time")
        .unwrap();
    transfer(&ss, &cs, 4, 256 << 10).await;
    cs.close(0u32.into(), b"");
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
        let e = tokio::time::timeout(Duration::from_secs(10), s.closed())
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
    PrefixAuth::new(b"key", Duration::from_secs(30), true).unwrap()
}

fn admission() -> Admission {
    Admission::prefix_auth(Arc::new(PrefixAuthVerifier::new(auth(), 1, 1024)))
        .with_peek_timeout(Duration::from_secs(5))
        .with_stall_interval(Duration::from_millis(300), Duration::from_millis(300))
}

/// A plain HTTP/3 request to the server with `body`, ended when `end`; the
/// response's status, or `None` when the request fails, and the time
/// it took.
async fn raw_request(h3: &H3, body: &[u8], end: bool) -> (Option<http::StatusCode>, Duration) {
    raw_request_with(h3, &[], body, end).await
}

/// [`raw_request`] with request header fields.
async fn raw_request_with(
    h3: &H3,
    fields: &[(&str, &str)],
    body: &[u8],
    end: bool,
) -> (Option<http::StatusCode>, Duration) {
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
    let started = tokio::time::Instant::now();
    let mut request = http::Request::post(h3.uri.clone());
    for (n, v) in fields {
        request = request.header(*n, *v);
    }
    let mut stream = send.send_request(request.body(()).unwrap()).await.unwrap();
    stream
        .send_data(bytes::Bytes::copy_from_slice(body))
        .await
        .unwrap();
    if end {
        stream.finish().await.unwrap();
    }
    let status = tokio::time::timeout(Duration::from_secs(10), stream.recv_response())
        .await
        .expect("answered or ended in time")
        .ok()
        .map(|r| r.status());
    let took = started.elapsed();
    drive.abort();
    conn.close(0u32.into(), b"");
    (status, took)
}

/// With an admission of bound prefix authentication tokens, a client with
/// the same `PrefixAuth` writes a token first on every request body, its
/// pipe's and its lanes', and both are accepted.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn admitted_requests_with_tokens_on_pipes_and_lanes() {
    let config = Config::multipath(PipeAuth::psk(*b"zmux-h3-adapter-test-psk-0123456"));
    let h3 = H3::admitted(config.clone(), admission(), &Options::default());
    let client = h3
        .h3_client(&Options::default().with_credential(Arc::new(auth())))
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
    cs.close(0u32.into(), b"");
    h3.stop().await;
}

/// A request whose body does not start with a valid token goes to the
/// fallback handler with every body byte read, unanswered before.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_request_without_a_token_goes_to_the_fallback_with_its_bytes() {
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let fallback = H3Fallback::new(move |mut req| {
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
    let (status, _) = raw_request(&h3, &body, true).await;
    assert_eq!(status, Some(http::StatusCode::IM_A_TEAPOT));
    assert_eq!(rx.recv().await.unwrap(), body);
    h3.stop().await;
}

/// A stalled request whose body stays open is not answered: it ends
/// without a response once the stall is over.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_stalled_request_ends_without_a_response() {
    let adm = Admission::new(4, |_, _| Verdict::Stall)
        .with_peek_timeout(Duration::from_secs(5))
        .with_stall_interval(Duration::from_millis(300), Duration::from_millis(300));
    let h3 = H3::admitted(Config::default(), adm, &Options::default());
    let (status, took) = raw_request(&h3, b"abcd", false).await;
    assert_eq!(status, None);
    assert!(took >= Duration::from_millis(250), "{took:?}");
    h3.stop().await;
}

/// Without an admission, a request the listener does not take, with
/// nothing written on it, is answered by the fallback: 404 without one.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_request_the_listener_does_not_take_is_answered_with_404() {
    let h3 = H3::new(Config::default(), &Options::default());
    let (status, _) = raw_request(&h3, b"GET / HTTP/1.1\r\n\r\n", true).await;
    assert_eq!(status, Some(http::StatusCode::NOT_FOUND));
    h3.stop().await;
}

/// A request forwarded from TLS early data is answered 425 and counted as
/// a setup failure.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn early_data_is_too_early_and_a_setup_failure() {
    let h3 = H3::new(Config::default(), &Options::default());
    let (status, _) = raw_request_with(&h3, &[("early-data", "1")], b"", true).await;
    assert_eq!(status, Some(http::StatusCode::TOO_EARLY));
    assert_eq!(h3.listener.stats().setup_failures, 1);
    h3.stop().await;
}

/// A session with datagrams enabled sends them as HTTP Datagrams of its
/// request stream (EXTENSIONS.md Section 6.8), both ways.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn datagrams_ride_http_datagrams_of_the_request() {
    tokio::time::timeout(Duration::from_secs(60), async {
        let mut config = Config::default();
        config.enable_datagrams = true;
        let opts = Options::default();
        let h3 = H3::new(config.clone(), &opts);
        let client = zmux_h3::connect(&h3.client, h3.addr, h3.uri.clone(), &opts, config)
            .await
            .unwrap();
        let server = h3.listener.accept().await.unwrap();
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
        // The client's first ones may go in records: its channel is
        // usable once the server's SETTINGS arrived.
        assert!(c.datagrams_sent_channel >= 18, "{c:?}");
        assert_eq!(s.datagrams_sent_channel, 20);
        assert_eq!(c.datagrams_received_channel, 20);
        assert_eq!(s.datagrams_received_channel, c.datagrams_sent_channel);
        client.close(0u32.into(), b"bye");
        let _ = server.closed().await;
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
        Verdict::Close
    });
    let mut lc = ListenerConfig::default();
    lc.trusted_proxies = zmux::TrustedProxies::new()
        .with_net(zmux::IpNet::new("127.0.0.1".parse().unwrap(), 32).unwrap())
        .with_forwarded_header("x-forwarded-for");
    lc.admission = Some(admission);
    let h3 = H3::with_listener(Config::default(), lc, &Options::default());
    let _ = raw_request_with(&h3, &[("x-forwarded-for", "192.0.2.7")], b"x", true).await;
    let source = tokio::time::timeout(Duration::from_secs(10), rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(source, Some("192.0.2.7:0".parse().unwrap()));
    // Without the field: the connection's peer.
    let _ = raw_request(&h3, b"x", true).await;
    let source = rx.recv().await.unwrap().unwrap();
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
