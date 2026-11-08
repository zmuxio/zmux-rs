//! HTTP exchanges as pipes over loopback: a session over HTTP/1.1 and over
//! HTTP/2, both bodies of one exchange carrying the two directions, two
//! pipes on one HTTP/2 connection with lanes only when turned on, and a
//! cut connection seen as a failure, never a clean end.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use tokio::net::{TcpListener, TcpStream};
use zmux::{
    Config, Listener, ListenerConfig, PipeAuth, PipeFailure, PipeOptions, Session, SessionError,
};
use zmux_http::{Http2Connection, Options};

/// A listener served on loopback: its address and the serving task.
async fn server(config: Config) -> (String, Listener, tokio::task::JoinHandle<()>) {
    let listener =
        Listener::new(config, ListenerConfig::default()).expect("valid listener configuration");
    let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = tcp.local_addr().unwrap().to_string();
    let serving = tokio::spawn(zmux_http::serve(listener.clone(), tcp, Options::default()));
    (addr, listener, serving)
}

/// Sends `n` streams of `len` bytes from `from` to `to` at once and checks
/// every byte.
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
    tokio::time::timeout(Duration::from_secs(20), receiver)
        .await
        .expect("transfer in time")
        .unwrap();
}

/// Both directions, then a close the peer sees.
async fn round_trip_and_close(client: Session, server: Session) {
    transfer(&client, &server, 2, 256 << 10).await;
    transfer(&server, &client, 2, 256 << 10).await;
    client.close(3u32.into(), b"bye").await;
    let e = tokio::time::timeout(Duration::from_secs(5), server.closed())
        .await
        .expect("closed");
    assert!(
        matches!(e, SessionError::ApplicationClosed { remote: true, .. }),
        "{e:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_session_over_http1() {
    let (addr, listener, serving) = server(Config::default()).await;
    let client = zmux_http::connect_http1(&addr, &Options::default(), Config::default())
        .await
        .unwrap();
    let server = listener.accept().await.unwrap();
    assert_kind([&client, &server], zmux::CarrierKind::Streaming);
    round_trip_and_close(client, server).await;
    listener.close();
    serving.await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_session_over_http2() {
    let (addr, listener, serving) = server(Config::default()).await;
    let client = zmux_http::connect_http2(&addr, &Options::default(), Config::default())
        .await
        .unwrap();
    let server = listener.accept().await.unwrap();
    round_trip_and_close(client, server).await;
    listener.close();
    serving.await.unwrap();
}

/// Body pairing: one HTTP/1.1 exchange carries the whole session, its
/// request body one direction and its response body the other, through a
/// server of the application's own that routes the request to
/// `handle_request`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn one_exchange_carries_both_directions() {
    let listener = Listener::new(Config::default(), ListenerConfig::default())
        .expect("valid listener configuration");
    let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = tcp.local_addr().unwrap().to_string();
    let requests = Arc::new(AtomicUsize::new(0));
    {
        let (listener, requests) = (listener.clone(), requests.clone());
        tokio::spawn(async move {
            let (stream, peer) = tcp.accept().await.unwrap();
            let service = hyper::service::service_fn(move |req| {
                requests.fetch_add(1, Ordering::SeqCst);
                let listener = listener.clone();
                async move {
                    zmux_http::handle_request(&listener, req, Some(peer), None)
                        .await
                        .map_err(|_| std::io::Error::other("not handled"))
                }
            });
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(hyper_util::rt::TokioIo::new(stream), service)
                .await;
        });
    }
    let client = zmux_http::connect_http1(&addr, &Options::default(), Config::default())
        .await
        .unwrap();
    let server = listener.accept().await.unwrap();
    transfer(&client, &server, 1, 1 << 20).await;
    transfer(&server, &client, 1, 1 << 20).await;
    assert_eq!(requests.load(Ordering::SeqCst), 1, "one exchange");
    client.close(0u32.into(), b"").await;
}

fn multipath() -> Config {
    Config::multipath(PipeAuth::psk(*b"zmux-http-test-psk-0123456789abc").with_end_to_end())
}

/// HTTP/2: two pipes of a multipath session on one connection (the join
/// over the second exchange is accepted), and lanes on further requests of
/// the connection only when turned on.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn http2_pipes_share_a_connection_and_lanes_only_when_enabled() {
    let (addr, listener, serving) = server(multipath()).await;
    for lanes in [false, true] {
        let conn = Http2Connection::connect(&addr, Options::default().with_lanes(lanes))
            .await
            .unwrap();
        let client = conn.connect_session(multipath()).await.unwrap();
        let server = listener.accept().await.unwrap();
        let second = client
            .begin_add_pipe(conn.open_pipe().await.unwrap(), PipeOptions::new())
            .unwrap();
        tokio::time::timeout(Duration::from_secs(10), second.joined())
            .await
            .expect("joined in time")
            .unwrap();
        transfer(&client, &server, 8, 1 << 20).await;
        let most = client
            .pipe_stats()
            .iter()
            .map(|p| p.lanes_out)
            .max()
            .unwrap();
        if lanes {
            assert!(most > 1, "no lane was opened");
        } else {
            assert_eq!(most, 1, "a lane was opened while lanes are off");
        }
        client.close(0u32.into(), b"").await;
    }
    listener.close();
    serving.await.unwrap();
}

/// A TCP proxy to `to` for one connection; aborting the task drops both
/// sockets.
async fn proxy(to: &str) -> (String, tokio::task::JoinHandle<()>) {
    let front = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = front.local_addr().unwrap().to_string();
    let to = to.to_owned();
    let task = tokio::spawn(async move {
        let (mut a, _) = front.accept().await.unwrap();
        let mut b = TcpStream::connect(to).await.unwrap();
        let _ = tokio::io::copy_bidirectional(&mut a, &mut b).await;
    });
    (addr, task)
}

/// A connection cut under a session is a failure of its pipe at both
/// ends, never the peer's clean end.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_cut_connection_is_a_failure_not_a_clean_end() {
    let (addr, listener, serving) = server(Config::default()).await;
    for http2 in [false, true] {
        let (front, cut) = proxy(&addr).await;
        let client = if http2 {
            zmux_http::connect_http2(&front, &Options::default(), Config::default()).await
        } else {
            zmux_http::connect_http1(&front, &Options::default(), Config::default()).await
        }
        .unwrap();
        let server = listener.accept().await.unwrap();
        transfer(&client, &server, 1, 64 << 10).await;
        cut.abort();
        for s in [&client, &server] {
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
                "http2={http2}: {e:?}"
            );
        }
    }
    listener.close();
    serving.await.unwrap();
}

/// TLS configurations whose ALPN offers `h2` and `http/1.1` (the client
/// offers only `client_alpn`).
fn tls(client_alpn: &[u8]) -> (tokio_rustls::TlsConnector, tokio_rustls::TlsAcceptor) {
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let der = CertificateDer::from(cert.cert.der().to_vec());
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()));
    let mut server = rustls::ServerConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![der.clone()], key)
        .unwrap();
    server.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let mut roots = rustls::RootCertStore::empty();
    roots.add(der).unwrap();
    let mut client = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    client.alpn_protocols = vec![client_alpn.to_vec()];
    (
        tokio_rustls::TlsConnector::from(Arc::new(client)),
        tokio_rustls::TlsAcceptor::from(Arc::new(server)),
    )
}

/// HTTPS: sessions over HTTP/2 and HTTP/1.1 on TLS connections the
/// application made, served by `serve_with` with a TLS setup step; a
/// connection whose TLS handshake fails is counted, not silently dropped.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sessions_over_tls_and_a_failed_handshake_is_counted() {
    for alpn in [&b"h2"[..], b"http/1.1"] {
        let (connector, acceptor) = tls(alpn);
        let listener = Listener::new(Config::default(), ListenerConfig::default())
            .expect("valid listener configuration");
        let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = tcp.local_addr().unwrap();
        let l = listener.clone();
        let serving = tokio::spawn(async move {
            zmux_http::serve_with(
                l,
                || tcp.accept(),
                move |conn, _| acceptor.accept(conn),
                Options::default(),
            )
            .await
        });
        let name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
        let conn = connector
            .connect(name, TcpStream::connect(addr).await.unwrap())
            .await
            .unwrap();
        assert_eq!(conn.get_ref().1.alpn_protocol(), Some(alpn));
        let client = if alpn == b"h2" {
            Http2Connection::handshake(conn, "localhost", Options::default())
                .await
                .unwrap()
                .connect_session(Config::default())
                .await
                .unwrap()
        } else {
            let io = zmux_http::dial_http1_over(conn, "localhost", &Options::default())
                .await
                .unwrap();
            Session::connect(io, Config::default()).await.unwrap()
        };
        let server = listener.accept().await.unwrap();
        round_trip_and_close(client, server).await;

        // Not TLS at all: a setup failure.
        let mut plain = TcpStream::connect(addr).await.unwrap();
        tokio::io::AsyncWriteExt::write_all(&mut plain, b"GET / HTTP/1.1\r\n\r\n")
            .await
            .unwrap();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while listener.stats().setup_failures == 0 {
            assert!(
                tokio::time::Instant::now() < deadline,
                "{:?}",
                listener.stats()
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let stats = listener.stats();
        assert_eq!((stats.sessions, stats.setup_failures), (1, 1), "{stats:?}");
        listener.close();
        serving.await.unwrap();
    }
}

/// A full setup limit ends the oldest handshake rather than refusing the
/// new client.
#[tokio::test]
async fn a_stalled_handshake_yields_its_setup_slot() {
    let (connector, acceptor) = tls(b"http/1.1");
    let mut limits = ListenerConfig::default();
    limits.max_pending = 1;
    let listener = Listener::new(Config::default(), limits).expect("valid listener configuration");
    let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = tcp.local_addr().unwrap();
    let l = listener.clone();
    let serving = tokio::spawn(async move {
        zmux_http::serve_with(
            l,
            || tcp.accept(),
            move |conn, _| acceptor.accept(conn),
            Options::default(),
        )
        .await
    });
    // Connected, silent: its TLS handshake holds the only setup slot.
    let stalled = TcpStream::connect(addr).await.unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;
    let name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
    let conn = connector
        .connect(name, TcpStream::connect(addr).await.unwrap())
        .await
        .unwrap();
    let io = zmux_http::dial_http1_over(conn, "localhost", &Options::default())
        .await
        .unwrap();
    let client = Session::connect(io, Config::default()).await.unwrap();
    let server = listener.accept().await.unwrap();
    round_trip_and_close(client, server).await;
    assert_eq!(listener.stats().setup_failures, 1);
    drop(stalled);
    listener.close();
    serving.await.unwrap();
}

// ---- admission -----------------------------------------------------------------------

/// A listener served on loopback with `options`.
async fn server_with(options: Options) -> (String, Listener) {
    serve_admitted(options, None).await
}

async fn serve_admitted(
    options: Options,
    admission: Option<zmux::Admission>,
) -> (String, Listener) {
    let mut limits = ListenerConfig::default();
    limits.admission = admission;
    let listener = Listener::new(Config::default(), limits).expect("valid listener configuration");
    let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = tcp.local_addr().unwrap().to_string();
    tokio::spawn(zmux_http::serve(listener.clone(), tcp, options));
    (addr, listener)
}

/// A request body read from a byte stream.
struct StreamBody<R>(R);

impl<R: tokio::io::AsyncRead + Unpin> http_body::Body for StreamBody<R> {
    type Data = bytes::Bytes;
    type Error = std::io::Error;

    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<http_body::Frame<bytes::Bytes>, std::io::Error>>> {
        let mut buf = vec![0u8; 16 * 1024];
        let mut rb = tokio::io::ReadBuf::new(&mut buf);
        match std::task::ready!(std::pin::Pin::new(&mut self.0).poll_read(cx, &mut rb)) {
            Err(e) => std::task::Poll::Ready(Some(Err(e))),
            Ok(()) if rb.filled().is_empty() => std::task::Poll::Ready(None),
            Ok(()) => {
                let n = rb.filled().len();
                buf.truncate(n);
                std::task::Poll::Ready(Some(Ok(http_body::Frame::data(buf.into()))))
            }
        }
    }
}

/// A response body as a byte stream.
struct IncomingReader(hyper::body::Incoming, bytes::Bytes);

impl tokio::io::AsyncRead for IncomingReader {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        use http_body::Body;
        loop {
            if !self.1.is_empty() {
                let n = self.1.len().min(buf.remaining());
                buf.put_slice(&self.1.split_to(n));
                return std::task::Poll::Ready(Ok(()));
            }
            match std::task::ready!(std::pin::Pin::new(&mut self.0).poll_frame(cx)) {
                None => return std::task::Poll::Ready(Ok(())),
                Some(Err(e)) => return std::task::Poll::Ready(Err(std::io::Error::other(e))),
                Some(Ok(f)) => {
                    if let Ok(d) = f.into_data() {
                        self.1 = d;
                    }
                }
            }
        }
    }
}

/// One HTTP/1.1 POST to `path` of `addr` with `body`: the response, or the
/// error of an exchange that ended without one.
async fn post<B>(
    addr: &str,
    path: &str,
    body: B,
) -> hyper::Result<http::Response<hyper::body::Incoming>>
where
    B: http_body::Body<Data = bytes::Bytes> + Send + 'static,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    let tcp = TcpStream::connect(addr).await.unwrap();
    let (mut sender, conn) =
        hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(tcp)).await?;
    tokio::spawn(conn);
    let req = http::Request::post(path)
        .header(http::header::HOST, addr)
        .body(body)
        .unwrap();
    sender.send_request(req).await
}

fn fixed(data: &'static [u8]) -> StreamBody<&'static [u8]> {
    StreamBody(data)
}

const BODY: &[u8] = b"0123456789abcdef0123456789abcdef-and-the-rest-of-the-request-body";

/// A fallback handler that answers with the body it was given.
fn echo() -> zmux_http::HttpFallback {
    zmux_http::HttpFallback::new(|req: zmux_http::FallbackRequest, _| async move {
        http::Response::new(zmux_http::PipeBody::full(collect(req.into_body()).await))
    })
}

/// The data of a replayed request body.
async fn collect(mut body: zmux_http::ReplayBody<hyper::body::Incoming>) -> Vec<u8> {
    use http_body::Body;
    let mut out = Vec::new();
    while let Some(f) =
        std::future::poll_fn(|cx| std::pin::Pin::new(&mut body).poll_frame(cx)).await
    {
        if let Ok(d) = f.unwrap().into_data() {
            out.extend_from_slice(&d);
        }
    }
    out
}

async fn read_all(resp: http::Response<hyper::body::Incoming>) -> Vec<u8> {
    let mut out = Vec::new();
    let mut r = IncomingReader(resp.into_body(), bytes::Bytes::new());
    tokio::io::AsyncReadExt::read_to_end(&mut r, &mut out)
        .await
        .unwrap();
    out
}

/// A prefix authentication token as the first bytes of the request body
/// is accepted: the response is 200 at once, and a session runs over the
/// rest of the body and the response.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_admitted_request_carries_a_session() {
    let auth = zmux::PrefixAuth::new(b"psk", Duration::from_secs(30), false).unwrap();
    let verifier = Arc::new(zmux::PrefixAuthVerifier::new(auth.clone(), 1, 1024));
    let admission = zmux::Admission::prefix_auth(verifier);
    let (addr, listener) = serve_admitted(Options::default(), Some(admission)).await;
    let (mut ours, theirs) = tokio::io::duplex(64 << 10);
    tokio::io::AsyncWriteExt::write_all(&mut ours, &auth.token(None).unwrap())
        .await
        .unwrap();
    let resp = tokio::time::timeout(
        Duration::from_secs(5),
        post(&addr, "/zmux", StreamBody(theirs)),
    )
    .await
    .expect("answered at the decision")
    .unwrap();
    assert_eq!(resp.status(), 200);
    let io = zmux::PipeIo::from_halves(IncomingReader(resp.into_body(), bytes::Bytes::new()), ours);
    let client = Session::connect(io, Config::default()).await.unwrap();
    let server = listener.accept().await.unwrap();
    transfer(&client, &server, 1, 64 << 10).await;
    transfer(&server, &client, 1, 64 << 10).await;
    client.close(0u32.into(), b"").await;
}

/// A fallback decision hands the request to the fallback handler with
/// every body byte, those read for the decision first; without a handler
/// it is answered with 404.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_fallback_request_reaches_the_handler_with_its_whole_body() {
    let admission = || zmux::Admission::new(32, |_, _| zmux::Verdict::Fallback);
    let (addr, _l) =
        serve_admitted(Options::default().with_fallback(echo()), Some(admission())).await;
    let resp = post(&addr, "/zmux", fixed(BODY)).await.unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(read_all(resp).await, BODY);
    // Other paths go to the handler as well.
    let resp = post(&addr, "/other", fixed(BODY)).await.unwrap();
    assert_eq!(read_all(resp).await, BODY);

    let (addr, _l) = serve_admitted(Options::default(), Some(admission())).await;
    let resp = post(&addr, "/zmux", fixed(BODY)).await.unwrap();
    assert_eq!(resp.status(), 404);
}

/// A stall answers nothing: the request ends without a response once the
/// stall is over, and a close at once.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_stalled_or_closed_request_gets_no_response() {
    for (verdict, at_least) in [
        (zmux::Verdict::Stall, Duration::from_millis(300)),
        (zmux::Verdict::Close, Duration::ZERO),
    ] {
        let v = verdict.clone();
        let admission = zmux::Admission::new(32, move |_, _| v.clone())
            .with_stall_interval(Duration::from_millis(300), Duration::from_millis(400));
        let (addr, _l) =
            serve_admitted(Options::default().with_fallback(echo()), Some(admission)).await;
        // A body that does not end: the stall lasts its drawn duration.
        let (_ours, theirs) = tokio::io::duplex(1024);
        let body = StreamBody(tokio::io::AsyncReadExt::chain(BODY, theirs));
        let start = tokio::time::Instant::now();
        let r = tokio::time::timeout(Duration::from_secs(5), post(&addr, "/zmux", body))
            .await
            .expect("ended in time");
        assert!(
            r.is_err(),
            "{verdict:?}: answered {:?}",
            r.map(|r| r.status())
        );
        assert!(start.elapsed() >= at_least, "{verdict:?}: ended early");
    }
}

/// Without an admission, a request the listener does not take, nothing
/// written, goes to the fallback handler without its body, and is
/// answered with 404 without a handler.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_request_the_listener_does_not_take_falls_back() {
    let (addr, _l) = server_with(Options::default().with_fallback(echo())).await;
    let resp = post(&addr, "/zmux", fixed(BODY)).await.unwrap();
    assert_eq!(resp.status(), 200);
    assert!(read_all(resp).await.is_empty());

    let (addr, l) = server_with(Options::default()).await;
    let resp = post(&addr, "/zmux", fixed(BODY)).await.unwrap();
    assert_eq!(resp.status(), 404);
    assert_eq!(l.stats().rejected, 1);
}

/// A client with a prefix authentication credential writes an unbound
/// token first on its request body, which the server's admission accepts;
/// tokens that bind TLS are refused by the client, which has no exporter.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_client_writes_its_token_first_on_the_request_body() {
    let auth = zmux::PrefixAuth::new(b"psk", Duration::from_secs(30), false).unwrap();
    let verifier = Arc::new(zmux::PrefixAuthVerifier::new(auth.clone(), 1, 1024));
    let admission = zmux::Admission::prefix_auth(verifier);
    let (addr, listener) = serve_admitted(Options::default(), Some(admission)).await;
    let client_opts = Options::default().with_credential(Arc::new(auth));
    for client in [
        zmux_http::connect_http1(&addr, &client_opts, Config::default())
            .await
            .unwrap(),
        zmux_http::connect_http2(&addr, &client_opts, Config::default())
            .await
            .unwrap(),
    ] {
        let server = listener.accept().await.unwrap();
        transfer(&client, &server, 1, 64 << 10).await;
        transfer(&server, &client, 1, 64 << 10).await;
        client.close(0u32.into(), b"").await;
    }
    let bound = zmux::PrefixAuth::new(b"psk", Duration::from_secs(30), true).unwrap();
    let e = zmux_http::dial_http1(&addr, &Options::default().with_credential(Arc::new(bound)))
        .await
        .unwrap_err();
    assert_eq!(e.kind(), std::io::ErrorKind::InvalidInput);
}

/// Pipe 0 of each session is of carrier kind `kind`.
fn assert_kind(sessions: [&Session; 2], kind: zmux::CarrierKind) {
    for s in sessions {
        let p = s.pipe(zmux::PipeId::new(0)).unwrap();
        assert_eq!(p.stats().unwrap().carrier, Some(kind));
    }
}
