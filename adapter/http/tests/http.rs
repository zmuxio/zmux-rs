//! HTTP exchanges as pipes over loopback: a session over HTTP/1.1 and over
//! HTTP/2, both bodies of one exchange carrying the two directions, two
//! pipes on one HTTP/2 connection with lanes only when turned on, and a
//! cut connection seen as a failure, never a clean end.

mod support;

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
                assert!(
                    data.iter()
                        .enumerate()
                        .all(|(i, &b)| b == u8::try_from(i % 251).unwrap())
                );
            }
        })
    };
    let data = bytes::Bytes::from(
        (0..len)
            .map(|i| u8::try_from(i % 251).unwrap())
            .collect::<Vec<_>>(),
    );
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
    let Ok(outcome) = tokio::time::timeout(Duration::from_secs(20), receiver).await else {
        // A stalled transfer: leave the state of both ends in the log.
        for (side, s) in [("sender", from), ("receiver", to)] {
            eprintln!("{side} session: {:?}", s.stats());
            for p in s.pipes() {
                eprintln!("{side} pipe: {:?}", p.stats());
            }
        }
        panic!("transfer of {n} x {len} bytes did not finish in time");
    };
    outcome.unwrap();
}

/// Both directions, then a close the peer sees.
async fn round_trip_and_close(client: Session, server: Session) {
    transfer(&client, &server, 2, 256 << 10).await;
    transfer(&server, &client, 2, 256 << 10).await;
    client.close().await;
    let e = tokio::time::timeout(Duration::from_secs(5), server.closing())
        .await
        .expect("closed");
    assert!(
        matches!(e, SessionError::ApplicationClosed { remote: true, .. }),
        "{e:?}"
    );
}

#[test]
fn a_session_over_http1() {
    support::run(2, 90, || async {
        let (addr, listener, serving) = server(Config::default()).await;
        let client = zmux_http::connect_http1(&addr, &Options::default(), Config::default())
            .await
            .unwrap();
        let server = listener.accept().await.unwrap();
        assert_kind([&client, &server], zmux::CarrierKind::Streaming);
        round_trip_and_close(client, server).await;
        listener.close();
        serving.await.unwrap();
    });
}

#[test]
fn a_session_over_http2() {
    support::run(2, 90, || async {
        let (addr, listener, serving) = server(Config::default()).await;
        let client = zmux_http::connect_http2(&addr, &Options::default(), Config::default())
            .await
            .unwrap();
        let server = listener.accept().await.unwrap();
        round_trip_and_close(client, server).await;
        listener.close();
        serving.await.unwrap();
    });
}

/// Body pairing: one HTTP/1.1 exchange carries the whole session, its
/// request body one direction and its response body the other, through a
/// server of the application's own that routes the request to
/// `handle_request`.
#[test]
fn one_exchange_carries_both_directions() {
    support::run(2, 90, || async {
        let mut limits = ListenerConfig::default();
        limits.admission = Some(zmux::Admission::new(0, |_, _| {
            zmux::AdmissionVerdict::accept(0)
        }));
        let listener = Listener::new(Config::default(), limits).unwrap();
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
                        zmux_http::handle_request(
                            &listener,
                            req,
                            Some(peer),
                            None,
                            &zmux_http::PairField::default(),
                        )
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
        listener.close();
        transfer(&client, &server, 1, 1 << 20).await;
        transfer(&server, &client, 1, 1 << 20).await;
        assert_eq!(requests.load(Ordering::SeqCst), 1, "one exchange");
        client.close().await;
    });
}

fn multipath() -> Config {
    Config::multipath(PipeAuth::psk(*b"zmux-http-test-psk-0123456789abc").with_end_to_end())
}

/// HTTP/2: two pipes of a multipath session on one connection (the join
/// over the second exchange is accepted), and lanes on further requests of
/// the connection only when turned on.
#[test]
fn http2_pipes_share_a_connection_and_lanes_only_when_enabled() {
    support::run(2, 90, || async {
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
            client.close().await;
        }
        listener.close();
        serving.await.unwrap();
    });
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
#[test]
fn a_cut_connection_is_a_failure_not_a_clean_end() {
    support::run(2, 90, || async {
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
                    "http2={http2}: {e:?}"
                );
            }
        }
        listener.close();
        serving.await.unwrap();
    });
}

/// TLS configurations whose ALPN offers `h2` and `http/1.1` (the client
/// offers only `client_alpn`).
fn tls(
    client_alpn: &[u8],
) -> (
    tokio_rustls::TlsConnector,
    tokio_rustls::TlsAcceptor,
    rustls::pki_types::ServerName<'static>,
) {
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let name = std::net::Ipv4Addr::LOCALHOST;
    let cert = zmux_testcert::self_signed(vec![name.to_string()]).unwrap();
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
        std::net::IpAddr::V4(name).into(),
    )
}

/// HTTPS: sessions over HTTP/2 and HTTP/1.1 on TLS connections the
/// application made, served by `serve_with` with a TLS setup step; a
/// connection whose TLS handshake fails is counted, not silently dropped.
#[test]
// HS-08
fn sessions_over_tls_and_a_failed_handshake_is_counted() {
    support::run(2, 90, || async {
        for alpn in [&b"h2"[..], b"http/1.1"] {
            let (connector, acceptor, name) = tls(alpn);
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
                .await;
            });
            // Not TLS at all: a setup failure.
            let mut plain = TcpStream::connect(addr).await.unwrap();
            tokio::io::AsyncWriteExt::write_all(&mut plain, b"GET / HTTP/1.1\r\n\r\n")
                .await
                .unwrap();
            // The rejected connection ends before the next handshake starts.
            let _ = tokio::io::AsyncReadExt::read_to_end(&mut plain, &mut Vec::new()).await;
            let conn = connector
                .connect(name, TcpStream::connect(addr).await.unwrap())
                .await
                .unwrap();
            assert_eq!(conn.get_ref().1.alpn_protocol(), Some(alpn));
            let client = if alpn == b"h2" {
                Box::pin(Http2Connection::handshake(
                    conn,
                    "localhost",
                    Options::default(),
                ))
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

            let stats = listener.stats();
            assert_eq!((stats.sessions, stats.setup_failures), (1, 1), "{stats:?}");
            listener.close();
            serving.await.unwrap();
        }
    });
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
#[derive(Debug)]
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

#[tokio::test]
// HS-05
async fn dropping_a_post_response_releases_pending_transform() {
    use tokio::io::AsyncReadExt;
    let entered = Arc::new(tokio::sync::Notify::new());
    let gate = entered.clone();
    let mut limits = ListenerConfig::default();
    limits.admission = Some(zmux::Admission::new(0, |_, _| {
        zmux::AdmissionVerdict::accept(0)
    }));
    limits.handshake_timeout = Duration::from_secs(60);
    limits.limits.max_pending = Some(1);
    limits.inbound_transform = Some(zmux::InboundTransform::new(
        move |io, _: &zmux::PipeHint| {
            let gate = gate.clone();
            async move {
                gate.notify_one();
                std::future::pending::<()>().await;
                Ok(io)
            }
        },
    ));
    let listener = Listener::new(Config::default(), limits).unwrap();
    let (mut peer, body) = tokio::io::duplex(4096);
    let request = http::Request::post("/")
        .version(http::Version::HTTP_2)
        .body(StreamBody(body))
        .unwrap();
    let response = zmux_http::handle_request(
        &listener,
        request,
        None,
        None,
        &zmux_http::PairField::default(),
    )
    .await
    .ok()
    .unwrap();
    entered.notified().await;
    let peer_addr = (std::net::Ipv4Addr::LOCALHOST, 0).into();
    assert!(listener.adapter().enter(peer_addr, None).is_none());
    drop(response.into_body());
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(2), peer.read(&mut [0]))
            .await
            .unwrap()
            .unwrap(),
        0
    );
    assert_eq!(listener.stats().sessions, 0);
    assert!(listener.adapter().enter(peer_addr, None).is_some());
}

#[derive(Clone, Copy)]
enum ResetTransport {
    Tcp,
    Tls,
    BoundTls,
}

// HS-05. Backpressure above the setup replay limit must not hide a TCP reset.
#[tokio::test]
async fn a_backpressured_tcp_request_observes_transport_reset() {
    backpressured_request_observes_transport_reset(ResetTransport::Tcp).await;
}

#[tokio::test]
async fn a_backpressured_tls_request_observes_transport_reset() {
    backpressured_request_observes_transport_reset(ResetTransport::Tls).await;
}

#[tokio::test]
async fn a_backpressured_bound_tls_request_observes_transport_reset() {
    backpressured_request_observes_transport_reset(ResetTransport::BoundTls).await;
}

async fn backpressured_request_observes_transport_reset(transport: ResetTransport) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn upload<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
        mut peer: T,
        address: std::net::SocketAddr,
    ) -> T {
        peer.write_all(
            format!("POST /zmux HTTP/1.1\r\nHost: {address}\r\nTransfer-Encoding: chunked\r\n\r\n40000\r\n").as_bytes(),
        )
        .await
        .unwrap();
        peer.write_all(&vec![0; 128 * 1024]).await.unwrap();
        peer.flush().await.unwrap();
        let mut byte = [0];
        let mut head = Vec::new();
        while !head.ends_with(b"\r\n\r\n") {
            peer.read_exact(&mut byte).await.unwrap();
            head.push(byte[0]);
        }
        assert!(head.starts_with(b"HTTP/1.1 200 "));
        peer
    }

    tokio::time::timeout(Duration::from_secs(5), async {
        let (started, mut entered) = tokio::sync::mpsc::unbounded_channel();
        let mut limits = ListenerConfig::default();
        limits.admission = Some(zmux::Admission::new(0, |_, _| {
            zmux::AdmissionVerdict::accept(0)
        }));
        limits.handshake_timeout = Duration::from_secs(60);
        limits.inbound_transform = Some(zmux::InboundTransform::new(
            move |io, _: &zmux::PipeHint| {
                let (worker, exited) = tokio::sync::oneshot::channel::<()>();
                started.send(exited).unwrap();
                async move {
                    std::future::pending::<()>().await;
                    drop(worker);
                    Ok(io)
                }
            },
        ));
        let listener = Listener::new(Config::default(), limits).unwrap();
        let server = listener.clone();
        let tcp = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let address = tcp.local_addr().unwrap();
        let peer = TcpStream::connect(address).await.unwrap();
        peer.set_zero_linger().unwrap();
        let (sock, addr) = tcp.accept().await.unwrap();
        let (connector, acceptor, name) = tls(b"http/1.1");
        let serving = tokio::spawn(async move {
            let endpoint = zmux_http::Endpoint::new(server, Options::default());
            match transport {
                ResetTransport::Tcp => endpoint.serve_connection(sock, Some(addr)).await,
                ResetTransport::Tls => {
                    endpoint
                        .serve_connection(acceptor.accept(sock).await.unwrap(), Some(addr))
                        .await;
                }
                ResetTransport::BoundTls => {
                    let stream =
                        zmux_rustls::TlsConnection::new(acceptor.accept(sock).await.unwrap());
                    endpoint.serve_connection(stream, Some(addr)).await;
                }
            }
        });
        let exited = if matches!(transport, ResetTransport::Tcp) {
            let peer = upload(peer, address).await;
            let exited = entered.recv().await.unwrap();
            drop(peer);
            exited
        } else {
            let peer = upload(connector.connect(name, peer).await.unwrap(), address).await;
            let exited = entered.recv().await.unwrap();
            drop(peer);
            exited
        };
        assert!(exited.await.is_err());
        serving.await.unwrap();
        assert_eq!(listener.stats().sessions, 0);
    })
    .await
    .expect("the reset ends setup before its handshake deadline");
}

#[tokio::test]
// HS-02
async fn response_drop_after_accept_leaves_the_session_in_charge() {
    use bytes::Buf;
    use http_body::Body;
    use std::future::poll_fn;
    use tokio::io::AsyncWriteExt;
    let mut limits = ListenerConfig::default();
    limits.admission = Some(zmux::Admission::new(0, |_, _| {
        zmux::AdmissionVerdict::accept(0)
    }));
    let listener = Listener::new(multipath(), limits).unwrap();
    let (near, far) = tokio::io::duplex(1 << 16);
    let (up, mut down) = tokio::io::split(far);
    let request = http::Request::post("/")
        .version(http::Version::HTTP_2)
        .body(StreamBody(up))
        .unwrap();
    let mut response = zmux_http::handle_request(
        &listener,
        request,
        None,
        None,
        &zmux_http::PairField::default(),
    )
    .await
    .ok()
    .unwrap()
    .into_body();
    let (stop, mut stopped) = tokio::sync::oneshot::channel();
    let relay = tokio::spawn(async move {
        loop {
            let frame = tokio::select! {
                _ = &mut stopped => break,
                f = poll_fn(|cx| Pin::new(&mut response).poll_frame(cx)) => f,
            };
            let Some(Ok(frame)) = frame else { break };
            if let Ok(mut chunks) = frame.into_data() {
                let data = chunks.copy_to_bytes(chunks.remaining());
                down.write_all(&data).await.unwrap();
            }
        }
    });
    let client = Session::connect(zmux::PipeIo::new(near), multipath())
        .await
        .unwrap();
    let server = listener.accept().await.unwrap();
    let (a, b) = tokio::io::duplex(1 << 16);
    let (added, handled) = tokio::join!(
        client.add_pipe(zmux::PipeIo::new(a), PipeOptions::default()),
        listener.handle_pipe(zmux::PipeIo::new(b), zmux::PipeHint::default())
    );
    added.unwrap();
    handled.unwrap();
    listener.close();
    stop.send(()).unwrap();
    relay.await.unwrap();
    transfer(&client, &server, 1, 4096).await;
    server.close().await;
    client.closed().await;
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
fn echo() -> zmux_http::Fallback {
    zmux_http::Fallback::new(|req: zmux_http::FallbackRequest, _| async move {
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
#[test]
fn an_admitted_request_carries_a_session() {
    support::run(2, 90, || async {
        let auth = zmux::PrefixAuth::new(b"psk", Duration::from_secs(30), false).unwrap();
        let verifier = Arc::new(zmux::PrefixAuthVerifier::new(auth.clone(), 1, 1024).unwrap());
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
        let io =
            zmux::PipeIo::from_halves(IncomingReader(resp.into_body(), bytes::Bytes::new()), ours);
        let client = Session::connect(io, Config::default()).await.unwrap();
        let server = listener.accept().await.unwrap();
        transfer(&client, &server, 1, 64 << 10).await;
        transfer(&server, &client, 1, 64 << 10).await;
        client.close().await;
    });
}

/// A fallback decision hands the request to the fallback handler with
/// every body byte, those read for the decision first; without a handler
/// it is answered with 404.
#[test]
fn a_fallback_request_reaches_the_handler_with_its_whole_body() {
    support::run(2, 90, || async {
        let admission = || zmux::Admission::new(32, |_, _| zmux::AdmissionVerdict::fallback());
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
    });
}

#[test]
fn an_http_fallback_panic_ends_only_its_request() {
    support::run(2, 20, || async {
        let fallback = zmux_http::Fallback::new(|request, _| {
            let path = request.uri().path().to_owned();
            assert_ne!(path, "/call");
            async move {
                assert_ne!(path, "/poll");
                http::Response::new(zmux_http::PipeBody::empty())
            }
        });
        let (addr, _listener) = server_with(Options::default().with_fallback(fallback)).await;
        for (path, expected) in [("/call", 500), ("/poll", 500), ("/ok", 200)] {
            assert_eq!(
                post(&addr, path, fixed(BODY)).await.unwrap().status(),
                expected
            );
        }
    });
}

/// A stall answers nothing: the request ends without a response once the
/// stall is over, and a close at once.
#[test]
fn a_stalled_or_closed_request_gets_no_response() {
    support::run(2, 90, || async {
        for (verdict, at_least) in [
            (zmux::AdmissionVerdict::Stall, Duration::from_millis(300)),
            (zmux::AdmissionVerdict::Close, Duration::ZERO),
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
    });
}

/// An HTTP request carrier whose prefix is late is closed without a
/// response, even where the admission takes late byte streams to the
/// fallback.
#[test]
fn a_late_prefix_on_a_request_is_closed() {
    support::run(2, 90, || async {
        let admission =
            zmux::Admission::new(32, |_, _| -> zmux::AdmissionVerdict { panic!("decided") })
                .with_peek_timeout(Duration::from_millis(100))
                .with_fallback_on_peek_timeout(true);
        let (addr, l) =
            serve_admitted(Options::default().with_fallback(echo()), Some(admission)).await;
        // Four bytes of 32, then a body that does not end.
        let (_ours, theirs) = tokio::io::duplex(1024);
        let body = StreamBody(tokio::io::AsyncReadExt::chain(&BODY[..4], theirs));
        let r = tokio::time::timeout(Duration::from_secs(5), post(&addr, "/zmux", body))
            .await
            .expect("ended in time");
        assert!(r.is_err(), "answered {:?}", r.map(|r| r.status()));
        let a = l.stats().admission;
        assert_eq!((a.peek_timed_out, a.fallback), (1, 0));
    });
}

/// Without an admission, a request the listener does not take, nothing
/// written, goes to the fallback handler without its body, and is
/// answered with 404 without a handler.
#[test]
fn a_request_the_listener_does_not_take_falls_back() {
    support::run(2, 90, || async {
        let (addr, _l) = server_with(Options::default().with_fallback(echo())).await;
        let resp = post(&addr, "/zmux", fixed(BODY)).await.unwrap();
        assert_eq!(resp.status(), 200);
        assert_eq!(read_all(resp).await, Vec::<u8>::new());

        let (addr, l) = server_with(Options::default()).await;
        let resp = post(&addr, "/zmux", fixed(BODY)).await.unwrap();
        assert_eq!(resp.status(), 404);
        assert_eq!(l.stats().rejected, 1);
    });
}

/// A client with a prefix authentication credential writes an unbound
/// token first on its request body, which the server's admission accepts;
/// tokens that bind TLS are refused by the client, which has no exporter.
#[test]
fn a_client_writes_its_token_first_on_the_request_body() {
    support::run(2, 90, || async {
        let auth = zmux::PrefixAuth::new(b"psk", Duration::from_secs(30), false).unwrap();
        let verifier = Arc::new(zmux::PrefixAuthVerifier::new(auth.clone(), 1, 1024).unwrap());
        let admission = zmux::Admission::prefix_auth(verifier);
        let (addr, listener) = serve_admitted(Options::default(), Some(admission)).await;
        let client_opts = Options::default().with_carrier_credential(Arc::new(auth));
        for http2 in [false, true] {
            // The listener queues sessions independently of when clients connect.
            // Dial only one at a time so accept returns that client's peer.
            let client = if http2 {
                zmux_http::connect_http2(&addr, &client_opts, Config::default()).await
            } else {
                zmux_http::connect_http1(&addr, &client_opts, Config::default()).await
            }
            .unwrap();
            let server = listener.accept().await.unwrap();
            transfer(&client, &server, 1, 64 << 10).await;
            transfer(&server, &client, 1, 64 << 10).await;
            client.close().await;
        }
        let bound = zmux::PrefixAuth::new(b"psk", Duration::from_secs(30), true).unwrap();
        let e = zmux_http::dial_http1(
            &addr,
            &Options::default().with_carrier_credential(Arc::new(bound)),
        )
        .await
        .unwrap_err();
        assert_eq!(e.kind(), std::io::ErrorKind::InvalidInput);
    });
}

/// Pipe 0 of each session is of carrier kind `kind`.
fn assert_kind(sessions: [&Session; 2], kind: zmux::CarrierKind) {
    for s in sessions {
        let p = s.pipe(zmux::PipeId::new(0)).unwrap();
        assert_eq!(p.stats().unwrap().carrier, Some(kind));
    }
}

/// An HTTP/2 extended CONNECT tunnel keeps its connection in use after
/// its response: the idle timeout does not close the connection under it.
#[test]
fn an_extended_connect_tunnel_is_not_idle() {
    support::run(2, 90, || async {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut limits = ListenerConfig::default();
        limits.handshake_timeout = Duration::from_millis(200);
        let listener = Listener::new(Config::default(), limits).unwrap();
        let options = Options::default().with_idle_timeout(Some(Duration::from_millis(100)));
        let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = tcp.local_addr().unwrap();
        let l = listener.clone();
        tokio::spawn(async move {
            let (conn, peer) = tcp.accept().await.unwrap();
            zmux_http::serve_connection_with(
                &l,
                conn,
                Some(peer),
                &options,
                |mut req, _, _| async move {
                    let up = hyper::upgrade::on(&mut req);
                    tokio::spawn(async move {
                        // An echo over the tunnel.
                        let mut io = hyper_util::rt::TokioIo::new(up.await.unwrap());
                        let mut b = [0u8; 64];
                        while let Ok(n @ 1..) = io.read(&mut b).await {
                            io.write_all(&b[..n]).await.unwrap();
                        }
                    });
                    Ok(http::Response::new(zmux_http::PipeBody::empty()))
                },
            )
            .await;
        });
        let tcp = TcpStream::connect(addr).await.unwrap();
        let (mut sender, conn) = hyper::client::conn::http2::handshake(
            hyper_util::rt::TokioExecutor::new(),
            hyper_util::rt::TokioIo::new(tcp),
        )
        .await
        .unwrap();
        let conn = tokio::spawn(conn);
        let mut req = http::Request::connect(format!("http://{addr}/ws"))
            .body(zmux_http::PipeBody::empty())
            .unwrap();
        req.extensions_mut()
            .insert(hyper::ext::Protocol::from_static("websocket"));
        let mut resp = sender.send_request(req).await.unwrap();
        assert!(resp.status().is_success());
        let mut io = hyper_util::rt::TokioIo::new(hyper::upgrade::on(&mut resp).await.unwrap());
        // Past the idle timeout and the close's own limit, many times over.
        for round in 0..4u8 {
            tokio::time::sleep(Duration::from_millis(250)).await;
            io.write_all(&[round; 3]).await.unwrap();
            let mut b = [0u8; 3];
            io.read_exact(&mut b).await.unwrap();
            assert_eq!(b, [round; 3]);
        }
        assert!(!conn.is_finished());
    });
}

/// A connection that served a request is closed once it has been idle
/// for the idle timeout, also on HTTP/2, which has no idle timeout of its
/// own; a request in progress keeps it open.
#[test]
fn an_idle_connection_is_closed_after_it_was_used() {
    support::run(2, 90, || async {
        let options = Options::default()
            .with_fallback(echo())
            .with_idle_timeout(Some(Duration::from_millis(300)));
        let (addr, _l) = server_with(options).await;
        let tcp = TcpStream::connect(&addr).await.unwrap();
        let (mut sender, conn) = hyper::client::conn::http2::handshake(
            hyper_util::rt::TokioExecutor::new(),
            hyper_util::rt::TokioIo::new(tcp),
        )
        .await
        .unwrap();
        let conn = tokio::spawn(conn);
        // A request whose body is still arriving is in progress past the
        // idle timeout.
        let (mut w, r) = tokio::io::duplex(64);
        let req = http::Request::post(format!("http://{addr}/other"))
            .body(StreamBody(r))
            .unwrap();
        let pending = sender.send_request(req);
        let late = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(600)).await;
            tokio::io::AsyncWriteExt::write_all(&mut w, BODY)
                .await
                .unwrap();
        });
        let resp = pending.await.unwrap();
        late.await.unwrap();
        assert_eq!(read_all(resp).await, BODY);
        assert!(!conn.is_finished());
        // Then idle: the server closes the connection.
        tokio::time::timeout(Duration::from_secs(5), conn)
            .await
            .expect("the idle connection is closed")
            .unwrap()
            .unwrap();
    });
}

/// One POST to `path` of `addr` with `body` over HTTP/2 (prior knowledge).
async fn post2<B>(
    addr: &str,
    path: &str,
    body: B,
) -> hyper::Result<http::Response<hyper::body::Incoming>>
where
    B: http_body::Body<Data = bytes::Bytes> + Send + Unpin + 'static,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    let tcp = TcpStream::connect(addr).await.unwrap();
    let (mut sender, conn) = hyper::client::conn::http2::handshake(
        hyper_util::rt::TokioExecutor::new(),
        hyper_util::rt::TokioIo::new(tcp),
    )
    .await?;
    tokio::spawn(conn);
    let req = http::Request::post(format!("http://{addr}{path}"))
        .body(body)
        .unwrap();
    sender.send_request(req).await
}

/// On the same listener HTTP Fallback replays the request to its HTTP
/// handler (404 without one). Takeover delivers the carrier, answered 200 by
/// zmux, its pipe the request body (the decided bytes replayed) and the
/// response body, full duplex, over HTTP/1.1 and HTTP/2. The host detaches
/// it and serves it after the fallback's future; it ends the response
/// first (half-close) and reads the request body on to its end.
#[test]
// HS-13, HS-15, HS-19
fn http_fallback_and_takeover_use_their_own_targets() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    support::run(2, 90, || async {
        for h2 in [false, true] {
            let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
            let fallback = zmux::Fallback::new(move |t: zmux::Takeover| {
                let tx = tx.clone();
                async move {
                    assert_eq!(t.info().stage, zmux::AdmissionStage::Carrier);
                    let value = t.value().and_then(|v| v.downcast_ref::<&str>()).copied();
                    t.detach().unwrap();
                    let mut s = t.into_pipe().into_stream();
                    tokio::spawn(async move {
                        let mut head = [0; 8];
                        s.read_exact(&mut head).await.unwrap();
                        s.write_all(b"pong").await.unwrap();
                        // The response ends; the request body reads on.
                        s.shutdown().await.unwrap();
                        let mut rest = Vec::new();
                        s.read_to_end(&mut rest).await.unwrap();
                        let _ = tx.send((value, head.to_vec(), rest));
                    });
                }
            });
            let admission = zmux::Admission::new(4, |_, p: &[u8]| {
                let verdict = if p == b"HELO" {
                    zmux::AdmissionVerdict::takeover().with_value(Arc::new("echo"))
                } else if p == b"0123" {
                    zmux::AdmissionVerdict::fallback()
                } else {
                    zmux::AdmissionVerdict::Close
                };
                verdict.labelled("route")
            });
            let mut limits = ListenerConfig::default();
            limits.admission = Some(admission);
            limits.fallback = Some(fallback);
            let listener = Listener::new(Config::default(), limits).unwrap();
            let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = tcp.local_addr().unwrap().to_string();
            let fallback_calls = Arc::new(AtomicUsize::new(0));
            let calls = fallback_calls.clone();
            let http_handler = zmux_http::Fallback::new(move |req, _| {
                calls.fetch_add(1, Ordering::SeqCst);
                async move {
                    http::Response::builder()
                        .status(201)
                        .body(zmux_http::PipeBody::full(collect(req.into_body()).await))
                        .unwrap()
                }
            });
            tokio::spawn(zmux_http::serve(
                listener.clone(),
                tcp,
                Options::default().with_fallback(http_handler),
            ));
            let request = |addr: String| async move {
                if h2 {
                    post2(&addr, "/zmux", fixed(BODY)).await
                } else {
                    post(&addr, "/zmux", fixed(BODY)).await
                }
            };
            let resp = request(addr.clone()).await.unwrap();
            assert_eq!(resp.status(), 201);
            assert_eq!(read_all(resp).await, BODY);
            assert!(rx.try_recv().is_err());
            let no_handler = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
                .await
                .unwrap();
            let missing = no_handler.local_addr().unwrap().to_string();
            tokio::spawn(zmux_http::serve(
                listener.clone(),
                no_handler,
                Options::default(),
            ));
            assert_eq!(request(missing).await.unwrap().status(), 404);
            let (mut ours, theirs) = tokio::io::duplex(1024);
            ours.write_all(b"HELOping").await.unwrap();
            let resp = tokio::time::timeout(Duration::from_secs(5), async {
                if h2 {
                    post2(&addr, "/zmux", StreamBody(theirs)).await
                } else {
                    post(&addr, "/zmux", StreamBody(theirs)).await
                }
            })
            .await
            .expect("answered")
            .unwrap();
            assert_eq!(resp.status(), 200, "h2 {h2}");
            // The response ends before the request does.
            let got = tokio::time::timeout(Duration::from_secs(5), read_all(resp))
                .await
                .expect("the response ended");
            assert_eq!(got, b"pong", "h2 {h2}");
            ours.write_all(b"tail").await.unwrap();
            drop(ours);
            let (value, head, tail) = tokio::time::timeout(Duration::from_secs(5), rx.recv())
                .await
                .expect("the host read the request to its end")
                .unwrap();
            assert_eq!(
                (value, &head[..], &tail[..]),
                (Some("echo"), &b"HELOping"[..], &b"tail"[..]),
                "h2 {h2}"
            );
            let a = listener.stats().admission;
            assert_eq!(
                (a.takeover, a.fallback, a.stalled, a.accepted),
                (1, 1, 1, 0)
            );
            let v = listener.variant_stats().variants["route"];
            assert_eq!(
                (v.takeover, v.fallback, v.stalled, v.accepted),
                (1, 1, 1, 0)
            );
            assert_eq!(fallback_calls.load(Ordering::SeqCst), 1);
            assert!(rx.try_recv().is_err());
            listener.close();
        }
    });
}

/// A request carrier taken over and not detached is closed with the
/// fallback's future, wherever the host keeps its pipe: the response it
/// did not end is reset (the client sees a failure, not an end), over
/// HTTP/1.1 and HTTP/2.
#[test]
fn an_undetached_request_carrier_is_reset_when_the_fallback_returns() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    support::run(2, 90, || async {
        for h2 in [false, true] {
            let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
            // The client has the response head: the future may return.
            let (go_tx, go) = tokio::sync::oneshot::channel::<()>();
            let go = std::sync::Mutex::new(Some(go));
            let fallback = zmux::Fallback::new(move |t: zmux::Takeover| {
                let tx = tx.clone();
                let go = go.lock().unwrap().take();
                async move {
                    let mut s = t.into_pipe().into_stream();
                    let mut head = [0; 4];
                    s.read_exact(&mut head).await.unwrap();
                    s.write_all(b"pong").await.unwrap();
                    s.flush().await.unwrap();
                    // Kept past the future, never ended.
                    let _ = tx.send(s);
                    let _ = go.unwrap().await;
                }
            });
            let admission =
                zmux::Admission::new(4, |_, _: &[u8]| zmux::AdmissionVerdict::takeover());
            let mut limits = ListenerConfig::default();
            limits.admission = Some(admission);
            limits.fallback = Some(fallback);
            let listener = Listener::new(Config::default(), limits).unwrap();
            let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = tcp.local_addr().unwrap().to_string();
            tokio::spawn(zmux_http::serve(listener.clone(), tcp, Options::default()));
            let (mut ours, theirs) = tokio::io::duplex(1024);
            ours.write_all(b"HELO").await.unwrap();
            let resp = tokio::time::timeout(Duration::from_secs(5), async {
                if h2 {
                    post2(&addr, "/zmux", StreamBody(theirs)).await
                } else {
                    post(&addr, "/zmux", StreamBody(theirs)).await
                }
            })
            .await
            .expect("answered")
            .unwrap();
            assert_eq!(resp.status(), 200, "h2 {h2}");
            go_tx.send(()).unwrap();
            let held = tokio::time::timeout(Duration::from_secs(5), rx.recv())
                .await
                .unwrap()
                .unwrap();
            let mut r = IncomingReader(resp.into_body(), bytes::Bytes::new());
            let mut got = Vec::new();
            let end = tokio::time::timeout(Duration::from_secs(5), r.read_to_end(&mut got))
                .await
                .expect("the response ended");
            assert!(end.is_err(), "reset, not ended: h2 {h2}, {got:?}");
            drop(held);
            drop(ours);
        }
    });
}

#[tokio::test]
async fn http2_lane_response_ends_with_its_attachment() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::sync::oneshot;
    for hold_head in [true, false] {
        let listener = Listener::new(multipath(), ListenerConfig::default()).unwrap();
        let tcp = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let addr = tcp.local_addr().unwrap();
        let (entered, seen) = oneshot::channel();
        let (release, gate) = tokio::io::duplex(16);
        let (lifetime, ended) = oneshot::channel::<()>();
        let gate = Arc::new(std::sync::Mutex::new(Some((entered, gate, lifetime))));
        let l = listener.clone();
        let service = tokio::spawn(async move {
            let (io, peer) = tcp.accept().await.unwrap();
            let route = l.clone();
            let requests = AtomicUsize::new(0);
            zmux_http::serve_connection_with(
                &l,
                io,
                Some(peer),
                &Options::default(),
                move |req, peer, conn| {
                    let gate = (requests.fetch_add(1, Ordering::Relaxed) == 1)
                        .then(|| gate.lock().unwrap().take().unwrap());
                    let l = route.clone();
                    async move {
                        let response = zmux_http::route_request(
                            &l,
                            req,
                            peer,
                            Some(conn),
                            &Options::default(),
                        )
                        .await?;
                        if let Some((entered, mut gate, lifetime)) = gate {
                            entered.send(()).unwrap();
                            if hold_head {
                                let _lifetime = lifetime;
                                let _ = tokio::io::AsyncReadExt::read(&mut gate, &mut [0]).await;
                            } else {
                                // Keep the routed body alive while its response FIN is gated.
                                let (parts, original) = response.into_parts();
                                let stream = StreamBody(GatedBody {
                                    stream: gate,
                                    _original: original,
                                    _lifetime: lifetime,
                                });
                                return Ok(http::Response::from_parts(
                                    parts,
                                    zmux_http::PipeBody::new(stream),
                                ));
                            }
                        }
                        Ok(response)
                    }
                },
            )
            .await;
        });
        let conn = Http2Connection::connect(&addr.to_string(), Options::default().with_lanes(true))
            .await
            .unwrap();
        let client = conn.connect_session(multipath()).await.unwrap();
        let server = listener.accept().await.unwrap();
        let pipe = client.pipe(zmux::PipeId::new(0)).unwrap();
        tokio::time::timeout(
            Duration::from_secs(8),
            transfer(&client, &server, 4, 512 << 10),
        )
        .await
        .unwrap();
        seen.await.unwrap();
        if hold_head {
            pipe.abort().unwrap();
        } else {
            client.close().await;
            client.closed().await;
            let pending = std::pin::pin!(pipe.closed())
                .as_mut()
                .poll(&mut std::task::Context::from_waker(std::task::Waker::noop()));
            assert!(pending.is_pending());
        }
        if !hold_head {
            drop(release);
        }
        tokio::time::timeout(Duration::from_secs(3), pipe.closed())
            .await
            .expect("attachment released")
            .ok();
        tokio::time::timeout(Duration::from_secs(3), ended)
            .await
            .expect("HTTP response dropped")
            .unwrap_err();
        service.abort();
    }
}

struct GatedBody {
    stream: tokio::io::DuplexStream,
    _original: zmux_http::PipeBody,
    _lifetime: tokio::sync::oneshot::Sender<()>,
}
impl tokio::io::AsyncRead for GatedBody {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        b: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.stream).poll_read(cx, b)
    }
}

/// The final wake of an uplink HTTP response can run host code. Keep it
/// inside the attachment, including when the other half is already gone.
#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn split_completion_includes_the_empty_uplink_response() {
    use http_body::Body;
    use std::pin::{Pin, pin};
    use std::sync::{Mutex, mpsc};
    use std::task::{Context, Wake, Waker};
    use zmux::{HandleError, PipeHint, PipeId, PipeIo};

    struct ResponseWake {
        entered: tokio::sync::Notify,
        release: Mutex<mpsc::Receiver<()>>,
    }
    impl Wake for ResponseWake {
        fn wake(self: Arc<Self>) {
            self.entered.notify_one();
            self.release
                .lock()
                .unwrap()
                .recv_timeout(Duration::from_secs(5))
                .unwrap();
        }
    }

    let token = "AAECAwQFBgcICQoLDA0ODw";
    let hint = || PipeHint::default().with_pair_header(token);
    let mut config = ListenerConfig::default();
    config.admission = Some(zmux::Admission::new(0, |_, _| {
        zmux::AdmissionVerdict::accept(0)
    }));
    let listener = Listener::new(Config::default(), config).unwrap();
    let (up, up_server) = tokio::io::duplex(1 << 16);
    let (down, down_server) = tokio::io::duplex(1 << 16);
    let request = http::Request::post("/zmux")
        .version(http::Version::HTTP_2)
        .header(zmux::adapter::PAIR_HEADER, token)
        .body(StreamBody(up_server))
        .unwrap();
    let mut response = zmux_http::handle_request(
        &listener,
        request,
        None,
        None,
        &zmux_http::PairField::default(),
    )
    .await
    .ok()
    .unwrap()
    .into_body();
    let (setup, client) = tokio::join!(
        listener.handle_pipe(PipeIo::writer(down_server), hint()),
        Session::connect(PipeIo::from_halves(down, up), Config::default())
    );
    setup.unwrap();
    let _client = client.unwrap();
    let server = listener.accept().await.unwrap();
    let pipe = server.pipe(PipeId::new(0)).unwrap();
    let (release, gate) = mpsc::channel();
    let gate = Arc::new(ResponseWake {
        entered: tokio::sync::Notify::new(),
        release: Mutex::new(gate),
    });
    let waker = Waker::from(gate.clone());
    assert!(
        Pin::new(&mut response)
            .poll_frame(&mut Context::from_waker(&waker))
            .is_pending()
    );
    server.close().await;
    tokio::time::timeout(Duration::from_secs(3), gate.entered.notified())
        .await
        .unwrap();
    let mut closed = pin!(pipe.closed());
    let mut cx = Context::from_waker(Waker::noop());
    assert!(closed.as_mut().poll(&mut cx).is_pending());
    let retry = || listener.handle_pipe(PipeIo::reader(tokio::io::empty()), hint());
    assert_eq!(
        pin!(retry()).as_mut().poll(&mut cx),
        std::task::Poll::Ready(Err(HandleError::Rejected))
    );
    release.send(()).unwrap();
    let _ = closed.await;
    assert!(pin!(retry()).as_mut().poll(&mut cx).is_pending());
    assert!(matches!(
        Pin::new(&mut response).poll_frame(&mut cx),
        std::task::Poll::Ready(None)
    ));
}

/// The transport, including flush, is controlled independently of Hyper
/// accepting the service response and polling its body.
#[tokio::test]
// HS-15, HS-16, HS-19
async fn takeover_waits_for_the_accepted_response_to_flush() {
    use std::{
        io,
        pin::Pin,
        task::{Context, Poll, Waker},
    };
    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
    #[derive(Default)]
    struct Gate {
        armed: std::sync::atomic::AtomicBool,
        blocked: tokio::sync::Notify,
        result: std::sync::Mutex<(Option<bool>, Option<Waker>)>,
    }
    struct Transport(TcpStream, Arc<Gate>);
    impl AsyncRead for Transport {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            b: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.0).poll_read(cx, b)
        }
    }
    impl AsyncWrite for Transport {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            b: &[u8],
        ) -> Poll<io::Result<usize>> {
            Pin::new(&mut self.0).poll_write(cx, b)
        }
        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            if self.1.armed.load(Ordering::Acquire) {
                let mut g = self.1.result.lock().unwrap();
                match g.0 {
                    Some(true) => {}
                    Some(false) => return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())),
                    None => {
                        g.1 = Some(cx.waker().clone());
                        self.1.blocked.notify_one();
                        return Poll::Pending;
                    }
                }
            }
            Pin::new(&mut self.0).poll_flush(cx)
        }
        fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.0).poll_shutdown(cx)
        }
    }
    tokio::time::timeout(Duration::from_secs(12), async {
        #[cfg(feature = "websocket")]
        let methods = ["http1", "http2", "connect"];
        #[cfg(not(feature = "websocket"))]
        let methods = ["http1", "http2"];
        for method in methods {
            for ending in ["flushed", "failed", "stopped"] {
                let gate = Arc::new(Gate::default());
                let g = gate.clone();
                let (called, mut calls) = tokio::sync::mpsc::unbounded_channel();
                let mut limits = ListenerConfig::default();
                limits.admission = Some(zmux::Admission::new(0, move |_, _| {
                    g.armed.store(true, Ordering::Release);
                    zmux::AdmissionVerdict::takeover().labelled("relay")
                }));
                limits.fallback = Some(zmux::Fallback::new(move |_| {
                    called.send(()).unwrap();
                    async {}
                }));
                let listener = Listener::new(Config::default(), limits).unwrap();
                let tcp = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
                    .await
                    .unwrap();
                let addr = tcp.local_addr().unwrap().to_string();
                let l = listener.clone();
                let g = gate.clone();
                let serving = tokio::spawn(async move {
                    let (socket, peer) = tcp.accept().await.unwrap();
                    let endpoint = zmux_http::Endpoint::new(l, Options::default());
                    #[cfg(feature = "websocket")]
                    let endpoint = endpoint.with_websocket(zmux_websocket::Options::default());
                    endpoint
                        .serve_connection(Transport(socket, g), Some(peer))
                        .await;
                });
                let dial = tokio::spawn(async move {
                    match method {
                        "http1" => post(&addr, "/zmux", fixed(b"request")).await,
                        "http2" => post2(&addr, "/zmux", fixed(b"request")).await,
                        _ => {
                            let tcp = TcpStream::connect(&addr).await.unwrap();
                            let (mut tx, conn) = hyper::client::conn::http2::handshake(
                                hyper_util::rt::TokioExecutor::new(),
                                hyper_util::rt::TokioIo::new(tcp),
                            )
                            .await?;
                            tokio::spawn(conn);
                            let mut req = http::Request::connect(format!("http://{addr}/zmux"))
                                .header("Sec-WebSocket-Version", "13")
                                .header("Sec-WebSocket-Protocol", "qmux-02")
                                .body(zmux_http::PipeBody::empty())
                                .unwrap();
                            req.extensions_mut()
                                .insert(hyper::ext::Protocol::from_static("websocket"));
                            tx.send_request(req).await
                        }
                    }
                });
                gate.blocked.notified().await;
                assert_eq!(listener.stats().admission.takeover, 0);
                assert!(listener.variant_stats().variants.is_empty());
                assert!(calls.try_recv().is_err(), "{method} {ending}");
                if ending == "stopped" {
                    listener.close();
                }
                let waker = {
                    let mut g = gate.result.lock().unwrap();
                    g.0 = Some(ending != "failed");
                    g.1.take().unwrap()
                };
                waker.wake();
                if ending == "flushed" {
                    calls.recv().await.unwrap();
                }
                drop(dial.await.unwrap());
                serving.await.unwrap();
                assert!(calls.try_recv().is_err(), "{method} {ending}");
                let stats = listener.stats().admission;
                assert_eq!(stats.fallback, 0);
                assert_eq!(stats.takeover, u64::from(ending == "flushed"));
                let variant = listener
                    .variant_stats()
                    .variants
                    .get("relay")
                    .copied()
                    .unwrap_or_default();
                assert_eq!((variant.takeover, variant.fallback), (stats.takeover, 0));
                assert_eq!(
                    stats.takeover + stats.handshake_failed + stats.peek_timed_out + stats.closed,
                    1,
                    "{method} {ending} {stats:?}"
                );
            }
        }
    })
    .await
    .unwrap();
}

// HS-13. The last peek reaches trailers when the prefix is shorter than requested.
#[tokio::test]
// HS-13
async fn fallback_replays_body_frames_and_original_headers() {
    use http_body::{Body, Frame};
    use std::pin::Pin;
    use std::task::{Context, Poll};
    struct Frames(std::collections::VecDeque<Frame<bytes::Bytes>>);
    impl Body for Frames {
        type Data = bytes::Bytes;
        type Error = std::io::Error;
        fn poll_frame(
            mut self: Pin<&mut Self>,
            _: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
            Poll::Ready(self.0.pop_front().map(Ok))
        }
    }
    for chunked in [true, false] {
        for expect in [true, false] {
            for declare in [true, false] {
                let mut limits = ListenerConfig::default();
                limits.admission = Some(zmux::Admission::new(9, |_, _| {
                    zmux::AdmissionVerdict::fallback()
                }));
                let listener = Listener::new(Config::default(), limits).unwrap();
                let mut head = http::Request::post("/").version(http::Version::HTTP_11);
                head = if chunked {
                    head.header("transfer-encoding", "chunked")
                } else {
                    head.header("content-length", "3")
                };
                if expect {
                    head = head.header("expect", "100-continue");
                }
                if declare {
                    head = head.header("trailer", "x-tail");
                }
                let mut frames = std::collections::VecDeque::from([Frame::data(
                    bytes::Bytes::from_static(b"abc"),
                )]);
                if chunked {
                    let mut trailers = http::HeaderMap::new();
                    trailers.insert("x-tail", http::HeaderValue::from_static("visible"));
                    frames.push_back(Frame::trailers(trailers));
                }
                let req = head.body(Frames(frames)).unwrap();
                let original = req.headers().clone();
                let Err(zmux_http::Unhandled::Fallback(request)) = zmux_http::handle_request(
                    &listener,
                    req,
                    None,
                    None,
                    &zmux_http::PairField::default(),
                )
                .await
                else {
                    panic!("fallback must receive the request before a response");
                };
                assert_eq!(request.headers(), &original);
                let mut replay = request.into_body();
                let mut bytes = Vec::new();
                let mut trailers = None;
                while let Some(f) =
                    std::future::poll_fn(|cx| Pin::new(&mut replay).poll_frame(cx)).await
                {
                    match f.unwrap().into_data() {
                        Ok(d) => bytes.extend_from_slice(&d),
                        Err(frame) => trailers = frame.into_trailers().ok(),
                    }
                }
                assert_eq!(bytes, b"abc");
                assert_eq!(
                    trailers.as_ref().map(|h| &h["x-tail"]),
                    chunked.then_some(&http::HeaderValue::from_static("visible"))
                );
            }
        }
    }
}

// HS-14. A silent request body has already reached the host's Next handler.
#[tokio::test]
// HS-14
async fn closing_listener_ends_the_fallbacks_pending_body_read() {
    use tokio::io::AsyncWriteExt;
    let entered = Arc::new(tokio::sync::Notify::new());
    let ended = Arc::new(tokio::sync::Notify::new());
    let (start, done) = (entered.clone(), ended.clone());
    let options = Options::default().with_fallback(zmux_http::Fallback::new(move |req, _| {
        let (start, done) = (start.clone(), done.clone());
        async move {
            start.notify_one();
            assert_eq!(collect(req.into_body()).await, b"");
            done.notify_one();
            http::Response::new(zmux_http::PipeBody::empty())
        }
    }));
    let (addr, listener) = serve_admitted(
        options,
        Some(zmux::Admission::new(0, |_, _| {
            zmux::AdmissionVerdict::fallback()
        })),
    )
    .await;
    let mut peer = TcpStream::connect(&addr).await.unwrap();
    let head = format!("POST /zmux HTTP/1.1\r\nHost: {addr}\r\nContent-Length: 99\r\n\r\n");
    peer.write_all(head.as_bytes()).await.unwrap();
    tokio::time::timeout(Duration::from_secs(5), entered.notified())
        .await
        .unwrap();
    listener.close();
    tokio::time::timeout(Duration::from_secs(5), ended.notified())
        .await
        .unwrap();
}

#[tokio::test]
// HS-30
async fn drained_http_split_preserves_the_protocol_close() {
    let (addr, listener, serving) = server(Config::default()).await;
    listener.drain(b"emptying");
    let pipe = zmux_http::dial_http1_split(&addr, &Options::default())
        .await
        .unwrap();
    let error = match Session::connect(pipe, Config::default()).await {
        Ok(session) => session.closing().await,
        Err(zmux::ConnectError::SessionLost(e)) => e,
        Err(e) => panic!("unexpected dial error {e}"),
    };
    assert!(
        matches!(error, SessionError::TransportClosed { code, reason, remote: true, .. } if code == zmux::proto::TransportErrorCode::CONNECTION_REFUSED && reason.as_ref() == b"emptying")
    );
    listener.close();
    serving.await.unwrap();
}

// HS-16a. The foreign HTTP writer acknowledges cancellation on its own
// executor, but a transport operation it submitted has not exited yet.
#[tokio::test]
async fn cancelled_response_head_owns_its_slot_until_the_writer_exits() {
    for global_limit in [None, Some(2)] {
        let mut limits = ListenerConfig::default();
        limits.limits.max_pending = global_limit;
        limits.limits.max_pending_per_source = 2;
        limits.admission = Some(zmux::Admission::new(0, |_, _| {
            zmux::AdmissionVerdict::takeover()
        }));
        let called = Arc::new(AtomicUsize::new(0));
        let calls = called.clone();
        limits.fallback = Some(zmux::Fallback::new(move |_| {
            calls.fetch_add(1, Ordering::SeqCst);
            async {}
        }));
        let listener = Listener::new(Config::default(), limits).unwrap();
        let peer = (std::net::Ipv4Addr::LOCALHOST, 0).into();
        let probe_peer = if global_limit.is_some() {
            (std::net::Ipv6Addr::LOCALHOST, 0).into()
        } else {
            peer
        };
        let _occupied = listener.adapter().enter(peer, None).unwrap();
        let req = http::Request::post("/zmux")
            .header(http::header::TRANSFER_ENCODING, "chunked")
            .body(fixed(b"request"))
            .unwrap();
        let mut response = zmux_http::handle_request(
            &listener,
            req,
            Some(peer),
            None,
            &zmux_http::PairField::default(),
        )
        .await
        .unwrap();
        let mut write = response.body_mut().take_response_head().unwrap();
        let (cancelled, observed) = tokio::sync::oneshot::channel();
        let (finish, finishing) = tokio::sync::oneshot::channel();
        let host = listener.clone();
        let writer = tokio::spawn(async move {
            write.cancelled().await;
            // The host cancellation action re-enters the listener and returns.
            assert!(host.adapter().enter(probe_peer, None).is_none());
            cancelled.send(()).unwrap();
            finishing.await.unwrap();
            drop(write);
        });
        drop(response);
        observed.await.unwrap();
        assert!(listener.adapter().enter(probe_peer, None).is_none());
        assert_eq!(called.load(Ordering::SeqCst), 0);
        let stats = listener.stats().admission;
        assert_eq!(
            (stats.handshake_failed, stats.peek_timed_out, stats.closed),
            (1, 0, 0)
        );
        finish.send(()).unwrap();
        writer.await.unwrap();
        assert!(listener.adapter().enter(probe_peer, None).is_some());
    }
}
