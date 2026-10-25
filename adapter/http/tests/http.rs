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
    let listener = Listener::new(config, ListenerConfig::default());
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
    client.close(3u32.into(), b"bye");
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
    let listener = Listener::new(Config::default(), ListenerConfig::default());
    let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = tcp.local_addr().unwrap().to_string();
    let requests = Arc::new(AtomicUsize::new(0));
    {
        let (listener, requests) = (listener.clone(), requests.clone());
        tokio::spawn(async move {
            let (stream, peer) = tcp.accept().await.unwrap();
            let service = hyper::service::service_fn(move |req| {
                requests.fetch_add(1, Ordering::SeqCst);
                let resp = zmux_http::handle_request(&listener, req, Some(peer.ip()), None);
                std::future::ready(Ok::<_, std::convert::Infallible>(resp))
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
    client.close(0u32.into(), b"");
}

fn multipath() -> Config {
    Config::multipath(PipeAuth::psk(*b"zmux-http-test-psk-0123456789abc"))
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
            .add_pipe(conn.open_pipe().await.unwrap(), PipeOptions::new())
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
        client.close(0u32.into(), b"");
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
        let listener = Listener::new(Config::default(), ListenerConfig::default());
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
