//! WebSocket carriers end to end over loopback TCP: one-step `connect` and
//! `serve` with the subprotocol negotiated, one record per binary message
//! on the wire, a connection lost without a Close frame is a failure,
//! never a clean end, and the source trusted intermediaries report.

use std::time::Duration;

use futures_util::StreamExt;
use tokio::net::{TcpListener, TcpStream};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http;
use zmux::{Config, Listener, ListenerConfig, PipeFailure, Session, SessionError};

async fn server() -> (std::net::SocketAddr, Listener, tokio::task::JoinHandle<()>) {
    let listener = Listener::new(Config::default(), ListenerConfig::default())
        .expect("valid listener configuration");
    let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = tcp.local_addr().unwrap();
    let serving = tokio::spawn(zmux_websocket::serve(
        listener.clone(),
        tcp,
        Default::default(),
    ));
    (addr, listener, serving)
}

/// A stream each way between the two sessions.
async fn round_trip(client: &Session, server: &Session) {
    let (mut send, mut recv) = client.open_bi().await.unwrap();
    let data: Vec<u8> = (0..(256 << 10)).map(|i| (i % 251) as u8).collect();
    let writer = {
        let data = data.clone();
        tokio::spawn(async move {
            send.write_all(&data).await.unwrap();
            send.finish().unwrap();
            send
        })
    };
    let (mut s, mut r) = server.accept_bi().await.unwrap();
    let got = r.read_to_end(1 << 20).await.unwrap();
    assert_eq!(got, data);
    s.write_all(&got).await.unwrap();
    s.finish().unwrap();
    assert_eq!(recv.read_to_end(1 << 20).await.unwrap(), data);
    drop(writer.await.unwrap());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn connect_and_serve() {
    let (addr, listener, serving) = server().await;
    let client = zmux_websocket::connect(
        format!("ws://{addr}/zmux"),
        &Default::default(),
        Config::default(),
    )
    .await
    .unwrap();
    let server = listener.accept().await.unwrap();
    assert_kind([&client, &server], zmux::CarrierKind::WebSocket);
    assert_eq!(client.protocol().as_deref(), Some("qmux-02"));
    assert_eq!(server.protocol().as_deref(), Some("qmux-02"));
    round_trip(&client, &server).await;
    client.close().await;
    assert!(matches!(
        server.closing().await,
        SessionError::ApplicationClosed { remote: true, .. }
    ));
    listener.close();
    serving.await.unwrap();
}

/// Message boundaries: a plain WebSocket peer receives every record as one
/// binary message, the first holding QX_TRANSPORT_PARAMETERS from its
/// first byte, and none of them holds two records.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::result_large_err)]
async fn every_record_is_one_message() {
    let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = tcp.local_addr().unwrap();
    let raw = tokio::spawn(async move {
        let (conn, _) = tcp.accept().await.unwrap();
        let mut ws = tokio_tungstenite::accept_hdr_async(
            conn,
            |_: &tokio_tungstenite::tungstenite::handshake::server::Request,
             mut resp: tokio_tungstenite::tungstenite::handshake::server::Response| {
                resp.headers_mut()
                    .insert("Sec-WebSocket-Protocol", "qmux-02".parse().unwrap());
                Ok(resp)
            },
        )
        .await
        .unwrap();
        match ws.next().await.unwrap().unwrap() {
            Message::Binary(b) => b,
            m => panic!("{m:?}"),
        }
    });
    let io = zmux_websocket::dial(format!("ws://{addr}/zmux"), &Default::default())
        .await
        .unwrap();
    // The peer never answers: establishment waits; the first record went
    // out as one message.
    let client = tokio::spawn(async move {
        let mut c = Config::default();
        c.handshake_timeout = Some(Duration::from_millis(500));
        Session::connect(io, c).await
    });
    let first = raw.await.unwrap();
    assert!(
        first.starts_with(&zmux::proto::ident::SESSION_PREFIX),
        "{:02x?}",
        &first[..first.len().min(16)]
    );
    // The message is the Frames field alone (no Size before it), and holds
    // the whole QX_TRANSPORT_PARAMETERS frame: its Length lies within it.
    let rest = &first[zmux::proto::ident::SESSION_PREFIX.len()..];
    let (len, w) = zmux::proto::varint::decode(rest).unwrap();
    assert!(w as u64 + len <= rest.len() as u64, "a split record");
    let _ = client.await;
}

/// A TCP proxy to `to` for one connection; aborting its task drops both
/// sockets without a Close frame.
async fn proxy(to: std::net::SocketAddr) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    let front = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = front.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let (mut a, _) = front.accept().await.unwrap();
        let mut b = TcpStream::connect(to).await.unwrap();
        let _ = tokio::io::copy_bidirectional(&mut a, &mut b).await;
    });
    (addr, task)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_lost_connection_is_a_failure_not_a_clean_end() {
    let (addr, listener, _serving) = server().await;
    let (front, proxy) = proxy(addr).await;
    let client = zmux_websocket::connect(
        format!("ws://{front}/zmux"),
        &Default::default(),
        Config::default(),
    )
    .await
    .unwrap();
    let server = listener.accept().await.unwrap();
    round_trip(&client, &server).await;
    proxy.abort();
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
            "{e:?}"
        );
    }
    listener.close();
}

/// Both subprotocol forms: an application's own identifier is negotiated
/// as it is, and `qmux-02.<application>` is accepted from a client that
/// offers only its draft-01 alias.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn application_subprotocols() {
    use zmux_websocket::Options;
    for (server_opts, client_opts, expect) in [
        (
            Options::for_protocol("moq-transport-18"),
            Options::for_protocol("moq-transport-18"),
            Some("moq-transport-18"),
        ),
        (
            Options::for_application("chat"),
            Options::for_protocol("qmux-01.chat"),
            Some("qmux-01.chat"),
        ),
        // Neither offered nor selected: no application protocol.
        (
            Options::default().with_no_subprotocol(true),
            Options::default().with_no_subprotocol(true),
            None,
        ),
    ] {
        let listener = Listener::new(Config::default(), ListenerConfig::default())
            .expect("valid listener configuration");
        let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = tcp.local_addr().unwrap();
        let serving = tokio::spawn(zmux_websocket::serve(listener.clone(), tcp, server_opts));
        let client =
            zmux_websocket::connect(format!("ws://{addr}/zmux"), &client_opts, Config::default())
                .await
                .unwrap();
        let server = listener.accept().await.unwrap();
        assert_eq!(client.protocol().as_deref(), expect);
        assert_eq!(server.protocol().as_deref(), expect);
        client.close().await;
        listener.close();
        serving.await.unwrap();
    }
}

/// A WebSocket relay to the server at `to` that sends `empties` empty
/// messages to it after the client's first message.
#[allow(clippy::result_large_err)]
async fn empty_injector(
    to: std::net::SocketAddr,
    empties: usize,
) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    use futures_util::SinkExt;
    let front = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = front.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let (conn, _) = front.accept().await.unwrap();
        let client = tokio_tungstenite::accept_hdr_async(
            conn,
            |_: &tokio_tungstenite::tungstenite::handshake::server::Request,
             mut resp: tokio_tungstenite::tungstenite::handshake::server::Response| {
                resp.headers_mut()
                    .insert("Sec-WebSocket-Protocol", "qmux-02".parse().unwrap());
                Ok(resp)
            },
        )
        .await
        .unwrap();
        let mut req = IntoClientRequest::into_client_request(format!("ws://{to}/zmux")).unwrap();
        req.headers_mut()
            .insert("Sec-WebSocket-Protocol", "qmux-02".parse().unwrap());
        let (server, _) = tokio_tungstenite::connect_async(req).await.unwrap();
        let (mut cs, mut cr) = client.split();
        let (mut ss, mut sr) = server.split();
        let up = async move {
            let mut first = true;
            while let Some(Ok(m)) = cr.next().await {
                if ss.send(m).await.is_err() {
                    break;
                }
                if std::mem::take(&mut first) {
                    for _ in 0..empties {
                        if ss.send(Message::Binary(Default::default())).await.is_err() {
                            return;
                        }
                    }
                }
            }
        };
        let down = async move {
            while let Some(Ok(m)) = sr.next().await {
                if cs.send(m).await.is_err() {
                    break;
                }
            }
        };
        tokio::join!(up, down);
    });
    (addr, task)
}

/// Empty messages are empty records: the server counts each in its pipe
/// positions and does not charge it against the no-effect budget. The
/// injected messages are bytes the client never sent, so the client sees a
/// PIPE_ACK above what it sent and closes the session.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn empty_messages_count_in_pipe_positions() {
    let (addr, listener, _serving) = server().await;
    let (front, relay) = empty_injector(addr, 100_000).await;
    let client = zmux_websocket::connect(
        format!("ws://{front}/zmux"),
        &Default::default(),
        Config::default(),
    )
    .await
    .unwrap();
    // The relay writes the empty messages one by one: slow on a loaded host.
    let e = tokio::time::timeout(Duration::from_secs(60), client.closing())
        .await
        .expect("closed");
    assert!(
        matches!(
            &e,
            SessionError::TransportClosed { code, remote: false, .. }
                if *code == zmux::proto::TransportErrorCode::PROTOCOL_VIOLATION
        ),
        "{e:?}"
    );
    relay.abort();
    listener.close();
}

/// wss://: `connect_tls` against `serve_tls`, admitted by a prefix
/// authentication token in the request header, bound to the TLS
/// connection: the client's credential takes the binding from its
/// connection, the server's admission from the connection's exporter.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn connect_over_tls() {
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use std::sync::Arc;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let der = CertificateDer::from(cert.cert.der().to_vec());
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()));
    let server_tls = rustls::ServerConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![der.clone()], key)
        .unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(der).unwrap();
    let client_tls = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_tls));
    let connector = tokio_rustls::TlsConnector::from(Arc::new(client_tls));

    let auth = zmux::PrefixAuth::new(b"psk", Duration::from_secs(30), true).unwrap();
    let verifier = Arc::new(zmux::PrefixAuthVerifier::new(auth.clone(), 1, 1024));
    let mut limits = ListenerConfig::default();
    limits.admission = Some(zmux::Admission::prefix_auth(verifier));
    let listener = Listener::new(Config::default(), limits).expect("valid listener configuration");
    let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = tcp.local_addr().unwrap().port();
    let serving = tokio::spawn(zmux_websocket::serve_tls(
        listener.clone(),
        tcp,
        acceptor,
        Default::default(),
    ));
    let url = format!("wss://localhost:{port}/zmux");
    // Without the token: refused.
    let refused = zmux_websocket::dial_tls(url.as_str(), &connector, &Default::default()).await;
    assert!(refused.is_err());
    // Unbound tokens do not verify where bound ones are configured.
    let unbound = zmux::PrefixAuth::new(b"psk", Duration::from_secs(30), false).unwrap();
    let options = zmux_websocket::Options::default().with_carrier_credential(Arc::new(unbound));
    assert!(
        zmux_websocket::dial_tls(url.as_str(), &connector, &options)
            .await
            .is_err()
    );
    let options = zmux_websocket::Options::default().with_carrier_credential(Arc::new(auth));
    let client = zmux_websocket::connect_tls(url.as_str(), &connector, &options, Config::default())
        .await
        .unwrap();
    let server = listener.accept().await.unwrap();
    assert_eq!(client.protocol().as_deref(), Some("qmux-02"));
    round_trip(&client, &server).await;
    client.close().await;
    listener.close();
    serving.await.unwrap();
}

/// A join over a second WebSocket connection.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_second_connection_joins() {
    let mut config = Config::default();
    config.pipe_auth = zmux::PipeAuth::psk(vec![7u8; 32]).with_end_to_end();
    config.max_pipes = 8;
    let listener = Listener::new(config.clone(), ListenerConfig::default())
        .expect("valid listener configuration");
    let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = tcp.local_addr().unwrap();
    let serving = tokio::spawn(zmux_websocket::serve(
        listener.clone(),
        tcp,
        Default::default(),
    ));
    let client = zmux_websocket::connect(format!("ws://{addr}/zmux"), &Default::default(), config)
        .await
        .unwrap();
    let server = listener.accept().await.unwrap();
    let req = IntoClientRequest::into_client_request(format!("ws://{addr}/zmux")).unwrap();
    let io = zmux_websocket::dial(req, &Default::default())
        .await
        .unwrap();
    let pipe = client.begin_add_pipe(io, zmux::PipeOptions::new()).unwrap();
    tokio::time::timeout(Duration::from_secs(5), pipe.joined())
        .await
        .unwrap()
        .unwrap();
    round_trip(&client, &server).await;
    client.close().await;
    serving.abort();
}

/// A raw request on `addr`: the response the server writes until it ends
/// the connection.
async fn raw_request(addr: std::net::SocketAddr, request: &[u8]) -> Vec<u8> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut tcp = TcpStream::connect(addr).await.unwrap();
    tcp.write_all(request).await.unwrap();
    let mut out = Vec::new();
    tokio::time::timeout(Duration::from_secs(10), tcp.read_to_end(&mut out))
        .await
        .unwrap()
        .unwrap();
    out
}

fn upgrade_request(protocol: Option<&str>) -> Vec<u8> {
    let mut r = String::from(
        "GET /zmux HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\
         Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n",
    );
    if let Some(p) = protocol {
        r.push_str(&format!("Sec-WebSocket-Protocol: {p}\r\n"));
    }
    r.push_str("\r\n");
    r.into_bytes()
}

/// A client offering no accepted subprotocol, or none, is refused: without
/// a fallback it gets a 404 and no session starts.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unaccepted_subprotocol_is_refused_with_not_found() {
    let (addr, listener, serving) = server().await;
    for protocol in [Some("other-1"), None] {
        let response = raw_request(addr, &upgrade_request(protocol)).await;
        assert!(
            response.starts_with(b"HTTP/1.1 404 Not Found\r\n"),
            "{}",
            String::from_utf8_lossy(&response)
        );
    }
    let response = raw_request(addr, &upgrade_request(Some("qmux-03, x"))).await;
    assert!(response.starts_with(b"HTTP/1.1 404"));
    // Failed upgrades: setup failures, no pipe input.
    let st = listener.stats();
    assert_eq!((st.sessions, st.rejected, st.setup_failures), (0, 0, 3));
    listener.close();
    serving.await.unwrap();
}

/// A refused request, an unaccepted subprotocol or a request that is not
/// an upgrade, reaches the fallback with every byte the server read.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_refused_request_reaches_the_fallback_with_every_byte() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let fallback = zmux::adapter::Fallback::new(|mut conn, _source| async move {
        // Echo the request as the body of a 200, then end.
        let mut got = vec![0u8; 4096];
        let mut n = 0;
        while !got[..n].ends_with(b"\r\n\r\nbody") {
            let m = conn.read(&mut got[n..]).await.unwrap();
            assert_ne!(m, 0);
            n += m;
        }
        let head = format!("HTTP/1.1 200 OK\r\nContent-Length: {n}\r\n\r\n");
        conn.write_all(head.as_bytes()).await.unwrap();
        conn.write_all(&got[..n]).await.unwrap();
        conn.shutdown().await.unwrap();
    });
    let mut limits = ListenerConfig::default();
    limits.fallback = Some(fallback);
    let listener = Listener::new(Config::default(), limits).expect("valid listener configuration");
    let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = tcp.local_addr().unwrap();
    let serving = tokio::spawn(zmux_websocket::serve(
        listener.clone(),
        tcp,
        Default::default(),
    ));
    let plain = b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\nbody".to_vec();
    let mut other = upgrade_request(Some("other-1"));
    other.extend_from_slice(b"body");
    for request in [plain, other] {
        let response = raw_request(addr, &request).await;
        assert!(response.starts_with(b"HTTP/1.1 200 OK\r\n"));
        assert!(response.ends_with(&request), "the request replayed in full");
    }
    // An accepted upgrade still makes a session.
    let client = zmux_websocket::connect(
        format!("ws://{addr}/zmux"),
        &Default::default(),
        Config::default(),
    )
    .await
    .unwrap();
    let server = listener.accept().await.unwrap();
    round_trip(&client, &server).await;
    client.close().await;
    listener.close();
    serving.await.unwrap();
}

/// An admission decides on the request head: its metadata carries the
/// request's parts, its header fields and the client's address.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_admission_decides_on_the_request_head() {
    use zmux::{Admission, AdmissionVerdict};
    let admission = Admission::new(0, |info, prefix| {
        assert!(prefix.is_empty());
        assert!(info.source.is_some());
        assert!(info.head);
        let mut upgrade = false;
        info.for_each_header(|n, v| upgrade |= n == "upgrade" && v == b"websocket");
        assert!(upgrade);
        let parts = info
            .request
            .and_then(|r| r.downcast_ref::<http::request::Parts>())
            .expect("the request head");
        if parts.headers.contains_key("x-pass") {
            AdmissionVerdict::accept(0)
        } else {
            AdmissionVerdict::Fallback
        }
    });
    let mut limits = ListenerConfig::default();
    limits.admission = Some(admission);
    let listener = Listener::new(Config::default(), limits).expect("valid listener configuration");
    let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = tcp.local_addr().unwrap();
    let serving = tokio::spawn(zmux_websocket::serve(
        listener.clone(),
        tcp,
        Default::default(),
    ));
    let response = raw_request(addr, &upgrade_request(Some("qmux-02"))).await;
    assert!(response.starts_with(b"HTTP/1.1 404"));
    let mut request = format!("ws://{addr}/zmux").into_client_request().unwrap();
    request
        .headers_mut()
        .insert("x-pass", http::HeaderValue::from_static("1"));
    let client = zmux_websocket::connect(request, &Default::default(), Config::default())
        .await
        .unwrap();
    let server = listener.accept().await.unwrap();
    round_trip(&client, &server).await;
    client.close().await;
    listener.close();
    serving.await.unwrap();
}

/// A `ws://` client with a prefix authentication credential sends its
/// token in the `Zmux-Prefix-Auth` field, which the server's admission
/// verifies once; without it, or with the token replayed, the request is
/// refused. A bound credential has no exporter on `ws://` and fails.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn prefix_auth_in_the_request_header() {
    use std::sync::Arc;
    let auth = zmux::PrefixAuth::new(b"psk", Duration::from_secs(30), false).unwrap();
    let verifier = Arc::new(zmux::PrefixAuthVerifier::new(auth.clone(), 1, 1024));
    let mut limits = ListenerConfig::default();
    limits.admission = Some(zmux::Admission::prefix_auth(verifier));
    let listener = Listener::new(Config::default(), limits).expect("valid listener configuration");
    let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = tcp.local_addr().unwrap();
    let serving = tokio::spawn(zmux_websocket::serve(
        listener.clone(),
        tcp,
        Default::default(),
    ));
    let url = format!("ws://{addr}/zmux");
    let refused = raw_request(addr, &upgrade_request(Some("qmux-02"))).await;
    assert!(refused.starts_with(b"HTTP/1.1 404"));

    let options =
        zmux_websocket::Options::default().with_carrier_credential(Arc::new(auth.clone()));
    let client = zmux_websocket::connect(url.as_str(), &options, Config::default())
        .await
        .unwrap();
    let server = listener.accept().await.unwrap();
    round_trip(&client, &server).await;
    client.close().await;

    let (name, value) = zmux::CarrierCredential::header(&auth, &zmux::CarrierInfo::new()).unwrap();
    assert_eq!(name, zmux::PREFIX_AUTH_HEADER);
    let mut request = format!("ws://{addr}/zmux").into_client_request().unwrap();
    request
        .headers_mut()
        .insert(zmux::PREFIX_AUTH_HEADER, value.parse().unwrap());
    zmux_websocket::dial(request.clone(), &Default::default())
        .await
        .unwrap();
    assert!(
        zmux_websocket::dial(request, &Default::default())
            .await
            .is_err(),
        "a replayed token"
    );

    let bound = zmux::PrefixAuth::new(b"psk", Duration::from_secs(30), true).unwrap();
    let options = zmux_websocket::Options::default().with_carrier_credential(Arc::new(bound));
    let e = zmux_websocket::dial(url.as_str(), &options)
        .await
        .unwrap_err();
    assert_eq!(e.kind(), std::io::ErrorKind::InvalidInput);
    listener.close();
    serving.await.unwrap();
}

/// Behind intermediaries the listener trusts: `serve` reads the PROXY
/// protocol header of a trusted peer first, and the request's forwarding
/// header field applies only when the client that header reports is
/// itself trusted. Without an admission the upgrade goes on after the
/// header.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn trusted_intermediaries_report_the_source() {
    use std::sync::Mutex;
    use zmux::{Admission, AdmissionVerdict, TrustedProxies};
    let forwarded = |proxy: &str| {
        let mut r = format!("PROXY TCP4 {proxy} 10.0.0.1 4000 443\r\n").into_bytes();
        let up = upgrade_request(Some("qmux-02"));
        let at = up.len() - 2;
        r.extend_from_slice(&up[..at]);
        r.extend_from_slice(b"X-Forwarded-For: 1.2.3.4\r\n\r\n");
        r
    };
    let proxies = TrustedProxies::new()
        .with_net("127.0.0.0/8".parse().unwrap())
        .with_proxy_protocol(true)
        .with_forwarded_header("X-Forwarded-For");
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let tx = Mutex::new(tx);
    let admission = Admission::new(0, move |info, _| {
        let _ = tx.lock().unwrap().send(info.source.unwrap());
        AdmissionVerdict::Close
    });
    let serve = async |admission| {
        let mut limits = ListenerConfig::default();
        limits.trusted_proxies = proxies.clone();
        limits.admission = admission;
        let listener =
            Listener::new(Config::default(), limits).expect("valid listener configuration");
        let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = tcp.local_addr().unwrap();
        let task = tokio::spawn(zmux_websocket::serve(
            listener.clone(),
            tcp,
            Default::default(),
        ));
        (addr, listener, task)
    };
    let (admitted, admitted_listener, a) = serve(Some(admission)).await;
    let (plain, plain_listener, p) = serve(None).await;
    for (proxy, expect) in [
        ("198.51.100.7", "198.51.100.7:4000"),
        ("127.0.0.2", "1.2.3.4:0"),
    ] {
        let response = raw_request(admitted, &forwarded(proxy)).await;
        assert!(response.is_empty(), "{response:?}");
        assert_eq!(rx.recv().await.unwrap().to_string(), expect);
    }
    let mut tcp = TcpStream::connect(plain).await.unwrap();
    {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        tcp.write_all(&forwarded("198.51.100.7")).await.unwrap();
        let mut head = [0u8; 12];
        tokio::time::timeout(Duration::from_secs(10), tcp.read_exact(&mut head))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&head, b"HTTP/1.1 101");
    }
    admitted_listener.close();
    plain_listener.close();
    drop(tcp);
    a.await.unwrap();
    p.await.unwrap();
}

/// Pipe 0 of each session is of carrier kind `kind`.
fn assert_kind(sessions: [&Session; 2], kind: zmux::CarrierKind) {
    for s in sessions {
        let p = s.pipe(zmux::PipeId::new(0)).unwrap();
        assert_eq!(p.stats().unwrap().carrier, Some(kind));
    }
}

/// The `wss` feature: `dial` takes a `wss://` URL with the Mozilla roots, which do not
/// trust a self-signed certificate; `tls_connector` with that certificate as its root
/// connects to `serve_tls`.
#[cfg(feature = "wss")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wss_with_the_feature() {
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use std::sync::Arc;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let der = CertificateDer::from(cert.cert.der().to_vec());
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()));
    let mut server_tls = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![der.clone()], key)
        .unwrap();
    server_tls.alpn_protocols = vec![b"http/1.1".to_vec()];
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_tls));
    let listener =
        Listener::new(Config::default(), ListenerConfig::default()).expect("valid configuration");
    let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = tcp.local_addr().unwrap().port();
    let serving = tokio::spawn(zmux_websocket::serve_tls(
        listener.clone(),
        tcp,
        acceptor,
        Default::default(),
    ));
    let url = format!("wss://localhost:{port}/zmux");
    let e = zmux_websocket::dial(url.as_str(), &Default::default())
        .await
        .expect_err("a self-signed certificate is not trusted");
    assert!(e.to_string().contains("certificate"), "{e}");
    let mut roots = rustls::RootCertStore::empty();
    roots.add(der).unwrap();
    let connector = zmux_websocket::tls_connector(roots);
    let client = zmux_websocket::connect_tls(
        url.as_str(),
        &connector,
        &Default::default(),
        Config::default(),
    )
    .await
    .unwrap();
    let server = listener.accept().await.unwrap();
    round_trip(&client, &server).await;
    client.close().await;
    listener.close();
    serving.abort();
}

/// Without the `wss` feature `dial` refuses a `wss://` URL as invalid input.
#[cfg(not(feature = "wss"))]
#[tokio::test]
async fn wss_without_the_feature_is_invalid_input() {
    let e = zmux_websocket::dial("wss://localhost:1/zmux", &Default::default())
        .await
        .expect_err("refused");
    assert_eq!(e.kind(), std::io::ErrorKind::InvalidInput);
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

/// N16 over WebSocket, through the adapter's `connect` and `serve`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_close_is_delivered_with_its_code() {
    for (code, reason, slow) in [
        (0x2a, &b"bye"[..], false),
        (0, &b""[..], false),
        (0x2a, &b"bye"[..], true),
    ] {
        let (addr, listener, serving) = server().await;
        let client = zmux_websocket::connect(
            format!("ws://{addr}/zmux"),
            &Default::default(),
            lingering(Config::default()),
        )
        .await
        .unwrap();
        let server = listener.accept().await.unwrap();
        close_delivery(&client, &server, code, reason, slow).await;
        listener.close();
        serving.await.unwrap();
    }
}
