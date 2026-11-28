//! WebSocket carriers end to end over loopback TCP: one-step `connect` and
//! `serve` with the subprotocol negotiated, one record per binary message
//! on the wire, a connection lost without a Close frame is a failure,
//! never a clean end, and the source trusted intermediaries report.

#[path = "../../test-support/ticket.rs"]
mod ticket;

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
        zmux_websocket::Options::default(),
    ));
    (addr, listener, serving)
}

/// A stream each way between the two sessions.
async fn round_trip(client: &Session, server: &Session) {
    let (mut send, mut recv) = client.open_bi().await.unwrap();
    let data: Vec<u8> = (0..(256 << 10))
        .map(|i| u8::try_from(i % 251).unwrap())
        .collect();
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
        &zmux_websocket::Options::default(),
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
/// binary message, the first holding `QX_TRANSPORT_PARAMETERS` from its
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
    let io = zmux_websocket::dial(
        format!("ws://{addr}/zmux"),
        &zmux_websocket::Options::default(),
    )
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
        &zmux_websocket::Options::default(),
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
                        if ss
                            .send(Message::Binary(
                                tokio_tungstenite::tungstenite::Bytes::default(),
                            ))
                            .await
                            .is_err()
                        {
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
/// `PIPE_ACK` above what it sent and closes the session.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn empty_messages_count_in_pipe_positions() {
    let (addr, listener, _serving) = server().await;
    // Twice the no-effect budget's 4096 tokens: charged, they would end the
    // session with a budget violation instead. The client's next record
    // follows them through the relay, so they all pass before the server
    // acknowledges past them; many more would take the relay longer than
    // the server's idle timeout on a loaded host.
    let (front, relay) = empty_injector(addr, 8192).await;
    let client = zmux_websocket::connect(
        format!("ws://{front}/zmux"),
        &zmux_websocket::Options::default(),
        Config::default(),
    )
    .await
    .unwrap();
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
    let cert = zmux_testcert::self_signed(vec!["localhost".into()]).unwrap();
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

    let (auth, verifier) = ticket::fixture(zmux::PrefixBinding::Bound);
    let mut limits = ListenerConfig::default();
    limits.admission = Some(zmux::Admission::prefix_auth(
        verifier,
        zmux::PrefixRejection::Fallback,
    ));
    let listener = Listener::new(Config::default(), limits).expect("valid listener configuration");
    let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = tcp.local_addr().unwrap().port();
    let serving = tokio::spawn(zmux_websocket::serve_tls(
        listener.clone(),
        tcp,
        acceptor,
        zmux_websocket::Options::default(),
    ));
    let url = format!("wss://localhost:{port}/zmux");
    // Without the token: refused.
    let refused = zmux_websocket::dial_tls(
        url.as_str(),
        &connector,
        &zmux_websocket::Options::default(),
    )
    .await;
    assert!(refused.is_err());
    // Unbound tokens do not verify where bound ones are configured.
    let unbound = ticket::fixture(zmux::PrefixBinding::AllowCleartext).0;
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
    let tcp = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .unwrap();
    let name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
    let tls = zmux_rustls::TlsConnection::client(
        connector.connect(name, tcp).await.unwrap(),
        "localhost",
    );
    let info = tls.info();
    let pipe = zmux_websocket::dial_over(tls, url.as_str(), &options, &info)
        .await
        .unwrap();
    let hosted = Session::connect(pipe, Config::default()).await.unwrap();
    let accepted = listener.accept().await.unwrap();
    assert_eq!(accepted.bound_prefix_principal(), Some(ticket::ID));
    round_trip(&hosted, &accepted).await;
    hosted.close().await;
    client.close().await;
    listener.close();
    serving.await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn ticket_record_refusal_replays_complete_messages_and_closes_failed_reads() {
    use futures_util::SinkExt;
    use tokio_tungstenite::{
        WebSocketStream,
        tungstenite::{
            Message,
            protocol::{Role, WebSocketConfig},
        },
    };
    use zmux::{
        Admission, CarrierInfo, Fallback, MAX_ADMISSION_MESSAGE, PrefixBinding, PrefixRejection,
    };

    let max = MAX_ADMISSION_MESSAGE;
    for (reject, message, fallback, stalled, closed) in [
        (
            PrefixRejection::Fallback,
            Message::binary(vec![1; max + 1]),
            true,
            false,
            false,
        ),
        (
            PrefixRejection::Fallback,
            Message::binary(vec![2; max + 2]),
            false,
            true,
            false,
        ),
        (
            PrefixRejection::Stall,
            Message::binary(vec![3; max + 1]),
            false,
            true,
            false,
        ),
        (
            PrefixRejection::Stall,
            Message::binary(vec![4; max + 2]),
            false,
            true,
            false,
        ),
        (
            PrefixRejection::Fallback,
            Message::text("text"),
            false,
            false,
            true,
        ),
        (
            PrefixRejection::Fallback,
            Message::binary(Vec::new()),
            false,
            false,
            true,
        ),
    ] {
        let (report, mut reports) = tokio::sync::mpsc::unbounded_channel();
        let (_, verifier) = ticket::fixture(PrefixBinding::AllowCleartext);
        let mut limits = ListenerConfig::default();
        limits.admission = Some(
            Admission::prefix_auth(verifier, reject)
                .with_stall_interval(Duration::from_secs(2), Duration::from_secs(2)),
        );
        limits.fallback = Some(Fallback::new(move |carrier| {
            let report = report.clone();
            async move {
                report.send(carrier.replayed().to_vec()).unwrap();
            }
        }));
        let listener = Listener::new(Config::default(), limits).unwrap();
        let (client, server) = tokio::io::duplex(max + 32);
        let cfg = WebSocketConfig::default()
            .max_message_size(Some(max + 1))
            .max_frame_size(Some(max + 1));
        let server = WebSocketStream::from_raw_socket(server, Role::Server, Some(cfg)).await;
        let mut client = WebSocketStream::from_raw_socket(client, Role::Client, None).await;
        client.send(message).await.unwrap();
        let mut entry = listener
            .adapter()
            .enter("127.0.0.1:0".parse().unwrap(), None)
            .unwrap();
        assert!(
            entry
                .admit(CarrierInfo::new(), zmux_websocket::pipe(server, None))
                .await
                .is_none()
        );
        let stats = listener.stats().admission;
        assert_eq!(stats.fallback, u64::from(fallback));
        assert_eq!(stats.stalled, u64::from(stalled));
        assert_eq!(stats.closed, u64::from(closed));
        if fallback {
            assert_eq!(reports.try_recv().unwrap(), vec![1; max + 1]);
        } else {
            assert!(reports.try_recv().is_err());
        }
    }
}

/// A join over a second WebSocket connection.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_second_connection_joins() {
    let mut config = Config::default();
    config.pipe_auth = zmux::PipeAuth::psk(vec![7u8; 32]).with_end_to_end();
    config.session_policy.limits.steady_attachments = 8;
    let listener = Listener::new(config.clone(), ListenerConfig::default())
        .expect("valid listener configuration");
    let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = tcp.local_addr().unwrap();
    let serving = tokio::spawn(zmux_websocket::serve(
        listener.clone(),
        tcp,
        zmux_websocket::Options::default(),
    ));
    let client = zmux_websocket::connect(
        format!("ws://{addr}/zmux"),
        &zmux_websocket::Options::default(),
        config,
    )
    .await
    .unwrap();
    let server = listener.accept().await.unwrap();
    let req = IntoClientRequest::into_client_request(format!("ws://{addr}/zmux")).unwrap();
    let io = zmux_websocket::dial(req, &zmux_websocket::Options::default())
        .await
        .unwrap();
    let pipe = client
        .test_begin_join(io, zmux::PipeOptions::new())
        .unwrap();
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
        r += "Sec-WebSocket-Protocol: ";
        r += p;
        r += "\r\n";
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
    let fallback = zmux::Fallback::new(|t: zmux::Takeover| async move {
        let mut conn = t.into_stream().expect("the TCP connection");
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
        zmux_websocket::Options::default(),
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
        &zmux_websocket::Options::default(),
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
        assert_eq!(prefix, b"");
        assert!(info.source.is_some());
        assert!(info.is_head() && info.upgrade);
        let mut upgrade = false;
        info.for_each_header(|n, v| upgrade |= n == "upgrade" && v == b"websocket");
        assert!(upgrade);
        let parts = info
            .request
            .as_deref()
            .and_then(|r| r.downcast_ref::<http::request::Parts>())
            .expect("the request head");
        if parts.headers.contains_key("x-pass") {
            AdmissionVerdict::accept(0)
        } else {
            AdmissionVerdict::fallback()
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
        zmux_websocket::Options::default(),
    ));
    let response = raw_request(addr, &upgrade_request(Some("qmux-02"))).await;
    assert!(response.starts_with(b"HTTP/1.1 404"));
    let mut request = format!("ws://{addr}/zmux").into_client_request().unwrap();
    request
        .headers_mut()
        .insert("x-pass", http::HeaderValue::from_static("1"));
    let client = zmux_websocket::connect(
        request,
        &zmux_websocket::Options::default(),
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

/// Even a bearer ticket enabled for cleartext binary presentation may
/// travel in a request field only on an encrypted connection.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn prefix_auth_in_a_cleartext_request_header_is_refused() {
    let (auth, verifier) = ticket::fixture(zmux::PrefixBinding::AllowCleartext);
    let mut limits = ListenerConfig::default();
    limits.admission = Some(zmux::Admission::prefix_auth(
        verifier,
        zmux::PrefixRejection::Fallback,
    ));
    let listener = Listener::new(Config::default(), limits).unwrap();
    let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = tcp.local_addr().unwrap();
    let serving = tokio::spawn(zmux_websocket::serve(
        listener.clone(),
        tcp,
        zmux_websocket::Options::default(),
    ));
    let raw = auth.token(&zmux::CarrierInfo::new()).unwrap();
    let value = zmux::PrefixAuth::header_value(&raw);
    let mut request = format!("ws://{addr}/zmux").into_client_request().unwrap();
    request
        .headers_mut()
        .insert(zmux::PREFIX_AUTH_HEADER, value.parse().unwrap());
    assert!(
        zmux_websocket::dial(request, &zmux_websocket::Options::default())
            .await
            .is_err()
    );
    let options =
        zmux_websocket::Options::default().with_carrier_credential(std::sync::Arc::new(auth));
    assert_eq!(
        zmux_websocket::dial(format!("ws://{addr}/zmux").as_str(), &options)
            .await
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::InvalidInput,
    );
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
            zmux_websocket::Options::default(),
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
    let cert = zmux_testcert::self_signed(vec!["localhost".into()]).unwrap();
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
        zmux_websocket::Options::default(),
    ));
    let url = format!("wss://localhost:{port}/zmux");
    let e = zmux_websocket::dial(url.as_str(), &zmux_websocket::Options::default())
        .await
        .expect_err("a self-signed certificate is not trusted");
    assert!(e.to_string().contains("certificate"), "{e}");
    let mut roots = rustls::RootCertStore::empty();
    roots.add(der).unwrap();
    let connector = zmux_websocket::tls_connector(roots);
    let client = zmux_websocket::connect_tls(
        url.as_str(),
        &connector,
        &zmux_websocket::Options::default(),
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
    let e = zmux_websocket::dial(
        "wss://localhost:1/zmux",
        &zmux_websocket::Options::default(),
    )
    .await
    .expect_err("refused");
    assert_eq!(e.kind(), std::io::ErrorKind::InvalidInput);
}

#[path = "../../test-support/close_delivery.rs"]
mod close_delivery;
use close_delivery::{close_delivery, lingering};

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
            &zmux_websocket::Options::default(),
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

/// The reverse-tunnel flow: the head defers, and the decision is taken on
/// the first message, a zmux client's first record accepted (a working
/// session) and anything else taken over by the listener's fallback, which
/// reads the first message again and then the next, answers, and returns;
/// the carrier is closed then. Per-source counts kept by the decision see
/// both.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_deferred_decision_on_the_first_message_accepts_or_takes_over() {
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    use futures_util::SinkExt;
    use zmux::adapter::{FirstBytes, classify_first_bytes};
    use zmux::{Admission, AdmissionVerdict, Fallback, Takeover};

    let per_source: Arc<Mutex<HashMap<std::net::IpAddr, usize>>> = Arc::default();
    let seen = per_source.clone();
    let admission = Admission::new(0, move |info, first| {
        if info.is_head() {
            return AdmissionVerdict::Defer;
        }
        assert!(info.upgrade && info.request.is_some());
        assert_eq!(info.framing, zmux::adapter::Framing::Records);
        *seen
            .lock()
            .unwrap()
            .entry(info.source.unwrap().ip())
            .or_default() += 1;
        match classify_first_bytes(first, info.framing) {
            FirstBytes::Record => AdmissionVerdict::accept(0),
            FirstBytes::NeedMore(_) | FirstBytes::Other => AdmissionVerdict::fallback(),
        }
    })
    .with_peek_timeout(Duration::from_secs(10));
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let fallback = Fallback::new(move |t: Takeover| {
        let tx = tx.clone();
        async move {
            assert_eq!(t.framing(), zmux::adapter::Framing::Records);
            assert!(!t.has_stream());
            let replayed = t.replayed().to_vec();
            let mut pipe = t.into_pipe();
            let mut first = Vec::new();
            pipe.read_handshake(&mut first).await.unwrap();
            let mut second = Vec::new();
            pipe.read_handshake(&mut second).await.unwrap();
            pipe.write_handshake(b"tunnel reply").await.unwrap();
            let _ = tx.send((replayed, first, second));
        }
    });
    let mut limits = ListenerConfig::default();
    limits.admission = Some(admission);
    limits.fallback = Some(fallback);
    let listener = Listener::new(Config::default(), limits).expect("valid listener configuration");
    let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = tcp.local_addr().unwrap();
    let serving = tokio::spawn(zmux_websocket::serve(
        listener.clone(),
        tcp,
        zmux_websocket::Options::default(),
    ));

    // A zmux client: accepted on its first record.
    let client = zmux_websocket::connect(
        format!("ws://{addr}/zmux"),
        &zmux_websocket::Options::default(),
        Config::default(),
    )
    .await
    .unwrap();
    let server = listener.accept().await.unwrap();
    round_trip(&client, &server).await;

    // A tunnel client: its messages reach the fallback, the first again.
    let mut request = format!("ws://{addr}/tunnel").into_client_request().unwrap();
    request
        .headers_mut()
        .insert("Sec-WebSocket-Protocol", "qmux-02".parse().unwrap());
    let (mut ws, _) = tokio_tungstenite::connect_async(request).await.unwrap();
    ws.send(Message::binary(b"hello tunnel".to_vec()))
        .await
        .unwrap();
    ws.send(Message::binary(b"second".to_vec())).await.unwrap();
    let (replayed, first, second) = tokio::time::timeout(Duration::from_secs(10), rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(replayed, b"hello tunnel");
    assert_eq!(first, b"hello tunnel");
    assert_eq!(second, b"second");
    let reply = ws.next().await.unwrap().unwrap();
    assert_eq!(reply, Message::binary(b"tunnel reply".to_vec()));
    // Closed once the fallback returned.
    let end = tokio::time::timeout(Duration::from_secs(10), ws.next())
        .await
        .unwrap();
    assert!(
        matches!(end, None | Some(Err(_) | Ok(Message::Close(_)))),
        "{end:?}"
    );

    let a = listener.stats().admission;
    assert_eq!(
        (a.accepted, a.fallback, a.closed, a.peek_timed_out),
        (1, 1, 0, 0)
    );
    let ip = std::net::IpAddr::from([127, 0, 0, 1]);
    assert_eq!(per_source.lock().unwrap()[&ip], 2);
    client.close().await;
    listener.close();
    serving.await.unwrap();
}

/// A WebSocket the listener's fallback took over after a deferred decision
/// and detached is the host's: it is served by typed messages after the
/// fallback's future completed, and closed only when the host is done.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_detached_websocket_is_served_after_the_fallback() {
    use futures_util::SinkExt;
    use zmux::{Admission, AdmissionVerdict, Fallback, Takeover};

    let admission = Admission::new(0, |info, _| {
        if info.is_head() {
            AdmissionVerdict::Defer
        } else {
            AdmissionVerdict::fallback()
        }
    })
    .with_peek_timeout(Duration::from_secs(10));
    let (returned_tx, returned) = tokio::sync::oneshot::channel::<()>();
    let returned_tx = std::sync::Mutex::new(Some(returned_tx));
    let (resume, resume_after_return) = tokio::sync::oneshot::channel::<()>();
    let resume_after_return = std::sync::Mutex::new(Some(resume_after_return));
    let fallback = Fallback::new(move |t: Takeover| {
        let returned_tx = returned_tx.lock().unwrap().take();
        let resume_after_return = resume_after_return.lock().unwrap().take().unwrap();
        async move {
            t.detach().unwrap();
            let mut m = t.into_messages().expect("message-framed");
            tokio::spawn(async move {
                // Served once the fallback's future completed.
                resume_after_return.await.unwrap();
                while let Some(msg) = m.read_message(1024).await.unwrap() {
                    let mut echo = b"echo ".to_vec();
                    echo.extend_from_slice(&msg);
                    m.write_message(&echo).await.unwrap();
                    if msg == b"bye" {
                        break;
                    }
                }
                m.shutdown().await.unwrap();
            });
            let _ = returned_tx.unwrap().send(());
        }
    });
    let mut limits = ListenerConfig::default();
    limits.admission = Some(admission);
    limits.fallback = Some(fallback);
    let listener = Listener::new(Config::default(), limits).expect("valid listener configuration");
    let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = tcp.local_addr().unwrap();
    let serving = tokio::spawn(zmux_websocket::serve(
        listener.clone(),
        tcp,
        zmux_websocket::Options::default(),
    ));
    let mut request = format!("ws://{addr}/tunnel").into_client_request().unwrap();
    request
        .headers_mut()
        .insert("Sec-WebSocket-Protocol", "qmux-02".parse().unwrap());
    let (mut ws, _) = tokio_tungstenite::connect_async(request).await.unwrap();
    ws.send(Message::binary(b"first".to_vec())).await.unwrap();
    tokio::time::timeout(Duration::from_secs(10), returned)
        .await
        .unwrap()
        .unwrap();
    resume.send(()).unwrap();
    for msg in [&b"first"[..], b"second", b"bye"] {
        if msg != b"first" {
            ws.send(Message::binary(msg.to_vec())).await.unwrap();
        }
        let reply = tokio::time::timeout(Duration::from_secs(10), ws.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let mut want = b"echo ".to_vec();
        want.extend_from_slice(msg);
        assert_eq!(reply, Message::binary(want));
    }
    let end = tokio::time::timeout(Duration::from_secs(10), ws.next())
        .await
        .unwrap();
    assert!(
        matches!(end, None | Some(Err(_) | Ok(Message::Close(_)))),
        "{end:?}"
    );
    assert_eq!(listener.stats().admission.fallback, 1);
    listener.close();
    serving.await.unwrap();
}

/// A request refused before its upgrade over TLS reaches the fallback as a
/// carrier with the capabilities of an accepted one: the terminated TLS
/// and, the connection bound, its exporter.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_refused_request_over_tls_keeps_its_capabilities() {
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let cert = zmux_testcert::self_signed(vec!["localhost".into()]).unwrap();
    let der = CertificateDer::from(cert.cert.der().to_vec());
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()));
    let mut server_tls = rustls::ServerConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![der.clone()], key)
        .unwrap();
    server_tls.alpn_protocols = vec![b"http/1.1".to_vec()];
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_tls));
    let (seen_tx, seen) = tokio::sync::mpsc::unbounded_channel();
    let fallback = zmux::Fallback::new(move |t: zmux::Takeover| {
        let seen_tx = seen_tx.clone();
        async move {
            let mut pipe = t.into_pipe();
            let _ = seen_tx.send((
                pipe.terminated_tls().is_some(),
                pipe.bound_exporter().is_some(),
            ));
            let _ = pipe
                .write_handshake(b"HTTP/1.1 204 No Content\r\n\r\n")
                .await;
        }
    });
    let mut limits = ListenerConfig::default();
    limits.fallback = Some(fallback);
    let listener = Listener::new(Config::default(), limits).expect("valid listener configuration");
    let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = tcp.local_addr().unwrap();
    let serving = tokio::spawn(zmux_websocket::serve_tls(
        listener.clone(),
        tcp,
        acceptor,
        zmux_websocket::Options::default(),
    ));
    let mut roots = rustls::RootCertStore::empty();
    roots.add(der).unwrap();
    let client_tls = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(client_tls));
    let tcp = TcpStream::connect(addr).await.unwrap();
    let mut tls = connector
        .connect(ServerName::try_from("localhost").unwrap(), tcp)
        .await
        .unwrap();
    tls.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .unwrap();
    let mut seen = seen;
    let got = tokio::time::timeout(Duration::from_secs(10), seen.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(got, (true, true), "terminated TLS and its exporter");
    let mut response = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(10), tls.read_to_end(&mut response)).await;
    assert!(response.starts_with(b"HTTP/1.1 204"), "{response:?}");
    listener.close();
    serving.abort();
}

#[tokio::test]
async fn stopping_an_upgrade_interrupts_its_partial_response_head() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut cfg = ListenerConfig::default();
    let (called, mut calls) = tokio::sync::mpsc::unbounded_channel();
    cfg.admission = Some(zmux::Admission::new(0, |_, _| {
        zmux::AdmissionVerdict::takeover()
    }));
    cfg.fallback = Some(zmux::Fallback::new(move |_| {
        called.send(()).unwrap();
        async {}
    }));
    let listener = Listener::new(Config::default(), cfg).unwrap();
    let peer = (std::net::Ipv4Addr::LOCALHOST, 0).into();
    let entry = listener.adapter().enter(peer, None).unwrap();
    let (io, mut other) = tokio::io::duplex(1);
    let l = listener.clone();
    let handler = tokio::spawn(async move {
        zmux_websocket::accept(
            io,
            entry,
            |_| zmux::CarrierInfo::new(),
            &l,
            &zmux_websocket::Options::default(),
        )
        .await
        .unwrap()
    });
    other
        .write_all(&upgrade_request(Some("qmux-02")))
        .await
        .unwrap();
    assert_eq!(other.read_u8().await.unwrap(), b'H');
    listener.close();
    assert!(matches!(
        handler.await.unwrap(),
        zmux_websocket::Upgrade::Ended
    ));
    assert!(calls.try_recv().is_err());
}

#[tokio::test(start_paused = true)]
async fn deferred_upgrade_uses_the_peek_deadline_for_write_and_flush() {
    use std::io::{Cursor, Result};
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use tokio::io::{AsyncWrite, ReadBuf};

    struct Response {
        head: Cursor<Vec<u8>>,
        block_write: bool,
        written: Vec<u8>,
    }
    impl tokio::io::AsyncRead for Response {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<Result<()>> {
            Pin::new(&mut self.head).poll_read(cx, buf)
        }
    }
    impl AsyncWrite for Response {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<Result<usize>> {
            if self.block_write {
                return Poll::Pending;
            }
            self.written.extend_from_slice(buf);
            Poll::Ready(Ok(buf.len()))
        }
        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Result<()>> {
            assert!(self.written.starts_with(b"HTTP/1.1 101 "));
            Poll::Pending
        }
        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    struct Deferred;
    impl zmux::Decide for Deferred {
        fn decide(
            &self,
            _: zmux::CarrierInfo,
            _: &[u8],
        ) -> zmux::Decision<zmux::AdmissionDecision> {
            zmux::Decision::later(async {
                tokio::time::sleep(Duration::from_secs(1)).await;
                zmux::AdmissionVerdict::Defer.into()
            })
        }
    }

    for block_write in [true, false] {
        let peek = Duration::from_secs(2);
        let mut config = ListenerConfig::default();
        config.admission = Some(zmux::Admission::with_decider(1, Deferred).with_peek_timeout(peek));
        let listener = Listener::new(Config::default(), config).unwrap();
        let entry = listener
            .adapter()
            .enter("127.0.0.1:1234".parse().unwrap(), None)
            .unwrap();
        let start = tokio::time::Instant::now();
        let result = zmux_websocket::accept(
            Response {
                head: Cursor::new(upgrade_request(Some("qmux-02"))),
                block_write,
                written: Vec::new(),
            },
            entry,
            |_| zmux::CarrierInfo::new(),
            &listener,
            &zmux_websocket::Options::default(),
        )
        .await
        .unwrap();
        assert!(matches!(result, zmux_websocket::Upgrade::Ended));
        assert_eq!(start.elapsed(), peek);
        let stats = listener.stats().admission;
        assert_eq!((stats.peek_timed_out, stats.closed), (1, 0));
    }
}
