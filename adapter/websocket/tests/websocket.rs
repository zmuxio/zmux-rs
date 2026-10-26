//! WebSocket carriers end to end over loopback TCP: one-step `connect` and
//! `serve` with the subprotocol negotiated, one record per binary message
//! on the wire, and a connection lost without a Close frame is a failure,
//! never a clean end.

use std::time::Duration;

use futures_util::StreamExt;
use tokio::net::{TcpListener, TcpStream};
use tokio_tungstenite::tungstenite::Message;
use zmux::{Config, Listener, ListenerConfig, PipeFailure, Session, SessionError};

async fn server() -> (std::net::SocketAddr, Listener, tokio::task::JoinHandle<()>) {
    let listener = Listener::new(Config::default(), ListenerConfig::default());
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
    assert!(got == data);
    s.write_all(&got).await.unwrap();
    s.finish().unwrap();
    assert!(recv.read_to_end(1 << 20).await.unwrap() == data);
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
    assert_eq!(client.protocol().as_deref(), Some("qmux-02"));
    assert_eq!(server.protocol().as_deref(), Some("qmux-02"));
    round_trip(&client, &server).await;
    client.close(0u32.into(), b"bye");
    assert!(matches!(
        server.closed().await,
        SessionError::ApplicationClosed { remote: true, .. }
    ));
    listener.close();
    serving.await.unwrap();
}

/// Message boundaries: a plain WebSocket peer receives every record as one
/// binary message, the first holding QX_TRANSPORT_PARAMETERS from its
/// first byte (SPEC.md Section 3.4), and none of them holds two records.
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
        c.handshake_timeout = Duration::from_millis(500);
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
            "moq-transport-18",
        ),
        (
            Options::for_application("chat"),
            Options::for_protocol("qmux-01.chat"),
            "qmux-01.chat",
        ),
    ] {
        let listener = Listener::new(Config::default(), ListenerConfig::default());
        let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = tcp.local_addr().unwrap();
        let serving = tokio::spawn(zmux_websocket::serve(listener.clone(), tcp, server_opts));
        let client =
            zmux_websocket::connect(format!("ws://{addr}/zmux"), &client_opts, Config::default())
                .await
                .unwrap();
        let server = listener.accept().await.unwrap();
        assert_eq!(client.protocol().as_deref(), Some(expect));
        assert_eq!(server.protocol().as_deref(), Some(expect));
        client.close(0u32.into(), b"");
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
        let mut req =
            tokio_tungstenite::tungstenite::client::IntoClientRequest::into_client_request(
                format!("ws://{to}/zmux"),
            )
            .unwrap();
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
/// positions and charges it against the non-progress budget like a
/// PADDING-only record. The injected messages are bytes the client never
/// sent, so the session ends either way: the server closes it for the load,
/// or the client first sees a PIPE_ACK above what it sent. (That a few are
/// no-ops is a trace of the core.)
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_flood_of_empty_messages_is_charged() {
    let (addr, listener, _serving) = server().await;
    let (front, relay) = empty_injector(addr, 100_000).await;
    let client = zmux_websocket::connect(
        format!("ws://{front}/zmux"),
        &Default::default(),
        Config::default(),
    )
    .await
    .unwrap();
    let e = tokio::time::timeout(Duration::from_secs(10), client.closed())
        .await
        .expect("closed by the server");
    assert!(
        matches!(
            &e,
            SessionError::TransportClosed { code, remote: true, .. }
                if *code == zmux::proto::TransportErrorCode::ZMUX_EXCESSIVE_LOAD
        ) || matches!(
            &e,
            SessionError::TransportClosed { code, remote: false, .. }
                if *code == zmux::proto::TransportErrorCode::PROTOCOL_VIOLATION
        ),
        "{e:?}"
    );
    relay.abort();
    listener.close();
}

/// wss://: `connect_tls` against a server that terminates TLS and upgrades
/// with `accept` inside the listener's `serve_with`.
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

    let listener = Listener::new(Config::default(), ListenerConfig::default());
    let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = tcp.local_addr().unwrap().port();
    let l = listener.clone();
    let serving = tokio::spawn(async move {
        l.serve_with(
            || tcp.accept(),
            move |conn, peer| {
                let tls = acceptor.clone();
                async move {
                    let conn = tls.accept(conn).await?;
                    zmux_websocket::accept(conn, Some(peer.ip()), &Default::default()).await
                }
            },
        )
        .await
    });
    let client = zmux_websocket::connect_tls(
        format!("wss://localhost:{port}/zmux"),
        &connector,
        &Default::default(),
        Config::default(),
    )
    .await
    .unwrap();
    let server = listener.accept().await.unwrap();
    assert_eq!(client.protocol().as_deref(), Some("qmux-02"));
    round_trip(&client, &server).await;
    client.close(0u32.into(), b"bye");
    serving.abort();
}

/// An out-of-band join: the reservation's header on the upgrade request.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn out_of_band_join() {
    let mut config = Config::default();
    config.pipe_auth = zmux::PipeAuth::psk(vec![7u8; 32]);
    config.max_pipes = 8;
    let listener = Listener::new(config.clone(), ListenerConfig::default());
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
    let r = client
        .reserve_pipe(zmux::PipeDirection::Bidi, zmux::PipeOptions::new())
        .unwrap();
    let mut req = tokio_tungstenite::tungstenite::client::IntoClientRequest::into_client_request(
        format!("ws://{addr}/zmux"),
    )
    .unwrap();
    req.headers_mut()
        .insert(zmux::JOIN_HEADER, r.header().parse().unwrap());
    let io = zmux_websocket::dial(req, &Default::default())
        .await
        .unwrap();
    let pipe = r.attach(io).unwrap();
    tokio::time::timeout(Duration::from_secs(5), pipe.joined())
        .await
        .unwrap()
        .unwrap();
    round_trip(&client, &server).await;
    client.close(0u32.into(), b"bye");
    serving.abort();
}
