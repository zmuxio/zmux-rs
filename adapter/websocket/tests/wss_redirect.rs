//! wss:// carriers have the TLS exporter and are declared secure at both
//! ends, so a Bound join works over them; clients follow same-host
//! redirects of the upgrade within their bound and refuse the others.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use zmux::{Config, Listener, ListenerConfig, PipeAuth, PipeOptions, Session};

fn tls() -> (tokio_rustls::TlsAcceptor, tokio_rustls::TlsConnector) {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let der = CertificateDer::from(cert.cert.der().to_vec());
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()));
    let server = rustls::ServerConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![der.clone()], key)
        .unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(der).unwrap();
    let client = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    (
        tokio_rustls::TlsAcceptor::from(Arc::new(server)),
        tokio_rustls::TlsConnector::from(Arc::new(client)),
    )
}

async fn echo(client: &Session, server: &Session) {
    let server = server.clone();
    let echo = tokio::spawn(async move {
        let (mut send, mut recv) = server.accept_bi().await.unwrap();
        let data = recv.read_to_end(1 << 20).await.unwrap();
        send.write_all(&data).await.unwrap();
        send.finish().unwrap();
    });
    let (mut send, mut recv) = client.open_bi().await.unwrap();
    let data: Vec<u8> = (0..(64 << 10)).map(|i| (i % 251) as u8).collect();
    send.write_all(&data).await.unwrap();
    send.finish().unwrap();
    assert_eq!(recv.read_to_end(1 << 20).await.unwrap(), data);
    echo.await.unwrap();
}

/// The session secret comes from the bootstrap carrier's exporter, the
/// same at both ends, and a further wss:// carrier joins Bound, which the
/// configuration allows only on a carrier declared secure.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_bound_join_over_wss() {
    let mut config = Config::multipath(PipeAuth::exporter().with_end_to_end());
    config.allow_record_mode = Some(zmux::AllowRecordMode::new(|c, mode, _| {
        mode != zmux::RecordMode::Bound || c.secure
    }));
    let (acceptor, connector) = tls();
    let listener = Listener::new(config.clone(), ListenerConfig::default()).unwrap();
    let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = tcp.local_addr().unwrap().port();
    let serving = tokio::spawn(zmux_websocket::serve_tls(
        listener.clone(),
        tcp,
        acceptor,
        Default::default(),
    ));
    let url = format!("wss://localhost:{port}/zmux");
    let options = zmux_websocket::Options::default();
    let cs = zmux_websocket::connect_tls(url.as_str(), &connector, &options, config)
        .await
        .unwrap();
    let ss = listener.accept().await.unwrap();
    assert_eq!(
        cs.export_keying_material("app", b"", 16).unwrap(),
        ss.export_keying_material("app", b"", 16).unwrap()
    );
    let io = zmux_websocket::dial_tls(url.as_str(), &connector, &options)
        .await
        .unwrap();
    let pipe = cs
        .begin_add_pipe(
            io,
            PipeOptions::new().with_record_mode(zmux::RecordMode::Bound),
        )
        .unwrap();
    tokio::time::timeout(Duration::from_secs(10), pipe.joined())
        .await
        .expect("joined in time")
        .unwrap();
    echo(&cs, &ss).await;
    cs.close().await;
    listener.close();
    serving.await.unwrap();
}

/// A front on the server's port: a request whose target starts with one of
/// `redirects`' paths is answered with its status and location, every
/// other one is relayed to `backend`. Counts the redirects answered.
async fn front(
    backend: std::net::SocketAddr,
    redirects: &'static [(&'static str, &'static str)],
) -> (
    std::net::SocketAddr,
    Arc<AtomicUsize>,
    tokio::task::JoinHandle<()>,
) {
    let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = tcp.local_addr().unwrap();
    let count = Arc::new(AtomicUsize::new(0));
    let counted = count.clone();
    let task = tokio::spawn(async move {
        loop {
            let (mut conn, _) = tcp.accept().await.unwrap();
            let count = counted.clone();
            tokio::spawn(async move {
                let mut head = Vec::new();
                let mut b = [0u8; 1];
                while !head.ends_with(b"\r\n\r\n") {
                    if conn.read(&mut b).await.unwrap_or(0) == 0 {
                        return;
                    }
                    head.push(b[0]);
                }
                let line = String::from_utf8_lossy(&head);
                let target = line.split(' ').nth(1).unwrap_or_default().to_owned();
                if let Some((_, to)) = redirects.iter().find(|(p, _)| target.starts_with(p)) {
                    count.fetch_add(1, Ordering::SeqCst);
                    let to = to.replace("{addr}", &addr.to_string());
                    let r = format!(
                        "HTTP/1.1 302 Found\r\nLocation: {to}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    );
                    let _ = conn.write_all(r.as_bytes()).await;
                    return;
                }
                let mut up = TcpStream::connect(backend).await.unwrap();
                up.write_all(&head).await.unwrap();
                let _ = tokio::io::copy_bidirectional(&mut conn, &mut up).await;
            });
        }
    });
    (addr, count, task)
}

async fn ws_server() -> (std::net::SocketAddr, Listener, tokio::task::JoinHandle<()>) {
    let listener = Listener::new(Config::default(), ListenerConfig::default()).unwrap();
    let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = tcp.local_addr().unwrap();
    let serving = tokio::spawn(zmux_websocket::serve(
        listener.clone(),
        tcp,
        Default::default(),
    ));
    (addr, listener, serving)
}

fn redirect_error(e: &std::io::Error) -> &zmux_websocket::RedirectError {
    e.get_ref()
        .and_then(|e| e.downcast_ref())
        .unwrap_or_else(|| panic!("not a redirect error: {e}"))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_same_host_redirect_is_followed() {
    let (backend, listener, serving) = ws_server().await;
    let (addr, count, front) = front(backend, &[("/old", "/zmux")]).await;
    let cs = zmux_websocket::connect(
        format!("ws://{addr}/old"),
        &Default::default(),
        Config::default(),
    )
    .await
    .unwrap();
    let ss = listener.accept().await.unwrap();
    assert_eq!(count.load(Ordering::SeqCst), 1);
    echo(&cs, &ss).await;
    // Following none, the redirect is a refusal.
    let options = zmux_websocket::Options::default().with_max_redirects(0);
    let e = zmux_websocket::dial(format!("ws://{addr}/old"), &options)
        .await
        .unwrap_err();
    assert_eq!(redirect_error(&e).reason, "too many redirects");
    cs.close().await;
    front.abort();
    serving.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn redirects_to_another_host_or_port_are_refused() {
    let (backend, _listener, serving) = ws_server().await;
    let (addr, count, front) = front(
        backend,
        &[
            ("/host", "ws://localhost:1/zmux"),
            ("/port", "ws://127.0.0.1:1/zmux"),
            ("/down", "wss://127.0.0.1:1/zmux"),
        ],
    )
    .await;
    for (path, reason) in [("/host", "another host"), ("/port", "another port")] {
        let e = zmux_websocket::dial(format!("ws://{addr}{path}"), &Default::default())
            .await
            .unwrap_err();
        assert_eq!(e.kind(), std::io::ErrorKind::ConnectionRefused);
        assert_eq!(redirect_error(&e).reason, reason);
    }
    assert_eq!(count.load(Ordering::SeqCst), 2);
    front.abort();
    serving.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn redirects_stop_at_the_bound() {
    let (backend, _listener, serving) = ws_server().await;
    let (addr, count, front) = front(backend, &[("/loop", "/loop")]).await;
    let e = zmux_websocket::dial(format!("ws://{addr}/loop"), &Default::default())
        .await
        .unwrap_err();
    assert_eq!(redirect_error(&e).reason, "too many redirects");
    assert_eq!(
        count.load(Ordering::SeqCst),
        zmux_websocket::DEFAULT_MAX_REDIRECTS + 1
    );
    let options = zmux_websocket::Options::default().with_max_redirects(2);
    count.store(0, Ordering::SeqCst);
    assert!(
        zmux_websocket::dial(format!("ws://{addr}/loop"), &options)
            .await
            .is_err()
    );
    assert_eq!(count.load(Ordering::SeqCst), 3);
    front.abort();
    serving.abort();
}

/// A candidate's later carriers start at the URL its redirect led to.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_candidate_starts_at_the_redirected_url() {
    let (backend, listener, serving) = ws_server().await;
    let (addr, count, front) = front(backend, &[("/old", "/zmux")]).await;
    let candidate = zmux_websocket::candidate(
        move || TcpStream::connect(addr),
        &format!("ws://{addr}/old"),
        &Default::default(),
    );
    let mut sessions = Vec::new();
    for _ in 0..2 {
        let io = candidate.dial().await.unwrap();
        let (cs, ss) = tokio::join!(Session::connect(io, Config::default()), listener.accept());
        sessions.push((cs.unwrap(), ss.unwrap()));
    }
    assert_eq!(count.load(Ordering::SeqCst), 1);
    for (cs, _) in &sessions {
        cs.close().await;
    }
    front.abort();
    serving.abort();
}

/// A carrier mode keeps the URL redirects led a usable kind to in its
/// cache, and a new candidate under the same key starts there.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_carrier_mode_caches_the_redirected_url() {
    let (backend, listener, serving) = ws_server().await;
    let (addr, count, front) = front(backend, &[("/old", "/zmux")]).await;
    let cache = zmux::CarrierCache::default();
    let mut policy = zmux::CarrierChoicePolicy::new();
    policy.cache = Some(cache.clone());
    policy.key = "server".into();
    let mut sessions = Vec::new();
    for _ in 0..2 {
        let candidate = zmux_websocket::candidate(
            move || TcpStream::connect(addr),
            &format!("ws://{addr}/old"),
            &Default::default(),
        );
        let mode = zmux::CarrierChoice::auto([candidate]);
        let (cs, ss) = tokio::join!(
            zmux::dial_choice(&mode, Config::default(), &policy),
            listener.accept()
        );
        sessions.push((cs.unwrap(), ss.unwrap()));
        assert_eq!(
            cache
                .url("server", zmux::CarrierKind::WebSocket, None)
                .as_deref(),
            Some(format!("ws://{addr}/zmux").as_str())
        );
    }
    // The second candidate started at the cached URL: one redirect in all.
    assert_eq!(count.load(Ordering::SeqCst), 1);
    for (cs, _) in &sessions {
        cs.close().await;
    }
    front.abort();
    serving.abort();
}
