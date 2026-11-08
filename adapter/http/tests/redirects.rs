//! Redirects of carrier requests (HTTP/1.1, HTTP/2, exchange): followed
//! within the origin with the uplink written so far repeated, refused to
//! another host and past the bound, and the URL they led to kept in the
//! carrier cache.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use zmux::{
    CarrierCache, CarrierKind, Config, Listener, ListenerConfig, Mode, ModePolicy, Session,
};
use zmux_http::Options;

/// The origin: carriers on `/zmux`.
async fn origin() -> (std::net::SocketAddr, Listener, tokio::task::JoinHandle<()>) {
    let listener = Listener::new(Config::default(), ListenerConfig::default()).unwrap();
    let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = tcp.local_addr().unwrap();
    let serving = tokio::spawn(zmux_http::serve(listener.clone(), tcp, Options::default()));
    (addr, listener, serving)
}

/// A front on its own port relaying to `backend`: a request whose target
/// starts with a path of `redirects` is answered `307` to its location
/// after the first byte of its body arrived (`{addr}` is the front's
/// address); the redirects answered are counted.
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
                let text = String::from_utf8_lossy(&head).into_owned();
                let target = text.split(' ').nth(1).unwrap_or_default().to_owned();
                if let Some((_, to)) = redirects.iter().find(|(p, _)| target.starts_with(p)) {
                    if text.starts_with("POST") {
                        // The uplink is under way before the redirect.
                        let _ = conn.read(&mut b).await;
                    }
                    count.fetch_add(1, Ordering::SeqCst);
                    let to = to.replace("{addr}", &addr.to_string());
                    let r = format!(
                        "HTTP/1.1 307 Temporary Redirect\r\nLocation: {to}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    );
                    let _ = conn.write_all(r.as_bytes()).await;
                    return;
                }
                // The origin serves `/zmux`: relay with the target rewritten.
                let head = text.replacen(&target, "/zmux", 1);
                let mut up = TcpStream::connect(backend).await.unwrap();
                up.write_all(head.as_bytes()).await.unwrap();
                let _ = tokio::io::copy_bidirectional(&mut conn, &mut up).await;
            });
        }
    });
    (addr, count, task)
}

fn connect(
    addr: std::net::SocketAddr,
) -> impl Fn() -> std::pin::Pin<Box<dyn Future<Output = std::io::Result<TcpStream>> + Send>>
+ Send
+ Sync
+ 'static {
    move || Box::pin(TcpStream::connect(addr))
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
    send.write_all(b"hello").await.unwrap();
    send.finish().unwrap();
    assert_eq!(recv.read_to_end(1 << 20).await.unwrap(), b"hello");
    echo.await.unwrap();
}

async fn within<T>(f: impl Future<Output = T>) -> T {
    tokio::time::timeout(Duration::from_secs(10), f)
        .await
        .expect("in time")
}

/// A streaming carrier follows a 307 with its preface repeated; the
/// candidate's next carrier starts at the URL it led to, which the carrier
/// cache keeps.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_redirect_is_followed_with_the_uplink_repeated() {
    let (backend, listener, serving) = origin().await;
    let (addr, count, front) = front(backend, &[("/old", "/new")]).await;
    let options = Options::default().with_path("/old");
    let candidate = zmux_http::streaming_candidate(connect(addr), &addr.to_string(), &options);
    let cache = CarrierCache::default();
    let policy = ModePolicy::new().with_cache(cache.clone(), "k");
    let mode = Mode::auto([candidate.clone()]);
    let (cs, ss) =
        within(async { tokio::join!(dial_mode_session(&mode, &policy), listener.accept()) }).await;
    let (cs, ss) = (cs, ss.unwrap());
    assert_eq!(count.load(Ordering::SeqCst), 1);
    echo(&cs, &ss).await;
    assert_eq!(
        cache.url("k", CarrierKind::Streaming, None).as_deref(),
        Some(format!("http://{addr}/new").as_str())
    );
    // The next carrier starts at /new: no redirect.
    let io = candidate.dial().await.unwrap();
    let (c2, s2) =
        within(async { tokio::join!(Session::connect(io, Config::default()), listener.accept()) })
            .await;
    assert_eq!(count.load(Ordering::SeqCst), 1);
    echo(&c2.unwrap(), &s2.unwrap()).await;
    cs.close(0u32.into(), b"").await;
    front.abort();
    serving.abort();
}

async fn dial_mode_session(mode: &Mode, policy: &ModePolicy) -> Session {
    zmux::dial_mode(mode, Config::default(), policy)
        .await
        .unwrap()
}

/// The error a failed session establishment carries, as text.
async fn refused(addr: std::net::SocketAddr, path: &str, options: Options) -> String {
    let options = options.with_path(path);
    let io = zmux_http::dial_http1(&addr.to_string(), &options)
        .await
        .unwrap();
    let Err(e) = within(Session::connect(io, Config::default())).await else {
        panic!("established");
    };
    format!("{e:?}")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn redirects_to_another_host_or_past_the_bound_are_refused() {
    let (backend, _listener, serving) = origin().await;
    let (addr, count, front) = front(
        backend,
        &[("/host", "http://localhost:1/zmux"), ("/loop", "/loop")],
    )
    .await;
    let e = refused(addr, "/host", Options::default()).await;
    assert!(e.contains("ConnectionRefused"), "{e}");
    assert_eq!(count.swap(0, Ordering::SeqCst), 1);
    let e = refused(addr, "/loop", Options::default()).await;
    assert!(e.contains("ConnectionRefused"), "{e}");
    assert_eq!(
        count.swap(0, Ordering::SeqCst),
        zmux::redirect::DEFAULT_MAX_REDIRECTS + 1
    );
    let e = refused(addr, "/loop", Options::default().with_max_redirects(0)).await;
    assert!(e.contains("ConnectionRefused"), "{e}");
    assert_eq!(count.load(Ordering::SeqCst), 1);
    front.abort();
    serving.abort();
}

/// An origin whose connections (HTTP/1.1 or HTTP/2 by prior knowledge)
/// answer a request whose path starts with a path of `redirects` with
/// the status and location given, before reading its body, and route the
/// others as `options` say (carriers on `/zmux`); the redirects answered
/// are counted.
async fn redirecting(
    listener: Listener,
    options: Options,
    redirects: &'static [(&'static str, u16, &'static str)],
) -> (
    std::net::SocketAddr,
    Listener,
    Arc<AtomicUsize>,
    tokio::task::JoinHandle<()>,
) {
    let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = tcp.local_addr().unwrap();
    let count = Arc::new(AtomicUsize::new(0));
    let (l, counted, options) = (listener.clone(), count.clone(), Arc::new(options));
    let task = tokio::spawn(async move {
        loop {
            let (conn, peer) = tcp.accept().await.unwrap();
            let (l, count, options) = (l.clone(), counted.clone(), options.clone());
            tokio::spawn(async move {
                let route_l = l.clone();
                zmux_http::serve_connection_with(
                    &l,
                    conn,
                    Some(peer),
                    &options.clone(),
                    move |req, peer, id| {
                        let (l, count, options) = (route_l.clone(), count.clone(), options.clone());
                        async move {
                            let path = req.uri().path().to_owned();
                            if let Some((_, status, to)) =
                                redirects.iter().find(|(p, ..)| path.starts_with(p))
                            {
                                count.fetch_add(1, Ordering::SeqCst);
                                let to = to.replace("{addr}", &addr.to_string());
                                return Ok(http::Response::builder()
                                    .status(*status)
                                    .header(http::header::LOCATION, to)
                                    .body(zmux_http::PipeBody::empty())
                                    .unwrap());
                            }
                            zmux_http::route_request(&l, req, peer, Some(id), &options).await
                        }
                    },
                )
                .await;
            });
        }
    });
    (addr, listener, count, task)
}

/// An HTTP/2 carrier request follows a 307 as a further request of its
/// connection, with its preface repeated, and the HTTP/2 connection's
/// next carrier starts at the URL it led to; one to another host is
/// refused.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn http2_requests_follow_redirects_within_the_origin() {
    let listener = Listener::new(Config::default(), ListenerConfig::default()).unwrap();
    let (addr, listener, count, server) = redirecting(
        listener,
        Options::default(),
        &[
            ("/old", 307, "/zmux"),
            ("/host", 308, "http://localhost:1/zmux"),
        ],
    )
    .await;
    let options = Options::default().with_path("/old");
    let conn = within(zmux_http::Http2Connection::connect(
        &addr.to_string(),
        options,
    ))
    .await
    .unwrap();
    let (cs, ss) =
        within(async { tokio::join!(conn.connect_session(Config::default()), listener.accept()) })
            .await;
    let (cs, ss) = (cs.unwrap(), ss.unwrap());
    assert_eq!(count.load(Ordering::SeqCst), 1);
    echo(&cs, &ss).await;
    cs.close(0u32.into(), b"").await;

    let conn = within(zmux_http::Http2Connection::connect(
        &addr.to_string(),
        Options::default().with_path("/host"),
    ))
    .await
    .unwrap();
    let Err(e) = within(conn.connect_session(Config::default())).await else {
        panic!("established");
    };
    let e = format!("{e:?}");
    assert!(e.contains("ConnectionRefused"), "{e}");
    assert_eq!(count.load(Ordering::SeqCst), 2);
    server.abort();
}

fn exchange_options() -> zmux_http::ExchangeOptions {
    let mut o = zmux_http::ExchangeOptions::default().with_psk(*b"exchange redirect psk");
    o.request_timeout = Duration::from_secs(2);
    o.deadline = Duration::from_secs(4);
    o.hold = Duration::from_millis(300);
    o
}

/// Every exchange request follows a 307 or 308 within the origin with its
/// body unchanged, per request; a 301 of its POST, another host, and a
/// loop past the bound fail the carrier.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn exchange_requests_follow_redirects_per_request() {
    let listener = Listener::new(Config::default(), ListenerConfig::default()).unwrap();
    let exchange = zmux_http::ExchangeServer::new(&listener, exchange_options()).unwrap();
    let (addr, listener, count, server) = redirecting(
        listener,
        Options::default().with_exchange(exchange),
        &[
            ("/old/", 307, "/zmux/exchange"),
            ("/moved/", 301, "/zmux/exchange"),
            ("/host/", 308, "http://localhost:1/zmux/exchange"),
            ("/loop/", 307, "/loop/exchange"),
        ],
    )
    .await;
    let options = exchange_options().with_path("/old/exchange");
    let io = zmux_http::dial_exchange(&addr.to_string(), &options).unwrap();
    let (cs, ss) =
        within(async { tokio::join!(Session::connect(io, Config::default()), listener.accept()) })
            .await;
    let (cs, ss) = (cs.unwrap(), ss.unwrap());
    echo(&cs, &ss).await;
    // Every request was redirected: the path is not remembered.
    let n = count.load(Ordering::SeqCst);
    assert!(n >= 3, "{n}");
    cs.close(0u32.into(), b"").await;

    for (path, hops) in [
        ("/moved/exchange", 1),
        ("/host/exchange", 1),
        ("/loop/exchange", zmux::redirect::DEFAULT_MAX_REDIRECTS + 1),
    ] {
        count.store(0, Ordering::SeqCst);
        let options = exchange_options()
            .with_path(path)
            .with_down_path("/zmux/exchange");
        let io = zmux_http::dial_exchange(&addr.to_string(), &options).unwrap();
        let start = std::time::Instant::now();
        let r = within(Session::connect(io, Config::default())).await;
        assert!(r.is_err(), "{path} established");
        // The first UP request failed the carrier, before the deadline of
        // repeats (its CLOSE may be under way as well).
        assert!(start.elapsed() < options.deadline, "{path}");
        let n = count.load(Ordering::SeqCst);
        assert!(n >= hops, "{path}: {n}");
    }
    server.abort();
}
