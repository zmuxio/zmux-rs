//! The one-way carriers over loopback: a split
//! bootstrap (an uplink `POST` and a downlink `GET` paired by a token) over
//! HTTP/1.1 and HTTP/2, with and without prefix authentication; a downlink
//! joined by one paired Join; the downlink response headers; forwarded early data
//! answered 425; and the source a trusted intermediary reports.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::net::{TcpListener, TcpStream};
use zmux::{Config, Listener, ListenerConfig, PipeAuth, PipeOptions, Session, TrustedProxies};
use zmux_http::{Http2Connection, Options};

async fn server_with(
    config: Config,
    limits: ListenerConfig,
    options: Options,
) -> (String, Listener) {
    let listener = Listener::new(config, limits).expect("valid listener configuration");
    let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = tcp.local_addr().unwrap().to_string();
    tokio::spawn(zmux_http::serve(listener.clone(), tcp, options));
    (addr, listener)
}

/// A stream each way, every byte checked, then a close the peer sees.
async fn exchange(client: Session, server: Session) {
    let echo = tokio::spawn(async move {
        let (mut s, mut r) = server.accept_bi().await.unwrap();
        let got = r.read_to_end(1 << 20).await.unwrap();
        s.write_all(&got).await.unwrap();
        s.finish().unwrap();
        server.closing().await
    });
    let data: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
    let (mut s, mut r) = client.open_bi().await.unwrap();
    s.write_all(&data).await.unwrap();
    s.finish().unwrap();
    assert_eq!(r.read_to_end(1 << 20).await.unwrap(), data);
    client.close().await;
    tokio::time::timeout(Duration::from_secs(5), echo)
        .await
        .unwrap()
        .unwrap();
}

fn admitted(mut limits: ListenerConfig, admission: zmux::Admission) -> ListenerConfig {
    limits.admission = Some(admission);
    limits
}

fn prefix_auth() -> (zmux::PrefixAuth, zmux::Admission) {
    let auth = zmux::PrefixAuth::new(b"psk", Duration::from_secs(30), false).unwrap();
    let verifier = Arc::new(zmux::PrefixAuthVerifier::new(auth.clone(), 1, 1024));
    (auth, zmux::Admission::prefix_auth(verifier))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn split_bootstrap_over_http1_and_http2() {
    tokio::time::timeout(Duration::from_secs(60), async {
        for admitted in [false, true] {
            let (auth, admission) = prefix_auth();
            let mut limits = ListenerConfig::default();
            let client_opts = if admitted {
                limits.admission = Some(admission);
                Options::default().with_carrier_credential(Arc::new(auth))
            } else {
                Options::default()
            };
            let (addr, listener) = server_with(Config::default(), limits, Options::default()).await;
            let client = zmux_http::connect_http1_split(&addr, &client_opts, Config::default())
                .await
                .unwrap();
            exchange(client, listener.accept().await.unwrap()).await;
            let h2 = Http2Connection::connect(&addr, client_opts.clone())
                .await
                .unwrap();
            let client = h2.connect_split_session(Config::default()).await.unwrap();
            let server = listener.accept().await.unwrap();
            assert_kind([&client, &server], zmux::CarrierKind::Split);
            exchange(client, server).await;
            assert_eq!(listener.stats().sessions, 2, "admitted {admitted}");
        }
    })
    .await
    .unwrap();
}

/// Both ends pairing by another field: the split bootstrap works, and a
/// server pairing by the default field does not take the halves.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn split_bootstrap_with_another_pair_field() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let opts = Options::default().with_pair_field(zmux_http::PairField::new("X-Tie").unwrap());
        let (addr, listener) =
            server_with(Config::default(), ListenerConfig::default(), opts.clone()).await;
        let client = zmux_http::connect_http1_split(&addr, &opts, Config::default())
            .await
            .unwrap();
        exchange(client, listener.accept().await.unwrap()).await;

        let (addr, _listener) = server_with(
            Config::default(),
            ListenerConfig::default(),
            Options::default(),
        )
        .await;
        let opts = opts.with_timeout(Duration::from_secs(2));
        assert!(
            zmux_http::connect_http1_split(&addr, &opts, Config::default())
                .await
                .is_err()
        );
    })
    .await
    .unwrap();
}

/// Without the credential, neither half is accepted: the downlink's header
/// token and the uplink's prefix are both checked.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn split_bootstrap_without_a_credential_is_refused() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let (_, admission) = prefix_auth();
        let (addr, listener) = server_with(
            Config::default(),
            admitted(ListenerConfig::default(), admission),
            Options::default(),
        )
        .await;
        let opts = Options::default().with_timeout(Duration::from_secs(2));
        let r = zmux_http::connect_http1_split(&addr, &opts, Config::default()).await;
        assert!(r.is_err());
        assert_eq!(listener.stats().sessions, 0);
    })
    .await
    .unwrap();
}

fn multipath() -> Config {
    let mut c = Config::default();
    c.max_pipes = 4;
    c.pipe_auth = PipeAuth::psk(*b"http-carriers-psk-0123456789abcd").with_end_to_end();
    c
}

/// A split carrier, an uplink `POST` and a downlink `GET` paired by a token, joins an
/// established session: it then has two pipes.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_split_carrier_joins() {
    tokio::time::timeout(Duration::from_secs(30), async {
        for http2 in [false, true] {
            let (addr, listener) =
                server_with(multipath(), ListenerConfig::default(), Options::default()).await;
            let opts = Options::default();
            let h2 = if http2 {
                Some(Http2Connection::connect(&addr, opts.clone()).await.unwrap())
            } else {
                None
            };
            let client = match &h2 {
                Some(h2) => h2.connect_session(multipath()).await.unwrap(),
                None => zmux_http::connect_http1(&addr, &opts, multipath())
                    .await
                    .unwrap(),
            };
            let server = listener.accept().await.unwrap();
            let joined = tokio::time::timeout(Duration::from_secs(5), async {
                match &h2 {
                    Some(h2) => h2.join_split(&client, PipeOptions::default()).await,
                    None => {
                        let a = addr.clone();
                        zmux_http::join_http1_split_with(
                            &client,
                            move || {
                                let a = a.clone();
                                async move {
                                    let tcp = TcpStream::connect(a).await?;
                                    tcp.set_nodelay(true)?;
                                    Ok(tcp)
                                }
                            },
                            &addr,
                            &opts,
                            PipeOptions::default(),
                        )
                        .await
                    }
                }
            })
            .await
            .expect("joined in time");
            joined.unwrap();
            assert_eq!(client.pipes().len(), 2, "http2 {http2}");
            // The joiner is done once Confirm is written; the listener counts the join when
            // it has read that, and the exchange ends with a close of the session.
            while listener.stats().joins == 0 {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
            exchange(client, server).await;
            assert_eq!(listener.stats().joins, 1);
        }
    })
    .await
    .unwrap();
}

/// A raw HTTP/1.1 request; the response head, as text.
async fn raw(addr: &str, request: &str) -> String {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut tcp = TcpStream::connect(addr).await.unwrap();
    tcp.write_all(request.as_bytes()).await.unwrap();
    let mut buf = vec![0u8; 4096];
    let mut got = Vec::new();
    loop {
        let n = tcp.read(&mut buf).await.unwrap();
        if n == 0 {
            break;
        }
        got.extend_from_slice(&buf[..n]);
        if got.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }
    String::from_utf8_lossy(&got).to_lowercase()
}

/// A downlink's response asks proxies neither to cache nor to buffer it and
/// has no length; a carrier request forwarded from early data is answered
/// 425 before any admission, and a request of no carrier is not.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn downlink_headers_and_early_data() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let (auth, admission) = prefix_auth();
        let (addr, listener) = server_with(
            Config::default(),
            admitted(ListenerConfig::default(), admission),
            Options::default(),
        )
        .await;
        let token = zmux::PrefixAuth::header_value(&auth.token(None).unwrap());
        let get = format!(
            "GET /zmux HTTP/1.1\r\nHost: x\r\nZmux-Pipe-Pair: AAECAwQFBgcICQoLDA0ODw\r\n\
             Zmux-Prefix-Auth: {token}\r\n\r\n"
        );
        let head = raw(&addr, &get).await;
        assert!(head.starts_with("http/1.1 200"), "{head}");
        assert!(head.contains("cache-control: no-store"), "{head}");
        assert!(head.contains("x-accel-buffering: no"), "{head}");
        assert!(head.contains("connection: close"), "{head}");
        assert!(head.contains("transfer-encoding: chunked"), "{head}");
        assert!(!head.contains("content-length"), "{head}");
        for request in [
            "POST /zmux HTTP/1.1\r\nHost: x\r\nEarly-Data: 1\r\nTransfer-Encoding: chunked\r\n\r\n",
            "GET /zmux HTTP/1.1\r\nHost: x\r\nEarly-Data: 1\r\nZmux-Pipe-Pair: AAECAwQFBgcICQoLDA0ODw\r\n\r\n",
        ] {
            let head = raw(&addr, request).await;
            assert!(head.starts_with("http/1.1 425"), "{head}");
        }
        // Each 425 is a setup failure, its connection not counted again.
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(listener.stats().setup_failures, 2);
        let head = raw(&addr, "GET /zmux HTTP/1.1\r\nHost: x\r\nEarly-Data: 1\r\n\r\n").await;
        assert!(head.starts_with("http/1.1 404"), "{head}");
    })
    .await
    .unwrap();
}

/// The admission and the listener see the client a trusted intermediary
/// reports in its forwarding header, and the peer itself when the peer is
/// not trusted.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_trusted_intermediary_reports_the_source() {
    tokio::time::timeout(Duration::from_secs(30), async {
        for (net, expect) in [("127.0.0.0/8", "198.51.100.7"), ("10.0.0.0/8", "127.0.0.1")] {
            let seen: Arc<Mutex<Option<SocketAddr>>> = Arc::default();
            let s = seen.clone();
            let admission = zmux::Admission::new(0, move |info, _| {
                *s.lock().unwrap() = info.source;
                zmux::AdmissionVerdict::accept(0)
            });
            let mut limits = ListenerConfig::default();
            limits.trusted_proxies = TrustedProxies::new()
                .with_net(net.parse().unwrap())
                .with_forwarded_header("X-Forwarded-For");
            limits.admission = Some(admission);
            let (addr, _listener) =
                server_with(Config::default(), limits, Options::default()).await;
            let head = raw(
                &addr,
                "GET /zmux HTTP/1.1\r\nHost: x\r\nX-Forwarded-For: 1.2.3.4, 198.51.100.7\r\n\
                 Zmux-Pipe-Pair: AAECAwQFBgcICQoLDA0ODw\r\n\r\n",
            )
            .await;
            assert!(head.starts_with("http/1.1 200"), "{head}");
            let got = seen.lock().unwrap().unwrap();
            assert_eq!(got.ip().to_string(), expect, "trusting {net}");
        }
    })
    .await
    .unwrap();
}

/// Pipe 0 of each session is of carrier kind `kind`.
fn assert_kind(sessions: [&Session; 2], kind: zmux::CarrierKind) {
    for s in sessions {
        let p = s.pipe(zmux::PipeId::new(0)).unwrap();
        assert_eq!(p.stats().unwrap().carrier, Some(kind));
    }
}
