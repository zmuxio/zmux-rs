//! Carrier modes through intermediaries (API.md Section 4.8): one unified
//! endpoint with prefix authentication serves every kind, and a test proxy
//! in front of it behaves as common reverse proxies and CDNs do. Auto mode
//! picks the best kind each path passes; an explicit mode never falls back;
//! with joins, a session established on the exchange carrier moves to a
//! preferred kind.

mod proxy;

use std::sync::Arc;
use std::time::Duration;

use proxy::Profile;
use tokio::net::{TcpListener, TcpStream};
use zmux::{
    Admission, CandidateOutcome, CarrierKind, Config, Listener, ListenerConfig, Mode, ModePolicy,
    PipeAuth, PrefixAuth, PrefixAuthVerifier, Session, dial_mode,
};
use zmux_http::{Endpoint, ExchangeOptions, ExchangeServer, Options};

const PSK: &[u8] = b"an exchange key";

fn auth() -> PrefixAuth {
    PrefixAuth::new(b"prefix psk", Duration::from_secs(30), false).unwrap()
}

fn exchange_options() -> ExchangeOptions {
    ExchangeOptions::default().with_psk(PSK).with_path("/zmux")
}

/// The unified endpoint, prefix authentication on every streaming kind;
/// its address and listener.
async fn origin(config: Config) -> (std::net::SocketAddr, Listener) {
    let verifier = Arc::new(PrefixAuthVerifier::new(auth(), 1, 4096));
    let mut limits = ListenerConfig::default();
    limits.admission = Some(Admission::prefix_auth(verifier));
    let listener = Listener::new(config, limits);
    let exchange = ExchangeServer::new(&listener, exchange_options()).unwrap();
    let endpoint = Endpoint::new(listener.clone(), Options::default().with_exchange(exchange))
        .with_websocket(zmux_websocket::Options::default());
    let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = tcp.local_addr().unwrap();
    tokio::spawn(endpoint.serve(tcp));
    // Every session echoes its streams: a candidate the client gave up may
    // have started one too.
    let l = listener.clone();
    tokio::spawn(async move {
        while let Some(s) = l.accept().await {
            tokio::spawn(async move {
                while let Ok((mut send, mut recv)) = s.accept_bi().await {
                    tokio::spawn(async move {
                        if let Ok(got) = recv.read_to_end(1 << 16).await {
                            let _ = send.write_all(&got).await;
                            let _ = send.finish();
                        }
                    });
                }
            });
        }
    });
    (addr, listener)
}

fn connect(
    addr: &str,
) -> impl Fn() -> std::pin::Pin<Box<dyn std::future::Future<Output = std::io::Result<TcpStream>> + Send>>
+ Send
+ Sync
+ Clone
+ 'static {
    let addr = addr.to_owned();
    move || {
        let addr = addr.clone();
        Box::pin(async move { TcpStream::connect(addr).await })
    }
}

/// The candidates of every HTTP kind through `addr`, by kind.
fn candidate(kind: CarrierKind, addr: &str) -> zmux::Candidate {
    let credential: Arc<dyn zmux::Credential> = Arc::new(auth());
    let http = Options::default()
        .with_credential(credential.clone())
        .with_timeout(Duration::from_secs(3));
    match kind {
        CarrierKind::WebSocket => zmux_websocket::candidate(
            connect(addr),
            &format!("ws://{addr}/zmux"),
            &zmux_websocket::Options::default().with_credential(credential),
        ),
        CarrierKind::Streaming => zmux_http::streaming_candidate(connect(addr), addr, &http),
        CarrierKind::Split => zmux_http::split_candidate(connect(addr), addr, &http),
        CarrierKind::Exchange => {
            let options = exchange_options().with_credential(credential);
            zmux_http::exchange_candidate(connect(addr), addr, &options)
        }
        _ => unreachable!(),
    }
}

const ORDER: [CarrierKind; 4] = [
    CarrierKind::WebSocket,
    CarrierKind::Streaming,
    CarrierKind::Split,
    CarrierKind::Exchange,
];

fn auto(order: &[CarrierKind], addr: &str) -> Mode {
    Mode::auto(order.iter().map(|&k| candidate(k, addr)))
}

fn config() -> Config {
    let mut c = Config::default();
    c.handshake_timeout = Some(Duration::from_secs(4));
    c
}

/// A stream each way over the session.
async fn works(client: &Session) {
    let (mut s, mut r) = client.open_bi().await.unwrap();
    s.write_all(b"through the proxy").await.unwrap();
    s.finish().unwrap();
    assert_eq!(r.read_to_end(1024).await.unwrap(), b"through the proxy");
}

fn tries(s: &Session) -> Vec<(CarrierKind, CandidateOutcome)> {
    s.stats()
        .carrier_candidates
        .iter()
        .map(|r| (r.kind, r.outcome))
        .collect()
}

/// Auto mode without joins takes, per path, the first kind that passes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn auto_picks_the_best_kind_each_path_passes() {
    use CandidateOutcome::{Refused, TimedOut, Usable};
    use CarrierKind::{Exchange, Split, Streaming, WebSocket};
    tokio::time::timeout(Duration::from_secs(120), async {
        let (origin, _listener) = origin(config()).await;
        let direct = origin.to_string();
        let policy = ModePolicy::default().without_join();
        let cases: Vec<(&str, Option<Profile>, &[CarrierKind], Vec<_>)> = vec![
            ("direct", None, &ORDER, vec![(WebSocket, Usable)]),
            (
                "reverse proxy",
                Some(Profile::REVERSE_PROXY),
                &ORDER,
                vec![
                    (WebSocket, Refused),
                    (Streaming, TimedOut),
                    (Split, TimedOut),
                    (Exchange, Usable),
                ],
            ),
            (
                "half duplex",
                Some(Profile::HALF_DUPLEX),
                &ORDER,
                vec![(WebSocket, Refused), (Streaming, TimedOut), (Split, Usable)],
            ),
            (
                "buffering CDN",
                Some(Profile::BUFFERING_CDN),
                &ORDER,
                vec![
                    (WebSocket, Refused),
                    (Streaming, TimedOut),
                    (Split, TimedOut),
                    (Exchange, Usable),
                ],
            ),
            (
                "WebSocket only",
                Some(Profile::WEBSOCKET_ONLY),
                &[Streaming, Split, Exchange, WebSocket],
                vec![
                    (Streaming, Refused),
                    (Split, Refused),
                    (Exchange, TimedOut),
                    (WebSocket, Usable),
                ],
            ),
        ];
        for (name, profile, order, expect) in cases {
            let addr = match profile {
                Some(p) => proxy::start(p, origin).await.0,
                None => direct.clone(),
            };
            let client = dial_mode(&auto(order, &addr), config(), &policy)
                .await
                .unwrap_or_else(|e| panic!("{name}: {e}"));
            assert_eq!(tries(&client), expect, "{name}");
            works(&client).await;
            client.close(0u32.into(), b"");
        }
    })
    .await
    .unwrap();
}

/// An explicit mode reports its kind's failure and tries no other.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn explicit_never_falls_back() {
    tokio::time::timeout(Duration::from_secs(60), async {
        let (origin, listener) = origin(config()).await;
        let (addr, _p) = proxy::start(Profile::REVERSE_PROXY, origin).await;
        let e = dial_mode(
            &Mode::explicit(candidate(CarrierKind::WebSocket, &addr)),
            config(),
            &ModePolicy::default(),
        )
        .await
        .unwrap_err();
        assert_eq!(e.results.len(), 1);
        assert_eq!(e.results[0].outcome, CandidateOutcome::Refused);
        let e = dial_mode(
            &Mode::explicit(candidate(CarrierKind::Streaming, &addr)),
            config(),
            &ModePolicy::default(),
        )
        .await
        .unwrap_err();
        assert_eq!(e.results.len(), 1, "{e}");
        assert_eq!(listener.stats().sessions, 0);
        // The kind that passes works explicitly too.
        let client = dial_mode(
            &Mode::explicit(candidate(CarrierKind::Exchange, &addr)),
            config(),
            &ModePolicy::default(),
        )
        .await
        .unwrap();
        works(&client).await;
        client.close(0u32.into(), b"");
    })
    .await
    .unwrap();
}

fn multipath() -> Config {
    let mut c = config();
    c.max_pipes = 4;
    c.pipe_auth = PipeAuth::psk(*b"carrier-modes-psk-0123456789abcd");
    c
}

/// With joins, the session is established on the exchange carrier and
/// moves to the split kind (two pipes), which the half-duplex path passes;
/// the exchange pipe is retired.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn auto_with_joins_moves_off_the_exchange() {
    tokio::time::timeout(Duration::from_secs(60), async {
        let (origin, _listener) = origin(multipath()).await;
        let (addr, _p) = proxy::start(Profile::HALF_DUPLEX, origin).await;
        let mut policy = ModePolicy::default();
        policy.settle = Duration::from_millis(300);
        let client = dial_mode(&auto(&ORDER, &addr), multipath(), &policy)
            .await
            .unwrap();
        assert_eq!(client.stats().carrier, Some(CarrierKind::Exchange));
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        while client.stats().carrier != Some(CarrierKind::Split) {
            assert!(
                tokio::time::Instant::now() < deadline,
                "no switch: {:?}",
                tries(&client)
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        while client.pipes().len() != 2 {
            assert!(
                tokio::time::Instant::now() < deadline,
                "exchange not retired"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        works(&client).await;
        client.close(0u32.into(), b"");
    })
    .await
    .unwrap();
}

/// A WebSocket upgrade forwarded from TLS early data is answered 425 by
/// the endpoint and counted once as a setup failure.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_early_websocket_upgrade_is_too_early_and_a_setup_failure() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    tokio::time::timeout(Duration::from_secs(30), async {
        let (addr, listener) = origin(config()).await;
        let mut c = TcpStream::connect(addr).await.unwrap();
        c.write_all(
            b"GET /zmux HTTP/1.1\r\nHost: x\r\nEarly-Data: 1\r\nConnection: Upgrade\r\n\
              Upgrade: websocket\r\nSec-WebSocket-Version: 13\r\n\
              Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n",
        )
        .await
        .unwrap();
        let mut head = [0u8; 12];
        c.read_exact(&mut head).await.unwrap();
        assert_eq!(&head, b"HTTP/1.1 425");
        drop(c);
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(listener.stats().setup_failures, 1);
    })
    .await
    .unwrap();
}
