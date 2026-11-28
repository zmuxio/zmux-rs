//! Carrier modes through intermediaries: one unified
//! endpoint with an admission credential serves every kind, and a test proxy
//! in front of it behaves as common reverse proxies and CDNs do. The controller
//! picks the best carrier that works over each path.

#![cfg(feature = "websocket")]

mod support;

mod proxy;

use std::sync::Arc;
use std::time::Duration;

use proxy::Profile;
use tokio::net::{TcpListener, TcpStream};
use zmux::{
    Admission, CandidateOutcome, CarrierKind, Config, ControllerError, ControllerOptions, Listener,
    ListenerConfig, Session, SessionController, SessionTarget,
};
use zmux_http::{Endpoint, ExchangeOptions, ExchangeServer, Options};

const PSK: &[u8] = b"an exchange key";

#[derive(Debug)]
struct FixtureCredential;

const FIXTURE_HEADER: &str = "x-test-carrier";
const FIXTURE_PREFIX: &[u8] = b"carrier-fixture";

impl zmux::CarrierCredential for FixtureCredential {
    fn prefix(&self, _: &zmux::CarrierInfo) -> std::io::Result<Vec<u8>> {
        Ok(FIXTURE_PREFIX.to_vec())
    }

    fn header(&self, _: &zmux::CarrierInfo) -> std::io::Result<(String, String)> {
        Ok((FIXTURE_HEADER.into(), "fixture".into()))
    }
}

fn exchange_options() -> ExchangeOptions {
    ExchangeOptions::default().with_psk(PSK).with_path("/zmux")
}

/// The unified endpoint, with admission on every streaming kind;
/// its address and listener.
async fn origin(config: Config) -> (std::net::SocketAddr, Listener) {
    let mut limits = ListenerConfig::default();
    limits.admission = Some(Admission::new(FIXTURE_PREFIX.len(), |info, prefix| {
        if info.is_head() {
            let mut valid = false;
            info.for_each_header(|name, value| {
                valid |= name.eq_ignore_ascii_case(FIXTURE_HEADER) && value == b"fixture";
            });
            if valid {
                zmux::AdmissionVerdict::accept(0)
            } else {
                zmux::AdmissionVerdict::Close
            }
        } else if prefix == FIXTURE_PREFIX {
            zmux::AdmissionVerdict::accept(prefix.len())
        } else {
            zmux::AdmissionVerdict::Close
        }
    }));
    let listener = Listener::new(config, limits).expect("valid listener configuration");
    let exchange = ExchangeServer::new(&listener, exchange_options()).unwrap();
    let endpoint = Endpoint::new(listener.clone(), Options::default().with_exchange(exchange))
        .unwrap()
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
) -> impl Fn() -> std::pin::Pin<Box<dyn Future<Output = std::io::Result<TcpStream>> + Send>>
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
    let credential: Arc<dyn zmux::CarrierCredential> = Arc::new(FixtureCredential);
    let http = Options::default()
        .with_carrier_credential(credential.clone())
        .with_timeout(Duration::from_secs(3));
    match kind {
        CarrierKind::WebSocket => zmux_websocket::candidate(
            connect(addr),
            &format!("ws://{addr}/zmux"),
            &zmux_websocket::Options::default().with_carrier_credential(credential),
        ),
        CarrierKind::Streaming => zmux_http::candidate(connect(addr), addr, &http),
        CarrierKind::Split => zmux_http::candidate_split(connect(addr), addr, &http),
        CarrierKind::Exchange => {
            let options = exchange_options().with_carrier_credential(credential);
            zmux_http::candidate_exchange(connect(addr), addr, &options)
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

async fn open_controller(
    order: &[CarrierKind],
    addr: &str,
    domain: &str,
) -> Result<Session, ControllerError> {
    let candidates = order
        .iter()
        .zip(0..)
        .map(|(&kind, tier)| {
            candidate(kind, addr)
                .with_tier(tier)
                .with_identity(kind.name(), kind.name())
        })
        .collect();
    let controller = SessionController::new(ControllerOptions::new(domain, candidates))?;
    let (session, control) = controller.open(config(), SessionTarget::default()).await?;
    if let Some(control) = control {
        control.release().unwrap();
        control.done().await;
    }
    Ok(session)
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
#[test]
fn auto_picks_the_best_kind_each_path_passes() {
    support::run(4, 90, || async {
        use CandidateOutcome::{Refused, TimedOut, Usable};
        use CarrierKind::{Exchange, Split, Streaming, WebSocket};
        tokio::time::timeout(Duration::from_secs(120), async {
            let (origin, _listener) = origin(config()).await;
            let direct = origin.to_string();
            let cases: Vec<(&str, Option<Profile>, &[CarrierKind], Vec<_>)> = vec![
                ("direct", None, &ORDER, vec![(WebSocket, Usable)]),
                (
                    "transparent proxy",
                    Some(Profile::TRANSPARENT),
                    &[Streaming, WebSocket],
                    vec![(Streaming, Usable)],
                ),
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
                let client = open_controller(order, &addr, name)
                    .await
                    .unwrap_or_else(|e| panic!("{name}: {e}"));
                assert_eq!(tries(&client), expect, "{name}");
                works(&client).await;
                client.close().await;
            }
        })
        .await
        .unwrap();
    });
}

/// An explicit mode reports its kind's failure and tries no other.
#[test]
fn explicit_never_falls_back() {
    support::run(4, 90, || async {
        tokio::time::timeout(Duration::from_secs(60), async {
            let (origin, listener) = origin(config()).await;
            let (addr, _p) = proxy::start(Profile::REVERSE_PROXY, origin).await;
            let Err(ControllerError::Bootstrap(first)) =
                open_controller(&[CarrierKind::WebSocket], &addr, "single-ws").await
            else {
                panic!("expected bootstrap refusal");
            };
            assert_eq!(first.results.len(), 1);
            assert_eq!(first.results[0].outcome, CandidateOutcome::Refused);
            let Err(ControllerError::Bootstrap(second)) =
                open_controller(&[CarrierKind::Streaming], &addr, "single-streaming").await
            else {
                panic!("expected bootstrap failure");
            };
            assert_eq!(second.results.len(), 1);
            assert_eq!(listener.stats().sessions, 0);
            let client = open_controller(&[CarrierKind::Exchange], &addr, "single-exchange")
                .await
                .unwrap();
            works(&client).await;
            client.close().await;
        })
        .await
        .unwrap();
    });
}

/// A WebSocket upgrade forwarded from TLS early data is answered 425 by
/// the endpoint and counted once as a setup failure.
#[test]
fn an_early_websocket_upgrade_is_too_early_and_a_setup_failure() {
    support::run(2, 90, || async {
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
            assert_eq!(listener.stats().setup_failures, 1);
        })
        .await
        .unwrap();
    });
}
