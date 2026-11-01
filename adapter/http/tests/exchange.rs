//! The exchange carrier end to end: zmux sessions over it directly and
//! through a fault-injecting HTTP/1.0 proxy (each fault alone, then seeded
//! mixes), a wrong PSK, and every resource back at its baseline after
//! each.
//!
//! The resource counts are process-wide: the tests run one at a time.

mod exchange_proxy;

use std::sync::{Mutex, MutexGuard};
use std::time::Duration;

use exchange_proxy::{Faults, Proxy, Rng, Stats};
use sha2::{Digest, Sha256};
use tokio::net::TcpListener;
use zmux::test_hooks::{Resources, resources};
use zmux::{Config, Listener, ListenerConfig, Session};
use zmux_http::{BodyEncoding, ExchangeOptions, ExchangeServer, Options};

static SERIAL: Mutex<()> = Mutex::new(());

fn serial() -> MutexGuard<'static, ()> {
    SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Runs `f` on a fresh runtime under a watchdog of `secs` seconds.
fn run<F: Future<Output = ()>>(secs: u64, f: F) {
    let _g = serial();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        tokio::time::timeout(Duration::from_secs(secs), f)
            .await
            .expect("the test did not finish in time");
    });
}

/// Options with short timers, so that faults cost little time.
fn quick() -> ExchangeOptions {
    let mut o = ExchangeOptions::default().with_psk(*b"exchange test psk");
    o.hold = Duration::from_millis(400);
    o.idle_timeout = Duration::from_secs(2);
    // At least the deadline: a request the client repeats up to its
    // deadline is answered GONE rather than taken for a new carrier.
    o.gone_memory = Duration::from_secs(20);
    o.request_timeout = Duration::from_secs(2);
    o.deadline = Duration::from_secs(20);
    o.backoff.initial = Duration::from_millis(5);
    o.backoff.max = Duration::from_millis(100);
    o.up_piece = Some(64 << 10);
    o.down_piece = Some(64 << 10);
    o
}

struct Server {
    addr: String,
    listener: Listener,
    exchange: ExchangeServer,
    serving: tokio::task::JoinHandle<()>,
    echo: tokio::task::JoinHandle<()>,
}

/// A listener served with the exchange server; every session it accepts
/// echoes its bidirectional streams.
async fn server(options: ExchangeOptions) -> Server {
    let listener = Listener::new(Config::default(), ListenerConfig::default());
    let exchange = ExchangeServer::new(&listener, options).unwrap();
    let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = tcp.local_addr().unwrap().to_string();
    let serving = tokio::spawn(zmux_http::serve(
        listener.clone(),
        tcp,
        Options::default().with_exchange(exchange.clone()),
    ));
    let l = listener.clone();
    let echo = tokio::spawn(async move {
        let mut sessions = tokio::task::JoinSet::new();
        while let Some(s) = l.accept().await {
            sessions.spawn(async move {
                let mut streams = tokio::task::JoinSet::new();
                while let Ok((mut send, mut recv)) = s.accept_bi().await {
                    streams.spawn(async move {
                        let mut buf = vec![0u8; 64 << 10];
                        while let Ok(Some(n)) = recv.read(&mut buf).await {
                            if send.write_all(&buf[..n]).await.is_err() {
                                return;
                            }
                        }
                        let _ = send.finish();
                    });
                }
                while streams.join_next().await.is_some() {}
            });
        }
        while sessions.join_next().await.is_some() {}
    });
    Server {
        addr,
        listener,
        exchange,
        serving,
        echo,
    }
}

/// Sends `len` bytes on a new stream and checks the echo by its hash.
async fn echo(session: &Session, len: usize, seed: u64) {
    let mut rng = Rng::new(seed);
    let data: Vec<u8> = (0..len).map(|_| rng.next() as u8).collect();
    let sent = Sha256::digest(&data);
    let (mut send, mut recv) = session.open_bi().await.unwrap();
    let writer = tokio::spawn(async move {
        for c in data.chunks(100_000) {
            send.write_all(c).await.unwrap();
        }
        send.finish().unwrap();
        send
    });
    let mut hash = Sha256::new();
    let mut got = 0;
    let mut buf = vec![0u8; 64 << 10];
    while let Some(n) = recv.read(&mut buf).await.unwrap() {
        hash.update(&buf[..n]);
        got += n;
    }
    drop(writer.await.unwrap());
    assert_eq!(got, len);
    assert_eq!(hash.finalize(), sent, "the echo differs");
}

/// What must come back to its baseline.
#[derive(Debug, PartialEq, Eq)]
struct Snapshot {
    res: Resources,
    tasks: usize,
}

fn snapshot() -> Snapshot {
    Snapshot {
        res: resources(),
        tasks: tokio::runtime::Handle::current()
            .metrics()
            .num_alive_tasks(),
    }
}

/// Closes the listener and waits for its tasks.
async fn shut_down(srv: Server) {
    let Server {
        listener,
        serving,
        echo,
        ..
    } = srv;
    listener.close();
    serving.await.unwrap();
    echo.await.unwrap();
}

/// Closes both ends and waits until every resource is back at `base`.
/// `ready` is the snapshot with the server and `proxies` up and no client
/// yet: the client's exchange requests go on until each has its result
/// (an answer, or GONE once the server ended the carrier), so the path
/// stays up until the client is gone; torn down earlier, its last request
/// would be repeated until the client's deadline.
async fn finish(
    client: Session,
    srv: Server,
    proxies: Vec<Proxy>,
    base: Snapshot,
    ready: Snapshot,
) {
    client.close(0u32.into(), b"done");
    let _ = tokio::time::timeout(Duration::from_secs(5), client.closed()).await;
    drop(client);
    // The server's carriers end (complete or idle) without a close.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while srv.exchange.carriers() > 0 {
        assert!(
            tokio::time::Instant::now() < deadline,
            "carriers left: {}",
            srv.exchange.carriers()
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    // The client's requests have their results.
    loop {
        let now = snapshot();
        if now == ready {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "client tasks left\n  ready {ready:?}\n  now   {now:?}"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    drop(proxies);
    shut_down(srv).await;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        let now = snapshot();
        if now == base {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "resources not released\n  baseline {base:?}\n  now      {now:?}"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// A session over the carrier, without and with a PSK and base64 bodies:
/// a few MiB each way, several streams at once.
#[test]
fn sessions_over_the_carrier() {
    run(60, async {
        for options in [
            ExchangeOptions::default().with_unauthenticated(),
            ExchangeOptions::default()
                .with_psk(*b"a shared secret")
                .with_encoding(BodyEncoding::Base64)
                .with_path("/x/{instance}/y")
                .with_query("r"),
        ] {
            let base = snapshot();
            let mut server_options = options.clone();
            server_options.idle_timeout = Duration::from_secs(2);
            server_options.hold = Duration::from_millis(500);
            let srv = server(server_options).await;
            let ready = snapshot();
            let client = zmux_http::connect_exchange(&srv.addr, &options, Config::default())
                .await
                .unwrap();
            let streams: Vec<_> = (0..3)
                .map(|i| {
                    let c = client.clone();
                    tokio::spawn(async move { echo(&c, 3 << 20, i).await })
                })
                .collect();
            for s in streams {
                s.await.unwrap();
            }
            assert_eq!(srv.exchange.carriers(), 1);
            finish(client, srv, Vec::new(), base, ready).await;
        }
    });
}

/// UP and DOWN requests through different fronts, to different paths, of
/// the same server.
#[test]
fn split_up_and_down_targets() {
    run(60, async {
        let base = snapshot();
        let o = quick()
            .with_path("/up/{instance}/{nonce}")
            .with_down_path("/down/{instance}");
        let srv = server(o.clone()).await;
        let up = Proxy::start(&srv.addr, Faults::default(), 1).await;
        let down = Proxy::start(&srv.addr, Faults::default(), 2).await;
        let ready = snapshot();
        let pipe = zmux_http::dial_exchange_split(
            zmux_http::ExchangeEndpoint::tcp(&up.addr),
            zmux_http::ExchangeEndpoint::tcp(&down.addr),
            &o,
        )
        .unwrap();
        let client = Session::connect(pipe, Config::default()).await.unwrap();
        echo(&client, 2 << 20, 7).await;
        let (u, d) = (up.stats.clone(), down.stats.clone());
        assert!(Stats::get(&u.requests) > 0 && Stats::get(&d.requests) > 0);
        finish(client, srv, vec![up, down], base, ready).await;
    });
}

/// One session through the proxy with `faults`; returns the proxy's counts.
async fn through_proxy(faults: Faults, seed: u64, len: usize) -> std::sync::Arc<Stats> {
    let base = snapshot();
    let o = quick();
    let srv = server(o.clone()).await;
    let proxy = Proxy::start(&srv.addr, faults, seed).await;
    let ready = snapshot();
    let client = zmux_http::connect_exchange(&proxy.addr, &o, Config::default())
        .await
        .unwrap();
    echo(&client, len, seed).await;
    // Idle: DOWN requests are held to the end of the hold time.
    tokio::time::sleep(Duration::from_millis(900)).await;
    echo(&client, len / 4, seed + 1).await;
    let stats = proxy.stats.clone();
    finish(client, srv, vec![proxy], base, ready).await;
    stats
}

/// The count of a fault in the proxy's counts.
type Applied = fn(&Stats) -> u64;

/// Each fault alone, with a check that it happened.
#[test]
fn each_fault_alone() {
    run(240, async {
        let p = 0.15;
        let cases: [(&str, Faults, Applied); 7] = [
            (
                "drop request",
                Faults {
                    drop_request: p,
                    ..Faults::default()
                },
                |s| Stats::get(&s.dropped_requests),
            ),
            (
                "drop response",
                Faults {
                    drop_response: p,
                    ..Faults::default()
                },
                |s| Stats::get(&s.dropped_responses),
            ),
            (
                "5xx",
                Faults {
                    error: p,
                    ..Faults::default()
                },
                |s| Stats::get(&s.errors),
            ),
            (
                "duplicate",
                Faults {
                    duplicate: p,
                    ..Faults::default()
                },
                |s| Stats::get(&s.duplicates),
            ),
            (
                "replay",
                Faults {
                    replay: p,
                    ..Faults::default()
                },
                |s| Stats::get(&s.replays),
            ),
            (
                "reorder",
                Faults {
                    reorder: Duration::from_millis(30),
                    ..Faults::default()
                },
                |s| Stats::get(&s.requests),
            ),
            // Held DOWN requests (400 ms) are cut at 150 ms.
            (
                "cut",
                Faults {
                    cut: Some(Duration::from_millis(150)),
                    ..Faults::default()
                },
                |s| Stats::get(&s.cuts),
            ),
        ];
        for (i, (name, faults, applied)) in cases.into_iter().enumerate() {
            let stats = through_proxy(faults, 100 + i as u64, 2 << 20).await;
            assert!(
                applied(&stats) > 0,
                "{name}: the fault never happened: {stats:?}"
            );
        }
    });
}

/// Every fault at once, seeded; `ZMUX_EXCHANGE_SEEDS` sets the number of
/// seeds (default 3).
#[test]
fn seeded_fault_mix() {
    let seeds: u64 = std::env::var("ZMUX_EXCHANGE_SEEDS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(3);
    run(120 * seeds, async move {
        for seed in 0..seeds {
            let faults = Faults {
                drop_request: 0.05,
                drop_response: 0.05,
                error: 0.05,
                duplicate: 0.05,
                replay: 0.05,
                reorder: Duration::from_millis(20),
                cut: Some(Duration::from_millis(250)),
            };
            let stats = through_proxy(faults, 1000 + seed, 1 << 20).await;
            assert!(Stats::get(&stats.requests) > 0, "seed {seed}");
        }
    });
}

/// Without a PSK the carrier must be chosen unauthenticated, and not both.
#[test]
fn authentication_is_required_unless_declined() {
    let _g = serial();
    let listener = Listener::new(Config::default(), ListenerConfig::default());
    let e = zmux_http::ExchangeEndpoint::tcp("127.0.0.1:1");
    for o in [
        ExchangeOptions::default(),
        ExchangeOptions::default()
            .with_psk(*b"k")
            .with_unauthenticated(),
    ] {
        let kind = |r: std::io::Result<()>| r.unwrap_err().kind();
        assert_eq!(
            kind(ExchangeServer::new(&listener, o.clone()).map(drop)),
            std::io::ErrorKind::InvalidInput
        );
        assert_eq!(
            kind(zmux_http::dial_exchange_split(e.clone(), e.clone(), &o).map(drop)),
            std::io::ErrorKind::InvalidInput
        );
    }
}

/// A client with another PSK gets no result: its requests go to the
/// fallback (404 without one) and the carrier fails at the deadline, with nothing left behind
/// on either side.
#[test]
fn wrong_psk_fails_the_carrier() {
    run(30, async {
        let base = snapshot();
        let srv = server(quick().with_psk(*b"right")).await;
        let mut o = quick().with_psk(*b"wrong");
        o.deadline = Duration::from_millis(500);
        let r = zmux_http::connect_exchange(&srv.addr, &o, Config::default()).await;
        assert!(r.is_err(), "connected with a wrong PSK");
        assert_eq!(srv.exchange.carriers(), 0);
        shut_down(srv).await;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        while snapshot() != base {
            assert!(
                tokio::time::Instant::now() < deadline,
                "{:?} vs {base:?}",
                snapshot()
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    });
}

/// An UP piece over the server's limit is not authenticated: the carrier
/// fails at the client's deadline.
#[test]
fn oversized_piece_fails_at_the_deadline() {
    run(30, async {
        let base = snapshot();
        let mut so = quick();
        so.max_up_piece = Some(16 << 10);
        let srv = server(so).await;
        let ready = snapshot();
        let mut o = quick();
        o.up_piece = Some(1 << 20);
        o.deadline = Duration::from_secs(1);
        let client = zmux_http::connect_exchange(&srv.addr, &o, Config::default())
            .await
            .unwrap();
        let started = tokio::time::Instant::now();
        let (mut send, recv) = client.open_bi().await.unwrap();
        let _ = send.write_all(&vec![7u8; 1 << 20]).await;
        let e = tokio::time::timeout(Duration::from_secs(10), client.closed())
            .await
            .expect("the session ends with its only carrier");
        assert!(
            started.elapsed() >= o.deadline / 2 && started.elapsed() < o.deadline * 5,
            "{e:?} after {:?}",
            started.elapsed()
        );
        drop((send, recv));
        finish(client, srv, Vec::new(), base, ready).await;
    });
}

/// The serve loop hands every request it does not take to the fallback,
/// with the body bytes it read replayed: other paths, other methods and
/// exchange requests that are not authenticated alike.
#[test]
fn fallback_gets_requests_with_their_bodies() {
    use http_body::Body as _;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    run(30, async {
        let listener = Listener::new(Config::default(), ListenerConfig::default());
        let exchange = ExchangeServer::new(&listener, quick()).unwrap();
        let fallback =
            zmux_http::HttpFallback::new(|req: zmux_http::FallbackRequest, _| async move {
                let line = format!("{} {} ", req.method(), req.uri().path());
                let mut body = req.into_body();
                let mut got = line.into_bytes();
                while let Some(Ok(f)) =
                    std::future::poll_fn(|cx| std::pin::Pin::new(&mut body).poll_frame(cx)).await
                {
                    if let Ok(d) = f.into_data() {
                        got.extend_from_slice(&d);
                    }
                }
                http::Response::new(zmux_http::PipeBody::full(got))
            });
        let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = tcp.local_addr().unwrap();
        let serving = tokio::spawn(zmux_http::serve(
            listener.clone(),
            tcp,
            Options::default()
                .with_exchange(exchange)
                .with_fallback(fallback),
        ));
        for (req, want) in [
            (
                "POST /zmux/exchange?n=1 HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello",
                "POST /zmux/exchange hello",
            ),
            (
                "GET /zmux/exchange HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
                "GET /zmux/exchange ",
            ),
            (
                "PUT /other HTTP/1.1\r\nHost: x\r\nContent-Length: 3\r\nConnection: close\r\n\r\nabc",
                "PUT /other abc",
            ),
        ] {
            let mut c = tokio::net::TcpStream::connect(addr).await.unwrap();
            c.write_all(req.as_bytes()).await.unwrap();
            let mut resp = String::new();
            c.read_to_string(&mut resp).await.unwrap();
            assert!(resp.starts_with("HTTP/1.1 200"), "{resp}");
            assert!(resp.ends_with(want), "{resp}");
        }
        listener.close();
        let _ = serving.await;
    });
}

/// An exchange request forwarded from TLS early data is answered 425 and
/// counted once as a setup failure, its connection not again.
#[test]
fn early_data_is_too_early_and_a_setup_failure() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    run(30, async {
        let srv = server(quick()).await;
        let mut c = tokio::net::TcpStream::connect(&srv.addr).await.unwrap();
        c.write_all(
            b"POST /zmux/exchange HTTP/1.1\r\nHost: x\r\nEarly-Data: 1\r\n\
              Content-Length: 5\r\nConnection: close\r\n\r\nhello",
        )
        .await
        .unwrap();
        let mut resp = String::new();
        c.read_to_string(&mut resp).await.unwrap();
        assert!(resp.starts_with("HTTP/1.1 425"), "{resp}");
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(srv.listener.stats().setup_failures, 1);
        shut_down(srv).await;
    });
}
