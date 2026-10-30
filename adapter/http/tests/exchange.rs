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
    SERIAL.lock().unwrap_or_else(|e| e.into_inner())
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
    let mut o = ExchangeOptions::default();
    o.hold = Duration::from_millis(400);
    o.idle_timeout = Duration::from_secs(2);
    o.gone_memory = Duration::from_secs(5);
    o.request_timeout = Duration::from_secs(2);
    o.deadline = Duration::from_secs(20);
    o.backoff.initial = Duration::from_millis(5);
    o.backoff.max = Duration::from_millis(100);
    o.up_piece = 64 << 10;
    o.down_piece = 64 << 10;
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
    let exchange = ExchangeServer::new(&listener, options);
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
async fn finish(client: Session, srv: Server, proxy: Option<Proxy>, base: Snapshot) {
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
    drop(proxy);
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
            ExchangeOptions::default(),
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
            finish(client, srv, None, base).await;
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
        let pipe = zmux_http::dial_exchange_split(
            zmux_http::ExchangeEndpoint::tcp(&up.addr),
            zmux_http::ExchangeEndpoint::tcp(&down.addr),
            &o,
        );
        let client = Session::connect(pipe, Config::default()).await.unwrap();
        echo(&client, 2 << 20, 7).await;
        let (u, d) = (up.stats.clone(), down.stats.clone());
        assert!(Stats::get(&u.requests) > 0 && Stats::get(&d.requests) > 0);
        drop(down);
        finish(client, srv, Some(up), base).await;
    });
}

/// One session through the proxy with `faults`; returns the proxy's counts.
async fn through_proxy(faults: Faults, seed: u64, len: usize) -> std::sync::Arc<Stats> {
    let base = snapshot();
    let o = quick();
    let srv = server(o.clone()).await;
    let proxy = Proxy::start(&srv.addr, faults, seed).await;
    let client = zmux_http::connect_exchange(&proxy.addr, &o, Config::default())
        .await
        .unwrap();
    echo(&client, len, seed).await;
    // Idle: DOWN requests are held to the end of the hold time.
    tokio::time::sleep(Duration::from_millis(900)).await;
    echo(&client, len / 4, seed + 1).await;
    let stats = proxy.stats.clone();
    finish(client, srv, Some(proxy), base).await;
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

/// A client with another PSK gets no result: its requests are refused
/// (404) and the carrier fails at the deadline, with nothing left behind
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

/// An UP piece over the server's limit is answered GONE: the carrier fails
/// at once, without repetitions up to the deadline.
#[test]
fn oversized_piece_fails_at_once() {
    run(30, async {
        let base = snapshot();
        let mut so = quick();
        so.max_up_piece = 16 << 10;
        let srv = server(so).await;
        let mut o = quick();
        o.up_piece = 1 << 20;
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
            started.elapsed() < o.deadline / 2,
            "{e:?} after {:?}",
            started.elapsed()
        );
        drop((send, recv));
        finish(client, srv, None, base).await;
    });
}
