//! A zmux peer that runs one traffic-shaping definition over TCP, for the
//! interoperability tests of the other implementations (Go, Java).
//!
//! ```text
//! zmux-shaping-peer server            listen, print `LISTEN <addr>`, serve one session
//! zmux-shaping-peer client <addr>     dial and run the exchange
//! ```
//!
//! The environment variable `SHAPE_DEF` names a shaping definition (JSON,
//! `zmux-shaping`'s machine format, as in `defs/`); unset or empty, the side runs unshaped.
//!
//! The exchange: the client opens eight bidirectional streams and sends
//! `200000 + i * 7919` pseudo-random bytes on stream `i` (the generator is
//! xorshift64 seeded with `i + 1`, so every implementation can produce and
//! check them); the server echoes each stream back and the client compares.
//! Each side prints `STATS wire_spent=<n> injected=<n> dropped=<n> clamped=<n>
//! faults=<n>` from the session's shaping statistics and `OK`. A shaped side
//! fails (exit status 1) when its session added no wire bytes or counted a
//! fault. A 60-second deadline ends the process.

use std::sync::Arc;
use std::time::Duration;

use zmux::{Config, PipeIo, Session};

const STREAMS: usize = 8;

fn die(m: &str) -> ! {
    eprintln!("{m}");
    std::process::exit(1)
}

/// The data of stream `i`: xorshift64 seeded with `i + 1`.
fn payload(i: usize) -> Vec<u8> {
    let mut x = i as u64 + 1;
    (0..200_000 + i * 7919)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x.to_le_bytes()[0]
        })
        .collect()
}

/// The definition's path, when this side is shaped.
fn definition() -> Option<String> {
    std::env::var("SHAPE_DEF").ok().filter(|p| !p.is_empty())
}

fn shape(s: &Session) {
    let Some(path) = definition() else { return };
    let json = std::fs::read(&path).unwrap_or_else(|e| die(&format!("{path}: {e}")));
    let factory = zmux_shaping::MachineFactory::from_json(&json, zmux_shaping::Options::default())
        .unwrap_or_else(|e| die(&format!("definition: {e}")));
    s.set_shaper(Some(Arc::new(factory)), None);
}

fn report(s: &Session) {
    let st = s.shaping_stats();
    println!(
        "STATS wire_spent={} injected={} dropped={} clamped={} faults={}",
        st.wire_spent, st.injected, st.inject_dropped, st.clamped, st.faults
    );
    if definition().is_some() && (st.wire_spent == 0 || st.faults != 0) {
        die("not shaped");
    }
}

async fn serve() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    println!("LISTEN {}", listener.local_addr().unwrap());
    let (tcp, _) = listener.accept().await.unwrap();
    let s = Session::accept(PipeIo::new(tcp), Config::default())
        .await
        .unwrap();
    shape(&s);
    let mut echoes = Vec::new();
    for _ in 0..STREAMS {
        let (mut send, mut recv) = s.accept_bi().await.unwrap();
        echoes.push(tokio::spawn(async move {
            let data = recv.read_to_end(1 << 24).await.unwrap();
            send.write_all(&data).await.unwrap();
            send.finish().unwrap();
            let _ = send.stopped().await;
        }));
    }
    for e in echoes {
        e.await.unwrap();
    }
    s.closed().await;
    report(&s);
    println!("OK");
}

async fn dial(addr: &str) {
    let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
    let s = Session::connect(PipeIo::new(tcp), Config::default())
        .await
        .unwrap();
    shape(&s);
    let mut exchanges = Vec::new();
    for i in 0..STREAMS {
        let s = s.clone();
        exchanges.push(tokio::spawn(async move {
            let (mut send, mut recv) = s.open_bi().await.unwrap();
            let want = payload(i);
            let out = want.clone();
            tokio::spawn(async move {
                send.write_all(&out).await.unwrap();
                send.finish().unwrap();
            });
            let got = recv.read_to_end(1 << 24).await.unwrap();
            if got != want {
                die(&format!(
                    "stream {i}: {} of {} bytes",
                    got.len(),
                    want.len()
                ));
            }
        }));
    }
    for e in exchanges {
        e.await.unwrap();
    }
    // Let the shaper's last injections go out before the statistics.
    tokio::time::sleep(Duration::from_millis(300)).await;
    report(&s);
    let _ = tokio::time::timeout(Duration::from_secs(5), s.close()).await;
    println!("OK");
}

#[tokio::main]
async fn main() {
    std::thread::spawn(|| {
        std::thread::sleep(Duration::from_secs(60));
        die("deadline");
    });
    let args: Vec<String> = std::env::args().collect();
    match (args.get(1).map(String::as_str), args.get(2)) {
        (Some("server"), _) => serve().await,
        (Some("client"), Some(addr)) => dial(addr).await,
        _ => die("usage: zmux-shaping-peer server | client <addr>"),
    }
}
