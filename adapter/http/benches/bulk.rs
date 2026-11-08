//! Bulk throughput of one stream over HTTP/1.1 and HTTP/2 carriers on
//! loopback: `cargo bench -p zmux-http --bench bulk` (`BULK_MIB`, default
//! 512).

#![allow(missing_docs)]

use std::time::Instant;

use bytes::Bytes;
use zmux::{Config, Listener, ListenerConfig, Session};
use zmux_http::Options;

async fn bulk(name: &str, client: Session, server: Session) {
    let total = std::env::var("BULK_MIB")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(512u64)
        << 20;
    let warm = 32u64 << 20;
    let reader = tokio::spawn(async move {
        let mut r = server.accept_uni().await.unwrap();
        let mut buf = vec![0u8; 256 * 1024];
        let mut n = 0u64;
        while let Some(k) = r.read(&mut buf).await.unwrap() {
            n += k as u64;
        }
        (n, server)
    });
    let mut s = client.open_uni().await.unwrap();
    let chunk = Bytes::from(vec![1u8; 64 * 1024]);
    let (mut sent, mut t) = (0u64, Instant::now());
    while sent < total + warm {
        if sent == warm {
            t = Instant::now();
        }
        s.write_chunk(chunk.clone()).await.unwrap();
        sent += chunk.len() as u64;
    }
    s.finish().unwrap();
    let (n, _server) = reader.await.unwrap();
    assert_eq!(n, total + warm);
    println!(
        "RESULT carrier={name} MBps={:.0}",
        total as f64 / t.elapsed().as_secs_f64() / 1e6
    );
}

fn main() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        for h2 in [false, true] {
            let listener = Listener::new(Config::default(), ListenerConfig::default())
                .expect("valid listener configuration");
            let tcp = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = tcp.local_addr().unwrap().to_string();
            tokio::spawn(zmux_http::serve(listener.clone(), tcp, Options::default()));
            let c = if h2 {
                zmux_http::connect_http2(&addr, &Options::default(), Config::default()).await
            } else {
                zmux_http::connect_http1(&addr, &Options::default(), Config::default()).await
            }
            .unwrap();
            let s = listener.accept().await.unwrap();
            bulk(if h2 { "http2" } else { "http1" }, c, s).await;
        }
    });
}
