//! Bulk throughput of one stream over a WebSocket carrier on loopback, and the
//! allocations per record sent: `cargo bench -p zmux-websocket --bench bulk`.
//! `BULK_MIB` sets the measured transfer (default 1024).

#![allow(missing_docs, unsafe_code)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::time::Instant;

use bytes::Bytes;
use zmux::{Config, Listener, ListenerConfig, Session};

struct Counting;

static ALLOCS: AtomicU64 = AtomicU64::new(0);

// SAFETY: forwards to the system allocator unchanged.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        ALLOCS.fetch_add(1, Relaxed);
        // SAFETY: forwarded unchanged.
        unsafe { System.alloc(l) }
    }

    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        // SAFETY: forwarded unchanged.
        unsafe { System.dealloc(p, l) }
    }

    unsafe fn realloc(&self, p: *mut u8, l: Layout, n: usize) -> *mut u8 {
        ALLOCS.fetch_add(1, Relaxed);
        // SAFETY: forwarded unchanged.
        unsafe { System.realloc(p, l, n) }
    }
}

#[global_allocator]
static GLOBAL: Counting = Counting;

async fn pair() -> (Session, Session) {
    let listener = Listener::new(Config::default(), ListenerConfig::default())
        .expect("valid listener configuration");
    let tcp = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = tcp.local_addr().unwrap();
    tokio::spawn(zmux_websocket::serve(
        listener.clone(),
        tcp,
        Default::default(),
    ));
    let c = zmux_websocket::connect(
        format!("ws://{addr}/zmux"),
        &Default::default(),
        Config::default(),
    )
    .await
    .unwrap();
    let s = listener.accept().await.unwrap();
    (c, s)
}

async fn bulk(client: Session, server: Session, zero_copy: bool) {
    let total = std::env::var("BULK_MIB")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(1024u64)
        << 20;
    let warm = 64u64 << 20;
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
    let data = vec![1u8; 64 * 1024];
    let chunk = Bytes::from(data.clone());
    let (mut sent, mut t, mut allocs, mut records) = (0u64, Instant::now(), 0, 0);
    while sent < total + warm {
        if sent == warm {
            t = Instant::now();
            allocs = ALLOCS.load(Relaxed);
            records = client.stats().records_sent;
        }
        if zero_copy {
            s.write_chunk(chunk.clone()).await.unwrap();
        } else {
            s.write_all(&data).await.unwrap();
        }
        sent += data.len() as u64;
    }
    s.finish().unwrap();
    let (n, _server) = reader.await.unwrap();
    let d = t.elapsed();
    let allocs = ALLOCS.load(Relaxed) - allocs;
    let records = client.stats().records_sent - records;
    assert_eq!(n, total + warm);
    println!(
        "RESULT carrier=websocket path={} MBps={:.0} allocs_per_record={:.3} allocs_per_MiB={:.1}",
        if zero_copy { "zero-copy" } else { "copy" },
        total as f64 / d.as_secs_f64() / 1e6,
        allocs as f64 / records.max(1) as f64,
        allocs as f64 / (total >> 20) as f64,
    );
}

fn main() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        for zero_copy in [true, false] {
            let (c, s) = pair().await;
            bulk(c, s, zero_copy).await;
        }
    });
}
