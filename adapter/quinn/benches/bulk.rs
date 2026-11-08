//! Bulk throughput of one stream over a QUIC carrier on loopback, and the
//! allocations per record sent: `cargo bench -p zmux-quinn --bench bulk`.
//! `BULK_MIB` sets the measured transfer (default 1024).

#![allow(missing_docs, unsafe_code)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::time::Instant;

use bytes::Bytes;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use zmux::{Config, Listener, ListenerConfig, Session};
use zmux_quinn::Options;

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
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let der = CertificateDer::from(cert.cert.der().to_vec());
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()));
    let opts = Options::default();
    let tls = rustls::ServerConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![der.clone()], key)
        .unwrap();
    let server = quinn::Endpoint::server(
        zmux_quinn::server_config(tls, &opts).unwrap(),
        "127.0.0.1:0".parse().unwrap(),
    )
    .unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(der).unwrap();
    let tls = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let mut client = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    client.set_default_client_config(zmux_quinn::client_config(tls, &opts).unwrap());
    let addr = server.local_addr().unwrap();
    let listener = Listener::new(Config::default(), ListenerConfig::default())
        .expect("valid listener configuration");
    tokio::spawn(zmux_quinn::serve(
        listener.clone(),
        server,
        opts.clone(),
        None,
    ));
    let c = zmux_quinn::connect(&client, addr, "localhost", &opts, Config::default())
        .await
        .unwrap();
    let s = listener.accept().await.unwrap();
    std::mem::forget(client);
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
        "RESULT carrier=quinn path={} MBps={:.0} allocs_per_record={:.3} allocs_per_MiB={:.1}",
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
