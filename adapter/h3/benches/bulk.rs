//! Bulk throughput of one stream over an HTTP/3 carrier on loopback:
//! `cargo bench -p zmux-h3 --bench bulk` (`BULK_MIB`, default 512).

#![allow(missing_docs)]

use std::sync::Arc;
use std::time::Instant;

use bytes::Bytes;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use zmux::{Config, Listener, ListenerConfig, Session};
use zmux_h3::Options;

async fn pair() -> (Session, Session) {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let cert = rcgen::generate_simple_self_signed(vec!["127.0.0.1".into()]).unwrap();
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
        zmux_h3::server_config(tls, &opts).unwrap(),
        "127.0.0.1:0".parse().unwrap(),
    )
    .unwrap();
    let addr = server.local_addr().unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(der).unwrap();
    let tls = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let mut client = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    client.set_default_client_config(zmux_h3::client_config(tls, &opts).unwrap());
    let listener = Listener::new(Config::default(), ListenerConfig::default());
    tokio::spawn(zmux_h3::serve(listener.clone(), server, opts.clone()));
    let uri = format!("https://127.0.0.1:{}/zmux", addr.port())
        .parse()
        .unwrap();
    let c = zmux_h3::connect(&client, addr, uri, &opts, Config::default())
        .await
        .unwrap();
    let s = listener.accept().await.unwrap();
    std::mem::forget(client);
    (c, s)
}

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
        let (c, s) = pair().await;
        bulk("h3", c, s).await;
    });
}
