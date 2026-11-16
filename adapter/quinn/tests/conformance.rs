//! The carrier contract (`zmux::test_hooks::carrier_conformance`) on pipes
//! of QUIC connections over loopback.

use std::sync::Arc;

use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use zmux::test_hooks::{carrier_conformance, carrier_conformance_byte};
use zmux_quinn::{Carrier, Options};

fn endpoints() -> (quinn::Endpoint, quinn::Endpoint) {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let der = CertificateDer::from(cert.cert.der().to_vec());
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()));
    let mut tls = rustls::ServerConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![der.clone()], key)
        .unwrap();
    tls.alpn_protocols = vec![b"zmux".to_vec()];
    let server_config =
        quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(tls).unwrap()));
    let server = quinn::Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(der).unwrap();
    let mut tls = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    tls.alpn_protocols = vec![b"zmux".to_vec()];
    let mut client = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    client.set_default_client_config(quinn::ClientConfig::new(Arc::new(
        QuicClientConfig::try_from(tls).unwrap(),
    )));
    (server, client)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn quic_pipes_keep_the_carrier_contract() {
    let (server, client) = endpoints();
    let addr = server.local_addr().unwrap();
    let (cc, sc) = tokio::join!(
        async { client.connect(addr, "localhost").unwrap().await.unwrap() },
        async { server.accept().await.unwrap().await.unwrap() }
    );
    let client = Carrier::new(cc, Options::default());
    let server = Carrier::new(sc, Options::default());
    carrier_conformance("quinn", || {
        let (client, server) = (client.clone(), server.clone());
        async move {
            // The peer sees a stream once it carries data.
            let opened = [carrier_conformance_byte(0)];
            let a = client.open_pipe_with_prefix(&opened).await.unwrap();
            let b = server.accept_pipe().await.unwrap();
            (a, b, opened.len())
        }
    })
    .await;
}
