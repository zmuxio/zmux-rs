//! The carrier contract (`zmux::test_hooks::carrier_conformance`) on pipes
//! of a WebTransport session over loopback.

use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use web_transport_quinn::quinn;
use zmux::test_hooks::carrier_conformance;
use zmux_webtransport::{Carrier, Options, Url};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn webtransport_pipes_keep_the_carrier_contract() {
    let opts = Options::default();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let cert = rcgen::generate_simple_self_signed(vec!["127.0.0.1".into()]).unwrap();
    let der = CertificateDer::from(cert.cert.der().to_vec());
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()));
    let alpn = vec![web_transport_quinn::ALPN.as_bytes().to_vec()];
    let mut tls = rustls::ServerConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![der.clone()], key)
        .unwrap();
    tls.alpn_protocols.clone_from(&alpn);
    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(tls).unwrap(),
    ));
    server_config.transport_config(Arc::new(opts.transport_config()));
    let endpoint = quinn::Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
    let addr = endpoint.local_addr().unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(der).unwrap();
    let mut tls = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    tls.alpn_protocols = alpn;
    let mut client_config = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(tls).unwrap(),
    ));
    client_config.transport_config(Arc::new(opts.transport_config()));
    let client_ep = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    let mut server = web_transport_quinn::Server::new(endpoint);
    let client = web_transport_quinn::Client::new(client_ep, client_config);
    let url: Url = format!("https://{addr}/zmux").parse().unwrap();
    let (c, s) = tokio::join!(client.connect(url), async {
        server.accept().await.unwrap().ok().await
    });
    let client = Carrier::new(c.unwrap(), opts.clone());
    let server = Carrier::new(s.unwrap(), opts);
    carrier_conformance("webtransport", || {
        let (client, server) = (client.clone(), server.clone());
        async move {
            let a = client.open_pipe().await.unwrap();
            let b = server.accept_pipe().await.unwrap();
            (a, b, 0)
        }
    })
    .await;
}
