//! The carrier contract (`zmux::test_hooks::carrier_conformance`) on TLS
//! pipes over in-memory connections.

use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use zmux::test_hooks::carrier_conformance;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tls_pipes_keep_the_carrier_contract() {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let der = CertificateDer::from(cert.cert.der().to_vec());
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()));
    let server = Arc::new(
        rustls::ServerConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![der.clone()], key)
            .unwrap(),
    );
    let mut roots = rustls::RootCertStore::empty();
    roots.add(der).unwrap();
    let client = Arc::new(
        rustls::ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    );
    carrier_conformance("rustls", || {
        let (client, server) = (client.clone(), server.clone());
        async move {
            let (a, b) = tokio::io::duplex(64 << 10);
            let name = ServerName::try_from("localhost").unwrap();
            let (c, s) = tokio::join!(
                tokio_rustls::TlsConnector::from(client).connect(name, a),
                tokio_rustls::TlsAcceptor::from(server).accept(b)
            );
            (
                zmux_rustls::pipe(c.unwrap()),
                zmux_rustls::pipe(s.unwrap()),
                0,
            )
        }
    })
    .await;
}
