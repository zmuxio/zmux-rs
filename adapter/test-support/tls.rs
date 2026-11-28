//! TLS configuration used by loopback carrier tests.

use std::sync::Arc;

use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};

pub(crate) fn configs(
    name: &str,
    alpn: Vec<Vec<u8>>,
) -> (rustls::ClientConfig, rustls::ServerConfig) {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let cert = zmux_testcert::self_signed(vec![name.into()]).unwrap();
    let der = cert.cert.der().clone();
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()));
    let mut server = rustls::ServerConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![der.clone()], key)
        .unwrap();
    server.alpn_protocols.clone_from(&alpn);
    (client_for(der, alpn), server)
}

pub(crate) fn client_for(
    cert: rustls::pki_types::CertificateDer<'static>,
    alpn: Vec<Vec<u8>>,
) -> rustls::ClientConfig {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert).unwrap();
    let mut client = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    client.alpn_protocols = alpn;
    client
}
