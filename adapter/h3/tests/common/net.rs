use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

/// A server endpoint with a fresh certificate and a client endpoint that
/// trusts it, over loopback.
pub(super) fn endpoints(
    opts: &zmux_h3::Options,
) -> (quinn::Endpoint, quinn::Endpoint, SocketAddr) {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let cert = zmux_testcert::self_signed(vec![Ipv4Addr::LOCALHOST.to_string()]).unwrap();
    let der = CertificateDer::from(cert.cert.der().to_vec());
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()));
    let tls = rustls::ServerConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![der.clone()], key)
        .unwrap();
    // The configuration helpers add `h3`.
    let server_config = zmux_h3::server_config(tls, opts).unwrap();
    let server = quinn::Endpoint::server(server_config, SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
    let addr = server.local_addr().unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(der).unwrap();
    let tls = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let client_config = zmux_h3::client_config(tls, opts).unwrap();
    let mut client = quinn::Endpoint::client(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
    client.set_default_client_config(client_config);
    (server, client, addr)
}
