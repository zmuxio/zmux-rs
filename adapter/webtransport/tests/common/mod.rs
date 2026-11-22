use super::{Options, Url};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use web_transport_quinn::quinn;
use zmux::Session;

/// A WebTransport server and a client for it over loopback.
pub(super) struct Wt {
    pub(super) server: Option<web_transport_quinn::Server>,
    pub(super) client: web_transport_quinn::Client,
    pub(super) url: Url,
    /// The client's endpoint and configuration, for connections made
    /// outside `client`.
    #[allow(dead_code, reason = "used by the external QUIC handshake test")]
    pub(super) client_ep: quinn::Endpoint,
    #[allow(dead_code, reason = "used by the external QUIC handshake test")]
    pub(super) client_config: quinn::ClientConfig,
}

impl Wt {
    pub(super) fn new(opts: &Options) -> Self {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let cert = zmux_testcert::self_signed(vec![Ipv4Addr::LOCALHOST.to_string()]).unwrap();
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
        let endpoint =
            quinn::Endpoint::server(server_config, SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
                .unwrap();
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
        let client_ep =
            quinn::Endpoint::client(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
        Self {
            server: Some(web_transport_quinn::Server::new(endpoint)),
            client: web_transport_quinn::Client::new(client_ep.clone(), client_config.clone()),
            url: format!("https://{addr}/zmux").parse().unwrap(),
            client_ep,
            client_config,
        }
    }

    /// A WebTransport session: the client's end and the server's.
    pub(super) async fn pair(
        &mut self,
    ) -> (web_transport_quinn::Session, web_transport_quinn::Session) {
        let server = self.server.as_mut().unwrap();
        let (c, s) = tokio::join!(self.client.connect(self.url.clone()), async {
            server.accept().await.unwrap().ok().await
        });
        (c.unwrap(), s.unwrap())
    }
}

/// Sends `n` streams of `len` bytes each from `from` to `to` at once and
/// checks every byte.
pub(super) async fn transfer(from: &Session, to: &Session, n: usize, len: usize) {
    let receiver = {
        let to = to.clone();
        tokio::spawn(async move {
            let mut readers = Vec::new();
            for _ in 0..n {
                let mut recv = to.accept_uni().await.unwrap();
                readers.push(tokio::spawn(async move {
                    recv.read_to_end(len + 1).await.unwrap()
                }));
            }
            for r in readers {
                let data = r.await.unwrap();
                assert_eq!(data.len(), len);
                assert!(
                    data.iter()
                        .enumerate()
                        .all(|(i, &b)| b == u8::try_from(i % 251).unwrap())
                );
            }
        })
    };
    let data = bytes::Bytes::from(
        (0..len)
            .map(|i| u8::try_from(i % 251).unwrap())
            .collect::<Vec<_>>(),
    );
    let mut writers = Vec::new();
    for _ in 0..n {
        let mut send = from.open_uni().await.unwrap();
        let data = data.clone();
        writers.push(tokio::spawn(async move {
            send.write_chunk(data).await.unwrap();
            send.finish().unwrap();
            send
        }));
    }
    for w in writers {
        drop(w.await.unwrap());
    }
    receiver.await.unwrap();
}
