#[path = "../../../test-support/tls.rs"]
pub(crate) mod tls;

use super::wt;
use super::{Options, Url};
use quinn::crypto::rustls as crypto;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

/// A WebTransport server and a client for it over loopback.
pub(crate) struct Wt {
    pub(crate) server: Option<quinn::Endpoint>,
    pub(crate) client: wt::Client,
    pub(crate) url: Url,
    /// The client's endpoint and configuration, for connections made
    /// outside `client`.
    #[allow(dead_code, reason = "used by the external QUIC handshake test")]
    pub(crate) client_ep: quinn::Endpoint,
    #[allow(dead_code, reason = "used by the external QUIC handshake test")]
    pub(crate) client_config: quinn::ClientConfig,
}

impl Wt {
    pub(crate) fn new(opts: &Options) -> Self {
        let alpn = vec![wt::ALPN.as_bytes().to_vec()];
        let (client_tls, tls) = tls::configs(&Ipv4Addr::LOCALHOST.to_string(), alpn);
        let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(
            crypto::QuicServerConfig::try_from(tls).unwrap(),
        ));
        zmux_quinn::track_server_early_data(&mut server_config);
        server_config.transport_config(Arc::new(opts.transport_config()));
        let endpoint =
            quinn::Endpoint::server(server_config, (Ipv4Addr::LOCALHOST, 0).into()).unwrap();
        let addr = endpoint.local_addr().unwrap();
        let mut client_config = quinn::ClientConfig::new(Arc::new(
            crypto::QuicClientConfig::try_from(client_tls).unwrap(),
        ));
        client_config.transport_config(Arc::new(opts.transport_config()));
        let client_ep =
            quinn::Endpoint::client(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
        Self {
            server: Some(endpoint),
            client: wt::Client::new(client_ep.clone(), client_config.clone()),
            url: format!("https://{addr}/zmux").parse().unwrap(),
            client_ep,
            client_config,
        }
    }

    /// A WebTransport session: the client's end and the server's.
    pub(crate) async fn pair(&mut self) -> (wt::Session, wt::Session) {
        let server = self.server.as_mut().unwrap();
        let (c, s) = tokio::join!(self.client.connect(self.url.clone()), async {
            wt::Request::accept(server.accept().await.unwrap().await.unwrap())
                .await
                .unwrap()
                .ok()
                .await
        });
        (c.unwrap(), s.unwrap())
    }
}

/// Options for taking over a connection established with these transport settings.
#[allow(dead_code, reason = "not every test target adopts connections")]
pub(crate) fn adopted_options(options: Options) -> Options {
    let windows = options.windows;
    options.with_windows(windows.with_established_receive_window(windows.receive_window()))
}
