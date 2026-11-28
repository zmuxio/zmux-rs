use std::sync::Arc;

use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};

#[path = "../../../test-support/tls.rs"]
mod tls;
pub(crate) use tls::configs as tls_configs;

pub(crate) fn endpoints(
    alpn: Vec<Vec<u8>>,
    server_transport: quinn::TransportConfig,
    client_transport: quinn::TransportConfig,
) -> (quinn::Endpoint, quinn::Endpoint) {
    let (client, server) = tls_configs("localhost", alpn);
    let mut server_config =
        quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(server).unwrap()));
    zmux_quinn::track_server_early_data(&mut server_config);
    server_config.transport_config(Arc::new(server_transport));
    let server = quinn::Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
    let mut client_config =
        quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(client).unwrap()));
    client_config.transport_config(Arc::new(client_transport));
    let mut client = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    client.set_default_client_config(client_config);
    (server, client)
}

/// Options for taking over a connection established with these transport settings.
#[allow(dead_code, reason = "not every test target adopts connections")]
pub(crate) fn adopted_options(options: zmux_quinn::Options) -> zmux_quinn::Options {
    let windows = options.windows;
    options.with_windows(windows.with_established_receive_window(windows.receive_window()))
}
