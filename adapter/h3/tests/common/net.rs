#[path = "../../../test-support/tls.rs"]
mod tls;

use std::net::{Ipv4Addr, SocketAddr};

/// A server endpoint with a fresh certificate and a client endpoint that
/// trusts it, over loopback.
pub(super) fn endpoints(opts: &zmux_h3::Options) -> (quinn::Endpoint, quinn::Endpoint, SocketAddr) {
    let (client_tls, tls) = tls::configs(&Ipv4Addr::LOCALHOST.to_string(), Vec::new());
    // The configuration helpers add `h3`.
    let server_config = zmux_h3::server_config(tls, opts).unwrap();
    let server =
        quinn::Endpoint::server(server_config, SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
    let addr = server.local_addr().unwrap();
    let client_config = zmux_h3::client_config(client_tls, opts).unwrap();
    let mut client = quinn::Endpoint::client(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
    client.set_default_client_config(client_config);
    (server, client, addr)
}
