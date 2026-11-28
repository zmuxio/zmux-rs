//! The carrier contract (`zmux::test_hooks::carrier_conformance`) on pipes
//! of QUIC connections over loopback.

mod common;

use zmux::test_hooks::{carrier_conformance, carrier_conformance_byte};
use zmux_quinn::{Carrier, Options};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn quic_pipes_keep_the_carrier_contract() {
    let (server, client) = common::endpoints(
        vec![b"zmux".to_vec()],
        Options::default().transport_config(),
        Options::default().transport_config(),
    );
    let addr = server.local_addr().unwrap();
    let (cc, sc) = tokio::join!(
        async { client.connect(addr, "localhost").unwrap().await.unwrap() },
        async { server.accept().await.unwrap().await.unwrap() }
    );
    let client = Carrier::new(cc, &common::adopted_options(Options::default())).unwrap();
    let server = Carrier::new(sc, &common::adopted_options(Options::default())).unwrap();
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
