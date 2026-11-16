//! The carrier contract (`zmux::test_hooks::carrier_conformance`) on
//! WebSocket pipes over in-memory connections.

use zmux::test_hooks::carrier_conformance;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn websocket_pipes_keep_the_carrier_contract() {
    carrier_conformance("websocket", || async {
        let (a, b) = tokio::io::duplex(64 << 10);
        let (client, server) = tokio::join!(
            async {
                tokio_tungstenite::client_async("ws://localhost/zmux", a)
                    .await
                    .unwrap()
                    .0
            },
            async { tokio_tungstenite::accept_async(b).await.unwrap() }
        );
        (
            zmux_websocket::pipe(client, None),
            zmux_websocket::pipe(server, None),
            0,
        )
    })
    .await;
}
