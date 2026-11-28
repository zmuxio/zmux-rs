//! Close delivery contract shared by the byte and message carrier tests.

use std::time::Duration;
use zmux::{Config, Session};

pub(crate) fn lingering(mut c: Config) -> Config {
    c.test_hooks().linger_timeout = Some(Duration::from_secs(3600));
    c
}

pub(crate) async fn close_delivery(
    client: &Session,
    server: &Session,
    code: u32,
    reason: &[u8],
    slow: bool,
) {
    let len = if slow { 128 << 10 } else { 1 << 20 };
    let data: Vec<u8> = (0..len).map(|i| u8::try_from(i % 251).unwrap()).collect();
    let (accepted, peer_has_stream) = tokio::sync::oneshot::channel();
    let reader = {
        let (client, server, data) = (client.clone(), server.clone(), data.clone());
        tokio::spawn(async move {
            let (_s, mut r) = server.accept_bi().await.unwrap();
            accepted.send(()).unwrap();
            if slow {
                // Begin reading after close is initiated locally. The
                // unread payload fits within the peer's initial stream credit.
                client.closing().await;
            }
            assert_eq!(r.read_to_end(2 << 20).await.unwrap(), data);
            server.closing().await
        })
    };
    let (mut w, _r) = client.open_bi().await.unwrap();
    w.write_all(&data).await.unwrap();
    w.finish().unwrap();
    tokio::time::timeout(Duration::from_secs(60), peer_has_stream)
        .await
        .expect("the peer did not accept the stream")
        .unwrap();
    let (mut open, _r2) = client.open_bi().await.unwrap();
    open.write_all(b"left open").await.unwrap();
    let code = zmux::VarInt::from_u32(code);
    tokio::time::timeout(Duration::from_secs(60), async {
        if code == zmux::VarInt::ZERO && reason.is_empty() {
            client.close().await;
        } else {
            client.close_with_error(code, reason).await;
        }
    })
    .await
    .expect("the close operation hung");
    let end = tokio::time::timeout(Duration::from_secs(60), client.closed())
        .await
        .expect("the server ended its side after the close");
    assert!(
        matches!(&end, zmux::SessionError::ApplicationClosed { code: c, remote: false, .. } if *c == code),
        "{end:?}"
    );
    let seen = tokio::time::timeout(Duration::from_secs(60), reader)
        .await
        .expect("the server read everything")
        .unwrap();
    assert!(
        matches!(&seen, zmux::SessionError::ApplicationClosed { code: c, reason: r, remote: true }
            if *c == code && r.as_ref() == reason),
        "{seen:?}"
    );
    let e = open.write_all(b"more").await.unwrap_err();
    assert!(
        matches!(&e, zmux::StreamError::SessionLost(zmux::SessionError::ApplicationClosed { code: c, remote: false, .. }) if *c == code),
        "{e:?}"
    );
}
