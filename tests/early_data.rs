//! Early data under the zmux floor through the tokio driver (SPEC.md
//! Section 6.1.2): `connect` returns before the peer's parameters, the
//! first stream's bytes go out at once, and a peer that cannot take them
//! processed none of them.

mod common;

use std::time::Duration;

use common::{duplex, multi_thread, watchdog};
use zmux::{Config, ConnectError, EarlyData, Session, SessionError};

fn early() -> Config {
    let mut c = Config::default();
    c.early_data = EarlyData::for_zmux_peer();
    c
}

#[test]
fn early_streams_carry_data_within_and_beyond_the_floor() {
    multi_thread(async {
        let ((a, _), (b, _)) = duplex(1 << 20);
        // The client's session is usable before the server even reads.
        let client = watchdog(5, "connect", Session::connect(a, early()))
            .await
            .unwrap();
        let (mut send, _recv) = client.open_bi().await.unwrap();
        // 10 000 bytes: 4096 of them (preamble included) go as early data,
        // the rest once the parameters arrive.
        let data: Vec<u8> = (0..10_000u32).map(|i| i as u8).collect();
        send.write_all(&data).await.unwrap();
        send.finish().unwrap();
        let server = watchdog(5, "accept", Session::accept(b, Config::default()))
            .await
            .unwrap();
        let (_s, mut r) = watchdog(5, "accept_bi", server.accept_bi()).await.unwrap();
        let got = watchdog(5, "read", r.read_to_end(1 << 20)).await.unwrap();
        assert_eq!(got, data);
        client.close(0u32.into(), b"");
    });
}

#[test]
fn a_peer_without_bidirectional_streams_rejects_early_data_unprocessed() {
    multi_thread(async {
        let ((a, _), (b, _)) = duplex(1 << 20);
        let client = Session::connect(a, early()).await.unwrap();
        let (mut send, _recv) = client.open_bi().await.unwrap();
        send.write_all(b"GET /").await.unwrap();
        let mut server_cfg = Config::default();
        server_cfg.max_incoming_streams = 0;
        // The server fails at the first early STREAM frame; either side
        // may finish establishing first.
        let server = Session::accept(b, server_cfg).await;
        let e = watchdog(5, "closed", client.closed()).await;
        assert!(e.is_early_data_rejected(), "{e:?}");
        assert_eq!(e, SessionError::EarlyDataRejected);
        if let Ok(s) = server {
            assert!(
                tokio::time::timeout(Duration::from_millis(200), s.accept_bi())
                    .await
                    .map_or(true, |r| r.is_err()),
                "no stream reached the server"
            );
        }
    });
}

#[test]
fn role_auto_cannot_send_early_data() {
    multi_thread(async {
        let ((a, _), _) = duplex(1 << 20);
        let e = Session::peer(a, early()).await.unwrap_err();
        assert!(matches!(e, ConnectError::InvalidConfig(_)), "{e:?}");
    });
}

#[test]
fn early_streams_carry_preamble_and_priority() {
    multi_thread(async {
        let ((a, _), (b, _)) = duplex(1 << 20);
        let client = watchdog(5, "connect", Session::connect(a, early()))
            .await
            .unwrap();
        let pre = zmux::Preamble::new()
            .with_info("GET /")
            .with_tlv(0x1000, b"dest");
        let (mut send, recv) = client.open_bi_with(&pre).await.unwrap();
        let prio = zmux::Priority::new(1, true).unwrap();
        recv.set_peer_priority(prio).unwrap();
        send.write_all(b"early").await.unwrap();
        send.finish().unwrap();
        let server = watchdog(5, "accept", Session::accept(b, Config::default()))
            .await
            .unwrap();
        let (_s, mut r) = watchdog(5, "accept_bi", server.accept_bi()).await.unwrap();
        let got = r.preamble();
        assert_eq!(got.info().map(|b| &b[..]), Some(&b"GET /"[..]));
        assert_eq!(got.tlv(0x1000).as_deref(), Some(&b"dest"[..]));
        assert_eq!(r.requested_priority(), Some(prio));
        let data = watchdog(5, "read", r.read_to_end(1 << 10)).await.unwrap();
        assert_eq!(data, b"early");
        client.close(0u32.into(), b"");
    });
}
