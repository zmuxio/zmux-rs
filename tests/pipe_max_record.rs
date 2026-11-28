//! A carrier's record limit ([`PipeIo::with_max_record`]) holds on a session's first
//! pipe, whichever way the session starts: it bounds the datagram a session may send and
//! the records written.

#![allow(
    clippy::large_stack_arrays,
    reason = "scenario code: buffers and futures stay on the stack on purpose, long scripted scenarios read top to bottom"
)]

use std::time::Duration;

use bytes::Bytes;
use zmux::{Config, Listener, ListenerConfig, PipeHint, PipeId, PipeIo, Session};

const LIMIT: Duration = Duration::from_secs(10);
const CAP: usize = 8192;
const SEALED_CAP: usize = 9000;

fn config() -> Config {
    let mut c = Config::default();
    c.enable_datagrams = true;
    c
}

/// Both ends see datagrams bounded by the capped end's records, and a transfer on the
/// capped end's pipe 0 is written in records of at most `CAP`.
async fn check(capped: &Session, other: &Session) {
    let max = capped.max_datagram_size().expect("datagrams on");
    assert!(max < CAP, "{max}");
    // The other end's own pipe is not limited.
    assert!(other.max_datagram_size().expect("datagrams on") > CAP);

    let (mut send, _recv) = capped.open_bi().await.unwrap();
    send.write_all(&[7; 200_000]).await.unwrap();
    send.finish().unwrap();
    let (_s, mut r) = other.accept_bi().await.unwrap();
    assert_eq!(r.read_to_end(1 << 20).await.unwrap().len(), 200_000);
    let stats = capped.pipe(PipeId::new(0)).unwrap().stats().unwrap();
    assert!(
        stats.records_sent >= 200_000 / CAP as u64,
        "{} records",
        stats.records_sent
    );
    capped
        .send_datagram(Bytes::from(vec![1; max]))
        .expect("the largest reported fits");
    assert!(capped.send_datagram(Bytes::from(vec![1; max + 1])).is_err());
}

#[tokio::test]
async fn connect_applies_the_carrier_record_limit() {
    tokio::time::timeout(LIMIT, async {
        let (a, b) = tokio::io::duplex(1 << 16);
        let server = tokio::spawn(Session::accept(PipeIo::new(b), config()));
        let client = Session::connect(PipeIo::new(a).with_max_record(CAP).unwrap(), config())
            .await
            .unwrap();
        let server = server.await.unwrap().unwrap();
        check(&client, &server).await;
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn accept_applies_the_carrier_record_limit() {
    tokio::time::timeout(LIMIT, async {
        let (a, b) = tokio::io::duplex(1 << 16);
        let client = tokio::spawn(Session::connect(PipeIo::new(a), config()));
        let server = Session::accept(PipeIo::new(b).with_max_record(CAP).unwrap(), config())
            .await
            .unwrap();
        let client = client.await.unwrap().unwrap();
        check(&server, &client).await;
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn a_listener_applies_the_carrier_record_limit() {
    tokio::time::timeout(LIMIT, async {
        let listener = Listener::new(config(), ListenerConfig::default()).unwrap();
        let (a, b) = tokio::io::duplex(1 << 16);
        let l = listener.clone();
        tokio::spawn(async move {
            let _ = l
                .handle_pipe(
                    PipeIo::new(b).with_max_record(CAP).unwrap(),
                    PipeHint::default(),
                )
                .await;
        });
        let client = Session::connect(PipeIo::new(a), config()).await.unwrap();
        let server = listener.accept().await.unwrap();
        check(&server, &client).await;
    })
    .await
    .unwrap();
}

/// A pipe added by a Sealed join keeps its carrier's record limit, less the Sealed
/// overhead, on both ends: the joiner's and the acceptor's records stay under it. The
/// limit holds a whole `SESSION_EPOCH` frame, which no record may split.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_sealed_join_keeps_the_carrier_record_limit() {
    use zmux::proto::session::AllowRecordMode;
    use zmux::{PipeAuth, PipeOptions};
    fn mp() -> Config {
        let mut c = Config::multipath(
            PipeAuth::psk(*b"a pre-shared key of 32 bytes....").with_end_to_end(),
        );
        c.allow_record_mode = Some(AllowRecordMode::new(|_, _, _| true));
        c
    }
    tokio::time::timeout(LIMIT, async {
        let listener = Listener::new(mp(), ListenerConfig::default()).unwrap();
        let (first_a, first_b) = tokio::io::duplex(1 << 16);
        let l = listener.clone();
        tokio::spawn(async move {
            l.handle_pipe(PipeIo::new(first_b), PipeHint::default())
                .await
        });
        let client = Session::connect(PipeIo::new(first_a), mp()).await.unwrap();
        let server = listener.accept().await.unwrap();
        client.established().await.unwrap();

        let (near, far) = tokio::io::duplex(1 << 16);
        let l = listener.clone();
        tokio::spawn(async move {
            l.handle_pipe(
                PipeIo::new(far).with_max_record(SEALED_CAP).unwrap(),
                PipeHint::default(),
            )
            .await
        });
        let pipe = client
            .test_begin_join(
                PipeIo::new(near).with_max_record(SEALED_CAP).unwrap(),
                PipeOptions::new(),
            )
            .unwrap();
        pipe.joined().await.unwrap();
        while server.pipes().len() < 2 {
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        client.pipe(PipeId::new(0)).unwrap().abort().unwrap();

        for (from, to) in [(&client, &server), (&server, &client)] {
            let joined = from
                .pipes()
                .into_iter()
                .find(|p| p.id() != PipeId::new(0))
                .unwrap();
            let before = joined.stats().unwrap().records_sent;
            let (mut send, _recv) = from.open_bi().await.unwrap();
            send.write_all(&[7; 200_000]).await.unwrap();
            send.finish().unwrap();
            let (_s, mut r) = to.accept_bi().await.unwrap();
            assert_eq!(r.read_to_end(1 << 20).await.unwrap().len(), 200_000);
            let records = joined.stats().unwrap().records_sent - before;
            // At most SEALED_CAP - 18 bytes of plaintext each, where the Sealed maximum alone
            // would take four.
            assert!(
                records >= 200_000 / (SEALED_CAP as u64 - 18),
                "{records} records"
            );
        }
    })
    .await
    .unwrap();
}

/// The record limit of a pipe input is at least the carrier record floor (8192 bytes).
#[test]
fn a_record_limit_below_the_floor_is_an_invalid_configuration() {
    for bad in [1, 512, 4096, 8191] {
        assert!(
            PipeIo::new(tokio::io::empty())
                .with_max_record(bad)
                .is_err()
        );
    }
    for good in [0, 8192, 65535, 65536, 1 << 20, usize::MAX] {
        assert!(
            PipeIo::new(tokio::io::empty())
                .with_max_record(good)
                .is_ok()
        );
    }
}

/// A Sealed pipe whose carrier limit leaves less than 8192 bytes after the Sealed overhead
/// is refused when it is added: an invalid configuration, nothing attached.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_pipe_the_sealed_overhead_takes_below_the_floor_is_refused() {
    use zmux::proto::session::AllowRecordMode;
    use zmux::{PipeAuth, PipeError, PipeOptions};
    fn mp() -> Config {
        let mut c = Config::multipath(
            PipeAuth::psk(*b"a pre-shared key of 32 bytes....").with_end_to_end(),
        );
        c.allow_record_mode = Some(AllowRecordMode::new(|_, _, _| true));
        c
    }
    tokio::time::timeout(LIMIT, async {
        let listener = Listener::new(mp(), ListenerConfig::default()).unwrap();
        let (first_a, first_b) = tokio::io::duplex(1 << 16);
        let l = listener.clone();
        tokio::spawn(async move {
            l.handle_pipe(PipeIo::new(first_b), PipeHint::default())
                .await
        });
        let client = Session::connect(PipeIo::new(first_a), mp()).await.unwrap();
        let _server = listener.accept().await.unwrap();
        client.established().await.unwrap();
        let (near, _far) = tokio::io::duplex(1 << 16);
        let r = client.test_begin_join(
            PipeIo::new(near).with_max_record(CAP).unwrap(),
            PipeOptions::new(),
        );
        assert!(matches!(r.err(), Some(PipeError::InvalidOptions(_))));
        assert_eq!(client.pipes().len(), 1);
    })
    .await
    .unwrap();
}

/// The Session Epoch exchange completes, and data keeps flowing, when every pipe is at the
/// carrier record floor: the only pipe is Sealed over a byte stream limited to 8210 bytes,
/// so its records hold exactly 8192 bytes of plaintext after the 18 bytes of overhead.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_epoch_exchange_completes_with_every_pipe_at_the_floor() {
    use zmux::proto::session::AllowRecordMode;
    use zmux::{PipeAuth, PipeOptions};
    const FLOOR_UNDER_SEALED: usize = 8192 + 18;
    fn mp() -> Config {
        let mut c = Config::multipath(
            PipeAuth::psk(*b"a pre-shared key of 32 bytes....").with_end_to_end(),
        );
        c.allow_record_mode = Some(AllowRecordMode::new(|_, _, _| true));
        c
    }
    tokio::time::timeout(LIMIT, async {
        let listener = Listener::new(mp(), ListenerConfig::default()).unwrap();
        let (first_a, first_b) = tokio::io::duplex(1 << 16);
        let l = listener.clone();
        tokio::spawn(async move {
            l.handle_pipe(PipeIo::new(first_b), PipeHint::default())
                .await
        });
        let client = Session::connect(PipeIo::new(first_a), mp()).await.unwrap();
        let server = listener.accept().await.unwrap();
        client.established().await.unwrap();

        let (near, far) = tokio::io::duplex(1 << 16);
        let l = listener.clone();
        tokio::spawn(async move {
            l.handle_pipe(
                PipeIo::new(far)
                    .with_max_record(FLOOR_UNDER_SEALED)
                    .unwrap(),
                PipeHint::default(),
            )
            .await
        });
        let pipe = client
            .test_begin_join(
                PipeIo::new(near)
                    .with_max_record(FLOOR_UNDER_SEALED)
                    .unwrap(),
                PipeOptions::new(),
            )
            .unwrap();
        pipe.joined().await.unwrap();
        while server.pipes().len() < 2 {
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        // The join starts the first epoch exchange (the pipe is the only one that may carry
        // it), and a request asks for one too: both ends reach epoch 1 over the capped pipe
        // alone, whose records hold the SESSION_EPOCH frames.
        client.advance_epoch().unwrap();
        while client.epoch() < Some(1) || server.epoch() < Some(1) {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        // The first pipe goes: the one left carries records of the floor's size.
        client.pipe(PipeId::new(0)).unwrap().abort().unwrap();

        for (from, to) in [(&client, &server), (&server, &client)] {
            let (mut send, _recv) = from.open_bi().await.unwrap();
            send.write_all(&[7; 200_000]).await.unwrap();
            send.finish().unwrap();
            let (_s, mut r) = to.accept_bi().await.unwrap();
            assert_eq!(r.read_to_end(1 << 20).await.unwrap().len(), 200_000);
        }
    })
    .await
    .unwrap();
}
