//! A carrier whose first bytes start a session and then stall: the
//! listener's handshake timeout ends it, and so does its close, whatever the
//! session configuration's own handshake timeout (none here).

#[path = "common/clock.rs"]
mod clock;

use std::time::Duration;

use clock::ManualClock;
use zmux::{ClockDomain, MonotonicClock};

use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};
use zmux::{Config, HandleError, Listener, ListenerConfig, PipeHint, PipeIo, Session};

const LIMIT: Duration = Duration::from_secs(10);

/// The first bytes a client sends: the start of its first record.
async fn first_bytes() -> Vec<u8> {
    let (a, mut b) = duplex(1 << 16);
    let client = tokio::spawn(Session::connect(PipeIo::new(a), Config::default()));
    let mut buf = vec![0; 1 << 16];
    let n = tokio::time::timeout(LIMIT, b.read(&mut buf))
        .await
        .unwrap()
        .unwrap();
    client.abort();
    buf.truncate(n);
    // Half of it: the classifier accepts the record's start.
    buf.truncate((n / 2).max(4));
    buf
}

fn listener(handshake: Duration) -> Listener {
    let mut server = Config::default();
    server.handshake_timeout = None;
    let mut limits = ListenerConfig::default();
    limits.handshake_timeout = handshake;
    Listener::new(server, limits).expect("valid listener configuration")
}

#[tokio::test]
async fn a_valid_first_record_that_stalls_times_out() {
    tokio::time::timeout(LIMIT, async {
        let first = first_bytes().await;
        let wait = Duration::from_secs(90);
        let (clock, domain) = ManualClock::domain(Duration::from_secs(120));
        let mut timers = clock.registrations();
        let deadline = domain.now() + wait;
        let mut config = Config::default();
        config.handshake_timeout = None;
        config.clock_domain = domain;
        let mut limits = ListenerConfig::default();
        limits.handshake_timeout = wait;
        let l = Listener::new(config, limits).unwrap();
        let (mut near, far) = duplex(1 << 16);
        near.write_all(&first).await.unwrap();
        let accepting = l.clone();
        let handled = tokio::spawn(async move {
            accepting
                .handle_pipe(PipeIo::new(far), PipeHint::default())
                .await
        });
        while timers.recv().await.unwrap() != deadline {}
        clock.advance(wait);
        assert_eq!(handled.await.unwrap(), Err(HandleError::TimedOut));
        assert_eq!(l.stats().timed_out, 1);
        l.close();
    })
    .await
    .expect("listener establishment timeout test watchdog");
}

#[tokio::test]
async fn the_listeners_close_ends_a_stalled_establishment() {
    let first = first_bytes().await;
    let l = listener(Duration::from_secs(3600));
    let (mut near, far) = duplex(1 << 16);
    near.write_all(&first).await.unwrap();
    let ll = l.clone();
    let handled =
        tokio::spawn(async move { ll.handle_pipe(PipeIo::new(far), PipeHint::default()).await });
    // The listener's own first record shows the establishment began.
    let mut answer = [0u8; 1];
    tokio::time::timeout(LIMIT, near.read(&mut answer))
        .await
        .unwrap()
        .unwrap();
    l.close();
    let r = tokio::time::timeout(LIMIT, handled).await.unwrap().unwrap();
    assert!(r.is_err(), "{r:?}");
    drop(near);
}
