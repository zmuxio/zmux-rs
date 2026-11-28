//! A listener's memory budget and suspended-session limit, which its
//! sessions keep up to date from their own rounds (no periodic pass over
//! the sessions).

#![cfg(feature = "tokio")]

mod common;

use std::time::Duration;

use common::{Ctl, duplex, watchdog};
use zmux::{
    Config, HandleError, Listener, ListenerConfig, PipeAuth, PipeHint, Session,
    SessionState as State,
};

/// A carrier to `listener`: the client's end, its control and the
/// listener's handling of the other end.
fn dial(
    listener: &Listener,
) -> (
    zmux::PipeIo,
    std::sync::Arc<Ctl>,
    tokio::task::JoinHandle<Result<(), HandleError>>,
) {
    let ((a, ca), (b, _)) = duplex(64 * 1024);
    let l = listener.clone();
    let handled = tokio::spawn(async move { l.handle_pipe(b, PipeHint::default()).await });
    (a, ca, handled)
}

/// Refusal is a setup result even when the peer cannot yet read its close.
#[tokio::test]
async fn backlog_refusal_returns_before_close_flush() {
    let mut limits = ListenerConfig::default();
    limits.max_unaccepted = Some(0);
    let listener = Listener::new(Config::default(), limits).unwrap();
    let ((client, _), (server, writes)) = duplex(65536);
    writes.stall(true);
    let dialer = tokio::spawn(Session::connect(client, Config::default()));
    let result = watchdog(
        2,
        "backlog refusal",
        listener.handle_pipe(server, PipeHint::default()),
    )
    .await;
    assert_eq!(result, Err(HandleError::Refused));
    writes.stall(false);
    let error = match watchdog(2, "refusal delivered", dialer).await.unwrap() {
        Ok(session) => watchdog(2, "peer close", session.closing()).await,
        Err(zmux::ConnectError::SessionLost(error)) => error,
        Err(e) => panic!("unexpected connect error: {e}"),
    };
    assert!(
        matches!(error, zmux::SessionError::TransportClosed { code, remote: true, .. }
        if code == zmux::proto::TransportErrorCode::CONNECTION_REFUSED)
    );
}

/// A carrier filling the shared budget causes refusal until it returns the grant.
#[tokio::test]
async fn a_full_budget_refuses_sessions_until_carrier_memory_returns() {
    let mut limits = ListenerConfig::default();
    let budget = 16 * 1024 * 1024;
    limits.limits.memory_budget = Some(budget);
    let (changes, mut pressure) = tokio::sync::mpsc::unbounded_channel();
    limits.on_memory_pressure = Some(zmux::OnMemoryPressure::new(move |event| {
        let _ = changes.send(event);
    }));
    let listener = Listener::new(Config::default(), limits).unwrap();
    let held = listener.adapter().reserve_memory(budget).unwrap();
    let entered = watchdog(30, "pressure started", pressure.recv())
        .await
        .unwrap();
    assert!(entered.active);
    assert_eq!((entered.used, entered.budget), (budget, budget));
    let (io, _, handled) = dial(&listener);
    let dialer = tokio::spawn(Session::connect(io, Config::default()));
    assert_eq!(
        watchdog(30, "refused", handled).await.unwrap(),
        Err(HandleError::Refused)
    );
    let error = match watchdog(30, "refusal delivered", dialer).await.unwrap() {
        Ok(s) => watchdog(30, "peer close", s.closing()).await,
        Err(zmux::ConnectError::SessionLost(e)) => e,
        Err(e) => panic!("unexpected connect error: {e}"),
    };
    assert!(
        matches!(error, zmux::SessionError::TransportClosed { code, remote: true, .. }
        if code == zmux::proto::TransportErrorCode::CONNECTION_REFUSED)
    );
    drop(held);
    let left = watchdog(30, "pressure ended", pressure.recv())
        .await
        .unwrap();
    assert!(!left.active);
    let (io, _, handled) = dial(&listener);
    let _client = watchdog(
        30,
        "connect after release",
        Session::connect(io, Config::default()),
    )
    .await
    .unwrap();
    assert!(
        watchdog(30, "accepted after release", handled)
            .await
            .unwrap()
            .is_ok()
    );
    listener.close();
}

fn mp_config() -> Config {
    let mut c = Config::default();
    c.session_policy.limits.steady_attachments = 4;
    c.pipe_auth = PipeAuth::psk(*b"account-test-psk-0123456789abcd!").with_end_to_end();
    c.liveness.suspect_floor = Duration::from_millis(100);
    c.resume_timeout = Some(Duration::from_secs(30));
    c
}

/// Beyond `max_suspended`, the session suspended first is closed; the one
/// suspended later stays suspended.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_oldest_suspended_session_beyond_the_limit_is_closed() {
    let mut limits = ListenerConfig::default();
    limits.limits.max_suspended = 1;
    let listener = Listener::new(mp_config(), limits).expect("valid listener configuration");
    let mut pairs = Vec::new();
    for _ in 0..2 {
        let (io, ctl, _) = dial(&listener);
        let client = watchdog(10, "connect", Session::connect(io, mp_config()))
            .await
            .expect("connect");
        let server = watchdog(10, "accept", listener.accept())
            .await
            .expect("accept");
        pairs.push((client, server, ctl));
    }
    // The first loses its only pipe, then the second.
    for (_, server, ctl) in &pairs {
        ctl.fail();
        watchdog(30, "session suspended", async {
            while !matches!(
                server.next_event().await.unwrap(),
                zmux::SessionEvent::SessionSuspended
            ) {}
        })
        .await;
    }
    watchdog(30, "the oldest closed", pairs[0].1.closing()).await;
    assert_eq!(
        pairs[1].1.state(),
        State::Suspended,
        "the newer one was closed"
    );
    drop(pairs);
    listener.close();
}

/// Under memory pressure a join to a session that is not suspended is declined through
/// the reject policy, like an unknown Locator, and not closed past it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_join_under_pressure_goes_to_the_reject_policy() {
    let mut limits = ListenerConfig::default();
    let budget = 16 * 1024 * 1024;
    limits.limits.memory_budget = Some(budget);
    let (reported, mut pressure) = tokio::sync::mpsc::unbounded_channel();
    limits.on_memory_pressure = Some(zmux::OnMemoryPressure::new(move |event| {
        let _ = reported.send(event.active);
    }));
    let (rejected, mut reasons) = tokio::sync::mpsc::unbounded_channel();
    limits.on_reject = Some(zmux::OnReject::new(move |i| {
        let _ = rejected.send(i.reason);
        zmux::RejectAction::Close
    }));
    let listener = Listener::new(mp_config(), limits).expect("valid listener configuration");
    let (io, _ctl, _) = dial(&listener);
    let client = watchdog(10, "connect", Session::connect(io, mp_config()))
        .await
        .expect("connect");
    let _server = watchdog(10, "accept", listener.accept())
        .await
        .expect("accept");
    watchdog(10, "established", client.established())
        .await
        .expect("established");
    let adapter = listener.adapter();
    let mut available = 0;
    let mut refused = budget + 1;
    while available + 1 < refused {
        let mid = available.midpoint(refused);
        if adapter.reserve_memory(mid).is_ok() {
            available = mid;
        } else {
            refused = mid;
        }
    }
    let _grant = adapter.reserve_memory(available).unwrap();
    assert_eq!(
        watchdog(30, "pressure started", pressure.recv()).await,
        Some(true)
    );
    let (io, _, handled) = dial(&listener);
    let _pipe = client
        .test_begin_join(io, zmux::PipeOptions::new())
        .unwrap();
    assert_eq!(
        watchdog(30, "join handled", handled).await.unwrap(),
        Err(HandleError::Rejected)
    );
    assert_eq!(reasons.try_recv(), Ok("memory_pressure"));
}

/// The first-record timeout has one exported default, 2 s, which a listener
/// starts with and the process-level lane entry uses.
#[test]
fn the_first_record_timeout_has_one_exported_default() {
    assert_eq!(
        zmux::DEFAULT_FIRST_RECORD_TIMEOUT,
        std::time::Duration::from_secs(2)
    );
    assert_eq!(
        ListenerConfig::default().limits.first_record_timeout,
        zmux::DEFAULT_FIRST_RECORD_TIMEOUT
    );
}

#[tokio::test]
async fn a_new_limit_must_cover_live_reservations() {
    let mut config = ListenerConfig::default();
    config.limits.memory_budget = None;
    let listener = Listener::new(Config::default(), config).unwrap();
    let initial = listener.limits();
    let adapter = listener.adapter();
    let mut grant = adapter.reserve_memory(512).unwrap();
    let mut smaller = initial;
    smaller.memory_budget = Some(511);
    smaller.max_suspended /= 2;
    assert!(listener.set_limits(smaller).is_err());
    assert_eq!(listener.limits(), initial);
    grant.resize(511).unwrap();
    listener.set_limits(smaller).unwrap();
    assert_eq!(listener.limits(), smaller);
    assert!(grant.resize(512).is_err());
    assert!(adapter.reserve_memory(1).is_err());
    drop(grant);
    assert!(adapter.reserve_memory(511).is_ok());
}

#[tokio::test]
async fn closing_an_offered_bootstrap_keeps_the_session_count() {
    let listener = Listener::new(Config::default(), ListenerConfig::default()).unwrap();
    let (io, _, handled) = dial(&listener);
    let client = Session::connect(io, Config::default()).await.unwrap();
    handled.await.unwrap().unwrap();
    let offered = listener.stats();
    assert_eq!(offered.sessions, 1);
    listener.close();
    assert!(listener.accept().await.is_none());
    client.closing().await;
    let closed = listener.stats();
    assert_eq!(
        (closed.sessions, closed.rejected, closed.refused),
        (1, offered.rejected, offered.refused)
    );
}
