//! A listener's memory budget and suspended-session limit, which its
//! sessions keep up to date from their own rounds (no periodic pass over
//! the sessions).

#![cfg(feature = "tokio")]

mod common;

use std::time::Duration;

use common::{Ctl, duplex, eventually, watchdog};
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

/// Sessions over the budget refuse new sessions; once their charges leave
/// (the session ended), new sessions are accepted again. The
/// `on_memory_pressure` hook is told when pressure starts and ends.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_listener_over_its_budget_refuses_sessions_until_charges_leave() {
    let mut limits = ListenerConfig::default();
    // Below one idle session's charge.
    limits.memory_budget = Some(1024);
    let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let log = seen.clone();
    limits.on_memory_pressure = Some(zmux::OnMemoryPressure(std::sync::Arc::new(
        move |p: zmux::MemoryPressure| {
            assert_eq!(p.budget, 1024);
            log.lock().unwrap().push(p.active);
        },
    )));
    let listener = Listener::new(Config::default(), limits).expect("valid listener configuration");
    let (io, _ctl, _) = dial(&listener);
    let client = watchdog(10, "connect", Session::connect(io, Config::default()))
        .await
        .expect("connect");
    let server = watchdog(10, "accept", listener.accept())
        .await
        .expect("accept");
    // The server reported its charge in its first rounds.
    let mut refused = false;
    for _ in 0..200 {
        let (io, _ctl, handled) = dial(&listener);
        // The first record makes the listener start a session, or refuse.
        let dialer = tokio::spawn(Session::connect(io, Config::default()));
        let r = watchdog(10, "refusal", handled).await.unwrap();
        if r == Err(HandleError::Refused) {
            // CONNECTION_REFUSED after the listener's parameters, so that the
            // peer reads why, as the Go listener sends it.
            let error = match watchdog(10, "refused dialer", dialer).await.unwrap() {
                Ok(s) => watchdog(10, "refused session", s.closing()).await,
                Err(zmux::ConnectError::SessionLost(e)) => e,
                Err(e) => panic!("not refused: {e:?}"),
            };
            assert!(
                matches!(
                    error,
                    zmux::SessionError::TransportClosed { code, remote: true, .. }
                        if code == zmux::proto::TransportErrorCode::CONNECTION_REFUSED
                ),
                "{error:?}"
            );
            refused = true;
            break;
        }
        dialer.abort();
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(refused, "a listener over its budget accepted a session");
    eventually(10, "pressure reported", || {
        seen.lock().unwrap().first() == Some(&true)
    })
    .await;
    client.close().await;
    watchdog(10, "server closed", server.closing()).await;
    drop((client, server));
    // The ended session's charge left the account: the end of the
    // pressure is reported once, after its start (wait for it before a
    // new session charges again, which the hook may see coalesced).
    eventually(10, "pressure end reported", || {
        seen.lock().unwrap().len() >= 2
    })
    .await;
    assert_eq!(seen.lock().unwrap()[..2], [true, false]);
    let accepted = async {
        loop {
            let (io, _ctl, _) = dial(&listener);
            if let Ok(Ok(c)) = tokio::time::timeout(
                Duration::from_secs(1),
                Session::connect(io, Config::default()),
            )
            .await
            {
                return c;
            }
        }
    };
    let c = watchdog(10, "accepted again", accepted).await;
    drop(c);
    listener.close();
}

fn mp_config() -> Config {
    let mut c = Config::default();
    c.max_pipes = 4;
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
    limits.max_suspended = 1;
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
    pairs[0].2.fail();
    eventually(30, "first suspended", || {
        pairs[0].1.state() == State::Suspended
    })
    .await;
    pairs[1].2.fail();
    eventually(30, "second suspended", || {
        pairs[1].1.state() == State::Suspended
    })
    .await;
    watchdog(30, "the oldest closed", pairs[0].1.closing()).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
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
    // Below one idle session's charge.
    limits.memory_budget = Some(1024);
    let reasons = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let seen = reasons.clone();
    limits.on_reject = Some(zmux::OnReject(std::sync::Arc::new(move |i| {
        seen.lock().unwrap().push(i.reason);
        zmux::RejectAction::Close
    })));
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
    for _ in 0..200 {
        let (io, _ctl, handled) = dial(&listener);
        let _pipe = client.begin_add_pipe(io, zmux::PipeOptions::new()).unwrap();
        let r = watchdog(10, "join handled", handled).await.unwrap();
        if reasons.lock().unwrap().contains(&"memory_pressure") {
            assert_eq!(r, Err(HandleError::Rejected));
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!(
        "no join declined under pressure: {:?}",
        reasons.lock().unwrap()
    );
}

/// The per-session bound on Unconfirmed carriers is 4 by default and at least 1.
#[test]
fn unconfirmed_per_session_is_at_least_one() {
    assert_eq!(ListenerConfig::default().max_pending_per_session, 4);
    let mut limits = ListenerConfig::default();
    limits.max_pending_per_session = 0;
    assert!(Listener::new(Config::default(), limits).is_err());
}
