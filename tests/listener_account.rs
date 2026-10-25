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
    limits.memory_budget = 1024;
    let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let log = seen.clone();
    limits.on_memory_pressure = Some(zmux::OnMemoryPressure(std::sync::Arc::new(
        move |p: zmux::MemoryPressure| {
            assert_eq!(p.budget, 1024);
            log.lock().unwrap().push(p.active);
        },
    )));
    let listener = Listener::new(Config::default(), limits);
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
        dialer.abort();
        if r == Err(HandleError::Refused) {
            refused = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(refused, "a listener over its budget accepted a session");
    eventually(10, "pressure reported", || {
        seen.lock().unwrap().first() == Some(&true)
    })
    .await;
    client.close(zmux::VarInt::from_u32(0), b"");
    watchdog(10, "server closed", server.closed()).await;
    drop((client, server));
    // The ended session's charge left the account.
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
    // Pressure ended before the new session was accepted, and was
    // reported once each way, in order (the new session may start it
    // again).
    eventually(10, "pressure end reported", || {
        seen.lock().unwrap().len() >= 2
    })
    .await;
    assert_eq!(seen.lock().unwrap()[..2], [true, false]);
    drop(c);
    listener.close();
}

fn mp_config() -> Config {
    let mut c = Config::default();
    c.max_pipes = 4;
    c.pipe_auth = PipeAuth::psk(*b"account-test-psk-0123456789abcd!");
    c.suspect_floor = Duration::from_millis(100);
    c.resume_timeout = Some(Duration::from_secs(30));
    c
}

/// Beyond `max_suspended`, the session suspended first is closed; the one
/// suspended later stays suspended.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_oldest_suspended_session_beyond_the_limit_is_closed() {
    let mut limits = ListenerConfig::default();
    limits.max_suspended = 1;
    let listener = Listener::new(mp_config(), limits);
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
    watchdog(30, "the oldest closed", pairs[0].1.closed()).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        pairs[1].1.state(),
        State::Suspended,
        "the newer one was closed"
    );
    drop(pairs);
    listener.close();
}
