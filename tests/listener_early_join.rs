//! A join that arrives as carrier early data is offered only once the
//! carrier's handshake completed; one whose handshake does not complete in
//! time is a setup failure and counted nowhere else in the statistics.

#[path = "common/clock.rs"]
mod clock;

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Notify;

use clock::ManualClock;
use zmux::{
    ClockDomain, Config, HandleError, Listener, ListenerConfig, MonotonicClock, PipeAuth, PipeHint,
    PipeIo, Session,
};

fn config() -> Config {
    let mut c = Config::default();
    c.session_policy.limits.steady_attachments = 4;
    c.pipe_auth = PipeAuth::psk(*b"early-join-test-psk-0123456789ab").with_end_to_end();
    c
}

const WATCHDOG: Duration = Duration::from_secs(30);

#[tokio::test]
async fn an_early_join_whose_handshake_never_completes_is_a_setup_failure() {
    tokio::time::timeout(WATCHDOG, async {
        let wait = Duration::from_secs(41);
        let (clock, domain) = ManualClock::domain(Duration::from_secs(120));
        let mut accepting = config();
        accepting.clock_domain = domain.clone();
        accepting.join_timeout = wait;
        let listener = Listener::new(accepting, ListenerConfig::default()).unwrap();
        let (c0, s0) = tokio::io::duplex(1 << 16);
        let l = listener.clone();
        tokio::spawn(async move { l.handle_pipe(PipeIo::new(s0), PipeHint::default()).await });
        let mut dialing = config();
        dialing.join_timeout = Duration::from_secs(60);
        let client = Session::connect(PipeIo::new(c0), dialing).await.unwrap();
        let _server = listener.accept().await.unwrap();
        let mut timers = clock.registrations();
        let deadline = domain.now() + wait;
        let (c1, s1) = tokio::io::duplex(1 << 16);
        let _pipe = client
            .test_begin_join(PipeIo::new(c1), zmux::PipeOptions::new())
            .unwrap();
        // The server's carrier took the join as early data, and its
        // handshake never completes.
        let io = PipeIo::new(s1).with_early_data_in(std::future::pending::<()>);
        let accepting = listener.clone();
        let handling =
            tokio::spawn(async move { accepting.handle_pipe(io, PipeHint::default()).await });
        while timers.recv().await.unwrap() != deadline {}
        clock.advance(wait);
        assert_eq!(handling.await.unwrap(), Err(HandleError::SetupFailed));
        let st = listener.stats();
        assert_eq!(st.setup_failures, 1);
        assert_eq!(
            (st.sessions, st.joins, st.rejected, st.refused, st.timed_out),
            (1, 0, 0, 0, 0)
        );
        client.close().await;
        listener.close();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn an_early_join_goes_on_once_the_handshake_completed() {
    tokio::time::timeout(WATCHDOG, async {
        let listener = Listener::new(config(), ListenerConfig::default())
            .expect("valid listener configuration");
        let (c0, s0) = tokio::io::duplex(1 << 16);
        let l = listener.clone();
        tokio::spawn(async move { l.handle_pipe(PipeIo::new(s0), PipeHint::default()).await });
        let client = Session::connect(PipeIo::new(c0), config()).await.unwrap();
        let _server = listener.accept().await.unwrap();
        let (c1, s1) = tokio::io::duplex(1 << 16);
        let pipe = client
            .test_begin_join(PipeIo::new(c1), zmux::PipeOptions::new())
            .unwrap();
        let started = Arc::new(Notify::new());
        let complete = Arc::new(Notify::new());
        let (entered, finish) = (started.clone(), complete.clone());
        let io = PipeIo::new(s1).with_early_data_in(move || {
            let (entered, finish) = (entered.clone(), finish.clone());
            async move {
                entered.notify_one();
                finish.notified().await;
            }
        });
        let accepting = listener.clone();
        let handling =
            tokio::spawn(async move { accepting.handle_pipe(io, PipeHint::default()).await });
        started.notified().await;
        assert_eq!(listener.stats().joins, 0);
        complete.notify_one();
        pipe.joined().await.unwrap();
        handling.await.unwrap().unwrap();
        assert_eq!(listener.stats().joins, 1);
        assert_eq!(listener.stats().setup_failures, 0);
        client.close().await;
        listener.close();
    })
    .await
    .unwrap();
}

#[tokio::test(start_paused = true)]
async fn listener_close_interrupts_named_early_join() {
    let listener = Listener::new(config(), ListenerConfig::default()).unwrap();
    let (c0, s0) = tokio::io::duplex(1 << 16);
    let l = listener.clone();
    tokio::spawn(async move { l.handle_pipe(PipeIo::new(s0), PipeHint::default()).await });
    let client = Session::connect(PipeIo::new(c0), config()).await.unwrap();
    let _server = listener.accept().await.unwrap();
    let (near, far) = tokio::io::duplex(1 << 16);
    let _pipe = client
        .test_begin_join(PipeIo::new(near), zmux::PipeOptions::new())
        .unwrap();
    let started = Arc::new(Notify::new());
    let entered = started.clone();
    let io = PipeIo::new(far).with_early_data_in(move || {
        entered.notify_one();
        std::future::pending::<()>()
    });
    let l = listener.clone();
    let handler = tokio::spawn(async move { l.handle_pipe(io, PipeHint::default()).await });
    started.notified().await;
    let before = tokio::time::Instant::now();
    listener.close();
    assert_eq!(handler.await.unwrap(), Err(HandleError::Refused));
    assert_eq!(listener.stats().setup_failures, 0);
    assert_eq!(before, tokio::time::Instant::now());
}
