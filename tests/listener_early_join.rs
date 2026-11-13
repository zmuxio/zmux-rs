//! A join that arrives as carrier early data is offered only once the
//! carrier's handshake completed; one whose handshake does not complete in
//! time is a setup failure and counted nowhere else in the statistics.

use std::time::Duration;

use zmux::{Config, HandleError, Listener, ListenerConfig, PipeAuth, PipeHint, PipeIo, Session};

fn config() -> Config {
    let mut c = Config::default();
    c.max_pipes = 4;
    c.pipe_auth = PipeAuth::psk(*b"early-join-test-psk-0123456789ab").with_end_to_end();
    c
}

fn limits() -> ListenerConfig {
    let mut l = ListenerConfig::default();
    l.handshake_timeout = Duration::from_millis(300);
    l
}

#[tokio::test]
async fn an_early_join_whose_handshake_never_completes_is_a_setup_failure() {
    tokio::time::timeout(Duration::from_secs(20), async {
        let listener = Listener::new(config(), limits()).expect("valid listener configuration");
        let (c0, s0) = tokio::io::duplex(1 << 16);
        let l = listener.clone();
        tokio::spawn(async move { l.handle_pipe(PipeIo::new(s0), PipeHint::default()).await });
        let client = Session::connect(PipeIo::new(c0), config()).await.unwrap();
        let _server = listener.accept().await.unwrap();
        let (c1, s1) = tokio::io::duplex(1 << 16);
        let _pipe = client
            .begin_add_pipe(PipeIo::new(c1), zmux::PipeOptions::new())
            .unwrap();
        // The server's carrier took the join as early data, and its
        // handshake never completes.
        let io = PipeIo::new(s1).with_early_data_in(std::future::pending::<()>);
        let r = listener.handle_pipe(io, PipeHint::default()).await;
        assert_eq!(r, Err(HandleError::SetupFailed));
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
    tokio::time::timeout(Duration::from_secs(20), async {
        let listener = Listener::new(config(), limits()).expect("valid listener configuration");
        let (c0, s0) = tokio::io::duplex(1 << 16);
        let l = listener.clone();
        tokio::spawn(async move { l.handle_pipe(PipeIo::new(s0), PipeHint::default()).await });
        let client = Session::connect(PipeIo::new(c0), config()).await.unwrap();
        let _server = listener.accept().await.unwrap();
        let (c1, s1) = tokio::io::duplex(1 << 16);
        let pipe = client
            .begin_add_pipe(PipeIo::new(c1), zmux::PipeOptions::new())
            .unwrap();
        let io =
            PipeIo::new(s1).with_early_data_in(|| tokio::time::sleep(Duration::from_millis(50)));
        let l = listener.clone();
        tokio::spawn(async move { l.handle_pipe(io, PipeHint::default()).await });
        pipe.joined().await.unwrap();
        assert_eq!(listener.stats().joins, 1);
        assert_eq!(listener.stats().setup_failures, 0);
        client.close().await;
        listener.close();
    })
    .await
    .unwrap();
}
