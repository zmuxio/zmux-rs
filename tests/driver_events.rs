//! The pipe-event queue stays bounded (CONFORMANCE.md): a peer that joins and drops pipes in
//! a loop while the application reads no events leaves memory bounded, and
//! no terminal outcome is lost.

use std::time::{Duration, Instant};

use zmux::{
    CapacityFloor, Config, Listener, ListenerConfig, PipeAuth, PipeHint, PipeIo, PipeOptions,
    PipeState, QualityBand, Session, SessionEvent,
};

fn config() -> Config {
    let mut c = Config::default();
    c.max_pipes = 4;
    c.pipe_auth = PipeAuth::psk(*b"events-test-psk-0123456789abcdef");
    c
}

/// A carrier pair in memory; the second half goes to the listener.
fn carrier(listener: &Listener) -> PipeIo {
    let (a, b) = tokio::io::duplex(256 * 1024);
    let l = listener.clone();
    tokio::spawn(async move {
        let _ = l
            .handle_pipe(PipeIo::new(b), PipeHint::from_addr([127, 0, 0, 1].into()))
            .await;
    });
    PipeIo::new(a)
}

async fn until(what: &str, mut f: impl FnMut() -> bool) {
    let start = Instant::now();
    while !f() {
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "timed out: {what}"
        );
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn join_and_drop_churn_keeps_the_queue_bounded() {
    let listener = Listener::new(config(), ListenerConfig::default());
    let client = Session::connect(carrier(&listener), config())
        .await
        .unwrap();
    let server = listener.accept().await.unwrap();
    assert!(client.multipath() == zmux::Multipath::InUse);
    // Unretired attachments per joiner: max_pipes + H (8); per attachment
    // two directions and a priority slot, plus the summary.
    let bound = 3 * (2 * (4 + 8) + 1) + 1;
    let mut most = (0, 0);
    for round in 0..60u32 {
        let pipe = client
            .add_pipe(carrier(&listener), PipeOptions::default())
            .unwrap();
        until("pipe active", || {
            pipe.stats()
                .is_some_and(|i| i.outbound == Some(PipeState::Active))
        })
        .await;
        if round.is_multiple_of(2) {
            pipe.abort().unwrap();
        } else {
            pipe.close().unwrap();
        }
        most.0 = most.0.max(client.event_backlog());
        most.1 = most.1.max(server.event_backlog());
        assert!(
            server.pipes().len() <= 2 * (4 + 8) + 1,
            "{}",
            server.pipes().len()
        );
    }
    assert!(most.0 <= bound && most.1 <= bound, "{most:?}");
    // The session still works.
    let (mut send, mut recv) = client.open_bi().await.unwrap();
    send.write_all(b"ping").await.unwrap();
    send.finish().unwrap();
    let (mut s2, mut r2) = server.accept_bi().await.unwrap();
    assert_eq!(r2.read_to_end(16).await.unwrap(), b"ping");
    s2.finish().unwrap();
    assert_eq!(recv.read_to_end(16).await.unwrap(), b"");

    // Every pipe is accounted for: reported live, or counted as retired.
    client.close(0u32.into(), b"");
    let mut retired = 0;
    let mut seen = std::collections::HashSet::new();
    while let Some(e) = server.next_event().await {
        match e {
            SessionEvent::PipesRetired { retired: n, .. } => retired += n,
            SessionEvent::PipeState { pipe, .. } => {
                seen.insert(pipe);
            }
            _ => {}
        }
    }
    assert!(retired > 0);
    assert!(
        retired + seen.len() as u64 >= 60,
        "retired {retired}, live {}",
        seen.len()
    );
    drop(listener);
}

/// Quality events reach the application through the
/// pipe-event queue; a capacity floor set while the capacity is below it
/// is reported at once, and a pipe takes a band of its own.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn quality_events_reach_the_application() {
    let listener = Listener::new(config(), ListenerConfig::default());
    let client = Session::connect(carrier(&listener), config())
        .await
        .unwrap();
    let _server = listener.accept().await.unwrap();
    let pipe = client
        .add_pipe(carrier(&listener), PipeOptions::default())
        .unwrap();
    pipe.set_quality_band(Some(QualityBand::new(Duration::from_millis(5), 1.5)))
        .unwrap();
    client.set_quality_band(None);
    client.set_capacity_floor(Some(CapacityFloor::new(u64::MAX)));
    let event = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            match client.next_event().await {
                Some(e @ SessionEvent::CapacityBelow { .. }) => return Some(e),
                Some(_) => {}
                None => return None,
            }
        }
    })
    .await
    .unwrap();
    assert!(
        matches!(event, Some(SessionEvent::CapacityBelow { rate }) if rate < u64::MAX),
        "{event:?}"
    );
    client.set_capacity_floor(None);
}
