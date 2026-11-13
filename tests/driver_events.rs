//! The pipe-event queue stays bounded: a peer that joins and drops pipes in
//! a loop while the application reads no events leaves memory bounded, and
//! no terminal outcome is lost.

use std::future::Future;
use std::time::{Duration, Instant};

use zmux::{
    CapacityFloor, Config, Listener, ListenerConfig, PipeAuth, PipeError, PipeHint, PipeIo,
    PipeOptions, QualityBand, Session, SessionEvent,
};

fn config() -> Config {
    let mut c = Config::default();
    c.max_pipes = 4;
    c.pipe_auth = PipeAuth::psk(*b"events-test-psk-0123456789abcdef").with_end_to_end();
    c
}

/// A carrier pair in memory; the second half goes to the listener.
fn carrier(listener: &Listener) -> PipeIo {
    let (a, b) = tokio::io::duplex(256 * 1024);
    let l = listener.clone();
    tokio::spawn(async move {
        let _ = l
            .handle_pipe(
                PipeIo::new(b),
                PipeHint::from_peer(([127, 0, 0, 1], 0).into()),
            )
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
    let listener =
        Listener::new(config(), ListenerConfig::default()).expect("valid listener configuration");
    let client = Session::connect(carrier(&listener), config())
        .await
        .unwrap();
    let server = listener.accept().await.unwrap();
    assert!(client.multipath() == zmux::Multipath::InUse);
    // Unretired attachments per joiner: max_pipes + H (8); per attachment
    // two directions and a priority slot, plus the summary.
    let bound = 3 * (2 * (4 + 8) + 1) + 1;
    let mut most = (0, 0);
    let mut refused = 0;
    for round in 0..60u32 {
        let pipe = client
            .begin_add_pipe(carrier(&listener), PipeOptions::default())
            .unwrap();
        let joined = tokio::time::timeout(Duration::from_secs(10), pipe.joined())
            .await
            .expect("timed out: pipe joined");
        match joined {
            Ok(()) => {}
            // The joiner may retire a dropped attachment before the acceptor
            // does (MULTIPATH.md Section 8.4); a join it releases then can
            // meet the acceptor's cap and be refused (Section 5.4 step 9),
            // and the refused attachment is retired at once.
            Err(PipeError::JoinRefused) => {
                assert!(server.pipes().iter().all(|p| p.id() != pipe.id()));
                refused += 1;
                continue;
            }
            Err(e) => panic!("join failed: {e:?}"),
        }
        // The joiner is ACTIVE at the verified Reply, before the acceptor has
        // the confirmation and attachment state (MULTIPATH.md Section 5.4):
        // a pipe dropped before then never existed at the server, which
        // would report nothing of it.
        until("pipe attached at the server", || {
            server.pipes().iter().any(|p| p.id() == pipe.id())
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
    assert!(refused < 60, "every join was refused");
    // The session still works.
    let (mut send, mut recv) = client.open_bi().await.unwrap();
    send.write_all(b"ping").await.unwrap();
    send.finish().unwrap();
    let (mut s2, mut r2) = server.accept_bi().await.unwrap();
    assert_eq!(r2.read_to_end(16).await.unwrap(), b"ping");
    s2.finish().unwrap();
    assert_eq!(recv.read_to_end(16).await.unwrap(), b"");

    // Every pipe is accounted for: reported live, or counted as retired.
    client.close().await;
    let mut retired = 0;
    let mut seen = std::collections::HashSet::new();
    while let Some(e) = server.next_event().await {
        match e {
            SessionEvent::PipesRetired { retired: n, .. } => retired += n,
            e => {
                if let Some(pipe) = e.pipe() {
                    seen.insert(pipe);
                }
            }
        }
    }
    assert!(retired > 0);
    assert!(
        retired + seen.len() as u64 + refused >= 60,
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
    let listener =
        Listener::new(config(), ListenerConfig::default()).expect("valid listener configuration");
    let client = Session::connect(carrier(&listener), config())
        .await
        .unwrap();
    let _server = listener.accept().await.unwrap();
    let pipe = client
        .begin_add_pipe(carrier(&listener), PipeOptions::default())
        .unwrap();
    pipe.set_quality_band(Some(QualityBand::new(
        Some(Duration::from_millis(5)),
        Some(1.5),
    )))
    .unwrap();
    client.set_quality_band(None).unwrap();
    // A rate ratio that is not a number, or a negative one, is rejected.
    for bad in [f64::NAN, -1.0] {
        let band = Some(QualityBand::new(Some(Duration::from_millis(5)), Some(bad)));
        assert!(matches!(
            client.set_quality_band(band),
            Err(zmux::PipeError::InvalidOptions(_))
        ));
        assert!(matches!(
            pipe.set_quality_band(band),
            Err(zmux::PipeError::InvalidOptions(_))
        ));
    }
    let mut nan = CapacityFloor::new(1);
    nan.rate_ratio = f64::NAN;
    assert!(matches!(
        client.set_capacity_floor(Some(nan)),
        Err(zmux::PipeError::InvalidOptions(_))
    ));
    client
        .set_capacity_floor(Some(CapacityFloor::new(u64::MAX)))
        .unwrap();
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
    client.set_capacity_floor(None).unwrap();
}

/// A local join is reported by the six pipe state events: `PipeAdded`, then `PipeJoined`, then its terminal event, which
/// closes the outbound direction.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_join_reports_added_joined_and_closed() {
    let listener =
        Listener::new(config(), ListenerConfig::default()).expect("valid listener configuration");
    let client = Session::connect(carrier(&listener), config())
        .await
        .unwrap();
    let _server = listener.accept().await.unwrap();
    let pipe = client
        .begin_add_pipe(carrier(&listener), PipeOptions::default())
        .unwrap();
    let id = pipe.id();
    let mut seen = Vec::new();
    tokio::time::timeout(Duration::from_secs(10), async {
        while !seen.iter().any(|e: &SessionEvent| e.is_terminal()) {
            let e = client.next_event().await.expect("an event");
            // Retired before its end was read, the end is counted there.
            if let SessionEvent::PipesRetired { last, closed, .. } = &e
                && last.contains(&id)
            {
                assert!(*closed <= 1, "{e:?}");
                seen.push(SessionEvent::PipeClosed {
                    pipe: id,
                    half: zmux::PipeHalf::Outbound,
                    carrier: None,
                });
                continue;
            }
            // The inbound end may come before or after the outbound one.
            let inbound = matches!(
                e,
                SessionEvent::PipeClosed {
                    half: zmux::PipeHalf::Inbound,
                    ..
                }
            );
            if e.pipe() != Some(id) || inbound {
                continue;
            }
            if matches!(e, SessionEvent::PipeJoined { .. }) {
                pipe.close().unwrap();
            }
            seen.push(e);
        }
    })
    .await
    .unwrap_or_else(|_| panic!("events: {seen:?}"));
    assert!(
        matches!(
            seen[..],
            [
                SessionEvent::PipeAdded { .. },
                SessionEvent::PipeJoined { .. },
                SessionEvent::PipeClosed {
                    half: zmux::PipeHalf::Outbound,
                    ..
                }
            ]
        ),
        "{seen:?}"
    );
}

/// A join held by the attachment cap is pending, not failed: waiting for
/// it does not end at once, and its handshake runs once the cap has room.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_join_held_by_the_cap_is_pending_and_goes_once_there_is_room() {
    let mut c = config();
    c.max_pipes = 2;
    c.pipe_headroom = 0;
    // The acceptor has room for both: only the joiner holds its join.
    let listener =
        Listener::new(config(), ListenerConfig::default()).expect("valid listener configuration");
    let client = Session::connect(carrier(&listener), c).await.unwrap();
    let server = listener.accept().await.unwrap();
    let first = client
        .begin_add_pipe(carrier(&listener), PipeOptions::default())
        .unwrap();
    first.joined().await.unwrap();
    until("first pipe attached at the server", || {
        server.pipes().iter().any(|p| p.id() == first.id())
    })
    .await;
    // The bootstrap pipe and `first` fill the cap: this join is held.
    let held = client
        .begin_add_pipe(carrier(&listener), PipeOptions::default())
        .unwrap();
    let mut joined = std::pin::pin!(held.joined());
    let waker = std::task::Waker::noop();
    assert!(
        joined
            .as_mut()
            .poll(&mut std::task::Context::from_waker(waker))
            .is_pending(),
        "a held join reads as ended"
    );
    first.abort().unwrap();
    tokio::time::timeout(Duration::from_secs(10), joined)
        .await
        .expect("the held join goes once the cap has room")
        .unwrap();
}

/// A join the acceptor refuses for its cap reports the refusal, though the
/// joiner retires the attachment at once: to `joined`, to every handle of
/// the pipe, and to `add_pipe`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_refused_join_reports_the_refusal_after_its_retirement() {
    let mut acceptor = config();
    acceptor.max_pipes = 2;
    acceptor.pipe_headroom = 0;
    let listener =
        Listener::new(acceptor, ListenerConfig::default()).expect("valid listener configuration");
    let client = Session::connect(carrier(&listener), config())
        .await
        .unwrap();
    let _server = listener.accept().await.unwrap();
    // The bootstrap pipe and this one fill the acceptor's cap.
    client
        .add_pipe(carrier(&listener), PipeOptions::default())
        .await
        .unwrap();
    // The acceptor reads this join only once the second handle is taken:
    // a refusal that came first would retire the pipe before the lookup.
    let (a, b) = tokio::io::duplex(256 * 1024);
    let refused = client
        .begin_add_pipe(PipeIo::new(a), PipeOptions::default())
        .unwrap();
    let other = client.pipe(refused.id()).expect("known while joining");
    let l = listener.clone();
    tokio::spawn(async move {
        let _ = l
            .handle_pipe(
                PipeIo::new(b),
                PipeHint::from_peer(([127, 0, 0, 1], 0).into()),
            )
            .await;
    });
    assert_eq!(refused.joined().await, Err(PipeError::JoinRefused));
    assert!(refused.stats().is_none(), "retired at once");
    assert_eq!(other.joined().await, Err(PipeError::JoinRefused));
    assert_eq!(refused.attached().await, Err(PipeError::JoinRefused));
    let added = client
        .add_pipe(carrier(&listener), PipeOptions::default())
        .await;
    assert_eq!(added.err(), Some(PipeError::JoinRefused));
}
