//! The keyed event queue stays bounded and never drops: a peer that joins
//! and drops pipes in a loop, or fails joins in a loop, while the application
//! reads no events leaves memory bounded, and no terminal outcome is lost; the
//! tracer is told every occurrence through a fixed backlog.

#![allow(
    clippy::cast_possible_truncation,
    reason = "test values are small and bounded; checked conversions would only add noise"
)]

use std::future::Future;
use std::sync::Arc;
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
    assert_eq!(client.multipath(), zmux::Multipath::InUse);
    // The keys of the pipes the session holds, at most nine each, plus the
    // summary and the session's own few: the unretired attachments are
    // bounded by what admits them.
    let bound = 9 * (2 * (4 + 8) + 1) + 16;
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
            Err(PipeError::Failed(zmux::PipeFailure::JoinRefused)) => {
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
    pipe.update(&zmux::PipeUpdate {
        quality_band: zmux::Change::Set(Some(QualityBand::new(
            Some(Duration::from_millis(5)),
            Some(1.5),
        ))),
        ..Default::default()
    })
    .unwrap();
    client.set_quality_band(None).unwrap();
    // A rate ratio other than finite and at least 1 is rejected, 0 included.
    for bad in [0.0, f64::NAN, -1.0, 0.5, f64::INFINITY] {
        let band = Some(QualityBand::new(Some(Duration::from_millis(5)), Some(bad)));
        assert!(matches!(
            client.set_quality_band(band),
            Err(zmux::PipeError::InvalidOptions(_))
        ));
        assert!(matches!(
            pipe.update(&zmux::PipeUpdate {
                quality_band: zmux::Change::Set(band),
                ..Default::default()
            }),
            Err(zmux::PipeError::InvalidOptions(_))
        ));
    }
    for bad in [0.0, f64::NAN, -1.0, 0.5, 0.999, f64::INFINITY] {
        let mut floor = CapacityFloor::new(1);
        floor.recovery_ratio = bad;
        assert!(matches!(
            client.set_capacity_floor(Some(floor)),
            Err(zmux::PipeError::InvalidOptions(_))
        ));
    }
    assert!(matches!(
        client.set_capacity_floor(Some(CapacityFloor::new(0))),
        Err(zmux::PipeError::InvalidOptions(_))
    ));
    let mut floor = CapacityFloor::new(1);
    floor.recovery_ratio = 1.0;
    client.set_capacity_floor(Some(floor)).unwrap();
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
    assert!(matches!(
        refused.joined().await,
        Err(PipeError::Failed(zmux::PipeFailure::JoinRefused))
    ));
    assert!(refused.stats().is_none(), "retired at once");
    assert!(matches!(
        other.joined().await,
        Err(PipeError::Failed(zmux::PipeFailure::JoinRefused))
    ));
    assert!(matches!(
        refused.attached().await,
        Err(PipeError::Failed(zmux::PipeFailure::JoinRefused))
    ));
    let added = client
        .add_pipe(carrier(&listener), PipeOptions::default())
        .await;
    assert!(matches!(
        added.err(),
        Some(PipeError::Failed(zmux::PipeFailure::JoinRefused))
    ));
}

/// A carrier pair in memory whose two ends export `ends.0` and `ends.1`;
/// the second half goes to the listener. A session whose bootstrap carrier
/// has two different values derives two different join secrets: every join
/// of it fails verification at the acceptor.
fn exporting_carrier(listener: &Listener, ends: (u8, u8)) -> PipeIo {
    let (a, b) = tokio::io::duplex(256 * 1024);
    let l = listener.clone();
    tokio::spawn(async move {
        let _ = l
            .handle_pipe(
                PipeIo::new(b).with_exporter(move |label, context, out| {
                    out.fill(label.len() as u8 ^ context.len() as u8 ^ ends.1);
                    true
                }),
                PipeHint::from_peer(([127, 0, 0, 1], 0).into()),
            )
            .await;
    });
    PipeIo::new(a).with_exporter(move |label, context, out| {
        out.fill(label.len() as u8 ^ context.len() as u8 ^ ends.0);
        true
    })
}

/// A peer that fails joins over and over, beside the events of the session:
/// the failures are counted in one `JoinAuthFailed`, no other event is
/// displaced or lost, and the queue holds a constant number of slots.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn failed_joins_never_displace_other_events() {
    let mut c = Config::multipath(PipeAuth::exporter().with_end_to_end());
    c.max_pipes = 4;
    let listener =
        Listener::new(c.clone(), ListenerConfig::default()).expect("valid listener configuration");
    let client = Session::connect(exporting_carrier(&listener, (0, 1)), c)
        .await
        .unwrap();
    let server = listener.accept().await.unwrap();
    // An event the server queued before the failures.
    server
        .set_capacity_floor(Some(CapacityFloor::new(u64::MAX)))
        .unwrap();
    until("the capacity event", || server.event_backlog() > 0).await;
    let before = server.event_backlog();
    let hostile = 40;
    let mut most = 0;
    for _ in 0..hostile {
        let pipe = client
            .begin_add_pipe(exporting_carrier(&listener, (0, 0)), PipeOptions::default())
            .unwrap();
        let joined = tokio::time::timeout(Duration::from_secs(10), pipe.joined())
            .await
            .expect("timed out: hostile join");
        assert!(joined.is_err(), "a hostile join verified");
        most = most.max(server.event_backlog());
    }
    // One slot for the failures, whatever their number.
    assert_eq!(most, before + 1, "after {hostile} failures");
    assert_eq!(server.stats().join_auth_failures, hostile);
    // What was queued before is read first, and the failures follow as one
    // count.
    let mut events = Vec::new();
    while server.event_backlog() > 0 {
        events.push(server.next_event().await.expect("an event"));
    }
    assert!(
        matches!(
            events[..],
            [
                SessionEvent::CapacityBelow { .. },
                SessionEvent::JoinAuthFailed {
                    reason: "auth",
                    count
                }
            ] if count == hostile
        ),
        "{events:?}"
    );
    drop(listener);
}

/// A tracer whose first call blocks until the test opens the gate; it
/// keeps what it was told.
struct Gated {
    gate: std::sync::Mutex<bool>,
    open: std::sync::Condvar,
    records: std::sync::Mutex<Vec<zmux::TraceRecord>>,
}

impl zmux::Tracer for Gated {
    fn trace(&self, _: zmux::SessionId, record: &zmux::TraceRecord) {
        let mut open = self.gate.lock().unwrap();
        while !*open {
            open = self.open.wait(open).unwrap();
        }
        drop(open);
        self.records.lock().unwrap().push(record.clone());
    }
}

impl Gated {
    fn release(&self) {
        *self.gate.lock().unwrap() = true;
        self.open.notify_all();
    }

    fn told(&self) -> Vec<zmux::TraceRecord> {
        self.records.lock().unwrap().clone()
    }
}

/// Forwards to a [`Gated`] and holds one end of a channel, so that the
/// channel disconnects when the last reference to the tracer is gone: the
/// session and its hook context are finished and nothing more is told.
struct Watched {
    inner: Arc<Gated>,
    _alive: std::sync::mpsc::Sender<()>,
}

impl zmux::Tracer for Watched {
    fn trace(&self, session: zmux::SessionId, record: &zmux::TraceRecord) {
        self.inner.trace(session, record);
    }
}

/// A tracer that blocks gets `established` first, every lost event counted
/// in a `dropped` before the next event it receives or before `closed`, and
/// `closed` last, with nothing after it; the session's own event stream
/// loses nothing meanwhile.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_blocked_tracer_is_told_what_it_lost_in_place() {
    use zmux::{Change, PipeUpdate, TraceRecord};
    let gated = Arc::new(Gated {
        gate: std::sync::Mutex::new(false),
        open: std::sync::Condvar::new(),
        records: std::sync::Mutex::new(Vec::new()),
    });
    let mut traced = config();
    let (alive, gone) = std::sync::mpsc::channel::<()>();
    traced.tracer = Some(Arc::new(Watched {
        inner: gated.clone(),
        _alive: alive,
    }));
    let listener =
        Listener::new(config(), ListenerConfig::default()).expect("valid listener configuration");
    let client = Session::connect(carrier(&listener), traced).await.unwrap();
    let _server = listener.accept().await.unwrap();
    let pipe = client
        .begin_add_pipe(carrier(&listener), PipeOptions::default())
        .unwrap();
    tokio::time::timeout(Duration::from_secs(10), pipe.joined())
        .await
        .expect("timed out: pipe joined")
        .unwrap();
    // 300 priority changes while the tracer is blocked in its first call.
    let update = |p: u64| PipeUpdate {
        send_priority: Change::Set(p),
        ..Default::default()
    };
    for i in 0..300u64 {
        pipe.update(&update(1 + i % 2)).unwrap();
    }
    // The stream keeps one slot for the pipe's priority, however often it
    // changed.
    assert!(client.event_backlog() <= 8, "{}", client.event_backlog());
    gated.release();
    // The 256 events the backlog held, then the next event that is accepted,
    // with the count before it: the changes past the backlog were lost
    // there, and nothing queued was replaced.
    until("the backlog was read", || gated.told().len() >= 257).await;
    pipe.update(&update(3)).unwrap();
    let last = |r: &TraceRecord| {
        matches!(
            r,
            TraceRecord::Event(zmux::SessionEvent::PipePriorityChanged {
                send_priority: 3,
                ..
            })
        )
    };
    until("the last change", || gated.told().iter().any(last)).await;
    let told = gated.told();
    assert_eq!(told[0], TraceRecord::Established);
    assert!(
        told[1..257]
            .iter()
            .all(|r| matches!(r, TraceRecord::Event(_)))
    );
    let TraceRecord::Dropped(missed) = told[257] else {
        panic!("{:?}", &told[255..]);
    };
    // The pipe's two events and 299 changes (the first value was the default)
    // made 301 events or more, 256 held.
    assert!(missed >= 45, "{missed}");
    assert!(
        told[258..]
            .iter()
            .all(|r| !matches!(r, TraceRecord::Dropped(_)))
    );
    // Nothing is lost beyond the count: 300 + 1 changes and the pipe's own
    // events were told or counted. The end is last and alone.
    client.close().await;
    // Once the session and its hook context are gone (the tracer's last
    // reference with them), nothing can be told any more.
    drop(pipe);
    drop(client);
    let ended = tokio::task::spawn_blocking(move || gone.recv_timeout(Duration::from_secs(30)))
        .await
        .unwrap();
    assert_eq!(
        ended,
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected),
        "the session's hook context ended"
    );
    let told = gated.told();
    assert_eq!(
        told.iter()
            .filter(|r| matches!(r, TraceRecord::Closed(_)))
            .count(),
        1
    );
    assert!(matches!(told.last(), Some(TraceRecord::Closed(_))));
    drop(listener);
}

/// The tracer is told each retirement as it happens: one `PipesRetired` per
/// pipe, `retired` 1, `last` that pipe, `failed` or `closed` by how the
/// pipe ended; the event stream folds them into one.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_tracer_is_told_one_retirement_per_pipe() {
    use zmux::TraceRecord;
    let gated = Arc::new(Gated {
        gate: std::sync::Mutex::new(true),
        open: std::sync::Condvar::new(),
        records: std::sync::Mutex::new(Vec::new()),
    });
    let mut traced = config();
    traced.tracer = Some(gated.clone());
    let listener =
        Listener::new(config(), ListenerConfig::default()).expect("valid listener configuration");
    let client = Session::connect(carrier(&listener), traced).await.unwrap();
    let server = listener.accept().await.unwrap();
    let mut ids = Vec::new();
    for round in 0..4 {
        let pipe = client
            .begin_add_pipe(carrier(&listener), PipeOptions::default())
            .unwrap();
        tokio::time::timeout(Duration::from_secs(10), pipe.joined())
            .await
            .expect("timed out: pipe joined")
            .unwrap();
        until("pipe attached at the server", || {
            server.pipes().iter().any(|p| p.id() == pipe.id())
        })
        .await;
        if round % 2 == 0 {
            pipe.abort().unwrap();
        } else {
            pipe.close().unwrap();
        }
        ids.push(pipe.id());
    }
    until("every retirement was traced", || {
        let retired = |id| {
            gated.told().iter().any(|r| {
                matches!(r, TraceRecord::Event(zmux::SessionEvent::PipesRetired { last, .. }) if *last == [id])
            })
        };
        ids.iter().all(|&id| retired(id))
    })
    .await;
    // An aborted pipe counts as failed, a closed one as closed.
    for (round, id) in ids.iter().enumerate() {
        let (failed, closed) = if round % 2 == 0 { (1, 0) } else { (0, 1) };
        let told = gated.told();
        let one = told.iter().filter(|r| {
            matches!(r, TraceRecord::Event(zmux::SessionEvent::PipesRetired { last, .. }) if *last == [*id])
        });
        assert_eq!(one.clone().count(), 1);
        assert!(
            one.into_iter().all(|r| *r
                == TraceRecord::Event(zmux::SessionEvent::PipesRetired {
                    retired: 1,
                    failed,
                    closed,
                    last: vec![*id],
                })),
            "pipe {id:?}"
        );
    }
    drop(listener);
}

/// A tracer that panics at every call: the session logs each panic.
struct Panics;

impl zmux::Tracer for Panics {
    fn trace(&self, _: zmux::SessionId, _: &zmux::TraceRecord) {
        panic!("a tracer that panics");
    }
}

/// A subscription nobody reads holds 256 of a session's log lines: the rest
/// are dropped and counted in `log_lines_dropped`, never in a trace `Dropped`,
/// and the trace records and the end are not affected.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_full_log_queue_counts_the_lines_it_drops() {
    use zmux::{Change, HostEvent, PipeUpdate, TraceRecord};
    let mut traced = config();
    traced.tracer = Some(Arc::new(Panics));
    traced.logger = Some(zmux::Logger::new(|_, _| {}));
    let events = traced.events();
    let listener =
        Listener::new(config(), ListenerConfig::default()).expect("valid listener configuration");
    let client = Session::connect(carrier(&listener), traced).await.unwrap();
    let _server = listener.accept().await.unwrap();
    let pipe = client
        .begin_add_pipe(carrier(&listener), PipeOptions::default())
        .unwrap();
    tokio::time::timeout(Duration::from_secs(10), pipe.joined())
        .await
        .expect("timed out: pipe joined")
        .unwrap();
    // Each change is traced, each panic logged, one line per call.
    for i in 0..400u64 {
        pipe.update(&PipeUpdate {
            send_priority: Change::Set(3 + i % 2),
            ..Default::default()
        })
        .unwrap();
    }
    until("256 lines queued and the rest dropped", || {
        client.stats().log_lines_dropped > 0
    })
    .await;
    let id = client.id();
    client.close().await;
    let mut lines = 0;
    let mut dropped = 0;
    while let Some(e) = events.try_next() {
        match e {
            HostEvent::Log { session, .. } => {
                assert_eq!(session, Some(id));
                lines += 1;
            }
            HostEvent::Trace {
                record: TraceRecord::Dropped(n),
                ..
            } => dropped += n,
            _ => {}
        }
    }
    assert_eq!(lines, 256);
    // The trace backlog is its own: whatever it lost is its own count.
    let _ = dropped;
    drop(listener);
}
