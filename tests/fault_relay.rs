//! Carriers through a faulty relay in the middle, on a paused clock: idle
//! cut-offs and black holes. Idle probes keep idle carriers alive and detect failures.

#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    reason = "test and bench values are small and bounded; checked conversions would only add noise"
)]

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream};
use tokio::sync::{Notify, watch};
use tokio::time::{Instant, sleep_until};
use zmux::{
    AttachmentSpec, Backoff, Candidate, CarrierCache, CarrierCacheConfig, CarrierKind,
    CarrierOpener, Config, ControllerOptions, Directions, GroupTarget, Listener, ListenerConfig,
    MemberQuota, OutboundState, PipeAuth, PipeHint, PipeIo, PipeOptions, RotationPolicy, Session,
    SessionControl, SessionController, SessionTarget, TargetCandidate,
};

fn config(edit: impl FnOnce(&mut Config)) -> Config {
    let mut c = Config::default();
    c.session_policy.limits.steady_attachments = 6;
    c.pipe_auth = PipeAuth::psk(*b"fault-relay-psk-0123456789abcdef").with_end_to_end();
    c.max_idle_timeout = None;
    c.resume_timeout = Some(Duration::from_secs(120));
    edit(&mut c);
    c
}

/// How the relay treats a connection.
#[derive(Default)]
struct Faults {
    /// A connection without bytes either way for this long is dropped
    /// silently: nothing more is forwarded, neither end is told.
    idle_cut: Option<Duration>,
}

/// One relayed connection's switches.
#[derive(Default)]
struct Conn {
    /// Forwards nothing more, ends stay open (a black hole).
    blackhole: AtomicBool,
    /// Silently cut by the idle rule.
    idled: AtomicBool,
    idle_event: Notify,
    forwarded: watch::Sender<u64>,
}

#[derive(Clone)]
struct Relay {
    listener: Listener,
    faults: Arc<Faults>,
    conns: Arc<Mutex<Vec<Arc<Conn>>>>,
    dials: Arc<Mutex<Vec<Instant>>>,
}

/// Copies `from` to `to` until either ends, the relay drops it or `conn`
/// is cut; `last` is the time of the last byte either way.
async fn pump(
    mut from: impl AsyncRead + Unpin,
    mut to: impl AsyncWrite + Unpin,
    conn: Arc<Conn>,
    last: Arc<Mutex<Instant>>,
) {
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = match from.read(&mut buf).await {
            Ok(0) | Err(_) => return,
            Ok(n) => n,
        };
        if conn.blackhole.load(Ordering::SeqCst) || conn.idled.load(Ordering::SeqCst) {
            continue;
        }
        *last.lock().unwrap() = Instant::now();
        if to.write_all(&buf[..n]).await.is_err() {
            return;
        }
        conn.forwarded.send_modify(|count| *count += 1);
    }
}

impl Relay {
    fn new(listener: &Listener, faults: Faults) -> Self {
        Self {
            listener: listener.clone(),
            faults: Arc::new(faults),
            conns: Arc::default(),
            dials: Arc::default(),
        }
    }

    /// A connection through the relay: the dialer's end, the listener's
    /// end, and its switches.
    fn connect(&self) -> (DuplexStream, DuplexStream, Arc<Conn>) {
        let (near, relay_a) = tokio::io::duplex(256 * 1024);
        let (relay_b, far) = tokio::io::duplex(256 * 1024);
        let conn = Arc::new(Conn::default());
        self.conns.lock().unwrap().push(conn.clone());
        let faults = self.faults.clone();
        let c = conn.clone();
        tokio::spawn(async move {
            let opened = Instant::now();
            let last = Arc::new(Mutex::new(opened));
            let (ar, aw) = tokio::io::split(relay_a);
            let (br, bw) = tokio::io::split(relay_b);
            let mut up = tokio::spawn(pump(ar, bw, c.clone(), last.clone()));
            let mut down = tokio::spawn(pump(br, aw, c.clone(), last.clone()));
            loop {
                let idle_at = faults
                    .idle_cut
                    .filter(|_| !c.idled.load(Ordering::SeqCst))
                    .map(|limit| *last.lock().unwrap() + limit);
                tokio::select! {
                    _ = &mut up => break,
                    _ = &mut down => break,
                    () = async {
                        if let Some(at) = idle_at {
                            sleep_until(at).await;
                        } else {
                            std::future::pending::<()>().await;
                        }
                    } => {}
                }
                if faults
                    .idle_cut
                    .is_some_and(|limit| Instant::now() >= *last.lock().unwrap() + limit)
                {
                    c.idled.store(true, Ordering::SeqCst);
                    c.idle_event.notify_one();
                }
            }
            // Dropping the copies drops the relay's ends: both ends see the
            // end of their stream.
            up.abort();
            down.abort();
        });
        (near, far, conn)
    }

    fn hint() -> PipeHint {
        PipeHint::from_peer(([127, 0, 0, 1], 0).into())
    }

    /// A bidirectional carrier through the relay.
    fn carrier(&self) -> PipeIo {
        self.dials.lock().unwrap().push(Instant::now());
        let (near, far, _) = self.connect();
        let l = self.listener.clone();
        tokio::spawn(async move {
            let _ = l.handle_pipe(PipeIo::new(far), Self::hint()).await;
        });
        PipeIo::new(near)
    }

    fn manage(&self, session: &Session, options: PipeOptions) -> SessionControl {
        let relayed = self.clone();
        let open = CarrierOpener::new(move |_| {
            std::future::ready(zmux::OpenedCarriers::ready(vec![relayed.carrier()]))
        });
        let relay = self.clone();
        let candidate = Candidate::new(CarrierKind::Streaming, move || {
            std::future::ready(Ok(relay.carrier()))
        })
        .with_identity("relay", "relay")
        .with_join_opener(vec![AttachmentSpec::new(Directions::BOTH, options)], open);
        let mut options =
            ControllerOptions::new(format!("fault-relay-{:?}", session.id()), vec![candidate]);
        let mut cache = CarrierCacheConfig::default();
        cache.backoff = Backoff::new(Duration::from_millis(500), Duration::from_secs(5));
        options.cache = Some(CarrierCache::new(cache).unwrap());
        SessionController::new(options)
            .unwrap()
            .manage(
                session,
                SessionTarget {
                    revision: 1,
                    groups: vec![GroupTarget {
                        id: "relay".into(),
                        quotas: vec![MemberQuota {
                            id: "one".into(),
                            count: 1,
                            directions: Directions::BOTH,
                            candidates: vec![TargetCandidate {
                                id: "relay".into(),
                                send: None,
                                receive: None,
                            }],
                        }],

                        rotation: zmux::RotationPolicy::default(),
                    }],
                    replace: Vec::new(),
                },
            )
            .unwrap()
    }

    fn dial_count(&self) -> usize {
        self.dials.lock().unwrap().len()
    }

    fn first_connection(&self) -> Arc<Conn> {
        self.conns.lock().unwrap()[0].clone()
    }
}

/// A session over a direct carrier (not relayed) and its peer.
async fn direct(listener: &Listener, cfg: Config) -> (Session, Session) {
    let (a, b) = tokio::io::duplex(256 * 1024);
    let l = listener.clone();
    tokio::spawn(async move {
        let _ = l.handle_pipe(PipeIo::new(b), Relay::hint()).await;
    });
    let client = Session::connect(PipeIo::new(a), cfg).await.unwrap();
    let server = listener.accept().await.unwrap();
    (client, server)
}

async fn observe<T>(session: &Session, mut predicate: impl FnMut() -> Option<T>) -> T {
    loop {
        let observed = session.capacity().observed;
        if let Some(value) = predicate() {
            return value;
        }
        session.capacity_changed(observed).await;
    }
}

async fn joined_pipe(session: &Session, except: Option<zmux::PipeId>) -> zmux::PipeId {
    observe(session, || {
        session
            .pipe_stats()
            .into_iter()
            .find(|pipe| {
                pipe.pipe.get() != 0
                    && Some(pipe.pipe) != except
                    && pipe.peer_attached
                    && pipe.outbound == Some(OutboundState::Active)
            })
            .map(|pipe| pipe.pipe)
    })
    .await
}

async fn lost(session: &Session, pipe: zmux::PipeId) {
    observe(session, || {
        session
            .pipe_stats()
            .into_iter()
            .find(|p| p.pipe == pipe)
            .is_none_or(|p| p.outbound == Some(OutboundState::Failed))
            .then_some(())
    })
    .await;
}

fn probe_options(period: Duration) -> PipeOptions {
    PipeOptions::new().with_liveness(zmux::PipeLiveness {
        probe_interval: zmux::Inherit::Set(Some(period)),
        probe_jitter: zmux::Inherit::Set(0.0),
        ..zmux::PipeLiveness::default()
    })
}

const WATCHDOG: Duration = Duration::from_hours(1);

#[tokio::test(start_paused = true)]
async fn probes_keep_an_idle_relay_open() {
    tokio::time::timeout(WATCHDOG, async {
        let quiet = |config: &mut Config| {
            config.liveness.probe_interval = Some(Duration::from_hours(1));
            config.liveness.probe_jitter = 0.0;
        };
        let listener = Listener::new(config(quiet), ListenerConfig::default()).unwrap();
        let relay = Relay::new(
            &listener,
            Faults {
                idle_cut: Some(Duration::from_secs(8)),
            },
        );
        let (client, _server) = direct(&listener, config(quiet)).await;
        let control = relay.manage(&client, probe_options(Duration::from_secs(5)));
        joined_pipe(&client, None).await;
        let link = relay.first_connection();
        let mut forwarded = link.forwarded.subscribe();
        for _ in 0..3 {
            let previous = *forwarded.borrow_and_update();
            tokio::select! {
                biased;
                () = link.idle_event.notified() => panic!("relay closed without another probe"),
                changed = forwarded.wait_for(|&count| count > previous) => { changed.unwrap(); }
            }
        }
        assert_eq!(relay.dial_count(), 1);
        control.release().unwrap();
        control.done().await;
        client.close().await;

        let relay = Relay::new(
            &listener,
            Faults {
                idle_cut: Some(Duration::from_secs(8)),
            },
        );
        let (client, _server) = direct(&listener, config(quiet)).await;
        let control = relay.manage(&client, probe_options(Duration::from_secs(12)));
        let first = joined_pipe(&client, None).await;
        relay.first_connection().idle_event.notified().await;
        lost(&client, first).await;
        joined_pipe(&client, Some(first)).await;
        assert_eq!(relay.dial_count(), 2);
        control.release().unwrap();
        control.done().await;
        client.close().await;
    })
    .await
    .unwrap();
}

#[tokio::test(start_paused = true)]
async fn a_black_hole_is_found_by_the_probe() {
    tokio::time::timeout(WATCHDOG, async {
        let listener = Listener::new(config(|_| {}), ListenerConfig::default()).unwrap();
        let relay = Relay::new(&listener, Faults::default());
        let (client, _server) = direct(&listener, config(|_| {})).await;
        let control = relay.manage(&client, probe_options(Duration::from_secs(5)));
        let pipe = joined_pipe(&client, None).await;
        relay
            .first_connection()
            .blackhole
            .store(true, Ordering::SeqCst);
        lost(&client, pipe).await;
        control.release().unwrap();
        control.done().await;
        client.close().await;
    })
    .await
    .unwrap();
}

#[tokio::test(start_paused = true)]
async fn a_confirmed_recovery_releases_the_alternates_protocol_reservation() {
    tokio::time::timeout(Duration::from_secs(2), async {
        let config = config(|_| {});
        let listener = Listener::new(config.clone(), ListenerConfig::default()).unwrap();
        let (session, _peer) = direct(&listener, config).await;
        let relay = Relay::new(&listener, Faults::default());
        let confirm_winner = Arc::new(Notify::new());
        let winner = CarrierOpener::new({
            let confirm_winner = confirm_winner.clone();
            move |_| {
                let relay = relay.clone();
                let confirm_winner = confirm_winner.clone();
                async move {
                    confirm_winner.notified().await;
                    zmux::OpenedCarriers::ready(vec![relay.carrier()])
                }
            }
        });
        let alternate_started = Arc::new(Notify::new());
        let alternate = CarrierOpener::new({
            let alternate_started = alternate_started.clone();
            move |_| {
                alternate_started.notify_one();
                std::future::pending::<zmux::OpenedCarriers>()
            }
        });
        let candidate = |id, tier, opener| {
            Candidate::new(CarrierKind::Streaming, || async { unreachable!() })
                .with_identity(id, id)
                .with_tier(tier)
                .join_only()
                .with_join_opener(
                    vec![AttachmentSpec::new(
                        Directions::BOTH,
                        PipeOptions::default(),
                    )],
                    opener,
                )
        };
        let controller = SessionController::new(ControllerOptions::new(
            "directional-recovery-alternatives",
            vec![
                candidate("winner", 0, winner),
                candidate("alternate", 1, alternate),
            ],
        ))
        .unwrap();
        let target = SessionTarget {
            groups: vec![GroupTarget {
                id: "recovery".into(),
                quotas: vec![MemberQuota {
                    id: "coverage".into(),
                    count: 1,
                    directions: Directions::BOTH,
                    candidates: ["winner", "alternate"]
                        .map(|id| TargetCandidate {
                            id: id.into(),
                            send: None,
                            receive: None,
                        })
                        .into(),
                }],

                rotation: zmux::RotationPolicy::default(),
            }],
            ..SessionTarget::default()
        };
        let control = controller.manage(&session, target).unwrap();
        session.pipe(zmux::PipeId::new(0)).unwrap().abort().unwrap();
        alternate_started.notified().await;
        assert_eq!(session.capacity().reserved_attachments, 2);
        confirm_winner.notify_one();
        observe(&session, || {
            let capacity = session.capacity();
            (capacity.covered == Directions::BOTH && capacity.reserved_attachments == 0)
                .then_some(())
        })
        .await;
        assert_eq!(control.snapshot().host_calls_in_flight, 1);
        control.release().unwrap();
        control.done().await;
    })
    .await
    .unwrap();
}

#[tokio::test(start_paused = true)]
async fn directional_recovery_alternatives_share_the_batch_deadline() {
    tokio::time::timeout(Duration::from_secs(2), async {
        let config = config(|_| {});
        let listener = Listener::new(config.clone(), ListenerConfig::default()).unwrap();
        let (session, _peer) = direct(&listener, config).await;
        let (requests, mut started) = tokio::sync::mpsc::unbounded_channel();
        let candidate = |id, tier, directions| {
            let released = Arc::new(Notify::new());
            let opener = CarrierOpener::new({
                let released = released.clone();
                let listener = listener.clone();
                let requests = requests.clone();
                move |request| {
                    requests.send((id, request)).unwrap();
                    let listener = listener.clone();
                    let released = released.clone();
                    async move {
                        released.notified().await;
                        let (ours, theirs) = tokio::io::duplex(64 * 1024);
                        tokio::spawn(async move {
                            let _ = listener
                                .handle_pipe(PipeIo::new(theirs), Relay::hint())
                                .await;
                        });
                        zmux::OpenedCarriers::ready(vec![PipeIo::new(ours)])
                    }
                }
            });
            let candidate = Candidate::new(CarrierKind::Streaming, || async { unreachable!() })
                .with_identity(id, id)
                .with_tier(tier)
                .join_only()
                .with_join_opener(
                    vec![AttachmentSpec::new(directions, PipeOptions::default())],
                    opener,
                );
            (candidate, released)
        };
        let (send, release_send) = candidate("send", 0, Directions::SEND);
        let (duplex, release_duplex) = candidate("duplex", 1, Directions::BOTH);
        let controller = SessionController::new(ControllerOptions::new(
            "partial-recovery",
            vec![send, duplex],
        ))
        .unwrap();
        let control = controller
            .manage(&session, SessionTarget::default())
            .unwrap();
        session.pipe(zmux::PipeId::new(0)).unwrap().abort().unwrap();

        let (id, send) = started.recv().await.unwrap();
        assert_eq!(id, "send");
        let (id, duplex) = started.recv().await.unwrap();
        assert_eq!(id, "duplex");
        assert_eq!(send.need, Directions::SEND);
        assert_eq!(duplex.need, Directions::BOTH);
        assert_eq!(duplex.deadline, send.deadline);
        assert_eq!(session.capacity().reserved_attachments, 2);

        release_duplex.notify_one();
        let mut view = control.subscribe();
        view.wait_for(|state| {
            state.last_attempt.as_ref().is_some_and(|result| {
                result.id == duplex.attempt && result.reason == zmux::AttemptReason::Confirmed
            })
        })
        .await
        .unwrap();
        assert_eq!(session.capacity().covered, Directions::BOTH);
        assert_eq!(session.capacity().reserved_attachments, 0);
        assert!(started.try_recv().is_err());
        release_send.notify_one();
        control.release().unwrap();
        control.done().await;
    })
    .await
    .unwrap();
}

#[tokio::test(start_paused = true)]
async fn an_open_keeps_its_pending_place_until_the_session_inherits_it() {
    tokio::time::timeout(Duration::from_secs(2), async {
        let config = config(|_| {});
        let listener = Listener::new(config.clone(), ListenerConfig::default()).unwrap();
        let entered = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());
        let candidate = Candidate::new(CarrierKind::Streaming, {
            let entered = entered.clone();
            let release = release.clone();
            let listener = listener.clone();
            move || {
                let entered = entered.clone();
                let release = release.clone();
                let listener = listener.clone();
                async move {
                    entered.notify_one();
                    release.notified().await;
                    let (ours, theirs) = tokio::io::duplex(64 * 1024);
                    tokio::spawn(async move {
                        let _ = listener.handle_pipe(PipeIo::new(theirs), Relay::hint()).await;
                    });
                    Ok(PipeIo::new(ours))
                }
            }
        }).with_identity("bootstrap", "bootstrap");
        let mut options = ControllerOptions::new("bootstrap-pending-place", vec![candidate]);
        options.limits.pending_owners = std::num::NonZeroUsize::MIN;
        let controller = SessionController::new(options).unwrap();
        let opening = controller.open(config.clone(), SessionTarget::default());
        tokio::pin!(opening);
        tokio::select! {
            () = entered.notified() => {}
            result = &mut opening => panic!("open completed before its callback was released: {:?}", result.err()),
        }
        assert!(matches!(controller.open(config, SessionTarget::default()).await, Err(zmux::ControllerError::QueueFull)));
        release.notify_one();
        let (session, control) = opening.await.unwrap();
        let control = control.unwrap();
        control.release().unwrap();
        control.done().await;
        session.close().await;
    }).await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn a_blocked_due_start_is_counted_once_across_controller_wakeups() {
    tokio::time::timeout(Duration::from_secs(2), async {
        let config = config(|_| {});
        let listener = Listener::new(config.clone(), ListenerConfig::default()).unwrap();
        let (session, _peer) = direct(&listener, config).await;
        let candidate = Candidate::new(CarrierKind::Streaming, || async {
            std::future::pending::<std::io::Result<PipeIo>>().await
        })
        .with_identity("scheduled", "scheduled")
        .join_only();
        let cache = CarrierCache::new(CarrierCacheConfig::default()).unwrap();
        let mut options = ControllerOptions::new("suppression-count", vec![candidate]);
        options.cache = Some(cache.clone());
        let at = Instant::now();
        options
            .dial_after
            .insert("scheduled".into(), (at + Duration::from_secs(1)).into_std());
        let controller = SessionController::new(options).unwrap();
        let control = controller
            .manage(&session, SessionTarget::default())
            .unwrap();
        session.pipe(zmux::PipeId::new(0)).unwrap().abort().unwrap();

        let mut view = control.subscribe();
        for millis in [1000, 1100, 1200, 1300] {
            if millis == 1300 {
                tokio::time::advance(Duration::from_millis(1050)).await;
            }
            let due = (at + Duration::from_millis(millis)).into_std();
            control
                .set_dial_after("scheduled".into(), Some(due))
                .unwrap();
            view.wait_for(|snapshot| snapshot.next_retry == Some(due))
                .await
                .unwrap();
            assert_eq!(
                cache
                    .retry_metrics("scheduled", CarrierKind::Streaming, "")
                    .suppressions
                    .get(&zmux::RetryAdmission::DialAfter),
                Some(&1)
            );
        }
        control.release().unwrap();
        control.done().await;
    })
    .await
    .unwrap();
}

#[tokio::test(start_paused = true)]
async fn queued_sessions_rotate_before_the_next_ready_pool() {
    tokio::time::timeout(Duration::from_secs(2), async {
        let config = config(|_| {});
        let listener = Listener::new(config.clone(), ListenerConfig::default()).unwrap();
        let (a, _peer_a) = direct(&listener, config.clone()).await;
        let (b, _peer_b) = direct(&listener, config.clone()).await;
        let busy_started = Arc::new(Notify::new());
        let release_busy = Arc::new(Notify::new());
        let busy = Candidate::new(CarrierKind::Streaming, {
            let busy_started = busy_started.clone();
            let release_busy = release_busy.clone();
            move || {
                let busy_started = busy_started.clone();
                let release_busy = release_busy.clone();
                async move {
                    busy_started.notify_one();
                    release_busy.notified().await;
                    Err(std::io::Error::other("release test opener"))
                }
            }
        })
        .with_identity("busy", "busy");
        let (starts, mut started) = tokio::sync::mpsc::unbounded_channel();
        let relay = Relay::new(&listener, Faults::default());
        let candidate = |id| {
            let relay = relay.clone();
            let starts = starts.clone();
            Candidate::new(CarrierKind::Streaming, move || {
                starts.send(id).unwrap();
                std::future::ready(Ok(relay.carrier()))
            })
            .with_identity(id, id)
            .join_only()
        };
        let mut options = ControllerOptions::new(
            "rotate-pools-within-a-session",
            vec![busy, candidate("p"), candidate("q"), candidate("r")],
        );
        options.limits.concurrent_openers = std::num::NonZeroUsize::MIN;
        let controller = SessionController::new(options).unwrap();
        let occupying = tokio::spawn({
            let controller = controller.clone();
            async move { controller.open(config, SessionTarget::default()).await }
        });
        busy_started.notified().await;

        let group = |id: &str, count| GroupTarget {
            id: id.into(),
            quotas: vec![MemberQuota {
                id: "coverage".into(),
                count,
                directions: Directions::BOTH,
                candidates: vec![TargetCandidate {
                    id: id.into(),
                    send: None,
                    receive: None,
                }],
            }],

            rotation: zmux::RotationPolicy::default(),
        };
        let stalled = |control: &SessionControl| {
            let mut view = control.subscribe();
            async move {
                view.wait_for(|state| state.blocked == Some(zmux::ControllerBlock::Execution))
                    .await
                    .unwrap();
            }
        };
        let a = controller
            .manage(
                &a,
                SessionTarget {
                    groups: vec![group("p", 2), group("q", 1)],
                    ..SessionTarget::default()
                },
            )
            .unwrap();
        stalled(&a).await;
        let b = controller
            .manage(
                &b,
                SessionTarget {
                    groups: vec![group("r", 1)],
                    ..SessionTarget::default()
                },
            )
            .unwrap();
        stalled(&b).await;

        release_busy.notify_one();
        for pool in ["p", "r", "q", "p"] {
            assert_eq!(started.recv().await, Some(pool));
        }
        assert!(occupying.await.unwrap().is_err());
        a.release().unwrap();
        b.release().unwrap();
        a.done().await;
        b.done().await;
    })
    .await
    .unwrap();
}

#[tokio::test(start_paused = true)]
async fn a_single_recovery_candidate_retries_at_the_sampled_cadence() {
    tokio::time::timeout(Duration::from_secs(4), async {
        let config = config(|_| {});
        let listener = Listener::new(config.clone(), ListenerConfig::default()).unwrap();
        let (session, _peer) = direct(&listener, config).await;
        let (starts, mut started) = tokio::sync::mpsc::unbounded_channel();
        let candidate = Candidate::new(CarrierKind::Streaming, move || {
            starts.send(Instant::now()).unwrap();
            std::future::ready(Err(std::io::Error::other("test cooldown")))
        })
        .with_identity("only", "only")
        .join_only();
        let mut cache = CarrierCacheConfig::default();
        cache.backoff = Backoff::new(Duration::from_secs(1), Duration::from_secs(1));
        cache.recovery_sample = || 0.5;
        cache.backoff.jitter = 0.0;
        cache.backoff.jitter_up = 0.0;
        let mut options = ControllerOptions::new("single-recovery-cooldown", vec![candidate]);
        options.cache = Some(CarrierCache::new(cache).unwrap());
        let controller = SessionController::new(options).unwrap();
        let control = controller
            .manage(&session, SessionTarget::default())
            .unwrap();
        session.pipe(zmux::PipeId::new(0)).unwrap().abort().unwrap();

        let first = started.recv().await.unwrap();
        let cadence = Duration::from_millis(500);
        let due = first + cadence;
        let mut view = control.subscribe();
        view.wait_for(|snapshot| snapshot.next_retry == Some(due.into_std()))
            .await
            .unwrap();
        tokio::time::advance(cadence.checked_sub(Duration::from_nanos(1)).unwrap()).await;
        assert!(started.try_recv().is_err());
        tokio::time::advance(Duration::from_nanos(1)).await;
        assert_eq!(started.recv().await.unwrap(), due);
        control.release().unwrap();
        control.done().await;
    })
    .await
    .unwrap();
}

#[tokio::test(start_paused = true)]
async fn a_suspended_recovery_deadline_is_strictly_inside_grace() {
    tokio::time::timeout(Duration::from_secs(4), async {
        let grace = Duration::from_secs(2);
        let config = config(|config| config.resume_timeout = Some(grace));
        let listener = Listener::new(config.clone(), ListenerConfig::default()).unwrap();
        let (session, _peer) = direct(&listener, config).await;
        let (starts, mut started) = tokio::sync::mpsc::unbounded_channel();
        let opener = CarrierOpener::new(move |request| {
            starts.send(request).unwrap();
            std::future::pending::<zmux::OpenedCarriers>()
        });
        let candidate = Candidate::new(CarrierKind::Streaming, || async { unreachable!() })
            .with_identity("recovery", "recovery")
            .join_only()
            .with_join_opener(
                vec![AttachmentSpec::new(
                    Directions::BOTH,
                    PipeOptions::default(),
                )],
                opener,
            );
        let controller =
            SessionController::new(ControllerOptions::new("bounded-recovery", vec![candidate]))
                .unwrap();
        let control = controller
            .manage(&session, SessionTarget::default())
            .unwrap();
        let suspended = Instant::now();
        session.pipe(zmux::PipeId::new(0)).unwrap().abort().unwrap();

        let request = started.recv().await.unwrap();
        assert_eq!(
            request.deadline,
            (suspended + grace - Duration::from_nanos(1)).into_std()
        );
        assert_ne!(request.attempt.0, 0);
        control.release().unwrap();
        control.done().await;
    })
    .await
    .unwrap();
}

#[tokio::test(start_paused = true)]
async fn a_managed_ack_stall_preserves_coverage_and_waits_for_actual_opener_failure() {
    use std::sync::atomic::AtomicUsize;

    static CADENCE_SAMPLES: AtomicUsize = AtomicUsize::new(0);
    tokio::time::timeout(Duration::from_secs(20), async {
        let config = config(|cfg| {
            cfg.liveness.probe_interval = Some(Duration::from_secs(1));
            cfg.liveness.probe_jitter = 0.0;
            cfg.test_hooks().probe_seed = Some(1);
        });
        let listener = Listener::new(config.clone(), ListenerConfig::default()).unwrap();
        let primary = Relay::new(&listener, Faults::default());
        let alternate = Relay::new(&listener, Faults::default());
        let session = Session::connect(primary.carrier(), config).await.unwrap();
        let _peer = listener.accept().await.unwrap();

        let calls = Arc::new(AtomicUsize::new(0));
        let (started, mut recovery) = tokio::sync::mpsc::unbounded_channel();
        let open = CarrierOpener::new({
            let calls = calls.clone();
            let alternate = alternate.clone();
            move |request| {
                let first = calls.fetch_add(1, Ordering::SeqCst) == 0;
                let alternate = alternate.clone();
                let started = started.clone();
                async move {
                    if first {
                        zmux::OpenedCarriers::ready(vec![alternate.carrier()])
                    } else {
                        started.send(request).unwrap();
                        std::future::pending().await
                    }
                }
            }
        });
        let candidate = Candidate::new(CarrierKind::Streaming, || async { unreachable!() })
            .with_identity("alternate", "alternate")
            .join_only()
            .with_join_opener(
                vec![AttachmentSpec::new(
                    Directions::BOTH,
                    PipeOptions::default(),
                )],
                open,
            );
        let mut cache = CarrierCacheConfig::default();
        cache.recovery_sample = || {
            CADENCE_SAMPLES.fetch_add(1, Ordering::SeqCst);
            0.5
        };
        let mut options = ControllerOptions::new("ack-stall-coverage", vec![candidate]);
        options.cache = Some(CarrierCache::new(cache).unwrap());
        let controller = SessionController::new(options).unwrap();
        let control = controller
            .manage(
                &session,
                SessionTarget {
                    groups: vec![GroupTarget {
                        id: "coverage".into(),
                        quotas: vec![MemberQuota {
                            id: "one".into(),
                            count: 1,
                            directions: Directions::BOTH,
                            candidates: vec![TargetCandidate {
                                id: "alternate".into(),
                                send: None,
                                receive: None,
                            }],
                        }],
                        rotation: zmux::RotationPolicy::default(),
                    }],
                    ..SessionTarget::default()
                },
            )
            .unwrap();
        let q = joined_pipe(&session, None).await;
        observe(&session, || {
            session.pipe(q)?.health()?.send.settled.then_some(())
        })
        .await;
        let p = zmux::PipeId::new(0);
        primary
            .first_connection()
            .blackhole
            .store(true, Ordering::SeqCst);
        lost(&session, p).await;
        let covered = control.snapshot().capacity.covered;
        assert!(covered.contains(Directions::SEND));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert!(recovery.try_recv().is_err());

        alternate
            .first_connection()
            .blackhole
            .store(true, Ordering::SeqCst);
        recovery.recv().await.unwrap();
        lost(&session, q).await;
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert_eq!(CADENCE_SAMPLES.load(Ordering::SeqCst), 0);
        control.release().unwrap();
        control.done().await;
    })
    .await
    .unwrap();
}

#[tokio::test(start_paused = true)]
async fn controller_empty_target_keeps_redundant_coverage() {
    tokio::time::timeout(Duration::from_secs(2), async {
        let cfg = config(|_| {});
        let listener = Listener::new(cfg.clone(), ListenerConfig::default()).unwrap();
        let (session, _peer) = direct(&listener, cfg).await;
        let relay = Relay::new(&listener, Faults::default());
        let candidate = Candidate::new(CarrierKind::Streaming, move || {
            let carrier = relay.carrier();
            async move { Ok(carrier) }
        })
        .with_identity("second", "second");
        let ctl = SessionController::new(ControllerOptions::new(
            "empty-target-keeps-coverage",
            vec![candidate],
        ))
        .unwrap();
        let control = ctl
            .manage(
                &session,
                SessionTarget {
                    revision: 1,
                    groups: vec![GroupTarget {
                        id: "pool".into(),
                        quotas: vec![MemberQuota {
                            id: "duplex".into(),
                            count: 1,
                            directions: Directions::BOTH,
                            candidates: vec![TargetCandidate {
                                id: "second".into(),
                                send: None,
                                receive: None,
                            }],
                        }],
                        rotation: RotationPolicy::default(),
                    }],
                    ..Default::default()
                },
            )
            .unwrap();
        let mut view = control.subscribe();
        view.wait_for(|s| s.members.len() == 2 && s.members.iter().all(|m| m.complete))
            .await
            .unwrap();
        control
            .set_target(SessionTarget {
                revision: 2,
                ..Default::default()
            })
            .unwrap();
        let result = view.wait_for(|s| s.revision == 2).await.unwrap();
        assert_eq!(result.members.len(), 2);
        assert!(result.members.iter().all(|m| m.complete));
        assert_eq!(session.capacity().covered, Directions::BOTH);
    })
    .await
    .unwrap();
}

#[tokio::test(start_paused = true)]
async fn controller_plain_open_returns_no_binding() {
    tokio::time::timeout(Duration::from_secs(2), async {
        let listener = Listener::new(Config::default(), ListenerConfig::default()).unwrap();
        let relay = Relay::new(&listener, Faults::default());
        let candidate = Candidate::new(CarrierKind::Streaming, move || {
            let carrier = relay.carrier();
            async move { Ok(carrier) }
        })
        .with_identity("plain", "plain");
        let ctl = SessionController::new(ControllerOptions::new(
            "plain-empty-target",
            vec![candidate],
        ))
        .unwrap();
        let (session, control) = ctl
            .open(Config::default(), SessionTarget::default())
            .await
            .unwrap();
        let _peer = listener.accept().await.unwrap();
        assert_ne!(session.multipath(), zmux::Multipath::InUse);
        assert!(control.is_none());
        ctl.close();
        ctl.done().await;
    })
    .await
    .unwrap();
}

#[tokio::test(start_paused = true)]
async fn controller_bootstrap_attribution_checks_layout_and_original_key() {
    tokio::time::timeout(Duration::from_secs(2), async {
        let cfg = config(|_| {});
        let listener = Listener::new(cfg.clone(), ListenerConfig::default()).unwrap();
        let relay = Relay::new(&listener, Faults::default());
        let io = relay.carrier().with_carrier(CarrierKind::Streaming);
        let session = Session::connect(io, cfg).await.unwrap();
        let _peer = listener.accept().await.unwrap();
        let candidate = |key| {
            Candidate::new(CarrierKind::Streaming, || async {
                unreachable!("empty target must not dial")
            })
            .with_identity("first", key)
        };
        let opts = |name, candidates| {
            SessionController::new(ControllerOptions::new(name, candidates)).unwrap()
        };
        let split = candidate("original").with_join_opener(
            vec![
                AttachmentSpec::new(Directions::SEND, PipeOptions::default()),
                AttachmentSpec::new(Directions::RECEIVE, PipeOptions::default()),
            ],
            CarrierOpener::new(|_| std::future::pending::<zmux::OpenedCarriers>()),
        );
        let ctl = opts("bootstrap-split-rejected", vec![split]);
        assert!(matches!(
            ctl.manage_with_bootstrap(&session, SessionTarget::default(), Some(&"first".into())),
            Err(zmux::ControllerError::Invalid(_))
        ));
        let ctl = opts("bootstrap-original", vec![candidate("original")]);
        let old = ctl
            .manage_with_bootstrap(&session, SessionTarget::default(), Some(&"first".into()))
            .unwrap();
        let middle = opts("bootstrap-unknown", Vec::new());
        let old = middle.take_over(&old, SessionTarget::default()).unwrap();
        let changed = opts("bootstrap-changed", vec![candidate("different")]);
        assert!(matches!(
            changed.take_over(&old, SessionTarget::default()),
            Err(zmux::ControllerError::Invalid(_))
        ));
        let matching = opts("bootstrap-matching", vec![candidate("original")]);
        assert!(matching.take_over(&old, SessionTarget::default()).is_ok());
    })
    .await
    .unwrap();
}

#[tokio::test(start_paused = true)]
async fn controller_panicking_opener_finishes_without_waiting_for_deadline() {
    tokio::time::timeout(Duration::from_secs(2), async {
        let cfg = config(|_| {});
        let listener = Listener::new(cfg.clone(), ListenerConfig::default()).unwrap();
        let (session, _peer) = direct(&listener, cfg).await;
        let candidate = Candidate::new(CarrierKind::Streaming, || async {
            panic!("scripted opener panic")
        })
        .with_identity("panic", "panic");
        let cache = CarrierCache::default();
        let mut options = ControllerOptions::new("opener-panic", vec![candidate]);
        options.cache = Some(cache.clone());
        let ctl = SessionController::new(options).unwrap();
        let control = ctl.manage(&session, SessionTarget::default()).unwrap();
        session.pipe(zmux::PipeId::new(0)).unwrap().abort().unwrap();
        let mut view = control.subscribe();
        let view = view.wait_for(|s| s.last_attempt.is_some()).await.unwrap();
        assert_eq!(
            view.last_attempt.as_ref().unwrap().reason,
            zmux::AttemptReason::HookFailed
        );
        assert_eq!(
            cache
                .retry_metrics("panic", CarrierKind::Streaming, "")
                .faults,
            0
        );
        assert_eq!(session.capacity().reserved_attachments, 0);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn controller_takeover_settles_before_a_reentrant_sampler_returns() {
    use std::sync::OnceLock;
    use tokio::sync::oneshot;
    type Sample = (
        CarrierCache,
        oneshot::Sender<()>,
        std::sync::mpsc::Receiver<()>,
    );
    static SAMPLE: OnceLock<Mutex<Option<Sample>>> = OnceLock::new();
    fn sample() -> f64 {
        let (cache, entered, release) = SAMPLE.get().unwrap().lock().unwrap().take().unwrap();
        assert_eq!(
            cache
                .retry_metrics("shared", CarrierKind::Streaming, "")
                .attempted_starts,
            1
        );
        entered.send(()).unwrap();
        release.recv().unwrap();
        1.0
    }
    tokio::time::timeout(Duration::from_secs(3), async {
        let cfg = config(|_| {});
        let listener = Listener::new(cfg.clone(), ListenerConfig::default()).unwrap();
        let (session, _peer) = direct(&listener, cfg).await;
        let (sampling, entered) = oneshot::channel();
        let (release, gate) = std::sync::mpsc::channel();
        let mut cache_opts = CarrierCacheConfig::default();
        cache_opts.recovery_sample = sample;
        let cache = CarrierCache::new(cache_opts).unwrap();
        *SAMPLE.get_or_init(Mutex::default).lock().unwrap() = Some((cache.clone(), sampling, gate));
        let candidate = Candidate::new(CarrierKind::Streaming, || async {
            Err(std::io::Error::other("scripted dial failure"))
        })
        .with_identity("shared", "shared");
        let mut opts = ControllerOptions::new("sampler-predecessor", vec![candidate.clone()]);
        opts.cache = Some(cache.clone());
        let old = SessionController::new(opts).unwrap();
        let binding = old.manage(&session, SessionTarget::default()).unwrap();
        session.pipe(zmux::PipeId::new(0)).unwrap().abort().unwrap();
        entered.await.unwrap();

        let mut opts = ControllerOptions::new("sampler-successor", vec![candidate]);
        opts.cache = Some(cache.clone());
        opts.dial_after.insert(
            "shared".into(),
            std::time::Instant::now() + Duration::from_secs(60),
        );
        let next = SessionController::new(opts).unwrap();
        let successor = next.take_over(&binding, SessionTarget::default()).unwrap();
        assert_eq!(session.capacity().reserved_attachments, 0);

        let mut timeline = Vec::new();
        let mut batch = 0;
        while let Some(event) = session.next_event().await {
            match event {
                zmux::SessionEvent::BatchReserved {
                    generation,
                    batch: id,
                    ..
                } if generation == binding.snapshot().generation => {
                    batch = id;
                    timeline.push("reserve");
                }
                zmux::SessionEvent::AttemptStarted { batch: id, .. } if id == batch => {
                    timeline.push("start");
                }
                zmux::SessionEvent::AttemptFinished {
                    batch: id,
                    generation,
                    reason,
                    ..
                } if id == batch => {
                    assert_eq!(generation, binding.snapshot().generation);
                    assert_eq!(reason, zmux::AttemptReason::Cancelled);
                    timeline.push("cancel");
                }
                zmux::SessionEvent::BatchRolledBack { batch: id, .. } if id == batch => {
                    timeline.push("rollback");
                }
                zmux::SessionEvent::TargetChanged { generation, .. }
                    if generation == successor.snapshot().generation =>
                {
                    break;
                }
                _ => {}
            }
        }
        assert_eq!(timeline, ["reserve", "start", "cancel", "rollback"]);
        release.send(()).unwrap();
        binding.done().await;
        assert_eq!(
            cache
                .retry_metrics("shared", CarrierKind::Streaming, "")
                .faults,
            0
        );
        assert_eq!(
            cache
                .retry_metrics("shared", CarrierKind::Streaming, "")
                .recovery_retry_at,
            None
        );
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn controller_panicking_sampler_finishes_the_attempt_as_hook_failed() {
    tokio::time::timeout(Duration::from_secs(3), async {
        let cfg = config(|_| {});
        let listener = Listener::new(cfg.clone(), ListenerConfig::default()).unwrap();
        let (session, _peer) = direct(&listener, cfg).await;
        let mut config = CarrierCacheConfig::default();
        config.recovery_sample = || panic!("scripted recovery sampler panic");
        let cache = CarrierCache::new(config).unwrap();
        let candidate = Candidate::new(CarrierKind::Streaming, || async {
            Err(std::io::Error::other("scripted dial failure"))
        })
        .with_identity("sampler", "sampler");
        let mut opts = ControllerOptions::new("sampler-panics", vec![candidate]);
        opts.cache = Some(cache.clone());
        let ctl = SessionController::new(opts).unwrap();
        let ctl = ctl.manage(&session, SessionTarget::default()).unwrap();
        session.pipe(zmux::PipeId::new(0)).unwrap().abort().unwrap();
        let mut view = ctl.subscribe();
        let view = view.wait_for(|s| s.last_attempt.is_some()).await.unwrap();
        assert_eq!(
            view.last_attempt.as_ref().unwrap().reason,
            zmux::AttemptReason::HookFailed
        );
        let metrics = cache.retry_metrics("sampler", CarrierKind::Streaming, "");
        assert_eq!(metrics.faults, 0);
        // The failed draw falls back to the full nominal wait, so the
        // session still has a next recovery opportunity.
        assert_eq!(metrics.recovery_sampled, Duration::from_secs(1));
    })
    .await
    .unwrap();
}
