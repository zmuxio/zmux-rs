//! The carrier hooks and runtime controls: late exporter, deferred join
//! secret, runtime limits, flush, first-bytes and replay vectors, admission
//! rounds and labels, and the cache's reports.

#![allow(
    clippy::cast_possible_truncation,
    reason = "test and bench values are small and bounded; checked conversions would only add noise"
)]

mod common;

#[path = "common/core_pair.rs"]
mod core_pair;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tokio::io::AsyncWriteExt as _;

use common::{duplex, multi_thread, watchdog};
use zmux::adapter::{FirstBytes, classify_first_bytes};
use zmux::proto::record::Framing;
use zmux::{
    Admission, AdmissionVerdict, CarrierCache, CarrierKind, Config, ExportError, Listener,
    ListenerConfig, Liveness, PipeAuth, PipeError, PipeIo, ReplayFilter, ReplayVerdict, Session,
    SessionError,
};

fn exported(p: PipeIo, reads: Option<Arc<AtomicUsize>>) -> PipeIo {
    p.with_exporter(move |label, context, out| {
        if label == "EXPORTER-zmux-session"
            && let Some(r) = &reads
        {
            r.fetch_add(1, Ordering::SeqCst);
        }
        out.fill(label.len() as u8 ^ context.len() as u8);
        true
    })
}

fn connected(
    client: Config,
    server: Config,
    exporter: bool,
) -> impl Future<Output = (Session, Session)> {
    Box::pin(async move {
        let ((a, _), (b, _)) = duplex(1 << 20);
        let (a, b) = if exporter {
            (exported(a, None), exported(b, None))
        } else {
            (a, b)
        };
        let server = tokio::spawn(common::accept(b, server));
        let client = watchdog(5, "connect", Session::connect(a, client))
            .await
            .unwrap();
        let server = watchdog(5, "accept", server).await.unwrap().unwrap();
        watchdog(5, "c", client.established()).await.unwrap();
        watchdog(5, "s", server.established()).await.unwrap();
        (client, server)
    })
}

#[test]
fn the_exporter_is_read_when_the_parameters_arrive_and_exports_for_the_host() {
    multi_thread(async {
        let ((a, _), (b, _)) = duplex(1 << 20);
        let reads = Arc::new(AtomicUsize::new(0));
        let a = exported(a, Some(reads.clone()));
        let c = Config::multipath(PipeAuth::exporter());
        let client = watchdog(5, "connect", async {
            let server = tokio::spawn(common::accept(exported(b, None), c.clone()));
            let client = Session::connect(a, c.clone()).await.unwrap();
            (client, server.await.unwrap().unwrap())
        })
        .await;
        let (client, server) = client;
        watchdog(5, "c", client.established()).await.unwrap();
        watchdog(5, "s", server.established()).await.unwrap();
        assert_eq!(reads.load(Ordering::SeqCst), 1);
        assert_eq!(
            client.export_keying_material("app", b"x", 16).unwrap(),
            server.export_keying_material("app", b"x", 16).unwrap()
        );
        assert_eq!(
            client.export_keying_material("EXPORTER-zmux-pipe", b"", 32),
            Err(ExportError::ReservedLabel)
        );
        // A public value, the same at both ends.
        assert!(client.session_binding().is_some());
        assert_eq!(client.session_binding(), server.session_binding());
    });
}

#[test]
fn no_exporter_and_no_multipath_answer_as_such() {
    multi_thread(async {
        let (client, _server) = connected(Config::default(), Config::default(), false).await;
        assert_eq!(
            client.export_keying_material("app", b"", 8),
            Err(ExportError::NoExporter)
        );
        assert_eq!(client.session_binding(), None);
    });
}

#[test]
fn a_deferred_join_secret_holds_joins_until_it_is_given() {
    multi_thread(async {
        let c = Config::multipath(PipeAuth::deferred_psk().with_end_to_end());
        let (client, server) = connected(c.clone(), c, false).await;
        assert!(client.join_pending());
        let ((extra, _), _other) = duplex(1 << 16);
        assert!(matches!(
            client.test_begin_join(extra, zmux::PipeOptions::default()),
            Err(PipeError::JoinPending(zmux::JoinMissing::DeferredPsk))
        ));
        assert!(!client.adapter().join_ready());
        let key = [7u8; 32];
        assert!(matches!(
            client.set_join_secret(&key[..8]),
            Err(PipeError::InvalidArgument)
        ));
        client.set_join_secret(&key).unwrap();
        server.set_join_secret(&key).unwrap();
        assert!(!client.join_pending());
        assert!(matches!(
            client.set_join_secret(&key),
            Err(PipeError::JoinSecretSet)
        ));
        assert!(client.adapter().join_ready());
    });
}

/// A join held for the deferred key is offered once, and goes as soon as
/// the key is given.
#[test]
fn a_held_join_counts_once_and_wakes_with_the_key() {
    multi_thread(async {
        let listener = Listener::new(
            Config::multipath(PipeAuth::deferred_psk().with_end_to_end()),
            ListenerConfig::default(),
        )
        .expect("valid listener configuration");
        let c = Config::multipath(PipeAuth::deferred_psk().with_end_to_end());
        let ((a, _), (b, _)) = duplex(1 << 20);
        let serving = listener.clone();
        tokio::spawn(async move { serving.handle_pipe(b, zmux::PipeHint::default()).await });
        let client = watchdog(5, "connect", Session::connect(a, c))
            .await
            .unwrap();
        let server = watchdog(5, "accept", listener.accept()).await.unwrap();
        watchdog(5, "est", client.established()).await.unwrap();
        watchdog(5, "est", server.established()).await.unwrap();
        let key = [7u8; 32];
        client.set_join_secret(&key).unwrap();
        let ((extra_a, _), (extra_b, _)) = duplex(1 << 20);
        let serving = listener.clone();
        let joined = tokio::spawn(async move {
            serving
                .handle_pipe(extra_b, zmux::PipeHint::default())
                .await
        });
        let pipe = client
            .test_begin_join(extra_a, zmux::PipeOptions::default())
            .unwrap();
        watchdog(60, "held", async {
            while server.stats().join_pending == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await;
        watchdog(60, "bootstrap ping while the Join is held", client.ping())
            .await
            .unwrap();
        assert_eq!(server.stats().join_pending, 1);
        server.set_join_secret(&key).unwrap();
        watchdog(60, "joined", joined).await.unwrap().unwrap();
        watchdog(60, "confirmed", pipe.attached()).await.unwrap();
        assert_eq!(server.pipe_stats().len(), 2);
        assert_eq!(server.stats().join_pending, 1);
        assert_eq!(listener.stats().joins, 1);
    });
}

/// A panic elsewhere that unwinds through a stream's drop is no panic under
/// the session's lock: the session goes on.
#[test]
fn dropping_a_stream_while_unwinding_leaves_the_session_alive() {
    multi_thread(async {
        let (client, server) = connected(Config::default(), Config::default(), false).await;
        watchdog(5, "c", client.established()).await.unwrap();
        watchdog(5, "s", server.established()).await.unwrap();
        let held = client.open_bi().await.unwrap();
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
            let _held = held;
            panic!("application panic, unrelated to the session");
        }));
        assert!(r.is_err());
        watchdog(60, "another stream crosses the session", async {
            let (mut send, _recv) = client.open_bi().await.unwrap();
            send.write_all(b"x").await.unwrap();
            send.flush().await.unwrap();
            let (_reply, mut recv) = server.accept_bi().await.unwrap();
            let mut byte = [0];
            recv.read_exact(&mut byte).await.unwrap();
            assert_eq!(&byte, b"x");
        })
        .await;
    });
}

/// A flush of a finished or reset part returns normally.
#[test]
fn flush_after_finish_and_reset_returns() {
    multi_thread(async {
        let (client, server) = connected(Config::default(), Config::default(), false).await;
        watchdog(5, "c", client.established()).await.unwrap();
        watchdog(5, "s", server.established()).await.unwrap();
        let (mut send, _r1) = client.open_bi().await.unwrap();
        send.write_all(b"x").await.unwrap();
        send.finish().unwrap();
        watchdog(5, "finished", send.flush()).await.unwrap();
        let (mut send, _r2) = client.open_bi().await.unwrap();
        send.write_all(b"y").await.unwrap();
        send.reset(zmux::VarInt::ZERO).unwrap();
        watchdog(5, "reset", send.flush()).await.unwrap();
    });
}

#[test]
fn an_exporter_config_needs_an_exporter_on_the_carrier() {
    multi_thread(async {
        let ((a, _), _b) = duplex(1 << 16);
        assert!(matches!(
            Session::connect(a, Config::multipath(PipeAuth::exporter())).await,
            Err(zmux::ConnectError::InvalidConfig(_))
        ));
    });
}

#[test]
fn a_secret_the_negotiation_did_not_select_is_dropped() {
    multi_thread(async {
        let c = Config::multipath(PipeAuth::deferred_psk().with_end_to_end());
        // The other end offers no multipath.
        let ((a, _), (b, _)) = duplex(1 << 20);
        // The server session is kept: dropping it would close the session,
        // and the client would see the close instead of the negotiation.
        let (client, _server) = Box::pin(watchdog(5, "connect", async {
            let server = tokio::spawn(Session::accept(b, Config::default()));
            let client = Session::connect(a, c).await.unwrap();
            (client, server.await.unwrap().unwrap())
        }))
        .await;
        client.set_join_secret(&[7; 32]).ok();
        watchdog(5, "est", client.established()).await.unwrap();
        assert!(!client.join_pending());
        assert!(matches!(
            client.set_join_secret(&[7; 32]),
            Err(PipeError::NotNegotiated)
        ));
    });
}

#[test]
fn liveness_and_limits_change_while_the_session_runs() {
    multi_thread(async {
        let mut inbound = Config::default();
        inbound.max_incoming_streams = 0;
        let (client, server) = connected(Config::default(), inbound, false).await;
        let mut l = client.liveness();
        l.keep_alive_period = Some(Duration::from_millis(10));
        assert!(client.set_liveness(&l).is_err(), "below 1 s");
        l.keep_alive_period = None;
        client.set_liveness(&l).unwrap();
        assert_eq!(client.liveness().keep_alive_period, None);
        assert_ne!(Liveness::default().keep_alive_period, None);

        let mut limits = client.shaping_limits();
        limits.wire = Some(zmux::shaping::Account::new((1 << 53) + 1, 0, 0, 0));
        assert!(client.set_shaping_limits(limits).is_err());
        limits.wire = Some(zmux::shaping::Account::new(500, 500, 0, 0));
        client.set_shaping_limits(limits).unwrap();
        assert_eq!(client.shaping_limits().wire.unwrap().initial, 500);

        assert!(server.raise_incoming_streams((1 << 60) + 1, 0).is_err());
        assert!(matches!(
            client.try_open_bi(),
            Err(zmux::OpenError::Blocked)
        ));
        server.raise_incoming_streams(1000, 0).unwrap();
        watchdog(60, "credit", client.open_bi()).await.unwrap();
    });
}

#[test]
fn flush_opens_a_stream_with_nothing_written_and_data_goes_with_it() {
    multi_thread(async {
        let (client, server) = connected(Config::default(), Config::default(), false).await;
        let (mut send, _r) = client.open_bi().await.unwrap();
        assert_eq!(send.id(), None);
        watchdog(5, "flush", send.flush()).await.unwrap();
        assert!(send.id().is_some());
        let (mut back, _sr) = watchdog(5, "accept", server.accept_bi()).await.unwrap();
        assert_eq!(back.id(), send.id());
        back.write_all(b"banner").await.unwrap();

        let (mut with_data, _r) = client.open_bi().await.unwrap();
        with_data.write_all(b"hello").await.unwrap();
        watchdog(5, "flush", with_data.flush()).await.unwrap();
        let (_s, mut r) = watchdog(5, "accept", server.accept_bi()).await.unwrap();
        let mut buf = [0; 5];
        watchdog(5, "read", r.read_exact(&mut buf)).await.unwrap();
        assert_eq!(&buf, b"hello");
    });
}

#[derive(serde::Deserialize)]
struct FirstVectors {
    vectors: Vec<FirstVector>,
}

#[derive(serde::Deserialize)]
struct FirstVector {
    hex: String,
    framing: String,
    class: String,
    need: usize,
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn first_bytes_follow_the_shared_vectors() {
    let v: FirstVectors =
        serde_json::from_str(include_str!("../testdata/firstbytes.json")).unwrap();
    assert!(!v.vectors.is_empty());
    for t in v.vectors {
        let framing = if t.framing == "records" {
            Framing::Records
        } else {
            Framing::ByteStream
        };
        let want = match (t.class.as_str(), t.need) {
            ("need_more", n) => FirstBytes::NeedMore(n),
            ("record", _) => FirstBytes::Record,
            _ => FirstBytes::Other,
        };
        assert_eq!(
            classify_first_bytes(&unhex(&t.hex), framing),
            want,
            "{} {}",
            t.hex,
            t.framing
        );
    }
}

#[derive(serde::Deserialize)]
struct ReplayCases {
    cases: Vec<ReplayCase>,
}

#[derive(serde::Deserialize)]
struct ReplayCase {
    name: String,
    window_ms: u64,
    max: usize,
    not_before_ms: u64,
    steps: Vec<ReplayStep>,
}

#[derive(serde::Deserialize)]
struct ReplayStep {
    now_ms: i64,
    key_hex: String,
    t_ms: i64,
    verdict: String,
}

#[test]
fn replay_filter_follows_the_shared_vectors() {
    let v: ReplayCases = serde_json::from_str(include_str!("../testdata/replay.json")).unwrap();
    assert!(!v.cases.is_empty());
    for c in v.cases {
        let mut f = ReplayFilter::new(Duration::from_millis(c.window_ms), c.max).unwrap();
        if c.not_before_ms != 0 {
            f = f.with_not_before(std::time::UNIX_EPOCH + Duration::from_millis(c.not_before_ms));
        }
        for (i, s) in c.steps.iter().enumerate() {
            let want = match s.verdict.as_str() {
                "fresh" => ReplayVerdict::Fresh,
                "seen" => ReplayVerdict::Seen,
                "outside" => ReplayVerdict::Outside,
                _ => ReplayVerdict::Full,
            };
            assert_eq!(
                f.check_at(&unhex(&s.key_hex), s.t_ms, s.now_ms),
                want,
                "{} step {i}",
                c.name
            );
        }
    }
    assert!(ReplayFilter::new(Duration::ZERO, 1).is_err());
    assert!(ReplayFilter::new(Duration::from_secs(1), 0).is_err());
}

#[tokio::test(start_paused = true)]
async fn the_cache_takes_reports_per_variant() {
    use std::sync::atomic::AtomicU64;
    use std::time::SystemTime;
    use zmux::{CarrierCacheConfig, CooldownReason, RetryAdmission};

    let wall = Arc::new(AtomicU64::new(1_700_000_000));
    let config = CarrierCacheConfig::default().with_wall_clock({
        let wall = wall.clone();
        move || SystemTime::UNIX_EPOCH + Duration::from_secs(wall.load(Ordering::Relaxed))
    });
    let cache = CarrierCache::new(config.clone()).unwrap();
    let candidate = zmux::Candidate::new(CarrierKind::Split, || async {
        Err(std::io::Error::from(std::io::ErrorKind::ConnectionRefused))
    })
    .with_identity("candidate-x", "k")
    .with_variant("x");
    let mut options = zmux::ControllerOptions::new("variant-cache", vec![candidate]);
    options.cache = Some(cache.clone());
    let controller = zmux::SessionController::new(options).unwrap();
    let refused = controller
        .open(Config::default(), zmux::SessionTarget::default())
        .await;
    assert!(matches!(refused, Err(zmux::ControllerError::Bootstrap(_))));

    assert_eq!(cache.score("k", CarrierKind::Split, "").cooldown, None);
    let score = cache.score("k", CarrierKind::Split, "x");
    let cooldown = score.cooldown.unwrap();
    assert_eq!(cooldown.reason, Some(CooldownReason::Attempt));
    assert_eq!(score.cooldown_level, 1);
    assert_eq!(cooldown.nominal_wait, config.backoff.min);
    let started = cooldown.started_at.unwrap();
    assert_eq!(cooldown.retry_at - started, cooldown.sampled_wait.unwrap());
    assert_eq!(
        cache.retry_admission("k", CarrierKind::Split, "x"),
        Err(RetryAdmission::Cooling)
    );
    let data = cache.export().unwrap();
    let snapshot: serde_json::Value = serde_json::from_slice(&data).unwrap();
    assert_eq!(snapshot["exported_at"], "2023-11-14T22:13:20Z");
    assert_eq!(
        snapshot["entries"][0]["history"]["at"],
        snapshot["exported_at"]
    );
    assert_eq!(cache.export().unwrap(), data);

    let elapsed = Duration::from_secs(1);
    wall.fetch_add(elapsed.as_secs(), Ordering::Relaxed);
    let restored = CarrierCache::new(config).unwrap();
    restored.import(&data).unwrap();
    assert_eq!(restored.score("k", CarrierKind::Split, "x").attempts, 1);
    let imported = restored
        .score("k", CarrierKind::Split, "x")
        .cooldown
        .unwrap();
    assert_eq!(imported.nominal_wait, cooldown.nominal_wait);
    assert_eq!(imported.reason, None);
    assert_eq!(
        restored.score("k", CarrierKind::Split, "x").cooldown_level,
        1
    );
    assert_eq!(imported.sampled_wait, None);
    let remaining_ms = snapshot["entries"][0]["cooling"]["remaining_ms"]
        .as_u64()
        .unwrap();
    assert_eq!(
        imported.retry_at,
        restored.clock_domain().now()
            + Duration::from_millis(remaining_ms)
                .checked_sub(elapsed)
                .unwrap()
    );
    assert_eq!(restored.score("k", CarrierKind::Split, "").attempts, 0);
    let remaining = cooldown
        .retry_at
        .saturating_duration_since(tokio::time::Instant::now().into_std());
    tokio::time::advance(remaining).await;
    assert_eq!(cache.retry_admission("k", CarrierKind::Split, "x"), Ok(()));
    let refused = controller
        .open(Config::default(), zmux::SessionTarget::default())
        .await;
    assert!(matches!(refused, Err(zmux::ControllerError::Bootstrap(_))));
    let doubled = cache.score("k", CarrierKind::Split, "x");
    assert_eq!(doubled.cooldown_level, 2);
    let second = doubled.cooldown.unwrap();
    assert_eq!(second.reason, Some(CooldownReason::Attempt));
    assert_eq!(second.nominal_wait, cooldown.nominal_wait * 2);
}

#[tokio::test(start_paused = true)]
async fn controller_bootstrap_waits_for_dial_after_and_records_authenticated_refusal_as_a_failure()
{
    use zmux::{
        CarrierRetryAfter, ClockDomain, ControllerError, CooldownEvent, CooldownReason,
        RetryAdmission,
    };

    let cache = CarrierCache::default();
    let mut events = cache.subscribe_cooldown();
    let clock = ClockDomain::default();
    let init = clock.now();
    let after = init + Duration::from_secs(5);
    let candidate = zmux::Candidate::new(CarrierKind::Split, move || {
        let at = ClockDomain::default().now();
        async move {
            assert!(at >= after);
            let authenticated: std::io::Error =
                CarrierRetryAfter::new(Duration::from_mins(2)).into();
            Err(std::io::Error::other(authenticated))
        }
    })
    .with_identity("dial-after", "retry-key");
    let mut options = zmux::ControllerOptions::new("bootstrap-dial-after", vec![candidate.clone()]);
    options.cache = Some(cache.clone());
    options.dial_after.insert("dial-after".into(), after);
    let controller = zmux::SessionController::new(options).unwrap();
    assert!(matches!(
        controller
            .open(Config::default(), zmux::SessionTarget::default())
            .await,
        Err(ControllerError::Bootstrap(_))
    ));
    let CooldownEvent::Started {
        reason,
        nominal_wait,
        started_at,
        ..
    } = events.try_recv().unwrap()
    else {
        panic!("expected one fault event");
    };
    assert_eq!(reason, CooldownReason::Attempt);
    assert_eq!(
        nominal_wait,
        zmux::CarrierCacheConfig::default().backoff.min
    );
    assert!(started_at >= after);
    assert_eq!(
        cache.retry_admission("retry-key", CarrierKind::Split, ""),
        Err(RetryAdmission::RetryAfter)
    );

    let mut options =
        zmux::ControllerOptions::new("bootstrap-dial-after-deadline", vec![candidate]);
    let after = clock.now() + Duration::from_hours(1);
    options.dial_after.insert("dial-after".into(), after);
    let controller = zmux::SessionController::new(options).unwrap();
    assert!(
        matches!(controller.open(Config::default(), zmux::SessionTarget::default()).await,
        Err(ControllerError::DialAfter(next)) if next == after)
    );
}

#[tokio::test(start_paused = true)]
async fn managed_dial_after_publishes_next_time_and_follows_binding_updates() {
    use zmux::{
        ClockDomain, ControllerBlock, ControllerOptions, Directions, GroupTarget, MemberQuota,
        SessionController, SessionTarget, TargetCandidate,
    };
    let mut config = Config::multipath(PipeAuth::exporter());
    config.session_policy.limits.steady_attachments = 4;
    let (client, _server) = connected(config.clone(), config, true).await;
    let clock = ClockDomain::default();
    let initial = clock.now() + Duration::from_secs(5);
    let updated = clock.now() + Duration::from_secs(7);
    let candidate = zmux::Candidate::new(CarrierKind::Split, || async {
        Err(std::io::Error::from(std::io::ErrorKind::ConnectionRefused))
    })
    .with_identity("managed", "managed-key");
    let mut options = ControllerOptions::new("managed-dial-after", vec![candidate]);
    options.dial_after.insert("managed".into(), initial);
    let controller = SessionController::new(options).unwrap();
    let target = SessionTarget {
        revision: 1,
        groups: vec![GroupTarget {
            id: "main".into(),
            quotas: vec![MemberQuota {
                id: "extra".into(),
                count: 1,
                directions: Directions::BOTH,
                candidates: vec![TargetCandidate {
                    id: "managed".into(),
                    send: None,
                    receive: None,
                }],
            }],

            rotation: zmux::RotationPolicy::default(),
        }],
        replace: Vec::new(),
    };
    let control = controller.manage(&client, target).unwrap();
    let mut states = control.subscribe();
    let first = watchdog(
        2,
        "initial DialAfter",
        states.wait_for(|s| {
            s.blocked == Some(ControllerBlock::DialAfter) && s.next_retry == Some(initial)
        }),
    )
    .await
    .unwrap();
    drop(first);
    control
        .set_dial_after("managed".into(), Some(updated))
        .unwrap();
    let changed = watchdog(
        2,
        "updated DialAfter",
        states.wait_for(|s| {
            s.blocked == Some(ControllerBlock::DialAfter) && s.next_retry == Some(updated)
        }),
    )
    .await
    .unwrap();
    drop(changed);
    let unblocked = watchdog(
        12,
        "DialAfter expires",
        states.wait_for(|s| s.blocked != Some(ControllerBlock::DialAfter)),
    )
    .await
    .unwrap();
    assert!(clock.now() >= updated);
    drop(unblocked);
    control.release().unwrap();
    watchdog(2, "managed stop", control.done()).await;
}

#[test]
fn admission_timeouts_beyond_the_clock_do_not_panic() {
    multi_thread(async {
        use zmux::{Listener, ListenerConfig};
        let adm = Admission::new(2, |_: zmux::CarrierInfo, prefix: &[u8]| {
            if prefix.len() < 5 {
                AdmissionVerdict::More { need: 5 }.labelled("x")
            } else {
                AdmissionVerdict::accept(5).labelled("x")
            }
        })
        .with_max_peek(8)
        .with_peek_timeout(Duration::MAX)
        .with_stall_interval(Duration::MAX, Duration::MAX);
        let mut lc = ListenerConfig::default();
        lc.admission = Some(adm);
        let listener = Listener::new(Config::default(), lc).expect("valid listener configuration");
        let peer: std::net::SocketAddr = "127.0.0.1:9".parse().unwrap();
        let mut entry = listener.adapter().enter(peer, None).unwrap();
        let mut bytes: &[u8] = b"abcdefgh";
        let admit = entry
            .decide_request(zmux::CarrierInfo::new(), Some(&mut bytes))
            .await;
        assert_eq!(admit, zmux::adapter::Admit::Accept(Vec::new()));
        assert_eq!(bytes, b"fgh");
        let stats = listener.stats().admission;
        assert_eq!(stats.accepted, 1);
        assert_eq!(
            listener.variant_stats().variants[&Arc::<str>::from("x")].accepted,
            1
        );
        drop(entry);
        // A `need` out of bounds closes.
        let _: Option<SessionError> = None;
    });
}

#[test]
fn a_panic_under_the_lock_closes_with_internal_error() {
    multi_thread(async {
        let (client, server) = connected(Config::default(), Config::default(), false).await;
        let c = client.clone();
        let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
            c.panic_under_lock();
        }));
        assert!(panicked.is_err());
        let e = watchdog(5, "closed", server.closing()).await;
        assert!(
            matches!(
                &e,
                SessionError::TransportClosed { code, remote: true, .. }
                    if *code == zmux::proto::TransportErrorCode::INTERNAL_ERROR
            ),
            "{e:?}"
        );
    });
}

/// With no handshake timeout, a join still ends at the 10 s default, and establishment waits.
#[test]
fn a_join_has_a_deadline_without_a_handshake_timeout() {
    use zmux::proto::record::Framing;
    use zmux::proto::seal::RecordMode;
    use zmux::proto::session::{Config as CoreConfig, PipeFailure, PipeOptions};
    let mut c = CoreConfig::multipath(
        PipeAuth::psk(*b"a pre-shared key of 32 bytes....").with_end_to_end(),
    );
    c.handshake_timeout = None;
    let mut b = c.clone();
    b.test_hooks().locator = b"server".to_vec();
    let mut p = core_pair::CorePair::new(c, b);
    let now = p.now;
    let f = Some(Framing::ByteStream);
    let id =
        p.a.add_pipe(f, f, &PipeOptions::new(), RecordMode::Trusted, None, now)
            .unwrap();
    p.a.join_prepare(id, now).unwrap().unwrap();
    let later = now + Duration::from_secs(9);
    p.a.handle_timeout(later);
    assert!(p.a.pipe_joined(id).and_then(Result::err).is_none());
    let later = now + Duration::from_secs(10);
    p.a.handle_timeout(later);
    assert!(matches!(
        p.a.pipe_joined(id).and_then(Result::err),
        Some(PipeError::Failed(PipeFailure::JoinTimedOut))
    ));
}
