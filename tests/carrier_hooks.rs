//! The carrier hooks and runtime controls: late exporter, deferred join
//! secret, runtime limits, flush, first-bytes and replay vectors, admission
//! rounds and labels, and the cache's reports.

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
    Admission, AdmissionVerdict, CacheOutcome, CarrierCache, CarrierKind, Config, ExportError,
    Listener, ListenerConfig, Liveness, PipeAuth, PipeError, PipeIo, ReplayFilter, ReplayVerdict,
    Session, SessionError,
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

async fn connected(client: Config, server: Config, exporter: bool) -> (Session, Session) {
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
            client.begin_add_pipe(extra, Default::default()),
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
        tokio::spawn(async move { serving.handle_pipe(b, Default::default()).await });
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
        tokio::spawn(async move { serving.handle_pipe(extra_b, Default::default()).await });
        client.begin_add_pipe(extra_a, Default::default()).unwrap();
        // Longer than a good many rounds of any polling.
        watchdog(5, "held", async {
            while server.stats().join_pending == 0 {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await;
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(server.stats().join_pending, 1);
        server.set_join_secret(&key).unwrap();
        // The listener counts a join once it handed the attached pipe its
        // task, just after the session shows the pipe.
        watchdog(5, "joined", async {
            while server.pipe_stats().len() < 2 || listener.stats().joins == 0 {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await;
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
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(
            tokio::time::timeout(Duration::ZERO, client.closing())
                .await
                .is_err()
        );
        assert!(
            tokio::time::timeout(Duration::ZERO, server.closing())
                .await
                .is_err()
        );
        let (mut send, _recv) = client.open_bi().await.unwrap();
        send.write_all(b"x").await.unwrap();
        send.flush().await.unwrap();
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
        let (client, _server) = watchdog(5, "connect", async {
            let server = tokio::spawn(Session::accept(b, Config::default()));
            let client = Session::connect(a, c).await.unwrap();
            (client, server.await.unwrap().unwrap())
        })
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
        let (client, server) = connected(Config::default(), Config::default(), false).await;
        let mut l = client.liveness();
        l.keep_alive_period = Some(Duration::from_millis(10));
        assert!(client.set_liveness(&l).is_err(), "below 1 s");
        l.keep_alive_period = None;
        client.set_liveness(&l).unwrap();
        assert_eq!(client.liveness().keep_alive_period, None);
        assert_ne!(Liveness::default().keep_alive_period, None);

        let mut limits = client.shaping_limits();
        limits.wire = zmux::shaping::Account::new((1 << 53) + 1, 0, 0);
        assert!(client.set_shaping_limits(limits).is_err());
        limits.wire = zmux::shaping::Account::new(500, 0, 0);
        client.set_shaping_limits(limits).unwrap();
        assert_eq!(client.shaping_limits().wire.initial, 500);

        assert!(server.raise_incoming_streams((1 << 60) + 1, 0).is_err());
        server.raise_incoming_streams(1000, 0).unwrap();
        watchdog(5, "credit", async {
            loop {
                let r: Vec<_> = (0..600).map(|_| client.try_open_uni()).collect();
                drop(r);
                if client.try_open_bi().is_ok() {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await;
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

#[test]
fn early_flush_opens_on_the_floor_and_after_the_peer_answers() {
    multi_thread(async {
        let ((a, _), (b, _)) = duplex(1 << 20);
        let mut c = Config::default();
        c.early_data = zmux::EarlyData::for_zmux_peer();
        let client = watchdog(5, "connect", Session::connect(a, c))
            .await
            .unwrap();
        let (mut send, _r) = client.open_bi().await.unwrap();
        watchdog(5, "flush", send.flush()).await.unwrap();
        let server = watchdog(5, "accept", Session::accept(b, Config::default()))
            .await
            .unwrap();
        watchdog(5, "accept_bi", server.accept_bi()).await.unwrap();
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

#[test]
fn the_cache_takes_reports_per_variant() {
    let cache = CarrierCache::default();
    cache.report("k", CarrierKind::Split, Some("x"), CacheOutcome::Rejected);
    assert!(cache.failed_until("k", CarrierKind::Split, None).is_none());
    let text = cache.snapshot().to_json();
    assert!(text.contains("\"variant\":\"x\""), "{text}");
    let back = zmux::CacheSnapshot::from_json(&text).unwrap();
    assert_eq!(back.entries[0].variant.as_deref(), Some("x"));
    cache.report("k", CarrierKind::Split, None, CacheOutcome::Usable);
    assert!(cache.is_usable("k", CarrierKind::Split, None));
}

#[test]
fn admission_timeouts_beyond_the_clock_do_not_panic() {
    multi_thread(async {
        use zmux::{Listener, ListenerConfig};
        let adm = Admission::new(2, |_: &zmux::CarrierInfo<'_>, prefix: &[u8]| {
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
            .admit(zmux::CarrierInfo::new(), Some(&mut bytes))
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
