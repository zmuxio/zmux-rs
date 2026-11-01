//! Carrier modes (API.md Section 4.8) over in-memory carriers: an explicit
//! mode never falls back; auto mode keeps the first usable candidate in
//! order, reports every try, abandons a silent candidate at its timer and
//! skips kinds the cache holds as failed; with multipath it establishes on
//! the exchange candidate and moves to a preferred kind that joins; pools
//! dialed by a mode pick the cached kind, back failed upgrades off and
//! count early member failures.

use std::io;
use std::time::Duration;

use zmux::helpers::{Backoff, PipePool, maintain_pipes};
use zmux::{
    CacheSnapshot, CacheSnapshotEntry, Candidate, CandidateOutcome, CarrierCache, CarrierKind,
    Config, Listener, ListenerConfig, Mode, ModePolicy, PipeAuth, PipeHint, PipeIo, SessionEvent,
    dial_mode,
};

/// A candidate whose carriers reach `listener`.
fn served(kind: CarrierKind, listener: &Listener) -> Candidate {
    let l = listener.clone();
    Candidate::new(kind, move || {
        let l = l.clone();
        async move {
            let (a, b) = tokio::io::duplex(256 << 10);
            tokio::spawn(async move {
                let _ = l
                    .handle_pipe(
                        PipeIo::new(b),
                        PipeHint::from_peer(([127, 0, 0, 1], 0).into()),
                    )
                    .await;
            });
            Ok(PipeIo::new(a))
        }
    })
}

/// A candidate refused by the path.
fn refused(kind: CarrierKind) -> Candidate {
    Candidate::new(kind, || async {
        Err(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            "the server answered 403",
        ))
    })
}

/// A candidate whose carrier opens but carries nothing back (a path that
/// buffers): `seen` gets what the client wrote on it.
fn silent(kind: CarrierKind) -> Candidate {
    Candidate::new(kind, || async {
        let (a, b) = tokio::io::duplex(64 << 10);
        // Held open, never answered.
        tokio::spawn(async move {
            let _keep = b;
            tokio::time::sleep(Duration::from_secs(30)).await;
        });
        Ok(PipeIo::new(a))
    })
}

fn quick() -> ModePolicy {
    let mut p = ModePolicy::default();
    p.timer_min = Duration::from_millis(300);
    p.timer_max = Duration::from_millis(300);
    p.settle = Duration::from_millis(200);
    p
}

#[tokio::test]
async fn explicit_never_falls_back() {
    tokio::time::timeout(Duration::from_secs(20), async {
        let listener = Listener::new(Config::default(), ListenerConfig::default());
        let e = dial_mode(
            &Mode::explicit(refused(CarrierKind::WebSocket)),
            Config::default(),
            &quick(),
        )
        .await
        .unwrap_err();
        assert_eq!(e.results.len(), 1);
        assert_eq!(e.results[0].outcome, CandidateOutcome::Refused);
        let s = dial_mode(
            &Mode::explicit(served(CarrierKind::Streaming, &listener)),
            Config::default(),
            &quick(),
        )
        .await
        .unwrap();
        assert_eq!(s.stats().carrier, Some(CarrierKind::Streaming));
        listener.close();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn auto_keeps_the_first_usable_and_reports_every_try() {
    tokio::time::timeout(Duration::from_secs(20), async {
        let listener = Listener::new(Config::default(), ListenerConfig::default());
        let cache = CarrierCache::default();
        let policy = quick().with_cache(cache.clone(), "server|net");
        let mode = Mode::auto([
            refused(CarrierKind::WebSocket),
            silent(CarrierKind::Streaming),
            served(CarrierKind::Split, &listener),
            served(CarrierKind::Exchange, &listener),
        ]);
        let s = dial_mode(&mode, Config::default(), &policy).await.unwrap();
        let stats = s.stats();
        assert_eq!(stats.carrier, Some(CarrierKind::Split));
        let tries: Vec<_> = stats
            .carrier_candidates
            .iter()
            .map(|r| (r.kind, r.outcome))
            .collect();
        assert_eq!(
            tries,
            [
                (CarrierKind::WebSocket, CandidateOutcome::Refused),
                (CarrierKind::Streaming, CandidateOutcome::TimedOut),
                (CarrierKind::Split, CandidateOutcome::Usable),
            ]
        );
        let mut events = Vec::new();
        for _ in 0..4 {
            events.push(s.next_event().await.unwrap());
        }
        assert!(events.contains(&SessionEvent::CarrierChosen(CarrierKind::Split)));
        assert!(events.contains(&SessionEvent::CarrierCandidate {
            kind: CarrierKind::Streaming,
            outcome: CandidateOutcome::TimedOut,
            joined: false,
        }));
        // The failed kinds back off: the next dial goes straight to split.
        assert!(
            cache
                .failed_until("server|net", CarrierKind::WebSocket)
                .is_some()
        );
        assert!(cache.is_usable("server|net", CarrierKind::Split));
        let s2 = dial_mode(&mode, Config::default(), &policy).await.unwrap();
        assert_eq!(s2.stats().carrier_candidates.len(), 1);
        // Nothing usable: every try in the error.
        let e = dial_mode(
            &Mode::auto([
                refused(CarrierKind::WebSocket),
                silent(CarrierKind::Exchange),
            ]),
            Config::default(),
            &quick(),
        )
        .await
        .unwrap_err();
        assert_eq!(e.results.len(), 2);
        listener.close();
    })
    .await
    .unwrap();
}

fn multipath() -> Config {
    let mut c = Config::default();
    c.max_pipes = 4;
    c.pipe_auth = PipeAuth::psk(*b"mode-test-psk-0123456789abcdefgh");
    c
}

#[tokio::test]
async fn auto_with_joins_moves_to_a_preferred_kind() {
    tokio::time::timeout(Duration::from_secs(20), async {
        let listener = Listener::new(multipath(), ListenerConfig::default());
        let mode = Mode::auto([
            refused(CarrierKind::WebSocket),
            served(CarrierKind::Streaming, &listener),
            served(CarrierKind::Exchange, &listener),
        ]);
        let s = dial_mode(&mode, multipath(), &quick()).await.unwrap();
        let server = listener.accept().await.unwrap();
        // Established on the exchange candidate.
        assert_eq!(
            s.next_event().await,
            Some(SessionEvent::CarrierCandidate {
                kind: CarrierKind::Exchange,
                outcome: CandidateOutcome::Usable,
                joined: false
            })
        );
        // Then streaming joins, settles and becomes the carrier; the
        // exchange pipe is retired.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        while s.stats().carrier != Some(CarrierKind::Streaming) {
            assert!(tokio::time::Instant::now() < deadline, "no switch");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let joined: Vec<_> = s
            .stats()
            .carrier_candidates
            .iter()
            .filter(|r| r.joined)
            .map(|r| (r.kind, r.outcome))
            .collect();
        assert_eq!(
            joined,
            [
                (CarrierKind::WebSocket, CandidateOutcome::Refused),
                (CarrierKind::Streaming, CandidateOutcome::Usable),
            ]
        );
        while s.pipes().len() != 1 {
            assert!(
                tokio::time::Instant::now() < deadline,
                "exchange not retired"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        // Streams still flow.
        let (mut send, mut recv) = s.open_bi().await.unwrap();
        send.write_all(b"after the switch").await.unwrap();
        send.finish().unwrap();
        let (mut ss, mut sr) = server.accept_bi().await.unwrap();
        let got = sr.read_to_end(1024).await.unwrap();
        ss.write_all(&got).await.unwrap();
        ss.finish().unwrap();
        assert_eq!(recv.read_to_end(1024).await.unwrap(), b"after the switch");
        listener.close();
    })
    .await
    .unwrap();
}

/// A multipath client session over `listener`, and its server side.
async fn connected(listener: &Listener) -> (zmux::Session, zmux::Session) {
    let io = served(CarrierKind::WebSocket, listener)
        .dial()
        .await
        .unwrap();
    let client = zmux::Session::connect(io, multipath()).await.unwrap();
    let server = listener.accept().await.unwrap();
    (client, server)
}

fn joined_tries(s: &zmux::Session) -> Vec<(CarrierKind, CandidateOutcome)> {
    s.stats()
        .carrier_candidates
        .iter()
        .filter(|r| r.joined)
        .map(|r| (r.kind, r.outcome))
        .collect()
}

async fn until(what: &str, mut f: impl FnMut() -> bool) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while !f() {
        assert!(tokio::time::Instant::now() < deadline, "{what}");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// A pool's first member goes over the kind a restored cache holds as
/// usable, skipping the one it holds as failed; no other kind is tried.
#[tokio::test]
async fn mode_pool_dials_the_cached_usable_kind() {
    tokio::time::timeout(Duration::from_secs(20), async {
        let listener = Listener::new(multipath(), ListenerConfig::default());
        let (client, _server) = connected(&listener).await;
        let soon = Some(zmux::WallTime::now().saturating_add(Duration::from_secs(3600)));
        let mut failed = CacheSnapshotEntry::new("k", CarrierKind::Quic);
        failed.fail_until = soon;
        failed.backoff = Duration::from_secs(60);
        let mut good = CacheSnapshotEntry::new("k", CarrierKind::Streaming);
        good.good_until = soon;
        let mut snap = CacheSnapshot::default();
        snap.entries = vec![failed, good];
        let cache = CarrierCache::default();
        cache.restore(&snap);
        let mode = Mode::auto([
            served(CarrierKind::Quic, &listener),
            served(CarrierKind::Streaming, &listener),
            served(CarrierKind::Exchange, &listener),
        ]);
        let pool = PipePool::mode(&mode, &quick().with_cache(cache, "k")).unwrap();
        let _keep = maintain_pipes(&client, pool);
        until("no member", || client.pipes().len() == 2).await;
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert_eq!(
            joined_tries(&client),
            [(CarrierKind::Streaming, CandidateOutcome::Usable)]
        );
        assert_eq!(client.stats().carrier, Some(CarrierKind::Streaming));
        listener.close();
    })
    .await
    .unwrap();
}

/// A failed upgrade keeps the member and backs the preferred kind off,
/// doubling at each failure; a member that fails within the drop window
/// counts against its kind.
#[tokio::test]
async fn mode_pool_upgrade_failures_back_off() {
    tokio::time::timeout(Duration::from_secs(20), async {
        let listener = Listener::new(multipath(), ListenerConfig::default());
        let (client, _server) = connected(&listener).await;
        let cache = CarrierCache::new(
            Duration::from_secs(3600),
            Duration::from_millis(200),
            Duration::from_secs(10),
        );
        let mode = Mode::auto([
            refused(CarrierKind::WebSocket),
            served(CarrierKind::Streaming, &listener),
        ]);
        let pool = PipePool::mode(&mode, &quick().with_cache(cache.clone(), "k"))
            .unwrap()
            .with_backoff(Backoff::new(
                Duration::from_millis(50),
                Duration::from_millis(50),
            ));
        let pipe0 = client.pipes()[0].id();
        let _keep = maintain_pipes(&client, pool);
        let backoff = |kind| {
            cache
                .snapshot()
                .entries
                .iter()
                .find(|e| e.kind == kind)
                .map(|e| e.backoff)
        };
        until("no second upgrade failure", || {
            backoff(CarrierKind::WebSocket) == Some(Duration::from_millis(400))
        })
        .await;
        // The streaming member stayed throughout.
        let tries = joined_tries(&client);
        assert_eq!(tries[0], (CarrierKind::Streaming, CandidateOutcome::Usable));
        assert!(
            tries[1..]
                .iter()
                .all(|t| *t == (CarrierKind::WebSocket, CandidateOutcome::Refused)),
            "{tries:?}"
        );
        assert_eq!(client.pipes().len(), 2);
        assert!(cache.is_usable("k", CarrierKind::Streaming));
        // Its pipe fails soon after it was joined: streaming backs off.
        let member = client
            .pipes()
            .into_iter()
            .find(|p| p.id() != pipe0)
            .unwrap();
        member.abort().unwrap();
        until("member failure not recorded", || {
            cache.failed_until("k", CarrierKind::Streaming).is_some()
        })
        .await;
        listener.close();
    })
    .await
    .unwrap();
}

/// A mode without candidates or with a kind twice is rejected.
#[tokio::test]
async fn invalid_modes_are_rejected() {
    let listener = Listener::new(multipath(), ListenerConfig::default());
    let twice = Mode::auto([
        refused(CarrierKind::Split),
        served(CarrierKind::Split, &listener),
    ]);
    for mode in [Mode::auto([]), twice] {
        assert!(PipePool::mode(&mode, &quick()).is_err());
        let e = dial_mode(&mode, Config::default(), &quick())
            .await
            .unwrap_err();
        assert!(e.invalid.is_some() && e.results.is_empty(), "{e}");
    }
    let mut nan = quick();
    nan.timer_factor = f64::NAN;
    let one = Mode::explicit(served(CarrierKind::Split, &listener));
    assert!(PipePool::mode(&one, &nan).is_err());
}
