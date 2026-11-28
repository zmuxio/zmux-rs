use super::*;
use crate as zmux;
use crate::Candidate;
use crate::MonotonicClock as _;
use crate::driver::capacity_change::OpenerLifetime;

#[path = "../../../tests/common/cache_vectors.rs"]
mod cache_vectors;

#[test]
fn validates_durations_on_the_configured_clock() {
    struct FixedClock(Instant);

    impl crate::MonotonicClock for FixedClock {
        fn now(&self) -> Instant {
            self.0
        }

        fn sleep_until(
            &self,
            _deadline: Instant,
        ) -> std::pin::Pin<Box<dyn Future<Output = ()> + Send + '_>> {
            Box::pin(std::future::pending())
        }
    }

    let origin = Instant::now();
    // Find the end of this platform's Instant range to whole seconds.
    let mut low = 0;
    let mut high = u64::MAX;
    while low + 1 < high {
        let middle = low.midpoint(high);
        if origin.checked_add(Duration::from_secs(middle)).is_some() {
            low = middle;
        } else {
            high = middle;
        }
    }
    let end = origin.checked_add(Duration::from_secs(low)).unwrap();
    let second = Duration::from_secs(1);
    let mut backoff = Backoff::new(second, Duration::from_secs(3));
    assert!(backoff.validate().is_ok());
    let mut config = CarrierCacheConfig {
        clock_domain: crate::ClockDomain::with_source(FixedClock(
            end.checked_sub(backoff.max).unwrap(),
        )),
        half_life: second,
        drop_window: second,
        health_reset: second,
        performance_window: second,
        backoff,
        ..CarrierCacheConfig::default()
    };
    assert!(CarrierCache::new(config.clone()).is_ok());
    backoff.jitter_up = 1.0;
    config.backoff = backoff;
    assert_eq!(
        CarrierCache::new(config.clone()).unwrap_err().field(),
        "Backoff::max"
    );
    config.performance_window = Duration::from_secs(5);
    assert_eq!(
        CarrierCache::new(config).unwrap_err().field(),
        "CarrierCacheConfig::performance_window"
    );
}

#[test]
fn exposure_is_independent_of_observation_intervals() {
    let config = CarrierCacheConfig {
        half_life: Duration::from_secs(10),
        ..CarrierCacheConfig::default()
    };
    let cache = CarrierCache::new(config).unwrap();
    let clock = Clock {
        mono: Instant::now() + Duration::from_secs(10),
        wall: OffsetDateTime::UNIX_EPOCH,
    };
    let key = |name: &str| (name.to_owned(), CarrierKind::Quic, String::new());
    for (name, age, span) in [("whole", 0, 10), ("split", 5, 5), ("split", 0, 5)] {
        cache
            .update(
                &key(name),
                CacheOutcome::Lifetime,
                CarrierObservation {
                    at: clock.mono.checked_sub(Duration::from_secs(age)),
                    duration: Duration::from_secs(span),
                    ..CarrierObservation::default()
                },
                None,
                Some(clock),
                true,
            )
            .unwrap();
    }
    let history = cache.entries();
    let whole = history[&key("whole")].history.late_seconds;
    let split = history[&key("split")].history.late_seconds;
    assert!((whole - split).abs() < 1e-10);
}

fn retry_cache() -> (CarrierCacheConfig, cache_vectors::VectorClock, Candidate) {
    let wall = OffsetDateTime::UNIX_EPOCH;
    let clock = cache_vectors::VectorClock::new(wall);
    let mut config = CarrierCacheConfig::default().with_wall_clock(move || wall.into());
    config.clock_domain = crate::ClockDomain::with_source(clock.clone());
    config.backoff = Backoff::new(Duration::from_mins(1), Duration::from_mins(1));
    config.backoff.jitter = 0.0;
    let candidate = Candidate::new(CarrierKind::Quic, || async {
        panic!("cache tests do not invoke the opener")
    });
    (config, clock, candidate)
}

#[test]
fn late_attempt_uses_the_remaining_key_demand() {
    let (mut config, _, candidate) = retry_cache();
    config.recovery_sample = || 1.0;
    let cache = CarrierCache::new(config).unwrap();
    let key = candidate_key("aliases", &candidate);
    cache.recovery_demand(&key, true);
    let permit = cache.begin("aliases", &candidate, true, None).unwrap();
    let start = permit.start_handle();
    let host = OpenerLifetime(&start);
    start.start().unwrap();
    cache.recovery_demand(&key, true);
    cache.recovery_demand(&key, false);
    assert!(
        permit
            .commit_cadence(
                crate::AttemptReason::DialFailed,
                true,
                cache.clock_domain().now(),
                Some(start.sample())
            )
            .is_ok()
    );
    drop(permit);
    drop(host);
    assert!(matches!(
        cache.begin("aliases", &candidate, true, None),
        Err(RetryAdmission::RecoveryWait)
    ));
    cache.recovery_demand(&key, false);
    assert!(cache.begin("aliases", &candidate, true, None).is_ok());
}

#[test]
fn recovery_cadence_uses_one_sample_per_failure_and_waits_for_the_host() {
    let (mut config, clock, candidate) = retry_cache();
    config.recovery_sample = || 1.0;
    let cache = CarrierCache::new(config).unwrap();
    cache.recovery_demand(&candidate_key("route", &candidate), true);
    let begin = || cache.begin("route", &candidate, true, None);
    cache.record("route", &candidate, CacheOutcome::Failed, true);
    for seconds in [1, 2, 4, 8, 16, 32, 60, 60] {
        let permit = begin().unwrap();
        let start = permit.start_handle();
        let host = OpenerLifetime(&start);
        start.start().unwrap();
        assert!(
            permit
                .commit_cadence(
                    crate::AttemptReason::DialFailed,
                    true,
                    cache.clock_domain().now(),
                    Some(start.sample())
                )
                .is_ok()
        );
        drop(permit);
        assert!(matches!(begin(), Err(RetryAdmission::AlreadyInFlight)));
        drop(host);
        clock.advance(
            Duration::from_secs(seconds)
                .checked_sub(Duration::from_nanos(1))
                .unwrap(),
        );
        assert!(matches!(begin(), Err(RetryAdmission::RecoveryWait)));
        clock.advance(Duration::from_nanos(1));
    }
    let permit = begin().unwrap();
    let start = permit.start_handle();
    let host = OpenerLifetime(&start);
    start.start().unwrap();
    drop(host);
    assert!(matches!(begin(), Err(RetryAdmission::AlreadyInFlight)));
    permit.confirm();
    drop(permit);
    assert!(begin().is_ok());
    cache.recovery_demand(&candidate_key("route", &candidate), false);
}

#[test]
fn snapshot_keeps_the_level_without_delaying_recovery() {
    let (config, clock, candidate) = retry_cache();
    let reset = config.health_reset;
    let cache = CarrierCache::new(config.clone()).unwrap();
    let kind = candidate.kind();
    let fault =
        |cache: &CarrierCache| cache.record("route", &candidate, CacheOutcome::Failed, true);
    fault(&cache);
    fault(&cache);
    clock.advance(Duration::from_secs(5));
    let loaded = CarrierCache::new(config.clone()).unwrap();
    let snapshot = cache.export().unwrap();
    loaded.import(&snapshot).unwrap();
    assert_eq!(loaded.score("route", kind, "").cooldown_level, 2);
    assert!(matches!(
        loaded.begin("route", &candidate, false, None),
        Err(RetryAdmission::Cooling)
    ));

    let mut legacy: serde_json::Value = serde_json::from_slice(&snapshot).unwrap();
    let cooling = legacy["entries"][0]["cooling"].as_object_mut().unwrap();
    cooling.remove("level");
    let older = CarrierCache::new(config).unwrap();
    older.import(&serde_json::to_vec(&legacy).unwrap()).unwrap();
    let saved_wait = older.score("route", kind, "").cooldown.unwrap();
    assert_eq!(saved_wait.remaining, Duration::from_secs(55));
    assert_eq!(older.score("route", kind, "").cooldown_level, 0);
    fault(&older);
    assert_eq!(older.score("route", kind, "").cooldown_level, 1);

    clock.advance(Duration::from_secs(55));
    let score = loaded.score("route", kind, "");
    assert!(score.cooldown.is_none());
    assert_eq!(score.cooldown_level, 2);
    let expired: serde_json::Value = serde_json::from_slice(&loaded.export().unwrap()).unwrap();
    assert_eq!(expired["entries"][0]["cooling"]["level"], 2);
    assert_eq!(expired["entries"][0]["cooling"]["remaining_ms"], 0);
    fault(&loaded);
    assert_eq!(loaded.score("route", kind, "").cooldown_level, 3);

    clock.advance(reset);
    loaded
        .report(
            "route",
            kind,
            "",
            CacheOutcome::Recovered,
            CarrierObservation {
                duration: reset,
                ..CarrierObservation::default()
            },
        )
        .unwrap();
    fault(&loaded);
    assert_eq!(loaded.score("route", kind, "").cooldown_level, 1);
}

#[test]
fn authenticated_refusal_defers_every_attempt_on_the_same_key() {
    let (config, clock, candidate) = retry_cache();
    let cache = CarrierCache::new(config).unwrap();
    cache.record("route", &candidate, CacheOutcome::Failed, true);
    clock.advance(Duration::from_secs(5));
    let permit = cache.begin("route", &candidate, true, None).unwrap();
    assert!(permit.start_handle().start().is_ok());
    drop(OpenerLifetime(&permit.start_handle()));
    let refusal: std::io::Error = CarrierRetryAfter::new(Duration::from_mins(2)).into();
    permit.record_refusal(&std::io::Error::other(refusal));
    permit.record_refusal(&CarrierRetryAfter::new(Duration::from_secs(1)).into());
    drop(permit);
    for early in [false, true] {
        assert!(matches!(
            cache.begin("route", &candidate, early, None),
            Err(RetryAdmission::RetryAfter)
        ));
    }
    assert!(cache.begin("other", &candidate, false, None).is_ok());
    clock.advance(Duration::from_mins(2) - Duration::from_nanos(1));
    assert!(matches!(
        cache.begin("route", &candidate, true, None),
        Err(RetryAdmission::RetryAfter)
    ));
    clock.advance(Duration::from_nanos(1));
    assert!(
        cache
            .begin("route", &candidate, false, None)
            .unwrap()
            .start_handle()
            .start()
            .is_ok()
    );
}

#[test]
fn dial_after_is_candidate_scoped_and_rechecked_at_opener_start() {
    use super::super::controller::DialSchedule;
    let (config, clock, candidate) = retry_cache();
    let cache = CarrierCache::new(config).unwrap();
    let id = crate::CandidateId::from("first");
    let other = crate::CandidateId::from("second");
    let schedule = DialSchedule::default();
    let initial = clock.now();
    let key = "shared";
    cache.record(key, &candidate, CacheOutcome::Failed, true);
    clock.advance(Duration::from_secs(5));

    let reserved = cache
        .begin(key, &candidate, true, Some(schedule.gate(&id)))
        .unwrap();
    let after = initial + Duration::from_secs(70);
    schedule.set(id.clone(), Some(after));
    assert_eq!(
        reserved.start_handle().start(),
        Err(RetryAdmission::DialAfter)
    );
    drop(reserved);

    // Another candidate in the same cache keeps its opportunity in this episode.
    let independent = cache
        .begin(key, &candidate, true, Some(schedule.gate(&other)))
        .unwrap();
    drop(independent);
    clock.advance(Duration::from_secs(65) - Duration::from_nanos(1));
    assert!(matches!(
        cache.begin(key, &candidate, true, Some(schedule.gate(&id))),
        Err(RetryAdmission::DialAfter)
    ));
    clock.advance(Duration::from_nanos(1));
    for _ in 0..2 {
        let admitted = cache
            .begin(key, &candidate, true, Some(schedule.gate(&id)))
            .unwrap();

        assert_eq!(admitted.start_handle().start(), Ok(()));
        drop(OpenerLifetime(&admitted.start_handle()));
        drop(admitted);
        clock.advance(Duration::from_nanos(1));
    }
    let metrics = cache.retry_metrics(key, candidate.kind(), "");
    assert_eq!(metrics.attempted_starts, 2);
    assert_eq!(metrics.suppressions[&RetryAdmission::DialAfter], 1);
}

#[test]
fn cooldown_events_publish_committed_waits_and_one_reset_per_sequence() {
    let (config, clock, candidate) = retry_cache();
    let reset = config.health_reset;
    let cache = CarrierCache::new(config).unwrap();
    let mut events = cache.subscribe_cooldown();
    let initial = clock.now();
    let kind = candidate.kind();
    let key = "route";
    let span = Duration::from_mins(1);
    let peer = Arc::new(());
    let physical = crate::CarrierFailureReport::new(
        crate::CarrierConnId::new(&peer),
        std::num::NonZeroU64::MIN,
        std::io::ErrorKind::ConnectionReset,
    );
    let observation = crate::test_hooks::carrier_failure_observation(initial, physical);
    for _ in 0..2 {
        cache
            .report(key, kind, "", CacheOutcome::ShortDrop, observation.clone())
            .unwrap();
    }
    assert_eq!(
        events.try_recv().unwrap(),
        CooldownEvent::Started {
            key: CarrierCacheKey {
                key: key.into(),
                kind,
                variant: String::new()
            },
            episode: 1,
            level: 1,
            reason: CooldownReason::ShortDrop,
            started_at: initial,
            nominal_wait: span,
            sampled_wait: span,
            retry_at: initial + span,
        }
    );
    assert_eq!(cache.score(key, kind, "").cooldown_level, 1);
    assert!(events.try_recv().is_err());
    clock.advance(Duration::from_secs(5));
    let permit = cache.begin(key, &candidate, true, None).unwrap();
    assert!(matches!(
        cache.begin(key, &candidate, true, None),
        Err(RetryAdmission::AlreadyInFlight)
    ));
    permit.start_handle().start().unwrap();
    drop(OpenerLifetime(&permit.start_handle()));
    drop(permit);
    assert!(events.try_recv().is_err());
    let metrics = cache.retry_metrics(key, kind, "");
    assert_eq!((metrics.faults, metrics.attempted_starts), (1, 1));
    assert_eq!(metrics.elapsed, Some(Duration::from_secs(5)));
    assert_eq!(metrics.remaining, Duration::from_secs(55));
    assert!(
        !metrics
            .suppressions
            .contains_key(&RetryAdmission::AlreadyInFlight)
    );
    let report = |duration| {
        cache
            .report(
                key,
                kind,
                "",
                CacheOutcome::Recovered,
                CarrierObservation {
                    duration,
                    ..CarrierObservation::default()
                },
            )
            .unwrap();
    };
    let before = reset.checked_sub(Duration::from_nanos(1)).unwrap();
    clock.advance(before.checked_sub(Duration::from_secs(5)).unwrap());
    report(before);
    assert!(events.try_recv().is_err());
    clock.advance(Duration::from_nanos(1));
    report(reset);
    assert_eq!(
        events.try_recv().unwrap(),
        CooldownEvent::Reset {
            key: CarrierCacheKey {
                key: key.into(),
                kind,
                variant: String::new()
            },
            episode: Some(1),
            reset_at: initial + reset,
        }
    );
    report(reset);
    assert!(events.try_recv().is_err());
    assert_eq!(cache.score(key, kind, "").cooldown_level, 0);
}

#[test]
fn a_positive_snapshot_level_requires_a_cooldown_anchor() {
    let (config, _, candidate) = retry_cache();
    let cache = CarrierCache::new(config.clone()).unwrap();
    cache.record("route", &candidate, CacheOutcome::Failed, true);
    let mut snapshot: serde_json::Value = serde_json::from_slice(&cache.export().unwrap()).unwrap();
    let cooling = &mut snapshot["entries"][0]["cooling"];
    cooling["at"] = "0001-01-01T00:00:00Z".into();
    cooling["age_ns"] = 0.into();
    let loaded = CarrierCache::new(config).unwrap();
    assert_eq!(
        loaded.import(&serde_json::to_vec(&snapshot).unwrap()),
        Err(CarrierCacheError::Value)
    );
    assert_eq!(
        loaded.score("route", candidate.kind(), "").cooldown_level,
        0
    );
}

#[test]
fn recovery_cadence_uses_terminal_time_and_current_demand() {
    let (config, clock, candidate) = retry_cache();
    let cache = CarrierCache::new(config).unwrap();
    let key = candidate_key("terminal", &candidate);
    let permit = cache.begin("terminal", &candidate, true, None).unwrap();
    let start = permit.start_handle();
    let host = OpenerLifetime(&start);
    start.start().unwrap();
    let at = cache.clock_domain().now();
    // A later owner can add demand while the attempt is still live.
    cache.recovery_demand(&key, true);
    assert!(
        permit
            .commit_cadence(crate::AttemptReason::DialFailed, true, at, None)
            .is_err()
    );
    assert!(
        permit
            .commit_cadence(crate::AttemptReason::DialFailed, true, at, Some(1.0))
            .is_ok()
    );
    clock.advance(Duration::from_millis(200));
    assert_eq!(
        cache
            .retry_metrics("terminal", candidate.kind(), "")
            .recovery_retry_at,
        Some(at + Duration::from_secs(1))
    );
    cache.recovery_demand(&key, false);
    assert_eq!(
        cache
            .retry_metrics("terminal", candidate.kind(), "")
            .recovery_retry_at,
        None
    );
    drop(host);
}

#[test]
fn attributed_failure_after_verified_reply_cools_without_a_second_handshake() {
    let (config, _, candidate) = retry_cache();
    let cache = CarrierCache::new(config).unwrap();
    let permit = cache.begin("post-reply", &candidate, false, None).unwrap();
    let start = permit.start_handle();
    let host = OpenerLifetime(&start);
    start.start().unwrap();
    let at = cache.clock_domain().now();
    start.replied(at);
    permit.settle(
        &crate::AttemptResult {
            id: crate::AttemptId(1),
            generation: Some(1),
            batch: 1,
            reason: crate::AttemptReason::ConfirmationFailed,
            error: Some(crate::PipeError::Io(Arc::new(std::io::Error::other(
                "lost before confirmation",
            )))),
            open_error: None,
            member: None,
            pipes: Vec::new(),
            tickets: Vec::new(),
        },
        at,
    );
    let score = cache.score("post-reply", candidate.kind(), "");
    assert_eq!(score.success_weight, 1.0);
    assert_eq!(score.attempts, 1);
    assert_eq!(score.cooldown_level, 1);
    drop(host);
}
