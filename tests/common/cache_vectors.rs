//! Executes carrier-cache-v2 vectors through the public cache API.

use std::collections::HashMap;
use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::Deserialize;
use serde_json::Value;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use super::zmux::{
    self as zmux, Backoff, CacheOutcome, CarrierCache, CarrierCacheConfig, CarrierCacheError,
    CarrierKind, CarrierObservation,
};

#[derive(Clone, Copy, Deserialize)]
pub(super) struct Tolerance {
    pub(super) absolute: f64,
    pub(super) relative: f64,
}

fn assert_eq_value(expected: &Value, actual: &Value, tolerance: Tolerance, context: &str) {
    if expected.as_number().is_some_and(serde_json::Number::is_f64) {
        let a = actual.as_f64().unwrap();
        let b = expected.as_f64().unwrap();
        let allowed = tolerance
            .absolute
            .max(tolerance.relative * a.abs().max(b.abs()));
        assert!((a - b).abs() <= allowed, "{context}: got {a}, expected {b}");
    } else {
        assert_eq!(actual, expected, "{context}");
    }
}

#[derive(Deserialize)]
pub(super) struct Corpus {
    clock_start: String,
    default_key: [String; 3],
    cases: Vec<Case>,
    #[serde(default)]
    snapshots: Vec<CrossClock>,
}

#[derive(Deserialize)]
struct Case {
    name: String,
    backoff: Option<BackoffSettings>,
    steps: Vec<Step>,
}

#[derive(Clone, Copy, Deserialize)]
struct BackoffSettings {
    min_ms: u64,
    max_ms: u64,
    jitter_down: f64,
    jitter_up: f64,
}

#[derive(Deserialize)]
struct CrossClock {
    name: String,
    backoff: Option<BackoffSettings>,
    exporter: Vec<Step>,
    import_at: String,
    importer: Vec<Step>,
    #[cfg(test)]
    expected: HashMap<String, Value>,
}

#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "kebab-case")]
enum Step {
    Advance {
        ns: u64,
    },
    Report {
        outcome: String,
        key: Option<[String; 3]>,
        at: Option<String>,
        #[serde(default)]
        rtt_ns: u64,
        #[serde(default)]
        rate_bytes_per_second: u64,
    },
    Score {
        key: Option<[String; 3]>,
        expect: Option<Value>,
        #[serde(rename = "as")]
        name: Option<String>,
    },
    Save {
        #[serde(rename = "as")]
        name: String,
    },
    Restart,
    Import {
        from: Option<String>,
        json: Option<String>,
        error: Option<String>,
    },
    AssertExport {
        same_as: Option<String>,
        key_order: Option<Vec<[String; 3]>>,
    },
}

struct Harness<'a> {
    config: CarrierCacheConfig,
    cache: CarrierCache,
    clock: VectorClock,
    default_key: &'a [String; 3],
    saved: HashMap<&'a str, Vec<u8>>,
    observed: HashMap<String, Value>,
}

#[derive(Clone, Copy)]
struct TestTime {
    mono: Instant,
    wall: OffsetDateTime,
}

#[derive(Clone)]
pub(super) struct VectorClock(Arc<Mutex<TestTime>>);

impl VectorClock {
    pub(super) fn new(wall: OffsetDateTime) -> Self {
        Self(Arc::new(Mutex::new(TestTime {
            mono: Instant::now(),
            wall,
        })))
    }

    fn read(&self) -> TestTime {
        *self.0.lock().unwrap()
    }

    pub(super) fn advance(&self, elapsed: Duration) {
        let mut clock = self.0.lock().unwrap();
        clock.mono += elapsed;
        clock.wall += elapsed;
    }
}

impl VectorClock {
    fn observation_time(&self, text: &str) -> Instant {
        let observed = OffsetDateTime::parse(text, &Rfc3339).unwrap();
        let now = self.read();
        let age = Duration::try_from(now.wall - observed).unwrap();
        now.mono.checked_sub(age).unwrap()
    }
}

impl zmux::MonotonicClock for VectorClock {
    fn now(&self) -> Instant {
        self.read().mono
    }

    fn sleep_until(&self, _: Instant) -> std::pin::Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        Box::pin(std::future::pending())
    }
}

impl<'a> Harness<'a> {
    fn new(wall: &str, key: &'a [String; 3], backoff: Option<BackoffSettings>) -> Self {
        let clock = VectorClock::new(OffsetDateTime::parse(wall, &Rfc3339).unwrap());
        let mut config = CarrierCacheConfig::default().with_wall_clock({
            let clock = clock.clone();
            move || clock.read().wall.into()
        });
        config.clock_domain = zmux::ClockDomain::with_source(clock.clone());
        if let Some(backoff) = backoff {
            config.backoff = Backoff::new(
                Duration::from_millis(backoff.min_ms),
                Duration::from_millis(backoff.max_ms),
            );
            config.backoff.jitter = backoff.jitter_down;
            config.backoff.jitter_up = backoff.jitter_up;
        }
        Self {
            cache: CarrierCache::new(config.clone()).unwrap(),
            config,
            default_key: key,
            clock,
            saved: HashMap::new(),
            observed: HashMap::new(),
        }
    }

    fn key(&self, supplied: Option<&[String; 3]>) -> (String, CarrierKind, String) {
        let [key, kind, variant] = supplied.unwrap_or(self.default_key);
        (
            key.clone(),
            CarrierKind::from_name(kind).unwrap(),
            variant.clone(),
        )
    }

    fn run(&mut self, case: &str, steps: &'a [Step], tolerance: Tolerance) {
        for (index, step) in steps.iter().enumerate() {
            match step {
                Step::Advance { ns } => {
                    self.clock.advance(Duration::from_nanos(*ns));
                }
                Step::Report {
                    outcome,
                    key,
                    at,
                    rtt_ns,
                    rate_bytes_per_second,
                } => {
                    let outcome = match outcome.as_str() {
                        "usable" => CacheOutcome::Usable,
                        "failed" => CacheOutcome::Failed,
                        "performance" => CacheOutcome::Performance,
                        "short-drop" => CacheOutcome::ShortDrop,
                        "late-drop" => CacheOutcome::LateDrop,
                        "survived" => CacheOutcome::Survived,
                        other => panic!("unknown outcome {other}"),
                    };
                    let observed_at = at.as_deref().map(|text| self.clock.observation_time(text));
                    let (key, kind, variant) = self.key(key.as_ref());
                    let source = self.cache.register_report_source(key, kind, variant);
                    let observation = CarrierObservation::measured(
                        observed_at,
                        Duration::from_nanos(*rtt_ns),
                        *rate_bytes_per_second,
                    );
                    assert!(
                        self.cache
                            .report_from(&source, 1, outcome, observation)
                            .unwrap(),
                        "{case} step {index}: source did not report a fresh observation",
                    );
                }
                Step::Score { key, expect, name } => {
                    let (key, kind, variant) = self.key(key.as_ref());
                    let score = self.cache.score(&key, kind, &variant);
                    let mut estimated = serde_json::json!({
                        "score": score.score, "attempts": score.attempts, "weight": score.weight,
                        "age_ns": u64::try_from(score.age.as_ref().map_or(0, Duration::as_nanos)).unwrap(),
                        "cooling": score.cooldown.is_some(),
                        "remaining_ms": score.cooldown.map_or(0, |cooldown| {
                            i64::try_from(cooldown.remaining.as_millis()).unwrap_or(i64::MAX)
                        }),
                    });
                    if let Some(expected) = expect {
                        if expected.get("cooldown_level").is_some() {
                            estimated["cooldown_level"] = serde_json::json!(score.cooldown_level);
                        }
                        for (key, value) in expected.as_object().unwrap() {
                            assert_eq_value(
                                value,
                                &estimated[key],
                                tolerance,
                                &format!("{case} step {index}: {key}"),
                            );
                        }
                    }
                    if let Some(name) = name {
                        assert!(
                            self.observed.insert(name.clone(), estimated).is_none(),
                            "{case}: duplicate observation {name}"
                        );
                    }
                }
                Step::Save { name } => {
                    self.saved.insert(name, self.cache.export().unwrap());
                }
                Step::Restart => self.cache = CarrierCache::new(self.config.clone()).unwrap(),
                Step::Import { from, json, error } => {
                    let data = from.as_deref().map_or_else(
                        || json.as_ref().unwrap().as_bytes(),
                        |name| &self.saved[name],
                    );
                    let want = match error.as_deref() {
                        None => Ok(()),
                        Some("unsupported-version") => Err(CarrierCacheError::Version),
                        Some("malformed-snapshot") => Err(CarrierCacheError::Format),
                        Some("invalid-value") => Err(CarrierCacheError::Value),
                        Some(error) => panic!("unknown error {error}"),
                    };
                    assert_eq!(self.cache.import(data), want, "{case} step {index}");
                }
                Step::AssertExport { same_as, key_order } => {
                    let data = self.cache.export().unwrap();
                    if let Some(name) = same_as {
                        assert_eq!(data, self.saved[name.as_str()], "{case} step {index}");
                    }
                    if let Some(order) = key_order {
                        let exported: Value = serde_json::from_slice(&data).unwrap();
                        let keys: Vec<_> = exported["entries"]
                            .as_array()
                            .unwrap()
                            .iter()
                            .map(|row| serde_json::json!([row["key"], row["kind"], row["variant"]]))
                            .collect();
                        assert_eq!(
                            serde_json::json!(keys),
                            serde_json::json!(order),
                            "{case} step {index}"
                        );
                    }
                }
            }
        }
    }
}

impl Corpus {
    pub(super) fn run_case(&self, selector: &str, tolerance: Tolerance) {
        let mut cases = self.cases.iter().filter(|case| case.name == selector);
        let case = cases.next().expect("unknown carrier-cache case");
        assert!(cases.next().is_none(), "duplicate carrier-cache case");
        Harness::new(&self.clock_start, &self.default_key, case.backoff).run(
            selector,
            &case.steps,
            tolerance,
        );
    }

    fn snapshot(&self, selector: &str) -> &CrossClock {
        let mut cases = self.snapshots.iter().filter(|case| case.name == selector);
        let case = cases.next().expect("unknown carrier-cache snapshot");
        assert!(cases.next().is_none(), "duplicate carrier-cache snapshot");
        case
    }

    pub(super) fn export(&self, selector: &str, tolerance: Tolerance) -> String {
        let case = self.snapshot(selector);
        let mut exporter = Harness::new(&self.clock_start, &self.default_key, case.backoff);
        exporter.run(selector, &case.exporter, tolerance);
        String::from_utf8(exporter.cache.export().unwrap()).unwrap()
    }

    pub(super) fn import(
        &self,
        selector: &str,
        snapshot: &str,
        tolerance: Tolerance,
    ) -> HashMap<String, Value> {
        let case = self.snapshot(selector);
        let mut importer = Harness::new(&case.import_at, &self.default_key, case.backoff);
        importer.cache.import(snapshot.as_bytes()).unwrap();
        importer.run(selector, &case.importer, tolerance);
        importer.observed
    }

    #[cfg(test)]
    pub(super) fn run_all(&self, tolerance: Tolerance) {
        for case in &self.cases {
            self.run_case(&case.name, tolerance);
        }
        for case in &self.snapshots {
            let export = self.export(&case.name, tolerance);
            let observed = self.import(&case.name, &export, tolerance);
            assert_eq!(
                observed.len(),
                case.expected.len(),
                "{}: observation fields",
                case.name
            );
            for (name, expected) in &case.expected {
                assert_eq!(
                    observed[name].as_object().unwrap().len(),
                    expected.as_object().unwrap().len()
                );
                for (key, value) in expected.as_object().unwrap() {
                    assert_eq_value(
                        value,
                        &observed[name][key],
                        tolerance,
                        &format!("{}/{name}/{key}", case.name),
                    );
                }
            }
        }
    }
}

#[test]
fn shared_carrier_cache_v2() {
    let data = include_str!("../../testdata/carrier-cache/vectors.json");
    let corpus: Corpus = serde_json::from_str(data).unwrap();
    corpus.run_all(Tolerance {
        absolute: 1e-10,
        relative: 0.0,
    });
}
