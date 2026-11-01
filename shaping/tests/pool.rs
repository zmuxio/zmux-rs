//! The pool policy, with the language-independent cases of
//! `testdata/shaping/pool_policy.json`.

use std::time::Duration;

use serde::Deserialize;
use zmux_shaping::{MachinePoolPolicy, MemberDecision, Options, PoolMember, Source, pool_policy};

struct SplitMix(u64);

impl Source for SplitMix {
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }
}

fn seeded(seed: u64) -> Options {
    Options::default().with_source(move || Box::new(SplitMix(seed)))
}

#[derive(Deserialize)]
struct Vectors {
    version: u32,
    parse: Vec<ParseCase>,
    decide: Vec<DecideCase>,
}

#[derive(Deserialize)]
struct ParseCase {
    name: String,
    #[serde(default)]
    policy: Option<serde_json::Value>,
    /// The exact input, for what a JSON value cannot hold.
    #[serde(default)]
    raw: Option<String>,
    ok: bool,
    /// A substring of the error, compared case-insensitively.
    #[serde(default)]
    error: Option<String>,
}

#[derive(Deserialize)]
struct DecideCase {
    name: String,
    policy: serde_json::Value,
    steps: Vec<Step>,
}

#[derive(Deserialize)]
struct Step {
    #[serde(default)]
    failures: u32,
    /// Seconds since the last dial; absent: none.
    since_dial: Option<f64>,
    #[serde(default)]
    members: Vec<Member>,
    #[serde(default)]
    want: Want,
}

#[derive(Deserialize)]
struct Member {
    id: u64,
    #[serde(default)]
    age: f64,
    #[serde(default)]
    idle: f64,
    #[serde(default)]
    pipes: f64,
    #[serde(default)]
    bytes_sent: f64,
    #[serde(default)]
    bytes_received: f64,
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct Want {
    #[serde(default, deserialize_with = "present")]
    count: Option<Option<usize>>,
    #[serde(default, deserialize_with = "present")]
    dial_after: Option<Option<f64>>,
    retire: Option<Vec<u64>>,
    count_in: Option<[f64; 2]>,
    dial_after_in: Option<[f64; 2]>,
    #[serde(default, deserialize_with = "present")]
    recheck: Option<Option<f64>>,
    recheck_in: Option<[f64; 2]>,
    same_as: Option<usize>,
    #[serde(default, deserialize_with = "present")]
    probe_interval: Option<Option<f64>>,
    probe_interval_in: Option<[f64; 2]>,
    #[serde(default, deserialize_with = "present")]
    probe_jitter: Option<Option<f64>>,
    dial_after_same_as: Option<usize>,
    /// DialAfter was drawn anew: it differs from that of step n.
    dial_after_redrawn_from: Option<usize>,
}

/// A field that is present (possibly null) is `Some`.
fn present<'de, D, T>(d: D) -> Result<Option<Option<T>>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(d).map(Some)
}

fn vectors() -> Vectors {
    let b = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../testdata/shaping/pool_policy.json"
    ))
    .unwrap();
    let v: Vectors = serde_json::from_slice(&b).unwrap();
    assert_eq!(v.version, 3);
    v
}

fn members(ms: &[Member]) -> Vec<PoolMember> {
    ms.iter()
        .map(|m| {
            let mut p = PoolMember::new(m.id);
            p.age = Duration::from_secs_f64(m.age);
            p.idle = Duration::from_secs_f64(m.idle);
            p.pipes = m.pipes as u64;
            p.bytes_sent = m.bytes_sent as u64;
            p.bytes_received = m.bytes_received as u64;
            p
        })
        .collect()
}

fn decide(
    p: &mut MachinePoolPolicy,
    failures: u32,
    since: Option<f64>,
    ms: &[PoolMember],
) -> MemberDecision {
    let mut d = MemberDecision::default();
    p.decide_members(failures, since.map(Duration::from_secs_f64), ms, &mut d);
    d
}

#[test]
fn parse_vectors() {
    for c in vectors().parse {
        let raw = match (&c.raw, &c.policy) {
            (Some(r), _) => r.clone().into_bytes(),
            (None, Some(p)) => serde_json::to_vec(p).unwrap(),
            _ => panic!("{}: no input", c.name),
        };
        let r = pool_policy(&raw, seeded(1));
        assert_eq!(r.is_ok(), c.ok, "{}: {:?}", c.name, r.err());
        if let (Some(want), Err(e)) = (&c.error, &r) {
            let e = e.to_string().to_lowercase();
            assert!(
                e.contains(&want.to_lowercase()),
                "{}: {e}, want {want:?}",
                c.name
            );
        }
    }
}

#[test]
fn decide_vectors() {
    for seed in [1, 2, 3] {
        for c in vectors().decide {
            let raw = serde_json::to_vec(&c.policy).unwrap();
            let mut p = pool_policy(&raw, seeded(seed)).unwrap();
            let mut got: Vec<MemberDecision> = Vec::new();
            for (i, s) in c.steps.iter().enumerate() {
                let d = decide(&mut p, s.failures, s.since_dial, &members(&s.members));
                let at = format!("{} step {i} seed {seed}", c.name);
                let w = &s.want;
                if let Some(n) = w.count {
                    assert_eq!(d.count, n, "{at}");
                }
                if let Some(x) = w.dial_after {
                    assert_eq!(d.dial_after, x, "{at}");
                }
                if let Some(r) = &w.retire {
                    assert_eq!(&d.retire, r, "{at}");
                }
                if let Some([a, b]) = w.count_in {
                    let n = d.count.unwrap() as f64;
                    assert!(n >= a && n <= b, "{at}: {n}");
                }
                if let Some([a, b]) = w.dial_after_in {
                    let x = d.dial_after.unwrap();
                    assert!(x >= a && x <= b, "{at}: {x}");
                }
                if let Some(x) = w.recheck {
                    let r = d.recheck.map(|r| r.as_secs_f64());
                    assert!(
                        match (r, x) {
                            (Some(r), Some(x)) => (r - x).abs() < 1e-6,
                            (r, x) => r.is_none() && x.is_none(),
                        },
                        "{at}: {r:?}"
                    );
                }
                if let Some([a, b]) = w.recheck_in {
                    let x = d.recheck.unwrap().as_secs_f64();
                    assert!(x > 0.0 && x >= a && x <= b, "{at}: {x}");
                }
                if let Some(x) = w.probe_interval {
                    assert_eq!(d.probe_interval, x, "{at}");
                }
                let valid = d
                    .probe_interval
                    .is_none_or(|x| x == 0.0 || (1.0..=1e9).contains(&x))
                    && d.dial_after.is_none_or(|x| x >= 0.0);
                assert_eq!(d.validate().is_ok(), valid, "{at}");
                if let Some([a, b]) = w.probe_interval_in {
                    let x = d.probe_interval.unwrap();
                    assert!(x >= a && x <= b, "{at}: {x}");
                }
                if let Some(x) = w.probe_jitter {
                    assert_eq!(d.probe_jitter, x, "{at}");
                }
                if let Some(j) = w.dial_after_same_as {
                    assert_eq!(d.dial_after, got[j].dial_after, "{at}");
                }
                if let Some(j) = w.dial_after_redrawn_from {
                    assert_ne!(d.dial_after, got[j].dial_after, "{at}");
                }
                if let Some(j) = w.same_as {
                    assert_eq!(d, got[j], "{at}");
                }
                got.push(d);
            }
        }
    }
}

/// A policy of the shape of a deployment's (numbers only).
const SAMPLE: &str = r#"{
  "count": {"dist": {"kind": "poisson", "params": [1.7]}, "scope": "shared", "min": 1, "max": 4},
  "dial_after": [
    {"dist": {"kind": "empirical", "points": [1.9, 0.8, 1.2, 0.9], "weights": [0.3, 0.1, 0.3, 0.3]}, "min": 0.3, "max": 2.4},
    {"dist": {"kind": "weibull", "params": [9.1, 1.6]}, "min": 1.1, "max": 12.5}
  ],
  "retire": [
    {"metric": "age", "above": {"dist": {"kind": "gamma", "params": [6.1, 450]}, "scope": "pipe", "min": 600, "max": 4600}},
    {"metric": "bytes", "above": {"dist": {"kind": "lognormal", "params": [20.1, 0.36]}, "scope": "pipe", "min": 73000000, "max": 680000000}},
    {"metric": "idle", "above": {"range": [170, 254], "scope": "pipe", "min": 100, "max": 259}}
  ]
}"#;

#[test]
fn sample_policy() {
    let mut p = pool_policy(SAMPLE.as_bytes(), seeded(7)).unwrap();
    let mut young = PoolMember::new(1);
    young.age = Duration::from_secs(10);
    let mut old = PoolMember::new(2);
    old.age = Duration::from_secs(5000);
    let mut idle = PoolMember::new(3);
    idle.idle = Duration::from_secs(300);
    let ms = [young, old, idle];
    let first = decide(&mut p, 0, None, &ms);
    assert!((1..=4).contains(&first.count.unwrap()));
    let x = first.dial_after.unwrap();
    assert!((0.3..=2.4).contains(&x), "{x}");
    assert_eq!(first.retire, [2, 3]);
    for _ in 0..50 {
        let d = decide(&mut p, 2, None, &ms);
        assert_eq!(d.count, first.count);
        let x = d.dial_after.unwrap();
        assert!((1.1..=12.5).contains(&x), "{x}");
        assert_eq!(d.retire, [2, 3]);
    }
}

#[test]
fn fixed_seed_is_deterministic() {
    let run = |seed| {
        let mut p = pool_policy(SAMPLE.as_bytes(), seeded(seed)).unwrap();
        let mut m = PoolMember::new(1);
        m.age = Duration::from_secs(2000);
        (0..20)
            .map(|i| decide(&mut p, i % 3, None, std::slice::from_ref(&m)))
            .collect::<Vec<_>>()
    };
    assert_eq!(run(5), run(5));
    assert_ne!(run(5), run(6));
}

fn aged(id: u64, secs: u64) -> PoolMember {
    let mut m = PoolMember::new(id);
    m.age = Duration::from_secs(secs);
    m
}

/// Values of scope `pipe` are kept while the member is in view and drawn
/// anew when it comes back; other values without a scope vary.
#[test]
fn scopes() {
    let raw = br#"{"count": {"range": [1, 1000]},
        "retire": [{"metric": "age", "above": {"range": [0, 100], "scope": "pipe"}}]}"#;
    let mut p = pool_policy(raw, seeded(9)).unwrap();
    let m = [aged(1, 50)];
    let mut counts = std::collections::HashSet::new();
    let mut outcomes = std::collections::HashSet::new();
    for _ in 0..40 {
        let first = decide(&mut p, 0, None, &m);
        counts.insert(first.count);
        for _ in 0..5 {
            assert_eq!(decide(&mut p, 0, None, &m).retire, first.retire);
        }
        outcomes.insert(first.retire.clone());
        // The member leaves the view.
        decide(&mut p, 0, None, &[aged(2, 50)]);
    }
    assert!(counts.len() > 20, "{counts:?}");
    assert_eq!(outcomes.len(), 2, "{outcomes:?}");
}

#[test]
fn input_bound() {
    let mut o = seeded(1);
    o.limits.max_bytes = Some(4);
    assert!(pool_policy(b"{   }", o).is_err());
}

#[cfg(feature = "tokio")]
mod pool {
    //! A pipe pool run by a policy.

    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::{Duration, Instant};

    use zmux::helpers::{Backoff, PipePool, PoolDecision, PoolPolicy, PoolView};
    use zmux::{
        Config, Listener, ListenerConfig, OutboundState, PipeAuth, PipeHint, PipeIo, Session,
    };
    use zmux_shaping::pool_policy;

    fn config() -> Config {
        let mut c = Config::default();
        c.max_pipes = 6;
        c.pipe_auth = PipeAuth::psk(*b"pool-policy-psk-0123456789abcdef");
        c
    }

    fn carrier(l: &Listener) -> PipeIo {
        let (a, b) = tokio::io::duplex(256 * 1024);
        let l = l.clone();
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

    fn usable(s: &Session) -> usize {
        s.pipe_stats()
            .iter()
            .filter(|p| p.pipe.get() != 0)
            .filter(|p| p.outbound == Some(OutboundState::Active) && !p.in_probation)
            .count()
    }

    async fn until(what: &str, secs: u64, mut f: impl FnMut() -> bool) {
        let start = Instant::now();
        while !f() {
            assert!(
                start.elapsed() < Duration::from_secs(secs),
                "timed out: {what}"
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn count_and_retire() {
        let listener = Listener::new(config(), ListenerConfig::default());
        let client = Session::connect(carrier(&listener), config())
            .await
            .unwrap();
        let _server = listener.accept().await.unwrap();
        let dials = Arc::new(AtomicUsize::new(0));
        let (l, n) = (listener.clone(), dials.clone());
        let mut pool = PipePool::new(1, move |_| {
            n.fetch_add(1, Ordering::SeqCst);
            std::future::ready(Ok(carrier(&l)))
        });
        pool.options.probation = Some(Duration::from_millis(50));
        pool.backoff = Backoff::new(Duration::from_millis(50), Duration::from_millis(200));
        let policy = pool_policy(
            br#"{"count": {"const": 2}, "retire": [{"metric": "age", "above": {"const": 0.4}}]}"#,
            Default::default(),
        )
        .unwrap();
        let handle = zmux::helpers::maintain_pipes(&client, pool.with_policy(policy));
        until("two usable pipes", 10, || usable(&client) == 2).await;
        // Pipes older than 0.4 s are replaced, make before break.
        until("replacements", 15, || dials.load(Ordering::SeqCst) >= 4).await;
        until("two usable pipes again", 10, || usable(&client) == 2).await;
        handle.stop();
        until("stopped", 5, || handle.is_finished()).await;
        client.close(0u32.into(), b"");
    }

    /// A decision with a probe interval below 1 s is rejected as a whole
    /// and reported: the pool keeps its own count of 1 instead of the
    /// policy's 2, and nothing raises the interval to 1 s.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn sub_second_probe_interval_rejects_the_decision() {
        let listener = Listener::new(config(), ListenerConfig::default());
        let client = Session::connect(carrier(&listener), config())
            .await
            .unwrap();
        let _server = listener.accept().await.unwrap();
        let l = listener.clone();
        let mut pool = PipePool::new(1, move |_| std::future::ready(Ok(carrier(&l))));
        pool.options.probation = Some(Duration::from_millis(50));
        let policy = pool_policy(
            br#"{"count": {"const": 2}, "probe_interval": {"const": 0.5}}"#,
            Default::default(),
        )
        .unwrap();
        let rejected = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let seen = rejected.clone();
        let pool = pool
            .with_policy(policy)
            .with_decision_rejected(move |r| seen.lock().unwrap().push(r.to_owned()));
        let handle = zmux::helpers::maintain_pipes(&client, pool);
        until("one usable pipe", 10, || usable(&client) == 1).await;
        until("rejections", 10, || rejected.lock().unwrap().len() >= 3).await;
        assert_eq!(usable(&client), 1);
        assert!(
            rejected.lock().unwrap()[0].contains("probe_interval"),
            "{:?}",
            rejected.lock().unwrap()
        );
        handle.stop();
        until("stopped", 5, || handle.is_finished()).await;
        client.close(0u32.into(), b"");
    }

    /// A pipe kept busy, with no pool event, is retired on age at the
    /// decision its recheck asks for: make before break, the session and
    /// its stream carry on.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn busy_pipe_retires_on_age_by_recheck() {
        let listener = Listener::new(config(), ListenerConfig::default());
        let client = Session::connect(carrier(&listener), config())
            .await
            .unwrap();
        let server = listener.accept().await.unwrap();
        let dials = Arc::new(AtomicUsize::new(0));
        let (l, n) = (listener.clone(), dials.clone());
        let mut pool = PipePool::new(1, move |_| {
            n.fetch_add(1, Ordering::SeqCst);
            std::future::ready(Ok(carrier(&l)))
        });
        pool.options.probation = Some(Duration::from_millis(50));
        let mut policy = pool_policy(
            br#"{"retire": [{"metric": "age", "above": {"const": 0.6}},
                            {"metric": "bytes", "above": {"const": 1e15}}]}"#,
            Default::default(),
        )
        .unwrap();
        let rechecks = Arc::new(std::sync::Mutex::new(Vec::new()));
        let seen = rechecks.clone();
        let pool = pool.with_policy(move |v: &PoolView<'_>, d: &mut PoolDecision| {
            policy.decide(v, d);
            if let Some(r) = d.recheck {
                seen.lock().unwrap().push(r);
            }
        });
        let handle = zmux::helpers::maintain_pipes(&client, pool);
        until("one usable pipe", 10, || usable(&client) == 1).await;
        // One stream busy throughout.
        let (mut tx, _rx) = client.open_bi().await.unwrap();
        let peer = server.clone();
        let reader = tokio::spawn(async move {
            let (_t, mut r) = peer.accept_bi().await.unwrap();
            let mut buf = vec![0; 64 * 1024];
            let mut total = 0usize;
            while let Some(k) = r.read(&mut buf).await.unwrap() {
                total += k;
            }
            total
        });
        let chunk = vec![7u8; 16 * 1024];
        let mut sent = 0usize;
        let start = Instant::now();
        while dials.load(Ordering::SeqCst) < 2 || start.elapsed() < Duration::from_millis(1500) {
            assert!(start.elapsed() < Duration::from_secs(15), "no retirement");
            tx.write_all(&chunk).await.unwrap();
            sent += chunk.len();
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        tx.finish().unwrap();
        assert_eq!(reader.await.unwrap(), sent);
        until("one pool pipe left", 10, || usable(&client) == 1).await;
        assert!(client.close_reason().is_none());
        assert_eq!(client.stats().bytes_reinjected, 0);
        // Each recheck is the age rule's time left: at most 0.6 s.
        let r = rechecks.lock().unwrap().clone();
        assert!(!r.is_empty());
        assert!(r.iter().all(|r| *r <= Duration::from_millis(600)), "{r:?}");
        handle.stop();
        until("stopped", 5, || handle.is_finished()).await;
        client.close(0u32.into(), b"");
    }

    /// A quiet pipe probed every second is idle by its traffic clock: the
    /// `idle` rule replaces it although probes keep its byte counts moving.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn idle_rule_fires_on_a_probed_pipe() {
        let listener = Listener::new(config(), ListenerConfig::default());
        let client = Session::connect(carrier(&listener), config())
            .await
            .unwrap();
        let _server = listener.accept().await.unwrap();
        let dials = Arc::new(AtomicUsize::new(0));
        let (l, n) = (listener.clone(), dials.clone());
        let mut pool = PipePool::new(1, move |_| {
            n.fetch_add(1, Ordering::SeqCst);
            std::future::ready(Ok(carrier(&l)))
        });
        pool.options.probation = Some(Duration::from_millis(50));
        pool.options.probe_interval = Some(zmux::Period::Every(Duration::from_secs(1)));
        let policy = pool_policy(
            br#"{"retire": [{"metric": "idle", "above": {"const": 2.5}}]}"#,
            Default::default(),
        )
        .unwrap();
        let handle = zmux::helpers::maintain_pipes(&client, pool.with_policy(policy));
        until("one usable pipe", 10, || usable(&client) == 1).await;
        let first = client
            .pipe_stats()
            .iter()
            .map(|p| p.pings_sent)
            .sum::<u64>();
        until("an idle replacement", 10, || {
            dials.load(Ordering::SeqCst) >= 2
        })
        .await;
        let pings = client
            .pipe_stats()
            .iter()
            .map(|p| p.pings_sent)
            .sum::<u64>();
        assert!(pings > first, "no probe went before the replacement");
        handle.stop();
        until("stopped", 5, || handle.is_finished()).await;
        client.close(0u32.into(), b"");
    }
}
