//! The shared carrier cache snapshot vectors (testdata/carrier-cache):
//! every case's steps restored in order into a new cache, then its
//! snapshot compared with the expected entries; and the JSON round trip.

use std::time::{Duration, SystemTime};

use serde::Deserialize;
use zmux::{CacheSnapshot, CacheSnapshotEntry, CarrierCache, CarrierKind};

#[derive(Deserialize)]
struct Vectors {
    cases: Vec<Case>,
    exact: Vec<String>,
}

#[derive(Deserialize)]
struct Case {
    name: String,
    steps: Vec<Step>,
    expect: Vec<Expect>,
}

#[derive(Deserialize)]
struct Step {
    snapshot: String,
    #[serde(default)]
    error: bool,
}

#[derive(Deserialize, Debug, PartialEq)]
struct Expect {
    key: String,
    kind: String,
    usable: bool,
    failed: bool,
    backoff_ms: u64,
    url: String,
}

/// The RFC 3339 form of `t` (through the snapshot's own encoding).
fn rfc3339(t: SystemTime) -> String {
    let mut e = CacheSnapshotEntry::new("", CarrierKind::Quic);
    e.good_until = Some(t);
    let mut s = CacheSnapshot::default();
    s.entries.push(e);
    let json = s.to_json();
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    v["entries"][0]["good_until"].as_str().unwrap().to_owned()
}

/// Substitutes `"@+N"` and `"@-N"` with the time N seconds from `now`.
fn substitute(text: &str, now: SystemTime) -> String {
    let mut out = String::new();
    let mut rest = text;
    while let Some(i) = rest.find("\"@") {
        out.push_str(&rest[..=i]);
        let tail = &rest[i + 2..];
        let end = tail.find('"').unwrap();
        let (sign, n) = tail[..end].split_at(1);
        let d = Duration::from_secs(n.parse().unwrap());
        let t = if sign == "+" { now + d } else { now - d };
        out.push_str(&rfc3339(t));
        rest = &tail[end..];
    }
    out.push_str(rest);
    out
}

fn entries(cache: &CarrierCache, now: SystemTime) -> Vec<Expect> {
    let mut v: Vec<Expect> = cache
        .snapshot()
        .entries
        .into_iter()
        .map(|e| Expect {
            key: e.key,
            kind: e.kind.name().to_owned(),
            usable: e.good_until.is_some_and(|t| t > now),
            failed: e.fail_until.is_some_and(|t| t > now),
            backoff_ms: e.backoff.as_millis() as u64,
            url: e.url,
        })
        .collect();
    v.sort_by(|a, b| (&a.key, &a.kind).cmp(&(&b.key, &b.kind)));
    v
}

#[test]
fn shared_vectors() {
    let text = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/testdata/carrier-cache/vectors.json"
    ))
    .unwrap();
    let vectors: Vectors = serde_json::from_str(&text).unwrap();
    assert!(!vectors.cases.is_empty() && !vectors.exact.is_empty());
    for text in &vectors.exact {
        assert_eq!(&CacheSnapshot::from_json(text).unwrap().to_json(), text);
    }
    for case in vectors.cases {
        let now = SystemTime::now();
        let cache = CarrierCache::default();
        for (i, step) in case.steps.iter().enumerate() {
            let json = substitute(&step.snapshot, now);
            match CacheSnapshot::from_json(&json) {
                Ok(s) => {
                    assert!(!step.error, "{} step {i} accepted: {json}", case.name);
                    cache.restore(&s);
                }
                Err(e) => assert!(step.error, "{} step {i}: {e}: {json}", case.name),
            }
        }
        assert_eq!(entries(&cache, now), case.expect, "{}", case.name);
        // The cache's own snapshot round-trips through JSON.
        let snap = cache.snapshot();
        let again = CacheSnapshot::from_json(&snap.to_json()).unwrap();
        assert_eq!(again, snap, "{}", case.name);
        let other = CarrierCache::default();
        other.restore(&again);
        assert_eq!(entries(&other, now), case.expect, "{} again", case.name);
    }
}
