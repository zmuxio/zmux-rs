//! Session limits read from JSON, with the language-independent cases of
//! `testdata/shaping/session_limits.json`.

use serde::Deserialize;
use zmux_shaping::session_limits;

#[derive(Deserialize)]
struct Vectors {
    version: u32,
    cases: Vec<Case>,
}

#[derive(Deserialize)]
struct Case {
    name: String,
    #[serde(default)]
    limits: Option<serde_json::Value>,
    #[serde(default)]
    raw: Option<String>,
    ok: bool,
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    want: Option<Want>,
}

#[derive(Deserialize, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
struct Want {
    max_padding_bytes: Option<u64>,
    max_padding_ratio: Option<f64>,
    max_injected: Option<u64>,
    max_pause_total: Option<f64>,
    max_delay: Option<f64>,
}

#[test]
fn session_limit_vectors() {
    let b = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../testdata/shaping/session_limits.json"
    ))
    .unwrap();
    let v: Vectors = serde_json::from_slice(&b).unwrap();
    assert_eq!(v.version, 1);
    for c in v.cases {
        let raw = match (&c.raw, &c.limits) {
            (Some(r), _) => r.clone().into_bytes(),
            (None, Some(l)) => serde_json::to_vec(l).unwrap(),
            _ => panic!("{}: no input", c.name),
        };
        let r = session_limits(&raw);
        assert_eq!(r.is_ok(), c.ok, "{}: {:?}", c.name, r.as_ref().err());
        match r {
            Err(e) => {
                let e = e.to_string().to_lowercase();
                let want = c.error.as_deref().unwrap_or_default().to_lowercase();
                assert!(e.contains(&want), "{}: {e}, want {want:?}", c.name);
            }
            Ok(l) => {
                let got = Want {
                    max_padding_bytes: l.max_padding_bytes,
                    max_padding_ratio: l.max_padding_ratio,
                    max_injected: l.max_injected,
                    max_pause_total: l.max_pause_total.map(|d| d.as_secs_f64()),
                    max_delay: l.max_delay.map(|d| d.as_secs_f64()),
                };
                if let Some(w) = c.want {
                    assert_eq!(got, w, "{}", c.name);
                }
            }
        }
    }
}
