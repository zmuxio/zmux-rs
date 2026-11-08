//! The wire examples: every example encodes from its JSON to its bytes and
//! decodes back, the key-schedule vectors match, and the foreign prefixes are
//! rejected at the byte shown.

use std::collections::BTreeMap;

use serde_json::Value;
use zmux::proto::frame::Frame;
use zmux::proto::ident::{Classifier, Verdict};
use zmux::proto::params::{Grease, TransportParameters};
use zmux::proto::payload::{Flow, WirePreamble};
use zmux::proto::{Gates, keys};

use crate::corpus::read_records;
use crate::model::FrameSpec;
use crate::support::{hex, read, to_hex};
use crate::wire::{self, json_subset, no_placeholders, normalise};

struct Example {
    id: String,
    record: Value,
    bytes: Vec<u8>,
}

fn between<'a>(text: &'a str, start: &str, end: &str) -> Option<(&'a str, &'a str)> {
    let a = text.find(start)? + start.len();
    let b = text[a..].find(end)? + a;
    Some((&text[a..b], &text[b + end.len()..]))
}

fn examples() -> Vec<Example> {
    let text = read("WIRE_EXAMPLES.md");
    let mut rest = text.as_str();
    let mut out = Vec::new();
    while let Some((id, after)) = between(rest, "<!-- zmux-example ", " -->") {
        let (json, after) = between(after, "```json\n", "\n```").expect("JSON block");
        let (hexs, after) = between(after, "```hex\n", "\n```").expect("hex block");
        let spec: Value = serde_json::from_str(json).expect("example JSON");
        assert_eq!(spec["id"], id, "example id");
        out.push(Example {
            id: id.to_string(),
            record: spec["record"].clone(),
            bytes: hex(&hexs.replace('\n', "")),
        });
        rest = after;
    }
    out
}

fn key_vectors() -> BTreeMap<String, String> {
    let text = read("WIRE_EXAMPLES.md");
    let (table, _) = between(&text, "<!-- zmux-keys -->\n", "\n\n").expect("key vectors");
    table
        .lines()
        .filter_map(|l| {
            let l = l.strip_prefix("| ")?.strip_suffix("` |")?;
            let (k, v) = l.split_once(" | `")?;
            Some((k.to_string(), v.to_string()))
        })
        .collect()
}

#[test]
fn examples_round_trip() {
    let all = examples();
    assert!(all.len() >= 20, "only {} examples", all.len());
    for ex in &all {
        let id = ex.id.as_str();
        let specs: Vec<FrameSpec> = serde_json::from_value(ex.record.clone()).unwrap();
        let built = wire::encode_record(&specs, &no_placeholders);
        assert_eq!(to_hex(&built), to_hex(&ex.bytes), "{id}: JSON encoding");
        let expected = normalise(ex.record.as_array().unwrap());
        for chunk in [ex.bytes.len(), 1, 5] {
            let (records, positions) = read_records(&ex.bytes, 65_535, Gates::ALL, chunk)
                .unwrap_or_else(|e| panic!("{id}: {e}"));
            assert_eq!(records.len(), 1, "{id}: one record");
            assert_eq!(positions, [ex.bytes.len() as u64], "{id}: position");
            json_subset(
                &Value::Array(expected.clone()),
                &Value::Array(records[0].clone()),
                id,
            )
            .unwrap();
        }
    }
    eprintln!("wire examples: {} records", all.len());
}

fn example(id: &str) -> Vec<u8> {
    examples()
        .into_iter()
        .find(|e| e.id == id)
        .unwrap_or_else(|| panic!("example {id} missing"))
        .bytes
}

/// The frames of a single-record example.
fn body(bytes: &[u8]) -> &[u8] {
    let (size, width) = zmux::proto::varint::decode(bytes).unwrap();
    assert_eq!(bytes.len(), width + size as usize);
    &bytes[width..]
}

#[test]
fn examples_semantics() {
    // 1.1: the default parameters with GREASE 31 * 3 + 27 encode canonically.
    let tp_bytes = example("tp-zmux-default");
    let Frame::TransportParameters(f) = Frame::decode(body(&tp_bytes), &Gates::ALL).unwrap().0
    else {
        panic!("tp-zmux-default: not QX_TRANSPORT_PARAMETERS");
    };
    let tp = f.parameters().unwrap();
    assert!(!tp.is_plain_qmux());
    let mut buf = [0u8; 256];
    let grease = Grease {
        id: 120,
        value: &[0x9a, 0x7b],
    };
    let n = tp.encode_frame(Some(grease), &mut buf).unwrap();
    assert_eq!(&buf[..n], body(&tp_bytes));

    // 1.2: a plain QMux peer.
    let plain = example("tp-qmux-plain");
    let Frame::TransportParameters(f) = Frame::decode(body(&plain), &Gates::ALL).unwrap().0 else {
        panic!("tp-qmux-plain");
    };
    assert!(f.parameters().unwrap().is_plain_qmux());

    // 2.1: the preamble of a new stream.
    let open = example("stream-open-preamble");
    let Frame::Stream(s) = Frame::decode(body(&open), &Gates::ALL).unwrap().0 else {
        panic!("stream-open-preamble");
    };
    let (preamble, size) = WirePreamble::parse(s.data, 4096).unwrap();
    assert_eq!(preamble.open_info, Some(&b"example.com:443"[..]));
    assert_eq!(preamble.priority.map(|p| p.urgency()), Some(1));
    assert_eq!(&s.data[size..], b"hello");

    // 3.3 and 3.4: datagram flow prefixes.
    for (id, flow, payload) in [
        (
            "datagram-flow",
            Flow::Stream {
                stream_id: 4,
                context: 0,
            },
            &b"udp-payload"[..],
        ),
        ("datagram-session", Flow::Session, &b"ping"[..]),
    ] {
        let bytes = example(id);
        let Frame::Datagram(d) = Frame::decode(body(&bytes), &Gates::ALL).unwrap().0 else {
            panic!("{id}");
        };
        assert_eq!(Flow::parse(d.data).unwrap(), (flow, payload), "{id}");
    }
}

#[test]
fn key_schedule_vectors() {
    let v = key_vectors();
    let get = |k: &str| hex(v.get(k).unwrap_or_else(|| panic!("key vector {k} missing")));
    let psk_key = v
        .keys()
        .find(|k| k.starts_with("PSK"))
        .expect("PSK row")
        .clone();
    let ni: [u8; 16] = get("initiator Session Nonce").try_into().unwrap();
    let nr: [u8; 16] = get("responder Session Nonce").try_into().unwrap();
    let secret = keys::session_secret(&ni, &nr, &[], &get(&psk_key));
    assert_eq!(to_hex(&secret), v["session_secret"]);
    let one = zmux::proto::seal::SessionCrypto {
        suites: vec![1],
        groups: vec![2],
    };
    let encoded = zmux::proto::seal::session_crypto(&one, &one).unwrap();
    assert_eq!(
        to_hex(&encoded),
        v["session_crypto (Suite 1, Group 2 at each end)"]
    );
    let suite = zmux::proto::seal::Suite::from_value(1).unwrap();
    for (role, row) in [
        (
            zmux::proto::seal::JoinRole::Initiator,
            "join_psk_i, epoch 0, Suite 1",
        ),
        (
            zmux::proto::seal::JoinRole::Responder,
            "join_psk_r, epoch 0, Suite 1",
        ),
    ] {
        let psk = zmux::proto::seal::derive_join_psk(suite, &secret, role, &encoded).unwrap();
        assert_eq!(to_hex(&psk), v[row]);
    }
}

#[test]
fn foreign_prefixes_rejected_at_the_byte_shown() {
    let text = read("WIRE_EXAMPLES.md");
    let (_, section) = text
        .split_once("## 7. First bytes of foreign protocols")
        .expect("section 7");
    let mut rows = 0;
    for line in section.lines() {
        let cells: Vec<&str> = line.split('|').map(str::trim).collect();
        let [_, _, bytes, at, _] = cells.as_slice() else {
            continue;
        };
        let Some(bytes) = bytes.strip_prefix('`').and_then(|b| b.strip_suffix('`')) else {
            continue;
        };
        let bytes = hex(&bytes.replace(' ', ""));
        let at: u64 = at.parse().expect("byte number");
        let mut c = Classifier::bootstrap(65_535);
        // Feed one byte at a time: the verdict is decided by byte `at`.
        for (i, b) in bytes.iter().enumerate() {
            let v = c.push(&[*b]);
            if (i as u64) + 1 < at {
                assert_eq!(v, Verdict::NeedMore, "{line}");
            }
        }
        assert_eq!(c.verdict(), Verdict::Reject { at }, "{line}");
        rows += 1;
    }
    assert!(rows >= 4, "foreign prefix table not found");
}

#[test]
fn transport_parameters_from_profiles_validate() {
    let profiles: BTreeMap<String, crate::model::Profile> =
        serde_json::from_str(&read("profiles.json")).unwrap();
    for (name, p) in &profiles {
        let list: Vec<crate::model::ParamSpec> =
            p.tp.iter()
                .map(|(k, v)| crate::model::ParamSpec {
                    id: crate::model::ParamId::Name(k.clone()),
                    value: v.clone(),
                    raw: None,
                })
                .collect();
        let block = wire::param_block(&list);
        let tp =
            TransportParameters::decode(&block).unwrap_or_else(|e| panic!("profile {name}: {e}"));
        let mut buf = vec![0u8; tp.encoded_len(None)];
        tp.encode(None, &mut buf).unwrap();
        assert_eq!(
            TransportParameters::decode(&buf).unwrap(),
            tp,
            "profile {name}"
        );
    }
}
