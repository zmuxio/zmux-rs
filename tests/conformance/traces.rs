//! Executable traces (TRACES.md): every trace loads into the typed model,
//! and every byte string in them decodes with the codec. Running the traces
//! against a session needs the sans-IO core.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::Path;

use serde_json::Value;
use zmux::proto::frame::PipeJoin;
use zmux::proto::ident::{Classifier, Verdict};
use zmux::proto::record::{Event, RecordReader};
use zmux::proto::{Gates, TransportErrorCode};

use crate::corpus::{read_messages, read_records};
use crate::model::{
    Call, CodeRef, ErrorSpace, FrameSpec, FramingName, Hex, Op, Profile, Step, StreamRef, Trace,
    TypePattern, Via, parse_trace,
};
use crate::support::{read, read_json, spec_dir, to_hex};
use crate::wire::{self, json_subset, normalise};

/// Every trace listed in index.json, parsed.
pub fn load_all() -> Vec<(String, Trace)> {
    let index = read_json("traces/index.json");
    index["traces"]
        .as_array()
        .expect("traces")
        .iter()
        .map(|t| {
            let file = t["file"].as_str().unwrap();
            let rel = file.strip_prefix("fixtures/").expect("fixtures/ path");
            let trace = parse_trace(&read(rel)).unwrap_or_else(|e| panic!("{file}: {e}"));
            (rel.to_string(), trace)
        })
        .collect()
}

fn collect_files(dir: &Path, out: &mut BTreeSet<String>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            collect_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "ndjson") {
            let rel = path.strip_prefix(spec_dir()).unwrap();
            out.insert(rel.to_string_lossy().replace('\\', "/"));
        }
    }
}

fn frame_names() -> BTreeSet<String> {
    let reg = read_json("registry.json");
    reg["frame_types"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["name"].as_str().unwrap().to_string())
        .chain(["STREAM_DATA", "RAW", "REPEAT", "*"].map(String::from))
        .collect()
}

#[test]
fn traces_load_into_the_typed_model() {
    let index = read_json("traces/index.json");
    let entries = index["traces"].as_array().unwrap();
    let profiles: BTreeMap<String, Profile> =
        serde_json::from_str(&read("profiles.json")).expect("profiles.json");
    let traces = load_all();
    let mut listed = BTreeSet::new();
    let mut steps = 0usize;
    for ((rel, trace), entry) in traces.iter().zip(entries) {
        let h = &trace.header;
        listed.insert(rel.clone());
        let id = rel
            .strip_prefix("traces/")
            .and_then(|r| r.strip_suffix(".ndjson"))
            .unwrap()
            .replace('/', ".");
        assert_eq!(h.id, id, "{rel}: id");
        assert_eq!(entry["id"], h.id.as_str());
        assert!(
            profiles.contains_key(&h.profile),
            "{rel}: profile {}",
            h.profile
        );
        assert_eq!(
            entry["steps"].as_u64(),
            Some(trace.steps.len() as u64),
            "{rel}: step count"
        );
        for (i, s) in trace.steps.iter().enumerate() {
            assert_eq!(s.number as usize, i + 1, "{rel}: step numbering");
        }
        steps += trace.steps.len();
        check_references(rel, trace);
    }
    let mut files = BTreeSet::new();
    collect_files(&spec_dir().join("traces"), &mut files);
    assert_eq!(files, listed, "index.json and the trace files differ");
    eprintln!("traces: {} files, {} steps", traces.len(), steps);
}

/// Stream handles, frame names, error names and pipe/carrier fields.
fn check_references(rel: &str, trace: &Trace) {
    let names = frame_names();
    let mut handles = BTreeSet::new();
    for step in &trace.steps {
        let n = step.number;
        match &step.op {
            Op::PipeUp { pipe, carrier, .. } | Op::PeerSend { pipe, carrier, .. } => {
                assert!(
                    pipe.is_some() != carrier.is_some(),
                    "{rel} step {n}: exactly one of pipe and carrier"
                );
            }
            Op::Api(api) => {
                let stream = match &api.call {
                    Call::Write(a) => Some(&a.stream),
                    Call::StreamId(a)
                    | Call::SetReliableBoundary(a)
                    | Call::Finish(a)
                    | Call::Release(a)
                    | Call::Reject(a) => Some(&a.stream),
                    Call::Reset(a) | Call::Stop(a) => Some(&a.stream),
                    Call::Read(a) => Some(&a.stream),
                    Call::SetPriority(a) | Call::SetPeerPriority(a) => Some(&a.stream),
                    Call::SendDatagram(a) => a.stream.as_ref(),
                    Call::RecvDatagram(a) => a.stream.as_ref(),
                    _ => None,
                };
                if let Some(StreamRef::Handle(h)) = stream {
                    assert!(handles.contains(h), "{rel} step {n}: unbound handle {h}");
                }
                if let Call::Write(w) = &api.call {
                    assert!(
                        w.data.is_some() != w.fill.is_some(),
                        "{rel} step {n}: write needs data or fill"
                    );
                }
                if let Some(b) = &api.bind {
                    handles.insert(b.clone());
                }
            }
            Op::ExpectFrames { frames, .. } => {
                for p in frames {
                    let types: Vec<&String> = match &p.ty {
                        TypePattern::Name(t) => vec![t],
                        TypePattern::OneOf(o) => o.oneof.iter().collect(),
                    };
                    for t in types {
                        assert!(names.contains(t.as_str()), "{rel} step {n}: frame type {t}");
                    }
                }
            }
            Op::ExpectNoFrames { types: Some(t), .. } => {
                for t in t {
                    assert!(names.contains(t.as_str()), "{rel} step {n}: frame type {t}");
                }
            }
            Op::ExpectClose { error, .. } => match (error.space, &error.code) {
                (ErrorSpace::Transport, CodeRef::Name(name)) => assert!(
                    zmux::proto::error::TRANSPORT_ERRORS
                        .iter()
                        .any(|(_, n, _)| n == name),
                    "{rel} step {n}: transport error {name}"
                ),
                (ErrorSpace::Application, CodeRef::Value(_)) => {}
                (ErrorSpace::Local, CodeRef::Name(name)) => assert!(
                    [
                        "HANDSHAKE_TIMEOUT",
                        "IDLE_TIMEOUT",
                        "PIPES_LOST",
                        "EARLY_DATA_REJECTED"
                    ]
                    .contains(&name.as_str()),
                    "{rel} step {n}: local reason {name}"
                ),
                other => panic!("{rel} step {n}: bad close error {other:?}"),
            },
            _ => {}
        }
    }
}

/// The inbound side of one carrier as the trace feeds it.
struct Inbound {
    bootstrap: bool,
    reader: Option<RecordReader>,
    classifier: Classifier,
}

impl Inbound {
    fn new(bootstrap: bool) -> Self {
        Self {
            bootstrap,
            reader: Some(RecordReader::new(65_535)),
            classifier: Classifier::new(65_535, true, !bootstrap),
        }
    }
}

#[derive(Default)]
struct Totals {
    blobs: usize,
    compared: usize,
    messages: usize,
    joins: usize,
}

#[test]
fn trace_bytes_decode() {
    let mut totals = Totals::default();
    for (rel, trace) in load_all() {
        check_trace_bytes(&rel, &trace, &mut totals);
    }
    eprintln!(
        "trace bytes: {} peer_send blobs, {} decoded and compared with their records, \
         {} messages, {} PIPE_JOIN frames",
        totals.blobs, totals.compared, totals.messages, totals.joins
    );
    assert!(totals.compared > 500);
}

fn carrier_key(pipe: Option<u64>, carrier: Option<&str>) -> String {
    match (pipe, carrier) {
        (Some(p), _) => format!("pipe {p}"),
        (_, Some(c)) => format!("carrier {c}"),
        _ => unreachable!(),
    }
}

fn check_trace_bytes(rel: &str, trace: &Trace, totals: &mut Totals) {
    let mut inbound: HashMap<String, Inbound> = HashMap::new();
    let mut aliases: HashMap<String, String> = HashMap::new();
    let mut expects_violation = false;
    for step in &trace.steps {
        let n = step.number;
        let at = format!("{rel} step {n}");
        match &step.op {
            Op::PipeUp {
                pipe,
                carrier,
                via,
                framing,
                oob_join,
                ..
            } => {
                let key = carrier_key(*pipe, carrier.as_deref());
                if let Some(join) = oob_join {
                    let (frame, len) =
                        PipeJoin::decode(&join.0).unwrap_or_else(|e| panic!("{at}: oob_join: {e}"));
                    assert_eq!(len, join.0.len(), "{at}: oob_join length");
                    aliases.insert(carrier_key(Some(frame.pipe_id), None), key.clone());
                    totals.joins += 1;
                }
                if *framing != Some(FramingName::Records) {
                    let bootstrap = matches!(via, None | Some(Via::Bootstrap));
                    inbound.insert(key, Inbound::new(bootstrap));
                }
            }
            Op::PeerSend {
                pipe,
                carrier,
                records,
                hex,
                messages,
                messages_hex,
                chunks,
                invalid,
            } => {
                if messages.is_some() || messages_hex.is_some() {
                    check_messages(&at, step, messages_hex.as_deref(), totals);
                    continue;
                }
                let mut key = carrier_key(*pipe, carrier.as_deref());
                if let Some(alias) = aliases.get(&key) {
                    key = alias.clone();
                }
                let state = inbound
                    .entry(key.clone())
                    .or_insert_with(|| Inbound::new(false));
                let raw = records
                    .as_ref()
                    .is_some_and(|r| r.iter().flatten().any(FrameSpec::has_raw));
                let placeholder = records
                    .as_ref()
                    .is_some_and(|r| r.iter().flatten().any(FrameSpec::has_placeholder));
                let bytes: Vec<u8> = match (records, hex) {
                    (Some(recs), Some(hex)) => {
                        let encoded: Vec<u8> = recs
                            .iter()
                            .flat_map(|r| wire::encode_record(r, &wire::no_placeholders))
                            .collect();
                        assert_eq!(
                            to_hex(&encoded),
                            to_hex(&hex.0),
                            "{at}: hex does not match records"
                        );
                        encoded
                    }
                    (Some(recs), None) => {
                        assert!(placeholder, "{at}: records without hex need a placeholder");
                        // The positions are the runner's to fill in.
                        recs.iter()
                            .flat_map(|r| wire::encode_record(r, &|_, _| PLACEHOLDER_SENT))
                            .collect()
                    }
                    (None, Some(hex)) => hex.0.clone(),
                    (None, None) => panic!("{at}: peer_send without bytes"),
                };
                totals.blobs += 1;
                if let Some(chunks) = chunks {
                    assert_eq!(chunks.iter().sum::<usize>(), bytes.len(), "{at}: chunks");
                }
                if state.bootstrap
                    && matches!(state.classifier.push(&bytes), Verdict::Reject { .. })
                {
                    expects_violation = true;
                }
                let checkable = records.is_some() && !raw && !*invalid;
                let Some(reader) = state.reader.as_mut() else {
                    continue;
                };
                match feed(reader, &bytes, chunks.as_deref()) {
                    Ok(got) => {
                        for record in &got {
                            if let Some(first) = record.first()
                                && first["type"] == "PIPE_JOIN"
                            {
                                let id = first["pipe"].as_u64().unwrap();
                                aliases.insert(carrier_key(Some(id), None), key.clone());
                            }
                        }
                        if checkable {
                            let mut raw_records = step.raw["records"].clone();
                            resolve_placeholders(&mut raw_records, PLACEHOLDER_SENT);
                            let expected: Vec<Value> = raw_records
                                .as_array()
                                .unwrap()
                                .iter()
                                .map(|r| Value::Array(normalise(r.as_array().unwrap())))
                                .collect();
                            let got = Value::Array(got.into_iter().map(Value::Array).collect());
                            json_subset(&Value::Array(expected), &got, &at).unwrap();
                            // Whole-input decoding agrees with the chunked one.
                            read_records(&bytes, 65_535, Gates::ALL, bytes.len())
                                .unwrap_or_else(|e| panic!("{at}: {e}"));
                            totals.compared += 1;
                        }
                    }
                    Err(e) => {
                        assert!(!checkable, "{at}: valid records rejected by the codec: {e}");
                        state.reader = None;
                    }
                }
            }
            Op::ExpectClose { error, .. } => {
                let pv = TransportErrorCode::PROTOCOL_VIOLATION.name().unwrap();
                if error.space == ErrorSpace::Transport && error.code == CodeRef::Name(pv.into()) {
                    expects_violation = false;
                }
            }
            Op::ExpectEvent { fields, .. } => {
                if let Some(frame) = &fields.frame {
                    let (_, len) = PipeJoin::decode(&frame.0)
                        .unwrap_or_else(|e| panic!("{at}: event frame: {e}"));
                    assert_eq!(len, frame.0.len(), "{at}: event frame length");
                    totals.joins += 1;
                }
            }
            _ => {}
        }
    }
    assert!(
        !expects_violation,
        "{rel}: a bootstrap pipe fails the first-record check but no PROTOCOL_VIOLATION follows"
    );
}

/// The byte count the trace checks substitute for `$sent` placeholders.
const PLACEHOLDER_SENT: u64 = 1000;

/// Replaces `{"$sent": pipe, "plus": n}` with `sent + n`.
fn resolve_placeholders(v: &mut Value, sent: u64) {
    match v {
        Value::Object(o) if o.contains_key("$sent") => {
            let plus = o.get("plus").and_then(Value::as_u64).unwrap_or(0);
            *v = Value::from(sent + plus);
        }
        Value::Object(o) => o.values_mut().for_each(|x| resolve_placeholders(x, sent)),
        Value::Array(a) => a.iter_mut().for_each(|x| resolve_placeholders(x, sent)),
        _ => {}
    }
}

/// Feeds bytes in the step's chunks and returns the frames of each record
/// that ended in this step.
fn feed(
    reader: &mut RecordReader,
    bytes: &[u8],
    chunks: Option<&[usize]>,
) -> Result<Vec<Vec<Value>>, zmux::proto::Error> {
    let sizes: Vec<usize> = chunks.map_or_else(|| vec![bytes.len()], <[usize]>::to_vec);
    let mut records = Vec::new();
    let mut current: Vec<Value> = Vec::new();
    let mut rest = bytes;
    for size in sizes {
        let (mut input, tail) = rest.split_at(size.min(rest.len()));
        rest = tail;
        while let Some(event) = reader.read(&mut input, &Gates::ALL)? {
            match event {
                Event::RecordEnd { .. } => records.push(normalise(&std::mem::take(&mut current))),
                Event::Frame(f) => current.push(wire::frame_json(&f)),
            }
        }
    }
    Ok(records)
}

fn check_messages(at: &str, step: &Step, messages_hex: Option<&[Hex]>, totals: &mut Totals) {
    let specs: Option<Vec<Vec<FrameSpec>>> = step
        .raw
        .get("messages")
        .map(|m| serde_json::from_value(m.clone()).expect("messages"));
    let bytes: Vec<Vec<u8>> = match (&specs, messages_hex) {
        (Some(m), Some(h)) => {
            assert_eq!(m.len(), h.len(), "{at}: message count");
            for (frames, hex) in m.iter().zip(h) {
                let encoded = wire::encode_frames(frames, &wire::no_placeholders);
                assert_eq!(to_hex(&encoded), to_hex(&hex.0), "{at}: messages_hex");
            }
            h.iter().map(|x| x.0.clone()).collect()
        }
        (Some(m), None) => m
            .iter()
            .map(|f| wire::encode_frames(f, &wire::no_placeholders))
            .collect(),
        (None, Some(h)) => h.iter().map(|x| x.0.clone()).collect(),
        (None, None) => unreachable!(),
    };
    totals.messages += bytes.len();
    let Ok((records, _)) = read_messages(&bytes, 65_535, Gates::ALL) else {
        return;
    };
    if let Some(expected) = step.raw.get("messages").and_then(Value::as_array) {
        for (e, got) in expected.iter().zip(&records) {
            let e = normalise(e.as_array().unwrap());
            json_subset(&Value::Array(e), &Value::Array(got.clone()), at).unwrap();
        }
    }
}
