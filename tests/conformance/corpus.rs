//! The wire corpus (CONFORMANCE.md Section 5): every valid case round-trips
//! byte for byte and every invalid case fails with exactly its error.

use serde_json::Value;
use zmux::proto::record::{Event, Framing, RecordReader};
use zmux::proto::{Error, Frame, Gates};

use crate::model::FrameSpec;
use crate::support::{hex, read_ndjson, to_hex};
use crate::wire::{self, json_subset, no_placeholders, normalise};

/// The gates of a corpus entry (the `gates` list of parameter names).
pub fn gates_of(entry: &Value) -> Gates {
    let mut g = Gates::NONE;
    for name in entry["gates"].as_array().expect("gates") {
        match name.as_str().expect("gate name") {
            "reset_stream_at" => g.reset_stream_at = true,
            "max_datagram_frame_size" => g.max_datagram_frame_size = u64::MAX,
            "zmux_goaway" => g.goaway = true,
            "zmux_priority" => g.priority = true,
            "zmux_multipath" => g.multipath = true,
            "zmux_pipe_ack" => g.pipe_ack = true,
            "zmux_max_lanes" => g.lanes = true,
            other => panic!("unknown gate {other}"),
        }
    }
    // Sized gates: the receiver's announced limits.
    if let Some(m) = entry
        .get("limits")
        .and_then(|l| l.get("max_datagram_frame_size"))
    {
        g.max_datagram_frame_size = m.as_u64().expect("limit");
    }
    g
}

fn max_record_size(entry: &Value) -> u64 {
    entry
        .get("max_record_size")
        .and_then(Value::as_u64)
        .unwrap_or(65_535)
}

/// Feeds `bytes` to a record reader in chunks of `chunk` bytes and collects
/// the records as JSON frame lists plus the position after each record.
pub fn read_records(
    bytes: &[u8],
    max_record_size: u64,
    gates: Gates,
    chunk: usize,
) -> Result<(Vec<Vec<Value>>, Vec<u64>), Error> {
    let mut reader = RecordReader::new(max_record_size);
    let mut records = Vec::new();
    let mut positions = Vec::new();
    let mut current = Vec::new();
    for piece in bytes.chunks(chunk.max(1)) {
        let mut input = piece;
        while let Some(event) = reader.read(&mut input, &gates)? {
            match event {
                Event::RecordEnd { .. } => {
                    records.push(normalise(&std::mem::take(&mut current)));
                    positions.push(reader.position());
                }
                Event::Frame(f) => current.push(wire::frame_json(&f)),
            }
        }
        assert!(input.is_empty());
    }
    assert!(reader.at_record_boundary(), "input ended inside a record");
    Ok((records, positions))
}

/// Feeds messages to a message-framed reader; returns the frames of each
/// message and the position after it.
pub fn read_messages(
    messages: &[Vec<u8>],
    max_record_size: u64,
    gates: Gates,
) -> Result<(Vec<Vec<Value>>, Vec<u64>), Error> {
    let mut reader = RecordReader::with_framing(max_record_size, Framing::Records);
    let mut records = Vec::new();
    let mut positions = Vec::new();
    for m in messages {
        reader.begin_message(m.len())?;
        let mut input = m.as_slice();
        let mut current = Vec::new();
        let mut ended = false;
        while let Some(event) = reader.read(&mut input, &gates)? {
            match event {
                Event::RecordEnd { .. } => ended = true,
                Event::Frame(f) => current.push(wire::frame_json(&f)),
            }
        }
        assert!(
            ended && input.is_empty(),
            "message not consumed as one record"
        );
        records.push(normalise(&current));
        positions.push(reader.position());
    }
    Ok((records, positions))
}

fn frames_of(value: &Value) -> Vec<Value> {
    value.as_array().expect("frame list").clone()
}

fn check_record_lists(id: &str, expected: &[Value], got: &[Vec<Value>]) {
    assert_eq!(got.len(), expected.len(), "{id}: record count");
    for (e, g) in expected.iter().zip(got) {
        let e = normalise(&frames_of(e));
        json_subset(&Value::Array(e), &Value::Array(g.clone()), id).unwrap();
    }
}

#[test]
fn valid_cases_round_trip() {
    let entries = read_ndjson("wire/valid.ndjson");
    let mut counts = [0usize; 3];
    for e in &entries {
        let id = e["id"].as_str().unwrap();
        let gates = gates_of(e);
        match e["kind"].as_str().unwrap() {
            "frame" => {
                let bytes = hex(e["hex"].as_str().unwrap());
                let (frame, n) = Frame::decode(&bytes, &gates)
                    .unwrap_or_else(|err| panic!("{id}: rejected: {err}"));
                assert_eq!(n, bytes.len(), "{id}: trailing bytes");
                json_subset(&e["frame"], &wire::frame_json(&frame), id).unwrap();
                let mut again = Vec::new();
                wire::push(&mut again, &frame);
                let spec: FrameSpec = serde_json::from_value(e["frame"].clone()).unwrap();
                let built = wire::encode_frames(&[spec], &no_placeholders);
                if e.get("non_minimal") == Some(&Value::Bool(true)) {
                    // Re-encoding is minimal: compare meaning, not bytes
                    // (CONFORMANCE.md).
                    for (what, enc) in [("re-encoding", &again), ("JSON encoding", &built)] {
                        let (f, _) = Frame::decode(enc, &gates).unwrap();
                        assert_eq!(
                            wire::frame_json(&f),
                            wire::frame_json(&frame),
                            "{id}: {what}"
                        );
                        assert!(enc.len() < bytes.len(), "{id}: {what} is not shorter");
                    }
                } else {
                    assert_eq!(to_hex(&again), to_hex(&bytes), "{id}: re-encoding");
                    assert_eq!(to_hex(&built), to_hex(&bytes), "{id}: JSON encoding");
                }
                counts[0] += 1;
            }
            "record" => {
                let bytes = hex(e["hex"].as_str().unwrap());
                let expected = [e["record"].clone()];
                for chunk in [bytes.len(), 1, 2, 7] {
                    let (records, _) = read_records(&bytes, max_record_size(e), gates, chunk)
                        .unwrap_or_else(|err| panic!("{id}: rejected: {err}"));
                    check_record_lists(id, &expected, &records);
                }
                let specs: Vec<FrameSpec> = serde_json::from_value(e["record"].clone()).unwrap();
                let built = wire::encode_record(&specs, &no_placeholders);
                assert_eq!(to_hex(&built), to_hex(&bytes), "{id}: JSON encoding");
                // The one-shot decoder re-encodes every record exactly.
                let mut rest = bytes.as_slice();
                let mut again = Vec::new();
                while let Some((size, width)) = zmux::proto::varint::decode(rest) {
                    let (head, tail) = rest.split_at(width + size as usize);
                    again.extend_from_slice(&head[..width]);
                    for f in zmux::proto::Frames::new(&head[width..], gates) {
                        wire::push(&mut again, &f.unwrap());
                    }
                    rest = tail;
                }
                assert_eq!(to_hex(&again), to_hex(&bytes), "{id}: record re-encoding");
                counts[1] += 1;
            }
            "messages" => {
                let messages: Vec<Vec<u8>> = e["messages"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|m| hex(m.as_str().unwrap()))
                    .collect();
                let (records, positions) = read_messages(&messages, max_record_size(e), gates)
                    .unwrap_or_else(|err| panic!("{id}: rejected: {err}"));
                let expected: Vec<u64> = e["positions"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|p| p.as_u64().unwrap())
                    .collect();
                let mut cumulative = 0;
                for (pos, want) in positions.iter().zip(&expected) {
                    cumulative += want;
                    assert_eq!(*pos, cumulative, "{id}: position");
                }
                for (m, frames) in messages.iter().zip(&records) {
                    let decoded = wire::decode_body(m, gates).unwrap();
                    assert_eq!(
                        &normalise(&decoded),
                        frames,
                        "{id}: reader and decoder agree"
                    );
                    let mut again = Vec::new();
                    for f in zmux::proto::Frames::new(m, gates) {
                        wire::push(&mut again, &f.unwrap());
                    }
                    assert_eq!(&again, m, "{id}: message re-encoding");
                }
                counts[2] += 1;
            }
            other => panic!("{id}: unknown kind {other}"),
        }
    }
    eprintln!(
        "valid corpus: {} cases ({} frames, {} records, {} message sets)",
        entries.len(),
        counts[0],
        counts[1],
        counts[2]
    );
    assert_eq!(counts.iter().sum::<usize>(), entries.len());
}

#[test]
fn invalid_cases_fail_with_their_error() {
    let entries = read_ndjson("wire/invalid.ndjson");
    for e in &entries {
        let id = e["id"].as_str().unwrap();
        let gates = gates_of(e);
        let want = e["error"].as_str().unwrap();
        let errors: Vec<Error> = match e["kind"].as_str().unwrap() {
            "frame" => {
                let bytes = hex(e["hex"].as_str().unwrap());
                vec![Frame::decode(&bytes, &gates).expect_err(id)]
            }
            "record" => {
                let bytes = hex(e["hex"].as_str().unwrap());
                [bytes.len(), 1, 3]
                    .into_iter()
                    .map(|chunk| {
                        read_records(&bytes, max_record_size(e), gates, chunk).expect_err(id)
                    })
                    .collect()
            }
            "messages" => {
                let messages: Vec<Vec<u8>> = e["messages"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|m| hex(m.as_str().unwrap()))
                    .collect();
                vec![read_messages(&messages, max_record_size(e), gates).expect_err(id)]
            }
            other => panic!("{id}: unknown kind {other}"),
        };
        for err in errors {
            assert_eq!(err.code().name(), Some(want), "{id}: got {err}");
        }
    }
    eprintln!("invalid corpus: {} cases", entries.len());
}
