//! Fuzz-style robustness: random and mutated inputs never make a decoder
//! panic, every error carries one of the codes the wire layer may report,
//! successful decodes re-encode consistently, and the incremental record
//! reader agrees with whole-record decoding for every split of the input.

use std::sync::LazyLock;

use proptest::prelude::*;
use zmux::proto::frame::{Frame, Frames, PipeJoin};
use zmux::proto::ident::{Classifier, Verdict};
use zmux::proto::params::TransportParameters;
use zmux::proto::payload::{Flow, WirePreamble};
use zmux::proto::record::{Event, RecordReader};
use zmux::proto::{Error, Gates, TransportErrorCode, oob, varint};

use crate::support::{hex, read, read_ndjson};

const MAX_RECORD: u64 = 65_535;

/// Valid encodings to mutate: corpus frames and records, and the wire
/// examples.
static SEEDS: LazyLock<Vec<Vec<u8>>> = LazyLock::new(|| {
    let mut seeds: Vec<Vec<u8>> = read_ndjson("wire/valid.ndjson")
        .iter()
        .filter_map(|e| e["hex"].as_str().map(hex))
        .collect();
    let text = read("WIRE_EXAMPLES.md");
    for block in text.split("```hex\n").skip(1) {
        let end = block.find("\n```").unwrap();
        seeds.push(hex(&block[..end].replace('\n', "")));
    }
    seeds
});

fn assert_wire_code(e: &Error) {
    let allowed = [
        TransportErrorCode::FRAME_ENCODING_ERROR,
        TransportErrorCode::PROTOCOL_VIOLATION,
        TransportErrorCode::TRANSPORT_PARAMETER_ERROR,
    ];
    assert!(allowed.contains(&e.code()), "unexpected error {e}");
}

fn gates_from(bits: u8) -> Gates {
    Gates {
        reset_stream_at: bits & 1 != 0,
        max_datagram_frame_size: match bits >> 5 {
            0 => 0,
            1 => 8,
            2 => 1200,
            _ => u64::MAX,
        },
        goaway: bits & 2 != 0,
        priority: bits & 4 != 0,
        multipath: bits & 8 != 0,
        pipe_ack: bits & 16 != 0,
        // Lanes go with either acknowledgement feature.
        lanes: bits & 24 != 0 && bits & 1 != 0,
    }
}

#[derive(Debug, Clone)]
enum Mutation {
    Flip(usize, u8),
    Set(usize, u8),
    Insert(usize, u8),
    Remove(usize),
    Truncate(usize),
}

fn mutation() -> impl Strategy<Value = Mutation> {
    prop_oneof![
        (any::<usize>(), 0u8..8).prop_map(|(i, b)| Mutation::Flip(i, b)),
        (any::<usize>(), any::<u8>()).prop_map(|(i, b)| Mutation::Set(i, b)),
        (any::<usize>(), any::<u8>()).prop_map(|(i, b)| Mutation::Insert(i, b)),
        any::<usize>().prop_map(Mutation::Remove),
        any::<usize>().prop_map(Mutation::Truncate),
    ]
}

fn mutate(mut bytes: Vec<u8>, mutations: &[Mutation]) -> Vec<u8> {
    for m in mutations {
        let len = bytes.len();
        match *m {
            Mutation::Flip(i, bit) if len > 0 => bytes[i % len] ^= 1 << bit,
            Mutation::Set(i, b) if len > 0 => bytes[i % len] = b,
            Mutation::Insert(i, b) => bytes.insert(i % (len + 1), b),
            Mutation::Remove(i) if len > 0 => {
                bytes.remove(i % len);
            }
            Mutation::Truncate(i) => bytes.truncate(i % (len + 1)),
            _ => {}
        }
    }
    bytes
}

/// Random bytes, or a mutated valid encoding.
fn input() -> impl Strategy<Value = Vec<u8>> {
    prop_oneof![
        proptest::collection::vec(any::<u8>(), 0..200),
        (
            proptest::sample::select(SEEDS.clone()),
            proptest::collection::vec(mutation(), 0..6)
        )
            .prop_map(|(seed, ms)| mutate(seed, &ms)),
    ]
}

/// Split points for feeding an input in pieces.
fn splits() -> impl Strategy<Value = Vec<usize>> {
    proptest::collection::vec(1usize..40, 0..12)
}

fn chunked<'a>(bytes: &'a [u8], sizes: &[usize]) -> Vec<&'a [u8]> {
    let mut out = Vec::new();
    let mut rest = bytes;
    for &s in sizes {
        if rest.is_empty() {
            break;
        }
        let (a, b) = rest.split_at(s.min(rest.len()));
        out.push(a);
        rest = b;
    }
    if !rest.is_empty() {
        out.push(rest);
    }
    out
}

fn check_frame_round_trip(frame: &Frame<'_>, gates: &Gates, consumed: usize) {
    let len = frame.encoded_len();
    assert!(len <= consumed, "re-encoding is longer: {frame:?}");
    let mut buf = vec![0u8; len];
    assert_eq!(frame.encode(&mut buf), Ok(len), "{frame:?}");
    let (again, n) = Frame::decode(&buf, gates).expect("re-encoded frame decodes");
    assert_eq!(n, len);
    assert_eq!(&again, frame);
    let mut buf2 = vec![0u8; len];
    again.encode(&mut buf2).unwrap();
    assert_eq!(buf, buf2, "canonical encoding is not stable");
}

/// One record stream's outcome: the frames of each complete record (as
/// normalised text) and how the input ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum End {
    Clean,
    Incomplete,
    Error(TransportErrorCode),
}

#[derive(Default)]
struct Collector {
    records: Vec<Vec<String>>,
    current: Vec<String>,
}

impl Collector {
    fn frame(&mut self, f: &Frame<'_>) {
        match f {
            Frame::Padding(p) => self.padding(p.len),
            other => self.current.push(format!("{other:?}")),
        }
    }

    fn padding(&mut self, n: usize) {
        if let Some(last) = self.current.last_mut()
            && let Some(prev) = last.strip_prefix("PADDING ")
        {
            *last = format!("PADDING {}", prev.parse::<usize>().unwrap() + n);
            return;
        }
        self.current.push(format!("PADDING {n}"));
    }

    fn end_record(&mut self) {
        self.records.push(std::mem::take(&mut self.current));
    }
}

/// Whole-record reference: Size, then the Frames iterator over the body.
fn reference(bytes: &[u8], gates: &Gates) -> (Vec<Vec<String>>, End) {
    let mut c = Collector::default();
    let mut rest = bytes;
    loop {
        if rest.is_empty() {
            return (c.records, End::Clean);
        }
        let Some((size, width)) = varint::decode(rest) else {
            return (c.records, End::Incomplete);
        };
        if size == 0 || size > MAX_RECORD {
            return (
                c.records,
                End::Error(TransportErrorCode::FRAME_ENCODING_ERROR),
            );
        }
        let Some(body) = rest.get(width..width + size as usize) else {
            return (c.records, End::Incomplete);
        };
        for f in Frames::new(body, *gates) {
            match f {
                Ok(f) => c.frame(&f),
                Err(e) => {
                    assert_wire_code(&e);
                    return (c.records, End::Error(e.code()));
                }
            }
        }
        c.end_record();
        rest = &rest[width + size as usize..];
    }
}

fn collect_events(
    c: &mut Collector,
    reader: &mut RecordReader,
    input: &mut &[u8],
    gates: &Gates,
    retain: bool,
    last_position: &mut u64,
) -> Result<(), Error> {
    loop {
        let event = if retain {
            reader.read_complete(input, gates)
        } else {
            reader.read(input, gates)
        };
        match event {
            Ok(Some(Event::Frame(f))) => c.frame(&f),
            Ok(Some(Event::RecordEnd { len })) => {
                assert_eq!(reader.position(), *last_position + len);
                *last_position = reader.position();
                c.end_record();
            }
            Ok(None) => return Ok(()),
            Err(e) => {
                assert_wire_code(&e);
                // The reader stays failed.
                assert_eq!(reader.read(input, gates), Err(e));
                return Err(e);
            }
        }
    }
}

/// Feeds the pieces to `read`, which consumes everything.
fn incremental(bytes: &[u8], sizes: &[usize], gates: &Gates) -> (Vec<Vec<String>>, End) {
    let mut c = Collector::default();
    let mut reader = RecordReader::new(MAX_RECORD);
    let mut position = 0;
    for piece in chunked(bytes, sizes) {
        let mut input = piece;
        if let Err(e) = collect_events(&mut c, &mut reader, &mut input, gates, false, &mut position)
        {
            return (c.records, End::Error(e.code()));
        }
        assert!(input.is_empty(), "read left input unconsumed");
    }
    let end = if reader.at_record_boundary() {
        End::Clean
    } else {
        End::Incomplete
    };
    (c.records, end)
}

/// Feeds the pieces like a driver with its own buffer: `read_complete`
/// leaves incomplete records in the buffer, which grows with each read.
fn retaining(bytes: &[u8], sizes: &[usize], gates: &Gates) -> (Vec<Vec<String>>, End) {
    let mut c = Collector::default();
    let mut reader = RecordReader::new(MAX_RECORD);
    let mut position = 0;
    let mut buffer: Vec<u8> = Vec::new();
    for piece in chunked(bytes, sizes) {
        buffer.extend_from_slice(piece);
        let mut input = buffer.as_slice();
        if let Err(e) = collect_events(&mut c, &mut reader, &mut input, gates, true, &mut position)
        {
            return (c.records, End::Error(e.code()));
        }
        let consumed = buffer.len() - input.len();
        buffer.drain(..consumed);
    }
    let end = if buffer.is_empty() && reader.at_record_boundary() {
        End::Clean
    } else {
        End::Incomplete
    };
    (c.records, end)
}

proptest! {
    #![proptest_config(ProptestConfig {
        // PROPTEST_CASES raises the count for longer runs.
        cases: std::env::var("PROPTEST_CASES")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(3000),
        failure_persistence: None,
        ..ProptestConfig::default()
    })]

    #[test]
    fn frame_decoder_never_panics(bytes in input(), bits in any::<u8>()) {
        let gates = gates_from(bits);
        match Frame::decode(&bytes, &gates) {
            Ok((frame, n)) => {
                prop_assert!(n > 0 && n <= bytes.len());
                check_frame_round_trip(&frame, &gates, n);
            }
            Err(e) => assert_wire_code(&e),
        }
        for f in Frames::new(&bytes, gates) {
            match f {
                Ok(f) => check_frame_round_trip(&f, &gates, f.encoded_len()),
                Err(e) => assert_wire_code(&e),
            }
        }
    }

    #[test]
    fn record_reader_matches_whole_record_decoding(
        bytes in input(),
        sizes in splits(),
        bits in any::<u8>(),
    ) {
        let gates = gates_from(bits);
        let want = reference(&bytes, &gates);
        // Records are released only when complete, so every split of the
        // input gives exactly the whole-record result, in both modes.
        prop_assert_eq!(&incremental(&bytes, &sizes, &gates), &want);
        prop_assert_eq!(&retaining(&bytes, &sizes, &gates), &want);
    }

    #[test]
    fn transport_parameters_never_panic(bytes in input()) {
        // Parse both the raw bytes and, when they are a parameters frame,
        // its block.
        for block in [&bytes[..], bytes.get(10..).unwrap_or_default()] {
            match TransportParameters::decode(block) {
                Ok(tp) => {
                    let mut buf = vec![0u8; tp.encoded_len(None)];
                    tp.encode(None, &mut buf).unwrap();
                    prop_assert_eq!(TransportParameters::decode(&buf).unwrap(), tp);
                }
                Err(e) => {
                    prop_assert_eq!(e.code(), TransportErrorCode::TRANSPORT_PARAMETER_ERROR);
                }
            }
        }
    }

    #[test]
    fn payload_parsers_never_panic(bytes in input(), limit in 0u64..5000) {
        match WirePreamble::parse(&bytes, limit) {
            Ok((p, size)) => {
                prop_assert!(size <= bytes.len() && size as u64 <= limit);
                let _ = p;
            }
            Err(e) => prop_assert_eq!(e.code(), TransportErrorCode::PROTOCOL_VIOLATION),
        }
        match Flow::parse(&bytes) {
            Ok((flow, payload)) => {
                prop_assert!(flow.encoded_len() + payload.len() <= bytes.len());
            }
            Err(e) => prop_assert_eq!(e.code(), TransportErrorCode::PROTOCOL_VIOLATION),
        }
        match PipeJoin::decode(&bytes) {
            Ok((join, n)) => {
                prop_assert!(n <= bytes.len() && join.encoded_len() <= n);
            }
            Err(e) => prop_assert_eq!(e.code(), TransportErrorCode::FRAME_ENCODING_ERROR),
        }
        let mut out = [0u8; 256];
        let _ = oob::decode(&bytes, &mut out);
    }

    #[test]
    fn classifier_does_not_depend_on_splits(
        bytes in input(),
        sizes in splits(),
        sessions in any::<bool>(),
        joins in any::<bool>(),
    ) {
        let mut whole = Classifier::new(MAX_RECORD, sessions, joins);
        let want = whole.push(&bytes);
        let mut split = Classifier::new(MAX_RECORD, sessions, joins);
        for piece in chunked(&bytes, &sizes) {
            split.push(piece);
        }
        prop_assert_eq!(split.verdict(), want);
        if let Verdict::Reject { at } = want {
            prop_assert!(at >= 1 && at <= bytes.len() as u64 && at <= 16);
        }
        if bytes.len() >= 16 {
            prop_assert!(want != Verdict::NeedMore);
        }
    }
}
