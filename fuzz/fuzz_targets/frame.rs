//! Frames and records: the decoders never panic and report only the codes
//! the wire layer may; a decoded frame re-encodes to a stable canonical
//! form; the incremental record reader gives the same frames and the same
//! end however the input is split.
//!
//! Input: one byte selecting the negotiated features, one the piece size
//! of the incremental read, then the bytes to decode.
#![no_main]

use libfuzzer_sys::fuzz_target;
use zmux::proto::frame::{Frame, Frames, Gates};
use zmux::proto::record::{Event, RecordReader};
use zmux::proto::{TransportErrorCode, varint};

const MAX_RECORD: u64 = 65_535;

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
        datagram_ack: bits & 0x20 != 0,
        lanes: bits & 0x18 != 0 && bits & 1 != 0,
    }
}

fn assert_wire_code(code: TransportErrorCode) {
    assert!(
        [
            TransportErrorCode::FRAME_ENCODING_ERROR,
            TransportErrorCode::PROTOCOL_VIOLATION,
            TransportErrorCode::TRANSPORT_PARAMETER_ERROR,
        ]
        .contains(&code),
        "unexpected error code {code:?}"
    );
}

fn check_round_trip(frame: &Frame<'_>, gates: &Gates) {
    let len = frame.encoded_len();
    let mut buf = vec![0u8; len];
    assert_eq!(frame.encode(&mut buf), Ok(len), "{frame:?}");
    let (again, n) = Frame::decode(&buf, gates).expect("a re-encoded frame decodes");
    assert_eq!(n, len);
    assert_eq!(&again, frame);
    let mut buf2 = vec![0u8; len];
    again.encode(&mut buf2).unwrap();
    assert_eq!(buf, buf2, "the canonical encoding is not stable");
}

/// The frames of the records read in pieces of `step` bytes (adjacent
/// padding merged, as a split may cut it), and how the input ended.
fn read_in_pieces(
    bytes: &[u8],
    step: usize,
    gates: &Gates,
) -> (Vec<String>, Option<TransportErrorCode>, bool) {
    let mut reader = RecordReader::new(MAX_RECORD);
    let mut out: Vec<String> = Vec::new();
    for piece in bytes.chunks(step) {
        let mut input = piece;
        loop {
            match reader.read(&mut input, gates) {
                Ok(Some(Event::Frame(Frame::Padding(p)))) => {
                    if let Some(prev) = out.last_mut().and_then(|l| l.strip_prefix("PADDING ")) {
                        let total = prev.parse::<usize>().unwrap() + p.len;
                        *out.last_mut().unwrap() = format!("PADDING {total}");
                    } else {
                        out.push(format!("PADDING {}", p.len));
                    }
                }
                Ok(Some(Event::Frame(f))) => out.push(format!("{f:?}")),
                Ok(Some(Event::RecordEnd { .. })) => out.push("END".into()),
                Ok(None) => break,
                Err(e) => {
                    assert_wire_code(e.code());
                    return (out, Some(e.code()), false);
                }
            }
        }
        assert!(input.is_empty(), "read left input unconsumed");
    }
    (out, None, reader.at_record_boundary())
}

fuzz_target!(|data: &[u8]| {
    let [bits, step, bytes @ ..] = data else {
        return;
    };
    let gates = gates_from(*bits);
    match Frame::decode(bytes, &gates) {
        Ok((frame, n)) => {
            assert!(n > 0 && n <= bytes.len());
            check_round_trip(&frame, &gates);
        }
        Err(e) => assert_wire_code(e.code()),
    }
    for f in Frames::new(bytes, gates) {
        match f {
            Ok(f) => check_round_trip(&f, &gates),
            Err(e) => assert_wire_code(e.code()),
        }
    }
    // Records: a record is released whole, so any split gives one result.
    let step = usize::from(*step).max(1);
    let whole = read_in_pieces(bytes, bytes.len().max(1), &gates);
    assert_eq!(read_in_pieces(bytes, step, &gates), whole);
    assert_eq!(read_in_pieces(bytes, 1, &gates), whole);
    // A Size of 0 or above the bound is the reader's error, never a panic.
    if let Some((size, _)) = varint::decode(bytes)
        && (size == 0 || size > MAX_RECORD)
    {
        assert_eq!(whole.1, Some(TransportErrorCode::FRAME_ENCODING_ERROR));
    }
});
