//! Record framing at the end of a batch, sans IO, one pipe: every byte a
//! core hands to its carrier belongs to a record (SPEC.md Section 3).
//! Found by `tests/mp_fuzz.rs`.

use std::time::Instant;

use zmux::proto::frame::{Dir, Frames, Gates};
use zmux::proto::session::{Config, TransmitBuf};
use zmux::proto::varint;

#[path = "common/core_pair.rs"]
mod core_pair;

use core_pair::{CorePair, P0};

/// Checks that `wire` is whole records whose frames all decode.
fn check_records(wire: &[u8]) -> Result<(), String> {
    let gates = Gates {
        reset_stream_at: true,
        goaway: true,
        priority: true,
        ..Gates::default()
    };
    let mut rest = wire;
    let mut index = 0;
    while !rest.is_empty() {
        let (size, n) = varint::decode(rest).ok_or("truncated record size")?;
        let body = rest
            .get(n..n + size as usize)
            .ok_or_else(|| format!("record {index} ends after the batch"))?;
        if let Some(Err(e)) = Frames::new(body, gates).find(Result::is_err) {
            return Err(format!("record {index} of {size} bytes: {e:?}"));
        }
        rest = &rest[n + size as usize..];
        index += 1;
    }
    Ok(())
}

/// BUG (`output.rs`, the stream frame step and `Records::stream_room`): a
/// STREAM frame that carries only a FIN computes `min = 0`, so when the
/// open record has no room and the batch has none for a new record,
/// `stream_room` ends the record and returns 0 with no record open, the
/// check `room < min` passes, and `stream_header` writes the frame after
/// the last record, outside any record. The peer reads the frame type as a
/// record size and the following bytes as frames: here FRAME_ENCODING_ERROR
/// or a misparsed record, in general arbitrary frames. `write_copy` has the
/// same gap for a re-sent FIN without data (`room == 0 && want > 0`). A
/// zero `stream_room` must always mean "batch full".
#[test]
fn fin_only_frame_at_the_end_of_a_batch_stays_in_a_record() {
    let now = Instant::now();
    let batch = 2_000;
    for fill in batch - 60..batch {
        let mut p = CorePair::new(Config::default(), Config::default());
        let a = &mut p.a;
        // Stream X sends its data; its FIN comes later, alone.
        let x = a.open(Dir::Bidi).unwrap();
        a.write(x, &[1]).unwrap();
        p.pump();
        let (a, b) = (&mut p.a, &mut p.b);
        // Stream Y nearly fills a small batch, then X's FIN is due.
        let y = a.open(Dir::Bidi).unwrap();
        a.write(y, &vec![2; fill]).unwrap();
        a.finish(x).unwrap();
        let mut small = TransmitBuf::with_capacity(batch);
        a.poll_transmit(P0, now, &mut small);
        let mut wire = Vec::new();
        small.copy_to_vec(&mut wire);
        if let Err(e) = check_records(&wire) {
            panic!("fill {fill}: {e}");
        }
        b.receive(P0, &wire, now);
        p.pump();
        assert!(
            p.b.error().is_none(),
            "fill {fill}: the peer closed with {:?}",
            p.b.error()
        );
    }
}
