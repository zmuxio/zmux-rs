//! N19: the stream credit maximum. `MAX_STREAM_CREDIT` (2^60) is the top of
//! the range of the stream count options and of `raise_incoming_streams`,
//! and reaches the wire unchanged; one above it is the configuration error.

#[path = "common/core_pair.rs"]
mod core_pair;

use std::time::Instant;

use core_pair::CorePair;
use zmux::proto::frame::{Dir, Frame, Gates};
use zmux::proto::params::TransportParameters;
use zmux::proto::session::{Config, Role, SessionCore};
use zmux::proto::varint;
use zmux::{MAX_STREAM_CREDIT, UniCredit};

/// The frames of the byte-stream records in `bytes`.
fn frames(bytes: &[u8], mut each: impl FnMut(Frame<'_>)) {
    let mut rest = bytes;
    while let Some((len, width)) = varint::decode(rest) {
        let end = width + usize::try_from(len).unwrap();
        let mut body = &rest[width..end];
        while !body.is_empty() {
            let (f, n) = Frame::decode(body, &Gates::ALL).expect("a frame the core wrote");
            each(f);
            body = &body[n..];
        }
        rest = &rest[end..];
    }
    assert!(rest.is_empty(), "whole records");
}

fn granting_all() -> Config {
    let mut c = Config::default();
    c.max_incoming_streams = MAX_STREAM_CREDIT;
    c.max_incoming_uni_streams = UniCredit::Limit(MAX_STREAM_CREDIT);
    c
}

#[test]
fn the_maximum_is_advertised_and_one_above_it_is_refused() {
    assert_eq!(MAX_STREAM_CREDIT, 1 << 60);
    let mut p = CorePair::attached(granting_all(), Config::default());
    let mut tp = None;
    p.send_with(true, |bytes| {
        frames(bytes, |f| {
            if let Frame::TransportParameters(t) = f {
                tp = Some(TransportParameters::decode(t.block).unwrap());
            }
        });
    });
    let tp = tp.expect("the parameters went first");
    assert_eq!(tp.initial_max_streams_bidi, Some(MAX_STREAM_CREDIT));
    assert_eq!(tp.initial_max_streams_uni, Some(MAX_STREAM_CREDIT));
    p.pump();
    assert!(p.a.is_established() && p.b.is_established());
    assert_eq!(p.b.peer_initial_streams_bidi(), Some(MAX_STREAM_CREDIT));

    let now = Instant::now();
    let mut over = Config::default();
    over.max_incoming_streams = MAX_STREAM_CREDIT + 1;
    assert!(SessionCore::new(over, Role::Client, None, now).is_err());
    let mut over = Config::default();
    over.max_incoming_uni_streams = UniCredit::Limit(MAX_STREAM_CREDIT + 1);
    assert!(SessionCore::new(over, Role::Client, None, now).is_err());
}

#[test]
fn raising_to_the_maximum_sends_max_streams_of_it() {
    // Unidirectional credit set, not staged: a raise of it is sent at once.
    let mut b = Config::default();
    b.max_incoming_uni_streams = UniCredit::Limit(16);
    let mut p = CorePair::new(Config::default(), b);
    assert!(
        p.b.raise_incoming_streams(MAX_STREAM_CREDIT + 1, 0)
            .is_err()
    );
    p.b.raise_incoming_streams(MAX_STREAM_CREDIT, MAX_STREAM_CREDIT)
        .unwrap();
    let mut sent = Vec::new();
    p.send_with(false, |bytes| {
        frames(bytes, |f| {
            if let Frame::MaxStreams(m) = f {
                sent.push((m.dir, m.maximum));
            }
        });
    });
    sent.sort_by_key(|&(d, _)| d == Dir::Uni);
    assert_eq!(
        sent,
        [
            (Dir::Bidi, MAX_STREAM_CREDIT),
            (Dir::Uni, MAX_STREAM_CREDIT)
        ]
    );
    // The peer takes it as the protocol allows.
    p.pump();
    assert!(p.a.error().is_none() && p.b.error().is_none());
}
