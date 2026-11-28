//! The capsules of a packet stream (EXTENSIONS.md Section 12), without I/O:
//! the RFC 9297 Section 3.2 format, `Type (i), Length (i), Value (..)`,
//! where the DATAGRAM type 0x00 carries `Context ID (i)` and a payload.

use bytes::{Buf, Bytes, BytesMut};

use crate::proto::varint;

/// The DATAGRAM capsule type (RFC 9297 Section 3.5).
pub(crate) const DATAGRAM: u64 = 0x00;

/// The largest DATAGRAM capsule header: Type, Length and Context ID.
pub(crate) const MAX_HEADER: usize = 1 + 8 + 8;

/// How much a receiver reads at once while it is between payloads.
const READ: usize = 64 * 1024;

/// Largest possible Type, Length, and Context encoding received from a peer.
pub(crate) const MAX_WIRE_HEADER: usize = 24;

/// Bound for opaque capsule Values, independent of negotiated record size.
pub(crate) fn unknown_limit(packet_max: usize) -> usize {
    packet_max.saturating_add(8).min(crate::util::usize_sat(
        crate::proto::params::ZMUX_MAX_RECORD_SIZE,
    ))
}

/// Writes an encoded capsule header. Context, if present, is part of Value.
pub(crate) fn encode_header(
    ty: u64,
    context: Option<u64>,
    payload: usize,
    out: &mut [u8],
) -> usize {
    let value = context.map_or(0, |value| varint::len(value) as u64) + payload as u64;
    let mut n = 0;
    for v in [Some(ty), Some(value), context].into_iter().flatten() {
        n += varint::encode(v, &mut out[n..]).expect("capsule header fields are bounded");
    }
    n
}

/// Writes a minimally encoded DATAGRAM capsule header and returns its length.
pub(crate) fn datagram_header(context: u64, payload: usize, out: &mut [u8; MAX_HEADER]) -> usize {
    encode_header(DATAGRAM, Some(context), payload, out)
}

/// A complete capsule header with the Context ID factored out of the Value.
pub(crate) struct Header {
    pub(crate) ty: u64,
    pub(crate) context: Option<u64>,
    pub(crate) payload: usize,
}

pub(crate) enum HeaderState {
    Need(usize),
    Complete(Header),
    Fault(Fault),
}

/// A bounded incremental header cursor. It never takes bytes from the next
/// capsule to finish a Context ID or any bytes past a complete header.
#[derive(Debug, Default)]
pub(crate) struct HeaderCursor {
    bytes: [u8; MAX_WIRE_HEADER],
    have: usize,
}

impl HeaderCursor {
    pub(crate) fn bytes(&self) -> &[u8] {
        &self.bytes[..self.have]
    }

    pub(crate) fn append(&mut self, bytes: &[u8]) {
        let end = self.have + bytes.len();
        self.bytes[self.have..end].copy_from_slice(bytes);
        self.have = end;
    }

    pub(crate) fn state(&self, packet_max: usize, opaque_max: usize) -> HeaderState {
        let bytes = self.bytes();
        let Some((ty, t)) = varint::decode(bytes) else {
            return HeaderState::Need(missing(bytes));
        };
        let bytes = &bytes[t..];
        let Some((value, l)) = varint::decode(bytes) else {
            return HeaderState::Need(missing(bytes));
        };
        if ty != DATAGRAM {
            return bounded_header(ty, None, value, opaque_max);
        }
        if value == 0 {
            return HeaderState::Fault(Fault::Truncated);
        }
        if value > (packet_max as u64).saturating_add(8) {
            return HeaderState::Fault(Fault::Oversized);
        }
        let bytes = &bytes[l..];
        if bytes
            .first()
            .is_some_and(|&b| varint::width(b) as u64 > value)
        {
            return HeaderState::Fault(Fault::Truncated);
        }
        let Some((context, width)) = varint::decode(bytes) else {
            return HeaderState::Need(missing(bytes));
        };
        bounded_header(ty, Some(context), value - width as u64, packet_max)
    }
}

fn missing(bytes: &[u8]) -> usize {
    bytes.first().map_or(1, |&b| varint::width(b) - bytes.len())
}

fn bounded_header(ty: u64, context: Option<u64>, n: u64, max: usize) -> HeaderState {
    match usize::try_from(n) {
        Ok(payload) if payload <= max => HeaderState::Complete(Header {
            ty,
            context,
            payload,
        }),
        _ => HeaderState::Fault(Fault::Oversized),
    }
}

/// What a decoder found.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Decoded {
    /// It needs more bytes: everything given was consumed.
    More,
    /// A DATAGRAM capsule.
    Packet { context: u64, payload: Bytes },
    /// A capsule of another type, skipped whole.
    Skipped,
    /// The bytes are malformed (Section 12).
    Malformed(Fault),
}

/// How the bytes of a packet stream are malformed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Fault {
    /// The Value length or DATAGRAM payload exceeded its corresponding cap.
    Oversized,
    /// A DATAGRAM Value that ends inside its Context ID; also, a stream
    /// that ends inside a capsule ([`Decoder::at_boundary`]).
    Truncated,
}

/// Decodes the capsules of a packet stream, a DATAGRAM payload of at most
/// `max` bytes.
#[derive(Debug)]
pub(crate) struct Decoder {
    max: usize,
    header: HeaderCursor,
    state: State,
}

#[derive(Debug, Default)]
enum State {
    #[default]
    Header,
    /// `left` payload bytes to come; a payload that spans chunks is
    /// gathered in `acc`.
    Payload {
        context: u64,
        left: usize,
        acc: Option<BytesMut>,
    },
    /// `left` bytes of a capsule of another type to skip.
    Skip(u64),
}

impl Decoder {
    pub(crate) fn new(max: usize) -> Self {
        Self {
            max,
            header: HeaderCursor::default(),
            state: State::Header,
        }
    }

    /// Whether the bytes so far end on a capsule boundary: where the
    /// stream may end.
    pub(crate) fn at_boundary(&self) -> bool {
        matches!(self.state, State::Header) && self.header.bytes().is_empty()
    }

    /// The most bytes worth reading next.
    pub(crate) fn want(&self) -> usize {
        match &self.state {
            State::Payload {
                left, acc: Some(_), ..
            } => (*left).max(1),
            _ => READ,
        }
    }

    /// Consumes from `buf` until it finds something or `buf` is empty. A
    /// payload whole in `buf` is a slice of it, without copying.
    pub(crate) fn decode(&mut self, buf: &mut Bytes) -> Decoded {
        loop {
            if let State::Payload { context, left, acc } = &mut self.state {
                let context = *context;
                return match acc {
                    None if buf.len() >= *left => {
                        let payload = buf.split_to(*left);
                        self.state = State::Header;
                        Decoded::Packet { context, payload }
                    }
                    None => {
                        // Grown with the bytes that arrive: a header that
                        // declares a large payload reserves no more than
                        // one read's worth up front.
                        let mut a = BytesMut::with_capacity((*left).min(buf.len().max(READ)));
                        a.extend_from_slice(buf);
                        *left -= buf.len();
                        buf.clear();
                        *acc = Some(a);
                        Decoded::More
                    }
                    Some(a) => {
                        let n = (*left).min(buf.len());
                        a.extend_from_slice(&buf[..n]);
                        buf.advance(n);
                        *left -= n;
                        if *left > 0 {
                            Decoded::More
                        } else {
                            let payload = std::mem::take(a).freeze();
                            self.state = State::Header;
                            Decoded::Packet { context, payload }
                        }
                    }
                };
            }
            if let State::Skip(left) = self.state {
                let n = usize::try_from(left).unwrap_or(usize::MAX).min(buf.len());
                buf.advance(n);
                let left = left - n as u64;
                if left > 0 {
                    self.state = State::Skip(left);
                    return Decoded::More;
                }
                self.state = State::Header;
                return Decoded::Skipped;
            }
            match self.header.state(self.max, unknown_limit(self.max)) {
                HeaderState::Need(n) => {
                    if buf.is_empty() {
                        return Decoded::More;
                    }
                    let n = n.min(buf.len());
                    self.header.append(&buf[..n]);
                    buf.advance(n);
                }
                HeaderState::Fault(fault) => return self.malformed(fault),
                HeaderState::Complete(header) => {
                    self.header = HeaderCursor::default();
                    self.state = if let Some(context) = header.context {
                        State::Payload {
                            context,
                            left: header.payload,
                            acc: None,
                        }
                    } else {
                        State::Skip(header.payload as u64)
                    };
                }
            }
        }
    }

    fn malformed(&mut self, fault: Fault) -> Decoded {
        // Stays malformed: nothing after it is read.
        self.state = State::Skip(u64::MAX);
        Decoded::Malformed(fault)
    }
}

/// What a decoder made of a byte string fed in pieces (feature `test-hooks`,
/// for the fuzz targets).
#[cfg(feature = "test-hooks")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapsuleRun {
    /// The DATAGRAM capsules found: Context ID and payload.
    pub packets: Vec<(u64, Vec<u8>)>,
    /// Capsules of another type skipped whole.
    pub skipped: usize,
    /// `Some("oversized")` or `Some("truncated")` when the bytes are
    /// malformed; decoding stops there.
    pub fault: Option<&'static str>,
    /// Whether the bytes end on a capsule boundary (false after a fault).
    pub at_boundary: bool,
}

/// Feeds `bytes` to a decoder bounded by `max` in pieces of `step` bytes.
#[cfg(feature = "test-hooks")]
#[must_use]
pub fn decode_run(max: usize, bytes: &[u8], step: usize) -> CapsuleRun {
    let mut d = Decoder::new(max);
    let mut run = CapsuleRun {
        packets: Vec::new(),
        skipped: 0,
        fault: None,
        at_boundary: false,
    };
    for chunk in bytes.chunks(step.max(1)) {
        let mut b = Bytes::copy_from_slice(chunk);
        loop {
            match d.decode(&mut b) {
                Decoded::More => break,
                Decoded::Packet { context, payload } => {
                    run.packets.push((context, payload.to_vec()));
                }
                Decoded::Skipped => run.skipped += 1,
                Decoded::Malformed(f) => {
                    run.fault = Some(match f {
                        Fault::Oversized => "oversized",
                        Fault::Truncated => "truncated",
                    });
                    return run;
                }
            }
        }
    }
    run.at_boundary = d.at_boundary();
    run
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(context: u64, payload: usize) -> Vec<u8> {
        let mut h = [0; MAX_HEADER];
        let n = datagram_header(context, payload, &mut h);
        h[..n].to_vec()
    }

    fn capsule(context: u64, payload: &[u8]) -> Vec<u8> {
        let mut v = header(context, payload.len());
        v.extend_from_slice(payload);
        v
    }

    /// Feeds `bytes` in chunks of `step`, collecting what was decoded.
    fn decode_all(max: usize, bytes: &[u8], step: usize) -> (Vec<Decoded>, bool) {
        let mut d = Decoder::new(max);
        let mut out = Vec::new();
        for chunk in bytes.chunks(step.max(1)) {
            let mut b = Bytes::copy_from_slice(chunk);
            loop {
                match d.decode(&mut b) {
                    Decoded::More => break,
                    Decoded::Malformed(f) => {
                        out.push(Decoded::Malformed(f));
                        return (out, false);
                    }
                    x => out.push(x),
                }
            }
        }
        (out, d.at_boundary())
    }

    /// The largest bound never overflows, and a header declaring a large
    /// payload reserves no more than what arrives.
    #[test]
    fn a_huge_bound_neither_overflows_nor_reserves_ahead() {
        let mut v = header(0, 1 << 30);
        v.extend_from_slice(&[7; 100]);
        let (out, _) = decode_all(usize::MAX, &v, v.len());
        assert!(out.is_empty(), "waits for the payload");
        let mut d = Decoder::new(usize::MAX);
        let mut b = Bytes::copy_from_slice(&v);
        assert!(matches!(d.decode(&mut b), Decoded::More));
        if let State::Payload { acc: Some(a), .. } = &d.state {
            assert!(a.capacity() < 1 << 20);
        }
    }

    #[test]
    fn datagram_headers() {
        assert_eq!(header(0, 3), [0x00, 0x04, 0x00]);
        assert_eq!(header(0, 0), [0x00, 0x01, 0x00]);
        assert_eq!(header(64, 1), [0x00, 0x03, 0x40, 0x40]);
        assert_eq!(header(0, 65535), [0x00, 0x80, 0x01, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn decodes_across_any_chunking() {
        let mut bytes = capsule(0, b"hello");
        bytes.extend([0x21, 0x02, 0xaa, 0xbb]); // an unknown type, skipped
        bytes.extend(capsule(7, b""));
        bytes.extend(capsule(1 << 20, &[9; 300]));
        bytes.extend([0x3f, 0x00]); // unknown, empty
        for step in [1, 2, 3, 7, 64, 4096] {
            let (out, end) = decode_all(65535, &bytes, step);
            assert!(end, "step {step}");
            assert_eq!(
                out,
                [
                    Decoded::Packet {
                        context: 0,
                        payload: Bytes::from_static(b"hello")
                    },
                    Decoded::Skipped,
                    Decoded::Packet {
                        context: 7,
                        payload: Bytes::new()
                    },
                    Decoded::Packet {
                        context: 1 << 20,
                        payload: Bytes::from(vec![9; 300])
                    },
                    Decoded::Skipped,
                ],
                "step {step}"
            );
        }
    }

    #[test]
    fn a_whole_payload_is_a_slice() {
        let bytes = Bytes::from(capsule(0, &[5; 1000]));
        let base = bytes.as_ptr() as usize;
        let mut b = bytes.clone();
        let Decoded::Packet { payload, .. } = Decoder::new(65535).decode(&mut b) else {
            panic!()
        };
        assert_eq!(payload.as_ptr() as usize, base + 4);
    }

    #[test]
    fn bounds_and_truncation() {
        // At the bound, and one above it.
        let (out, _) = decode_all(10, &capsule(0, &[0; 10]), 4096);
        assert_eq!(out.len(), 1);
        let over = [Decoded::Malformed(Fault::Oversized)];
        assert_eq!(decode_all(10, &capsule(0, &[0; 11]), 4096).0, over);
        // Seen from the Length alone, whatever the type.
        assert_eq!(decode_all(10, &header(0, 1 << 20), 4096).0, over);
        assert_eq!(decode_all(10, &[0x05, 19], 1).0, over);
        // No room for the Context ID.
        let cut = [Decoded::Malformed(Fault::Truncated)];
        assert_eq!(decode_all(10, &[0x00, 0x00], 1).0, cut);
        assert_eq!(decode_all(10, &[0x00, 0x01, 0x40, 0x01], 1).0, cut);
        // A stream that ends inside a capsule is not at a boundary.
        let c = capsule(0, b"abc");
        for cut in 1..c.len() {
            let (out, end) = decode_all(10, &c[..cut], 1);
            assert!(out.is_empty() && !end, "cut {cut}");
        }
        // Unknown types up to the bound are skipped.
        let (out, end) = decode_all(10, &[0x01, 18], 1);
        assert!(out.is_empty() && !end);
    }

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// The specification's capsule vectors (fixtures/capsules.json), fed
    /// whole and byte by byte.
    #[test]
    fn spec_capsule_vectors() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/testdata/spec/capsules.json");
        let doc: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        let cases = doc["cases"].as_array().unwrap();
        assert_ne!(cases.len(), 0, "the vector file lists cases");
        for case in cases {
            let id = case["id"].as_str().unwrap();
            let max = usize::try_from(case["max_payload"].as_u64().unwrap()).unwrap();
            let bytes = unhex(case["hex"].as_str().unwrap());
            let want: Vec<(u64, Vec<u8>)> = case["packets"]
                .as_array()
                .unwrap()
                .iter()
                .map(|p| {
                    (
                        p["context"].as_u64().unwrap(),
                        unhex(p["payload"].as_str().unwrap()),
                    )
                })
                .collect();
            let skipped = usize::try_from(case["skipped"].as_u64().unwrap()).unwrap();
            let error = case["error"].as_str();
            for step in [bytes.len().max(1), 1] {
                let (out, end) = decode_all(max, &bytes, step);
                let mut got = Vec::new();
                let (mut skips, mut fault) = (0, None);
                for d in out {
                    match d {
                        Decoded::Packet { context, payload } => {
                            got.push((context, payload.to_vec()));
                        }
                        Decoded::Skipped => skips += 1,
                        Decoded::Malformed(f) => fault = Some(f),
                        Decoded::More => unreachable!(),
                    }
                }
                // The end of the stream follows the bytes.
                if fault.is_none() && !end {
                    fault = Some(Fault::Truncated);
                }
                let fault = fault.map(|f| match f {
                    Fault::Oversized => "oversized",
                    Fault::Truncated => "truncated",
                });
                assert_eq!(got, want, "{id} step {step}");
                assert_eq!((skips, fault), (skipped, error), "{id} step {step}");
            }
            if case["encode"].as_bool().unwrap() {
                let mut enc = Vec::new();
                for (c, p) in &want {
                    enc.extend(capsule(*c, p));
                }
                assert_eq!(enc, bytes, "{id} encoding");
            }
        }
    }
}
