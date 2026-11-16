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

/// Writes the header of a DATAGRAM capsule with Context ID `context` and a
/// payload of `payload` bytes; its length. `context` is below 2^62.
pub(crate) fn datagram_header(context: u64, payload: usize, out: &mut [u8; MAX_HEADER]) -> usize {
    let value = varint::len(context) as u64 + payload as u64;
    let mut n = 0;
    for v in [DATAGRAM, value, context] {
        // In range: `context` is checked by the callers, `value` is bounded
        // by the packet bound.
        n += varint::encode(v, &mut out[n..]).unwrap_or(0);
    }
    n
}

/// The largest capsule Type and Length together.
pub(crate) const MAX_TYPE_LENGTH: usize = 8 + 8;

/// Where the Type and Length at the start of `b` stand: `Err(k)` while
/// `k` more bytes are needed to know more (at least 1), `Ok(length)` once
/// both are in.
pub(crate) fn type_length(b: &[u8]) -> Result<u64, usize> {
    let field = |b: &[u8]| match b.first() {
        None => Err(1),
        Some(&f) => {
            let w = varint::width(f);
            varint::decode(b)
                .ok_or_else(|| w - b.len())
                .map(|(v, _)| (v, w))
        }
    };
    let (_, t) = field(b)?;
    field(&b[t..]).map(|(len, _)| len)
}

/// A varint read across chunks.
#[derive(Debug, Default, Clone, Copy)]
struct Field {
    buf: [u8; 8],
    have: u8,
}

impl Field {
    /// Takes the field's bytes from `data`; the value and its encoded
    /// width once complete (a varint need not be minimally encoded).
    fn take(&mut self, data: &mut &[u8]) -> Option<(u64, usize)> {
        while let Some((&b, rest)) = data.split_first() {
            if self.have == 0 && varint::width(b) == 1 {
                *data = rest;
                return Some((u64::from(b), 1));
            }
            self.buf[usize::from(self.have)] = b;
            self.have += 1;
            *data = rest;
            let width = varint::width(self.buf[0]);
            if usize::from(self.have) == width {
                self.have = 0;
                return varint::decode(&self.buf[..width]).map(|(v, _)| (v, width));
            }
        }
        None
    }

    /// The width of a field whose first byte is in, 0 before.
    fn width(&self) -> usize {
        if self.have == 0 {
            0
        } else {
            varint::width(self.buf[0])
        }
    }
}

/// Where a capsule sequence is, for a relay that passes it through: only
/// the headers are parsed.
#[derive(Debug, Default)]
pub(crate) struct Scanner {
    field: Field,
    state: Scan,
}

#[derive(Debug, Default, Clone, Copy)]
enum Scan {
    /// At a Type: on a capsule boundary when no byte of it was read.
    #[default]
    Type,
    Length,
    Value(u64),
}

impl Scanner {
    /// Whether the bytes so far end on a capsule boundary.
    pub(crate) fn at_boundary(&self) -> bool {
        matches!(self.state, Scan::Type) && self.field.have == 0
    }

    /// The Value bytes left of the capsule being passed over; `None` while
    /// at a Type or Length.
    pub(crate) fn value_left(&self) -> Option<u64> {
        match self.state {
            Scan::Value(left) => Some(left),
            Scan::Type | Scan::Length => None,
        }
    }

    /// Passes over `data`: all of it, or with `stop`, up to the first
    /// boundary after at least one byte. The bytes passed over.
    pub(crate) fn scan(&mut self, data: &[u8], stop: bool) -> usize {
        let mut rest = data;
        while !rest.is_empty() {
            match self.state {
                Scan::Type => {
                    if self.field.take(&mut rest).is_some() {
                        self.state = Scan::Length;
                    }
                }
                Scan::Length => {
                    if let Some((len, _)) = self.field.take(&mut rest) {
                        self.state = if len == 0 {
                            Scan::Type
                        } else {
                            Scan::Value(len)
                        };
                    }
                }
                Scan::Value(left) => {
                    let n = usize::try_from(left).unwrap_or(usize::MAX).min(rest.len());
                    rest = &rest[n..];
                    let left = left - n as u64;
                    self.state = if left == 0 {
                        Scan::Type
                    } else {
                        Scan::Value(left)
                    };
                }
            }
            if stop && self.at_boundary() {
                break;
            }
        }
        data.len() - rest.len()
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
    /// A Length above the bound plus 8 (any type), or a DATAGRAM payload
    /// above the bound.
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
    field: Field,
    state: State,
}

#[derive(Debug, Default)]
enum State {
    #[default]
    Type,
    Length(u64),
    /// The Context ID of a DATAGRAM capsule whose Value has `value` bytes.
    Context {
        value: u64,
    },
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
            field: Field::default(),
            state: State::Type,
        }
    }

    /// Whether the bytes so far end on a capsule boundary: where the
    /// stream may end.
    pub(crate) fn at_boundary(&self) -> bool {
        matches!(self.state, State::Type) && self.field.have == 0
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
                        self.state = State::Type;
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
                            self.state = State::Type;
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
                self.state = State::Type;
                return Decoded::Skipped;
            }
            if buf.is_empty() {
                return Decoded::More;
            }
            let mut data: &[u8] = buf;
            let before = data.len();
            if let State::Context { value } = self.state {
                // The Context ID lies within the Value.
                let first = self.field.width().max(varint::width(data[0]));
                if self.field.have == 0 && first as u64 > value {
                    return self.malformed(Fault::Truncated);
                }
            }
            let got = self.field.take(&mut data);
            let used = before - data.len();
            buf.advance(used);
            let Some((v, width)) = got else {
                return Decoded::More;
            };
            match self.state {
                State::Type => self.state = State::Length(v),
                // The bound holds for capsules of every type: an 8-byte
                // Context ID and the largest payload.
                State::Length(_) if v > (self.max as u64).saturating_add(8) => {
                    return self.malformed(Fault::Oversized);
                }
                State::Length(DATAGRAM) => {
                    // At least the Context ID.
                    if v == 0 {
                        return self.malformed(Fault::Truncated);
                    }
                    self.state = State::Context { value: v };
                }
                State::Length(_) => {
                    if v == 0 {
                        self.state = State::Type;
                        return Decoded::Skipped;
                    }
                    self.state = State::Skip(v);
                }
                State::Context { value } => {
                    // The width read, not the shortest one.
                    let left = value - width as u64;
                    if left > self.max as u64 {
                        return self.malformed(Fault::Oversized);
                    }
                    self.state = State::Payload {
                        context: v,
                        left: crate::util::usize_sat(left),
                        acc: None,
                    };
                }
                State::Payload { .. } | State::Skip(_) => unreachable!("handled above"),
            }
        }
    }

    fn malformed(&mut self, fault: Fault) -> Decoded {
        // Stays malformed: nothing after it is read.
        self.state = State::Skip(u64::MAX);
        Decoded::Malformed(fault)
    }
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
        assert_ne!(cases.as_slice(), [] as [serde_json::Value; 0]);
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

    #[test]
    fn the_scanner_finds_boundaries() {
        let mut bytes = capsule(0, b"abc");
        let first = bytes.len();
        bytes.extend([0x05, 0x00]);
        bytes.extend(capsule(3, &[1; 70]));
        let mut s = Scanner::default();
        assert_eq!(s.scan(&bytes, true), first);
        assert!(s.at_boundary());
        assert_eq!(s.scan(&bytes[first..], true), 2);
        assert_eq!(s.scan(&bytes[first + 2..], false), bytes.len() - first - 2);
        assert!(s.at_boundary());
        // Byte by byte, the same boundaries.
        let mut s = Scanner::default();
        let ends: Vec<usize> = (0..bytes.len())
            .filter(|&i| {
                s.scan(&bytes[i..=i], false);
                s.at_boundary()
            })
            .map(|i| i + 1)
            .collect();
        assert_eq!(ends, [first, first + 2, bytes.len()]);
    }
}
