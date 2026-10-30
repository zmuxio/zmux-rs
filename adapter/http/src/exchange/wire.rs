//! The exchange carrier's bodies: the request prefix, the response, their
//! MACs and the body encoding.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use bytes::{BufMut, Bytes, BytesMut};
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use zmux::proto::varint;

use super::BodyEncoding;

type HmacSha256 = Hmac<Sha256>;

/// The label of the carrier key.
const KEY_LABEL: &[u8] = b"zmux-http-exchange/1";
/// The length of a truncated MAC.
pub(crate) const MAC_LEN: usize = 16;
/// The length of a response's MAC and flags.
pub(crate) const RESPONSE_HEAD: usize = MAC_LEN + 1;
/// The longest request prefix: two 8-byte variable-length integers.
pub(crate) const MAX_PREFIX: usize = 16 + 1 + 1 + 8 + 8 + 8 + MAC_LEN;
/// The longest CLOSE reason.
pub(crate) const MAX_REASON: usize = 256;

/// A Carrier ID.
pub(crate) type CarrierId = [u8; 16];

/// A request's kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum Kind {
    Up = 1,
    Down = 2,
    Close = 3,
}

impl Kind {
    fn from_byte(b: u8) -> Option<Self> {
        match b {
            1 => Some(Self::Up),
            2 => Some(Self::Down),
            3 => Some(Self::Close),
            _ => None,
        }
    }
}

/// Request flag: the uplink ends after this piece.
pub(crate) const REQ_FIN: u8 = 0x01;
/// Response flag: the downlink ends after this piece.
pub(crate) const FIN: u8 = 0x01;
/// Response flag: not processed; repeat later.
pub(crate) const BUSY: u8 = 0x02;
/// Response flag: no usable state for the carrier.
pub(crate) const GONE: u8 = 0x04;

/// A carrier key: HMAC-SHA256(PSK, label || Carrier ID).
#[derive(Clone)]
pub(crate) struct Key(HmacSha256);

impl Key {
    pub(crate) fn new(psk: &[u8], cid: &CarrierId) -> Self {
        let mut mac = HmacSha256::new_from_slice(psk).expect("HMAC takes any key length");
        mac.update(KEY_LABEL);
        mac.update(cid);
        let k = mac.finalize().into_bytes();
        Self(HmacSha256::new_from_slice(&k).expect("HMAC takes any key length"))
    }

    /// A MAC over the concatenation of `parts`.
    fn mac(&self, parts: &[&[u8]]) -> HmacSha256 {
        let mut mac = self.0.clone();
        for p in parts {
            mac.update(p);
        }
        mac
    }

    fn tag(&self, parts: &[&[u8]]) -> [u8; MAC_LEN] {
        let full = self.mac(parts).finalize().into_bytes();
        let mut out = [0; MAC_LEN];
        out.copy_from_slice(&full[..MAC_LEN]);
        out
    }

    /// Whether `tag` is the truncated MAC over `parts` (constant time).
    fn check(&self, parts: &[&[u8]], tag: &[u8]) -> bool {
        self.mac(parts).verify_truncated_left(tag).is_ok()
    }

    /// The MAC of a response to the request `to`.
    fn response_tag(&self, to: &Answering<'_>, flags: u8, data: &[u8]) -> [u8; MAC_LEN] {
        self.tag(&[b"R", to.cid, &[to.kind], to.seq, to.nonce, &[flags], data])
    }
}

/// What a response MAC binds of the request it answers.
pub(crate) struct Answering<'a> {
    pub(crate) cid: &'a CarrierId,
    /// The Kind byte as sent.
    pub(crate) kind: u8,
    /// The Sequence in its variable-length encoding as sent.
    pub(crate) seq: &'a [u8],
    pub(crate) nonce: &'a [u8; 8],
}

/// A request to send: its prefix (everything before Data) and what its
/// response must be bound to.
pub(crate) struct Outgoing {
    pub(crate) prefix: Bytes,
    seq: [u8; 8],
    seq_len: usize,
    nonce: [u8; 8],
}

impl Outgoing {
    /// The request prefix for `data`, its MAC computed with `key`.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        key: &Key,
        cid: &CarrierId,
        kind: Kind,
        flags: u8,
        seq: u64,
        ack: u64,
        nonce: [u8; 8],
        data: &[u8],
    ) -> Self {
        let mut s = [0; 8];
        let seq_len = varint::encode(seq, &mut s).expect("piece numbers stay below 2^62");
        let mut a = [0; 8];
        let ack_len = varint::encode(ack, &mut a).expect("piece numbers stay below 2^62");
        let mut p = BytesMut::with_capacity(MAX_PREFIX);
        p.put_slice(cid);
        p.put_u8(kind as u8);
        p.put_u8(flags);
        p.put_slice(&s[..seq_len]);
        p.put_slice(&a[..ack_len]);
        p.put_slice(&nonce);
        let tag = key.tag(&[b"Q", &p, data]);
        p.put_slice(&tag);
        Self {
            prefix: p.freeze(),
            seq: s,
            seq_len,
            nonce,
        }
    }

    /// Whether `resp` is a response to this request, by its MAC.
    pub(crate) fn verifies(&self, key: &Key, cid: &CarrierId, kind: Kind, resp: &Response) -> bool {
        let to = Answering {
            cid,
            kind: kind as u8,
            seq: &self.seq[..self.seq_len],
            nonce: &self.nonce,
        };
        key.check(
            &[
                b"R",
                to.cid,
                &[to.kind],
                to.seq,
                to.nonce,
                &[resp.flags],
                &resp.data,
            ],
            &resp.mac,
        )
    }
}

/// A received request, before its MAC is checked.
#[derive(Debug)]
pub(crate) struct Request {
    pub(crate) cid: CarrierId,
    /// The Kind byte as received (validated after the MAC).
    kind: u8,
    pub(crate) flags: u8,
    pub(crate) seq: u64,
    pub(crate) ack: u64,
    pub(crate) nonce: [u8; 8],
    /// The body up to the MAC, as received.
    signed: Bytes,
    /// The Sequence's encoding within `signed`.
    seq_at: (usize, usize),
    mac: [u8; MAC_LEN],
    pub(crate) data: Bytes,
}

/// Why a request is not valid.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Malformed {
    /// The body is not a request.
    Body,
    /// The MAC does not verify.
    Mac,
    /// The request is authentic but breaks the binding's rules.
    Invalid,
}

impl Request {
    /// Parses the binary body of a request.
    pub(crate) fn parse(body: Bytes) -> Result<Self, Malformed> {
        let mut at = 16 + 2;
        if body.len() < at {
            return Err(Malformed::Body);
        }
        let mut cid = [0; 16];
        cid.copy_from_slice(&body[..16]);
        let (kind, flags) = (body[16], body[17]);
        let (seq, n) = varint::decode(&body[at..]).ok_or(Malformed::Body)?;
        let seq_at = (at, n);
        at += n;
        let (ack, n) = varint::decode(&body[at..]).ok_or(Malformed::Body)?;
        at += n;
        let nonce: [u8; 8] = body
            .get(at..at + 8)
            .and_then(|s| s.try_into().ok())
            .ok_or(Malformed::Body)?;
        at += 8;
        let mac: [u8; MAC_LEN] = body
            .get(at..at + MAC_LEN)
            .and_then(|s| s.try_into().ok())
            .ok_or(Malformed::Body)?;
        Ok(Self {
            cid,
            kind,
            flags,
            seq,
            ack,
            nonce,
            signed: body.slice(..at),
            seq_at,
            mac,
            data: body.slice(at + MAC_LEN..),
        })
    }

    /// Checks the MAC with `key`, then the rules of the binding; returns
    /// the request's kind.
    pub(crate) fn verify(&self, key: &Key) -> Result<Kind, Malformed> {
        if !key.check(&[b"Q", &self.signed, &self.data], &self.mac) {
            return Err(Malformed::Mac);
        }
        let kind = Kind::from_byte(self.kind).ok_or(Malformed::Invalid)?;
        let valid = match kind {
            Kind::Up => self.flags & !REQ_FIN == 0,
            Kind::Down => self.flags == 0 && self.data.is_empty(),
            Kind::Close => {
                self.flags == 0
                    && self.seq == 0
                    && self.data.len() <= MAX_REASON
                    && std::str::from_utf8(&self.data).is_ok()
            }
        };
        if valid {
            Ok(kind)
        } else {
            Err(Malformed::Invalid)
        }
    }

    /// The Kind byte as received.
    pub(crate) fn kind_byte(&self) -> u8 {
        self.kind
    }

    /// What a response to this request is bound to.
    pub(crate) fn answering(&self) -> Answering<'_> {
        Answering {
            cid: &self.cid,
            kind: self.kind,
            seq: &self.signed[self.seq_at.0..self.seq_at.0 + self.seq_at.1],
            nonce: &self.nonce,
        }
    }
}

/// The head of a response (MAC and flags) to the request `to`, carrying
/// `data` after it.
pub(crate) fn response_head(key: &Key, to: &Answering<'_>, flags: u8, data: &[u8]) -> Bytes {
    let mut h = BytesMut::with_capacity(RESPONSE_HEAD);
    h.put_slice(&key.response_tag(to, flags, data));
    h.put_u8(flags);
    h.freeze()
}

/// A received response, before its MAC is checked.
#[derive(Debug)]
pub(crate) struct Response {
    mac: [u8; MAC_LEN],
    pub(crate) flags: u8,
    pub(crate) data: Bytes,
}

impl Response {
    /// Parses the binary body of a response.
    pub(crate) fn parse(body: Bytes) -> Option<Self> {
        let mac = body.get(..MAC_LEN)?.try_into().ok()?;
        let flags = *body.get(MAC_LEN)?;
        Some(Self {
            mac,
            flags,
            data: body.slice(RESPONSE_HEAD..),
        })
    }

    /// Whether the flags and data of this verified response to a request
    /// of `kind` are valid (Section 4); a response that is not fails the
    /// carrier.
    pub(crate) fn valid_for(&self, kind: Kind) -> bool {
        match self.flags {
            BUSY | GONE => self.data.is_empty(),
            0 => kind == Kind::Down || self.data.is_empty(),
            FIN => kind == Kind::Down,
            _ => false,
        }
    }
}

/// An HTTP body of the binary body `head` then `tail`, in `encoding`.
pub(crate) fn encode_body(encoding: BodyEncoding, head: Bytes, tail: Bytes) -> (Bytes, Bytes) {
    match encoding {
        BodyEncoding::Binary => (head, tail),
        BodyEncoding::Base64 => {
            let mut bin = Vec::with_capacity(head.len() + tail.len());
            bin.extend_from_slice(&head);
            bin.extend_from_slice(&tail);
            (Bytes::from(BASE64.encode(bin)), Bytes::new())
        }
    }
}

/// The binary body of an HTTP body in `encoding`.
pub(crate) fn decode_body(encoding: BodyEncoding, body: Bytes) -> Option<Bytes> {
    match encoding {
        BodyEncoding::Binary => Some(body),
        BodyEncoding::Base64 => BASE64.decode(&body).ok().map(Bytes::from),
    }
}

/// The length of an HTTP body in `encoding` whose binary form has `len`
/// bytes.
pub(crate) fn encoded_len(encoding: BodyEncoding, len: usize) -> usize {
    match encoding {
        BodyEncoding::Binary => len,
        BodyEncoding::Base64 => len.div_ceil(3).saturating_mul(4),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn to_hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    const CID: CarrierId = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
    const NONCE: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];

    /// The test vectors of the binding (Section 9): both requests and both
    /// responses as each side builds them, and as the other parses and
    /// verifies them.
    #[test]
    fn test_vectors() {
        let cases = [
            (
                Vec::new(),
                "8e08f7810b828921459c8d8c4f1be67963269408f5e7179f7f0df94d417723ef",
                "000102030405060708090a0b0c0d0e0f0100000001020304050607083a03565a66d053fcaa22184304620da468656c6c6f",
                "477e5b04a29e7fc80fd53eb36fd0715400",
                "000102030405060708090a0b0c0d0e0f0200412c412b01020304050607088897fdc82804aa8d78f2c52a8e9a9f4c",
                "0ccf05f246c40f075271dd7e52d2420401776f726c64",
            ),
            (
                vec![0x6b; 32],
                "68489b10ee27b348be274432395cb2107dcfc8cf3f9f69f2cd4cf7cd7a0f8c95",
                "000102030405060708090a0b0c0d0e0f010000000102030405060708bace4bcb910362f6efd873612d5cfbbe68656c6c6f",
                "c5b18d1988c3d46dbfee70883026026000",
                "000102030405060708090a0b0c0d0e0f0200412c412b0102030405060708f5da46bda25a34468f71ad8de3505f08",
                "f900c6512f2edcc31275640df468edf201776f726c64",
            ),
        ];
        for (psk, k, up, up_r, down, down_r) in cases {
            // The carrier key.
            let mut mac = HmacSha256::new_from_slice(&psk).unwrap();
            mac.update(KEY_LABEL);
            mac.update(&CID);
            assert_eq!(to_hex(&mac.finalize().into_bytes()), k);
            let key = Key::new(&psk, &CID);

            // The client's requests.
            let up_out = Outgoing::new(&key, &CID, Kind::Up, 0, 0, 0, NONCE, b"hello");
            assert_eq!(to_hex(&up_out.prefix) + &to_hex(b"hello"), up);
            let down_out = Outgoing::new(&key, &CID, Kind::Down, 0, 300, 299, NONCE, b"");
            assert_eq!(to_hex(&down_out.prefix), down);

            // The server parses them and answers.
            let up_req = Request::parse(Bytes::from(hex(up))).unwrap();
            assert_eq!(up_req.verify(&key), Ok(Kind::Up));
            assert_eq!(
                (up_req.seq, up_req.ack, &up_req.data[..]),
                (0, 0, &b"hello"[..])
            );
            let head = response_head(&key, &up_req.answering(), 0, b"");
            assert_eq!(to_hex(&head), up_r);
            let down_req = Request::parse(Bytes::from(hex(down))).unwrap();
            assert_eq!(down_req.verify(&key), Ok(Kind::Down));
            assert_eq!((down_req.seq, down_req.ack), (300, 299));
            let head = response_head(&key, &down_req.answering(), FIN, b"world");
            assert_eq!(to_hex(&head) + &to_hex(b"world"), down_r);

            // The client verifies the responses.
            let r = Response::parse(Bytes::from(hex(up_r))).unwrap();
            assert!(up_out.verifies(&key, &CID, Kind::Up, &r) && r.valid_for(Kind::Up));
            let r = Response::parse(Bytes::from(hex(down_r))).unwrap();
            assert!(down_out.verifies(&key, &CID, Kind::Down, &r) && r.valid_for(Kind::Down));
            assert_eq!((r.flags, &r.data[..]), (FIN, &b"world"[..]));
        }
    }

    /// The negative control of cache replay: a response to an earlier
    /// request of the same carrier (an earlier attempt of the same piece,
    /// or another piece) is a well-formed response that the client would
    /// take as a piece, and only its MAC tells it apart.
    #[test]
    fn mac_catches_replayed_responses() {
        let key = Key::new(b"", &CID);
        let first = Outgoing::new(&key, &CID, Kind::Down, 0, 7, 7, NONCE, b"");
        let req = Request::parse(first.prefix.clone()).unwrap();
        let mut cached = BytesMut::new();
        cached.put(response_head(&key, &req.answering(), 0, b"stale"));
        cached.put_slice(b"stale");
        let cached = Response::parse(cached.freeze()).unwrap();
        // The genuine answer verifies.
        assert!(first.verifies(&key, &CID, Kind::Down, &cached));
        // Replayed to a repetition of the same piece (new nonce), or to
        // another piece: valid in form, rejected by the MAC.
        let again = Outgoing::new(&key, &CID, Kind::Down, 0, 7, 7, [9; 8], b"");
        let other = Outgoing::new(&key, &CID, Kind::Down, 0, 8, 7, NONCE, b"");
        assert!(cached.valid_for(Kind::Down));
        assert!(!again.verifies(&key, &CID, Kind::Down, &cached));
        assert!(!other.verifies(&key, &CID, Kind::Down, &cached));
        // Another carrier's key, and a key from another PSK.
        let mut cid2 = CID;
        cid2[0] ^= 1;
        assert!(!first.verifies(&Key::new(b"", &cid2), &cid2, Kind::Down, &cached));
        assert!(!first.verifies(&Key::new(b"x", &CID), &CID, Kind::Down, &cached));
        // A request whose data was rewritten.
        let mut forged =
            BytesMut::from(&Outgoing::new(&key, &CID, Kind::Up, 0, 0, 0, NONCE, b"a").prefix[..]);
        forged.put_slice(b"b");
        let forged = Request::parse(forged.freeze()).unwrap();
        assert_eq!(forged.verify(&key), Err(Malformed::Mac));
    }

    /// Requests that verify but break the rules, and response flags.
    #[test]
    fn validation() {
        let key = Key::new(b"", &CID);
        let req = |kind: u8, flags: u8, seq: u64, data: &[u8]| {
            let mut p = BytesMut::new();
            p.put_slice(&CID);
            p.put_u8(kind);
            p.put_u8(flags);
            let mut s = [0; 8];
            let len = varint::encode(seq, &mut s).unwrap();
            p.put_slice(&s[..len]);
            p.put_u8(0);
            p.put_slice(&NONCE);
            let tag = key.tag(&[b"Q", &p, data]);
            p.put_slice(&tag);
            p.put_slice(data);
            Request::parse(p.freeze()).unwrap().verify(&key)
        };
        assert_eq!(req(1, 1, 3, b"x"), Ok(Kind::Up));
        assert_eq!(req(1, 2, 3, b"x"), Err(Malformed::Invalid));
        assert_eq!(req(2, 0, 3, b""), Ok(Kind::Down));
        assert_eq!(req(2, 1, 3, b""), Err(Malformed::Invalid));
        assert_eq!(req(2, 0, 3, b"x"), Err(Malformed::Invalid));
        assert_eq!(req(3, 0, 0, b"bye"), Ok(Kind::Close));
        assert_eq!(req(3, 0, 0, &[0xff]), Err(Malformed::Invalid));
        assert_eq!(
            req(3, 0, 0, &[b'a'; MAX_REASON + 1]),
            Err(Malformed::Invalid)
        );
        assert_eq!(req(4, 0, 0, b""), Err(Malformed::Invalid));
        assert_eq!(
            Request::parse(Bytes::from_static(&[0; 40])).err(),
            Some(Malformed::Body)
        );

        // A non-minimal Sequence encoding is bound as sent.
        let mut p = BytesMut::new();
        p.put_slice(&CID);
        p.put_slice(&[2, 0, 0x40, 0x05, 0]);
        p.put_slice(&NONCE);
        let tag = key.tag(&[b"Q", &p]);
        p.put_slice(&tag);
        let r = Request::parse(p.freeze()).unwrap();
        assert_eq!((r.verify(&key), r.seq), (Ok(Kind::Down), 5));
        assert_eq!(r.answering().seq, &[0x40, 0x05]);

        let resp = |flags: u8, data: &'static [u8]| Response {
            mac: [0; MAC_LEN],
            flags,
            data: Bytes::from_static(data),
        };
        assert!(resp(BUSY, b"").valid_for(Kind::Up));
        assert!(!resp(BUSY, b"x").valid_for(Kind::Down));
        assert!(!resp(BUSY | FIN, b"").valid_for(Kind::Down));
        assert!(!resp(GONE | BUSY, b"").valid_for(Kind::Up));
        assert!(!resp(FIN, b"").valid_for(Kind::Up));
        assert!(!resp(0, b"x").valid_for(Kind::Up));
        assert!(!resp(0x08, b"").valid_for(Kind::Down));
        assert!(Response::parse(Bytes::from_static(&[0; 16])).is_none());
    }

    #[test]
    fn base64_bodies() {
        let (h, t) = encode_body(
            BodyEncoding::Base64,
            Bytes::from_static(b"he"),
            Bytes::from_static(b"llo"),
        );
        assert!(t.is_empty());
        assert_eq!(&h[..], b"aGVsbG8=");
        assert_eq!(encoded_len(BodyEncoding::Base64, 5), h.len());
        assert_eq!(&decode_body(BodyEncoding::Base64, h).unwrap()[..], b"hello");
        assert!(decode_body(BodyEncoding::Base64, Bytes::from_static(b"aGVsbG8")).is_none());
    }
}
