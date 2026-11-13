//! The exchange carrier's bodies: the request's authentication header and
//! Data MAC, the response, their MACs and the body encoding.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use bytes::{BufMut, Bytes, BytesMut};
use zmux::util::HmacSha256;

use super::BodyEncoding;

/// The label of the carrier key.
const KEY_LABEL: &[u8] = b"zmux-http-exchange/1";
/// The length of a truncated MAC.
pub(crate) const MAC_LEN: usize = 16;
/// The header fields the Header MAC covers: Carrier ID, Kind, Flags,
/// Sequence, Down Ack, Time, Nonce and Data Length.
const SIGNED_LEN: usize = 16 + 1 + 1 + 8 + 8 + 4 + 8 + 4;
/// The length of a request's authentication header.
pub(crate) const HEADER_LEN: usize = SIGNED_LEN + MAC_LEN;
/// What a request body holds besides its Data: the authentication header
/// and the Data MAC.
pub(crate) const REQUEST_OVERHEAD: usize = HEADER_LEN + MAC_LEN;
/// The length of a response's MAC and flags.
pub(crate) const RESPONSE_HEAD: usize = MAC_LEN + 1;
/// The longest CLOSE reason.
pub(crate) const MAX_REASON: usize = 256;
/// The longest Data a request can declare.
pub(crate) const MAX_DATA: usize = u32::MAX as usize;

/// The clock in seconds since 1970-01-01T00:00:00Z.
pub(crate) fn unix_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// The clock as a request's Time: [`unix_seconds`] modulo 2^32.
pub(crate) fn unix_time() -> u32 {
    unix_seconds() as u32
}

/// A Carrier ID.
pub(crate) type CarrierId = [u8; 16];

/// A request's kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum Kind {
    Up = 1,
    Down = 2,
    Close = 3,
}

impl From<Kind> for u8 {
    fn from(k: Kind) -> u8 {
        k as u8
    }
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
        let k = HmacSha256::new(psk).mac(&[KEY_LABEL, cid]);
        Self(HmacSha256::new(&k))
    }

    fn tag(&self, parts: &[&[u8]]) -> [u8; MAC_LEN] {
        let full = self.0.mac(parts);
        let mut out = [0; MAC_LEN];
        out.copy_from_slice(&full[..MAC_LEN]);
        out
    }

    /// Whether `tag` is the truncated MAC over `parts` (constant time).
    fn check(&self, parts: &[&[u8]], tag: &[u8]) -> bool {
        self.0.verify(parts, tag)
    }

    /// The parts the MAC of a response with `flags` and `data` to `to`
    /// covers, given `seq` as `to.seq` encoded.
    fn response_parts<'a>(
        to: &'a Answering<'a>,
        seq: &'a [u8; 8],
        flags: &'a [u8; 1],
        kind: &'a [u8; 1],
        data: &'a [u8],
    ) -> [&'a [u8]; 7] {
        [b"R", to.cid, kind, seq, to.nonce, flags, data]
    }

    /// The MAC of a response with `flags` and `data` to the request `to`.
    fn response_tag(&self, to: &Answering<'_>, flags: u8, data: &[u8]) -> [u8; MAC_LEN] {
        let seq = to.seq.to_be_bytes();
        self.tag(&Self::response_parts(to, &seq, &[flags], &[to.kind], data))
    }
}

/// What a response MAC binds of the request it answers.
pub(crate) struct Answering<'a> {
    pub(crate) cid: &'a CarrierId,
    /// The Kind byte as sent.
    pub(crate) kind: u8,
    pub(crate) seq: u64,
    pub(crate) nonce: &'a [u8; 8],
}

/// A request to send: its authentication header, its Data MAC, and what
/// its response must be bound to.
pub(crate) struct Outgoing {
    pub(crate) header: Bytes,
    pub(crate) data_mac: Bytes,
    seq: u64,
    nonce: [u8; 8],
}

impl Outgoing {
    /// The header and Data MAC of a request carrying `data` (at most
    /// [`MAX_DATA`] bytes), computed with `key`.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        key: &Key,
        cid: &CarrierId,
        kind: impl Into<u8>,
        flags: u8,
        seq: u64,
        ack: u64,
        time: u32,
        nonce: [u8; 8],
        data: &[u8],
    ) -> Self {
        let len = u32::try_from(data.len()).expect("pieces stay within MAX_DATA");
        let mut h = BytesMut::with_capacity(HEADER_LEN);
        h.put_slice(cid);
        h.put_u8(kind.into());
        h.put_u8(flags);
        h.put_u64(seq);
        h.put_u64(ack);
        h.put_u32(time);
        h.put_slice(&nonce);
        h.put_u32(len);
        let header_mac = key.tag(&[b"Q", &h]);
        h.put_slice(&header_mac);
        let data_mac = key.tag(&[b"D", &header_mac, data]);
        Self {
            header: h.freeze(),
            data_mac: Bytes::copy_from_slice(&data_mac),
            seq,
            nonce,
        }
    }

    /// Whether `resp` is a response to this request, by its MAC.
    pub(crate) fn verifies(
        &self,
        key: &Key,
        cid: &CarrierId,
        kind: impl Into<u8>,
        resp: &Response,
    ) -> bool {
        let to = Answering {
            cid,
            kind: kind.into(),
            seq: self.seq,
            nonce: &self.nonce,
        };
        let seq = to.seq.to_be_bytes();
        let (flags, kind) = ([resp.flags], [to.kind]);
        let parts = Key::response_parts(&to, &seq, &flags, &kind, &resp.data);
        key.check(&parts, &resp.mac)
    }
}

/// A received authentication header, before its MAC is checked.
#[derive(Debug)]
pub(crate) struct Header {
    pub(crate) cid: CarrierId,
    /// The Kind byte as received (validated after the MACs).
    kind: u8,
    pub(crate) flags: u8,
    pub(crate) seq: u64,
    pub(crate) ack: u64,
    /// The client's clock in seconds modulo 2^32.
    pub(crate) time: u32,
    pub(crate) nonce: [u8; 8],
    /// The declared length of Data.
    pub(crate) data_len: u32,
    /// The header as received.
    raw: [u8; HEADER_LEN],
}

impl Header {
    /// The fields of the binary header `raw`.
    pub(crate) fn parse(raw: [u8; HEADER_LEN]) -> Self {
        let u64_at = |at: usize| u64::from_be_bytes(raw[at..at + 8].try_into().expect("8 bytes"));
        let u32_at = |at: usize| u32::from_be_bytes(raw[at..at + 4].try_into().expect("4 bytes"));
        let mut cid = [0; 16];
        cid.copy_from_slice(&raw[..16]);
        let mut nonce = [0; 8];
        nonce.copy_from_slice(&raw[38..46]);
        Self {
            cid,
            kind: raw[16],
            flags: raw[17],
            seq: u64_at(18),
            ack: u64_at(26),
            time: u32_at(34),
            nonce,
            data_len: u32_at(46),
            raw,
        }
    }

    /// The Header MAC as received.
    fn mac(&self) -> &[u8] {
        &self.raw[SIGNED_LEN..]
    }

    /// Whether the Header MAC verifies with `key` (constant time).
    pub(crate) fn authentic(&self, key: &Key) -> bool {
        key.check(&[b"Q", &self.raw[..SIGNED_LEN]], self.mac())
    }

    /// Whether `tag` is the Data MAC of `data` after this header
    /// (constant time).
    pub(crate) fn data_authentic(&self, key: &Key, data: &[u8], tag: &[u8]) -> bool {
        key.check(&[b"D", self.mac(), data], tag)
    }

    /// The longest Data the request's Kind allows, `up` for UP and 0 for a
    /// Kind the binding does not define.
    pub(crate) fn data_limit(&self, up: usize) -> usize {
        match Kind::from_byte(self.kind) {
            Some(Kind::Up) => up,
            Some(Kind::Down) => 0,
            Some(Kind::Close) => MAX_REASON,
            // An undefined Kind carries no Data: one with none is
            // authenticated, and then malformed.
            None => 0,
        }
    }

    /// The request's kind, or `None` when its Kind, Flags, Sequence or
    /// `data` break the rules of the binding.
    pub(crate) fn valid_kind(&self, data: &[u8]) -> Option<Kind> {
        let kind = Kind::from_byte(self.kind)?;
        let valid = match kind {
            Kind::Up => self.flags & !REQ_FIN == 0,
            Kind::Down => self.flags == 0 && data.is_empty(),
            Kind::Close => {
                self.flags == 0
                    && self.seq == 0
                    && data.len() <= MAX_REASON
                    && std::str::from_utf8(data).is_ok()
            }
        };
        valid.then_some(kind)
    }

    /// What a response to this request is bound to.
    pub(crate) fn answering(&self) -> Answering<'_> {
        Answering {
            cid: &self.cid,
            kind: self.kind,
            seq: self.seq,
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
    /// of `kind` are valid; a response that is not fails the
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

/// An HTTP body of the binary body made of `parts`, in `encoding`: the
/// parts as they are, or their base64 form in the first part.
pub(crate) fn encode_body<const N: usize>(encoding: BodyEncoding, parts: [Bytes; N]) -> [Bytes; N] {
    match encoding {
        BodyEncoding::Binary => parts,
        BodyEncoding::Base64 => {
            let mut bin = Vec::with_capacity(parts.iter().map(Bytes::len).sum());
            for p in &parts {
                bin.extend_from_slice(p);
            }
            let mut out: [Bytes; N] = std::array::from_fn(|_| Bytes::new());
            if let Some(first) = out.first_mut() {
                *first = Bytes::from(BASE64.encode(bin));
            }
            out
        }
    }
}

/// The binary form of `body`, in `encoding`: a whole HTTP body, or a part
/// of one that starts at a multiple of 4 characters in base64.
pub(crate) fn decode_body(encoding: BodyEncoding, body: Bytes) -> Option<Bytes> {
    match encoding {
        BodyEncoding::Binary => Some(body),
        BodyEncoding::Base64 => BASE64.decode(&body).ok().map(Bytes::from),
    }
}

/// Decodes base64 `encoded` into `out` without allocating: the length
/// decoded, or `None` when it is not base64 or does not fit.
pub(crate) fn decode_base64_into(encoded: &[u8], out: &mut [u8]) -> Option<usize> {
    BASE64.decode_slice(encoded, out).ok()
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

    #[test]
    fn base64_decodes_into_a_slice() {
        let mut out = [0; HEADER_LEN];
        let bin: Vec<u8> = (0..HEADER_LEN as u8).collect();
        let enc = BASE64.encode(&bin);
        assert_eq!(
            decode_base64_into(enc.as_bytes(), &mut out),
            Some(HEADER_LEN)
        );
        assert_eq!(out[..], bin[..]);
        // Too long for the slice, or not base64.
        let long = BASE64.encode([0; HEADER_LEN + 3]);
        assert_eq!(decode_base64_into(long.as_bytes(), &mut out), None);
        assert_eq!(decode_base64_into(&[b'!'; 88], &mut out), None);
    }

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    use zmux::util::hex as to_hex;

    const CID: CarrierId = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
    const NONCE: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
    const TIME: u32 = 1_767_225_600;

    /// A received request body as the server takes it apart: its header,
    /// then its Data and Data MAC, both MACs checked, then its kind.
    fn verify(key: &Key, body: &[u8]) -> Result<(Header, Kind), &'static str> {
        let h = Header::parse(body[..HEADER_LEN].try_into().unwrap());
        if !h.authentic(key) {
            return Err("header mac");
        }
        if body.len() != REQUEST_OVERHEAD + h.data_len as usize {
            return Err("length");
        }
        let (data, tag) = body[HEADER_LEN..].split_at(h.data_len as usize);
        if !h.data_authentic(key, data, tag) {
            return Err("data mac");
        }
        let kind = h.valid_kind(data).ok_or("invalid")?;
        Ok((h, kind))
    }

    fn body(out: &Outgoing, data: &[u8]) -> Vec<u8> {
        [&out.header[..], data, &out.data_mac[..]].concat()
    }

    /// The test vectors of the binding: both requests and both responses
    /// as each side builds them, and as the other parses and verifies
    /// them.
    #[test]
    fn test_vectors() {
        let cases = [
            (
                Vec::new(),
                "8e08f7810b828921459c8d8c4f1be67963269408f5e7179f7f0df94d417723ef",
                "000102030405060708090a0b0c0d0e0f0100000000000000000000000000000000006955b90001020304050607080000000500178e3775404d528a25094a591bf36468656c6c6fdd1ab741da654edc8e365e51e9f7ebe6",
                "cf0b72020d0c5d8827e1131a6ad3ff8300",
                "000102030405060708090a0b0c0d0e0f0200000000000000012c000000000000012b6955b9000102030405060708000000000f8a9597942e2aeca56c93dd9cd643a2ba220cca8f1bbd9f8cdb4b22b0265607",
                "19df1f7aab49142d7b4919e2cd68942701776f726c64",
            ),
            (
                vec![0x6b; 32],
                "68489b10ee27b348be274432395cb2107dcfc8cf3f9f69f2cd4cf7cd7a0f8c95",
                "000102030405060708090a0b0c0d0e0f0100000000000000000000000000000000006955b9000102030405060708000000055a69b4f32b1258b63968abe73831a16d68656c6c6fa9d13425b6115dfcf7677ee22d70535c",
                "58696a7a658e71acfa63777f9655fbdb00",
                "000102030405060708090a0b0c0d0e0f0200000000000000012c000000000000012b6955b900010203040506070800000000b3f9c1b72105e61b0331705b811d47d29afea042a48e16233bfc597f178a49c5",
                "52774f4b737d7bd0a5f69989ff1fafd001776f726c64",
            ),
        ];
        for (psk, k, up, up_r, down, down_r) in cases {
            // The carrier key.
            assert_eq!(to_hex(&HmacSha256::new(&psk).mac(&[KEY_LABEL, &CID])), k);
            let key = Key::new(&psk, &CID);

            // The client's requests.
            let up_out = Outgoing::new(&key, &CID, Kind::Up, 0, 0, 0, TIME, NONCE, b"hello");
            assert_eq!(to_hex(&body(&up_out, b"hello")), up);
            let down_out = Outgoing::new(&key, &CID, Kind::Down, 0, 300, 299, TIME, NONCE, b"");
            assert_eq!(to_hex(&body(&down_out, b"")), down);

            // The server takes them apart and answers.
            let (h, kind) = verify(&key, &hex(up)).unwrap();
            assert_eq!(kind, Kind::Up);
            assert_eq!((h.seq, h.ack, h.data_len), (0, 0, 5));
            let head = response_head(&key, &h.answering(), 0, b"");
            assert_eq!(to_hex(&head), up_r);
            let (h, kind) = verify(&key, &hex(down)).unwrap();
            assert_eq!(kind, Kind::Down);
            assert_eq!((h.seq, h.ack, h.time), (300, 299, TIME));
            let head = response_head(&key, &h.answering(), FIN, b"world");
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
        let first = Outgoing::new(&key, &CID, Kind::Down, 0, 7, 7, TIME, NONCE, b"");
        let (req, _) = verify(&key, &body(&first, b"")).unwrap();
        let mut cached = BytesMut::new();
        cached.put(response_head(&key, &req.answering(), 0, b"stale"));
        cached.put_slice(b"stale");
        let cached = Response::parse(cached.freeze()).unwrap();
        // The genuine answer verifies.
        assert!(first.verifies(&key, &CID, Kind::Down, &cached));
        // Replayed to a repetition of the same piece (new nonce), or to
        // another piece: valid in form, rejected by the MAC.
        let again = Outgoing::new(&key, &CID, Kind::Down, 0, 7, 7, TIME, [9; 8], b"");
        let other = Outgoing::new(&key, &CID, Kind::Down, 0, 8, 7, TIME, NONCE, b"");
        assert!(cached.valid_for(Kind::Down));
        assert!(!again.verifies(&key, &CID, Kind::Down, &cached));
        assert!(!other.verifies(&key, &CID, Kind::Down, &cached));
        // Another carrier's key, and a key from another PSK.
        let mut cid2 = CID;
        cid2[0] ^= 1;
        assert!(!first.verifies(&Key::new(b"", &cid2), &cid2, Kind::Down, &cached));
        assert!(!first.verifies(&Key::new(b"x", &CID), &CID, Kind::Down, &cached));
    }

    /// The Header MAC covers every header field, the Data MAC the Data and
    /// the header it follows.
    #[test]
    fn macs_bind_header_and_data() {
        let key = Key::new(b"", &CID);
        let out = Outgoing::new(&key, &CID, Kind::Up, 0, 0, 0, TIME, NONCE, b"a");
        let good = body(&out, b"a");
        assert!(verify(&key, &good).is_ok());
        for at in 0..HEADER_LEN {
            let mut b = good.clone();
            b[at] ^= 1;
            assert_eq!(verify(&key, &b).err(), Some("header mac"), "{at}");
        }
        // Rewritten Data, or a Data MAC of another header.
        let mut b = good.clone();
        b[HEADER_LEN] ^= 1;
        assert_eq!(verify(&key, &b).err(), Some("data mac"));
        let other = Outgoing::new(&key, &CID, Kind::Up, 0, 0, 0, TIME, [7; 8], b"a");
        let mut b = good.clone();
        b[HEADER_LEN + 1..].copy_from_slice(&other.data_mac);
        assert_eq!(verify(&key, &b).err(), Some("data mac"));
    }

    /// Requests that verify but break the rules, and response flags.
    #[test]
    fn validation() {
        let key = Key::new(b"", &CID);
        let req = |kind: u8, flags: u8, seq: u64, data: &[u8]| {
            let mut h = BytesMut::new();
            h.put_slice(&CID);
            h.put_u8(kind);
            h.put_u8(flags);
            h.put_u64(seq);
            h.put_u64(0);
            h.put_u32(TIME);
            h.put_slice(&NONCE);
            h.put_u32(data.len() as u32);
            let tag = key.tag(&[b"Q", &h]);
            h.put_slice(&tag);
            let dtag = key.tag(&[b"D", &tag, data]);
            h.put_slice(data);
            h.put_slice(&dtag);
            verify(&key, &h).map(|(_, k)| k)
        };
        assert_eq!(req(1, 1, 3, b"x"), Ok(Kind::Up));
        assert_eq!(req(1, 2, 3, b"x"), Err("invalid"));
        assert_eq!(req(2, 0, 3, b""), Ok(Kind::Down));
        assert_eq!(req(2, 1, 3, b""), Err("invalid"));
        assert_eq!(req(2, 0, 3, b"x"), Err("invalid"));
        assert_eq!(req(3, 0, 0, b"bye"), Ok(Kind::Close));
        assert_eq!(req(3, 0, 1, b"bye"), Err("invalid"));
        assert_eq!(req(3, 0, 0, &[0xff]), Err("invalid"));
        assert_eq!(req(3, 0, 0, &[b'a'; MAX_REASON + 1]), Err("invalid"));
        assert_eq!(req(4, 0, 0, b""), Err("invalid"));

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
        let [h, t] = encode_body(
            BodyEncoding::Base64,
            [Bytes::from_static(b"he"), Bytes::from_static(b"llo")],
        );
        assert!(t.is_empty());
        assert_eq!(&h[..], b"aGVsbG8=");
        assert_eq!(encoded_len(BodyEncoding::Base64, 5), h.len());
        assert_eq!(&decode_body(BodyEncoding::Base64, h).unwrap()[..], b"hello");
        assert!(decode_body(BodyEncoding::Base64, Bytes::from_static(b"aGVsbG8")).is_none());
        // The header is whole base64 groups: it decodes on its own.
        assert_eq!(encoded_len(BodyEncoding::Base64, HEADER_LEN), 88);
        assert_eq!(HEADER_LEN % 3, 0);
    }
}
