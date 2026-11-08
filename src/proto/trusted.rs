//! Trusted intermediaries: behind a reverse proxy, load balancer or CDN
//! that the listener is configured to trust, a carrier's source is the
//! client address that intermediary reports, taken from the PROXY
//! protocol header of a TCP connection or from a forwarding header field
//! of an HTTP carrier. A report from any other peer is ignored, so that
//! a client cannot choose its own source.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// The intermediaries a listener trusts, and how they report the client:
/// part of [`crate::ListenerConfig`]. Nothing is trusted by default.
///
/// ```
/// use zmux::TrustedProxies;
///
/// let trusted = TrustedProxies::new()
///     .with_net("10.0.0.0/8".parse().unwrap())
///     .with_forwarded_header("X-Forwarded-For");
/// assert!(trusted.trusts("10.1.2.3".parse().unwrap()));
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct TrustedProxies {
    nets: Vec<IpNet>,
    header: Option<String>,
    proxy_protocol: bool,
}

impl TrustedProxies {
    /// Trusts nobody.
    pub fn new() -> Self {
        Self::default()
    }

    /// Also trusts the addresses of `net`.
    #[must_use]
    pub fn with_net(mut self, net: IpNet) -> Self {
        self.nets.push(net);
        self
    }

    /// HTTP carriers from a trusted address report their client in the
    /// request header field `name`: `Forwarded` (RFC 7239, its `for`
    /// parameters), or a comma-separated list of addresses such as
    /// `X-Forwarded-For`, each hop appending the address it received the
    /// request from (none by default).
    #[must_use]
    pub fn with_forwarded_header(mut self, name: impl Into<String>) -> Self {
        self.header = Some(name.into());
        self
    }

    /// TCP connections from a trusted address start with a PROXY protocol
    /// header (version 1 or 2), which reports the client; a connection from
    /// a trusted address without a valid header is closed (off by
    /// default).
    #[must_use]
    pub fn with_proxy_protocol(mut self, on: bool) -> Self {
        self.proxy_protocol = on;
        self
    }

    /// The trusted networks.
    pub fn nets(&self) -> &[IpNet] {
        &self.nets
    }

    /// The forwarding header field, if HTTP carriers report their client
    /// in one.
    pub fn forwarded_header(&self) -> Option<&str> {
        self.header.as_deref()
    }

    /// Whether trusted TCP connections start with a PROXY protocol header.
    pub fn proxy_protocol(&self) -> bool {
        self.proxy_protocol
    }

    /// Whether `addr` (an IPv4-mapped address as its IPv4 address) is
    /// trusted.
    pub fn trusts(&self, addr: IpAddr) -> bool {
        let addr = addr.to_canonical();
        self.nets.iter().any(|n| n.contains(addr))
    }

    /// The source of an HTTP request that arrived from `peer`, with the
    /// values of its request header fields `fields` (`(name, value)`, in
    /// order): `peer` itself unless it is trusted and the configured
    /// forwarding field reports a client. The reported hops are read from
    /// the last one back: every trusted address is skipped, and the first
    /// other one is the client. A hop that is not an address (`unknown`,
    /// a node name that is not an IP address) ends the walk at the trusted hop that
    /// reported it; when every hop is trusted, the first is the client. A
    /// reported port is kept; without one the port is 0.
    pub fn source<'a>(
        &self,
        peer: SocketAddr,
        fields: impl IntoIterator<Item = (&'a str, &'a [u8])>,
    ) -> SocketAddr {
        let Some(name) = self.header.as_deref() else {
            return peer;
        };
        if !self.trusts(peer.ip()) {
            return peer;
        }
        let rfc7239 = name.eq_ignore_ascii_case("forwarded");
        let mut hops: Vec<Option<SocketAddr>> = Vec::new();
        for (n, v) in fields {
            if !n.eq_ignore_ascii_case(name) {
                continue;
            }
            let Ok(v) = std::str::from_utf8(v) else {
                // A value that is not text reports nothing usable.
                hops.push(None);
                continue;
            };
            for element in v.split(',') {
                let element = element.trim();
                if element.is_empty() {
                    continue;
                }
                hops.push(if rfc7239 {
                    forwarded_for(element)
                } else {
                    parse_node(element)
                });
            }
        }
        let mut source = peer;
        for hop in hops.iter().rev() {
            match hop {
                Some(a) if self.trusts(a.ip()) => source = *a,
                Some(a) => return *a,
                None => return source,
            }
        }
        source
    }
}

/// Whether an intermediary forwarded an HTTP request from TLS early data,
/// given the request's header fields (`(name, value)`): one of them is
/// `Early-Data: 1` (RFC 8470). An adapter answers such a carrier request
/// `425 (Too Early)` before any admission and takes no carrier from it.
///
/// ```
/// let fields = [("early-data", &b"1"[..])];
/// assert!(zmux::forwarded_early_data(fields));
/// assert!(!zmux::forwarded_early_data([("early-data", &b"0"[..])]));
/// ```
pub fn forwarded_early_data<'a>(fields: impl IntoIterator<Item = (&'a str, &'a [u8])>) -> bool {
    fields
        .into_iter()
        .any(|(n, v)| n.eq_ignore_ascii_case("early-data") && v.trim_ascii() == b"1")
}

/// The `for` parameter of one element of a `Forwarded` field (RFC 7239
/// Section 4), as an address.
fn forwarded_for(element: &str) -> Option<SocketAddr> {
    for pair in element.split(';') {
        let (k, v) = pair.trim().split_once('=')?;
        if k.trim().eq_ignore_ascii_case("for") {
            let v = v.trim();
            let v = v
                .strip_prefix('"')
                .and_then(|v| v.strip_suffix('"'))
                .unwrap_or(v);
            return parse_node(v);
        }
    }
    None
}

/// An address, with or without a port: `192.0.2.1`, `192.0.2.1:80`,
/// `2001:db8::1`, `[2001:db8::1]`, `[2001:db8::1]:80`.
fn parse_node(s: &str) -> Option<SocketAddr> {
    if let Ok(a) = s.parse::<SocketAddr>() {
        return Some(a);
    }
    let bare = s
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(s);
    bare.parse::<IpAddr>().ok().map(|ip| SocketAddr::new(ip, 0))
}

/// A network: an address and a prefix length.
///
/// ```
/// let net: zmux::IpNet = "2001:db8::/32".parse().unwrap();
/// assert!(net.contains("2001:db8::1".parse().unwrap()));
/// // A bare address is a network of one.
/// let one: zmux::IpNet = "192.0.2.7".parse().unwrap();
/// assert_eq!(one.prefix(), 32);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct IpNet {
    addr: IpAddr,
    prefix: u8,
}

/// A network that does not parse, or whose prefix is longer than its
/// address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidNet;

impl std::fmt::Display for InvalidNet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("invalid network: expected an address with an optional /prefix")
    }
}

impl std::error::Error for InvalidNet {}

impl IpNet {
    /// The network of `addr` with `prefix` leading bits (an IPv4-mapped
    /// address as its IPv4 address).
    pub fn new(addr: IpAddr, prefix: u8) -> Result<Self, InvalidNet> {
        let addr = addr.to_canonical();
        let max = if addr.is_ipv4() { 32 } else { 128 };
        if prefix > max {
            return Err(InvalidNet);
        }
        Ok(Self { addr, prefix })
    }

    /// The network's address.
    pub fn addr(&self) -> IpAddr {
        self.addr
    }

    /// The prefix length.
    pub fn prefix(&self) -> u8 {
        self.prefix
    }

    /// Whether `addr` is in the network.
    pub fn contains(&self, addr: IpAddr) -> bool {
        match (self.addr, addr.to_canonical()) {
            (IpAddr::V4(n), IpAddr::V4(a)) => {
                masked(u128::from(n.to_bits()) << 96, self.prefix)
                    == masked(u128::from(a.to_bits()) << 96, self.prefix)
            }
            (IpAddr::V6(n), IpAddr::V6(a)) => {
                masked(n.to_bits(), self.prefix) == masked(a.to_bits(), self.prefix)
            }
            _ => false,
        }
    }
}

/// The first `prefix` bits of `bits`.
fn masked(bits: u128, prefix: u8) -> u128 {
    if prefix == 0 {
        0
    } else {
        bits & (u128::MAX << (128 - u32::from(prefix)))
    }
}

impl std::str::FromStr for IpNet {
    type Err = InvalidNet;

    fn from_str(s: &str) -> Result<Self, InvalidNet> {
        let (a, p) = match s.split_once('/') {
            Some((a, p)) => (a, Some(p)),
            None => (s, None),
        };
        let addr: IpAddr = a.trim().parse().map_err(|_| InvalidNet)?;
        let full = if addr.to_canonical().is_ipv4() {
            32
        } else {
            128
        };
        let prefix = match p {
            Some(p) => p.trim().parse::<u8>().map_err(|_| InvalidNet)?,
            None => full,
        };
        // A mapped address with a prefix counts its IPv4 bits.
        let prefix = if addr.is_ipv6() && addr.to_canonical().is_ipv4() && p.is_some() {
            prefix.checked_sub(96).ok_or(InvalidNet)?
        } else {
            prefix
        };
        Self::new(addr, prefix)
    }
}

impl std::fmt::Display for IpNet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix)
    }
}

/// The longest PROXY protocol version 1 header (its specification, Section
/// 2.1): 107 bytes.
pub const PROXY_V1_MAX: usize = 107;
/// The fixed part of a PROXY protocol version 2 header: 16 bytes.
pub const PROXY_V2_HEAD: usize = 16;
const PROXY_V2_SIG: &[u8; 12] = b"\r\n\r\n\0\r\nQUIT\n";

/// What the start of a connection holds of a PROXY protocol header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyHeader {
    /// More bytes are needed: at least this many in all.
    Incomplete(usize),
    /// Not a valid header.
    Invalid,
    /// A header of `len` bytes; `source` is the client it reports, `None`
    /// for a connection of the intermediary's own (version 2 `LOCAL`,
    /// version 1 `UNKNOWN`) or an address family without one.
    Complete {
        /// The header's length.
        len: usize,
        /// The reported client.
        source: Option<SocketAddr>,
    },
}

/// Parses the PROXY protocol header (version 1 or 2) at the start of
/// `buf`. Never reads beyond the header: a caller that reads exactly the
/// bytes [`ProxyHeader::Incomplete`] asks for consumes nothing after it.
pub fn parse_proxy_header(buf: &[u8]) -> ProxyHeader {
    // Enough to tell the versions apart: "PROXY " or the first bytes of
    // the version 2 signature.
    if buf.len() < 6 {
        return ProxyHeader::Incomplete(6);
    }
    if buf.starts_with(b"PROXY ") {
        return parse_v1(buf);
    }
    if !PROXY_V2_SIG.starts_with(&buf[..buf.len().min(12)]) {
        return ProxyHeader::Invalid;
    }
    if buf.len() < PROXY_V2_HEAD {
        return ProxyHeader::Incomplete(PROXY_V2_HEAD);
    }
    let (ver_cmd, fam) = (buf[12], buf[13]);
    let len = PROXY_V2_HEAD + usize::from(u16::from_be_bytes([buf[14], buf[15]]));
    if ver_cmd >> 4 != 2 || ver_cmd & 0x0f > 1 {
        return ProxyHeader::Invalid;
    }
    if buf.len() < len {
        return ProxyHeader::Incomplete(len);
    }
    let body = &buf[PROXY_V2_HEAD..len];
    if ver_cmd & 0x0f == 0 {
        // LOCAL: the intermediary's own connection.
        return ProxyHeader::Complete { len, source: None };
    }
    let source = match fam >> 4 {
        1 if body.len() >= 12 => {
            let ip = Ipv4Addr::new(body[0], body[1], body[2], body[3]);
            Some(SocketAddr::new(
                ip.into(),
                u16::from_be_bytes([body[8], body[9]]),
            ))
        }
        2 if body.len() >= 36 => {
            let mut a = [0u8; 16];
            a.copy_from_slice(&body[..16]);
            Some(SocketAddr::new(
                Ipv6Addr::from(a).into(),
                u16::from_be_bytes([body[32], body[33]]),
            ))
        }
        1 | 2 => return ProxyHeader::Invalid,
        // AF_UNSPEC or AF_UNIX: no address of the client.
        _ => None,
    };
    ProxyHeader::Complete { len, source }
}

fn parse_v1(buf: &[u8]) -> ProxyHeader {
    let Some(end) = buf.windows(2).position(|w| w == b"\r\n") else {
        return if buf.len() >= PROXY_V1_MAX {
            ProxyHeader::Invalid
        } else {
            // A version 1 header is read up to its end of line.
            ProxyHeader::Incomplete(buf.len() + 1)
        };
    };
    let len = end + 2;
    if len > PROXY_V1_MAX {
        return ProxyHeader::Invalid;
    }
    let Ok(line) = std::str::from_utf8(&buf[6..end]) else {
        return ProxyHeader::Invalid;
    };
    let mut parts = line.split(' ');
    match parts.next() {
        Some("UNKNOWN") => ProxyHeader::Complete { len, source: None },
        Some(proto @ ("TCP4" | "TCP6")) => {
            let (Some(src), Some(_dst), Some(sport), Some(_dport), None) = (
                parts.next(),
                parts.next(),
                parts.next(),
                parts.next(),
                parts.next(),
            ) else {
                return ProxyHeader::Invalid;
            };
            let ip: Option<IpAddr> = if proto == "TCP4" {
                src.parse::<Ipv4Addr>().ok().map(Into::into)
            } else {
                src.parse::<Ipv6Addr>().ok().map(Into::into)
            };
            match (ip, sport.parse::<u16>()) {
                (Some(ip), Ok(port)) => ProxyHeader::Complete {
                    len,
                    source: Some(SocketAddr::new(ip, port)),
                },
                _ => ProxyHeader::Invalid,
            }
        }
        _ => ProxyHeader::Invalid,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn trusted() -> TrustedProxies {
        TrustedProxies::new()
            .with_net("10.0.0.0/8".parse().unwrap())
            .with_net("2001:db8::/32".parse().unwrap())
    }

    #[test]
    fn nets() {
        let t = trusted();
        assert!(t.trusts("10.255.0.1".parse().unwrap()));
        assert!(t.trusts("::ffff:10.0.0.1".parse().unwrap()));
        assert!(!t.trusts("11.0.0.1".parse().unwrap()));
        assert!(t.trusts("2001:db8:1::1".parse().unwrap()));
        assert!(!t.trusts("2001:db9::1".parse().unwrap()));
        assert!("10.0.0.0/33".parse::<IpNet>().is_err());
        assert!("x/8".parse::<IpNet>().is_err());
        let all: IpNet = "0.0.0.0/0".parse().unwrap();
        assert!(all.contains("1.2.3.4".parse().unwrap()));
        assert!(!all.contains("::1".parse().unwrap()));
        let mapped: IpNet = "::ffff:10.0.0.0/104".parse().unwrap();
        assert_eq!(mapped.prefix(), 8);
        assert!(mapped.contains("10.9.9.9".parse().unwrap()));
    }

    fn src(t: &TrustedProxies, peer: &str, fields: &[(&str, &str)]) -> String {
        t.source(
            peer.parse().unwrap(),
            fields.iter().map(|(n, v)| (*n, v.as_bytes())),
        )
        .to_string()
    }

    #[test]
    fn forwarded_for_lists() {
        let t = trusted().with_forwarded_header("X-Forwarded-For");
        let proxy = "10.0.0.1:443";
        // The client the trusted proxy appended.
        assert_eq!(
            src(&t, proxy, &[("x-forwarded-for", "192.0.2.9")]),
            "192.0.2.9:0"
        );
        // A client cannot choose its own source: the hop the trusted proxy
        // appended counts, not the one the client wrote.
        assert_eq!(
            src(
                &t,
                proxy,
                &[("x-forwarded-for", "1.1.1.1, 192.0.2.9"), ("other", "x")]
            ),
            "192.0.2.9:0"
        );
        // Trusted hops are skipped, over several fields.
        assert_eq!(
            src(
                &t,
                proxy,
                &[
                    ("X-Forwarded-For", "198.51.100.4"),
                    ("x-forwarded-for", "10.0.0.7")
                ]
            ),
            "198.51.100.4:0"
        );
        // An untrusted peer's report is ignored.
        assert_eq!(
            src(&t, "192.0.2.1:5", &[("x-forwarded-for", "10.0.0.2")]),
            "192.0.2.1:5"
        );
        // No field: the peer.
        assert_eq!(src(&t, proxy, &[]), proxy);
        // A hop that is not an address stops at the hop that reported it.
        assert_eq!(
            src(&t, proxy, &[("x-forwarded-for", "192.0.2.9, unknown")]),
            proxy
        );
        assert_eq!(
            src(&t, proxy, &[("x-forwarded-for", "[2001:db9::5]:8080")]),
            "[2001:db9::5]:8080"
        );
    }

    #[test]
    fn rfc7239() {
        let t = trusted().with_forwarded_header("Forwarded");
        assert_eq!(
            src(
                &t,
                "10.0.0.1:1",
                &[(
                    "forwarded",
                    "for=192.0.2.60;proto=http;by=203.0.113.43, for=\"[2001:db9::1]:4711\""
                )]
            ),
            "[2001:db9::1]:4711"
        );
        assert_eq!(
            src(&t, "10.0.0.1:1", &[("forwarded", "for=_hidden")]),
            "10.0.0.1:1"
        );
    }

    #[test]
    fn proxy_v1() {
        let h = b"PROXY TCP4 192.0.2.1 10.0.0.1 56324 443\r\nGET";
        assert_eq!(
            parse_proxy_header(h),
            ProxyHeader::Complete {
                len: h.len() - 3,
                source: Some("192.0.2.1:56324".parse().unwrap())
            }
        );
        let h = b"PROXY TCP6 2001:db8::1 2001:db8::2 1 2\r\n";
        assert!(matches!(
            parse_proxy_header(h),
            ProxyHeader::Complete {
                source: Some(_),
                ..
            }
        ));
        assert_eq!(
            parse_proxy_header(b"PROXY UNKNOWN\r\n"),
            ProxyHeader::Complete {
                len: 15,
                source: None
            }
        );
        assert_eq!(parse_proxy_header(b"PRO"), ProxyHeader::Incomplete(6));
        assert_eq!(
            parse_proxy_header(b"PROXY TCP4"),
            ProxyHeader::Incomplete(11)
        );
        assert_eq!(
            parse_proxy_header(b"PROXY TCP4 x y 1 2\r\n"),
            ProxyHeader::Invalid
        );
        assert_eq!(
            parse_proxy_header(b"GET / HTTP/1.1\r\n"),
            ProxyHeader::Invalid
        );
        assert_eq!(parse_proxy_header(&[b'P'; 200]), ProxyHeader::Invalid);
    }

    #[test]
    fn proxy_v2() {
        let mut h = PROXY_V2_SIG.to_vec();
        h.extend_from_slice(&[0x21, 0x11, 0, 12]);
        h.extend_from_slice(&[192, 0, 2, 1, 10, 0, 0, 1, 0x1f, 0x90, 1, 187]);
        assert_eq!(
            parse_proxy_header(&h[..10]),
            ProxyHeader::Incomplete(PROXY_V2_HEAD)
        );
        assert_eq!(parse_proxy_header(&h[..16]), ProxyHeader::Incomplete(28));
        assert_eq!(
            parse_proxy_header(&h),
            ProxyHeader::Complete {
                len: 28,
                source: Some("192.0.2.1:8080".parse().unwrap())
            }
        );
        // LOCAL.
        let mut l = PROXY_V2_SIG.to_vec();
        l.extend_from_slice(&[0x20, 0x00, 0, 0]);
        assert_eq!(
            parse_proxy_header(&l),
            ProxyHeader::Complete {
                len: 16,
                source: None
            }
        );
        // Version 3, command 2.
        let mut bad = PROXY_V2_SIG.to_vec();
        bad.extend_from_slice(&[0x31, 0x11, 0, 0]);
        assert_eq!(parse_proxy_header(&bad), ProxyHeader::Invalid);
        let mut bad = PROXY_V2_SIG.to_vec();
        bad.extend_from_slice(&[0x22, 0x11, 0, 0]);
        assert_eq!(parse_proxy_header(&bad), ProxyHeader::Invalid);
        // A short address block.
        let mut short = PROXY_V2_SIG.to_vec();
        short.extend_from_slice(&[0x21, 0x11, 0, 4, 1, 2, 3, 4]);
        assert_eq!(parse_proxy_header(&short), ProxyHeader::Invalid);
    }
}
