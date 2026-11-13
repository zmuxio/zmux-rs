//! The classification of requests on a unified endpoint: which carrier a
//! request is, from its head alone, before any body byte is read. The one
//! place that decides it, for this adapter's server and for endpoints that
//! also serve WebSocket and WebTransport.

use std::io;

use http::header::{CONTENT_LENGTH, HeaderName, UPGRADE};
use http::{HeaderMap, Method, Version};

/// The request field that pairs the uplink `POST` and the downlink `GET`
/// of a split bootstrap: [`zmux::PAIR_HEADER`] by default, another name
/// only where an intermediary strips unknown fields. Both ends must use
/// the same ([`crate::Options::pair_field`]).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PairField(HeaderName);

/// Fields with a meaning of their own that a pairing field must not take
/// over (lower case); prefixes in [`RESERVED_PREFIXES`].
const RESERVED: &[&str] = &[
    "content-length",
    "content-type",
    "content-encoding",
    "transfer-encoding",
    "host",
    "connection",
    "upgrade",
    "keep-alive",
    "te",
    "trailer",
    "authorization",
    "cookie",
    "expect",
    "date",
    "early-data",
    "forwarded",
    "via",
    "location",
    "origin",
];
const RESERVED_PREFIXES: &[&str] = &["proxy-", "sec-websocket-", "x-forwarded-"];

impl PairField {
    /// The field `name`: a header field name that no protocol field of
    /// HTTP, WebSocket or the adapters uses ([`io::ErrorKind::InvalidInput`]
    /// otherwise).
    pub fn new(name: &str) -> io::Result<Self> {
        let invalid = |why| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("pairing field {name:?} {why}"),
            )
        };
        let field = HeaderName::from_bytes(name.as_bytes())
            .map_err(|_| invalid("is not a header field name"))?;
        let l = field.as_str();
        if RESERVED.contains(&l)
            || l.eq_ignore_ascii_case(zmux::PREFIX_AUTH_HEADER)
            || RESERVED_PREFIXES.iter().any(|p| l.starts_with(p))
        {
            return Err(invalid("is reserved"));
        }
        Ok(Self(field))
    }

    /// The field's name.
    pub fn name(&self) -> &HeaderName {
        &self.0
    }
}

impl Default for PairField {
    fn default() -> Self {
        Self(HeaderName::from_static("zmux-pipe-pair"))
    }
}

/// The carrier a request is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum RequestClass {
    /// A WebSocket opening handshake: `GET` with `Upgrade: websocket` on
    /// HTTP/1.1, or extended `CONNECT` with `:protocol` `websocket`.
    WebSocket,
    /// An extended `CONNECT` with `:protocol` `webtransport-h3` or
    /// `webtransport`.
    WebTransport,
    /// A `GET` with the pairing field ([`PairField`]): its response body
    /// is the downlink.
    Downlink,
    /// A `POST` with the pairing field (a split bootstrap's uplink): its
    /// request body is the uplink.
    Uplink,
    /// A `POST` with a `Content-Length`: an exchange request.
    Exchange,
    /// A `POST` without a `Content-Length`: the request body is the uplink
    /// and the response body the downlink.
    Bidirectional,
}

impl RequestClass {
    /// Whether the request's carrier is decided on its head alone, without
    /// a prefix of its body: the upgrades and the downlink `GET` (a
    /// credential travels in a header field).
    pub fn head_decided(self) -> bool {
        matches!(self, Self::WebSocket | Self::WebTransport | Self::Downlink)
    }
}

/// The class of a request with this head (the first rule that matches), or
/// `None` for a request that is no carrier and goes to the host's handler.
/// `protocol` is the `:protocol` pseudo-header of an extended `CONNECT`
/// (HTTP/2, HTTP/3); `pair` the pairing field.
pub fn classify_head(
    method: &Method,
    version: Version,
    headers: &HeaderMap,
    protocol: Option<&str>,
    pair: &PairField,
) -> Option<RequestClass> {
    let pair = headers.contains_key(pair.name());
    if *method == Method::CONNECT {
        return match protocol {
            Some(p) if p.eq_ignore_ascii_case("websocket") => Some(RequestClass::WebSocket),
            Some(p)
                if p.eq_ignore_ascii_case("webtransport")
                    || p.eq_ignore_ascii_case("webtransport-h3") =>
            {
                Some(RequestClass::WebTransport)
            }
            _ => None,
        };
    }
    if *method == Method::GET {
        if version <= Version::HTTP_11
            && tokens(headers, UPGRADE).any(|t| t.eq_ignore_ascii_case("websocket"))
        {
            return Some(RequestClass::WebSocket);
        }
        return pair.then_some(RequestClass::Downlink);
    }
    if *method != Method::POST {
        return None;
    }
    if pair {
        return Some(RequestClass::Uplink);
    }
    if headers.contains_key(CONTENT_LENGTH) {
        return Some(RequestClass::Exchange);
    }
    Some(RequestClass::Bidirectional)
}

/// [`classify_head`] of a request as hyper gives it: the extended
/// `CONNECT`'s `:protocol` is hyper's `Protocol` extension.
pub fn classify(parts: &http::request::Parts, pair: &PairField) -> Option<RequestClass> {
    let protocol = parts
        .extensions
        .get::<hyper::ext::Protocol>()
        .map(hyper::ext::Protocol::as_str);
    classify_head(&parts.method, parts.version, &parts.headers, protocol, pair)
}

/// Whether an intermediary forwarded the request from TLS early data
/// (`Early-Data: 1`, RFC 8470): [`zmux::forwarded_early_data`] of its
/// header fields. A carrier request with it is answered `425 (Too Early)`
/// and given to no listener.
pub fn forwarded_early_data(headers: &HeaderMap) -> bool {
    zmux::forwarded_early_data(headers.iter().map(|(n, v)| (n.as_str(), v.as_bytes())))
}

/// The comma-separated tokens of every `name` field.
fn tokens(headers: &HeaderMap, name: http::header::HeaderName) -> impl Iterator<Item = &str> {
    headers
        .get_all(name)
        .into_iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .map(str::trim)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn class(method: Method, version: Version, fields: &[(&str, &str)]) -> Option<RequestClass> {
        let mut h = HeaderMap::new();
        for (n, v) in fields {
            h.append(
                http::header::HeaderName::from_bytes(n.as_bytes()).unwrap(),
                v.parse().unwrap(),
            );
        }
        classify_head(&method, version, &h, None, &PairField::default())
    }

    #[test]
    fn rules_in_order() {
        use RequestClass as C;
        let v11 = Version::HTTP_11;
        let pair = ("zmux-pipe-pair", "AAECAwQFBgcICQoLDA0ODw");
        let cl = ("content-length", "10");
        // 1: a WebSocket upgrade, even with the other fields.
        assert_eq!(
            class(
                Method::GET,
                v11,
                &[("connection", "Upgrade"), ("upgrade", "WebSocket"), pair]
            ),
            Some(C::WebSocket)
        );
        // Not on HTTP/2, where the upgrade is an extended CONNECT.
        assert_eq!(
            class(Method::GET, Version::HTTP_2, &[("upgrade", "websocket")]),
            None
        );
        let h = HeaderMap::new();
        assert_eq!(
            classify_head(
                &Method::CONNECT,
                Version::HTTP_2,
                &h,
                Some("websocket"),
                &PairField::default()
            ),
            Some(C::WebSocket)
        );
        // 2.
        for p in ["webtransport", "webtransport-h3"] {
            assert_eq!(
                classify_head(
                    &Method::CONNECT,
                    Version::HTTP_3,
                    &h,
                    Some(p),
                    &PairField::default()
                ),
                Some(C::WebTransport)
            );
        }
        assert_eq!(
            classify_head(
                &Method::CONNECT,
                Version::HTTP_2,
                &h,
                None,
                &PairField::default()
            ),
            None
        );
        // 3.
        assert_eq!(class(Method::GET, v11, &[pair]), Some(C::Downlink));
        // 4: before the Content-Length rule.
        assert_eq!(class(Method::POST, v11, &[pair, cl]), Some(C::Uplink));
        // 5.
        assert_eq!(class(Method::POST, v11, &[cl]), Some(C::Exchange));
        // 6.
        assert_eq!(
            class(Method::POST, v11, &[("transfer-encoding", "chunked")]),
            Some(C::Bidirectional)
        );
        // 7.
        assert_eq!(class(Method::GET, v11, &[]), None);
        assert_eq!(class(Method::PUT, v11, &[pair]), None);
        assert!(C::Downlink.head_decided() && !C::Uplink.head_decided());
    }

    #[test]
    fn pair_field() {
        assert_eq!(
            PairField::default().name().as_str(),
            zmux::PAIR_HEADER.to_ascii_lowercase()
        );
        let x = PairField::new("X-Pair").unwrap();
        let mut h = HeaderMap::new();
        h.insert("x-pair", "t".parse().unwrap());
        assert_eq!(
            classify_head(&Method::GET, Version::HTTP_11, &h, None, &x),
            Some(RequestClass::Downlink)
        );
        // Not paired by the default field then.
        assert_eq!(
            class(Method::GET, Version::HTTP_11, &[("x-pair", "t")]),
            None
        );
        for bad in [
            "",
            "a b",
            "Content-Length",
            "Sec-WebSocket-Key",
            "X-Forwarded-For",
            "zmux-prefix-auth",
        ] {
            assert!(PairField::new(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn early_data() {
        let mut h = HeaderMap::new();
        assert!(!forwarded_early_data(&h));
        h.insert("early-data", "1".parse().unwrap());
        assert!(forwarded_early_data(&h));
        h.insert("early-data", "0".parse().unwrap());
        assert!(!forwarded_early_data(&h));
    }
}
