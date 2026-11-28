//! Request-head handling for the HTTP and WebSocket adapters.

use std::net::SocketAddr;

use http::{Extensions, HeaderMap, Method, Version};
use zmux::Listener;
use zmux::adapter::{Entry, RequestFallback, TrackRequestFallback};

/// How far a candidate WebSocket request satisfies the opening handshake.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WebSocket {
    /// An ordinary HTTP request.
    Other,
    /// The method and protocol name identify a WebSocket request, but
    /// required handshake fields are absent or have the wrong value.
    Incomplete,
    /// The adapter can proceed with subprotocol selection and admission.
    Opening,
}

/// Classifies the WebSocket request before subprotocol selection. Pass the
/// value of the extended CONNECT's `:protocol` pseudo-header if one was received.
#[must_use]
pub fn websocket(
    method: &Method,
    version: Version,
    headers: &HeaderMap,
    protocol: Option<&str>,
) -> WebSocket {
    let extended = *method == Method::CONNECT
        && matches!(version, Version::HTTP_2 | Version::HTTP_3)
        && protocol.is_some_and(|p| p.eq_ignore_ascii_case("websocket"));
    let upgrade = *method == Method::GET
        && version == Version::HTTP_11
        && tokens(headers, "upgrade").any(|t| t.eq_ignore_ascii_case("websocket"));
    if !extended && !upgrade {
        return WebSocket::Other;
    }
    let version_13 = headers
        .get("sec-websocket-version")
        .is_some_and(|v| v.as_bytes() == b"13");
    if version_13
        && (extended
            || (headers.contains_key("sec-websocket-key")
                && tokens(headers, "connection").any(|t| t.eq_ignore_ascii_case("upgrade"))))
    {
        WebSocket::Opening
    } else {
        WebSocket::Incomplete
    }
}

/// The comma-separated tokens of all fields with this name.
pub fn tokens<'a>(headers: &'a HeaderMap, name: &str) -> impl Iterator<Item = &'a str> {
    headers
        .get_all(name)
        .into_iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .map(str::trim)
}

/// The request was forwarded from TLS early data and requires a 425 response.
#[derive(Debug, Clone, Copy)]
pub struct TooEarly;

/// Checks a carrier head before taking a source slot. The peer is the
/// address of the trusted proxy, if one is present.
///
/// # Errors
///
/// Returns [`TooEarly`] and counts a setup failure for forwarded early data.
pub fn preprocess(
    listener: &Listener,
    headers: &HeaderMap,
    peer: SocketAddr,
) -> Result<SocketAddr, TooEarly> {
    if zmux::adapter::forwarded_early_data(headers) {
        listener.adapter().count_setup_failure();
        return Err(TooEarly);
    }
    Ok(listener.adapter().trusted_proxies().source(peer, headers))
}

/// Records that the HTTP router will decide whether a refused head is dispatched.
pub fn track_fallback(extensions: &mut Extensions) {
    extensions.insert(TrackRequestFallback);
}

/// Transfers a refusal to the HTTP router, or records it immediately for a
/// host that accepts returned requests directly.
pub fn return_fallback(entry: &mut Entry, extensions: &mut Extensions) {
    if extensions.get::<TrackRequestFallback>().is_some() {
        if let Some(outcome) = entry.request_fallback() {
            extensions.insert(outcome);
        }
    } else {
        entry.complete_request_fallback(true);
    }
}

/// Settles a returned request according to the HTTP router's dispatch decision.
pub fn finish_fallback(extensions: &mut Extensions, dispatched: bool) {
    extensions.remove::<TrackRequestFallback>();
    if let Some(outcome) = extensions.remove::<RequestFallback>() {
        outcome.complete(dispatched);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opening_requires_the_fields_of_its_transport() {
        let mut h = HeaderMap::new();
        h.append("upgrade", "other".parse().unwrap());
        h.append("upgrade", "websocket".parse().unwrap());
        h.insert("connection", "keep-alive, UPgrade".parse().unwrap());
        let classify =
            |headers: &HeaderMap| websocket(&Method::GET, Version::HTTP_11, headers, None);
        assert_eq!(classify(&h), WebSocket::Incomplete);
        h.insert("sec-websocket-version", "13".parse().unwrap());
        assert_eq!(classify(&h), WebSocket::Incomplete);
        assert_eq!(
            websocket(&Method::CONNECT, Version::HTTP_2, &h, Some("WebSocket")),
            WebSocket::Opening
        );
        h.insert("sec-websocket-key", "example".parse().unwrap());
        assert_eq!(classify(&h), WebSocket::Opening);
        assert_eq!(
            websocket(&Method::POST, Version::HTTP_11, &h, None),
            WebSocket::Other
        );
    }
}
