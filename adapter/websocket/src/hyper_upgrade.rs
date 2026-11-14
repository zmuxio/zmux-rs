//! WebSocket upgrades of requests that a hyper server received: the
//! HTTP/1.1 Upgrade (RFC 6455) and the extended `CONNECT` of HTTP/2 (RFC
//! 8441), for servers that serve WebSocket next to other requests on one
//! endpoint.

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;

use hyper_util::rt::TokioIo;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::handshake::derive_accept_key;
use tokio_tungstenite::tungstenite::http::{self, HeaderValue, Method, StatusCode, Version};
use tokio_tungstenite::tungstenite::protocol::Role;
use zmux::adapter::Admit;
use zmux::{CarrierInfo, Listener, PipeHint, PipeIo};

use crate::{Options, PROTOCOL_HEADER, pipe, ws_config};

/// The carrier of an accepted upgrade, once hyper has upgraded the
/// connection (or HTTP/2 stream): the carrier and its hint, for
/// [`Listener::handle_pipe`].
pub type UpgradedCarrier = Pin<Box<dyn Future<Output = io::Result<(PipeIo, PipeHint)>> + Send>>;

/// What became of a request ([`accept_request`]).
pub enum RequestUpgrade<B> {
    /// Accepted: answer the request with `response` (101 on HTTP/1.1, 200
    /// on HTTP/2); `carrier` resolves once the connection is upgraded.
    Accepted {
        /// The response, without a body.
        response: http::Response<()>,
        /// The carrier, after the upgrade.
        carrier: UpgradedCarrier,
    },
    /// Not a WebSocket upgrade this server takes, or not accepted by the
    /// admission: the request, untouched, for the host's HTTP handler.
    Refused(http::Request<B>),
    /// A WebSocket upgrade that an intermediary forwarded from TLS early
    /// data (`Early-Data: 1`): answer `425 (Too Early)` and take no carrier.
    TooEarly,
    /// Stalled (the stall is over) or closed by the admission: end the
    /// request without a response.
    Ended,
}

impl<B> std::fmt::Debug for RequestUpgrade<B> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Accepted { .. } => "Accepted",
            Self::Refused(_) => "Refused",
            Self::TooEarly => "TooEarly",
            Self::Ended => "Ended",
        })
    }
}

/// Whether `req` is a WebSocket opening handshake:
/// a `GET` with `Upgrade: websocket` and `Connection: upgrade` on HTTP/1.1,
/// or an extended `CONNECT` with `:protocol` `websocket` on HTTP/2, version
/// 13, with a key on HTTP/1.1.
fn is_upgrade<B>(req: &http::Request<B>) -> bool {
    let headers = req.headers();
    let version_13 = headers
        .get("Sec-WebSocket-Version")
        .is_some_and(|v| v.as_bytes() == b"13");
    if !version_13 {
        return false;
    }
    if req.method() == Method::CONNECT {
        return req
            .extensions()
            .get::<hyper::ext::Protocol>()
            .is_some_and(|p| p.as_str().eq_ignore_ascii_case("websocket"));
    }
    req.method() == Method::GET
        && req.version() <= Version::HTTP_11
        && has_token(headers, "connection", "upgrade")
        && has_token(headers, "upgrade", "websocket")
        && headers.contains_key("Sec-WebSocket-Key")
}

fn tokens<'a>(headers: &'a http::HeaderMap, name: &str) -> impl Iterator<Item = &'a str> {
    headers
        .get_all(name)
        .into_iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .map(str::trim)
}

fn has_token(headers: &http::HeaderMap, name: &str, token: &str) -> bool {
    tokens(headers, name).any(|t| t.eq_ignore_ascii_case(token))
}

/// Upgrades `req`, a request a hyper server received from `peer` (the
/// connection's remote address), to a WebSocket carrier, or refuses it,
/// deciding on the request alone as [`accept`] does on a connection: it is
/// upgraded when it is a WebSocket opening handshake (the HTTP/1.1
/// Upgrade, or the extended `CONNECT` of HTTP/2, whose server must allow
/// it: hyper's `enable_connect_protocol`), the client offers a subprotocol
/// `options` accepts, it gets its source slot ([`ListenerAdapter::enter`](zmux::adapter::ListenerAdapter::enter); the
/// source is the client a trusted intermediary reports,
/// [`zmux::TrustedProxies::source`] of `peer` and the request's header
/// fields), and the listener's admission accepts it on the request head.
/// `info` adds the connection's metadata to the carrier's (the TLS
/// exporter); the source, the peer, the request, its header fields and
/// [`CarrierInfo::head`] are set here. Nothing is answered before the
/// decision; a stall waits for its duration and ends the request. The
/// hint carries the entry. No TCP
/// socket is known: a pipe that zmux fails ends with a Close frame.
///
/// [`accept`]: crate::accept
pub async fn accept_request<B, I>(
    req: http::Request<B>,
    peer: SocketAddr,
    info: I,
    listener: &Listener,
    options: &Options,
) -> RequestUpgrade<B>
where
    I: for<'a> FnOnce(CarrierInfo<'a>) -> CarrierInfo<'a>,
{
    if !is_upgrade(&req) {
        return RequestUpgrade::Refused(req);
    }
    let offered: Vec<String> = tokens(req.headers(), PROTOCOL_HEADER)
        .map(str::to_owned)
        .collect();
    let Some(protocol) = options.accept(&offered) else {
        return RequestUpgrade::Refused(req);
    };
    if zmux::adapter::forwarded_early_data(
        req.headers()
            .iter()
            .map(|(n, v)| (n.as_str(), v.as_bytes())),
    ) {
        listener.adapter().count_setup_failure();
        return RequestUpgrade::TooEarly;
    }
    let (mut parts, body) = req.into_parts();
    let fields = || {
        parts
            .headers
            .iter()
            .map(|(n, v)| (n.as_str(), v.as_bytes()))
    };
    let source = listener.adapter().trusted_proxies().source(peer, fields());
    let Some(mut entry) = listener.adapter().enter(peer, Some(source)) else {
        // Not taken, nothing answered: the host's handler serves it.
        return RequestUpgrade::Refused(http::Request::from_parts(parts, body));
    };
    let admit = {
        let info = info(CarrierInfo::new())
            .with_head()
            .with_request(&parts)
            .with_headers(fields);
        entry.decide(info, Vec::new()).await
    };
    match admit {
        Admit::Accept(_) => {}
        Admit::Fallback(_) => {
            return RequestUpgrade::Refused(http::Request::from_parts(parts, body));
        }
        Admit::Stall => {
            entry.stall(None::<&mut tokio::io::Empty>).await;
            return RequestUpgrade::Ended;
        }
        _ => return RequestUpgrade::Ended,
    }
    let Some(on_upgrade) = parts.extensions.remove::<hyper::upgrade::OnUpgrade>() else {
        // A request hyper cannot upgrade.
        return RequestUpgrade::Refused(http::Request::from_parts(parts, body));
    };
    let mut response = http::Response::new(());
    *response.status_mut() = if parts.method == Method::CONNECT {
        StatusCode::OK
    } else {
        StatusCode::SWITCHING_PROTOCOLS
    };
    let h = response.headers_mut();
    if parts.method != Method::CONNECT {
        h.insert("connection", HeaderValue::from_static("Upgrade"));
        h.insert("upgrade", HeaderValue::from_static("websocket"));
        if let Some(key) = parts.headers.get("Sec-WebSocket-Key")
            && let Ok(accept) = HeaderValue::from_str(&derive_accept_key(key.as_bytes()))
        {
            h.insert("Sec-WebSocket-Accept", accept);
        }
    }
    if let Some(Ok(p)) = protocol.as_deref().map(HeaderValue::from_str) {
        h.insert(PROTOCOL_HEADER, p);
    }
    let hint = PipeHint::from_entry(entry);
    let l = listener.clone();
    let carrier = Box::pin(async move {
        let upgraded = on_upgrade.await.map_err(|e| {
            // A failed upgrade.
            l.adapter().count_setup_failure();
            io::Error::other(e)
        })?;
        let ws = WebSocketStream::from_raw_socket(
            TokioIo::new(upgraded),
            Role::Server,
            Some(ws_config()),
        )
        .await;
        Ok((pipe(ws, protocol), hint))
    });
    RequestUpgrade::Accepted { response, carrier }
}
