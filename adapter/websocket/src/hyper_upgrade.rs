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
use tokio_tungstenite::tungstenite::http::{self, HeaderValue, Method, StatusCode};
use tokio_tungstenite::tungstenite::protocol::Role;
use zmux::adapter::{Admit, AdmitIo};
use zmux::{CarrierInfo, Listener, PipeHint, PipeIo};

use crate::{Options, PROTOCOL_HEADER, pipe, ws_config};

/// The carrier of an upgrade, once hyper has upgraded the connection (or
/// HTTP/2 stream) and the carrier passed the rest of its admission
/// ([`zmux::adapter::Entry::admit_first`]): the carrier and its hint, for
/// [`Listener::handle_pipe`]; `None` when the upgrade failed or did not
/// come within the peek timeout of a deferred decision, or when the
/// decision on the carrier did not accept it (a fallback has then
/// completed).
pub type UpgradedCarrier = Pin<Box<dyn Future<Output = Option<(PipeIo, PipeHint)>> + Send>>;

/// The accepted extended CONNECT response's header-flush receipt. Hyper
/// makes an HTTP/2 tunnel available as soon as its headers are queued.
#[derive(Clone, Debug)]
pub struct UpgradeFlush(std::sync::Arc<std::sync::Mutex<Option<zmux::adapter::ResponseHead>>>);

impl UpgradeFlush {
    /// Takes the receipt from the response extensions. The HTTP server sends
    /// it after its successful header flush; dropping it withdraws the upgrade.
    pub fn take(response: &mut http::Response<()>) -> Option<zmux::adapter::ResponseHead> {
        response
            .extensions_mut()
            .remove::<Self>()?
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
    }
}

/// What became of a request ([`accept_request`]).
pub enum RequestUpgrade<B> {
    /// Accepted, or the decision deferred to the carrier: answer the
    /// request with `response` (101 on HTTP/1.1, 200 on HTTP/2); `carrier`
    /// resolves once the connection is upgraded and the carrier admitted.
    Accepted {
        /// The response, without a body. On an extended CONNECT which may
        /// transfer the carrier to the host, forward its [`UpgradeFlush`].
        response: http::Response<()>,
        /// The carrier, after the upgrade.
        carrier: UpgradedCarrier,
    },
    /// Not a WebSocket upgrade this server takes, or not accepted by the
    /// admission on its head: the request, untouched, for the host's HTTP
    /// handler (a request taken over as a request).
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

/// Upgrades `req`, a request a hyper server received from `peer` (the
/// connection's remote address), to a WebSocket carrier, or refuses it,
/// deciding on the request alone as [`accept`] does on a connection: it is
/// upgraded when it is a WebSocket opening handshake (the HTTP/1.1
/// Upgrade, or the extended `CONNECT` of HTTP/2, whose server must allow
/// it: hyper's `enable_connect_protocol`), the client offers a subprotocol
/// `options` accepts, it gets its source slot ([`ListenerAdapter::enter`](zmux::adapter::ListenerAdapter::enter); the
/// source is the client a trusted intermediary reports,
/// [`zmux::TrustedProxies::source`] of `peer` and the request's header
/// fields), and the listener's admission accepts it on the request head
/// or defers its decision to the carrier ([`zmux::AdmissionVerdict::Defer`]:
/// the carrier's first message is then decided on, with the same
/// metadata, and a `Fallback` hands the carrier to the listener's fallback,
/// [`zmux::ListenerConfig::fallback`], before [`UpgradedCarrier`]
/// resolves). `info` adds the connection's metadata to the carrier's (the
/// TLS exporter); the source, the peer, the request, its header fields,
/// the head stage and [`CarrierInfo::upgrade`] are set here. Nothing is
/// answered before the decision on the head; a stall waits for its
/// duration and ends the request. The hint carries the entry. No TCP
/// socket is known: a pipe that zmux fails ends with a Close frame. A
/// request whose extensions hold the [`zmux_rustls::TlsBinding`] of the
/// TLS connection it arrived on (the HTTP adapter's servers add it for a
/// [`zmux_rustls::TlsConnection`]), an HTTP/1.1 Upgrade or an extended
/// `CONNECT` on an HTTP/2 stream, has a carrier that declares that binding.
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
    I: FnOnce(CarrierInfo) -> CarrierInfo,
{
    let protocol = req
        .extensions()
        .get::<hyper::ext::Protocol>()
        .map(hyper::ext::Protocol::as_str);
    let opening = zmux_http_head::websocket(req.method(), req.version(), req.headers(), protocol);
    if opening == zmux_http_head::WebSocket::Other {
        return RequestUpgrade::Refused(req);
    }
    let Ok(source) = zmux_http_head::preprocess(listener, req.headers(), peer) else {
        return RequestUpgrade::TooEarly;
    };
    if opening != zmux_http_head::WebSocket::Opening {
        return RequestUpgrade::Refused(req);
    }
    let offered: Vec<String> = zmux_http_head::tokens(req.headers(), PROTOCOL_HEADER)
        .map(str::to_owned)
        .collect();
    let Some(protocol) = options.accept(&offered) else {
        return RequestUpgrade::Refused(req);
    };
    let (mut parts, body) = req.into_parts();
    let Some(mut entry) = listener.adapter().enter(peer, Some(source)) else {
        // Not taken, nothing answered: the host's handler serves it.
        return RequestUpgrade::Refused(http::Request::from_parts(parts, body));
    };
    let admit = {
        // The TLS connection's metadata, when the request came over one.
        let base = parts
            .extensions
            .get::<zmux_rustls::TlsBinding>()
            .map_or_else(CarrierInfo::new, zmux_rustls::TlsBinding::info);
        let Some(info) = entry.host(|| info(base)) else {
            return RequestUpgrade::Ended;
        };
        entry
            .decide_upgrade(
                info.with_request_head(std::sync::Arc::new(parts.clone()), crate::header_fields),
            )
            .await
    };
    match admit {
        Admit::Accept(_) | Admit::Defer | Admit::TakeOver(_) => {}
        Admit::Fallback(_) => {
            zmux_http_head::return_fallback(&mut entry, &mut parts.extensions);
            return RequestUpgrade::Refused(http::Request::from_parts(parts, body));
        }
        Admit::Stall => {
            entry
                .stall_local(http::Request::from_parts(parts, body))
                .await;
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
    let binding = parts.extensions.get::<zmux_rustls::TlsBinding>().cloned();
    let flush = (parts.method == Method::CONNECT
        && matches!(admit, Admit::TakeOver(_) | Admit::Defer))
    .then(|| {
        let (sent, ready) = entry.response_head();
        response
            .extensions_mut()
            .insert(UpgradeFlush(std::sync::Arc::new(std::sync::Mutex::new(
                Some(sent),
            ))));
        ready
    });
    let carrier = Box::pin(async move {
        // The upgrade, within what remains of a deferred decision's peek
        // timeout.
        let first = async move {
            let upgraded = on_upgrade.await.map_err(io::Error::other)?;
            if let Some(flush) = flush {
                flush.await.map_err(io::Error::other)?;
            }
            let ws = WebSocketStream::from_raw_socket(
                TokioIo::new(upgraded),
                Role::Server,
                Some(ws_config()),
            )
            .await;
            let io = pipe(ws, protocol);
            let io = match &binding {
                Some(b) => b.apply(io),
                None => io,
            };
            Ok(AdmitIo::pipe(io))
        };
        let io = entry.admit_first(CarrierInfo::new(), first).await?;
        Some((io, PipeHint::from_entry(entry)))
    });
    RequestUpgrade::Accepted { response, carrier }
}

#[cfg(test)]
mod local_body_tests {
    use super::*;

    #[tokio::test]
    async fn a_borrowed_non_send_upgrade_body_drops_before_its_slot() {
        use std::{cell::Cell, rc::Rc};
        struct Body<'a>(&'a Rc<Cell<bool>>, &'a Listener, SocketAddr);
        impl Drop for Body<'_> {
            fn drop(&mut self) {
                self.0.set(true);
                assert!(self.1.adapter().enter(self.2, None).is_none());
            }
        }
        let mut config = zmux::ListenerConfig::default();
        config.limits.max_pending_per_source = 2;
        config.admission = Some(zmux::Admission::new(0, |_, _| {
            zmux::AdmissionVerdict::Stall
        }));
        let listener = Listener::new(zmux::Config::default(), config).unwrap();
        let addr = (std::net::Ipv4Addr::LOCALHOST, 0).into();
        let _other = listener.adapter().enter(addr, None).unwrap();
        let dropped = Rc::new(Cell::new(false));
        let request = http::Request::builder()
            .header("Connection", "upgrade")
            .header("Upgrade", "websocket")
            .header("Sec-WebSocket-Version", "13")
            .header("Sec-WebSocket-Key", "test")
            .header(PROTOCOL_HEADER, "qmux-02")
            .body(Body(&dropped, &listener, addr))
            .unwrap();
        let options = Options::default();
        let mut future = Box::pin(accept_request(
            request,
            addr,
            std::convert::identity,
            &listener,
            &options,
        ));
        assert!(
            Future::poll(
                future.as_mut(),
                &mut std::task::Context::from_waker(std::task::Waker::noop())
            )
            .is_pending()
        );
        assert!(!dropped.get());
        drop(future);
        assert!(dropped.get());
        assert!(listener.adapter().enter(addr, None).is_some());
    }
}
