//! The unified endpoint (API.md Section 4.8):
//! every HTTP carrier on one request target, told apart by the request
//! head alone ([`classify`]), each handed to its adapter.

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use http::{Request, Response};
use hyper::body::Incoming;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};
use zmux::Listener;
use zmux::carrier::CarrierConnId;

use crate::body::PipeBody;
use crate::{Options, Unhandled, route_request};

/// One HTTP endpoint for every carrier kind of a listener: bidirectional,
/// uplink and downlink requests and the split bootstrap
/// ([`crate::handle_request`]), exchange requests ([`Options::exchange`])
/// and, with [`Endpoint::with_websocket`] (feature `websocket`), WebSocket
/// upgrades (`zmux_websocket::accept_request`), all on [`Options::path`].
/// It composes the adapters' handlers and adds no behaviour of its own: a
/// request it does not classify, that its carrier's admission does not
/// accept, or of a kind it does not serve (WebTransport, which runs over
/// HTTP/3), goes to [`Options::fallback`] (404 without one); a carrier
/// request forwarded from early data is answered 425. Cheap to clone.
#[derive(Clone)]
pub struct Endpoint {
    listener: Listener,
    options: Arc<Options>,
    #[cfg(feature = "websocket")]
    websocket: Option<Arc<zmux_websocket::Options>>,
}

impl std::fmt::Debug for Endpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Endpoint")
            .field("path", &self.options.path)
            .finish_non_exhaustive()
    }
}

impl Endpoint {
    /// The endpoint of `listener`'s carriers, with the request carriers'
    /// and the exchange's `options`.
    pub fn new(listener: Listener, options: Options) -> Self {
        Self {
            listener,
            options: Arc::new(options),
            #[cfg(feature = "websocket")]
            websocket: None,
        }
    }

    /// Also serves WebSocket upgrades with `options` (its subprotocols and
    /// admission).
    #[cfg(feature = "websocket")]
    #[must_use]
    pub fn with_websocket(mut self, options: zmux_websocket::Options) -> Self {
        self.websocket = Some(Arc::new(options));
        self
    }

    /// The listener.
    pub fn listener(&self) -> &Listener {
        &self.listener
    }

    /// Routes one request: its carrier to its adapter, or the request back
    /// for the fallback. `peer` is the connection's remote address
    /// ([`crate::handle_request`]), `conn` the connection's identity.
    pub async fn route(
        &self,
        req: Request<Incoming>,
        peer: Option<SocketAddr>,
        conn: CarrierConnId,
    ) -> Result<Response<PipeBody>, Unhandled<Incoming>> {
        #[cfg(feature = "websocket")]
        if let Some(ws) = &self.websocket {
            let (parts, body) = req.into_parts();
            let class = crate::classify(&parts);
            let req = Request::from_parts(parts, body);
            if class == Some(crate::RequestClass::WebSocket)
                && req.uri().path() == self.options.path
            {
                return self.websocket(ws, req, peer).await;
            }
            return route_request(&self.listener, req, peer, Some(conn), &self.options).await;
        }
        route_request(&self.listener, req, peer, Some(conn), &self.options).await
    }

    #[cfg(feature = "websocket")]
    async fn websocket(
        &self,
        ws: &zmux_websocket::Options,
        req: Request<Incoming>,
        peer: Option<SocketAddr>,
    ) -> Result<Response<PipeBody>, Unhandled<Incoming>> {
        use zmux_websocket::RequestUpgrade;
        if crate::forwarded_early_data(req.headers()) {
            self.listener.count_setup_failure();
            return Ok(crate::too_early());
        }
        let peer = peer.unwrap_or(SocketAddr::from(([0, 0, 0, 0], 0)));
        let info = remote_info(|i| i);
        match zmux_websocket::accept_request(req, peer, info, &self.listener, ws).await {
            RequestUpgrade::Accepted { response, carrier } => {
                let l = self.listener.clone();
                tokio::spawn(async move {
                    if let Ok((io, hint)) = carrier.await {
                        let _ = l.handle_pipe(io, hint).await;
                    }
                });
                Ok(response.map(|()| PipeBody::empty()))
            }
            RequestUpgrade::Refused(req) => Err(Unhandled::Fallback(Box::new(req.map(|b| {
                crate::ReplayBody::new([bytes::Bytes::new(), bytes::Bytes::new()], Some(b))
            })))),
            // Counted as a setup failure by the upgrade.
            RequestUpgrade::TooEarly => Ok(crate::too_early()),
            RequestUpgrade::Ended => Err(Unhandled::Abort),
        }
    }

    /// Serves one established connection ([`crate::serve_connection_with`]
    /// with [`Endpoint::route`]).
    pub async fn serve_connection<IO>(&self, io: IO, peer: Option<SocketAddr>)
    where
        IO: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        let this = self.clone();
        crate::serve_connection_with(&self.listener, io, peer, &self.options, move |r, s, c| {
            let this = this.clone();
            async move { this.route(r, s, c).await }
        })
        .await;
    }

    /// Serves the connections `accept` yields, set up by `setup`, which also
    /// gives each connection's source (see [`crate::serve_proxied`]).
    pub async fn serve_proxied<T, IO, A, AF, F, SF>(self, accept: A, setup: F)
    where
        A: FnMut() -> AF,
        AF: Future<Output = io::Result<(T, SocketAddr)>>,
        F: Fn(T, SocketAddr) -> SF,
        SF: Future<Output = io::Result<(IO, SocketAddr)>> + Send + 'static,
        IO: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        let this = self.clone();
        crate::serve_proxied_with(
            self.listener.clone(),
            accept,
            setup,
            (*self.options).clone(),
            move |r, s, c| {
                let this = this.clone();
                async move { this.route(r, s, c).await }
            },
        )
        .await;
    }

    /// Serves the connections `accept` yields, each set up by `setup` (a
    /// TLS handshake) first (see [`crate::serve_with`]).
    pub async fn serve_with<T, IO, A, AF, F, SF>(self, accept: A, setup: F)
    where
        A: FnMut() -> AF,
        AF: Future<Output = io::Result<(T, SocketAddr)>>,
        F: Fn(T, SocketAddr) -> SF,
        SF: Future<Output = io::Result<IO>> + Send + 'static,
        IO: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        self.serve_proxied(accept, move |conn, peer| {
            let made = setup(conn, peer);
            async move { Ok((made.await?, peer)) }
        })
        .await;
    }

    /// Serves HTTP/1.1 and HTTP/2 (prior knowledge) on a TCP listener until
    /// the listener is closed, reading the PROXY protocol header of a
    /// trusted intermediary first (see [`crate::serve`]).
    pub async fn serve(self, tcp: TcpListener) {
        let trusted = Arc::new(self.listener.trusted_proxies().clone());
        self.serve_proxied(
            || tcp.accept(),
            move |stream: TcpStream, peer| {
                let trusted = trusted.clone();
                async move {
                    let _ = stream.set_nodelay(true);
                    let mut stream = stream;
                    let source = zmux::proxied_source(&mut stream, peer, &trusted).await?;
                    Ok((stream, source))
                }
            },
        )
        .await;
    }
}

/// `f`, its type fixed as the metadata function of an upgrade.
#[cfg(feature = "websocket")]
fn remote_info<F>(f: F) -> F
where
    F: for<'a> FnOnce(zmux::CarrierInfo<'a>) -> zmux::CarrierInfo<'a>,
{
    f
}
