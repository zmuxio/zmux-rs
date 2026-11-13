//! The client: carriers over HTTP/1.1 connections and HTTP/2 connections.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use http::{Method, Request, Response, StatusCode, Version};
use hyper::body::Incoming;
use hyper::client::conn::{http1, http2};
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use zmux::carrier::CarrierConnId;
use zmux::redirect::{self, RedirectError};
use zmux::{
    Candidate, CarrierInfo, CarrierKind, ConnectError, Dial, DialRequest, HttpTarget, Pipe,
    PipeDirection, PipeIo, PipeOptions, Session,
};

use crate::Options;
use crate::body::{self, BodyReader, PipeBody};

pub(crate) fn hyper_err(e: hyper::Error) -> io::Error {
    io::Error::other(e)
}

/// `f` within `limit`, or a `TimedOut` error.
pub(crate) async fn within<T>(
    limit: Duration,
    f: impl Future<Output = io::Result<T>>,
) -> io::Result<T> {
    tokio::time::timeout(limit, f).await.unwrap_or_else(|_| {
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "the exchange was not established in time",
        ))
    })
}

/// What one carrier request is: its direction and its pairing token.
#[derive(Debug, Clone)]
struct Head {
    direction: PipeDirection,
    pair: Option<String>,
}

impl Head {
    fn of(request: &DialRequest) -> Self {
        Self {
            direction: request.direction,
            pair: None,
        }
    }
}

/// The writer of a request body and its abort.
type BodyFeed = (body::BodyWriter, body::Abort);

/// A request under way, its body's writer (none for a `GET`), and the
/// future of its response head.
struct Sent<F> {
    head: Head,
    body: Option<BodyFeed>,
    resp: F,
}

impl Options {
    /// The request of a carrier: a `GET` for a downlink, a `POST` whose
    /// body is fed by the returned writer otherwise, the prefix of
    /// [`Options::carrier_credential`] first on a body and its header form on a
    /// `GET`. Neither body has a
    /// `Content-Length`.
    ///
    /// `path` is the request target; `repeat`, the body of the request
    /// this one repeats at a redirect's URL, whose bytes it sends again
    /// after a fresh prefix ([`body::Abort::repeat`]).
    fn carrier_request(
        &self,
        authority: &str,
        path: &str,
        version: Version,
        head: &Head,
        repeat: Option<&body::Abort>,
    ) -> io::Result<(Request<PipeBody>, Option<BodyFeed>)> {
        let get = head.direction == PipeDirection::In;
        let mut req = Request::builder()
            .method(if get { Method::GET } else { Method::POST })
            .version(version);
        req = if version == Version::HTTP_2 {
            let scheme = if self.https { "https" } else { "http" };
            req.uri(format!("{scheme}://{authority}{path}"))
        } else {
            req.uri(path).header(http::header::HOST, authority)
        };
        if let Some(p) = &head.pair {
            req = req.header(self.pair_field.name(), p.as_str());
        }
        let (body, writer) = if get {
            if let Some(c) = &self.carrier_credential {
                let (name, value) = c.header(&CarrierInfo::new().with_head())?;
                req = req.header(name, value);
            }
            (PipeBody::empty(), None)
        } else {
            let prefix = match &self.carrier_credential {
                Some(c) => Some(bytes::Bytes::from(c.prefix(&CarrierInfo::new())?)),
                None => None,
            };
            match repeat {
                Some(a) => {
                    let body = a.repeat(prefix).ok_or_else(|| {
                        io::Error::other("the uplink is past the bound of a repeat")
                    })?;
                    (body, None)
                }
                None => {
                    let (writer, body, abort) = body::body();
                    if let Some(p) = prefix {
                        writer.preload(p);
                    }
                    (body, Some((writer, abort)))
                }
            }
        };
        let req = req
            .body(body)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        Ok((req, writer))
    }

    /// The URL of a carrier request to `authority` at `path`.
    pub(crate) fn url(&self, authority: &str, path: &str) -> String {
        let scheme = if self.https { "https" } else { "http" };
        format!("{scheme}://{authority}{path}")
    }

    /// These options at the path of `target`'s URL, when it is of the
    /// same origin as its base.
    fn at(&self, target: &HttpTarget) -> Self {
        let url = target.url();
        let mut o = self.clone();
        if redirect::same_origin(&url, target.base()) {
            path_of(&url).clone_into(&mut o.path);
        }
        o
    }
}

/// The path and query of a URL.
pub(crate) fn path_of(url: &str) -> &str {
    let rest = url.split_once("://").map_or(url, |(_, r)| r);
    rest.find(['/', '?']).map_or("/", |i| &rest[i..])
}

/// A connection of a redial.
pub(crate) trait IoStream: AsyncRead + AsyncWrite + Send + Unpin {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin> IoStream for T {}
type BoxIo = Box<dyn IoStream>;
type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send>>;

/// Makes a new connection to the carriers' endpoint, for a request
/// repeated at a redirect's URL.
pub(crate) type Redial = Arc<dyn Fn() -> BoxFuture<io::Result<BoxIo>> + Send + Sync>;

fn redial<C, F, IO>(connect: Arc<C>) -> Redial
where
    C: Fn() -> F + Send + Sync + 'static,
    F: Future<Output = io::Result<IO>> + Send + 'static,
    IO: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    Arc::new(move || {
        let f = connect();
        Box::pin(async move { Ok(Box::new(f.await?) as BoxIo) })
    })
}

/// Sends a carrier's request again at a path: its response.
type Resend = Arc<dyn Fn(String) -> BoxFuture<io::Result<ResponseFuture>> + Send + Sync>;

/// How a carrier request follows redirects, as [`redirect::check`]
/// allows and only within its origin (the connection's endpoint), up to
/// [`Options::max_redirects`]: the request is repeated whole, with a fresh
/// credential and every uplink byte written so far, up to
/// [`body::REPLAY_MAX`].
pub(crate) struct Follow {
    url: String,
    method: &'static str,
    max: usize,
    target: Option<Arc<HttpTarget>>,
    body: Option<body::Abort>,
    resend: Resend,
}

impl Follow {
    fn new(
        options: &Options,
        authority: &str,
        head: &Head,
        body: Option<&BodyFeed>,
        target: Option<Arc<HttpTarget>>,
        resend: Resend,
    ) -> Self {
        Self {
            url: options.url(authority, &options.path),
            method: if head.direction == PipeDirection::In {
                "GET"
            } else {
                "POST"
            },
            max: options.max_redirects,
            target,
            body: body.map(|(_, a)| a.clone()),
            resend,
        }
    }

    /// The first response that is not a redirect, and its URL.
    async fn run(&self, mut resp: Response<Incoming>) -> io::Result<(Response<Incoming>, String)> {
        let mut url = self.url.clone();
        let mut hops = 0;
        loop {
            let status = resp.status().as_u16();
            if !redirect::is_redirect(status) {
                return Ok((resp, url));
            }
            let location = resp
                .headers()
                .get(http::header::LOCATION)
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned);
            // The redirect's body is not the carrier's.
            drop(resp);
            let refuse = |reason| RedirectError {
                status,
                location: location.clone().unwrap_or_default(),
                reason,
            };
            let next = redirect::check(&url, self.method, status, location.as_deref())?;
            if !redirect::same_origin(&next, &url) {
                return Err(refuse("another origin over the carrier's connections").into());
            }
            if hops >= self.max {
                return Err(refuse("too many redirects").into());
            }
            if self.body.as_ref().is_some_and(|a| !a.replayable()) {
                return Err(refuse("the uplink is past the replay bound").into());
            }
            hops += 1;
            resp = (self.resend)(path_of(&next).to_owned())
                .await?
                .await
                .map_err(hyper_err)?;
            url = next;
        }
    }
}

/// The carrier of a request under way: a bidirectional one reads the
/// response body and writes the request body; an uplink writes the request
/// body, its response's end (or failure) ending the carrier; a downlink
/// reads the response body.
fn carrier<F>(timeout: Duration, sent: Sent<F>, follow: Option<Follow>) -> PipeIo
where
    F: Future<Output = Result<Response<Incoming>, hyper::Error>> + Send + 'static,
{
    if let (Some(_), Some((_, abort))) = (&follow, &sent.body) {
        abort.keep_replay();
    }
    match (sent.head.direction, sent.body) {
        (PipeDirection::In, _) | (_, None) => {
            PipeIo::reader(ResponseReader::spawn(timeout, sent.resp, None, follow))
                .with_carrier(CarrierKind::Split)
        }
        (PipeDirection::Bidi, Some((writer, abort))) => {
            let reader = ResponseReader::spawn(timeout, sent.resp, Some(abort.clone()), follow);
            PipeIo::from_chunk_halves(reader, writer)
                .with_abort(move || abort.run())
                .with_carrier(CarrierKind::Streaming)
        }
        (PipeDirection::Out, Some((writer, abort))) => {
            // The response carries no pipe bytes: it is read to its end,
            // which ends the carrier, as does a failure or another status.
            let mut reader = ResponseReader::spawn(timeout, sent.resp, Some(abort.clone()), follow);
            let ended = abort.clone();
            tokio::spawn(async move {
                match tokio::io::copy(&mut reader, &mut tokio::io::sink()).await {
                    Ok(_) => ended.run(),
                    Err(e) => ended.fail(e.kind()),
                }
            });
            PipeIo::chunk_writer(writer)
                .with_abort(move || abort.run())
                .with_carrier(CarrierKind::Split)
        }
    }
}

/// The response body of a carrier as its inbound half. The server answers
/// once the carrier is accepted, so the response is awaited in a task of
/// its own, within the establishing limit, and the reads wait for it: a
/// response that fails, is not 200, or does not arrive in time is a read
/// error.
pub(crate) struct ResponseReader {
    state: ReaderState,
}

enum ReaderState {
    Waiting(tokio::sync::oneshot::Receiver<io::Result<Response<Incoming>>>),
    Body(BodyReader<Incoming>),
    Failed(io::ErrorKind, String),
}

impl ResponseReader {
    /// With `request`, the request body of the same exchange learns the
    /// outcome: its writes fail as the response did
    /// ([`body::Abort::await_response`]). With `follow`, redirects are
    /// followed, and its target records the URL they led to.
    pub(crate) fn spawn<F>(
        timeout: Duration,
        resp: F,
        request: Option<body::Abort>,
        follow: Option<Follow>,
    ) -> Self
    where
        F: Future<Output = Result<Response<Incoming>, hyper::Error>> + Send + 'static,
    {
        if let Some(a) = &request {
            a.await_response();
        }
        let (tx, rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let r = within(timeout, async {
                let resp = resp.await.map_err(hyper_err)?;
                match &follow {
                    Some(f) => f.run(resp).await,
                    None => Ok((resp, String::new())),
                }
            })
            .await
            .and_then(|(resp, url)| Ok((answered(resp)?, url)));
            if let Some(t) = follow.as_ref().and_then(|f| f.target.as_ref()) {
                match &r {
                    Ok((_, url)) => t.redirected(url),
                    Err(_) => t.reset(),
                }
            }
            let r = r.map(|(resp, _)| resp);
            match (&r, request) {
                (Ok(_), Some(a)) => a.answered(),
                (Err(e), Some(a)) => a.fail(e.kind()),
                (_, None) => {}
            }
            let _ = tx.send(r);
        });
        Self {
            state: ReaderState::Waiting(rx),
        }
    }
}

/// `resp` if its status is 200.
fn answered(resp: Response<Incoming>) -> io::Result<Response<Incoming>> {
    if resp.status() == StatusCode::OK {
        Ok(resp)
    } else {
        Err(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            format!("the server answered {}", resp.status()),
        ))
    }
}

impl AsyncRead for ResponseReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            match &mut self.state {
                ReaderState::Body(b) => return Pin::new(b).poll_read(cx, buf),
                ReaderState::Failed(kind, msg) => {
                    return Poll::Ready(Err(io::Error::new(*kind, msg.clone())));
                }
                ReaderState::Waiting(rx) => {
                    self.state = match std::task::ready!(Pin::new(rx).poll(cx)) {
                        Ok(Ok(resp)) => ReaderState::Body(BodyReader::new(resp.into_body())),
                        Ok(Err(e)) => ReaderState::Failed(e.kind(), e.to_string()),
                        Err(_) => ReaderState::Failed(
                            io::ErrorKind::ConnectionAborted,
                            "the exchange ended without a response".into(),
                        ),
                    };
                }
            }
        }
    }
}

/// A fresh pairing token as its header value: 16 random bytes in
/// base64url without padding.
fn pairing_token() -> io::Result<String> {
    let mut token = [0u8; zmux::PAIRING_TOKEN_LEN];
    getrandom::fill(&mut token).map_err(io::Error::other)?;
    let mut out = [0u8; 24];
    let n = zmux::proto::oob::encode(&token, &mut out)
        .map_err(|_| io::Error::other("pairing token encoding"))?;
    Ok(String::from_utf8_lossy(&out[..n]).into_owned())
}

/// The two heads of a split bootstrap, with one pairing token.
fn split_heads() -> io::Result<(Head, Head)> {
    let pair = Some(pairing_token()?);
    Ok((
        Head {
            direction: PipeDirection::Out,
            pair: pair.clone(),
        },
        Head {
            direction: PipeDirection::In,
            pair,
        },
    ))
}

// ---- HTTP/1.1 ------------------------------------------------------------------------

/// A bidirectional carrier over a new HTTP/1.1 connection to `addr`
/// (`host:port`, also the `Host` header): one request, its request and
/// response bodies streamed at the same time ([`dial_http1_over`] on a TCP
/// connection).
pub async fn dial_http1(addr: &str, options: &Options) -> io::Result<PipeIo> {
    let addr: Arc<str> = addr.into();
    let a = addr.clone();
    let connect = redial(Arc::new(move || tcp_owned(a.clone())));
    let head = Head::of(&DialRequest::bidi());
    send_http1(tcp(&addr).await?, &addr, options, head, Some(connect), None).await
}

async fn tcp_owned(addr: Arc<str>) -> io::Result<TcpStream> {
    tcp(&addr).await
}

async fn tcp(addr: &str) -> io::Result<TcpStream> {
    let tcp = TcpStream::connect(addr).await?;
    let _ = tcp.set_nodelay(true);
    Ok(tcp)
}

/// A bidirectional carrier over an established connection, any byte
/// stream such as a TLS stream whose ALPN chose `http/1.1`: one HTTP/1.1
/// request with `authority` as its `Host` header ([`dial_http1_carrier_over`]
/// with [`DialRequest::bidi`]).
///
/// ```no_run
/// # async fn example(tls: tokio_rustls::TlsConnector,
/// #     name: tokio_rustls::rustls::pki_types::ServerName<'static>) -> std::io::Result<()> {
/// let tcp = tokio::net::TcpStream::connect("example.com:443").await?;
/// let conn = tls.connect(name, tcp).await?;
/// let pipe = zmux_http::dial_http1_over(conn, "example.com", &zmux_http::Options::default()).await?;
/// # drop(pipe);
/// # Ok(())
/// # }
/// ```
pub async fn dial_http1_over<IO>(io: IO, authority: &str, options: &Options) -> io::Result<PipeIo>
where
    IO: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    dial_http1_carrier_over(io, authority, options, &DialRequest::bidi()).await
}

/// A carrier of `request`'s direction over an established HTTP/1.1
/// connection, one request on it with `authority` as its `Host` header: a
/// bidirectional `POST`, an uplink `POST` (the local endpoint only writes;
/// the response's end ends the carrier), or a downlink `GET` (it only
/// reads). It returns
/// once the request is under way, before the response: the server answers
/// once the carrier is accepted, and the carrier's reads wait for the
/// response, which must arrive within [`Options::timeout`] (a read error
/// otherwise, and for a status other than 200). The connection's HTTP
/// handshake is bounded by the same limit.
pub async fn dial_http1_carrier_over<IO>(
    io: IO,
    authority: &str,
    options: &Options,
    request: &DialRequest,
) -> io::Result<PipeIo>
where
    IO: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    send_http1(io, authority, options, Head::of(request), None, None).await
}

async fn send_http1<IO>(
    io: IO,
    authority: &str,
    options: &Options,
    head: Head,
    redial: Option<Redial>,
    target: Option<Arc<HttpTarget>>,
) -> io::Result<PipeIo>
where
    IO: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let (resp, body) = http1_request(io, authority, options, &options.path, &head, None).await?;
    let follow = redial.map(|redial| {
        let abort = body.as_ref().map(|(_, a)| a.clone());
        let (a, o, h) = (Arc::<str>::from(authority), options.clone(), head.clone());
        let resend: Resend = Arc::new(move |path| {
            let (redial, a, o, h, abort) = (
                redial.clone(),
                a.clone(),
                o.clone(),
                h.clone(),
                abort.clone(),
            );
            Box::pin(async move {
                let io = redial().await?;
                let (resp, _) = http1_request(io, &a, &o, &path, &h, abort.as_ref()).await?;
                Ok(resp)
            })
        });
        Follow::new(options, authority, &head, body.as_ref(), target, resend)
    });
    Ok(carrier(options.timeout, Sent { head, body, resp }, follow))
}

/// One carrier request on a new HTTP/1.1 connection over `io`, the
/// connection closed once it is done.
async fn http1_request<IO>(
    io: IO,
    authority: &str,
    options: &Options,
    path: &str,
    head: &Head,
    repeat: Option<&body::Abort>,
) -> io::Result<(ResponseFuture, Option<BodyFeed>)>
where
    IO: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let (mut sender, conn) = within(options.timeout, async {
        http1::handshake::<_, PipeBody>(TokioIo::new(io))
            .await
            .map_err(hyper_err)
    })
    .await?;
    tokio::spawn(conn);
    let (req, body) = options.carrier_request(authority, path, Version::HTTP_11, head, repeat)?;
    let resp = sender.send_request(req);
    // One request per connection: it closes once this one is done.
    drop(sender);
    Ok((Box::pin(resp), body))
}

/// A split bootstrap over two HTTP/1.1 connections that `connect` makes
/// (one pipe from two one-way carriers): an uplink `POST` and a downlink `GET` with one
/// fresh pairing token in `Zmux-Pipe-Pair`, combined into pipe pair 0
/// ([`PipeIo::split_bootstrap`]). The pairing token is a bearer secret
/// until the session is established: the connections must be confidential
/// to the server or to an intermediary the deployment entrusts with the
/// carriers' contents (TLS).
pub async fn dial_http1_split_with<C, F, IO>(
    connect: C,
    authority: &str,
    options: &Options,
) -> io::Result<PipeIo>
where
    C: Fn() -> F + Send + Sync + 'static,
    F: Future<Output = io::Result<IO>> + Send + 'static,
    IO: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    split_http1(Arc::new(connect), authority, options, None).await
}

/// The two carriers of a split bootstrap or join over HTTP/1.1.
async fn split_http1_pair<C, F, IO>(
    connect: Arc<C>,
    authority: &str,
    options: &Options,
    target: Option<Arc<HttpTarget>>,
) -> io::Result<(PipeIo, PipeIo)>
where
    C: Fn() -> F + Send + Sync + 'static,
    F: Future<Output = io::Result<IO>> + Send + 'static,
    IO: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let (up, down) = split_heads()?;
    let again = redial(connect.clone());
    let up = send_http1(
        connect().await?,
        authority,
        options,
        up,
        Some(again.clone()),
        target.clone(),
    )
    .await?;
    let down = send_http1(
        connect().await?,
        authority,
        options,
        down,
        Some(again),
        target,
    )
    .await?;
    Ok((up, down))
}

async fn split_http1<C, F, IO>(
    connect: Arc<C>,
    authority: &str,
    options: &Options,
    target: Option<Arc<HttpTarget>>,
) -> io::Result<PipeIo>
where
    C: Fn() -> F + Send + Sync + 'static,
    F: Future<Output = io::Result<IO>> + Send + 'static,
    IO: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let (up, down) = split_http1_pair(connect, authority, options, target).await?;
    Ok(PipeIo::split_bootstrap(up, down).with_carrier(CarrierKind::Split))
}

/// Joins a split carrier over two HTTP/1.1 connections that `connect` makes to `session`:
/// one Join across a `POST` and a `GET` paired by a token, one attachment of the
/// two directions, `pipe_options` choosing its direction. Returns the pipe as
/// [`Session::add_pipe`] does: once the peer attached it, or with
/// [`PipeOptions::return_on_reply`] once its join is confirmed. A [`zmux::helpers::PipePool::join`] keeps such carriers up.
pub async fn join_http1_split_with<C, F, IO>(
    session: &Session,
    connect: C,
    authority: &str,
    options: &Options,
    pipe_options: PipeOptions,
) -> io::Result<Vec<Pipe>>
where
    C: Fn() -> F + Send + Sync + 'static,
    F: Future<Output = io::Result<IO>> + Send + 'static,
    IO: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let (up, down) = split_http1_pair(Arc::new(connect), authority, options, None).await?;
    let io = PipeIo::paired_join(up, down).with_carrier(CarrierKind::Split);
    let to_io = |e: zmux::PipeError| io::Error::other(e.to_string());
    let pipe = session.add_pipe(io, pipe_options).await.map_err(to_io)?;
    Ok(vec![pipe])
}

/// [`dial_http1_split_with`] over plain TCP connections to `addr`.
pub async fn dial_http1_split(addr: &str, options: &Options) -> io::Result<PipeIo> {
    let a: Arc<str> = addr.into();
    dial_http1_split_with(move || tcp_owned(a.clone()), addr, options).await
}

/// Establishes a session over a new HTTP/1.1 connection ([`dial_http1`]).
pub async fn connect_http1(
    addr: &str,
    options: &Options,
    config: impl Into<Arc<zmux::Config>>,
) -> Result<Session, ConnectError> {
    let io = dial_http1(addr, options)
        .await
        .map_err(|e| ConnectError::Io(Arc::new(e)))?;
    Session::connect(io, config).await
}

/// Establishes a session on a split bootstrap over plain TCP
/// ([`dial_http1_split`]).
pub async fn connect_http1_split(
    addr: &str,
    options: &Options,
    config: impl Into<Arc<zmux::Config>>,
) -> Result<Session, ConnectError> {
    let io = dial_http1_split(addr, options)
        .await
        .map_err(|e| ConnectError::Io(Arc::new(e)))?;
    Session::connect(io, config).await
}

/// A [`Dial`] for the session's helpers (pools, rejoins, joins of
/// split carriers): every carrier on a new HTTP/1.1 connection
/// that `connect` makes, in the direction each [`DialRequest`] asks for
/// ([`dial_http1_carrier_over`]).
pub fn http1_dial<C, F, IO>(connect: C, authority: &str, options: &Options) -> Dial
where
    C: Fn() -> F + Send + Sync + 'static,
    F: Future<Output = io::Result<IO>> + Send + 'static,
    IO: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let connect = Arc::new(connect);
    let authority: Arc<str> = authority.into();
    let options = Arc::new(options.clone());
    Dial::new(move |request: DialRequest| {
        let (connect, authority, options) = (connect.clone(), authority.clone(), options.clone());
        async move {
            let io = connect().await?;
            let again = redial(connect);
            send_http1(
                io,
                &authority,
                &options,
                Head::of(&request),
                Some(again),
                None,
            )
            .await
        }
    })
}

// ---- HTTP/2 --------------------------------------------------------------------------

/// An HTTP/2 client connection whose requests carry pipes: every pipe it
/// opens reports the connection as its carrier connection, and a
/// bidirectional one opens lanes as further requests when
/// [`Options::lanes`] is on. Cheap to clone; the connection stays open
/// while a clone or one of its requests is alive.
#[derive(Clone)]
pub struct Http2Connection {
    inner: Arc<H2Inner>,
}

struct H2Inner {
    sender: http2::SendRequest<PipeBody>,
    authority: String,
    options: Options,
}

impl std::fmt::Debug for Http2Connection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Http2Connection")
            .field("authority", &self.inner.authority)
            .finish_non_exhaustive()
    }
}

impl Http2Connection {
    /// An HTTP/2 connection (prior knowledge, no TLS) to `addr`
    /// (`host:port`, also the `:authority`).
    pub async fn connect(addr: &str, options: Options) -> io::Result<Self> {
        Self::handshake(tcp(addr).await?, addr, options).await
    }

    /// HTTP/2 on an established connection, any byte stream such as a TLS
    /// stream whose ALPN chose `h2`, with `authority` as the
    /// `:authority` of its requests.
    ///
    /// ```no_run
    /// # async fn example(tls: tokio_rustls::TlsConnector,
    /// #     name: tokio_rustls::rustls::pki_types::ServerName<'static>) -> Result<(), Box<dyn std::error::Error>> {
    /// let tcp = tokio::net::TcpStream::connect("example.com:443").await?;
    /// let conn = tls.connect(name, tcp).await?;
    /// let h2 = zmux_http::Http2Connection::handshake(conn, "example.com", Default::default()).await?;
    /// let session = h2.connect_session(zmux::Config::default()).await?;
    /// # drop(session);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn handshake<IO>(io: IO, authority: &str, options: Options) -> io::Result<Self>
    where
        IO: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        let (sender, conn) = within(options.timeout, async {
            http2::handshake::<_, _, PipeBody>(TokioExecutor::new(), TokioIo::new(io))
                .await
                .map_err(hyper_err)
        })
        .await?;
        tokio::spawn(conn);
        Ok(Self {
            inner: Arc::new(H2Inner {
                sender,
                authority: authority.to_owned(),
                options,
            }),
        })
    }

    /// The connection's identity, as its pipes report it.
    pub fn conn_id(&self) -> CarrierConnId {
        CarrierConnId::new(&self.inner)
    }

    /// A bidirectional carrier on a new request of the connection
    /// ([`Http2Connection::open_carrier`] with [`DialRequest::bidi`]).
    pub async fn open_pipe(&self) -> io::Result<PipeIo> {
        self.open_carrier(&DialRequest::bidi()).await
    }

    /// A carrier of `request`'s direction on a new request of the
    /// connection (see [`dial_http1_carrier_over`]), returned once the
    /// request is under way; its reads wait for the response, which must
    /// arrive within [`Options::timeout`]. A bidirectional one opens lanes
    /// with [`Options::lanes`].
    pub async fn open_carrier(&self, request: &DialRequest) -> io::Result<PipeIo> {
        let head = Head::of(request);
        let bidi = head.direction == PipeDirection::Bidi;
        let mut io = self.open(head).await?;
        if bidi && self.inner.options.lanes {
            let inner = self.inner.clone();
            io = io.with_lane_opener(move || {
                let inner = inner.clone();
                async move {
                    inner
                        .open_lane()
                        .await
                        .map(zmux::carrier::Lane::from_chunks)
                }
            });
        }
        Ok(io)
    }

    /// A split bootstrap on two new requests of the connection, an uplink
    /// `POST` and a downlink `GET` with one fresh pairing token (see
    /// [`dial_http1_split_with`]).
    pub async fn open_split(&self) -> io::Result<PipeIo> {
        let (up, down) = split_heads()?;
        let up = self.open(up).await?;
        let down = self.open(down).await?;
        Ok(PipeIo::split_bootstrap(up, down).with_carrier(CarrierKind::Split))
    }

    async fn open(&self, head: Head) -> io::Result<PipeIo> {
        self.open_at(head, &self.inner.options, None).await
    }

    /// A carrier request at `options`' path; its redirects are followed on
    /// further requests of the connection, `target` recording where they
    /// led.
    async fn open_at(
        &self,
        head: Head,
        options: &Options,
        target: Option<Arc<HttpTarget>>,
    ) -> io::Result<PipeIo> {
        let (resp, body) =
            within(options.timeout, self.inner.send(&head, &options.path, None)).await?;
        let abort = body.as_ref().map(|(_, a)| a.clone());
        let (inner, h) = (self.inner.clone(), head.clone());
        let resend: Resend = Arc::new(move |path| {
            let (inner, h, abort) = (inner.clone(), h.clone(), abort.clone());
            Box::pin(async move {
                let (resp, _) = inner.send(&h, &path, abort.as_ref()).await?;
                Ok(resp)
            })
        });
        let follow = Follow::new(
            options,
            &self.inner.authority,
            &head,
            body.as_ref(),
            target,
            resend,
        );
        Ok(
            carrier(options.timeout, Sent { head, body, resp }, Some(follow))
                .with_carrier_conn(self.conn_id()),
        )
    }

    /// Establishes a session on a new bidirectional request of the
    /// connection.
    pub async fn connect_session(
        &self,
        config: impl Into<Arc<zmux::Config>>,
    ) -> Result<Session, ConnectError> {
        let io = self
            .open_pipe()
            .await
            .map_err(|e| ConnectError::Io(Arc::new(e)))?;
        Session::connect(io, config).await
    }

    /// Establishes a session on a split bootstrap of the connection
    /// ([`Http2Connection::open_split`]).
    pub async fn connect_split_session(
        &self,
        config: impl Into<Arc<zmux::Config>>,
    ) -> Result<Session, ConnectError> {
        let io = self
            .open_split()
            .await
            .map_err(|e| ConnectError::Io(Arc::new(e)))?;
        Session::connect(io, config).await
    }

    /// A [`Dial`] for the session's helpers: every carrier on a new
    /// request of this connection ([`Http2Connection::open_carrier`]).
    pub fn dial(&self) -> Dial {
        let conn = self.clone();
        Dial::new(move |request: DialRequest| {
            let conn = conn.clone();
            async move { conn.open_carrier(&request).await }
        })
    }
}

type ResponseFuture =
    Pin<Box<dyn Future<Output = Result<Response<Incoming>, hyper::Error>> + Send>>;

impl H2Inner {
    /// Sends the request of `head` once the connection can take one; the
    /// future resolves to its response head.
    async fn send(
        &self,
        head: &Head,
        path: &str,
        repeat: Option<&body::Abort>,
    ) -> io::Result<(ResponseFuture, Option<BodyFeed>)> {
        let mut sender = self.sender.clone();
        sender.ready().await.map_err(hyper_err)?;
        let (req, body) =
            self.options
                .carrier_request(&self.authority, path, Version::HTTP_2, head, repeat)?;
        Ok((Box::pin(sender.send_request(req)), body))
    }

    /// A lane: a further request whose body is the lane, returned once the
    /// request is under way. Its response, the unused reverse half, is read
    /// to its end meanwhile; one that fails, is not 200 or does not arrive
    /// within [`Options::timeout`] fails the lane's writes.
    async fn open_lane(self: Arc<Self>) -> io::Result<body::BodyWriter> {
        let head = Head {
            direction: PipeDirection::Bidi,
            pair: None,
        };
        let (resp, body) = within(
            self.options.timeout,
            self.send(&head, &self.options.path, None),
        )
        .await?;
        let Some((writer, abort)) = body else {
            return Err(io::Error::other("a lane request without a body"));
        };
        let mut reader = ResponseReader::spawn(self.options.timeout, resp, None, None);
        tokio::spawn(async move {
            if tokio::io::copy(&mut reader, &mut tokio::io::sink())
                .await
                .is_err()
            {
                abort.run();
            }
        });
        Ok(writer)
    }
}

/// Establishes a session over a new HTTP/2 connection
/// ([`Http2Connection::connect`], then
/// [`Http2Connection::connect_session`]); further pipes of the session
/// need the connection handle.
pub async fn connect_http2(
    addr: &str,
    options: &Options,
    config: impl Into<Arc<zmux::Config>>,
) -> Result<Session, ConnectError> {
    let conn = Http2Connection::connect(addr, options.clone())
        .await
        .map_err(|e| ConnectError::Io(Arc::new(e)))?;
    conn.connect_session(config).await
}

// ---- candidates of carrier modes ---------------------------------------------------

/// A [`Candidate`] of [`CarrierKind::Streaming`]: a bidirectional
/// `POST` over a new HTTP/1.1 connection that `connect` makes
/// ([`dial_http1_over`]). It passes intermediaries that forward both bodies
/// at once.
pub fn candidate<C, F, IO>(connect: C, authority: &str, options: &Options) -> Candidate
where
    C: Fn() -> F + Send + Sync + 'static,
    F: Future<Output = io::Result<IO>> + Send + 'static,
    IO: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let connect = Arc::new(connect);
    let target = Arc::new(HttpTarget::new(options.url(authority, &options.path)));
    let authority: Arc<str> = authority.into();
    let options = Arc::new(options.clone());
    let named = target.clone();
    Candidate::new(CarrierKind::Streaming, move || {
        let (connect, authority, target) = (connect.clone(), authority.clone(), target.clone());
        let options = options.at(&target);
        async move {
            let head = Head::of(&DialRequest::bidi());
            let io = match connect().await {
                Ok(io) => io,
                Err(e) => {
                    target.reset();
                    return Err(e);
                }
            };
            let again = redial(connect);
            send_http1(io, &authority, &options, head, Some(again), Some(target)).await
        }
    })
    .with_target(named)
}

/// A [`Candidate`] of [`CarrierKind::Split`]: a split bootstrap over
/// HTTP/1.1 connections that `connect` makes ([`dial_http1_split_with`]);
/// as a further pipe of a session it joins across a paired `POST` and `GET`
/// ([`join_http1_split_with`]). Its
/// carriers must be confidential to the server or to a trusted
/// TLS-terminating intermediary.
pub fn candidate_split<C, F, IO>(connect: C, authority: &str, options: &Options) -> Candidate
where
    C: Fn() -> F + Send + Sync + 'static,
    F: Future<Output = io::Result<IO>> + Send + 'static,
    IO: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let connect = Arc::new(connect);
    let target = Arc::new(HttpTarget::new(options.url(authority, &options.path)));
    let authority: Arc<str> = authority.into();
    let options = Arc::new(options.clone());
    let (c, a, o, t) = (
        connect.clone(),
        authority.clone(),
        options.clone(),
        target.clone(),
    );
    Candidate::new(CarrierKind::Split, move || {
        let (connect, authority, target) = (c.clone(), a.clone(), t.clone());
        let options = o.at(&target);
        async move {
            let r = split_http1(connect, &authority, &options, Some(target.clone())).await;
            if r.is_err() {
                target.reset();
            }
            r
        }
    })
    .with_target(target)
    .with_join(move |session, pipe_options| {
        let (connect, authority, options) = (connect.clone(), authority.clone(), options.clone());
        async move {
            join_http1_split_with(
                &session,
                move || connect(),
                &authority,
                &options,
                pipe_options,
            )
            .await
        }
    })
}

/// A [`Candidate`] of [`CarrierKind::Exchange`]: an exchange carrier
/// whose requests go over HTTP/1.1 connections that `connect` makes
/// ([`crate::dial_exchange_with`]). It passes intermediaries that buffer
/// whole bodies; it authenticates with the exchange's PSK, and
/// [`Options::carrier_credential`] is not presented on it.
pub fn candidate_exchange<C, F, IO>(
    connect: C,
    authority: &str,
    options: &crate::ExchangeOptions,
) -> Candidate
where
    C: Fn() -> F + Send + Sync + 'static,
    F: Future<Output = io::Result<IO>> + Send + 'static,
    IO: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let endpoint = crate::ExchangeEndpoint::new(connect, authority);
    let options = options.clone();
    Candidate::new(CarrierKind::Exchange, move || {
        let r = crate::dial_exchange_split(endpoint.clone(), endpoint.clone(), &options);
        async move { r }
    })
}

impl Http2Connection {
    /// A [`Candidate`] of [`CarrierKind::Streaming`] on new requests
    /// of this connection ([`Http2Connection::open_pipe`]).
    pub fn candidate(&self) -> Candidate {
        let conn = self.clone();
        let target = Arc::new(self.target());
        let named = target.clone();
        Candidate::new(CarrierKind::Streaming, move || {
            let (conn, target) = (conn.clone(), target.clone());
            async move {
                let options = conn.inner.options.at(&target);
                let head = Head::of(&DialRequest::bidi());
                let r = conn.open_at(head, &options, Some(target.clone())).await;
                if r.is_err() {
                    target.reset();
                }
                r
            }
        })
        .with_target(named)
    }

    /// A target at the URL of the connection's carriers.
    fn target(&self) -> HttpTarget {
        let o = &self.inner.options;
        HttpTarget::new(o.url(&self.inner.authority, &o.path))
    }

    /// A [`Candidate`] of [`CarrierKind::Split`] on new requests of
    /// this connection ([`Http2Connection::open_split`]; see
    /// [`candidate_split`]).
    pub fn candidate_split(&self) -> Candidate {
        let conn = self.clone();
        let joining = self.clone();
        let target = Arc::new(self.target());
        let named = target.clone();
        Candidate::new(CarrierKind::Split, move || {
            let (conn, target) = (conn.clone(), target.clone());
            async move {
                let options = conn.inner.options.at(&target);
                let (up, down) = split_heads()?;
                let r = async {
                    let up = conn.open_at(up, &options, Some(target.clone())).await?;
                    let down = conn.open_at(down, &options, Some(target.clone())).await?;
                    Ok(PipeIo::split_bootstrap(up, down).with_carrier(CarrierKind::Split))
                }
                .await;
                if r.is_err() {
                    target.reset();
                }
                r
            }
        })
        .with_target(named)
        .with_join(move |session, pipe_options| {
            let conn = joining.clone();
            async move { conn.join_split(&session, pipe_options).await }
        })
    }

    /// Joins a split carrier on two new requests of the connection to `session`: one Join
    /// across a paired `POST` and `GET` (see [`join_http1_split_with`]).
    pub async fn join_split(
        &self,
        session: &Session,
        pipe_options: PipeOptions,
    ) -> io::Result<Vec<Pipe>> {
        let (up, down) = split_heads()?;
        let up = self.open(up).await?;
        let down = self.open(down).await?;
        let io = PipeIo::paired_join(up, down).with_carrier(CarrierKind::Split);
        let to_io = |e: zmux::PipeError| io::Error::other(e.to_string());
        let pipe = session.add_pipe(io, pipe_options).await.map_err(to_io)?;
        Ok(vec![pipe])
    }
}
