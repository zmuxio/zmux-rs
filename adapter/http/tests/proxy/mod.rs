//! A reverse proxy for the carrier mode tests, HTTP/1.1 on both sides,
//! with the forwarding behaviours of common intermediaries: request
//! bodies buffered whole (and forwarded with a `Content-Length`) or
//! streamed; responses streamed, buffered unless `X-Accel-Buffering: no`,
//! or always buffered; the response held until the request body ended (a
//! hop that is not full duplex); WebSocket upgrades refused, passed, or
//! the only requests passed.

use std::io;
use std::net::SocketAddr;

use bytes::BytesMut;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

/// How responses are forwarded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Responses {
    Stream,
    /// Buffered whole unless the response says `X-Accel-Buffering: no`.
    BufferUnlessAccelNo,
    Buffer,
}

/// What becomes of WebSocket upgrades.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Upgrades {
    Refuse,
    Pass,
    /// Only upgrades pass; every other request is refused.
    Only,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct Profile {
    pub(crate) buffer_requests: bool,
    pub(crate) responses: Responses,
    /// The response is forwarded only once the request body ended.
    pub(crate) half_duplex: bool,
    pub(crate) upgrades: Upgrades,
}

impl Profile {
    /// A reverse proxy with its defaults: request bodies buffered,
    /// responses buffered unless `X-Accel-Buffering: no`, no WebSocket.
    pub(crate) const REVERSE_PROXY: Self = Self {
        buffer_requests: true,
        responses: Responses::BufferUnlessAccelNo,
        half_duplex: false,
        upgrades: Upgrades::Refuse,
    };
    /// A CDN that buffers every body.
    pub(crate) const BUFFERING_CDN: Self = Self {
        buffer_requests: true,
        responses: Responses::Buffer,
        half_duplex: false,
        upgrades: Upgrades::Refuse,
    };
    /// Bodies streamed, but the response only after the request body.
    pub(crate) const HALF_DUPLEX: Self = Self {
        buffer_requests: false,
        responses: Responses::BufferUnlessAccelNo,
        half_duplex: true,
        upgrades: Upgrades::Refuse,
    };
    /// A transparent front: bodies streamed both ways, WebSocket passed.
    pub(crate) const TRANSPARENT: Self = Self {
        buffer_requests: false,
        responses: Responses::Stream,
        half_duplex: false,
        upgrades: Upgrades::Pass,
    };
    /// A front that passes WebSocket only.
    pub(crate) const WEBSOCKET_ONLY: Self = Self {
        buffer_requests: true,
        responses: Responses::Buffer,
        half_duplex: false,
        upgrades: Upgrades::Only,
    };
}

/// Serves `profile` in front of `origin`; its address and task.
pub(crate) async fn start(profile: Profile, origin: SocketAddr) -> (String, JoinHandle<()>) {
    let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = tcp.local_addr().unwrap().to_string();
    let task = tokio::spawn(async move {
        while let Ok((client, _)) = tcp.accept().await {
            let _ = client.set_nodelay(true);
            tokio::spawn(async move {
                let _ = serve(profile, client, origin).await;
            });
        }
    });
    (addr, task)
}

/// A reader with the bytes read ahead.
struct Buffered<R> {
    r: R,
    buf: BytesMut,
}

impl<R: AsyncRead + Unpin> Buffered<R> {
    fn new(r: R) -> Self {
        Self {
            r,
            buf: BytesMut::new(),
        }
    }

    /// Reads more; `false` at the end.
    async fn fill(&mut self) -> io::Result<bool> {
        let mut chunk = [0u8; 16 << 10];
        let n = self.r.read(&mut chunk).await?;
        self.buf.extend_from_slice(&chunk[..n]);
        Ok(n > 0)
    }

    /// The bytes up to and including the next `\r\n\r\n` (a head), or
    /// `None` at a clean end.
    async fn head(&mut self) -> io::Result<Option<Vec<u8>>> {
        loop {
            if let Some(i) = self.buf.windows(4).position(|w| w == b"\r\n\r\n") {
                return Ok(Some(self.buf.split_to(i + 4).to_vec()));
            }
            if !self.fill().await? {
                return if self.buf.is_empty() {
                    Ok(None)
                } else {
                    Err(io::ErrorKind::UnexpectedEof.into())
                };
            }
        }
    }

    /// One line, with its `\r\n`.
    async fn line(&mut self) -> io::Result<Vec<u8>> {
        loop {
            if let Some(i) = self.buf.windows(2).position(|w| w == b"\r\n") {
                return Ok(self.buf.split_to(i + 2).to_vec());
            }
            if !self.fill().await? {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
        }
    }

    /// Up to `n` bytes (at least one).
    async fn some(&mut self, n: usize) -> io::Result<Vec<u8>> {
        if self.buf.is_empty() && !self.fill().await? {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        let k = n.min(self.buf.len());
        Ok(self.buf.split_to(k).to_vec())
    }
}

/// A parsed head: its first line and fields.
struct Head {
    first: String,
    fields: Vec<(String, String)>,
}

impl Head {
    fn parse(raw: &[u8]) -> Self {
        let text = String::from_utf8_lossy(raw);
        let mut lines = text.split("\r\n");
        let first = lines.next().unwrap_or_default().to_owned();
        let fields = lines
            .filter(|l| !l.is_empty())
            .filter_map(|l| l.split_once(':'))
            .map(|(n, v)| (n.trim().to_ascii_lowercase(), v.trim().to_owned()))
            .collect();
        Self { first, fields }
    }

    fn get(&self, name: &str) -> Option<&str> {
        self.fields
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }

    fn has_token(&self, name: &str, token: &str) -> bool {
        self.fields
            .iter()
            .filter(|(n, _)| n == name)
            .flat_map(|(_, v)| v.split(','))
            .any(|t| t.trim().eq_ignore_ascii_case(token))
    }

    fn framing(&self, request: bool) -> Framing {
        if self.has_token("transfer-encoding", "chunked") {
            Framing::Chunked
        } else if let Some(n) = self.get("content-length").and_then(|v| v.parse().ok()) {
            Framing::Length(n)
        } else if request {
            Framing::Length(0)
        } else {
            Framing::Close
        }
    }

    /// The head with the body length set to `len` (chunked coding removed).
    fn with_length(&self, len: usize) -> Vec<u8> {
        let mut out = format!("{}\r\n", self.first);
        for (n, v) in &self.fields {
            if n != "content-length" && n != "transfer-encoding" {
                out.push_str(&format!("{n}: {v}\r\n"));
            }
        }
        out.push_str(&format!("content-length: {len}\r\n\r\n"));
        out.into_bytes()
    }
}

#[derive(Debug, Clone, Copy)]
enum Framing {
    Length(usize),
    Chunked,
    /// Until the connection closes.
    Close,
}

/// Relays a body of `framing` from `r` to `w` as it arrives, its framing
/// kept; without `w`, collects its data instead.
async fn body<R, W>(
    r: &mut Buffered<R>,
    mut w: Option<&mut W>,
    framing: Framing,
) -> io::Result<Vec<u8>>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut collected = Vec::new();
    // Framing bytes go to the writer only; data to the writer or collected.
    async fn put<W: AsyncWrite + Unpin>(
        w: &mut Option<&mut W>,
        collected: &mut Vec<u8>,
        bytes: &[u8],
        data: bool,
    ) -> io::Result<()> {
        match w {
            Some(w) => w.write_all(bytes).await,
            None if data => {
                collected.extend_from_slice(bytes);
                Ok(())
            }
            None => Ok(()),
        }
    }
    match framing {
        Framing::Length(mut n) => {
            while n > 0 {
                let b = r.some(n).await?;
                n -= b.len();
                put(&mut w, &mut collected, &b, true).await?;
            }
        }
        Framing::Close => loop {
            if r.buf.is_empty() && !r.fill().await? {
                break;
            }
            let b = r.buf.split_to(r.buf.len()).to_vec();
            put(&mut w, &mut collected, &b, true).await?;
            if let Some(w) = w.as_deref_mut() {
                w.flush().await?;
            }
        },
        Framing::Chunked => loop {
            let line = r.line().await?;
            let size = usize::from_str_radix(
                String::from_utf8_lossy(&line)
                    .trim()
                    .split(';')
                    .next()
                    .unwrap_or("0"),
                16,
            )
            .map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?;
            put(&mut w, &mut collected, &line, false).await?;
            if size == 0 {
                // Trailers, then the empty line.
                loop {
                    let t = r.line().await?;
                    put(&mut w, &mut collected, &t, false).await?;
                    if t == b"\r\n" {
                        break;
                    }
                }
                break;
            }
            let mut n = size;
            while n > 0 {
                let b = r.some(n).await?;
                n -= b.len();
                put(&mut w, &mut collected, &b, true).await?;
            }
            let crlf = r.line().await?;
            put(&mut w, &mut collected, &crlf, false).await?;
            if let Some(w) = w.as_deref_mut() {
                w.flush().await?;
            }
        },
    }
    if let Some(w) = w {
        w.flush().await?;
    }
    Ok(collected)
}

const REFUSED: &[u8] = b"HTTP/1.1 403 Forbidden\r\ncontent-length: 0\r\nconnection: close\r\n\r\n";

async fn serve(profile: Profile, client: TcpStream, origin: SocketAddr) -> io::Result<()> {
    let (cr, mut cw) = client.into_split();
    let mut cr = Buffered::new(cr);
    while let Some(raw) = cr.head().await? {
        let head = Head::parse(&raw);
        let upgrade = head.has_token("upgrade", "websocket");
        let refused = match profile.upgrades {
            Upgrades::Refuse => upgrade,
            Upgrades::Pass => false,
            Upgrades::Only => !upgrade,
        };
        if refused {
            cw.write_all(REFUSED).await?;
            return Ok(());
        }
        let upstream = TcpStream::connect(origin).await?;
        let _ = upstream.set_nodelay(true);
        let (or, mut ow) = upstream.into_split();
        let mut or = Buffered::new(or);
        if upgrade {
            ow.write_all(&raw).await?;
            let resp = or.head().await?.ok_or(io::ErrorKind::UnexpectedEof)?;
            cw.write_all(&resp).await?;
            // Both directions as they are, with what was read ahead.
            cw.write_all(&std::mem::take(&mut or.buf)).await?;
            ow.write_all(&std::mem::take(&mut cr.buf)).await?;
            let up = tokio::io::copy(&mut cr.r, &mut ow);
            let down = tokio::io::copy(&mut or.r, &mut cw);
            let _ = tokio::join!(up, down);
            return Ok(());
        }
        let framing = head.framing(true);
        let close = head.has_token("connection", "close");
        let request = async {
            if profile.buffer_requests {
                let data =
                    body::<_, tokio::net::tcp::OwnedWriteHalf>(&mut cr, None, framing).await?;
                ow.write_all(&head.with_length(data.len())).await?;
                ow.write_all(&data).await?;
                ow.flush().await
            } else {
                ow.write_all(&raw).await?;
                body(&mut cr, Some(&mut ow), framing).await.map(drop)
            }
        };
        let (requested, response_end) = if profile.half_duplex || profile.buffer_requests {
            let r = request.await;
            (r, None)
        } else {
            let (r, s) = tokio::join!(request, respond(profile, &mut or, &mut cw));
            (r, Some(s))
        };
        requested?;
        let keep = match response_end {
            Some(s) => s?,
            None => respond(profile, &mut or, &mut cw).await?,
        };
        if close || !keep {
            return Ok(());
        }
    }
    Ok(())
}

/// Forwards one response; whether the client connection may carry another
/// request.
async fn respond<R, W>(profile: Profile, or: &mut Buffered<R>, cw: &mut W) -> io::Result<bool>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let raw = or.head().await?.ok_or(io::ErrorKind::UnexpectedEof)?;
    let head = Head::parse(&raw);
    let framing = head.framing(false);
    let buffer = match profile.responses {
        Responses::Stream => false,
        Responses::Buffer => true,
        Responses::BufferUnlessAccelNo => !head
            .get("x-accel-buffering")
            .is_some_and(|v| v.eq_ignore_ascii_case("no")),
    };
    if buffer {
        let data = body::<_, W>(or, None, framing).await?;
        cw.write_all(&head.with_length(data.len())).await?;
        cw.write_all(&data).await?;
        cw.flush().await?;
    } else {
        cw.write_all(&raw).await?;
        body(or, Some(cw), framing).await?;
    }
    Ok(!matches!(framing, Framing::Close) && !head.has_token("connection", "close"))
}
