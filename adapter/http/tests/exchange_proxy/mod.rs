//! A fault-injecting reverse proxy for the exchange carrier's tests, on raw
//! TCP: it reads each request whole, forwards it to the origin as HTTP/1.0
//! with a `Content-Length`, reads the whole response until the origin
//! closes, and answers the client with an HTTP/1.0 response delimited by
//! closing the connection (no `Content-Length`, no chunked coding). Every
//! request may meet a fault drawn from a seeded generator.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

/// What may happen to a request: the probability of each fault (they are
/// drawn in this order, at most one per request), and the bounds.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct Faults {
    /// The connection closes before the request is forwarded.
    pub(crate) drop_request: f64,
    /// The origin processes the request; the response is lost.
    pub(crate) drop_response: f64,
    /// The origin processes the request; the client gets a 502.
    pub(crate) error: f64,
    /// The request is forwarded twice; the client gets one response.
    pub(crate) duplicate: f64,
    /// The client gets an earlier response of the origin instead (a cache
    /// answering what it should not); the request is not forwarded.
    pub(crate) replay: f64,
    /// Every request waits up to this before it is forwarded, so that
    /// requests overtake one another.
    pub(crate) reorder: Duration,
    /// A request whose response takes longer than this is cut.
    pub(crate) cut: Option<Duration>,
}

/// Counts of the faults applied.
#[derive(Debug, Default)]
pub(crate) struct Stats {
    pub(crate) requests: AtomicU64,
    pub(crate) dropped_requests: AtomicU64,
    pub(crate) dropped_responses: AtomicU64,
    pub(crate) errors: AtomicU64,
    pub(crate) duplicates: AtomicU64,
    pub(crate) replays: AtomicU64,
    pub(crate) cuts: AtomicU64,
}

impl Stats {
    pub(crate) fn get(c: &AtomicU64) -> u64 {
        c.load(Ordering::Relaxed)
    }
}

/// A seeded generator (xorshift64*).
pub(crate) struct Rng(u64);

impl Rng {
    pub(crate) fn new(seed: u64) -> Self {
        Self(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1)
    }

    pub(crate) fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    /// A value in [0, 1).
    pub(crate) fn unit(&mut self) -> f64 {
        (self.next() >> 11) as f64 / (1u64 << 53) as f64
    }
}

struct Shared {
    origin: String,
    faults: Faults,
    rng: Mutex<Rng>,
    /// Earlier 200 responses of the origin, newest last.
    cache: Mutex<Vec<Vec<u8>>>,
    stats: Arc<Stats>,
}

/// A running proxy; it stops when dropped.
pub(crate) struct Proxy {
    pub(crate) addr: String,
    pub(crate) stats: Arc<Stats>,
    task: JoinHandle<()>,
}

impl Drop for Proxy {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Proxy {
    pub(crate) async fn start(origin: &str, faults: Faults, seed: u64) -> Self {
        let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = tcp.local_addr().unwrap().to_string();
        let stats = Arc::new(Stats::default());
        let shared = Arc::new(Shared {
            origin: origin.to_owned(),
            faults,
            rng: Mutex::new(Rng::new(seed)),
            cache: Mutex::new(Vec::new()),
            stats: stats.clone(),
        });
        let task = tokio::spawn(async move {
            // Connection tasks end with the accept loop.
            let mut conns = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    a = tcp.accept() => {
                        let Ok((conn, _)) = a else { continue };
                        conns.spawn(serve(shared.clone(), conn));
                    }
                    Some(_) = conns.join_next() => {}
                }
            }
        });
        Self { addr, stats, task }
    }
}

/// Reads one HTTP message head and its `Content-Length` body (or, with
/// `to_close`, everything until the peer closes). Returns the head and the
/// body.
async fn read_message(conn: &mut TcpStream, to_close: bool) -> Option<(String, Vec<u8>)> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 16 * 1024];
    let end = loop {
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break i + 4;
        }
        let n = conn.read(&mut chunk).await.ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&chunk[..n]);
    };
    let head = String::from_utf8(buf[..end].to_vec()).ok()?;
    let mut body = buf.split_off(end);
    let len = head.lines().find_map(|l| {
        let (k, v) = l.split_once(':')?;
        k.eq_ignore_ascii_case("content-length")
            .then(|| v.trim().parse::<usize>().ok())
            .flatten()
    });
    match len {
        Some(len) => {
            while body.len() < len {
                let n = conn.read(&mut chunk).await.ok()?;
                if n == 0 {
                    return None;
                }
                body.extend_from_slice(&chunk[..n]);
            }
            body.truncate(len);
        }
        None if to_close => {
            conn.read_to_end(&mut body).await.ok()?;
        }
        None => {}
    }
    Some((head, body))
}

/// Forwards a request to the origin as HTTP/1.0; returns the response's
/// status code and body.
async fn forward(origin: &str, target: &str, body: &[u8]) -> Option<(u16, Vec<u8>)> {
    let mut conn = TcpStream::connect(origin).await.ok()?;
    let head = format!(
        "POST {target} HTTP/1.0\r\nHost: {origin}\r\nContent-Length: {}\r\n\r\n",
        body.len()
    );
    conn.write_all(head.as_bytes()).await.ok()?;
    conn.write_all(body).await.ok()?;
    let (head, body) = read_message(&mut conn, true).await?;
    let code = head.split(' ').nth(1)?.parse().ok()?;
    Some((code, body))
}

async fn reply(conn: &mut TcpStream, code: u16, body: &[u8]) {
    let head = format!("HTTP/1.0 {code} X\r\n\r\n");
    let _ = conn.write_all(head.as_bytes()).await;
    let _ = conn.write_all(body).await;
    let _ = conn.shutdown().await;
}

async fn serve(shared: Arc<Shared>, mut conn: TcpStream) {
    let Some((head, body)) = read_message(&mut conn, false).await else {
        return;
    };
    let Some(target) = head.split(' ').nth(1).map(str::to_owned) else {
        return;
    };
    let f = shared.faults;
    let st = &shared.stats;
    st.requests.fetch_add(1, Ordering::Relaxed);
    let (draw, delay) = {
        let mut rng = shared.rng.lock().unwrap();
        let delay = if f.reorder.is_zero() {
            Duration::ZERO
        } else {
            f.reorder.mul_f64(rng.unit())
        };
        (rng.unit(), delay)
    };
    // The faults in order, each in its share of [0, 1).
    let mut at = 0.0;
    let mut pick = |p: f64| {
        let hit = draw >= at && draw < at + p;
        at += p;
        hit
    };
    let (drop_req, drop_resp, error, dup, replay) = (
        pick(f.drop_request),
        pick(f.drop_response),
        pick(f.error),
        pick(f.duplicate),
        pick(f.replay),
    );
    if drop_req {
        st.dropped_requests.fetch_add(1, Ordering::Relaxed);
        return;
    }
    if replay {
        let cached = {
            let cache = shared.cache.lock().unwrap();
            let i = shared.rng.lock().unwrap().next() as usize;
            (!cache.is_empty()).then(|| cache[i % cache.len()].clone())
        };
        if let Some(c) = cached {
            st.replays.fetch_add(1, Ordering::Relaxed);
            reply(&mut conn, 200, &c).await;
            return;
        }
    }
    tokio::time::sleep(delay).await;
    if dup {
        st.duplicates.fetch_add(1, Ordering::Relaxed);
        let (origin, target, body) = (shared.origin.clone(), target.clone(), body.clone());
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(5)).await;
            let _ = tokio::time::timeout(Duration::from_secs(30), forward(&origin, &target, &body))
                .await;
        });
    }
    let fwd = forward(&shared.origin, &target, &body);
    let resp = match f.cut {
        Some(cut) => match tokio::time::timeout(cut, fwd).await {
            Ok(r) => r,
            Err(_) => {
                st.cuts.fetch_add(1, Ordering::Relaxed);
                return;
            }
        },
        None => fwd.await,
    };
    let Some((code, resp)) = resp else {
        return;
    };
    if code == 200 {
        let mut cache = shared.cache.lock().unwrap();
        cache.push(resp.clone());
        if cache.len() > 32 {
            cache.remove(0);
        }
    }
    if drop_resp {
        st.dropped_responses.fetch_add(1, Ordering::Relaxed);
        return;
    }
    if error {
        st.errors.fetch_add(1, Ordering::Relaxed);
        reply(&mut conn, 502, b"bad gateway").await;
        return;
    }
    reply(&mut conn, code, &resp).await;
}
