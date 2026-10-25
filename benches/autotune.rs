//! Receive-window auto-tuning over an in-process shaper (CONFORMANCE.md; the
//! shaper variant of the auto-tuning experiment): each
//! direction of the pipe is a link with a fixed rate, a one-way delay and a
//! bottleneck queue, with no TCP below. Run with `cargo bench --bench
//! autotune [-- <scenario>...]`; one RESULT line per scenario.
//!
//! | scenario | link | target |
//! |---|---|---|
//! | `AT-4` | 1 Gbit/s, 20 ms RTT | >= 80 % of the link within 2 s |
//! | `AT-5` | 2.5 Gbit/s, 200 ms RTT, caps >= 4 x BDP | the last 5 s >= 95 % |
//! | `H-1s` | 1 Gbit/s, 100 ms RTT, queue 1 x BDP, default caps | the last 5 s >= 90 % |
//! | `AT-6` | 1 Gbit/s, 100 ms RTT, 100 streams | total >= 95 %, Jain >= 0.9 |

#![allow(missing_docs)]

use std::collections::VecDeque;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::{Instant, Sleep};
use zmux::{Config, PipeIo, Session};

/// One direction of a shaped link.
struct Link {
    /// Bytes per second.
    rate: f64,
    delay: Duration,
    /// The most bytes waiting for the bottleneck.
    queue: f64,
    state: Mutex<LinkState>,
}

#[derive(Default)]
struct LinkState {
    /// When the bottleneck is free again.
    free_at: Option<Instant>,
    /// Bytes in flight: arrival time and data.
    flight: VecDeque<(Instant, Vec<u8>)>,
    reader: Option<Waker>,
    closed: bool,
}

struct Writer {
    link: Arc<Link>,
    wait: Option<Pin<Box<Sleep>>>,
}

struct Reader {
    link: Arc<Link>,
    wait: Option<Pin<Box<Sleep>>>,
}

fn link(rate_bps: f64, delay: Duration, queue_bytes: f64) -> (Writer, Reader) {
    let l = Arc::new(Link {
        rate: rate_bps / 8.0,
        delay,
        queue: queue_bytes,
        state: Mutex::new(LinkState::default()),
    });
    (
        Writer {
            link: l.clone(),
            wait: None,
        },
        Reader {
            link: l,
            wait: None,
        },
    )
}

impl AsyncWrite for Writer {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let now = Instant::now();
        let mut st = self.link.state.lock().unwrap();
        let free = st.free_at.unwrap_or(now).max(now);
        // A full bottleneck queue stops the writer until it drains.
        let backlog = (free - now).as_secs_f64() * self.link.rate;
        if backlog > self.link.queue {
            let at = free - Duration::from_secs_f64(self.link.queue / self.link.rate);
            drop(st);
            let w = self.wait.insert(Box::pin(tokio::time::sleep_until(at)));
            if w.as_mut().poll(cx).is_pending() {
                return Poll::Pending;
            }
            self.wait = None;
            return self.poll_write(cx, buf);
        }
        let n = buf.len().min(64 * 1024);
        let depart = free + Duration::from_secs_f64(n as f64 / self.link.rate);
        st.free_at = Some(depart);
        st.flight
            .push_back((depart + self.link.delay, buf[..n].to_vec()));
        if let Some(w) = st.reader.take() {
            w.wake();
        }
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut st = self.link.state.lock().unwrap();
        st.closed = true;
        if let Some(w) = st.reader.take() {
            w.wake();
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncRead for Reader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            let now = Instant::now();
            let mut st = self.link.state.lock().unwrap();
            let Some((at, _)) = st.flight.front() else {
                if st.closed {
                    return Poll::Ready(Ok(()));
                }
                st.reader = Some(cx.waker().clone());
                return Poll::Pending;
            };
            let at = *at;
            if at <= now {
                let (_, data) = st.flight.front_mut().unwrap();
                let k = data.len().min(buf.remaining());
                buf.put_slice(&data[..k]);
                if k == data.len() {
                    st.flight.pop_front();
                } else {
                    data.drain(..k);
                }
                return Poll::Ready(Ok(()));
            }
            drop(st);
            let w = self.wait.insert(Box::pin(tokio::time::sleep_until(at)));
            if w.as_mut().poll(cx).is_pending() {
                return Poll::Pending;
            }
            self.wait = None;
        }
    }
}

/// A shaped pipe pair: (client side, server side).
fn pipes(rate_bps: f64, rtt: Duration, queue_bytes: f64) -> (PipeIo, PipeIo) {
    let one_way = rtt / 2;
    let (cw, sr) = link(rate_bps, one_way, queue_bytes);
    let (sw, cr) = link(rate_bps, one_way, queue_bytes);
    (PipeIo::from_halves(cr, cw), PipeIo::from_halves(sr, sw))
}

struct Scenario {
    name: &'static str,
    rate_bps: f64,
    rtt: Duration,
    queue_bdp: f64,
    streams: usize,
    secs: u64,
    caps: Option<(u64, u64)>,
}

async fn run(sc: &Scenario) {
    let bdp = sc.rate_bps / 8.0 * sc.rtt.as_secs_f64();
    let (pc, ps) = pipes(sc.rate_bps, sc.rtt, sc.queue_bdp * bdp);
    let mut config = Config::default();
    if let Some((stream, session)) = sc.caps {
        config.max_stream_receive_window = zmux::Cap::Fixed(stream);
        config.max_connection_receive_window = zmux::Cap::Fixed(session);
        config.send_buffer_max = zmux::Cap::Fixed(session);
    }
    let server = tokio::spawn(Session::accept(ps, config.clone()));
    let client = Session::connect(pc, config).await.unwrap();
    let server = server.await.unwrap().unwrap();
    let counters: Arc<Vec<AtomicU64>> =
        Arc::new((0..sc.streams).map(|_| AtomicU64::new(0)).collect());
    // Readers.
    {
        let counters = counters.clone();
        let server = server.clone();
        let n = sc.streams;
        tokio::spawn(async move {
            for _ in 0..n {
                let Ok((_, mut r)) = server.accept_bi().await else {
                    return;
                };
                let counters = counters.clone();
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 256 * 1024];
                    let mut i = None;
                    loop {
                        match r.read(&mut buf).await {
                            Ok(Some(k)) => {
                                let idx = *i.get_or_insert_with(|| buf[0] as usize);
                                counters[idx % counters.len()].fetch_add(k as u64, Relaxed);
                            }
                            _ => return,
                        }
                    }
                });
            }
        });
    }
    // Writers: the first byte names the stream.
    for s in 0..sc.streams {
        let (mut w, _r) = client.open_bi().await.unwrap();
        let chunk = bytes::Bytes::from(vec![s as u8; 64 * 1024]);
        tokio::spawn(async move {
            let _keep = _r;
            while w.write_chunk(chunk.clone()).await.is_ok() {}
        });
    }
    // Throughput per 100 ms.
    let total = || counters.iter().map(|c| c.load(Relaxed)).sum::<u64>();
    let start = Instant::now();
    let mut samples = Vec::new();
    let mut last = 0u64;
    let tick = Duration::from_millis(100);
    let mut next = start + tick;
    while next <= start + Duration::from_secs(sc.secs) {
        tokio::time::sleep_until(next).await;
        let t = total();
        samples.push((t - last) as f64 * 8.0 / tick.as_secs_f64());
        last = t;
        next += tick;
    }
    let link = sc.rate_bps;
    let first_at = |pct: f64| {
        samples
            .iter()
            .position(|&r| r >= pct * link)
            .map_or(f64::NAN, |i| (i + 1) as f64 * 0.1)
    };
    let tail: Vec<f64> = samples.iter().rev().take(50).copied().collect();
    let last5 = tail.iter().sum::<f64>() / tail.len() as f64 / link;
    let shares: Vec<f64> = counters.iter().map(|c| c.load(Relaxed) as f64).collect();
    let jain = {
        let s: f64 = shares.iter().sum();
        let q: f64 = shares.iter().map(|x| x * x).sum();
        s * s / (shares.len() as f64 * q)
    };
    let stats = client.stats();
    println!(
        "RESULT scen={} rate_Mbps={:.0} rtt_ms={} last5s_pct={:.1} t80_s={:.1} t90_s={:.1} jain={:.3} client_rtt_us={:?} sent_MB={:.0}",
        sc.name,
        link / 1e6,
        sc.rtt.as_millis(),
        last5 * 100.0,
        first_at(0.8),
        first_at(0.9),
        jain,
        client.rtt().map(|r| r.as_micros()),
        stats.bytes_sent as f64 / 1e6,
    );
    client.close(zmux::VarInt::from_u32(0), b"");
}

fn main() {
    let filter: Vec<String> = std::env::args()
        .skip(1)
        .filter(|a| !a.starts_with('-'))
        .collect();
    let want = |name: &str| filter.is_empty() || filter.iter().any(|f| name == f);
    let ms = Duration::from_millis;
    let scenarios = [
        Scenario {
            name: "AT-4",
            rate_bps: 1e9,
            rtt: ms(20),
            queue_bdp: 1.0,
            streams: 1,
            secs: 5,
            caps: None,
        },
        Scenario {
            name: "H-1s",
            rate_bps: 1e9,
            rtt: ms(100),
            queue_bdp: 1.0,
            streams: 1,
            secs: 20,
            caps: None,
        },
        Scenario {
            name: "AT-5",
            rate_bps: 2.5e9,
            rtt: ms(200),
            queue_bdp: 1.0,
            streams: 1,
            secs: 12,
            caps: Some((256 << 20, 384 << 20)),
        },
        Scenario {
            name: "AT-6",
            rate_bps: 1e9,
            rtt: ms(100),
            queue_bdp: 1.0,
            streams: 100,
            secs: 20,
            caps: None,
        },
    ];
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .unwrap();
    for sc in scenarios.iter().filter(|s| want(s.name)) {
        rt.block_on(run(sc));
    }
}
