//! A slow bootstrap path next to a fast joined one, on a paused clock: the session
//! runs at the fast path's rate, not the slow one's.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::Notify;
use tokio::time::{Instant, sleep, sleep_until};
use zmux::{Config, Listener, ListenerConfig, PipeAuth, PipeIo, PipeOptions, Session};

/// A one-way link: its delay, its rate in bytes per second and the bytes it buffers
/// before the sender waits.
#[derive(Clone, Copy)]
struct Link {
    delay: Duration,
    rate: f64,
    cap: usize,
}

/// What a direction holds: the bytes in flight, each with its delivery time.
#[derive(Default)]
struct Line {
    queue: VecDeque<(Vec<u8>, Instant)>,
    held: usize,
}

/// Carries `from` to `to` through `link`: each read is serialised at the rate after the
/// previous one and delivered after the delay.
async fn shape(
    mut from: impl AsyncRead + Unpin + Send + 'static,
    mut to: impl AsyncWrite + Unpin + Send + 'static,
    link: Link,
) {
    let line = Arc::new(Mutex::new(Line::default()));
    let (filled, drained) = (Arc::new(Notify::new()), Arc::new(Notify::new()));
    let deliver = {
        let (line, filled, drained) = (line.clone(), filled.clone(), drained.clone());
        tokio::spawn(async move {
            loop {
                let next = line.lock().unwrap().queue.front().map(|(_, at)| *at);
                let Some(at) = next else {
                    filled.notified().await;
                    continue;
                };
                sleep_until(at).await;
                let (b, _) = line.lock().unwrap().queue.pop_front().expect("queued");
                if to.write_all(&b).await.is_err() {
                    return;
                }
                line.lock().unwrap().held -= b.len();
                drained.notify_one();
            }
        })
    };
    let mut last = Instant::now();
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        let n = match from.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        while line.lock().unwrap().held >= link.cap {
            drained.notified().await;
        }
        last = last.max(Instant::now()) + Duration::from_secs_f64(n as f64 / link.rate);
        let mut l = line.lock().unwrap();
        l.held += n;
        l.queue.push_back((buf[..n].to_vec(), last + link.delay));
        drop(l);
        filled.notify_one();
    }
    // Delivers what is in flight, then ends the far side.
    while !line.lock().unwrap().queue.is_empty() {
        sleep(Duration::from_millis(10)).await;
    }
    deliver.abort();
}

/// A carrier through `link` both ways: the dialer's end and the listener's.
fn carrier(link: Link) -> (PipeIo, PipeIo) {
    let (near, a) = tokio::io::duplex(64 * 1024);
    let (b, far) = tokio::io::duplex(64 * 1024);
    let (ar, aw) = tokio::io::split(a);
    let (br, bw) = tokio::io::split(b);
    tokio::spawn(shape(ar, bw, link));
    tokio::spawn(shape(br, aw, link));
    (PipeIo::new(near), PipeIo::new(far))
}

fn config() -> Config {
    // Default probation and scheduler: the joined pipe takes no new data at first.
    let mut c = Config::default();
    c.max_pipes = 4;
    c.pipe_auth = PipeAuth::psk(*b"slow-path-test-psk-0123456789abc").with_end_to_end();
    c
}

/// The bytes echoed in 6 s of a stream offered at about 3 MB/s, over a bootstrap pipe
/// through `first` and a joined one through `joined`.
async fn echoed(first: Link, joined: Link) -> usize {
    echoed_with(config(), first, joined).await.0
}

/// As [`echoed`] with `config` on both ends; also the client's reinjected bytes, the
/// bytes it sent on the bootstrap pipe and its opportunistic copies.
async fn echoed_with(config: Config, first: Link, joined: Link) -> (usize, u64, u64, u64) {
    let config = || config.clone();
    let listener = Listener::new(config(), ListenerConfig::default()).unwrap();
    let serve = |p: PipeIo| {
        let l = listener.clone();
        tokio::spawn(async move { l.handle_pipe(p, Default::default()).await });
    };
    let (near, far) = carrier(first);
    serve(far);
    let client = Session::connect(near, config()).await.unwrap();
    let server = listener.accept().await.unwrap();
    let (near, far) = carrier(joined);
    serve(far);
    client
        .add_pipe(near, PipeOptions::default())
        .await
        .expect("the fast pipe joins");
    let echo = tokio::spawn(async move {
        let (mut send, mut recv) = server.accept_bi().await.unwrap();
        let mut buf = vec![0u8; 64 * 1024];
        while let Ok(Some(n)) = recv.read(&mut buf).await {
            if send.write_all(&buf[..n]).await.is_err() {
                break;
            }
        }
        server
    });
    let (mut send, mut recv) = client.open_bi().await.unwrap();
    // About 3 MB/s offered.
    let writer = tokio::spawn(async move {
        let chunk = vec![7u8; 32 * 1024];
        while send.write_all(&chunk).await.is_ok() {
            sleep(Duration::from_millis(10)).await;
        }
    });
    let start = Instant::now();
    let mut got = 0usize;
    let mut buf = vec![0u8; 64 * 1024];
    while let Ok(r) =
        tokio::time::timeout_at(start + Duration::from_secs(6), recv.read(&mut buf)).await
    {
        match r {
            Ok(Some(n)) => got += n,
            _ => break,
        }
    }
    writer.abort();
    echo.abort();
    let stats = client.stats();
    let slow_sent = client
        .pipe_stats()
        .iter()
        .find(|p| p.pipe.get() == 0)
        .map_or(0, |p| p.bytes_sent);
    client.close().await;
    (
        got,
        stats.bytes_reinjected,
        slow_sent,
        stats.bytes_opportunistic,
    )
}

const SLOW: Link = Link {
    delay: Duration::from_millis(300),
    rate: 3e4,
    cap: 16 << 20,
};
const FAST: Link = Link {
    delay: Duration::from_millis(20),
    rate: 5e6,
    cap: 256 << 10,
};

/// A slow bootstrap path (300 ms one way, 30 kB/s, a deep buffer) next to a fast
/// joined one: the first window goes on the slow path while the joined pipe is in
/// probation, and the stream's binding then moves and waits for that data. A blocked
/// direction gets any credit at once, so a few bytes of credit arrive during the move;
/// the direction stays held back by the data on the slow pipe, and opportunistic
/// reinjection re-sends it on the fast pipe. The echo's credit goes on the fast pipe
/// too, even while its carrier is momentarily full, rather than behind the slow pipe's
/// queue. The echo then runs at the offered rate.
#[tokio::test(start_paused = true)]
async fn a_slow_path_does_not_hold_the_session() {
    let got = echoed(SLOW, FAST).await;
    assert!(
        got >= 8 << 20,
        "echoed {got} bytes in 6 s next to a slow path, want at least 8 MiB of the ~19 MB offered"
    );
}

/// The harness itself: two fast paths carry the offered rate.
#[tokio::test(start_paused = true)]
async fn two_fast_paths_carry_the_offered_rate() {
    let got = echoed(FAST, FAST).await;
    assert!(
        got >= 8 << 20,
        "echoed {got} bytes in 6 s over two fast paths"
    );
}

/// With windows of 16 MiB no credit runs out: the direction is held by its binding,
/// which waits on the slow pipe, so opportunistic reinjection starts, and its penalty
/// of the slow pipe re-sends once what the moved direction left there. The copies
/// stay within what the slow pipe carried and the opportunistic copies.
#[tokio::test(start_paused = true)]
async fn a_penalty_resends_what_a_moved_direction_left_on_the_slow_pipe() {
    let mut c = config();
    c.initial_stream_receive_window = 16 << 20;
    c.initial_connection_receive_window = 16 << 20;
    let (got, reinjected, slow_sent, opportunistic) = echoed_with(c, SLOW, FAST).await;
    assert!(
        got >= 8 << 20,
        "echoed {got} bytes in 6 s with 16 MiB windows"
    );
    assert!(
        reinjected <= slow_sent + opportunistic,
        "re-sent {reinjected} bytes, the slow pipe sent {slow_sent} and {opportunistic} were copied"
    );
}
