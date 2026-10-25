//! `helpers::splice`: a relay between two outer
//! sessions forwards streams verbatim and propagates every end and error
//! of its table with the code unchanged, holds at most one chunk per
//! direction, forwards stream datagrams, charges its limiters exactly what
//! it forwarded, and leaves nothing behind when it ends or is dropped.

mod common;

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use bytes::Bytes;
use common::{connect, duplex, eventually, multi_thread, settle, snapshot, watchdog};
use tokio::task::JoinHandle;
use zmux::helpers::{SpliceEnd, SpliceError, SpliceOptions, Spliced, splice};
use zmux::proto::{ApplicationErrorCode, TransportParameters};
use zmux::{Cap, Config, Limiter, RecvStream, SendStream, Session, StreamError, VarInt};

fn carrier_failed() -> VarInt {
    VarInt::from_u64(ApplicationErrorCode::ZMUX_CARRIER_FAILED.0).unwrap()
}

fn rejected() -> VarInt {
    VarInt::from_u64(ApplicationErrorCode::ZMUX_REJECTED.0).unwrap()
}

/// A, the relay R and B: A–R and R–B are outer sessions; R splices.
struct Hop {
    a: Session,
    ra: Session,
    rb: Session,
    b: Session,
}

impl Hop {
    /// A–R with `a_r` at both ends, R–B with `r_out` at R and `b` at B.
    async fn new(a_r: Config, r_out: Config, b: Config) -> Self {
        Self::with_carrier(a_r, r_out, b, 1 << 20).await
    }

    /// [`Hop::new`] with an R–B carrier that buffers `buffer` bytes.
    async fn with_carrier(a_r: Config, r_out: Config, b: Config, buffer: usize) -> Self {
        let ((x, _), (y, _)) = duplex(1 << 20);
        let (a, ra) = connect(x, y, a_r.clone(), a_r).await;
        let ((x, _), (y, _)) = duplex(buffer);
        let (rb, b) = connect(x, y, r_out, b).await;
        Self { a, ra, rb, b }
    }

    async fn default() -> Self {
        let mut c = Config::default();
        c.enable_datagrams = true;
        Self::new(c.clone(), c.clone(), c).await
    }

    /// Relays the next stream A opens: opens the outbound stream with the
    /// carrier flag and TLVs of the inbound one, then splices.
    fn relay(&self, opts: SpliceOptions) -> JoinHandle<Result<Spliced, SpliceError>> {
        let (ra, rb) = (self.ra.clone(), self.rb.clone());
        tokio::spawn(async move {
            let (s_in, r_in) = ra.accept_bi().await.unwrap();
            let (s_out, r_out) = rb.open_bi_with(&r_in.preamble()).await.unwrap();
            splice((s_in, r_in), (s_out, r_out), opts).await
        })
    }

    /// A stream from A to B through the relay; B's side once it arrived
    /// (A writes `first` to open it).
    async fn stream(&self, first: &[u8]) -> ((SendStream, RecvStream), (SendStream, RecvStream)) {
        let (mut s, r) = self.a.open_bi().await.unwrap();
        s.write_all(first).await.unwrap();
        let far = self.b.accept_bi().await.unwrap();
        ((s, r), far)
    }

    fn close(&self) {
        self.a.close(VarInt::ZERO, b"");
        self.b.close(VarInt::ZERO, b"");
    }
}

fn pattern(len: usize, seed: usize) -> Vec<u8> {
    (0..len).map(|i| (i * 31 + seed + i / 977) as u8).collect()
}

async fn read_all(r: &mut RecvStream, limit: usize) -> Result<Vec<u8>, StreamError> {
    let mut out = Vec::new();
    loop {
        match r.read_chunk(64 * 1024).await? {
            Some(c) => {
                out.extend_from_slice(&c);
                assert!(out.len() <= limit, "more than written");
            }
            None => return Ok(out),
        }
    }
}

/// Reads until the stream ends: the bytes and the reset, if any.
async fn read_until_end(r: &mut RecvStream) -> (Vec<u8>, Option<StreamError>) {
    let mut out = Vec::new();
    loop {
        match r.read_chunk(64 * 1024).await {
            Ok(Some(c)) => out.extend_from_slice(&c),
            Ok(None) => return (out, None),
            Err(e) => return (out, Some(e)),
        }
    }
}

#[test]
fn both_directions_are_forwarded_and_finish() {
    multi_thread(async {
        let base = snapshot();
        {
            let hop = Hop::default().await;
            let relay = hop.relay(SpliceOptions::default());
            let up = pattern(8 << 20, 1);
            let down = pattern(3 << 20, 2);
            let ((mut s, mut r), (mut fs, mut fr)) = hop.stream(&up[..1]).await;
            let a = {
                let up = up.clone();
                tokio::spawn(async move {
                    s.write_all(&up[1..]).await.unwrap();
                    s.finish().unwrap();
                    let back = read_all(&mut r, 8 << 20).await.unwrap();
                    (s, back)
                })
            };
            let far = {
                let down = down.clone();
                tokio::spawn(async move {
                    fs.write_all(&down).await.unwrap();
                    fs.finish().unwrap();
                    let got = read_all(&mut fr, 8 << 20).await.unwrap();
                    (fs, got)
                })
            };
            let (_s, back) = watchdog(60, "A", a).await.unwrap();
            let (_fs, got) = watchdog(60, "B", far).await.unwrap();
            assert!(got == up && back == down, "bytes differ");
            let done = watchdog(10, "splice", relay).await.unwrap().unwrap();
            assert_eq!(done.a_to_b.end, SpliceEnd::Finished);
            assert_eq!(done.b_to_a.end, SpliceEnd::Finished);
            assert_eq!(done.a_to_b.bytes, up.len() as u64);
            assert_eq!(done.b_to_a.bytes, down.len() as u64);
            // The relay read exactly what it wrote, both ways.
            assert_eq!(hop.ra.meter().bytes_read(), hop.rb.meter().bytes_written());
            assert_eq!(hop.rb.meter().bytes_read(), hop.ra.meter().bytes_written());
            eventually(5, "streams released", || {
                hop.ra.stats().streams_active == 0 && hop.rb.stats().streams_active == 0
            })
            .await;
            hop.close();
        }
        settle(base, 10, "finish").await;
    });
}

/// R–B stream windows of 64 KiB: the relay forwards at most that much
/// ahead of B's reads.
fn small() -> Config {
    let mut c = Config::default();
    c.initial_stream_receive_window = 64 * 1024;
    c.max_stream_receive_window = Cap::Fixed(64 * 1024);
    c
}

#[test]
fn a_reset_is_forwarded_with_its_reliable_bytes_within_the_next_hops_credit() {
    multi_thread(async {
        let base = snapshot();
        {
            let hop = Hop::new(Config::default(), Config::default(), small()).await;
            let mut relay = hop.relay(SpliceOptions::default());
            // Within the relay's upstream window (256 KiB), beyond B's.
            let data = pattern(192 << 10, 3);
            let ((mut s, _r), (mut fs, mut fr)) = hop.stream(&data[..1]).await;
            fs.finish().unwrap();
            // B does not read: the relay is held back by B's window while
            // A sends the rest, marks it reliable and resets.
            s.write_all(&data[1..]).await.unwrap();
            s.set_reliable_boundary().unwrap();
            s.reset(VarInt::from_u32(0x42)).unwrap();
            // The relay forwards only within B's credit: while B reads
            // nothing it waits, the reset not yet forwarded.
            assert!(
                tokio::time::timeout(Duration::from_millis(500), &mut relay)
                    .await
                    .is_err(),
                "the relay waits for B's credit"
            );
            // B reads: every reliable byte, then the reset.
            let reader = tokio::spawn(async move { read_until_end(&mut fr).await });
            let done = watchdog(30, "splice", relay).await.unwrap().unwrap();
            assert_eq!(done.a_to_b.end, SpliceEnd::Reset(VarInt::from_u32(0x42)));
            assert_eq!(done.a_to_b.bytes, data.len() as u64);
            assert_eq!(done.b_to_a.end, SpliceEnd::Finished);
            let (got, e) = watchdog(30, "B reads", reader).await.unwrap();
            assert!(got == data, "the reliable bytes");
            assert!(matches!(
                e,
                Some(StreamError::Reset { code, .. }) if code == VarInt::from_u32(0x42)
            ));
            hop.close();
        }
        settle(base, 10, "reset").await;
    });
}

#[test]
fn a_reset_towards_a_peer_without_reset_stream_at_follows_the_forwarded_bytes() {
    multi_thread(async {
        let base = snapshot();
        {
            // B is a plain QMux peer: no RESET_STREAM_AT.
            let mut qmux = Config::default();
            qmux.test_hooks().transport_parameters = Some(TransportParameters {
                initial_max_data: Some(1 << 22),
                initial_max_stream_data_bidi_local: Some(64 << 10),
                initial_max_stream_data_bidi_remote: Some(64 << 10),
                initial_max_stream_data_uni: Some(64 << 10),
                initial_max_streams_bidi: Some(16),
                initial_max_streams_uni: Some(16),
                ..TransportParameters::default()
            });
            let hop = Hop::new(Config::default(), Config::default(), qmux).await;
            assert!(hop.rb.is_plain_qmux_peer());
            let relay = hop.relay(SpliceOptions::default());
            let data = pattern(512 << 10, 4);
            let ((mut s, _r), (mut fs, mut fr)) = hop.stream(&data[..1]).await;
            fs.finish().unwrap();
            s.write_all(&data[1..]).await.unwrap();
            s.set_reliable_boundary().unwrap();
            s.reset(VarInt::from_u32(0x43)).unwrap();
            // B reads on: the relay resets only once everything forwarded
            // went to its carrier, so B receives all of it before the
            // RESET_STREAM.
            let reader = tokio::spawn(async move { read_until_end(&mut fr).await });
            let done = watchdog(30, "splice", relay).await.unwrap().unwrap();
            assert_eq!(done.a_to_b.end, SpliceEnd::Reset(VarInt::from_u32(0x43)));
            assert_eq!(done.a_to_b.bytes, data.len() as u64);
            let (got, e) = watchdog(30, "B reads", reader).await.unwrap();
            assert!(data.starts_with(&got));
            assert!(matches!(
                e,
                Some(StreamError::Reset { code, reliable_size: 0 }) if code == VarInt::from_u32(0x43)
            ));
            assert!(hop.b.stats().bytes_received >= data.len() as u64);
            hop.close();
        }
        settle(base, 10, "reset without RESET_STREAM_AT").await;
    });
}

#[test]
fn stops_resets_and_rejections_travel_with_their_codes() {
    multi_thread(async {
        let base = snapshot();
        {
            let hop = Hop::default().await;

            // B stops reading: A's sending part is stopped with B's code.
            let relay = hop.relay(SpliceOptions::default());
            let ((s, r), (fs, mut fr)) = hop.stream(b"x").await;
            fr.stop(VarInt::from_u32(9)).unwrap();
            assert_eq!(
                watchdog(10, "stopped", s.stopped()).await.unwrap(),
                Some(VarInt::from_u32(9))
            );
            drop((fs, fr));
            drop((s, r));
            let done = watchdog(10, "splice", relay).await.unwrap().unwrap();
            assert_eq!(done.a_to_b.end, SpliceEnd::Stopped(VarInt::from_u32(9)));

            // B resets its sending part: A reads B's code.
            let relay = hop.relay(SpliceOptions::default());
            let ((mut s, mut r), (mut fs, fr)) = hop.stream(b"x").await;
            fs.reset(VarInt::from_u32(11)).unwrap();
            let (_, e) = watchdog(10, "reset", read_until_end(&mut r)).await;
            assert!(
                matches!(e, Some(StreamError::Reset { code, .. }) if code == VarInt::from_u32(11))
            );
            s.finish().unwrap();
            drop(fr);
            let done = watchdog(10, "splice", relay).await.unwrap().unwrap();
            assert_eq!(done.b_to_a.end, SpliceEnd::Reset(VarInt::from_u32(11)));

            // B rejects the stream: A sees a rejection (ZMUX_REJECTED both
            // ways), retryable.
            let relay = hop.relay(SpliceOptions::default());
            let ((s, mut r), (_fs, fr)) = hop.stream(b"x").await;
            fr.reject().unwrap();
            let (_, e) = watchdog(10, "rejected", read_until_end(&mut r)).await;
            assert!(matches!(e, Some(StreamError::Rejected)));
            assert_eq!(
                watchdog(10, "stopped", s.stopped()).await.unwrap(),
                Some(rejected())
            );
            let done = watchdog(10, "splice", relay).await.unwrap().unwrap();
            assert_eq!(done.a_to_b.end, SpliceEnd::Stopped(rejected()));
            assert_eq!(done.b_to_a.end, SpliceEnd::Reset(rejected()));
            hop.close();
        }
        settle(base, 10, "codes").await;
    });
}

#[test]
fn a_lost_session_resets_and_stops_the_other_side_with_carrier_failed() {
    multi_thread(async {
        let base = snapshot();
        {
            let hop = Hop::default().await;
            let relay = hop.relay(SpliceOptions::default());
            let ((_s, _r), (fs, mut fr)) = hop.stream(b"x").await;
            // A's session goes away under the relay.
            hop.a.close(VarInt::from_u32(5), b"");
            let (_, e) = watchdog(10, "B reads", read_until_end(&mut fr)).await;
            assert!(matches!(e, Some(StreamError::Reset { code, .. }) if code == carrier_failed()));
            assert_eq!(
                watchdog(10, "B stopped", fs.stopped()).await.unwrap(),
                Some(carrier_failed())
            );
            let done = watchdog(10, "splice", relay).await.unwrap().unwrap();
            assert_eq!(done.a_to_b.end, SpliceEnd::UpstreamLost);
            assert_eq!(done.b_to_a.end, SpliceEnd::DownstreamLost);
            hop.close();
        }
        settle(base, 10, "session lost").await;
    });
}

#[test]
fn dropping_a_splice_resets_and_stops_both_streams_with_code_zero() {
    multi_thread(async {
        let base = snapshot();
        {
            let hop = Hop::default().await;
            let relay = hop.relay(SpliceOptions::default());
            let ((s, mut r), (fs, mut fr)) = hop.stream(b"x").await;
            relay.abort();
            let _ = relay.await;
            for (send, recv) in [(&s, &mut r), (&fs, &mut fr)] {
                let (_, e) = watchdog(10, "reset", read_until_end(recv)).await;
                assert!(matches!(e, Some(StreamError::Reset { code, .. }) if code == VarInt::ZERO));
                assert_eq!(
                    watchdog(10, "stopped", send.stopped()).await.unwrap(),
                    Some(VarInt::ZERO)
                );
            }
            hop.close();
        }
        settle(base, 10, "drop").await;
    });
}

#[test]
fn a_direction_into_its_own_stream_is_refused() {
    multi_thread(async {
        let hop = Hop::default().await;
        let (s1, r1) = hop.a.open_bi().await.unwrap();
        let (s2, r2) = hop.a.open_bi().await.unwrap();
        // a = (s1, r2) and b = (s2, r1): b's sending part takes what a's
        // receiving part reads, from the same stream.
        let r = splice((s1, r2), (s2, r1), SpliceOptions::default()).await;
        assert_eq!(r.err(), Some(SpliceError::SameStream));
        hop.close();
    });
}

/// A limiter that allows everything and counts what it was charged.
#[derive(Default)]
struct Count(AtomicU64);

impl Limiter for Count {
    fn poll_ready(&self, _: &mut Context<'_>, _: usize, max: usize) -> Poll<usize> {
        Poll::Ready(max)
    }
    fn try_ready(&self, max: usize) -> usize {
        max
    }
    fn charge(&self, n: usize) {
        self.0.fetch_add(n as u64, Ordering::Relaxed);
    }
}

/// A budget of bytes, refilled by the test; waits while it is empty.
#[derive(Default)]
struct Budget {
    left: Mutex<(usize, Option<Waker>)>,
    charged: AtomicU64,
}

impl Budget {
    fn add(&self, n: usize) {
        let w = {
            let mut g = self.left.lock().unwrap();
            g.0 += n;
            g.1.take()
        };
        if let Some(w) = w {
            w.wake();
        }
    }
}

impl Limiter for Budget {
    fn poll_ready(&self, cx: &mut Context<'_>, min: usize, max: usize) -> Poll<usize> {
        let mut g = self.left.lock().unwrap();
        if g.0 >= min {
            return Poll::Ready(g.0.min(max));
        }
        g.1 = Some(cx.waker().clone());
        Poll::Pending
    }
    fn try_ready(&self, max: usize) -> usize {
        self.left.lock().unwrap().0.min(max)
    }
    fn charge(&self, n: usize) {
        let mut g = self.left.lock().unwrap();
        g.0 = g.0.saturating_sub(n);
        self.charged.fetch_add(n as u64, Ordering::Relaxed);
    }
}

#[test]
fn limiters_are_charged_exactly_what_was_forwarded_and_datagrams_follow() {
    multi_thread(async {
        let base = snapshot();
        {
            let hop = Hop::default().await;
            let count = Arc::new(Count::default());
            let budget = Arc::new(Budget::default());
            budget.add(16 * 1024);
            let mut opts = SpliceOptions::default();
            opts.a_to_b = Some(count.clone());
            opts.b_to_a = Some(budget.clone());
            let relay = hop.relay(opts);
            let ((mut s, mut r), (mut fs, mut fr)) = hop.stream(b"x").await;
            // Stream datagrams go to the other stream with their context.
            s.send_datagram(3, Bytes::from_static(b"datagram")).unwrap();
            let (ctx, d) = watchdog(10, "datagram", fr.read_datagram()).await.unwrap();
            assert_eq!((ctx, &d[..]), (3, &b"datagram"[..]));
            // From B: the budget allows 16 KiB; a datagram larger than
            // what is left is dropped, the stream data waits for more.
            let down = pattern(64 << 10, 5);
            fs.write_all(&down).await.unwrap();
            fs.finish().unwrap();
            // The budget's first 16 KiB, in one chunk: then the direction
            // waits for a budget of 16 KiB again.
            eventually(10, "a chunk forwarded", || {
                budget.charged.load(Ordering::Relaxed) > 0
            })
            .await;
            tokio::time::sleep(Duration::from_millis(50)).await;
            let charged = budget.charged.load(Ordering::Relaxed) as usize;
            assert!(charged <= 16 * 1024);
            let over = vec![1u8; 16 * 1024 - charged + 1];
            fs.send_datagram(1, Bytes::from(over)).unwrap();
            tokio::time::sleep(Duration::from_millis(50)).await;
            budget.add(64 << 10);
            let back = watchdog(10, "A reads", read_all(&mut r, 64 << 10))
                .await
                .unwrap();
            assert!(back == down);
            s.write_all(&pattern(100_000, 6)).await.unwrap();
            s.finish().unwrap();
            let got = watchdog(10, "B reads", read_all(&mut fr, 1 << 20))
                .await
                .unwrap();
            assert_eq!(got.len(), 100_001);
            let done = watchdog(10, "splice", relay).await.unwrap().unwrap();
            let ab = done.a_to_b;
            let ba = done.b_to_a;
            assert_eq!(
                (ab.bytes, ab.datagram_bytes),
                (100_001, 8),
                "stream and datagram bytes"
            );
            assert_eq!(
                count.0.load(Ordering::Relaxed),
                ab.bytes + ab.datagram_bytes
            );
            assert_eq!(ba.bytes, down.len() as u64);
            assert_eq!(
                budget.charged.load(Ordering::Relaxed),
                ba.bytes + ba.datagram_bytes
            );
            assert_eq!(ba.datagrams_dropped, 1, "the datagram over budget");
            hop.close();
        }
        settle(base, 10, "limiters").await;
    });
}

#[test]
fn a_splice_cancelled_in_a_limiter_wait_leaves_nothing_behind() {
    multi_thread(async {
        let base = snapshot();
        {
            let hop = Hop::default().await;
            let budget = Arc::new(Budget::default());
            let mut opts = SpliceOptions::default();
            opts.a_to_b = Some(budget.clone());
            let relay = hop.relay(opts);
            let (mut s, mut r) = hop.a.open_bi().await.unwrap();
            s.write_all(b"x").await.unwrap();
            // The byte cannot pass: the splice waits in the limiter,
            // holding nothing; the outbound stream sent nothing yet.
            tokio::time::sleep(Duration::from_millis(50)).await;
            relay.abort();
            let _ = relay.await;
            assert_eq!(budget.charged.load(Ordering::Relaxed), 0);
            let (_, e) = watchdog(10, "reset", read_until_end(&mut r)).await;
            assert!(matches!(e, Some(StreamError::Reset { code, .. }) if code == VarInt::ZERO));
            assert_eq!(
                watchdog(10, "stopped", s.stopped()).await.unwrap(),
                Some(VarInt::ZERO)
            );
            assert_eq!(
                hop.b.stats().streams_opened_remote,
                0,
                "invisible downstream"
            );
            hop.close();
        }
        settle(base, 10, "cancelled").await;
    });
}

/// A downstream window smaller than a step (Appendix
/// A.2 step 1): once what the relay wrote was sent, the capacity left
/// below the step is forwarded, though no credit arrives (B reads nothing,
/// so it sends no MAX_STREAM_DATA) and nothing else happens upstream: the
/// drained send buffer wakes the capacity wait.
#[test]
fn a_window_remainder_below_the_step_is_forwarded_without_new_credit() {
    multi_thread(async {
        let base = snapshot();
        {
            let mut b = Config::default();
            b.initial_stream_receive_window = 16 * 1024;
            b.max_stream_receive_window = Cap::Fixed(16 * 1024);
            // A slow carrier: what the relay writes stays unsent a while.
            let hop = Hop::with_carrier(Config::default(), Config::default(), b, 512).await;
            let (mut s, r) = hop.a.open_bi().await.unwrap();
            s.write_all(&[7u8; 32 * 1024]).await.unwrap();
            let inbound = hop.ra.accept_bi().await.unwrap();
            // Everything A sent is at the relay before the splice starts.
            let readable = || inbound.1.stats().map_or(0, |st| st.bytes_received);
            eventually(5, "A's data at the relay", || readable() == 32 * 1024).await;
            // The outbound stream reaches B, which finishes its side at
            // once: B is quiet from then on and sends no credit.
            let (mut out_s, out_r) = hop.rb.open_bi().await.unwrap();
            out_s.write_all(b"o").await.unwrap();
            let (mut fs, fr) = hop.b.accept_bi().await.unwrap();
            fs.finish().unwrap();
            tokio::time::sleep(Duration::from_millis(50)).await;
            let mut opts = SpliceOptions::default();
            opts.chunk = 3 * 1024;
            let relay = tokio::spawn(splice(inbound, (out_s, out_r), opts));
            // B's whole window, but for the preamble, arrives.
            let received = || fr.stats().map_or(0, |st| st.bytes_received);
            eventually(5, "the window remainder", || received() >= 16 * 1024 - 256).await;
            assert!(received() <= 16 * 1024, "{}", received());
            drop((s, r, fs, fr));
            watchdog(10, "splice", relay).await.unwrap().unwrap();
            hop.close();
        }
        settle(base, 10, "remainder").await;
    });
}

#[test]
fn a_stalled_downstream_bounds_what_the_relay_holds() {
    multi_thread(async {
        let base = snapshot();
        {
            // Every stream window at most 64 KiB.
            let hop = Hop::new(small(), small(), small()).await;
            let relay = hop.relay(SpliceOptions::default());
            let ((mut s, r), (fs, fr)) = hop.stream(b"x").await;
            // B never reads; A writes as much as flow control lets it.
            let writer = tokio::spawn(async move {
                let chunk = vec![7u8; 64 * 1024];
                loop {
                    if s.write_all(&chunk).await.is_err() {
                        return;
                    }
                }
            });
            tokio::time::sleep(Duration::from_millis(300)).await;
            let held = hop.ra.debug_tables().held_bytes + hop.rb.debug_tables().held_bytes;
            // The upstream window, what the downstream holds unsent within
            // its peer's credit (B's window), one chunk: 3 x 64 KiB at
            // most, whatever A writes.
            assert!(held <= 3 * 64 * 1024, "the relay holds {held} bytes");
            assert!(
                hop.ra.debug_tables().held_bytes > 0,
                "the backlog waits upstream"
            );
            // Both ends give up: the splice ends both ways.
            writer.abort();
            let _ = writer.await;
            drop((r, fs, fr));
            let done = watchdog(10, "splice", relay).await.unwrap().unwrap();
            for end in [done.a_to_b.end, done.b_to_a.end] {
                assert!(
                    end == SpliceEnd::Reset(VarInt::ZERO)
                        || end == SpliceEnd::Stopped(VarInt::ZERO),
                    "{end:?}"
                );
            }
            hop.close();
        }
        settle(base, 10, "stall").await;
    });
}
