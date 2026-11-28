//! `helpers::splice`: a relay between two outer
//! sessions forwards streams verbatim and propagates every end and error
//! of its table with the code unchanged, holds at most one chunk per
//! direction, forwards stream datagrams, charges its limiters exactly what
//! it forwarded, and leaves nothing behind when it ends or is dropped.

#![allow(
    clippy::cast_possible_truncation,
    reason = "test and bench values are small and bounded; checked conversions would only add noise"
)]
#![allow(
    clippy::large_futures,
    clippy::large_stack_arrays,
    reason = "scenario code: buffers and futures stay on the stack on purpose, long scripted scenarios read top to bottom"
)]

mod common;

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use bytes::Bytes;
use common::{connect, duplex, eventually, multi_thread, settle, snapshot, watchdog};
use tokio::task::JoinHandle;
use zmux::helpers::{
    ControlledSpliceOptions, SpliceAbort, SpliceEnd, SpliceError, SpliceOptions, SpliceResult,
    splice,
};
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
    fn relay(&self, opts: SpliceOptions) -> JoinHandle<Result<SpliceResult, SpliceError>> {
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
        drop(self.a.close());
        drop(self.b.close());
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
            let relay = hop.relay(SpliceOptions::default());
            // Within the relay's upstream window (256 KiB), beyond B's.
            let data = pattern(192 << 10, 3);
            let ((mut s, _r), (mut fs, mut fr)) = hop.stream(&data[..1]).await;
            fs.finish().unwrap();
            // B does not read: the relay is held back by B's window while
            // A sends the rest, marks it reliable and resets.
            s.write_all(&data[1..]).await.unwrap();
            s.set_reliable_boundary().unwrap();
            s.reset(VarInt::from_u32(0x42)).unwrap();
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
            hop.a.abort(VarInt::from_u32(5), b"");
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
fn dropping_a_splice_resets_and_stops_both_streams() {
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
                assert!(matches!(e, Some(StreamError::Reset { code, .. }) if code == CANCELLED));
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
fn an_aborted_splice_ends_both_streams_with_the_code() {
    multi_thread(async {
        let base = snapshot();
        {
            let hop = Hop::default().await;
            let abort = SpliceAbort::new();
            let mut opts = SpliceOptions::default();
            opts.abort = Some(abort.clone());
            let relay = hop.relay(opts);
            let ((s, mut r), (fs, mut fr)) = hop.stream(b"x").await;
            let code = VarInt::from_u32(0x77);
            abort.abort(code);
            abort.abort(VarInt::from_u32(1));
            let done = watchdog(10, "splice", relay).await.unwrap().unwrap();
            assert_eq!(done.a_to_b.end, SpliceEnd::Cancelled(code));
            assert_eq!(done.b_to_a.end, SpliceEnd::Cancelled(code));
            for (send, recv) in [(&s, &mut r), (&fs, &mut fr)] {
                let (_, e) = watchdog(10, "reset", read_until_end(recv)).await;
                assert!(matches!(e, Some(StreamError::Reset { code: c, .. }) if c == code));
                assert_eq!(
                    watchdog(10, "stopped", send.stopped()).await.unwrap(),
                    Some(code)
                );
            }
            hop.close();
        }
        settle(base, 10, "abort").await;
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
    fn max_burst_bytes(&self) -> Option<u64> {
        Some(u64::MAX)
    }

    fn poll_acquire(
        &self,
        _: &mut Context<'_>,
        min: u64,
        max: u64,
    ) -> Poll<Result<u64, zmux::LimitError>> {
        Poll::Ready(Ok(self.try_acquire(min, max)))
    }
    fn try_acquire(&self, _: u64, max: u64) -> u64 {
        self.0.fetch_add(max, Ordering::Relaxed);
        max
    }
    fn refund(&self, n: u64) {
        self.0.fetch_sub(n, Ordering::Relaxed);
    }
}

/// A budget of bytes, refilled by the test; waits while it is empty.
#[derive(Default)]
struct Budget {
    left: Mutex<(u64, Option<Waker>)>,
    charged: AtomicU64,
    waiting: tokio::sync::Notify,
    refused: tokio::sync::Notify,
}

impl Budget {
    fn add(&self, n: u64) {
        let w = {
            let mut g = self.left.lock().unwrap();
            g.0 += n;
            g.1.take()
        };
        if let Some(w) = w {
            w.wake();
        }
    }
    fn take(&self, balance: &mut u64, max: u64) -> u64 {
        let n = (*balance).min(max);
        *balance -= n;
        self.charged.fetch_add(n, Ordering::Relaxed);
        n
    }
}

impl Limiter for Budget {
    fn max_burst_bytes(&self) -> Option<u64> {
        Some(u64::MAX)
    }

    fn poll_acquire(
        &self,
        cx: &mut Context<'_>,
        min: u64,
        max: u64,
    ) -> Poll<Result<u64, zmux::LimitError>> {
        let mut g = self.left.lock().unwrap();
        if g.0 < min {
            g.1 = Some(cx.waker().clone());
            self.waiting.notify_one();
            Poll::Pending
        } else {
            Poll::Ready(Ok(self.take(&mut g.0, max)))
        }
    }
    fn try_acquire(&self, min: u64, max: u64) -> u64 {
        let mut g = self.left.lock().unwrap();
        if g.0 < min {
            self.refused.notify_one();
            0
        } else {
            self.take(&mut g.0, max)
        }
    }
    fn refund(&self, n: u64) {
        self.left.lock().unwrap().0 += n;
        self.charged.fetch_sub(n, Ordering::Relaxed);
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
            let d = watchdog(10, "datagram", fr.read_datagram()).await.unwrap();
            assert_eq!((d.context, &d.payload[..]), (3, &b"datagram"[..]));
            // From B: the budget allows 16 KiB; a datagram larger than
            // what is left is dropped, the stream data waits for more.
            let down = pattern(64 << 10, 5);
            fs.write_all(&down).await.unwrap();
            fs.finish().unwrap();
            watchdog(
                30,
                "stream waiting for more quota",
                budget.waiting.notified(),
            )
            .await;
            assert_eq!(budget.charged.load(Ordering::Relaxed), 16 * 1024);
            fs.send_datagram(1, Bytes::from_static(b"x")).unwrap();
            watchdog(30, "datagram refused", budget.refused.notified()).await;
            budget.add(64 << 10);
            let back = watchdog(10, "A reads", read_all(&mut r, 64 << 10))
                .await
                .unwrap();
            assert_eq!(back, down);
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
            assert_eq!(ba.drops.total(), 1, "the datagram over budget");
            assert_eq!(
                (ba.drops.dropped_limiter, ba.drops.dropped_too_large),
                (1, 0)
            );
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
            watchdog(30, "stream waiting for quota", budget.waiting.notified()).await;
            relay.abort();
            let _ = relay.await;
            assert_eq!(budget.charged.load(Ordering::Relaxed), 0);
            let (_, e) = watchdog(10, "reset", read_until_end(&mut r)).await;
            assert!(matches!(e, Some(StreamError::Reset { code, .. }) if code == CANCELLED));
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

/// A downstream window smaller than the relay's forwarding step: once what the relay wrote was sent, the capacity left
/// below the step is forwarded, though no credit arrives (B reads nothing,
/// so it sends no `MAX_STREAM_DATA`) and nothing else happens upstream: the
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
            let readable = || inbound.1.stats().bytes_received;
            eventually(5, "A's data at the relay", || readable() == 32 * 1024).await;
            // The outbound stream reaches B, which finishes its side at
            // once: B is quiet from then on and sends no credit.
            let (mut out_s, mut out_r) = hop.rb.open_bi().await.unwrap();
            out_s.write_all(b"o").await.unwrap();
            let (mut fs, fr) = hop.b.accept_bi().await.unwrap();
            fs.finish().unwrap();
            assert!(
                watchdog(30, "reverse FIN", out_r.read_chunk(1))
                    .await
                    .unwrap()
                    .is_none()
            );
            let mut opts = SpliceOptions::default();
            opts.chunk = 3 * 1024;
            let relay = tokio::spawn(splice(inbound, (out_s, out_r), opts));
            // B's whole window, but for the preamble, arrives.
            let received = || fr.stats().bytes_received;
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
            // The finite input exceeds B's fixed window. Observe that
            // window fill and that the remaining input reached the relay.
            let data = vec![7; 112 * 1024];
            watchdog(30, "source window", s.write_all(&data))
                .await
                .unwrap();
            eventually(30, "buffered source input", || {
                hop.rb.meter().bytes_written() >= 64 * 1024 - 256
                    && hop.ra.debug_tables().held_bytes >= 16 * 1024
            })
            .await;
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
            drop((s, r, fs, fr));
            let done = watchdog(10, "splice", relay).await.unwrap().unwrap();
            for end in [done.a_to_b.end, done.b_to_a.end] {
                assert!(
                    end == SpliceEnd::Reset(CANCELLED) || end == SpliceEnd::Stopped(VarInt::ZERO),
                    "{end:?}"
                );
            }
            hop.close();
        }
        settle(base, 10, "stall").await;
    });
}

/// The code a dropped, unfinished sending part resets with.
const CANCELLED: VarInt = VarInt::from_u32(0x5a4d_0001);

/// Records every call: the arguments, what it granted and what came back.
#[derive(Default)]
struct Recorder {
    calls: Mutex<Vec<(u64, u64)>>,
    granted: AtomicU64,
    refunded: AtomicU64,
    fail: std::sync::atomic::AtomicBool,
}

impl Limiter for Recorder {
    fn max_burst_bytes(&self) -> Option<u64> {
        Some(u64::MAX)
    }

    fn poll_acquire(
        &self,
        _: &mut Context<'_>,
        min: u64,
        max: u64,
    ) -> Poll<Result<u64, zmux::LimitError>> {
        self.calls.lock().unwrap().push((min, max));
        if self.fail.load(Ordering::SeqCst) {
            return Poll::Ready(Err(zmux::LimitError::new("quota gone")));
        }
        self.granted.fetch_add(max, Ordering::SeqCst);
        Poll::Ready(Ok(max))
    }
    fn try_acquire(&self, _: u64, _: u64) -> u64 {
        0
    }
    fn refund(&self, n: u64) {
        self.refunded.fetch_add(n, Ordering::SeqCst);
    }
}

/// The limiter is asked only once the source is readable, for at most
/// what is readable, with `min` 1: an idle source holds no grant.
#[test]
fn a_splice_holds_no_grant_while_its_source_is_idle() {
    multi_thread(async {
        let hop = Hop::default().await;
        let rec = Arc::new(Recorder::default());
        let mut opts = SpliceOptions::default();
        opts.a_to_b = Some(rec.clone());
        let relay = hop.relay(opts);
        let ((mut s, _r), (_fs, mut fr)) = hop.stream(b"x").await;
        let got = watchdog(10, "x", read_n(&mut fr, 1)).await;
        assert_eq!(got, b"x");
        let used = || rec.granted.load(Ordering::SeqCst) - rec.refunded.load(Ordering::SeqCst);
        let calls = rec.calls.lock().unwrap().clone();
        assert_eq!(calls, [(1, 1)], "asked once, for the readable byte");
        assert_eq!(used(), 1);
        s.write_all(&[7; 10]).await.unwrap();
        let got = watchdog(10, "ten", read_n(&mut fr, 10)).await;
        assert_eq!(got, [7; 10]);
        for &(min, max) in rec.calls.lock().unwrap().iter() {
            assert!(min == 1 && (1..=10).contains(&max), "({min}, {max})");
        }
        assert_eq!(used(), 11, "exactly what was forwarded stays taken");
        relay.abort();
        hop.close();
    });
}

/// A limiter error ends the direction as cancelled: the upstream part is
/// stopped with `ZMUX_CANCELLED` (and the downstream part reset with it).
#[test]
fn a_limiter_error_ends_the_direction() {
    multi_thread(async {
        let hop = Hop::default().await;
        let rec = Arc::new(Recorder::default());
        rec.fail.store(true, Ordering::SeqCst);
        let mut opts = SpliceOptions::default();
        opts.a_to_b = Some(rec.clone());
        let relay = hop.relay(opts);
        let (mut s, _r) = hop.a.open_bi().await.unwrap();
        s.write_all(b"x").await.unwrap();
        let stopped = watchdog(30, "stopped", s.stopped()).await.unwrap();
        let cancelled = VarInt::from_u32(0x5a4d_0001);
        assert_eq!(stopped, Some(cancelled));
        assert!(rec.calls.lock().unwrap().iter().all(|c| c.0 == 1));
        relay.abort();
        hop.close();
    });
}

/// A limiter that fails before the downstream stream sent anything: the
/// downstream stream never reaches B, so the reverse direction can read
/// nothing from it and ends with its FIN; the splice ends both ways.
#[test]
fn a_limiter_error_on_a_never_flushed_downstream_ends_the_splice() {
    multi_thread(async {
        let hop = Hop::default().await;
        let rec = Arc::new(Recorder::default());
        rec.fail.store(true, Ordering::SeqCst);
        let mut opts = SpliceOptions::default();
        opts.a_to_b = Some(rec.clone());
        let relay = hop.relay(opts);
        let (mut s, mut r) = hop.a.open_bi().await.unwrap();
        s.write_all(b"x").await.unwrap();
        let done = watchdog(10, "splice", relay).await.unwrap().unwrap();
        assert_eq!(done.a_to_b.end, SpliceEnd::LimiterFailed);
        assert_eq!(done.b_to_a.end, SpliceEnd::Finished);
        let (got, e) = watchdog(10, "A reads", read_until_end(&mut r)).await;
        assert!(got.is_empty() && e.is_none(), "{got:?} {e:?}");
        assert_eq!(hop.b.stats().streams_opened_remote, 0, "never seen by B");
        hop.close();
    });
}

async fn read_n(r: &mut RecvStream, n: usize) -> Vec<u8> {
    let mut b = vec![0; n];
    r.read_exact(&mut b).await.unwrap();
    b
}

type Leg = (SendStream, RecvStream);

/// Both streams have identifiers before the test starts driving the splice.
async fn prepared_hop(hop: &Hop) -> (Leg, Leg, Leg, Leg) {
    let a = hop.a.open_bi().await.unwrap();
    a.0.pin_id().unwrap();
    let ra = hop.ra.accept_bi().await.unwrap();
    let rb = hop.rb.open_bi().await.unwrap();
    rb.0.pin_id().unwrap();
    let b = hop.b.accept_bi().await.unwrap();
    (a, ra, rb, b)
}

async fn controlled_hop(
    hop: &Hop,
    opts: ControlledSpliceOptions,
    packets: bool,
) -> (
    zmux::helpers::SpliceController,
    JoinHandle<SpliceResult>,
    Leg,
    Leg,
) {
    let (a, ra, rb, b) = prepared_hop(hop).await;
    let (control, relay) = if packets {
        let (control, run) = zmux::helpers::controlled_splice_packets(ra, rb, opts).unwrap();
        (control, tokio::spawn(run))
    } else {
        let (control, run) = zmux::helpers::controlled_splice(ra, rb, opts).unwrap();
        (control, tokio::spawn(run))
    };
    (control, relay, a, b)
}

#[test]
fn controlled_splice_detaches_without_redeciding_delayed_output() {
    use zmux::helpers::{SpliceDecision, SpliceHooks, SpliceMirror, SpliceSignal, SpliceWait};

    common::paused(async {
        let hop = Hop::default().await;
        let mut opts = ControlledSpliceOptions::default();
        let signal = SpliceSignal::default();
        let resume = signal.clone();
        let (mirror, mut samples) = SpliceMirror::channel(1, 1).unwrap();
        opts.a_to_b_mirror = Some(mirror);
        opts.a_to_b_hooks.stream.push(Arc::new(move |unit| {
            assert_eq!(unit.items(), 1);
            assert_eq!(unit.segments(0).unwrap().next(), Some(&b"a"[..]));
            unit.write(1, |out| out[0] = b'b')?;
            unit.write(1, |out| out[0] = b'c')?;
            Ok(SpliceDecision::Replace(SpliceWait {
                resume: Some(signal.clone()),
                ..SpliceWait::default()
            }))
        }));
        let (control, relay, (mut a, _reverse), (mut b, mut read)) =
            controlled_hop(&hop, opts, false).await;
        a.write_all(b"a").await.unwrap();
        let first = watchdog(60, "first input sampled", samples.recv())
            .await
            .unwrap();
        assert_eq!((first.generation, &first.prefix[..]), (1, &b"a"[..]));
        assert_eq!(
            control
                .a_to_b
                .replace_hooks(SpliceHooks::default())
                .await
                .unwrap(),
            2
        );
        a.write_all(b"d").await.unwrap();
        resume.resume();
        assert_eq!(
            watchdog(60, "forwarded generation", read_n(&mut read, 3)).await,
            b"bcd"
        );
        a.finish().unwrap();
        b.finish().unwrap();
        let result = watchdog(60, "controlled splice", relay).await.unwrap();
        assert_eq!(result.a_to_b.replacements, 1);
        assert_eq!(result.a_to_b.enqueued_items, 3);
        assert_eq!(result.a_to_b.end, SpliceEnd::Finished);
    });
}

#[test]
fn controlled_splice_admits_injection_after_resume_and_stop_ends_pause() {
    use zmux::helpers::{SpliceCommandError, SpliceInjection, SpliceKind};

    common::paused(async {
        let hop = Hop::default().await;
        let (control, relay, (_a, mut reverse), (mut b, mut read)) =
            controlled_hop(&hop, ControlledSpliceOptions::default(), false).await;
        let offer = || SpliceInjection {
            kind: SpliceKind::Stream,
            payload: zmux::Chunk::from_static(b"local"),
        };
        let pause = control.a_to_b.pause().await.unwrap();
        pause.acknowledged().await.unwrap();
        assert!(matches!(
            control.a_to_b.inject(offer()).await,
            Err(SpliceCommandError::Paused)
        ));
        b.write_all(b"reverse").await.unwrap();
        assert_eq!(
            watchdog(60, "reverse", read_n(&mut reverse, 7)).await,
            b"reverse"
        );
        control.a_to_b.resume(&pause).await.unwrap();
        let receipt = control.a_to_b.inject(offer()).await.unwrap();
        assert_eq!(
            watchdog(60, "injection", read_n(&mut read, 5)).await,
            b"local"
        );
        let disposition = receipt.disposition().await.unwrap();
        assert_eq!(
            (disposition.accepted_bytes, disposition.enqueued_items),
            (5, 1)
        );
        let pause = control.a_to_b.pause().await.unwrap();
        pause.acknowledged().await.unwrap();
        read.stop(VarInt::ZERO).unwrap();
        assert_eq!(
            watchdog(60, "stopped direction", control.a_to_b.finished())
                .await
                .unwrap(),
            SpliceEnd::Stopped(VarInt::ZERO)
        );
        b.finish().unwrap();
        let output = watchdog(60, "controlled splice", relay).await.unwrap();
        assert_eq!(output.a_to_b.end, SpliceEnd::Stopped(VarInt::ZERO));
        assert_eq!(output.b_to_a.end, SpliceEnd::Finished);
    });
}

#[test]
fn a_datagram_with_later_admission_overtakes_an_earlier_delayed_group() {
    use zmux::helpers::{SpliceDecision, SpliceInjection, SpliceKind, SpliceWait};

    common::paused(async {
        let hop = Hop::default().await;
        let mut opts = ControlledSpliceOptions::default();
        opts.limits.datagram_delay = true;
        let (decided, mut decision) = tokio::sync::mpsc::channel(2);
        opts.a_to_b_hooks.datagram.push(Arc::new(move |unit| {
            let delayed = matches!(unit.meta.kind, SpliceKind::Datagram { context } if context == VarInt::ZERO);
            decided.try_send(delayed).unwrap();
            if delayed {
                Ok(SpliceDecision::Pass(SpliceWait {
                    ready_at: Some(tokio::time::Instant::now() + Duration::from_secs(5)),
                    ..SpliceWait::default()
                }))
            } else {
                Ok(SpliceDecision::default())
            }
        }));
        let (control, relay, (mut a, _reverse), (mut b, read)) =
            controlled_hop(&hop, opts, false).await;
        let inject = |context, payload| SpliceInjection {
            kind: SpliceKind::Datagram {
                context: VarInt::from_u32(context),
            },
            payload: zmux::Chunk::from_static(payload),
        };
        let first = control.a_to_b.inject(inject(0, b"first")).await.unwrap();
        assert_eq!(decision.recv().await, Some(true));
        let second = control.a_to_b.inject(inject(1, b"second")).await.unwrap();
        assert_eq!(decision.recv().await, Some(false));
        let next = watchdog(60, "overtaking datagram", read.read_datagram())
            .await
            .unwrap();
        assert_eq!(&next.payload[..], b"second");
        assert_eq!(second.disposition().await.unwrap().enqueued_items, 1);
        tokio::time::advance(Duration::from_secs(5)).await;
        let next = watchdog(60, "released datagram", read.read_datagram())
            .await
            .unwrap();
        assert_eq!(&next.payload[..], b"first");
        assert_eq!(first.disposition().await.unwrap().enqueued_items, 1);
        a.finish().unwrap();
        b.finish().unwrap();
        let result = watchdog(60, "controlled splice", relay).await.unwrap();
        assert_eq!(result.a_to_b.datagram_bytes, 11);
    });
}

#[test]
fn capsule_hook_collects_a_bounded_unit_across_fragments() {
    use zmux::helpers::{SpliceDecision, SpliceKind, SpliceWait};

    common::paused(async {
        let hop = Hop::default().await;
        let mut opts = ControlledSpliceOptions::default();
        opts.forwarding.chunk = 1;
        opts.limits.descriptors = 2;
        opts.a_to_b_hooks.capsule.push(Arc::new(|unit| {
            assert_eq!(
                unit.meta.kind,
                SpliceKind::Capsule {
                    ty: VarInt::from_u32(5),
                    context: None
                }
            );
            let bytes: Vec<_> = unit.segments(0).unwrap().flatten().copied().collect();
            assert_eq!(bytes, b"abcd");
            unit.slice(0, 1..3)?;
            unit.write(1, |byte| byte[0] = b'e')?;
            Ok(SpliceDecision::Replace(SpliceWait::default()))
        }));
        let (_control, relay, (mut a, _reverse), (mut b, mut read)) =
            controlled_hop(&hop, opts, true).await;
        a.write_all(&[5, 4, b'a', b'b', b'c']).await.unwrap();
        eventually(60, "incomplete capsule held at the relay", || {
            hop.ra.meter().bytes_read() == 5
        })
        .await;
        assert!(matches!(
            read.try_read_chunk(1),
            Ok(zmux::TryRead::WouldBlock)
        ));
        a.write_all(b"d").await.unwrap();
        a.finish().unwrap();
        b.finish().unwrap();
        let got = watchdog(60, "transformed capsule group", read_all(&mut read, 7))
            .await
            .unwrap();
        assert_eq!(got, [5, 2, b'b', b'c', 5, 1, b'e']);
        let result = watchdog(60, "controlled splice", relay).await.unwrap();
        assert_eq!(
            (result.a_to_b.input_units, result.a_to_b.enqueued_items),
            (1, 2)
        );
    });
}

#[test]
fn truncated_hooked_capsule_never_submits_a_partial_unit() {
    common::paused(async {
        let hop = Hop::default().await;
        let mut opts = ControlledSpliceOptions::default();
        opts.a_to_b_hooks
            .capsule
            .push(Arc::new(|_| panic!("truncated capsule reached the hook")));
        let (_control, relay, (mut a, _reverse), (mut b, mut read)) =
            controlled_hop(&hop, opts, true).await;
        a.write_all(&[5, 4, b'a']).await.unwrap();
        a.finish().unwrap();
        b.finish().unwrap();
        let (bytes, error) = watchdog(60, "target reset", read_until_end(&mut read)).await;
        assert_eq!(bytes, [] as [u8; 0]);
        assert!(matches!(error, Some(StreamError::Reset { code, .. })
            if code.into_inner() == ApplicationErrorCode::ZMUX_PACKET_ERROR.0));
        let result = watchdog(60, "controlled splice", relay).await.unwrap();
        assert_eq!(result.a_to_b.end, SpliceEnd::PacketError);
        assert_eq!(result.a_to_b.input_units, 0);
        assert_eq!(result.a_to_b.enqueued_items, 0);
        assert_eq!(result.a_to_b.bytes, 0);
    });
}

#[test]
fn transparent_capsule_error_resets_at_the_last_complete_capsule() {
    check_transparent_capsule_error(b"\x21\x01a\x22\x02b".to_vec(), 3);
}

fn check_transparent_capsule_error(raw: Vec<u8>, prefix_size: u64) {
    common::paused(async {
        let hop = Hop::default().await;
        let ((mut a, mut reverse), ra, rb, (mut b, mut read)) = prepared_hop(&hop).await;
        let relay = tokio::spawn(zmux::helpers::splice_packets(
            ra,
            rb,
            SpliceOptions::default(),
        ));
        a.write_all(&raw).await.unwrap();
        assert_eq!(
            watchdog(
                60,
                "transparent stream before truncation",
                read_n(&mut read, raw.len())
            )
            .await,
            raw
        );
        a.finish().unwrap();
        b.finish().unwrap();

        let code = VarInt::from_u64(ApplicationErrorCode::ZMUX_PACKET_ERROR.0).unwrap();
        assert_eq!(
            watchdog(60, "peer received reset", read.received_reset())
                .await
                .unwrap(),
            Some(code)
        );
        let (bytes, error) = watchdog(60, "read after reset", read_until_end(&mut read)).await;
        assert_eq!(bytes, [] as [u8; 0]);
        assert!(
            matches!(error, Some(StreamError::Reset { code: reset_code, reliable_size })
            if reset_code == code && reliable_size == prefix_size)
        );
        assert!(
            watchdog(60, "reverse FIN", reverse.read_chunk(1))
                .await
                .unwrap()
                .is_none()
        );
        let result = watchdog(60, "splice result", relay).await.unwrap().unwrap();
        assert_eq!(result.a_to_b.end, SpliceEnd::PacketError);
        assert_eq!(result.b_to_a.end, SpliceEnd::Finished);
    });
}

#[test]
fn a_waiting_datagram_and_an_injected_stream_share_the_queue_limit() {
    use zmux::helpers::{
        SpliceCommandError, SpliceDecision, SpliceInjection, SpliceKind, SpliceSignal, SpliceWait,
    };

    common::paused(async {
        let hop = Hop::default().await;
        let mut opts = ControlledSpliceOptions::default();
        opts.limits.datagram_delay = true;
        opts.limits.queue_items = 1;
        let resume = SpliceSignal::default();
        let signal = resume.clone();
        opts.a_to_b_hooks.datagram.push(Arc::new(move |_| {
            Ok(SpliceDecision::Pass(SpliceWait {
                resume: Some(signal.clone()),
                ..SpliceWait::default()
            }))
        }));
        let (control, relay, (mut a, _reverse), (mut b, mut read)) =
            controlled_hop(&hop, opts, false).await;
        let payload = Bytes::from_static(b"test");
        let datagram = control
            .a_to_b
            .inject(SpliceInjection {
                kind: SpliceKind::Datagram {
                    context: VarInt::ZERO,
                },
                payload: zmux::Chunk::from_static(b"test"),
            })
            .await
            .unwrap();
        let stream = || SpliceInjection {
            kind: SpliceKind::Stream,
            payload: zmux::Chunk::from_static(b"test"),
        };
        assert!(matches!(
            control.a_to_b.inject(stream()).await,
            Err(SpliceCommandError::SpliceBudget)
        ));
        resume.resume();
        let got = watchdog(60, "released datagram", read.read_datagram())
            .await
            .unwrap();
        assert_eq!(got.payload, payload);
        assert_eq!(datagram.disposition().await.unwrap().enqueued_items, 1);
        let after = control.a_to_b.inject(stream()).await.unwrap();
        assert_eq!(
            watchdog(60, "stream after budget releases", read_n(&mut read, 4)).await,
            payload
        );
        assert_eq!(after.disposition().await.unwrap().enqueued_items, 1);
        a.finish().unwrap();
        b.finish().unwrap();
        let result = watchdog(60, "splice result", relay).await.unwrap();
        assert_eq!(result.a_to_b.end, SpliceEnd::Finished);
    });
}

// Loaded with include! so rustfmt does not require the development-only file.
#[cfg(zmux_dev_contracts)]
mod contracts {
    include!("splice_contract/vectors.rs");
}
