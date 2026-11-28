//! Fixed-work release benchmark for the driver to `ChunkWrite` handoff.
//!
//! Measures chunk-write throughput and allocation behavior.
#![allow(
    unsafe_code,
    reason = "the measurement allocator and Linux PMU need FFI"
)]

#[cfg(target_os = "linux")]
#[path = "chunk_write/instructions.rs"]
mod instructions;

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::future::{Future, pending};
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::Instant;

use bytes::Buf;
use tokio::io::{AsyncRead, ReadBuf};
use zmux::adapter::{ChunkBuf, ChunkWrite};
use zmux::proto::params::TransportParameters;
use zmux::{Chunk, ClockDomain, Config, MonotonicClock, PipeIo, RecvStream, SendStream, Session};

#[derive(Clone, Copy, Default)]
struct Counts {
    allocations: u64,
    bytes: u64,
}

thread_local! {
    static COUNTS: Cell<Counts> = const { Cell::new(Counts { allocations: 0, bytes: 0 }) };
}

fn count(size: usize) {
    let _ = COUNTS.try_with(|counts| {
        let mut value = counts.get();
        value.allocations += 1;
        value.bytes += size as u64;
        counts.set(value);
    });
}

struct Counting;

// SAFETY: all allocation arguments and results are forwarded to System.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        count(layout.size());
        // SAFETY: forwarded unchanged.
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        count(layout.size());
        // SAFETY: forwarded unchanged.
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        count(size);
        // SAFETY: forwarded unchanged.
        unsafe { System.realloc(ptr, layout, size) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: forwarded unchanged.
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

/// Retain each accepted batch until the receiver drains it, just as
/// an adapter's transport may retain its split header and payload.
#[derive(Default)]
struct Wire {
    accepted: ChunkBuf,
    reader: Option<Waker>,
    writer: Option<Waker>,
    closed: bool,
}

struct Read(Arc<Mutex<Wire>>);
struct Write(Arc<Mutex<Wire>>);

impl AsyncRead for Read {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let mut wire = self.0.lock().unwrap();
        if wire.accepted.is_empty() {
            if wire.closed {
                return Poll::Ready(Ok(()));
            }
            wire.reader = Some(cx.waker().clone());
            return Poll::Pending;
        }
        while !wire.accepted.is_empty() && buf.remaining() != 0 {
            let front = wire.accepted.chunk();
            let n = front.len().min(buf.remaining());
            buf.put_slice(&front[..n]);
            wire.accepted.advance(n);
        }
        if wire.accepted.is_empty()
            && let Some(waker) = wire.writer.take()
        {
            waker.wake();
        }
        Poll::Ready(Ok(()))
    }
}

impl ChunkWrite for Write {
    fn poll_write_chunks(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        chunks: &mut [Chunk],
    ) -> Poll<io::Result<usize>> {
        let mut wire = self.0.lock().unwrap();
        if !wire.accepted.is_empty() {
            wire.writer = Some(cx.waker().clone());
            return Poll::Pending;
        }
        let accepted = wire.accepted.take_from(chunks);
        if let Some(waker) = wire.reader.take() {
            waker.wake();
        }
        Poll::Ready(Ok(accepted))
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut wire = self.0.lock().unwrap();
        wire.closed = true;
        if let Some(waker) = wire.reader.take() {
            waker.wake();
        }
        Poll::Ready(Ok(()))
    }
}

fn carriers() -> (PipeIo, PipeIo) {
    let ab = Arc::<Mutex<Wire>>::default();
    let ba = Arc::<Mutex<Wire>>::default();
    (
        PipeIo::from_chunk_halves(Read(ba.clone()), Write(ab.clone())).with_low_water(),
        PipeIo::from_chunk_halves(Read(ab), Write(ba)).with_low_water(),
    )
}

struct FixedClock(Instant);

impl MonotonicClock for FixedClock {
    fn now(&self) -> Instant {
        self.0
    }

    fn sleep_until(&self, _: Instant) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        Box::pin(pending())
    }
}

const LENGTH: usize = 4096;
const WARMUP: usize = 2048;
const OPERATIONS: usize = 16_384;

async fn transfer(send: &mut SendStream, recv: &mut RecvStream, payload: &Chunk, count: usize) {
    for _ in 0..count {
        send.write_chunk(payload.clone()).await.unwrap();
        read_payload(recv, payload).await;
    }
}

async fn read_payload(recv: &mut RecvStream, payload: &Chunk) {
    let mut received = [0; LENGTH];
    let mut offset = 0;
    while offset < LENGTH {
        let n = recv.read(&mut received[offset..]).await.unwrap().unwrap();
        assert_ne!(n, 0);
        offset += n;
    }
    assert_eq!(&received, payload.as_ref());
}

async fn run() -> io::Result<()> {
    let (a, b) = carriers();
    let mut config = Config::default();
    config.clock_domain = ClockDomain::with_source(FixedClock(Instant::now()));
    config.max_idle_timeout = None;
    config.liveness.keep_alive_period = None;
    config.test_hooks().no_first_ping = true;
    config.test_hooks().grease_tp = Some((27, vec![0; 8]));
    // This baseline isolates the owned write path from ACK timers and
    // multipath scheduling. Stream and connection credit remain in use.
    config.test_hooks().transport_parameters = Some(TransportParameters {
        initial_max_data: Some(config.initial_connection_receive_window),
        initial_max_stream_data_uni: Some(config.initial_stream_receive_window),
        initial_max_streams_bidi: Some(16),
        initial_max_streams_uni: Some(16),
        ..TransportParameters::default()
    });
    let (client, server) = tokio::join!(
        Session::connect(a, config.clone()),
        Session::accept(b, config)
    );
    let client = client.unwrap();
    let server = server.unwrap();
    let mut send = client.open_uni().await.unwrap();
    let payload = Chunk::from(vec![0x35; LENGTH]);
    send.write_chunk(payload.clone()).await.unwrap();
    let mut recv = server.accept_uni().await.unwrap();
    read_payload(&mut recv, &payload).await;
    assert!(!client.pipe_ack_in_use());
    transfer(&mut send, &mut recv, &payload, WARMUP).await;

    #[cfg(target_os = "linux")]
    let instructions = instructions::Instructions::open()?;
    let before = COUNTS.get();
    #[cfg(target_os = "linux")]
    instructions.start()?;
    transfer(&mut send, &mut recv, &payload, OPERATIONS).await;
    #[cfg(target_os = "linux")]
    let instruction_count = instructions.stop()?;
    #[cfg(not(target_os = "linux"))]
    let instruction_count = 0;
    let after = COUNTS.get();
    println!(
        "{{\"operations\":{},\"allocations\":{},\"bytes\":{},\"instructions\":{}}}",
        OPERATIONS,
        after.allocations - before.allocations,
        after.bytes - before.bytes,
        instruction_count
    );
    Ok(())
}

fn main() -> io::Result<()> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()?;
    runtime.block_on(run())
}
