//! The runtime-setting setters of `StreamHandle`: they act on the stream, not
//! on a part, so they work while a write or a read of the part is in flight
//! (a part's own setters, which share their implementation, cannot be called
//! then in Rust), need no part, and fail as the parts' setters do.

#![allow(
    clippy::large_futures,
    reason = "scenario code: futures stay on the stack on purpose"
)]

mod common;

use std::future::{Future, poll_fn};
use std::pin::pin;
use std::task::Poll;

use common::{connect, small_windows, tcp, watchdog};
use zmux::sched::Scheduler;
use zmux::{Config, PipeIo, Priority, Session, StreamError, VarInt};

async fn pair() -> (Session, Session) {
    let (a, b) = tcp().await;
    connect(
        PipeIo::from_tcp(a),
        PipeIo::from_tcp(b),
        Config::default(),
        small_windows(Config::default()),
    )
    .await
}

/// A send buffer set through the handle while the part is blocked in a
/// write (in a task of its own) takes effect: the write, which could not
/// complete within the old bound, wakes and completes. The other
/// sending-part settings read back.
#[tokio::test]
async fn handle_setters_work_while_a_write_is_in_flight() {
    watchdog(20, "handle send setters", async {
        let (client, server) = pair().await;
        let (mut send, _recv) = client.open_bi().await.unwrap();
        let handle = send.handle();
        send.set_send_buffer(1).unwrap();
        let window = send.send_capacity();
        let bound = send.send_buffer() as u64;
        // More than the credit and the bound can hold: the write blocks
        // until the bound is raised, the peer reads nothing.
        let big = vec![7u8; usize::try_from(window + bound * 4).unwrap()];
        let writer = tokio::spawn(async move {
            send.write_all(&big).await.unwrap();
            send
        });
        // In flight: the credit used and the buffer full, so the write
        // waits for room that nothing but a larger bound makes.
        while {
            let stats = handle.stats();
            stats.bytes_sent < window || stats.bytes_written < window + bound
        } {
            tokio::task::yield_now().await;
        }
        assert!(!writer.is_finished());
        let want = Priority::new(1, false).unwrap();
        handle.set_priority(want).unwrap();
        handle
            .set_scheduler(Some(Scheduler::SpreadRoundRobin))
            .unwrap();
        handle.set_redundant(Some(true)).unwrap();
        assert_eq!(handle.priority(), want);
        assert!(matches!(
            handle.scheduler(),
            Some(Scheduler::SpreadRoundRobin)
        ));
        assert_eq!(handle.redundant(), Some(true));
        handle.set_scheduler(None).unwrap();
        handle.set_redundant(None).unwrap();
        assert!(handle.scheduler().is_none() && handle.redundant().is_none());
        // The bound raised: the blocked write wakes and takes the rest.
        handle.set_send_buffer(bound * 8).unwrap();
        assert_eq!(handle.send_buffer() as u64, bound * 8);
        let send = writer.await.unwrap();
        assert_eq!(
            send.send_buffer() as u64,
            bound * 8,
            "the part reads it too"
        );
        assert_eq!(send.priority(), want);
        drop(server);
    })
    .await;
}

/// A receive window set through the handle while the part waits in a read
/// is advertised: the peer's sending part gets the credit.
#[tokio::test]
async fn handle_receive_window_works_while_a_read_is_in_flight() {
    watchdog(20, "handle receive window", async {
        let (client, server) = pair().await;
        let (csend, mut crecv) = client.open_bi().await.unwrap();
        csend.pin_id().unwrap();
        let (ssend, _srecv) = server.accept_bi().await.unwrap();
        let handle = crecv.handle();
        let (initial, _) = handle.receive_window();
        let credit = ssend.send_capacity();
        assert_eq!(credit, initial, "the peer holds the advertised window");
        let mut buf = [0u8; 16];
        {
            let mut read = pin!(crecv.read(&mut buf));
            let polled = poll_fn(|cx| Poll::Ready(read.as_mut().poll(cx))).await;
            assert!(polled.is_pending(), "nothing to read");
            handle
                .set_receive_window(initial + 8192, initial + 16384)
                .unwrap();
            assert_eq!(handle.receive_window(), (initial + 8192, initial + 16384));
            // MAX_STREAM_DATA reaches the peer while the read still waits.
            ssend.wait_send_capacity(initial + 8192).await.unwrap();
        }
        assert_eq!(crecv.receive_window(), (initial + 8192, initial + 16384));
    })
    .await;
}

/// A handle's setter needs no part: it fails as the part's does where the
/// stream lacks that part, and once the stream was discarded.
#[tokio::test]
async fn handle_setters_fail_like_the_parts() {
    watchdog(20, "handle setter errors", async {
        let (client, server) = pair().await;
        let mut send = client.open_uni().await.unwrap();
        let handle = send.handle();
        // A send-only stream has no receiving part.
        assert_eq!(
            handle.set_receive_window(1 << 16, 1 << 17),
            Err(StreamError::ClosedLocally)
        );
        assert_eq!(
            handle.set_peer_priority(Priority::LOCAL_DEFAULT),
            Err(StreamError::ClosedLocally)
        );
        handle.set_send_buffer(1 << 20).unwrap();
        send.reset(VarInt::from_u32(0)).unwrap();
        drop(send);
        // The stream is discarded with its parts.
        for r in [
            handle.set_priority(Priority::LOCAL_DEFAULT),
            handle.set_scheduler(None),
            handle.set_redundant(None),
            handle.set_send_buffer(1 << 20),
        ] {
            assert_eq!(r, Err(StreamError::ClosedLocally));
        }
        assert_eq!(handle.send_buffer(), 1 << 20, "the last value stays");
        drop(server);
    })
    .await;
}

/// A datagram sent through the handle while a write of the part is blocked
/// is queued and reaches the peer's stream; the
/// handle reports the same path capacities as the part. Once the part was
/// released the handle's send fails as the part's would have: the stream is
/// closed.
#[tokio::test(start_paused = true)]
async fn handle_sends_a_stream_datagram_while_a_write_is_in_flight() {
    watchdog(60, "handle stream datagram", async {
        let config = || {
            let mut c = Config::default();
            c.enable_datagrams = true;
            c
        };
        let (a, b) = tokio::io::duplex(64 << 10);
        let (client, server) = connect(
            PipeIo::new(a),
            PipeIo::new(b),
            small_windows(config()),
            small_windows(config()),
        )
        .await;
        let (mut send, _recv) = client.open_bi().await.unwrap();
        send.pin_id().unwrap();
        let (_ssend, srecv) = server.accept_bi().await.unwrap();
        let handle = send.handle();
        send.set_send_buffer(1).unwrap();
        let window = send.send_capacity();
        let bound = send.send_buffer() as u64;
        let size = send.max_datagram_size(7);
        let path = send.datagram_path(7);
        assert!(size.is_some_and(|n| n > 0));
        assert!(path.payload.is_some_and(|n| n > 0));
        let big = vec![7u8; usize::try_from(window + bound * 4).unwrap()];
        {
            let mut write = pin!(send.write_all(&big));
            assert!(
                poll_fn(|cx| Poll::Ready(write.as_mut().poll(cx)))
                    .await
                    .is_pending()
            );
            assert_eq!(handle.max_datagram_size(7), size);
            assert_eq!(handle.datagram_path(7), path);
            assert_eq!(handle.path_datagram_size(7), path.payload);
            assert_eq!(handle.datagram_path(1 << 62), zmux::DatagramPath::default());
            handle
                .send_datagram(7, bytes::Bytes::from_static(b"while writing"))
                .unwrap();
            let got = srecv.read_datagram().await.unwrap();
            assert_eq!((got.context, &got.payload[..]), (7, &b"while writing"[..]));
            handle.set_send_buffer(bound * 8).unwrap();
            write.await.unwrap();
        }
        // A live stream refuses a context beyond the wire varint range.
        assert!(matches!(
            handle.send_datagram(1 << 62, bytes::Bytes::new()),
            Err(zmux::DatagramError::InvalidOptions(error)) if error.field() == "datagram_context"
        ));
        send.send_datagram(7, bytes::Bytes::from_static(b"part"))
            .unwrap();
        assert_eq!(&srecv.read_datagram().await.unwrap().payload[..], b"part");
        drop(send);
        assert_eq!(handle.datagram_path(7), zmux::DatagramPath::default());
        assert_eq!(
            handle.send_datagram(7, bytes::Bytes::from_static(b"late")),
            Err(zmux::DatagramError::ClosedStream),
            "the sending part was released"
        );
        drop(client);
    })
    .await;
}
