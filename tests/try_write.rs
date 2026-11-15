//! The synchronous writes of `SendStream`: `try_write` and
//! `try_write_chunk` take what fits now and never wait, `Ok(0)` when
//! nothing fits, the part's error once it ended; with `poll_writable`
//! they form a cancel-safe write.

#![allow(
    clippy::cast_possible_truncation,
    reason = "test values are small and bounded"
)]
#![allow(
    clippy::large_futures,
    reason = "scenario code: futures stay on the stack on purpose"
)]

mod common;

use std::future::poll_fn;
use std::time::Duration;

use bytes::Bytes;
use common::{connect, small_windows, tcp, watchdog};
use zmux::{Config, PipeIo, SendStream, Session, VarInt};

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

/// Fills the stream with `try_write` until it takes nothing; the total.
fn fill(send: &mut SendStream) -> usize {
    let buf = vec![7u8; 64 * 1024];
    let mut total = 0;
    loop {
        let n = send.try_write(&buf).unwrap();
        if n == 0 {
            return total;
        }
        assert!(n < buf.len() || total == 0, "a partial write once full");
        total += n;
    }
}

#[tokio::test]
async fn try_write_takes_what_fits_and_never_waits() {
    watchdog(20, "try_write", async {
        let (client, server) = pair().await;
        let (mut send, _recv) = client.open_bi().await.unwrap();
        send.set_send_buffer(1).unwrap();
        assert_eq!(send.try_write(&[]).unwrap(), 0, "empty");
        let window = send.send_capacity() as usize;
        let big = vec![1u8; window * 4];
        let first = send.try_write(&big).unwrap();
        assert!(first > 0 && first < big.len(), "partial: {first}");
        let mut total = first + fill(&mut send);
        assert_eq!(send.try_write(b"x").unwrap(), 0, "no room");
        // The driver drains the buffers as far as credit lets: every room
        // it makes is taken, until credit is out and the buffers are full.
        while let Ok(room) = tokio::time::timeout(Duration::from_millis(50), send.writable()).await
        {
            let room = room.unwrap() as usize;
            let n = send.try_write(&big).unwrap();
            assert!(n >= room.min(big.len()), "ready means the write takes it");
            total += n;
        }
        assert_eq!(send.send_capacity(), 0, "no credit left");

        // Cancelled room waits consume nothing.
        for _ in 0..3 {
            let w = tokio::time::timeout(
                Duration::from_millis(10),
                poll_fn(|cx| send.poll_writable(cx)),
            )
            .await;
            assert!(w.is_err(), "no room yet");
        }
        assert_eq!(send.try_write(b"x").unwrap(), 0, "still no room");

        let (_ss, mut sr) = server.accept_bi().await.unwrap();
        let read = async {
            tokio::time::sleep(Duration::from_millis(20)).await;
            let mut buf = vec![0u8; total];
            sr.read_exact(&mut buf).await.unwrap();
            sr
        };
        let (room, mut sr) = tokio::join!(send.writable(), read);
        let room = room.unwrap() as usize;
        assert!(room > 0);
        let n = send.try_write(&big).unwrap();
        assert!(n >= room.min(big.len()), "takes the room it was ready with");

        sr.stop(VarInt::from_u32(5)).unwrap();
        let ended = poll_fn(|cx| send.poll_writable(cx)).await;
        assert!(ended.is_err(), "{ended:?}");
        assert!(send.try_write(b"x").is_err(), "after STOP_SENDING");
        let mut chunk = Bytes::from_static(b"x");
        assert!(send.try_write_chunk(&mut chunk).is_err());
        assert_eq!(chunk.len(), 1, "an error takes nothing");
    })
    .await;
}

/// A binding's writer loop (wait for room, `try_write`) never spins:
/// every ready poll is followed by a write that takes bytes, so the polls
/// stay within twice the writes, and all the data arrives.
#[tokio::test]
async fn writable_then_try_write_never_spins() {
    const TOTAL: usize = 4 << 20;
    watchdog(30, "writable loop", async {
        let (client, server) = pair().await;
        let reader = tokio::spawn(async move {
            let (_ss, mut sr) = server.accept_bi().await.unwrap();
            let mut buf = vec![0u8; 64 * 1024];
            let mut got = 0;
            while got < TOTAL {
                let n = sr.read(&mut buf).await.unwrap().expect("data");
                got += n;
            }
            got
        });
        let (mut send, _recv) = client.open_bi().await.unwrap();
        let buf = vec![9u8; 48 * 1024];
        let (mut taken, mut polls, mut writes, mut wasted) = (0, 0u64, 0u64, 0u64);
        while taken < TOTAL {
            let room = poll_fn(|cx| {
                polls += 1;
                send.poll_writable(cx)
            })
            .await
            .unwrap();
            assert!(room > 0);
            let n = send
                .try_write(&buf[..buf.len().min(TOTAL - taken)])
                .unwrap();
            if n == 0 {
                wasted += 1;
            } else {
                writes += 1;
                taken += n;
            }
        }
        assert_eq!(wasted, 0, "a ready poll whose write took nothing");
        assert!(polls <= 2 * writes + 1, "{polls} polls for {writes} writes");
        send.finish().unwrap();
        assert_eq!(reader.await.unwrap(), TOTAL);
    })
    .await;
}

#[tokio::test]
async fn try_write_chunk_advances_and_reset_ends_it() {
    watchdog(20, "try_write_chunk", async {
        let (client, server) = pair().await;
        let (mut send, _recv) = client.open_bi().await.unwrap();
        send.set_send_buffer(1).unwrap();
        let window = send.send_capacity() as usize;
        let data = Bytes::from(vec![3u8; window * 4]);
        let mut chunk = data.clone();
        let n = send.try_write_chunk(&mut chunk).unwrap();
        assert!(n > 0 && n < data.len(), "partial: {n}");
        assert_eq!(chunk, data.slice(n..), "advanced by the bytes taken");
        while send.try_write_chunk(&mut chunk).unwrap() > 0 {}
        let left = chunk.len();
        assert_eq!(send.try_write_chunk(&mut chunk).unwrap(), 0);
        assert_eq!(chunk.len(), left, "Ok(0) leaves it unchanged");

        let (_ss, mut sr) = server.accept_bi().await.unwrap();
        let mut got = vec![0u8; data.len() - left];
        sr.read_exact(&mut got).await.unwrap();
        assert_eq!(&got[..], &data[..got.len()]);

        send.reset(VarInt::from_u32(1)).unwrap();
        assert!(send.try_write(b"x").is_err(), "after reset");
        assert!(send.try_write_chunk(&mut chunk).is_err());
    })
    .await;
}

/// The std driver's `try_write` never waits either, and its data arrives.
#[cfg(feature = "blocking")]
#[test]
fn blocking_try_write_never_waits() {
    use zmux::blocking::{PipeIo, Session};
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        let (c, _) = l.accept().unwrap();
        Session::accept(PipeIo::from_tcp(c), small_windows(Config::default())).unwrap()
    });
    let c = std::net::TcpStream::connect(addr).unwrap();
    let client = Session::connect(PipeIo::from_tcp(c), Config::default()).unwrap();
    let server = server.join().unwrap();
    let (mut send, _recv) = client.open_bi().unwrap();
    send.set_send_buffer(1).unwrap();
    let mut total = 0;
    let buf = vec![9u8; 64 * 1024];
    loop {
        let n = send.try_write(&buf).unwrap();
        if n == 0 {
            break;
        }
        total += n;
    }
    assert!(total > 0 && total < buf.len());
    // The driver runs on its own thread and may free buffer space between
    // calls, so a chunk may take part of itself or nothing, never wait, and
    // only the bytes it took (`Ok(0)` takes none) reach the peer.
    let mut chunk = Bytes::from(vec![9u8; 2]);
    let n = send.try_write_chunk(&mut chunk).unwrap();
    assert!(
        n <= 2 && chunk.len() == 2 - n,
        "advanced by the bytes taken"
    );
    total += n;
    let (_ss, mut sr) = server.accept_bi().unwrap();
    let mut got = vec![0u8; total];
    sr.read_exact(&mut got).unwrap();
    assert!(got.iter().all(|&b| b == 9));
    send.reset(VarInt::from_u32(1)).unwrap();
    assert!(send.try_write_chunk(&mut chunk).is_err());
}
