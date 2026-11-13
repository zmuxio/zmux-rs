//! The datagram queue knobs:
//! each bounds its queue as configured, the oldest making
//! room, and zero is not a configuration.

use std::time::Instant;

use bytes::Bytes;
use zmux::proto::frame::Dir;
use zmux::proto::session::{Config, Role, SessionCore};

#[path = "common/core_pair.rs"]
mod core_pair;

use core_pair::CorePair as Pair;

fn config(f: impl FnOnce(&mut Config)) -> Config {
    let mut c = Config::default();
    c.enable_datagrams = true;
    f(&mut c);
    c
}

fn pair(a: Config, b: Config) -> Pair {
    let mut p = Pair::attached(a, b);
    p.pump();
    assert!(p.a.is_established() && p.b.is_established());
    p
}

fn received(core: &mut SessionCore) -> Vec<Bytes> {
    std::iter::from_fn(|| core.recv_datagram().unwrap()).collect()
}

#[test]
fn the_send_queue_keeps_the_newest() {
    let mut p = pair(config(|c| c.datagram_send_queue = 2), config(|_| {}));
    for i in 0..3u8 {
        p.a.send_datagram(Bytes::from(vec![i]), true).unwrap();
    }
    assert!(p.a.datagram_queue_full());
    p.pump();
    assert_eq!(
        received(&mut p.b),
        [Bytes::from(vec![1]), Bytes::from(vec![2])]
    );
    assert_eq!(p.a.stats().datagrams_dropped_send, 1);
}

#[test]
fn the_receive_queue_keeps_the_newest() {
    let mut p = pair(config(|_| {}), config(|c| c.datagram_receive_queue = 2));
    for i in 0..3u8 {
        p.a.send_datagram(Bytes::from(vec![i]), true).unwrap();
    }
    p.pump();
    assert_eq!(
        received(&mut p.b),
        [Bytes::from(vec![1]), Bytes::from(vec![2])]
    );
    assert_eq!(p.b.stats().datagrams_dropped_recv, 1);
}

#[test]
fn the_stream_queue_keeps_the_newest() {
    let mut p = pair(config(|_| {}), config(|c| c.datagram_stream_queue = 2));
    let k = p.a.open(Dir::Bidi).unwrap();
    p.a.write(k, b"x").unwrap();
    p.pump();
    let s = p.b.accept(Dir::Bidi).unwrap().expect("opened");
    for i in 0..3u8 {
        p.a.send_stream_datagram(k, 0, Bytes::from(vec![i]), true)
            .unwrap();
    }
    p.pump();
    let got: Vec<_> = std::iter::from_fn(|| p.b.recv_stream_datagram(s).unwrap()).collect();
    assert_eq!(got, [(0, Bytes::from(vec![1])), (0, Bytes::from(vec![2]))]);
    assert_eq!(p.b.stats().datagrams_dropped_recv, 1);
}

#[test]
fn the_receive_bytes_bound_the_session_queue() {
    let mut p = pair(config(|_| {}), config(|c| c.datagram_receive_bytes = 100));
    for i in 0..3u8 {
        p.a.send_datagram(Bytes::from(vec![i; 60]), true).unwrap();
    }
    p.pump();
    assert_eq!(received(&mut p.b), [Bytes::from(vec![2; 60])]);
    assert_eq!(p.b.stats().datagrams_dropped_recv, 2);
}

/// `n` datagrams of `len` bytes from A to a stream B opened and never reads;
/// returns what B's stream then holds and B's session drops.
fn to_an_unread_stream(b: Config, n: u8, len: usize) -> (Vec<(u64, Bytes)>, u64) {
    let mut p = pair(config(|_| {}), b);
    let k = p.a.open(Dir::Bidi).unwrap();
    p.a.write(k, b"x").unwrap();
    p.pump();
    let s = p.b.accept(Dir::Bidi).unwrap().expect("opened");
    for i in 0..n {
        p.a.send_stream_datagram(k, 0, Bytes::from(vec![i; len]), true)
            .unwrap();
    }
    p.pump();
    // A session datagram as large as B's whole receive bytes still fits:
    // the stream queue holds none of them.
    let whole = p.b.config().datagram_receive_bytes.min(1000);
    p.a.send_datagram(Bytes::from(vec![0xee; whole]), true)
        .unwrap();
    p.pump();
    assert_eq!(received(&mut p.b), [Bytes::from(vec![0xee; whole])]);
    let got = std::iter::from_fn(|| p.b.recv_stream_datagram(s).unwrap()).collect();
    (got, p.b.stats().datagrams_dropped_recv)
}

/// N18: a stream's datagram queue is bounded by its own bytes as well as
/// its count, the oldest making room, each drop counted; unlimited bytes
/// leave the count alone; the session's receive bytes do not count them.
#[test]
fn the_stream_bytes_bound_each_stream_queue() {
    let kib4 = 4 * 1024;
    let (got, dropped) = to_an_unread_stream(
        config(|c| {
            c.datagram_stream_bytes = Some(16 * 1024);
            c.datagram_receive_bytes = 1000;
        }),
        10,
        kib4,
    );
    let want: Vec<_> = (6..10u8).map(|i| (0, Bytes::from(vec![i; kib4]))).collect();
    assert_eq!(got, want);
    assert_eq!(dropped, 6);

    let (got, dropped) = to_an_unread_stream(
        config(|c| {
            c.datagram_stream_bytes = None;
            c.datagram_receive_bytes = 1000;
        }),
        10,
        kib4,
    );
    assert_eq!(got.len(), 10);
    assert_eq!(dropped, 0);

    // A datagram larger than the bound alone is kept alone.
    let (got, dropped) =
        to_an_unread_stream(config(|c| c.datagram_stream_bytes = Some(1000)), 2, 1500);
    assert_eq!(got, [(0, Bytes::from(vec![1; 1500]))]);
    assert_eq!(dropped, 1);

    // The defaults keep 32 datagrams of 9000 bytes.
    let (got, dropped) = to_an_unread_stream(config(|_| {}), 32, 9000);
    assert_eq!(got.len(), 32);
    assert_eq!(dropped, 0);
}

#[test]
fn zero_is_not_a_queue_size() {
    let sets: [fn(&mut Config); 5] = [
        |c| c.datagram_send_queue = 0,
        |c| c.datagram_receive_queue = 0,
        |c| c.datagram_stream_queue = 0,
        |c| c.datagram_receive_bytes = 0,
        |c| c.datagram_stream_bytes = Some(0),
    ];
    for set in sets {
        let r = SessionCore::new(config(set), Role::Client, None, Instant::now());
        assert!(r.is_err());
    }
}
