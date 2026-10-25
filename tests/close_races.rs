//! Close races of the tokio driver (CONFORMANCE.md): each kind of wait raced, at a
//! random point, against session close, the peer's close, stream reset,
//! STOP_SENDING, the peer's GOAWAY, local shutdown, cancellation, deadline
//! expiry and carrier failure. Every call returns a defined outcome (no
//! hang, no panic), a cancellation racing with completion never loses or
//! duplicates data, streams or credit, and several waiters on one handle
//! are all served or released.
//!
//! Seeded on a single-threaded runtime with a paused clock (a failure
//! names its seed; `ZMUX_SEED=<n>` replays one iteration), plus a
//! multi-thread variant for real interleavings. `ZMUX_SOAK=50` runs the
//! 10^4 iterations per wait kind of the conformance plan.

mod common;

use std::time::Duration;

use bytes::Bytes;
use common::*;
use tokio::task::JoinHandle;
use zmux::{Config, VarInt};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Read,
    Write,
    OpenBi,
    OpenUni,
    AcceptBi,
    AcceptUni,
    Datagram,
    StreamDatagram,
    DatagramSpace,
    SessionEvent,
    Closed,
    Shutdown,
    Stopped,
    ReceivedReset,
}

const KINDS: [Kind; 14] = [
    Kind::Read,
    Kind::Write,
    Kind::OpenBi,
    Kind::OpenUni,
    Kind::AcceptBi,
    Kind::AcceptUni,
    Kind::Datagram,
    Kind::StreamDatagram,
    Kind::DatagramSpace,
    Kind::SessionEvent,
    Kind::Closed,
    Kind::Shutdown,
    Kind::Stopped,
    Kind::ReceivedReset,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Race {
    LocalClose,
    PeerClose,
    StreamReset,
    StopSending,
    PeerGoAway,
    LocalShutdown,
    Cancel,
    Deadline,
    CarrierFails,
}

const RACES: [Race; 9] = [
    Race::LocalClose,
    Race::PeerClose,
    Race::StreamReset,
    Race::StopSending,
    Race::PeerGoAway,
    Race::LocalShutdown,
    Race::Cancel,
    Race::Deadline,
    Race::CarrierFails,
];

fn config() -> Config {
    let mut c = small_windows(Config::default());
    // Writes wait for room (cancellable) well before the transfer ends.
    c.send_buffer = 64 * 1024;
    c.send_buffer_max = zmux::Cap::Fixed(64 * 1024);
    c.enable_datagrams = true;
    c.max_incoming_streams = 4;
    c.max_incoming_uni_streams = Some(1);
    c.max_idle_timeout = Duration::from_secs(5);
    c
}

/// One race: the waiter (`local`, the client unless noted) blocks in a wait
/// of `kind`; at a random point `race` happens; the wait must resolve.
async fn race_once(kind: Kind, race: Race, seed: u64, grace: Duration) {
    let mut rng = Rng::new(seed);
    let ((a, ca), (b, _cb)) = duplex(16 * 1024);
    let (local, peer) = connect(a, b, config(), config()).await;
    // Streams the waits use, with the peer's ends.
    let (mut l_send, l_recv) = local.open_bi().await.expect("open");
    l_send.write_all(b"x").await.expect("write");
    let (mut p_send, mut p_recv) = peer.accept_bi().await.expect("accept");
    let mut one = [0u8; 1];
    p_recv.read_exact(&mut one).await.expect("first byte");
    p_send.write_all(b"y").await.expect("write back");
    let mut l_recv = l_recv;
    l_recv.read_exact(&mut one).await.expect("first byte back");
    // Taken by the waits that use them, kept to the end otherwise.
    let mut l_send = Some(l_send);
    let mut l_recv = Some(l_recv);

    let deadline = Duration::from_micros(rng.below(3000));
    let wait: JoinHandle<String> = {
        let s = local.clone();
        let fut: std::pin::Pin<Box<dyn std::future::Future<Output = String> + Send>> = match kind {
            Kind::Read => {
                let mut r = l_recv.take().unwrap();
                Box::pin(async move {
                    let mut buf = [0u8; 64];
                    format!("{:?}", r.read(&mut buf).await)
                })
            }
            Kind::Write => {
                let mut w = l_send.take().unwrap();
                Box::pin(async move {
                    // The peer reads nothing: credit runs out.
                    let big = vec![1u8; 256 * 1024];
                    format!("{:?}", w.write_all(&big).await)
                })
            }
            Kind::OpenBi => Box::pin(async move {
                // The peer allows one stream, open already.
                format!("{:?}", s.open_bi().await.map(|_| ()))
            }),
            Kind::OpenUni => Box::pin(async move {
                let first = s.open_uni().await;
                let mut first = first.map_err(|e| format!("{e:?}"));
                if let Ok(f) = &mut first {
                    let _ = f.write_all(b"u").await;
                }
                format!("{:?}", s.open_uni().await.map(|_| ()))
            }),
            Kind::AcceptBi => {
                Box::pin(async move { format!("{:?}", s.accept_bi().await.map(|_| ())) })
            }
            Kind::AcceptUni => {
                Box::pin(async move { format!("{:?}", s.accept_uni().await.map(|_| ())) })
            }
            Kind::Datagram => Box::pin(async move { format!("{:?}", s.read_datagram().await) }),
            Kind::StreamDatagram => {
                let r = l_recv.take().unwrap();
                Box::pin(async move { format!("{:?}", r.read_datagram().await) })
            }
            Kind::DatagramSpace => {
                ca.stall(true);
                for _ in 0..2000 {
                    let _ = s.send_datagram(Bytes::from_static(b"d"));
                }
                Box::pin(async move {
                    format!("{:?}", s.send_datagram_wait(Bytes::from_static(b"w")).await)
                })
            }
            Kind::SessionEvent => Box::pin(async move { format!("{:?}", s.next_event().await) }),
            Kind::Closed => Box::pin(async move { format!("{:?}", s.closed().await) }),
            Kind::Shutdown => Box::pin(async move {
                // Waits for the open streams to end.
                format!("{:?}", s.shutdown(VarInt::from_u32(0), b"").await)
            }),
            Kind::Stopped => {
                let w = l_send.take().unwrap();
                Box::pin(async move { format!("{:?}", w.stopped().await) })
            }
            Kind::ReceivedReset => {
                let mut r = l_recv.take().unwrap();
                Box::pin(async move { format!("{:?}", r.received_reset().await) })
            }
        };
        let fut = if race == Race::Deadline {
            Box::pin(async move {
                match tokio::time::timeout(deadline, fut).await {
                    Ok(r) => r,
                    Err(_) => "deadline".to_string(),
                }
            })
        } else {
            fut
        };
        tokio::spawn(fut)
    };
    // A random point: the wait may not have started, be waiting, or be
    // about to complete.
    for _ in 0..rng.below(6) {
        tokio::task::yield_now().await;
    }
    if rng.below(2) == 0 {
        tokio::time::sleep(Duration::from_micros(rng.below(2000))).await;
    }
    match race {
        Race::LocalClose => local.close(VarInt::from_u32(1), b"local"),
        Race::PeerClose => peer.close(VarInt::from_u32(2), b"peer"),
        Race::StreamReset => {
            let _ = p_send.reset(VarInt::from_u32(3));
        }
        Race::StopSending => {
            let _ = p_recv.stop(VarInt::from_u32(4));
        }
        Race::PeerGoAway => {
            let p = peer.clone();
            tokio::spawn(async move {
                let _ = p.shutdown(VarInt::from_u32(5), b"goaway").await;
            });
        }
        Race::LocalShutdown => {
            let s = local.clone();
            tokio::spawn(async move {
                let _ = s.shutdown(VarInt::from_u32(6), b"shutdown").await;
            });
        }
        Race::Cancel => wait.abort(),
        Race::Deadline => {}
        Race::CarrierFails => ca.fail(),
    }
    // Waits that the race does not end (a read raced by STOP_SENDING, for
    // one) end with the session.
    let outcome = {
        let mut wait = wait;
        match tokio::time::timeout(grace, &mut wait).await {
            Ok(r) => r,
            Err(_) => {
                // A race that ends the session must have ended the wait.
                assert!(
                    !matches!(
                        race,
                        Race::LocalClose | Race::PeerClose | Race::CarrierFails
                    ),
                    "seed {seed}: {kind:?} raced with {race:?}: the session ended, the wait did not"
                );
                local.close(VarInt::from_u32(9), b"end");
                match tokio::time::timeout(Duration::from_secs(10), wait).await {
                    Ok(r) => r,
                    Err(_) => panic!(
                        "seed {seed}: {kind:?} raced with {race:?}: the wait did not resolve \
                         after the session closed"
                    ),
                }
            }
        }
    };
    match outcome {
        Ok(_) => {}
        Err(e) if e.is_cancelled() => assert_eq!(race, Race::Cancel, "seed {seed}"),
        Err(e) => panic!("seed {seed}: {kind:?} raced with {race:?}: the wait panicked: {e}"),
    }
    local.close(VarInt::from_u32(0), b"");
    peer.close(VarInt::from_u32(0), b"");
    drop((l_send, l_recv, p_send, p_recv));
    watchdog(10, "closed", local.closed()).await;
    watchdog(10, "peer closed", peer.closed()).await;
}

fn iterations(per_kind: usize) -> usize {
    soak(per_kind)
}

/// Every wait kind against every race, at random points, on a virtual
/// clock; resources back at their baseline every round.
#[test]
fn every_wait_resolves_against_every_race() {
    paused(async {
        let base = snapshot();
        let only: Option<u64> = std::env::var("ZMUX_SEED").ok().and_then(|v| v.parse().ok());
        let n = iterations(200);
        for i in 0..n * KINDS.len() {
            let seed = only.unwrap_or(i as u64);
            let kind = KINDS[(seed as usize) % KINDS.len()];
            let race = RACES[(seed as usize / KINDS.len()) % RACES.len()];
            let grace = Duration::from_millis(500);
            watchdog(
                60,
                &format!("seed {seed}: {kind:?} vs {race:?}"),
                race_once(kind, race, seed, grace),
            )
            .await;
            if only.is_some() {
                break;
            }
            if i % 500 == 499 {
                settle(base, 30, &format!("after seed {seed}")).await;
            }
        }
        settle(base, 30, "end").await;
    });
}

// ---- cancellation against completion -------------------------------------------------

/// When a call is cancelled: half the time right after its first poll (a
/// zero timeout: cancelled exactly when it would wait), else after a
/// random time.
fn cancel_point(rng: &mut Rng) -> Duration {
    if rng.below(2) == 0 {
        Duration::ZERO
    } else {
        Duration::from_micros(rng.below(400))
    }
}

/// Reads and writes cancelled at random points while data flows: what
/// arrives is exactly what the completed writes reported, in order.
#[test]
fn cancelled_reads_and_writes_lose_nothing() {
    paused(async {
        let base = snapshot();
        let ((a, _), (b, _)) = duplex(8 * 1024);
        let (client, server) = connect(a, b, config(), config()).await;
        let (mut send, _r) = client.open_bi().await.unwrap();
        send.write_all(b"\0").await.unwrap();
        let (_s, mut recv) = server.accept_bi().await.unwrap();
        let total = soak(4 << 20) as u64;
        let pat = |o: u64| (o ^ (o >> 9)) as u8;
        let writer = tokio::spawn(async move {
            let mut rng = Rng::new(1);
            let mut written = 1u64;
            let mut cancelled = 0u64;
            while written < total {
                let len = 1 + rng.below(20_000);
                let data: Vec<u8> = (written..written + len).map(pat).collect();
                let t = cancel_point(&mut rng);
                match tokio::time::timeout(t, send.write(&data)).await {
                    Ok(Ok(n)) => written += n as u64,
                    Ok(Err(e)) => panic!("write: {e:?}"),
                    Err(_) => cancelled += 1,
                }
            }
            send.finish().unwrap();
            (written, cancelled)
        });
        let mut rng = Rng::new(2);
        let mut read = 1u64;
        let mut cancelled = 0u64;
        let mut first = [0u8; 1];
        recv.read_exact(&mut first).await.unwrap();
        loop {
            let mut buf = vec![0u8; 1 + rng.below(30_000) as usize];
            let t = cancel_point(&mut rng);
            match tokio::time::timeout(t, recv.read(&mut buf)).await {
                Ok(Ok(Some(n))) => {
                    for (i, &b) in buf[..n].iter().enumerate() {
                        assert_eq!(
                            b,
                            pat(read + i as u64),
                            "byte {} lost or duplicated",
                            read + i as u64
                        );
                    }
                    read += n as u64;
                }
                Ok(Ok(None)) => break,
                Ok(Err(e)) => panic!("read: {e:?}"),
                Err(_) => cancelled += 1,
            }
        }
        let (written, w_cancelled) = writer.await.unwrap();
        assert_eq!(read, written);
        assert!(
            cancelled > 20 && w_cancelled > 20,
            "cancellations: {cancelled} reads, {w_cancelled} writes"
        );
        let t = (client.debug_tables(), server.debug_tables());
        assert!(t.0.waits == 0 && t.1.waits == 0, "stale waits: {t:?}");
        drop((recv, _r, _s));
        client.close(VarInt::from_u32(0), b"");
        drop((client, server));
        settle(base, 10, "end").await;
    });
}

/// Accepts and opens cancelled at random points: every stream the peer
/// opened is accepted exactly once, and cancelled openers keep no credit.
#[test]
fn cancelled_accepts_and_opens_lose_nothing() {
    paused(async {
        let base = snapshot();
        let ((a, _), (b, _)) = duplex(64 * 1024);
        let mut cfg = config();
        cfg.max_incoming_streams = 4;
        let (client, server) = connect(a, b, cfg.clone(), cfg).await;
        let n = soak(400) as u64;
        let opener = {
            let c = client.clone();
            tokio::spawn(async move {
                let mut rng = Rng::new(3);
                let mut opened = Vec::new();
                let mut cancelled = 0;
                while (opened.len() as u64) < n {
                    let t = cancel_point(&mut rng);
                    match tokio::time::timeout(t, c.open_bi()).await {
                        Ok(Ok((mut s, _r))) => {
                            let id = s.pin_id().unwrap().into_inner();
                            s.write_all(&id.to_le_bytes()).await.unwrap();
                            s.finish().unwrap();
                            opened.push(id);
                        }
                        Ok(Err(e)) => panic!("open: {e:?}"),
                        Err(_) => cancelled += 1,
                    }
                }
                (opened, cancelled)
            })
        };
        let mut rng = Rng::new(4);
        let mut accepted = std::collections::BTreeSet::new();
        let mut cancelled = 0;
        while (accepted.len() as u64) < n {
            let t = cancel_point(&mut rng);
            match tokio::time::timeout(t, server.accept_bi()).await {
                Ok(Ok((_s, mut r))) => {
                    let id = r.pin_id().unwrap().into_inner();
                    let body = r.read_to_end(8).await.unwrap();
                    assert_eq!(body, id.to_le_bytes(), "stream {id} body");
                    assert!(accepted.insert(id), "stream {id} accepted twice");
                }
                Ok(Err(e)) => panic!("accept: {e:?}"),
                Err(_) => cancelled += 1,
            }
        }
        let (opened, o_cancelled) = opener.await.unwrap();
        assert_eq!(
            opened
                .into_iter()
                .collect::<std::collections::BTreeSet<_>>(),
            accepted
        );
        assert!(
            cancelled > 10 && o_cancelled > 10,
            "cancellations: {cancelled} accepts, {o_cancelled} opens"
        );
        client.close(VarInt::from_u32(0), b"");
        drop((client, server));
        settle(base, 10, "end").await;
    });
}

// ---- multiple waiters ----------------------------------------------------------------

/// Several waiters on one handle, where the API allows them (methods on
/// `&self`): each condition serves them, and the close releases the rest.
#[test]
fn multiple_waiters_are_all_served_or_released() {
    paused(async {
        let base = snapshot();
        let ((a, _), (b, _)) = duplex(64 * 1024);
        let mut cfg = config();
        cfg.max_incoming_streams = 4;
        let (client, server) = connect(a, b, cfg.clone(), cfg).await;
        const N: usize = 6;
        // Acceptors: the peer opens N streams; each acceptor gets one.
        let acceptors: Vec<_> = (0..N)
            .map(|_| {
                let s = server.clone();
                tokio::spawn(async move {
                    let (_s, mut r) = s.accept_bi().await.ok()?;
                    let mut b = [0u8; 1];
                    r.read_exact(&mut b).await.ok()?;
                    Some(r.pin_id().ok()?.into_inner())
                })
            })
            .collect();
        // Openers beyond the credit: they wait, in order.
        let openers: Vec<_> = (0..N)
            .map(|i| {
                let c = client.clone();
                tokio::spawn(async move {
                    tokio::time::sleep(Duration::from_micros(i as u64)).await;
                    let (mut s, r) = c.open_bi().await.ok()?;
                    s.write_all(&[i as u8]).await.ok()?;
                    // Hold the stream until the acceptor read it.
                    tokio::time::sleep(Duration::from_millis(1)).await;
                    // The acceptor may have stopped it already.
                    let _ = s.finish();
                    drop(r);
                    Some(())
                })
            })
            .collect();
        // Datagram readers: each datagram reaches one of them.
        let readers: Vec<_> = (0..N)
            .map(|_| {
                let s = server.clone();
                tokio::spawn(async move { s.read_datagram().await.ok() })
            })
            .collect();
        // Waiters for the end: all released by the close.
        let closed: Vec<_> = (0..N)
            .map(|_| {
                let s = server.clone();
                tokio::spawn(async move { s.closed().await })
            })
            .collect();
        let events: Vec<_> = (0..N)
            .map(|_| {
                let s = server.clone();
                tokio::spawn(async move { s.next_event().await })
            })
            .collect();
        let mut ids = std::collections::BTreeSet::new();
        for a in acceptors {
            let id = watchdog(10, "acceptor", a)
                .await
                .unwrap()
                .expect("accepted");
            assert!(ids.insert(id), "stream {id} accepted twice");
        }
        for o in openers {
            assert!(watchdog(10, "opener", o).await.unwrap().is_some());
        }
        for i in 0..N {
            client.send_datagram(Bytes::from(vec![i as u8; 8])).unwrap();
        }
        let mut got = std::collections::BTreeSet::new();
        for r in readers {
            let d = watchdog(10, "datagram reader", r)
                .await
                .unwrap()
                .expect("datagram");
            assert!(got.insert(d[0]), "datagram {} read twice", d[0]);
        }
        client.close(VarInt::from_u32(1), b"bye");
        for c in closed {
            watchdog(10, "closed waiter", c).await.unwrap();
        }
        for e in events {
            watchdog(10, "pipe event waiter", e).await.unwrap();
        }
        drop((client, server));
        settle(base, 10, "end").await;
    });
}
