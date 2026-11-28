//! A
//! session that is CLOSING or CLOSED takes no new pipes and no new lanes
//! and keeps no lane state. Two sessions over an in-memory "connection"
//! whose further streams are duplex pairs handed to the peer's
//! `handle_lane`, as a QUIC adapter's accept loop would.

#![allow(
    clippy::cast_possible_truncation,
    reason = "test and bench values are small and bounded; checked conversions would only add noise"
)]

mod common;

use std::sync::Arc;
use std::time::Duration;

use common::{Carrier, eventually, multi_thread, settle, snapshot, watchdog};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use zmux::adapter::CarrierConnId;
use zmux::proto::session::State;
use zmux::test_hooks::lane_keys;
use zmux::{Config, PipeAuth, PipeIo, PipeOptions, Session};

const KEY: [u8; 16] = [0x5a; 16];

fn config(key: Option<[u8; 16]>) -> Config {
    let mut c = Config::default();
    c.session_policy.limits.steady_attachments = 4;
    c.pipe_auth = PipeAuth::psk(*b"lane-lifecycle--0123456789abcdef").with_end_to_end();
    c.test_hooks().lane_key = key;
    c
}

/// Lane 0 of a connection end: `conn` is this end's identity of the
/// connection, `peer` the other end's; a lane is a new duplex pair whose
/// reading end goes to the peer's lane routing.
fn lane_carrier(io: Carrier, conn: &CarrierConnId, peer: CarrierConnId) -> PipeIo {
    PipeIo::new(io)
        .with_carrier_conn(conn.clone())
        .with_lane_opener(move || {
            let peer = peer.clone();
            async move {
                let (w, r) = tokio::io::duplex(1 << 20);
                tokio::spawn(zmux::adapter::handle_lane(
                    PipeIo::reader(r).with_carrier_conn(peer),
                ));
                Ok(zmux::adapter::Lane::new(w))
            }
        })
}

/// The first record of a lane: `PIPE_LANE` for `key`, pipe 0, lane 7.
fn pipe_lane_record(key: &[u8; 16]) -> Vec<u8> {
    let mut frame = 0x3a05_a1c9u32.to_be_bytes().to_vec();
    frame[0] |= 0x80;
    frame.extend_from_slice(key);
    frame.extend_from_slice(&[0, 7]);
    let mut record = vec![frame.len() as u8];
    record.extend_from_slice(&frame);
    record
}

/// Hands a lane stream naming `key` to the lane routing as a stream of
/// connection `conn`: it is aborted (its writer sees the end), and the
/// routing refuses it.
async fn lane_is_aborted(conn: &CarrierConnId, key: &[u8; 16]) {
    let record = pipe_lane_record(key);
    for prefix_len in [1, record.len(), record.len() + 3] {
        let mut payload = record.clone();
        payload.extend_from_slice(b"end");
        for direct in [true, false] {
            let (mut w, r) = tokio::io::duplex(4096);
            w.write_all(&payload[prefix_len..]).await.unwrap();
            let io = PipeIo::reader(r)
                .with_carrier_conn(conn.clone())
                .with_prefix(payload[..prefix_len].to_vec());
            let routed = if direct {
                zmux::adapter::handle_lane(io).await
            } else {
                let l = zmux::Listener::new(Config::default(), zmux::ListenerConfig::default())
                    .unwrap();
                l.handle_pipe(io, zmux::PipeHint::default()).await
            };
            assert!(matches!(
                routed,
                Err(zmux::HandleError::Rejected | zmux::HandleError::Refused)
            ));
            assert!(matches!(w.read(&mut [0]).await, Ok(0) | Err(_)));
        }
    }
}

/// The bytes before and after a prefetched lane header reach the same live lane.
#[test]
// HS-31, HS-52, HS-58
fn prefetched_lane_records_attach_and_replay_their_suffix() {
    // Once the underlying reader has yielded the suffix, its next poll
    // acknowledges that the owner loop has processed the preceding record.
    struct Suffix {
        bytes: bytes::Bytes,
        consumed: Option<tokio::sync::oneshot::Sender<()>>,
    }

    impl tokio::io::AsyncRead for Suffix {
        fn poll_read(
            mut self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            if self.bytes.is_empty() {
                if let Some(consumed) = self.consumed.take() {
                    let _ = consumed.send(());
                }
                return std::task::Poll::Pending;
            }
            let n = self.bytes.len().min(buf.remaining());
            buf.put_slice(&self.bytes.split_to(n));
            std::task::Poll::Ready(Ok(()))
        }
    }

    struct EmptyLane {
        _dropped: tokio::sync::oneshot::Sender<()>,
    }
    impl tokio::io::AsyncRead for EmptyLane {
        fn poll_read(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
            _: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
    }

    multi_thread(async {
        let (ca, sa) = (Arc::new(()), Arc::new(()));
        let (cid, sid) = (CarrierConnId::new(&ca), CarrierConnId::new(&sa));
        let mut settings = config(Some(KEY));
        settings.max_lanes = 8u64.try_into().unwrap();
        let listener = zmux::Listener::new(settings, zmux::ListenerConfig::default()).unwrap();
        let (x, y) = tokio::io::duplex(8192);
        let (x, _) = Carrier::new(x);
        let (y, acknowledgements) = Carrier::new(y);
        let (handled, client) = tokio::join!(
            listener.handle_pipe(
                PipeIo::new(y)
                    .with_carrier_conn(sid.clone())
                    .with_lane_opener(std::future::pending),
                zmux::PipeHint::default()
            ),
            Session::connect(
                PipeIo::new(x)
                    .with_carrier_conn(cid)
                    .with_lane_opener(std::future::pending),
                config(None)
            )
        );
        handled.unwrap();
        let client = client.unwrap();
        let server = listener.accept().await.unwrap();
        let pipe = server.pipe(zmux::PipeId::new(0)).unwrap();
        // These streams stand in for peer-opened lanes. Keep their ACKs
        // from reaching the client, which did not originate their headers.
        acknowledgements.stall(true);
        listener.drain(b"lane routing during drain");
        // HS-58. The lane key and connection are genuine, but the other listener
        // never admitted this session.
        let lane = || {
            PipeIo::reader(tokio::io::empty())
                .with_carrier_conn(sid.clone())
                .with_prefix(pipe_lane_record(&KEY))
        };
        let other = zmux::Listener::new(config(None), zmux::ListenerConfig::default()).unwrap();
        assert_eq!(
            other.handle_pipe(lane(), zmux::PipeHint::default()).await,
            Err(zmux::HandleError::Rejected)
        );
        let mut number = 0u8;
        for direct in [true, false] {
            for prefetch in [
                1,
                pipe_lane_record(&KEY).len(),
                pipe_lane_record(&KEY).len() + 4,
            ] {
                number += 1;
                let mut record = pipe_lane_record(&KEY);
                *record.last_mut().unwrap() = number;
                // A complete record of padding following the first frame.
                record.extend_from_slice(&[3, 0, 0, 0]);
                let (consumed, processed) = tokio::sync::oneshot::channel();
                let r = Suffix {
                    bytes: bytes::Bytes::copy_from_slice(&record[prefetch..]),
                    consumed: Some(consumed),
                };
                let io = PipeIo::reader(r)
                    .with_carrier_conn(sid.clone())
                    .with_prefix(record[..prefetch].to_vec());
                if direct {
                    zmux::adapter::handle_lane(io).await.unwrap();
                } else {
                    listener
                        .handle_pipe(io, zmux::PipeHint::default())
                        .await
                        .unwrap();
                }
                watchdog(3, "lane reader resumed after its suffix", processed)
                    .await
                    .unwrap();
                let stats = pipe.stats().unwrap();
                let lane = stats
                    .lanes
                    .iter()
                    .find(|l| l.lane.get() == u64::from(number))
                    .unwrap();
                assert_eq!(lane.position_received, Some(record.len() as u64));
            }
        }
        // HS-52. A fresh lane can retire before its second record without
        // involving the main pipe. Wait for the actual reader's destructor.
        let (dropped, released) = tokio::sync::oneshot::channel();
        let mut header = pipe_lane_record(&KEY);
        *header.last_mut().unwrap() = number + 1;
        let io = PipeIo::reader(EmptyLane { _dropped: dropped })
            .with_carrier_conn(sid.clone())
            .with_prefix(header);
        zmux::adapter::handle_lane(io).await.unwrap();
        assert!(released.await.is_err());
        let (mut send, _recv) = client.open_bi().await.unwrap();
        send.write_all(b"after lane EOF").await.unwrap();
        send.finish().unwrap();
        let (_, mut recv) = server.accept_bi().await.unwrap();
        assert_eq!(
            recv.read_to_end(32).await.unwrap().as_slice(),
            b"after lane EOF"
        );
        listener.close();
        assert_eq!(
            zmux::adapter::handle_lane(lane()).await,
            Err(zmux::HandleError::Refused)
        );
    });
}

/// Adding a pipe fails, and its carrier is closed.
async fn attach_fails(s: &Session) {
    let (a, mut b) = tokio::io::duplex(4096);
    assert!(
        s.test_begin_join(PipeIo::new(a), PipeOptions::default())
            .is_err(),
        "a closing or closed session takes no pipe"
    );
    let mut buf = [0u8; 1];
    let r = watchdog(5, "the refused carrier closes", b.read(&mut buf)).await;
    assert!(matches!(r, Ok(0) | Err(_)), "the refused carrier is closed");
}

#[test]
fn a_closing_or_closed_session_takes_no_lanes_or_pipes_and_keeps_no_lane_state() {
    multi_thread(async {
        let base = snapshot();
        let n = lane_keys().len();
        let (ca, sa) = (Arc::new(()), Arc::new(()));
        let (cid, sid) = (CarrierConnId::new(&ca), CarrierConnId::new(&sa));
        let (x, y) = tokio::io::duplex(1 << 20);
        let (x, _) = Carrier::new(x);
        let (y, stall) = Carrier::new(y);
        let server = tokio::spawn(common::accept(
            lane_carrier(y, &sid, cid.clone()),
            config(Some(KEY)),
        ));
        let client = Session::connect(lane_carrier(x, &cid, sid.clone()), config(None))
            .await
            .unwrap();
        let server = server.await.unwrap().unwrap();
        // Bulk data opens lanes toward the server.
        let (mut send, crecv) = client.open_bi().await.unwrap();
        let writer = tokio::spawn(async move {
            send.write_all(&vec![7; 4 << 20]).await.unwrap();
            send.finish().unwrap();
            send
        });
        let (_, mut srecv) = server.accept_bi().await.unwrap();
        assert_eq!(srecv.read_to_end(8 << 20).await.unwrap().len(), 4 << 20);
        drop(writer.await.unwrap());
        assert!(server.debug_tables().lane_state > 0);
        assert!(lane_keys().contains(&KEY));
        assert_eq!(lane_keys().len(), n + 2);

        // CLOSING: the server's close frame waits behind a stalled carrier.
        stall.stall(true);
        drop(server.close());
        assert_eq!(server.state(), State::Closing);
        attach_fails(&server).await;
        lane_is_aborted(&sid, &KEY).await;
        assert_eq!(server.state(), State::Closing, "still closing");

        // CLOSED: lane state and the Lane Key entry are gone at once.
        stall.stall(false);
        eventually(5, "the server closes", || server.state() == State::Closed).await;
        assert_eq!(server.debug_tables().lane_state, 0);
        assert!(!lane_keys().contains(&KEY), "the Lane Key entry is gone");
        attach_fails(&server).await;
        lane_is_aborted(&sid, &KEY).await;
        assert_eq!(server.debug_tables().lane_state, 0, "nothing recreated");
        assert!(!lane_keys().contains(&KEY));

        drop(client.close());
        eventually(5, "the client closes", || client.state() == State::Closed).await;
        assert_eq!(client.debug_tables().lane_state, 0);
        assert_eq!(lane_keys().len(), n);
        drop((client, server, srecv, crecv));
        settle(base, 10, "sessions with lanes").await;
        tokio::time::sleep(Duration::from_millis(1)).await;
    });
}

/// A retiring pipe wakes the pending opener before its public completion.
#[test]
// HS-52
fn pipe_closed_waits_for_lane_worker_exit() {
    struct Worker {
        stopping: tokio::sync::oneshot::Sender<()>,
        release: std::sync::mpsc::Receiver<()>,
    }
    struct Gate(Option<Worker>);
    impl Drop for Gate {
        fn drop(&mut self) {
            let worker = self.0.take().unwrap();
            let _ = worker.stopping.send(());
            let _ = worker.release.recv_timeout(Duration::from_secs(5));
        }
    }
    multi_thread(async {
        let (ca, sa) = (Arc::new(()), Arc::new(()));
        let (cid, sid) = (CarrierConnId::new(&ca), CarrierConnId::new(&sa));
        let (x, y) = tokio::io::duplex(1 << 20);
        let (y, _) = Carrier::new(y);
        let server = tokio::spawn(common::accept(
            lane_carrier(y, &sid, cid.clone()),
            config(Some(KEY)),
        ));
        let (stop, stopping) = tokio::sync::oneshot::channel();
        let (release, gate) = std::sync::mpsc::channel();
        let (start, started) = tokio::sync::oneshot::channel();
        let worker = std::sync::Mutex::new(Some((
            start,
            Worker {
                stopping: stop,
                release: gate,
            },
        )));
        let io = PipeIo::new(x)
            .with_carrier_conn(cid)
            .with_lane_opener(move || {
                let worker = worker.lock().unwrap().take();
                async move {
                    let _hold = worker.map(|(start, worker)| {
                        let _ = start.send(());
                        Gate(Some(worker))
                    });
                    std::future::pending::<std::io::Result<zmux::adapter::Lane>>().await
                }
            });
        let client = Session::connect(io, config(None)).await.unwrap();
        let _server = server.await.unwrap().unwrap();
        let pipe = client.pipe(zmux::PipeId::new(0)).unwrap();
        let (mut send, _recv) = client.open_bi().await.unwrap();
        tokio::spawn(async move { send.write_all(&vec![7; 4 << 20]).await });
        watchdog(5, "lane opened", started).await.unwrap();
        pipe.abort().unwrap();
        watchdog(5, "opener retiring", stopping).await.unwrap();
        let mut closed = std::pin::pin!(pipe.closed());
        assert!(
            closed
                .as_mut()
                .poll(&mut std::task::Context::from_waker(std::task::Waker::noop()))
                .is_pending()
        );
        release.send(()).unwrap();
        assert!(matches!(
            watchdog(5, "lane worker released", closed).await,
            Err(zmux::PipeError::Failed(_))
        ));
    });
}

/// The unsent count a lane opener gives its lane reaches the pipe.
#[test]
fn a_lane_openers_unsent_count_is_read() {
    use tokio::sync::Notify;
    multi_thread(async {
        let (ca, sa) = (Arc::new(()), Arc::new(()));
        let (cid, sid) = (CarrierConnId::new(&ca), CarrierConnId::new(&sa));
        let (x, y) = tokio::io::duplex(1 << 20);
        let (x, _) = Carrier::new(x);
        let (y, _) = Carrier::new(y);
        let server = tokio::spawn(common::accept(
            lane_carrier(y, &sid, cid.clone()),
            config(Some(KEY)),
        ));
        let read = Arc::new(Notify::new());
        let (peer, was_read) = (sid.clone(), read.clone());
        let io = PipeIo::new(x)
            .with_carrier_conn(cid.clone())
            .with_lane_opener(move || {
                let (peer, was_read) = (peer.clone(), was_read.clone());
                async move {
                    let (w, r) = tokio::io::duplex(1 << 20);
                    tokio::spawn(zmux::adapter::handle_lane(
                        PipeIo::reader(r).with_carrier_conn(peer),
                    ));
                    Ok(zmux::adapter::Lane::new(w).with_unsent(move || {
                        was_read.notify_one();
                        Some(1234)
                    }))
                }
            });
        let client = Session::connect(io, config(None)).await.unwrap();
        let server = server.await.unwrap().unwrap();
        let (mut send, _r) = client.open_bi().await.unwrap();
        let writer = tokio::spawn(async move {
            let _ = send.write_all(&vec![7; 4 << 20]).await;
            send
        });
        watchdog(30, "the lane's count is read", read.notified()).await;
        drop(client.close());
        drop(server.close());
        drop(writer);
    });
}
