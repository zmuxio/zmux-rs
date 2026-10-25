//! A
//! session that is CLOSING or CLOSED takes no new pipes and no new lanes
//! and keeps no lane state. Two sessions over an in-memory "connection"
//! whose further streams are duplex pairs handed to the peer's
//! `handle_lane`, as a QUIC adapter's accept loop would.

mod common;

use std::io;
use std::sync::Arc;
use std::time::Duration;

use common::{Carrier, eventually, multi_thread, settle, snapshot, watchdog};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use zmux::carrier::CarrierConnId;
use zmux::proto::session::State;
use zmux::test_hooks::lane_keys;
use zmux::{Config, PipeAuth, PipeIo, PipeOptions, Session, VarInt};

const KEY: [u8; 16] = [0x5a; 16];

fn config(key: Option<[u8; 16]>) -> Config {
    let mut c = Config::default();
    c.max_pipes = 4;
    c.pipe_auth = PipeAuth::psk(*b"lane-lifecycle--0123456789abcdef");
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
                tokio::spawn(zmux::carrier::handle_lane(
                    PipeIo::reader(r).with_carrier_conn(peer),
                ));
                Ok::<_, io::Error>(w)
            }
        })
}

/// The first record of a lane: PIPE_LANE for `key`, pipe 0, lane 7.
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
    let (mut w, r) = tokio::io::duplex(4096);
    w.write_all(&pipe_lane_record(key)).await.unwrap();
    let routed =
        zmux::carrier::handle_lane(PipeIo::reader(r).with_carrier_conn(conn.clone())).await;
    assert!(routed.is_err(), "a closing or closed session takes no lane");
    let mut b = [0u8; 1];
    assert!(
        matches!(w.read(&mut b).await, Ok(0) | Err(_)),
        "the lane stream is closed"
    );
}

/// Adding a pipe fails, and its carrier is closed.
async fn attach_fails(s: &Session) {
    let (a, mut b) = tokio::io::duplex(4096);
    assert!(
        s.add_pipe(PipeIo::new(a), PipeOptions::default()).is_err(),
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
        server.close(VarInt::ZERO, b"");
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

        client.close(VarInt::ZERO, b"");
        eventually(5, "the client closes", || client.state() == State::Closed).await;
        assert_eq!(client.debug_tables().lane_state, 0);
        assert_eq!(lane_keys().len(), n);
        drop((client, server, srecv, crecv));
        settle(base, 10, "sessions with lanes").await;
        tokio::time::sleep(Duration::from_millis(1)).await;
    });
}
