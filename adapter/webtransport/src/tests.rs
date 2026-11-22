use std::net::{Ipv4Addr, SocketAddr};
use std::task::{Context, Waker};
use std::time::Duration;

use super::{Carrier, Options, Url};
use tokio::net::UdpSocket;
use tokio::sync::{oneshot, watch};
use zmux::{Config, PipeId, PipeIo, Session};

#[path = "../tests/common/mod.rs"]
mod common;

/// The main pipe runs in memory. Only the actual WebTransport lanes go
/// through the relay, so withholding their ACK cannot block session close.
#[tokio::test]
// HS-51
async fn closed_waits_for_the_webtransport_lane_ack() {
    let opts = Options::default();
    let mut wt = common::Wt::new(&opts);
    let server_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, wt.url.port().unwrap()));
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    wt.url
        .set_port(Some(socket.local_addr().unwrap().port()))
        .unwrap();
    let (gate, mut blocked) = watch::channel(false);
    let (waiting, pending_ack) = oneshot::channel();
    let relay = tokio::spawn(async move {
        let mut buf = vec![0; u16::MAX.into()];
        let mut peer = None;
        let mut waiting = Some(waiting);
        loop {
            let (len, addr) = socket.recv_from(&mut buf).await.unwrap();
            let to = if addr == server_addr {
                if *blocked.borrow() {
                    if let Some(waiting) = waiting.take() {
                        let _ = waiting.send(());
                    }
                    if blocked.wait_for(|held| !*held).await.is_err() {
                        return;
                    }
                }
                peer.expect("received an initial packet")
            } else {
                peer = Some(addr);
                server_addr
            };
            socket.send_to(&buf[..len], to).await.unwrap();
        }
    });
    tokio::time::timeout(Duration::from_secs(10), async {
        let (cw, sw) = wt.pair().await;
        let client = Carrier::new(cw, opts.clone());
        let server = Carrier::new(sw, opts);
        let (a, b) = tokio::io::duplex(1 << 16);
        let a = client
            .inner
            .with_lanes(PipeIo::new(a).with_carrier_conn(client.inner.id()));
        let b = PipeIo::new(b)
            .with_carrier_conn(server.inner.id())
            .with_lanes(true);
        let (cs, ss) = tokio::join!(
            Session::connect(a, Config::default()),
            Session::accept(b, Config::default())
        );
        let (cs, ss) = (cs.unwrap(), ss.unwrap());
        common::transfer(&cs, &ss, 3, 512 << 10).await;
        assert!(cs.pipe_stats()[0].lanes_out > 1);
        let pipe = cs.pipe(PipeId::new(0)).unwrap();
        gate.send(true).unwrap();
        cs.close().await;
        cs.closed().await;
        pending_ack.await.unwrap();
        let mut closed = std::pin::pin!(pipe.closed());
        assert!(
            closed
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
        gate.send(false).unwrap();
        assert!(matches!(closed.await, Err(zmux::PipeError::SessionLost(_))));
    })
    .await
    .expect("WebTransport lane completed");
    relay.abort();
    let _ = relay.await;
}
