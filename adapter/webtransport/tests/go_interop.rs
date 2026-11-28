//! Run both directions with interop/webtransport/run.sh.
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use tokio::io::{AsyncBufReadExt as _, BufReader};
use tokio::process::Command;
use zmux_webtransport::{self as wt, Options, Url};

#[allow(dead_code, reason = "only the loopback endpoint is needed here")]
mod common;

fn peer() -> Command {
    let mut command =
        Command::new(std::env::var_os("ZMUX_WT_GO_PEER").expect("build the Go peer with run.sh"));
    command.kill_on_drop(true);
    command
}

#[tokio::test]
#[ignore = "requires the external zmux-go peer"]
async fn go_client_rust_server() {
    for id in [0, 4] {
        tokio::time::timeout(Duration::from_secs(10), async {
            let fixture = common::Wt::new(&Options::default());
            let child = peer()
                .args(["client", fixture.url.as_str(), &id.to_string()])
                .spawn()
                .unwrap();
            let incoming = fixture
                .server
                .as_ref()
                .unwrap()
                .accept()
                .await
                .unwrap()
                .await
                .unwrap();
            let request = wt::Request::accept(incoming).await.unwrap();
            assert_eq!(request.id(), id);
            let session = request.ok().await.unwrap();
            exchange(&session, false).await.unwrap();
            assert_eq!(
                session.closed().await,
                wt::SessionEnd::Closed {
                    code: 42,
                    reason: "done".into(),
                    remote: true,
                }
            );
            let mut child = child;
            assert!(child.wait().await.unwrap().success());
            eprintln!(
                "Go client / Rust server, CONNECT ID {id}: bidi, uni and native datagrams both ways"
            );
        })
        .await
        .unwrap_or_else(|_| panic!("Go client timed out at CONNECT ID {id}"));
    }
}

#[tokio::test]
#[ignore = "requires the external zmux-go peer"]
async fn rust_client_go_server() {
    for id in [0, 4] {
        tokio::time::timeout(Duration::from_secs(10), async {
            let mut child = peer().arg("server").stdout(Stdio::piped()).spawn().unwrap();
            let mut ready = BufReader::new(child.stdout.take().unwrap()).lines();
            let url: Url = ready.next_line().await.unwrap().unwrap().parse().unwrap();
            let certificate = ready.next_line().await.unwrap().unwrap();
            let der = certificate
                .as_bytes()
                .chunks(2)
                .map(|chunk| u8::from_str_radix(std::str::from_utf8(chunk).unwrap(), 16))
                .collect::<Result<Vec<_>, _>>()
                .unwrap();
            let tls = common::tls::client_for(der.into(), vec![wt::ALPN.as_bytes().to_vec()]);
            let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls).unwrap();
            let mut config = quinn::ClientConfig::new(Arc::new(crypto));
            config.transport_config(Arc::new(Options::default().transport_config()));
            let endpoint = quinn::Endpoint::client((Ipv4Addr::LOCALHOST, 0).into()).unwrap();
            let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, url.port().unwrap()));
            let conn = endpoint
                .connect_with(config, addr, url.host_str().unwrap())
                .unwrap()
                .await
                .unwrap();
            let _reserved = if id == 0 {
                None
            } else {
                Some(conn.open_bi().await.unwrap())
            };
            let session = wt::Session::connect(conn, url).await.unwrap();
            assert_eq!(session.id(), id);
            exchange(&session, true).await.unwrap();
            session.close(42, b"done");
            let _ = session.closed().await;
            endpoint.wait_idle().await;
            assert!(child.wait().await.unwrap().success());
            eprintln!(
                "Rust client / Go server, CONNECT ID {id}: bidi, uni and native datagrams both ways"
            );
        })
        .await
        .unwrap_or_else(|_| panic!("Rust client timed out at CONNECT ID {id}"));
    }
}

async fn exchange(session: &wt::Session, client: bool) -> io::Result<()> {
    for (from_client, prefix) in [(true, "client"), (false, "server")] {
        let pipe = format!("{prefix}-pipe");
        let lane = format!("{prefix}-lane");
        let datagram = format!("{prefix}-datagram");
        if client == from_client {
            let (send, recv) = session.open_bi().await?;
            write_fin(send, &pipe).await?;
            read_fin(recv, &pipe).await?;
            write_fin(session.open_uni().await?, &lane).await?;
            session.send_datagram_wait(Bytes::from(datagram)).await?;
        } else {
            let (send, recv) = session.accept_bi().await?;
            read_fin(recv, &pipe).await?;
            write_fin(send, &pipe).await?;
            read_fin(session.accept_uni().await?, &lane).await?;
            assert_eq!(session.read_datagram().await?, datagram.as_bytes());
        }
    }
    Ok(())
}

async fn write_fin(mut stream: wt::SendStream, text: &str) -> io::Result<()> {
    stream.write_all(text.as_bytes()).await?;
    Ok(stream.finish()?)
}

async fn read_fin(mut stream: wt::RecvStream, text: &str) -> io::Result<()> {
    assert_eq!(
        stream
            .read_to_end(text.len() + 1)
            .await
            .map_err(io::Error::other)?,
        text.as_bytes()
    );
    Ok(())
}
