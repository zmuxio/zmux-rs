//! A scripted zmux responder for interoperability tests with the other
//! zmux implementations (Java, Go) over TCP.
//!
//! Usage: `zmux-interop-peer server [addr]` (prints `LISTEN <addr>`, serves
//! one session) or `zmux-interop-peer client <addr>`.
//!
//! The peer under test drives; this side answers. A bidirectional stream
//! carries its command in the stream preamble (OPEN_INFO):
//!
//! - `echo`: echo the data, then FIN;
//! - `info`: reply with `info=<open info>;prio=<u>,<i>` (the PRIORITY TLV);
//! - `reset`: read until the peer's reset and reply `reset=<code>`;
//! - `stop:<code>`: stop reading with `code`, then reply `stopped`;
//! - `sendreset:<code>`: write 1000 bytes, then reset with `code`;
//! - `open-bidi:<text>`: open a bidirectional stream with OPEN_INFO `back`,
//!   write `<text>`, FIN, read the answer and reply `opened=<answer>`;
//! - `open-uni:<text>`: open a unidirectional stream carrying `<text>`;
//! - `dgram`: echo the stream's datagrams (context + 1) until FIN;
//! - `goaway:<code>`: start a graceful shutdown with `code`; reply `draining`;
//! - `close:<code>:<reason>`: reply `closing`, then close the session.
//!
//! Unidirectional streams are echoed on a new unidirectional stream, and
//! session datagrams are echoed. The process exits when the session ends and
//! prints `CLOSED <reason>`.

use std::time::Duration;

use bytes::Bytes;
use tokio::net::{TcpListener, TcpStream};
use zmux::{Config, Preamble, RecvStream, SendStream, Session, StreamError, VarInt};

fn config() -> Config {
    let mut c = Config::default();
    c.enable_datagrams = true;
    c.max_incoming_uni_streams = Some(16);
    c
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mode = args.get(1).map(String::as_str).unwrap_or("server");
    let session = match mode {
        "server" => {
            let addr = args.get(2).map(String::as_str).unwrap_or("127.0.0.1:0");
            let listener = TcpListener::bind(addr).await.expect("bind");
            println!("LISTEN {}", listener.local_addr().expect("addr"));
            let (tcp, _) = listener.accept().await.expect("accept");
            Session::accept(zmux::PipeIo::tcp(tcp), config())
                .await
                .expect("establish")
        }
        "client" => {
            let addr = args.get(2).expect("address");
            let tcp = TcpStream::connect(addr).await.expect("connect");
            Session::connect(zmux::PipeIo::tcp(tcp), config())
                .await
                .expect("establish")
        }
        other => panic!("unknown mode {other}"),
    };
    println!("ESTABLISHED");
    {
        let s = session.clone();
        tokio::spawn(async move {
            while let Ok((send, recv)) = s.accept_bi().await {
                let s = s.clone();
                tokio::spawn(async move { bidi(s, send, recv).await });
            }
        });
    }
    {
        let s = session.clone();
        tokio::spawn(async move {
            while let Ok(mut recv) = s.accept_uni().await {
                let s = s.clone();
                tokio::spawn(async move {
                    if let Ok(data) = recv.read_to_end(1 << 24).await
                        && let Ok(mut send) = s.open_uni().await
                    {
                        let _ = send.write_all(&data).await;
                        let _ = send.finish();
                        let _ = send.stopped().await;
                    }
                });
            }
        });
    }
    {
        let s = session.clone();
        tokio::spawn(async move {
            while let Ok(d) = s.read_datagram().await {
                let _ = s.send_datagram(d);
            }
        });
    }
    let reason = session.closed().await;
    println!("CLOSED {reason}");
}

async fn reply(send: &mut SendStream, text: &str) {
    let _ = send.write_all(text.as_bytes()).await;
    let _ = send.finish();
    let _ = send.stopped().await;
}

async fn bidi(session: Session, mut send: SendStream, mut recv: RecvStream) {
    let cmd = recv
        .preamble()
        .info()
        .map(|b| String::from_utf8_lossy(b).into_owned())
        .unwrap_or_default();
    let (name, arg) = cmd.split_once(':').unwrap_or((cmd.as_str(), ""));
    match name {
        "echo" => {
            let mut buf = vec![0u8; 64 * 1024];
            loop {
                match recv.read(&mut buf).await {
                    Ok(Some(n)) => {
                        if send.write_all(&buf[..n]).await.is_err() {
                            return;
                        }
                    }
                    Ok(None) => break,
                    Err(_) => return,
                }
            }
            let _ = send.finish();
            let _ = send.stopped().await;
        }
        "info" => {
            let prio = recv
                .requested_priority()
                .map(|p| format!("{},{}", p.urgency(), p.incremental()))
                .unwrap_or_else(|| "none".into());
            let _ = recv.read_to_end(1 << 20).await;
            reply(&mut send, &format!("info={cmd};prio={prio}")).await;
        }
        "reset" => {
            let mut buf = vec![0u8; 4096];
            let text = loop {
                match recv.read(&mut buf).await {
                    Ok(Some(_)) => continue,
                    Ok(None) => break "fin".to_string(),
                    Err(StreamError::Reset { code, .. }) => break format!("reset={code}"),
                    Err(e) => break format!("error={e}"),
                }
            };
            reply(&mut send, &text).await;
        }
        "stop" => {
            let code: u64 = arg.parse().unwrap_or(0);
            let _ = recv.stop(VarInt::from_u64(code).unwrap_or(VarInt::ZERO));
            reply(&mut send, "stopped").await;
        }
        "sendreset" => {
            let code: u64 = arg.parse().unwrap_or(0);
            let _ = send.write_all(&[7u8; 1000]).await;
            tokio::time::sleep(Duration::from_millis(20)).await;
            let _ = send.reset(VarInt::from_u64(code).unwrap_or(VarInt::ZERO));
            let _ = recv.read_to_end(1 << 20).await;
        }
        "open-bidi" => {
            let text = match session
                .open_bi_with(&Preamble::new().with_info(Bytes::from_static(b"back")))
                .await
            {
                Ok((mut s2, mut r2)) => {
                    let _ = s2.write_all(arg.as_bytes()).await;
                    let _ = s2.finish();
                    match r2.read_to_end(1 << 20).await {
                        Ok(d) => format!("opened={}", String::from_utf8_lossy(&d)),
                        Err(e) => format!("error={e}"),
                    }
                }
                Err(e) => format!("error={e}"),
            };
            reply(&mut send, &text).await;
        }
        "open-uni" => {
            if let Ok(mut s2) = session.open_uni().await {
                let _ = s2.write_all(arg.as_bytes()).await;
                let _ = s2.finish();
                let _ = s2.stopped().await;
            }
            reply(&mut send, "sent").await;
        }
        "dgram" => {
            // Echoes `arg` stream datagrams (context + 1), then answers.
            let n: u64 = arg.parse().unwrap_or(1);
            for _ in 0..n {
                match recv.read_datagram().await {
                    Ok((ctx, d)) => {
                        if send.send_datagram(ctx + 1, d).is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
            let _ = recv.read_to_end(1 << 20).await;
            reply(&mut send, "dgram-done").await;
        }
        "goaway" => {
            let code: u64 = arg.parse().unwrap_or(0);
            let s = session.clone();
            tokio::spawn(async move {
                let _ = s
                    .shutdown(VarInt::from_u64(code).unwrap_or(VarInt::ZERO), b"drain")
                    .await;
            });
            let _ = recv.read_to_end(1 << 20).await;
            reply(&mut send, "draining").await;
        }
        "close" => {
            let (code, reason) = arg.split_once(':').unwrap_or((arg, ""));
            let code: u64 = code.parse().unwrap_or(0);
            let _ = recv.read_to_end(1 << 20).await;
            let _ = send.write_all(b"closing").await;
            let _ = send.finish();
            tokio::time::sleep(Duration::from_millis(50)).await;
            session.close(
                VarInt::from_u64(code).unwrap_or(VarInt::ZERO),
                reason.as_bytes(),
            );
        }
        other => {
            reply(&mut send, &format!("unknown={other}")).await;
        }
    }
}
