//! A scripted plain QMux peer built on the `qmux` crate (QMux draft-02),
//! for interoperability tests over TCP. The protocol it speaks is described
//! in README.md.

use std::process::exit;
use std::time::Duration;

use bytes::Bytes;
use tokio::net::{TcpListener, TcpStream};
use web_transport_trait::{RecvStream as _, SendStream as _, Session as _, Stats as _};

type Session = qmux::Session;
type Send = qmux::SendStream;
type Recv = qmux::RecvStream;

const MAX_COMMAND: usize = 1024;

fn usage() -> ! {
    eprintln!("usage: qmux-peer server|client <addr> [--rtt-ms <ms>] [--no-datagrams]");
    exit(2)
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() < 2 {
        usage();
    }
    let server = match args[0].as_str() {
        "server" => true,
        "client" => false,
        _ => usage(),
    };
    let addr = &args[1];
    let mut config = qmux::Config::new(qmux::Version::QMux02);
    let mut i = 2;
    while i < args.len() {
        match args[i].as_str() {
            "--rtt-ms" if i + 1 < args.len() => {
                let ms: u64 = args[i + 1].parse().unwrap_or_else(|_| usage());
                config.rtt_interval = Duration::from_millis(ms);
                i += 2;
            }
            "--no-datagrams" => {
                config.max_datagram_frame_size = 0;
                i += 1;
            }
            _ => usage(),
        }
    }

    let tcp = if server {
        let listener = TcpListener::bind(addr).await.expect("bind");
        println!("LISTEN {}", listener.local_addr().expect("local address"));
        listener.accept().await.expect("accept").0
    } else {
        TcpStream::connect(addr).await.expect("connect")
    };
    let _ = tcp.set_nodelay(true);
    let transport = qmux::transport::Stream::new(tcp, config.version, config.max_record_size);
    let session = if server {
        Session::accept(transport, config).await
    } else {
        Session::connect(transport, config).await
    };
    let session = match session {
        Ok(s) => s,
        Err(e) => {
            println!("CLOSED handshake {e}");
            exit(1);
        }
    };
    println!("ESTABLISHED");

    let bi = {
        let session = session.clone();
        tokio::spawn(async move {
            while let Ok((send, recv)) = session.accept_bi().await {
                tokio::spawn(bidi(session.clone(), send, recv));
            }
        })
    };
    let uni = {
        let session = session.clone();
        tokio::spawn(async move {
            while let Ok(recv) = session.accept_uni().await {
                tokio::spawn(uni(session.clone(), recv));
            }
        })
    };
    let dgram = {
        let session = session.clone();
        tokio::spawn(async move {
            while let Ok(d) = session.recv_datagram().await {
                let _ = session.send_datagram(d);
            }
        })
    };
    let err = session.closed().await;
    println!("RTT {}", rtt(&session));
    println!("CLOSED {}", describe(&err));
    for t in [bi, uni, dgram] {
        t.abort();
    }
}

fn rtt(session: &Session) -> String {
    match session.stats().rtt() {
        Some(d) => d.as_micros().to_string(),
        None => "none".to_string(),
    }
}

fn describe(err: &qmux::Error) -> String {
    match err {
        qmux::Error::ConnectionClosed { code, reason } => format!("app {} {}", code.into_inner(), reason),
        qmux::Error::ConnectionReset { code, reason } => {
            format!("transport {} {}", code.into_inner(), reason)
        }
        other => format!("other {other}"),
    }
}

/// The full 62-bit code of a stream reset or stop, which the trait API would
/// narrow to u32.
fn stream_code(err: &qmux::Error) -> String {
    match err {
        qmux::Error::StreamReset(code) | qmux::Error::StreamStop(code) => code.into_inner().to_string(),
        other => format!("error({other})"),
    }
}

/// Sends `text` on a new unidirectional stream.
async fn report(session: &Session, text: String) {
    if let Ok(mut s) = session.open_uni().await {
        if s.write_all(text.as_bytes()).await.is_ok() && s.finish().is_ok() {
            let _ = s.closed().await;
        }
    }
}

async fn reply(send: &mut Send, text: &str) {
    if send.write_all(text.as_bytes()).await.is_ok() && send.finish().is_ok() {
        let _ = send.closed().await;
    }
}

/// Reads until FIN, discarding; reports a reset.
async fn drain(session: &Session, recv: &mut Recv) -> bool {
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        match recv.read(&mut buf).await {
            Ok(Some(n)) if n > 0 => {}
            Ok(_) => return true,
            Err(e) => {
                report(session, format!("reset:{}", stream_code(&e))).await;
                return false;
            }
        }
    }
}

async fn bidi(session: Session, mut send: Send, mut recv: Recv) {
    // The command is the first line; what follows it is the payload.
    let mut acc = Vec::new();
    let mut buf = vec![0u8; 64 * 1024];
    let mut fin = false;
    let newline = loop {
        if let Some(p) = acc.iter().position(|&b| b == b'\n') {
            break Some(p);
        }
        if acc.len() > MAX_COMMAND {
            break None;
        }
        match recv.read(&mut buf).await {
            Ok(Some(n)) if n > 0 => acc.extend_from_slice(&buf[..n]),
            Ok(_) => {
                fin = true;
                break None;
            }
            Err(e) => {
                report(&session, format!("reset:{}", stream_code(&e))).await;
                return;
            }
        }
    };
    let (command, rest) = match newline {
        Some(p) => (String::from_utf8_lossy(&acc[..p]).to_string(), acc[p + 1..].to_vec()),
        None => (String::from_utf8_lossy(&acc).to_string(), Vec::new()),
    };
    let (verb, arg) = match command.split_once(':') {
        Some((v, a)) => (v.to_string(), a.to_string()),
        None => (command.clone(), String::new()),
    };

    if verb == "echo" {
        if send.write_all(&rest).await.is_err() {
            return;
        }
        if !fin {
            loop {
                match recv.read(&mut buf).await {
                    Ok(Some(n)) if n > 0 => {
                        if send.write_all(&buf[..n]).await.is_err() {
                            return;
                        }
                    }
                    Ok(_) => break,
                    Err(e) => {
                        report(&session, format!("reset:{}", stream_code(&e))).await;
                        return;
                    }
                }
            }
        }
        if send.finish().is_ok() {
            let _ = send.closed().await;
        }
        return;
    }
    if verb == "count" {
        // Counts the bytes after the command line; a reset is reported with
        // the count delivered before it.
        let mut n = rest.len() as u64;
        if !fin {
            loop {
                match recv.read(&mut buf).await {
                    Ok(Some(k)) if k > 0 => n += k as u64,
                    Ok(_) => break,
                    Err(e) => {
                        report(&session, format!("reset:{}:{n}", stream_code(&e))).await;
                        return;
                    }
                }
            }
        }
        reply(&mut send, &format!("count={n}")).await;
        return;
    }
    if verb == "stop" {
        // STOP_SENDING towards the opener, with the given code.
        let code: u32 = arg.parse().unwrap_or(0);
        recv.stop(code);
        reply(&mut send, "stopped").await;
        return;
    }
    if !fin && !drain(&session, &mut recv).await {
        return;
    }
    match verb.as_str() {
        "flood" => {
            // Write until the opener's STOP_SENDING arrives.
            let chunk = vec![b'x'; 1024];
            let err = loop {
                if let Err(e) = send.write_all(&chunk).await {
                    break e;
                }
                tokio::time::sleep(Duration::from_millis(1)).await;
            };
            report(&session, format!("stopped:{}", stream_code(&err))).await;
        }
        "reset" => {
            let code: u32 = arg.parse().unwrap_or(0);
            let _ = send.write_all(&[7u8; 1000]).await;
            tokio::time::sleep(Duration::from_millis(20)).await;
            send.reset(code);
        }
        "open-bidi" => {
            let answer = async {
                let (mut s, mut r) = session.open_bi().await.ok()?;
                s.write_all(arg.as_bytes()).await.ok()?;
                s.finish().ok()?;
                r.read_all().await.ok()
            }
            .await;
            match answer {
                Some(a) => reply(&mut send, &format!("opened={}", String::from_utf8_lossy(&a))).await,
                None => reply(&mut send, "opened-failed").await,
            }
        }
        "open-uni" => {
            report(&session, arg).await;
            reply(&mut send, "sent").await;
        }
        "rtt" => reply(&mut send, &format!("rtt={}", rtt(&session))).await,
        "datagram-size" => {
            reply(&mut send, &format!("max={}", session.max_datagram_size())).await;
        }
        "close" => {
            let (code, reason) = arg.split_once(':').unwrap_or((arg.as_str(), ""));
            let code: u32 = code.parse().unwrap_or(0);
            reply(&mut send, "closing").await;
            tokio::time::sleep(Duration::from_millis(50)).await;
            session.close(code, reason);
        }
        _ => reply(&mut send, &format!("unknown={command}")).await,
    }
}

async fn uni(session: Session, mut recv: Recv) {
    match recv.read_all().await {
        Ok(data) => {
            if let Ok(mut s) = session.open_uni().await {
                if s.write_chunk(Bytes::from(data.to_vec())).await.is_ok() && s.finish().is_ok() {
                    let _ = s.closed().await;
                }
            }
        }
        Err(e) => report(&session, format!("reset:{}", stream_code(&e))).await,
    }
}
