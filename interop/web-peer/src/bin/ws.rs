//! WebSocket peer for the Java HTTP interop test: `server|client|bad ADDR`.
//!
//! Prefix authentication key `ws-interop`, 30 s slots, skew 1, token in the
//! upgrade request's header field. `server` prints `READY`, echoes one stream
//! per session (`SESSION <content>`) and answers refused requests 418, printing
//! `FALLBACK <target>`. `client` prints `OK ping`; `bad` (no token) prints
//! `REFUSED <error>`.

#[path = "../common.rs"]
mod common;

use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

const KEY: &[u8] = b"ws-interop";

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    let (mode, addr) = (args[1].as_str(), args[2].as_str());
    match mode {
        "server" => server(addr).await,
        "client" | "bad" => client(addr, mode == "client").await,
        other => panic!("unknown mode {other}"),
    }
}

async fn server(addr: &str) {
    let fallback = zmux::Fallback::new(|mut conn, _| async move {
        let mut head = Vec::new();
        let mut b = [0u8; 1024];
        while !head.windows(4).any(|w| w == b"\r\n\r\n") {
            match conn.read(&mut b).await {
                Ok(0) | Err(_) => break,
                Ok(n) => head.extend_from_slice(&b[..n]),
            }
        }
        let line = String::from_utf8_lossy(&head);
        let target = line.split_whitespace().nth(1).unwrap_or("").to_string();
        println!("FALLBACK {target}");
        let body = format!("fallback {target}");
        let resp = format!(
            "HTTP/1.1 418 I'm a teapot\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        let _ = conn.write_all(resp.as_bytes()).await;
        let _ = conn.shutdown().await;
    });
    let listener = common::listener(KEY, Some(fallback));
    let tcp = TcpListener::bind(addr).await.expect("bind");
    tokio::spawn(zmux_websocket::serve(
        listener.clone(),
        tcp,
        Default::default(),
    ));
    println!("READY");
    common::serve_sessions(listener).await;
}

async fn client(addr: &str, authed: bool) {
    let mut options = zmux_websocket::Options::default();
    if authed {
        options = options.with_carrier_credential(Arc::new(common::auth(KEY)));
    }
    let url = format!("ws://{addr}/zmux");
    let session = match zmux_websocket::connect(url.as_str(), &options, zmux::Config::default()).await {
        Ok(s) => s,
        Err(e) => {
            println!("REFUSED {e}");
            return;
        }
    };
    match common::ping(&session).await {
        Ok(got) => println!("OK {got}"),
        Err(e) => println!("REFUSED {e}"),
    }
    session.close().await;
}
