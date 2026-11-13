//! HTTP streaming peer for the Java HTTP interop test: `server|client|bad KIND ADDR`,
//! KIND `stream`, `split` (HTTP/1.1), `stream2`, `split2` (h2c).
//!
//! Prefix authentication key `right` (`bad` presents `wrong`), 30 s slots, skew 1.
//! `server` serves HTTP/1.1 and h2c on ADDR whatever KIND, prints `READY`, echoes one
//! stream per session (`SESSION <content>`) and answers other requests 418, printing
//! `FALLBACK <target>`. `client` prints `OK ping`; `bad` prints `REFUSED <error>`.

#[path = "../common.rs"]
mod common;

use std::sync::Arc;

use tokio::net::TcpListener;
use zmux_http::{Http2Connection, Options};

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    let (mode, kind, addr) = (args[1].as_str(), args[2].as_str(), args[3].as_str());
    match mode {
        "server" => server(addr).await,
        "client" | "bad" => client(kind, addr, if mode == "client" { b"right" } else { b"wrong" }).await,
        other => panic!("unknown mode {other}"),
    }
}

async fn server(addr: &str) {
    let fallback = zmux_http::Fallback::new(|req: zmux_http::FallbackRequest, _| async move {
        let target = req.uri().path().to_string();
        println!("FALLBACK {target}");
        let mut resp = http::Response::new(zmux_http::PipeBody::full(format!("fallback {target}")));
        *resp.status_mut() = http::StatusCode::IM_A_TEAPOT;
        resp
    });
    let listener = common::listener(b"right", None);
    let tcp = TcpListener::bind(addr).await.expect("bind");
    tokio::spawn(zmux_http::serve(
        listener.clone(),
        tcp,
        Options::default().with_fallback(fallback),
    ));
    println!("READY");
    common::serve_sessions(listener).await;
}

async fn client(kind: &str, addr: &str, key: &[u8]) {
    let options = Options::default().with_carrier_credential(Arc::new(common::auth(key)));
    let config = zmux::Config::default();
    let session = match kind {
        "stream" => zmux_http::connect_http1(addr, &options, config).await,
        "split" => zmux_http::connect_http1_split(addr, &options, config).await,
        "stream2" | "split2" => match Http2Connection::connect(addr, options).await {
            Ok(h2) if kind == "stream2" => h2.connect_session(config).await,
            Ok(h2) => h2.connect_split_session(config).await,
            Err(e) => {
                println!("REFUSED {e}");
                return;
            }
        },
        other => panic!("unknown kind {other}"),
    };
    let session = match session {
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
