//! The exchange carrier's interop runner, a client or a server against
//! another implementation, configured by environment variables:
//!
//! - `ZMUX_EXCHANGE`: `server` or `client`.
//! - `ZMUX_EXCHANGE_PSK`: the pre-shared key in hex (empty by default).
//! - `ZMUX_EXCHANGE_BASE64=1`: base64 bodies.
//! - server: `ZMUX_EXCHANGE_ADDR` (default `127.0.0.1:8080`), the address
//!   to serve on, every POST path but `/zmux` (the streaming pipes) being
//!   an exchange request;
//!   `ZMUX_EXCHANGE_FOR` (seconds, default 60), how long to serve. Every
//!   stream of every session is echoed.
//! - client: `ZMUX_EXCHANGE_URL`, `http://host:port/path` where the path
//!   may hold `{instance}` and `{nonce}` (without `{nonce}` a query
//!   parameter `n` carries it); `ZMUX_EXCHANGE_DOWN_URL`, another target
//!   for DOWN requests (default the same); `ZMUX_EXCHANGE_BYTES` (default
//!   1 MiB), sent on one stream and checked by the hash of the echo.
//!
//! ```text
//! ZMUX_EXCHANGE=server ZMUX_EXCHANGE_ADDR=127.0.0.1:8080 \
//!     cargo run -p zmux-http --example exchange_interop
//! ZMUX_EXCHANGE=client ZMUX_EXCHANGE_URL='http://127.0.0.1:8080/x/{nonce}' \
//!     cargo run -p zmux-http --example exchange_interop
//! ```

use std::time::Duration;

use sha2::{Digest, Sha256};
use zmux::{Config, Listener, ListenerConfig, Session};
use zmux_http::{BodyEncoding, ExchangeEndpoint, ExchangeOptions, ExchangeServer, Options};

type Error = Box<dyn std::error::Error + Send + Sync>;

fn env(k: &str) -> Option<String> {
    std::env::var(k).ok().filter(|v| !v.is_empty())
}

fn options() -> Result<ExchangeOptions, Error> {
    let psk = env("ZMUX_EXCHANGE_PSK").unwrap_or_default();
    if !psk.len().is_multiple_of(2) {
        return Err("ZMUX_EXCHANGE_PSK: odd hex length".into());
    }
    let psk = (0..psk.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&psk[i..i + 2], 16))
        .collect::<Result<Vec<u8>, _>>()?;
    let mut o = ExchangeOptions::default().with_psk(psk);
    if env("ZMUX_EXCHANGE_BASE64").as_deref() == Some("1") {
        o = o.with_encoding(BodyEncoding::Base64);
    }
    Ok(o)
}

/// `http://host:port/path?query` as its authority and its target.
fn split_url(url: &str) -> Result<(String, String), Error> {
    let rest = url
        .strip_prefix("http://")
        .ok_or("only http:// URLs (TLS is the caller's)")?;
    let (host, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let host = if host.contains(':') {
        host.to_owned()
    } else {
        format!("{host}:80")
    };
    Ok((host, path.to_owned()))
}

async fn server(o: ExchangeOptions) -> Result<(), Error> {
    let addr = env("ZMUX_EXCHANGE_ADDR").unwrap_or_else(|| "127.0.0.1:8080".into());
    let secs: u64 = env("ZMUX_EXCHANGE_FOR").map_or(Ok(60), |s| s.trim_end_matches('s').parse())?;
    let listener = Listener::new(Config::default(), ListenerConfig::default());
    // Every path is an exchange path.
    let exchange = ExchangeServer::new(&listener, o.with_path("/"));
    let tcp = tokio::net::TcpListener::bind(&addr).await?;
    eprintln!("serving exchanges on {addr} for {secs} s");
    let serving = tokio::spawn(zmux_http::serve(
        listener.clone(),
        tcp,
        Options::default().with_exchange(exchange),
    ));
    let l = listener.clone();
    let echo = tokio::spawn(async move {
        while let Some(s) = l.accept().await {
            tokio::spawn(async move {
                while let Ok((mut send, mut recv)) = s.accept_bi().await {
                    tokio::spawn(async move {
                        let mut buf = vec![0u8; 64 << 10];
                        while let Ok(Some(n)) = recv.read(&mut buf).await {
                            if send.write_all(&buf[..n]).await.is_err() {
                                return;
                            }
                        }
                        let _ = send.finish();
                    });
                }
            });
        }
    });
    tokio::time::sleep(Duration::from_secs(secs)).await;
    listener.close();
    serving.await?;
    echo.await?;
    Ok(())
}

async fn client(o: ExchangeOptions) -> Result<(), Error> {
    let url = env("ZMUX_EXCHANGE_URL").ok_or("ZMUX_EXCHANGE_URL is not set")?;
    let (up_host, up_path) = split_url(&url)?;
    let (down_host, down_path) = match env("ZMUX_EXCHANGE_DOWN_URL") {
        Some(d) => split_url(&d)?,
        None => (up_host.clone(), up_path.clone()),
    };
    let n: usize = env("ZMUX_EXCHANGE_BYTES").map_or(Ok(1 << 20), |s| s.parse())?;
    let o = o.with_path(up_path).with_down_path(down_path);
    let pipe = zmux_http::dial_exchange_split(
        ExchangeEndpoint::tcp(&up_host),
        ExchangeEndpoint::tcp(&down_host),
        &o,
    );
    let session = Session::connect(pipe, Config::default()).await?;
    let mut msg = vec![0u8; n];
    getrandom::fill(&mut msg)?;
    let sent = Sha256::digest(&msg);
    let (mut send, mut recv) = session.open_bi().await?;
    let writer = tokio::spawn(async move {
        let r = send.write_all(&msg).await;
        let _ = send.finish();
        r.map(|_| send)
    });
    let got = recv.read_to_end(n + 1).await?;
    drop(writer.await?);
    if got.len() != n || Sha256::digest(&got) != sent {
        return Err(format!("echo: {} of {n} bytes, or a different hash", got.len()).into());
    }
    eprintln!("echoed {n} bytes");
    session.close(0u32.into(), b"done");
    let _ = tokio::time::timeout(Duration::from_secs(5), session.closed()).await;
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    let o = options()?;
    let run = async {
        match env("ZMUX_EXCHANGE").as_deref() {
            Some("server") => server(o).await,
            Some("client") => client(o).await,
            m => Err(format!("ZMUX_EXCHANGE={m:?}: want server or client").into()),
        }
    };
    // A hard bound on the whole run.
    tokio::time::timeout(Duration::from_secs(600), run)
        .await
        .map_err(|_| "timed out")?
}
