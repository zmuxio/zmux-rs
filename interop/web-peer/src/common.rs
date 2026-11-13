//! What the WebSocket and the HTTP peer share: the session script.

use std::sync::Arc;
use std::time::Duration;

use zmux::{Listener, Session};

/// The key of the prefix authentication tokens of the peer in `key`, 30 s slots.
pub fn auth(key: &[u8]) -> zmux::PrefixAuth {
    zmux::PrefixAuth::new(key, Duration::from_secs(30), false).expect("prefix auth")
}

/// A listener that admits only tokens of `auth`, one slot of skew.
pub fn listener(key: &[u8], fallback: Option<zmux::Fallback>) -> Listener {
    let verifier = Arc::new(zmux::PrefixAuthVerifier::new(auth(key), 1, 1 << 16));
    let mut limits = zmux::ListenerConfig::default();
    limits.admission = Some(zmux::Admission::prefix_auth(verifier));
    limits.fallback = fallback;
    Listener::new(zmux::Config::default(), limits).expect("valid listener configuration")
}

/// Echoes one stream of `session`, printing `SESSION <content>`.
pub async fn echo_one(session: Session) {
    let Ok((mut send, mut recv)) = session.accept_bi().await else {
        return;
    };
    let Ok(data) = recv.read_to_end(1 << 20).await else {
        return;
    };
    println!("SESSION {}", String::from_utf8_lossy(&data));
    if send.write_all(&data).await.is_ok() {
        let _ = send.finish();
    }
    // The client closes after reading the echo.
    let _ = tokio::time::timeout(Duration::from_secs(10), session.wait()).await;
}

/// Serves every session of `listener` until the process is killed.
pub async fn serve_sessions(listener: Listener) {
    while let Some(session) = listener.accept().await {
        tokio::spawn(echo_one(session));
    }
}

/// Sends `ping` on a stream of `session` and reads the echo.
pub async fn ping(session: &Session) -> Result<String, String> {
    let (mut send, mut recv) = session.open_bi().await.map_err(|e| e.to_string())?;
    send.write_all(b"ping").await.map_err(|e| e.to_string())?;
    send.finish().map_err(|e| e.to_string())?;
    let got = recv.read_to_end(1 << 16).await.map_err(|e| e.to_string())?;
    Ok(String::from_utf8_lossy(&got).into_owned())
}
