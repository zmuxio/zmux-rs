//! Run both directions with interop/webtransport/run.sh.
use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};
use std::time::Duration;

use zmux_webtransport::{Options, Url};

#[allow(dead_code, reason = "only the loopback endpoint is needed here")]
mod common;

fn peer() -> Command {
    Command::new(std::env::var_os("ZMUX_WT_GO_PEER").expect("build the Go peer with run.sh"))
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires the external zmux-go peer"]
async fn go_client_rust_server() {
    let mut wt = common::Wt::new(&Options::default());
    let mut config = zmux::ListenerConfig::default();
    config.admission = Some(zmux::Admission::new(1, |info, _| {
        if info.is_head() {
            zmux::AdmissionVerdict::Defer
        } else {
            zmux::AdmissionVerdict::takeover()
        }
    }));
    config.fallback = Some(zmux::Fallback::new(|takeover| async move {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let session = zmux_webtransport::takeover_session(&takeover).unwrap();
        let mut stream = takeover.into_stream().unwrap();
        let mut data = Vec::new();
        stream.read_to_end(&mut data).await.unwrap();
        assert_eq!(data, b"ping");
        stream.write_all(&data).await.unwrap();
        stream.shutdown().await.unwrap();
        let _ = session.closed().await;
    }));
    let listener = zmux::Listener::new(zmux::Config::default(), config).unwrap();
    let server = tokio::spawn(zmux_webtransport::serve(
        listener.clone(),
        (*wt.server.take().unwrap()).clone(),
        Options::default(),
    ));
    let url = wt.url.to_string();
    let output = tokio::task::spawn_blocking(move || peer().arg(url).output().unwrap())
        .await
        .unwrap();
    listener.close();
    server.await.unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(listener.stats().admission.takeover, 1);
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires the external zmux-go peer"]
async fn rust_client_go_server() {
    let mut child = peer().stdout(Stdio::piped()).spawn().unwrap();
    let mut ready = String::new();
    BufReader::new(child.stdout.take().unwrap())
        .read_line(&mut ready)
        .unwrap();
    let result = tokio::time::timeout(Duration::from_secs(8), async {
        let url: Url = ready.trim().parse()?;
        let client = web_transport_quinn::ClientBuilder::new()
            .dangerous()
            .with_no_certificate_verification()?;
        let session = client.connect(url).await?;
        let (mut send, mut recv) = session.open_bi().await?;
        send.write_all(b"ping").await?;
        send.finish()?;
        assert_eq!(recv.read_to_end(4).await?, b"ping");
        Ok::<_, Box<dyn std::error::Error>>(())
    })
    .await;
    let _ = child.kill();
    child.wait().unwrap();
    result.unwrap().unwrap();
}
