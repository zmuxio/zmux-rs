//! The peer against itself over QUIC, driven as the other implementations'
//! tests drive it: `server CERT KEY` with its `LISTEN` line, `client ADDR N`,
//! and the `STATS` lines of both. Both sides negotiate the datagram channel,
//! so every datagram counts on it.

use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};

const PEER: &str = env!("CARGO_BIN_EXE_zmux-datagram-peer");
const N: u64 = 20;

/// `(sent, sentch, recv, recvch)` of a `STATS` line.
fn counts(line: &str) -> [u64; 4] {
    let mut out = [0; 4];
    let fields = line
        .strip_prefix("STATS ")
        .unwrap_or_else(|| panic!("not a STATS line: {line:?}"));
    for (slot, (name, value)) in out.iter_mut().zip(
        fields
            .split(' ')
            .map(|f| f.split_once('=').expect("name=value")),
    ) {
        assert!(["sent", "sentch", "recv", "recvch"].contains(&name));
        *slot = value.parse().unwrap();
    }
    out
}

#[test]
fn a_client_gets_every_datagram_echoed_over_the_channel() {
    let dir = std::env::temp_dir().join(format!("zmux-datagram-peer-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let cert = zmux_testcert::self_signed(vec!["localhost".to_owned()]).unwrap();
    let (cert_path, key_path) = (dir.join("cert.pem"), dir.join("key.pem"));
    std::fs::write(&cert_path, cert.cert.pem()).unwrap();
    std::fs::write(&key_path, cert.signing_key.serialize_pem()).unwrap();

    let mut server = Command::new(PEER)
        .arg("server")
        .arg(&cert_path)
        .arg(&key_path)
        .stdout(Stdio::piped())
        .spawn()
        .expect("the server starts");
    let mut out = BufReader::new(server.stdout.take().unwrap());
    let mut listen = String::new();
    out.read_line(&mut listen).unwrap();
    let addr = listen
        .trim()
        .strip_prefix("LISTEN ")
        .unwrap_or_else(|| panic!("no LISTEN line: {listen:?}"))
        .to_owned();

    let client = Command::new(PEER)
        .args(["client", &addr, &N.to_string()])
        .output()
        .expect("the client runs");
    assert!(client.status.success(), "{client:?}");
    let client_stats = String::from_utf8(client.stdout).unwrap();
    let [sent, sentch, recv, recvch] = counts(client_stats.trim());
    assert_eq!((sent, recv), (N, N), "{client_stats}");
    assert_eq!((sentch, recvch), (N, N), "every datagram on the channel");

    // The server's session ends with the client's close.
    let mut stats = String::new();
    out.read_line(&mut stats).unwrap();
    assert!(server.wait().unwrap().success());
    let [sent, sentch, recv, recvch] = counts(stats.trim());
    assert_eq!((sent, sentch, recv, recvch), (N, N, N, N));
    std::fs::remove_dir_all(&dir).ok();
}
