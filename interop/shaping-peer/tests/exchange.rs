//! The peer against itself, driven as the other implementations' tests drive
//! it: a server process, its `LISTEN` line, a client process, and the exit
//! status and `OK` line of both, for every combination of shaped and
//! unshaped sides and each definition in `defs/`.

use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};

const PEER: &str = env!("CARGO_BIN_EXE_zmux-shaping-peer");

fn definition(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("defs")
        .join(format!("{name}.json"))
}

fn start(mode: &[&str], shaped: Option<&PathBuf>) -> Child {
    let mut c = Command::new(PEER);
    c.args(mode).stdout(Stdio::piped()).stderr(Stdio::inherit());
    match shaped {
        Some(path) => c.env("SHAPE_DEF", path),
        None => c.env_remove("SHAPE_DEF"),
    };
    c.spawn().expect("the peer starts")
}

/// The lines a process printed, once it exited with status 0.
fn lines(mut child: Child, first: Option<String>) -> Vec<String> {
    let out = BufReader::new(child.stdout.take().unwrap());
    let mut lines: Vec<String> = first.into_iter().collect();
    lines.extend(out.lines().map(Result::unwrap));
    let status = child.wait().unwrap();
    assert!(status.success(), "{status}: {lines:?}");
    lines
}

fn run(def: &str, server_shaped: bool, client_shaped: bool) {
    let path = definition(def);
    let mut server = start(&["server"], server_shaped.then_some(&path));
    let mut out = BufReader::new(server.stdout.take().unwrap());
    let mut listen = String::new();
    out.read_line(&mut listen).unwrap();
    let addr = listen
        .trim()
        .strip_prefix("LISTEN ")
        .unwrap_or_else(|| panic!("no LISTEN line: {listen:?}"))
        .to_owned();
    server.stdout = Some(out.into_inner());
    let client = start(&["client", &addr], client_shaped.then_some(&path));
    let client = lines(client, None);
    let server = lines(server, None);
    let what = format!("{def} server shaped {server_shaped} client shaped {client_shaped}");
    for (side, out, shaped) in [
        ("client", &client, client_shaped),
        ("server", &server, server_shaped),
    ] {
        assert_eq!(out.last().map(String::as_str), Some("OK"), "{what}: {side}");
        let stats = out
            .iter()
            .find(|l| l.starts_with("STATS wire_spent="))
            .unwrap_or_else(|| panic!("{what}: {side} printed no STATS: {out:?}"));
        let spent: u64 = stats["STATS wire_spent=".len()..]
            .split(' ')
            .next()
            .unwrap()
            .parse()
            .unwrap();
        assert_eq!(spent > 0, shaped, "{what}: {side}: {stats}");
    }
}

#[test]
fn every_combination_of_shaped_sides_echoes_every_stream() {
    for def in ["records", "delayed"] {
        for server_shaped in [false, true] {
            for client_shaped in [false, true] {
                run(def, server_shaped, client_shaped);
            }
        }
    }
}
