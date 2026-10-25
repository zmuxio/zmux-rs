//! The vendored assets match the specification's manifest, so a partial or
//! stale sync fails here first.

use std::path::Path;

use sha2::{Digest, Sha256};

use crate::support::{read_json, spec_dir, to_hex};

/// Where the sync script puts each manifest file.
fn vendored(spec_path: &str) -> &str {
    match spec_path {
        "assets/registry.json" => "registry.json",
        "fixtures/profiles.json" => "profiles.json",
        "fixtures/wire/valid.ndjson" => "wire/valid.ndjson",
        "fixtures/wire/invalid.ndjson" => "wire/invalid.ndjson",
        "fixtures/traces/index.json" => "traces/index.json",
        "WIRE_EXAMPLES.md" => "WIRE_EXAMPLES.md",
        other => panic!("manifest lists an unknown file {other}"),
    }
}

fn sha256_hex(path: &Path) -> String {
    let bytes = std::fs::read(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    to_hex(&Sha256::digest(&bytes))
}

fn trace_files(dir: &Path, out: &mut Vec<Vec<String>>, prefix: &[String]) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        let mut parts = prefix.to_vec();
        parts.push(path.file_name().unwrap().to_string_lossy().into_owned());
        if path.is_dir() {
            trace_files(&path, out, &parts);
        } else if path.extension().is_some_and(|e| e == "ndjson") {
            out.push(parts);
        }
    }
}

#[test]
fn vendored_assets_match_the_manifest() {
    let manifest = read_json("manifest.json");
    for (file, sum) in manifest["sha256"].as_object().unwrap() {
        let got = sha256_hex(&spec_dir().join(vendored(file)));
        assert_eq!(
            Some(got.as_str()),
            sum.as_str(),
            "{file} differs from the manifest"
        );
    }
    // Python sorts the trace paths by their components.
    let mut files = Vec::new();
    trace_files(&spec_dir().join("traces"), &mut files, &[]);
    files.sort();
    let mut all = Sha256::new();
    for parts in &files {
        let path = parts
            .iter()
            .fold(spec_dir().join("traces"), |p, part| p.join(part));
        all.update(sha256_hex(&path).as_bytes());
    }
    assert_eq!(
        Some(to_hex(&all.finalize()).as_str()),
        manifest["traces_sha256"].as_str(),
        "trace files differ from the manifest"
    );
    let counts = &manifest["counts"];
    assert_eq!(counts["traces"].as_u64(), Some(files.len() as u64));
    eprintln!(
        "manifest: {} traces, {} valid and {} invalid corpus cases",
        files.len(),
        counts["wire_valid"],
        counts["wire_invalid"]
    );
}
