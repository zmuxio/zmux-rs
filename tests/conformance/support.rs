//! Paths and small helpers shared by the conformance tests.

use std::path::{Path, PathBuf};

/// The vendored specification assets (`tools/sync-spec-fixtures.sh`), or
/// the directory `ZMUX_SPEC_FIXTURES` names (a preview of unreleased
/// specification assets laid out the same way).
pub fn spec_dir() -> PathBuf {
    std::env::var_os("ZMUX_SPEC_FIXTURES").map_or_else(
        || Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata/spec"),
        PathBuf::from,
    )
}

pub fn read(rel: &str) -> String {
    let path = spec_dir().join(rel);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

pub fn read_json(rel: &str) -> serde_json::Value {
    serde_json::from_str(&read(rel)).unwrap_or_else(|e| panic!("{rel}: {e}"))
}

/// Parses every line of an NDJSON file.
pub fn read_ndjson(rel: &str) -> Vec<serde_json::Value> {
    read(rel)
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).unwrap_or_else(|e| panic!("{rel}: {e}")))
        .collect()
}

pub fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn from_hex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

pub fn hex(s: &str) -> Vec<u8> {
    from_hex(s).unwrap_or_else(|| panic!("invalid hex {s:?}"))
}
