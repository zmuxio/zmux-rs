use std::io::ErrorKind;
use std::path::Path;

/// Read a development fixture, reporting a skip only when the file is missing.
pub(crate) fn read_fixture(path: &Path) -> Option<Vec<u8>> {
    match std::fs::read(path) {
        Ok(bytes) => Some(bytes),
        Err(err) if err.kind() == ErrorKind::NotFound => {
            eprintln!("skipped: shaping fixture {} is missing", path.display());
            None
        }
        Err(err) => panic!("cannot read shaping fixture {}: {err}", path.display()),
    }
}
