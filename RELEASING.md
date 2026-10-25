# Releasing

This document is for maintainers. User installation instructions belong in `README.md`.

Published crates, all with one version (major 1, in lockstep):

- `zmux` (the core)
- `zmux-rustls`, `zmux-quinn`, `zmux-websocket`, `zmux-http`, `zmux-h3`, `zmux-webtransport` (carrier adapters)

Releases are automated from tag `vX.Y.Z` (`.github/workflows/release.yml`). The workflow:

1. checks that every publishable workspace crate has version `X.Y.Z` with major 1, that each depends on the others with
   exactly that version, and that the tag is `vX.Y.Z`;
2. runs formatting, clippy, the tests and the docs;
3. skips the crates whose `X.Y.Z` is already on crates.io, dry-runs all the others together, then publishes them one
   at a time in dependency order (the core first), waiting until each is visible on crates.io before the next.

A run that failed after some crates were published can be repeated from the same tag: the published ones are skipped.
crates.io versions are immutable after publication. The repository secret `CARGO_REGISTRY_TOKEN` must be set.

## Version rules

- every `Cargo.toml` package version under the workspace: `X.Y.Z`
- every adapter's dependency on `zmux`: `{ version = "X.Y.Z", path = "../.." }`
- git tag: `vX.Y.Z`

## Release

```bash
git status --short --branch
git fetch origin
git rev-list --left-right --count main...origin/main
```

The ahead/behind count should be `0 0`. Update the versions above, then:

```bash
cargo metadata --locked --no-deps --format-version 1 > /dev/null
cargo publish --dry-run --locked --workspace
git add Cargo.toml Cargo.lock adapter/*/Cargo.toml
git commit -m "release: prepare vX.Y.Z"
git push origin main
git tag -a vX.Y.Z -m "vX.Y.Z"
git push origin vX.Y.Z
```

If the workflow fails before publishing, fix the issue, delete the failed remote tag, retag the fixed commit, and push
again.

After the workflow succeeds, `cargo info <crate>` shows each published version.
