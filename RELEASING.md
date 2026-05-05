# Releasing

This document is for maintainers. User installation instructions belong in `README.md`.

Published crates:

- `zmux`
- `zmux-quinn`

Releases are automated from tag `vX.Y.Z`. The workflow validates versions, runs checks, publishes `zmux`, waits for registry indexing, and publishes `zmux-quinn`.

## Version Rules

- `Cargo.toml` package version: `X.Y.Z`
- `adapter/quinn/Cargo.toml` package version: `X.Y.Z`
- `adapter/quinn/Cargo.toml` dependency on `zmux`: `X.Y.Z`
- Git tag: `vX.Y.Z`

## Release

```bash
git status --short --branch
git fetch origin
git rev-list --left-right --count main...origin/main
```

The ahead/behind count should be `0 0`.

Update the three version fields above, then commit and push:

```bash
cargo metadata --locked --no-deps --format-version 1
git add Cargo.toml Cargo.lock adapter/quinn/Cargo.toml README.md adapter/quinn/README.md RELEASING.md .github/workflows/release.yml
git commit -m "release: prepare vX.Y.Z"
git push origin main
```

Tag the release:

```bash
git tag -a vX.Y.Z -m "vX.Y.Z"
git push origin vX.Y.Z
```

If the workflow fails before publishing, fix the issue, delete the failed remote tag, retag the fixed commit, and push again. crates.io versions are immutable after publication.

After the workflow succeeds:

```bash
cargo info zmux
cargo info zmux-quinn
```
