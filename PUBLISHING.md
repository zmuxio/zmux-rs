# Publishing

This workspace publishes two crates:

- `zmux`: the core native ZMux implementation.
- `zmux-quinn`: the optional Quinn adapter.

Publish `zmux` first. `zmux-quinn` depends on the released `zmux` version, so
adapter packaging and publishing will fail until that core version is visible
in the crates.io index.

## GitHub Automation

The release workflow lives at `.github/workflows/release.yml`.

It runs when a tag matching `vX.Y.Z` is pushed. The workflow:

1. Validates that the tag matches the root `zmux` crate version.
2. Validates that `zmux-quinn` uses the same version and depends on that
   `zmux` version.
3. Runs formatting, clippy, tests, docs, and a core crate publish dry-run.
4. Publishes `zmux` using the `CARGO_REGISTRY_TOKEN` GitHub secret.
5. Waits until the new `zmux` version is visible to crates.io dependency
   resolution.
6. Publishes `zmux-quinn` using the same secret.

The repository secret must be named exactly:

```text
CARGO_REGISTRY_TOKEN
```

Use a crates.io API token from an account with publish rights to both crates,
for example your `djylb` crates.io account.

To release version `0.1.0`:

```text
git tag v0.1.0
git push origin v0.1.0
```

Do not push a tag until the tree contains the exact files and versions you want
to publish. The workflow intentionally has no manual publish trigger.

The quality workflow lives at `.github/workflows/code_quality.yml`. It runs on
pull requests, pushes to `main` and `releases/*`, and manual dispatch. It runs
Rust formatting, clippy, tests, docs, and core packaging. It also runs Qodana
when `QODANA_TOKEN` is configured; otherwise the Qodana step is skipped.

## Before Release

Use shell syntax appropriate for your environment when setting environment
variables. The commands below are platform-neutral Cargo commands.

1. Confirm package metadata:

   ```text
   cargo metadata --no-deps
   ```

2. Confirm versions:

    - root `Cargo.toml` package version is the version to publish.
    - `adapter/quinn/Cargo.toml` package version is the version to publish.
    - `adapter/quinn/Cargo.toml` depends on the same released `zmux` version.

3. Run the release checks:

   ```text
   cargo fmt --all -- --check
   cargo clippy --workspace --all-targets -- -D warnings
   cargo clippy -p zmux --features tokio-io,futures-io --all-targets -- -D warnings
   cargo test --workspace
   cargo doc --workspace --no-deps
   cargo package -p zmux
   ```

4. Optional interop checks require local Go and Java implementation checkouts:

   ```text
   ZMUX_INTEROP=1
   ZMUX_GO_ROOT=<path-to-zmux-go>
   ZMUX_JAVA_ROOT=<path-to-zmux-java>
   ZMUX_INTEROP_TIMEOUT_SECONDS=120
   ```

   ```text
   cargo test --test go_interop_smoke
   cargo test --test java_interop_smoke
   cargo test -p zmux-quinn --test go_quic_interop_smoke
   ```

## Dry Run

Run dry-runs without `--allow-dirty` from the exact tree you intend to release:

```text
cargo publish -p zmux --dry-run
```

After the core dry-run passes, the adapter dry-run will only pass if the
matching `zmux` version is already present in the crates.io index. Before that,
this error is expected:

```text
no matching package named `zmux` found
```

Once the core version exists in crates.io:

```text
cargo publish -p zmux-quinn --dry-run
```

## Publish

Authenticate once if this machine has not published before:

```text
cargo login
```

Publish the core crate:

```text
cargo publish -p zmux
```

Wait for crates.io to index the new `zmux` version. Then verify and publish the
adapter:

```text
cargo package -p zmux-quinn
cargo publish -p zmux-quinn --dry-run
cargo publish -p zmux-quinn
```

## After Publish

1. Check the crates.io pages for both crates.
2. Verify a fresh consumer project can resolve the published versions:

   ```text
   cargo new zmux-publish-check
   ```

   Add dependencies on `zmux` and `zmux-quinn`, then run:

   ```text
   cargo check
   ```

3. Tag the repository at the released version if that is part of the project
   workflow.

## Notes

- Do not use `--allow-dirty` for an actual publish.
- `zmux` has optional `tokio-io` and `futures-io` features; they are not enabled
  by default.
- `zmux-quinn` intentionally does not enable Quinn runtime or TLS-provider
  features for applications. Applications should depend on `quinn` directly
  with the runtime and crypto provider they deploy.
