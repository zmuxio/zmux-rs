#!/usr/bin/env bash
set -euo pipefail
go_repo=$(cd "${1:?usage: bash interop/webtransport/run.sh /path/to/zmux-go}" && pwd)
rust_repo=$(cd "$(dirname "$0")/../.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
cp "$rust_repo/interop/webtransport/main.go" "$tmp/"
cp "$go_repo/zmuxh3/go.sum" "$tmp/"
(
    cd "$tmp"
    export GOWORK=off GOMAXPROCS=${GOMAXPROCS:-4}
    go mod init zmux-wt-interop
    go mod edit -require=github.com/zmuxio/zmux-go/zmuxh3@v0.0.0 \
        "-replace=github.com/zmuxio/zmux-go/zmuxh3=$go_repo/zmuxh3" \
        "-replace=github.com/zmuxio/zmux-go/zmuxquic=$go_repo/zmuxquic" \
        "-replace=github.com/zmuxio/zmux-go=$go_repo"
    go build -p 4 -buildvcs=false -mod=mod -o "$tmp/go-peer" .
)
cd "$rust_repo"
ZMUX_WT_GO_PEER="$tmp/go-peer" CARGO_BUILD_JOBS=${CARGO_BUILD_JOBS:-6} \
    cargo test --locked -p zmux-webtransport --test go_interop \
    -- --ignored --nocapture --test-threads=4
