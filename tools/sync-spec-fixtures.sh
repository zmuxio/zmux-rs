#!/usr/bin/env bash
# Copies the conformance assets of the zmux specification into testdata/spec.
#
#   ZMUX_SPEC_DIR  path of the zmux-spec checkout (default: ../zmux-spec,
#                  relative to the repository root)
#
# The copied files are committed; run this script after the specification
# changes and review the diff.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
spec="${ZMUX_SPEC_DIR:-$root/../zmux-spec}"
spec="$(cd "$spec" && pwd)"
dest="$root/testdata/spec"

for f in assets/registry.json assets/manifest.json fixtures/profiles.json \
    fixtures/wire/valid.ndjson fixtures/wire/invalid.ndjson \
    fixtures/traces/index.json WIRE_EXAMPLES.md; do
    [[ -f "$spec/$f" ]] || { echo "missing $spec/$f" >&2; exit 1; }
done

rm -rf "$dest"
mkdir -p "$dest/wire" "$dest/traces"
cp "$spec/assets/registry.json" "$spec/assets/manifest.json" "$dest/"
cp "$spec/fixtures/profiles.json" "$dest/"
cp "$spec/fixtures/wire/valid.ndjson" "$spec/fixtures/wire/invalid.ndjson" "$dest/wire/"
cp "$spec/WIRE_EXAMPLES.md" "$dest/"
# Traces keep their directory layout below fixtures/traces.
(cd "$spec/fixtures/traces" && find . -type f \( -name '*.ndjson' -o -name 'index.json' \) -print0 |
    while IFS= read -r -d '' f; do
        mkdir -p "$dest/traces/$(dirname "$f")"
        cp "$f" "$dest/traces/$f"
    done)

if git -C "$spec" rev-parse --git-dir >/dev/null 2>&1; then
    {
        echo "source: zmux-spec"
        echo "commit: $(git -C "$spec" rev-parse HEAD)"
        if [[ -n "$(git -C "$spec" status --porcelain -- assets fixtures WIRE_EXAMPLES.md)" ]]; then
            echo "dirty: true (uncommitted changes were copied)"
        fi
    } >"$dest/SOURCE"
fi

echo "synced $(find "$dest" -type f | wc -l | tr -d ' ') files from $spec"
