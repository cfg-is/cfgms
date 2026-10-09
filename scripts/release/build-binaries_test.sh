#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 Jordan Ritz

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TEST_DIR="$(mktemp -d "${TMPDIR:-/tmp}/cfgms-binaries-test.XXXXXX")"
trap 'rm -rf "$TEST_DIR"' EXIT INT TERM

cd "$REPO_ROOT"
COMMIT="$(git rev-parse HEAD)"
EPOCH="$(git show -s --format=%ct HEAD)"
# Non-zero 32-byte test key (bytes 1..32), base64-encoded; a dummy public key,
# not a secret. Built at runtime so no high-entropy literal sits in the source.
TEST_KEY="$(for i in $(seq 1 32); do printf "\\$(printf '%03o' "$i")"; done | base64 -w0)"

build() {
    local out="$1"
    shift
    bash scripts/release/build-binaries.sh \
        --version v0.0.0-test \
        --commit "$COMMIT" \
        --source-date-epoch "$EPOCH" \
        --output "$out" \
        --allow-untagged --allow-dirty \
        "$@"
}

# Two independent invocations must produce identical bytes (each invocation also
# runs its own build-twice-and-compare internally).
build "$TEST_DIR/a" --platform linux/amd64
build "$TEST_DIR/b" --platform linux/amd64
for f in cfgms-controller-linux-amd64 cfgms-steward-linux-amd64; do
    test -s "$TEST_DIR/a/$f"
    cmp "$TEST_DIR/a/$f" "$TEST_DIR/b/$f"
done
cmp "$TEST_DIR/a/SHA256SUMS" "$TEST_DIR/b/SHA256SUMS"
(cd "$TEST_DIR/a" && sha256sum -c SHA256SUMS)
test "$(wc -l < "$TEST_DIR/a/SHA256SUMS")" -eq 2
echo "build-binaries reproducibility + SHA256SUMS: PASS"

# An unsupported platform fails closed and produces nothing.
status=0
build "$TEST_DIR/bad" --platform plan9/amd64 > "$TEST_DIR/bad.log" 2>&1 || status=$?
if [[ $status -eq 0 || -e "$TEST_DIR/bad" ]] || ! grep -q "unsupported release platform" "$TEST_DIR/bad.log"; then
    echo "FAIL: unsupported platform was not rejected" >&2
    exit 1
fi
echo "build-binaries unsupported platform: PASS"

# A malformed publisher key is rejected.
status=0
build "$TEST_DIR/badkey" --platform linux/amd64 --publisher-key "c2hvcnQ=" > /dev/null 2>&1 || status=$?
if [[ $status -eq 0 ]]; then
    echo "FAIL: short publisher key was accepted" >&2
    exit 1
fi

# Without a key the steward keeps the package placeholder; with one, the key is
# linked into the binary's string data. The controller never receives it.
has_key() { grep -qaF -- "$TEST_KEY" "$1"; }
if has_key "$TEST_DIR/a/cfgms-steward-linux-amd64"; then
    echo "FAIL: keyless steward build carries the test publisher key" >&2
    exit 1
fi
build "$TEST_DIR/keyed" --platform linux/amd64 --publisher-key "$TEST_KEY"
if ! has_key "$TEST_DIR/keyed/cfgms-steward-linux-amd64"; then
    echo "FAIL: keyed steward build is missing the publisher key" >&2
    exit 1
fi
if has_key "$TEST_DIR/keyed/cfgms-controller-linux-amd64"; then
    echo "FAIL: controller build carries the publisher key" >&2
    exit 1
fi
echo "build-binaries publisher key override: PASS"
