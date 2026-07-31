#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 Jordan Ritz

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TEST_DIR="$(mktemp -d "${TMPDIR:-/tmp}/cfgms-repro-test.XXXXXX")"
cleanup() {
    rm -rf "$TEST_DIR"
}
trap cleanup EXIT INT TERM

cd "$REPO_ROOT"
COMMIT="$(git rev-parse HEAD)"
EPOCH="$(git show -s --format=%ct HEAD)"
# Public test key only; the matching private key is intentionally not present.
TEST_PUBLISHER_KEY="O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik="

bash scripts/release/build-reproducible.sh \
    --version v0.0.0-pb016-test \
    --commit "$COMMIT" \
    --source-date-epoch "$EPOCH" \
    --publisher-key "$TEST_PUBLISHER_KEY" \
    --output "$TEST_DIR/out" \
    --platform linux/amd64 \
    --allow-untagged \
    --allow-dirty

ARCHIVE="$TEST_DIR/out/cfgms-linux-amd64.tar.gz"
test -s "$ARCHIVE"
tar -tzf "$ARCHIVE" > "$TEST_DIR/archive-files"
grep -qx 'cfgms-controller' "$TEST_DIR/archive-files"
grep -qx 'cfgms-steward' "$TEST_DIR/archive-files"
grep -qx 'cfgms-steward-launcher' "$TEST_DIR/archive-files"
grep -qx 'MANIFEST.sha256' "$TEST_DIR/archive-files"
(
    cd "$TEST_DIR/out"
    sha256sum -c SHA256SUMS
)
echo "reproducible release artifact test: PASS"
