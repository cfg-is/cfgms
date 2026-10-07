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

# Test-only publisher seed (bytes 1..32). It is not the dev seed, and it is not a
# secret: nothing signed with it is trusted by any real steward. The matching
# public key is derived through the signer so the release script's seed/key
# agreement check has a real match to accept.
TEST_SEED="AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA="
DEV_PUBLIC_KEY="O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik="
TEST_PUBLISHER_KEY="$(CFGMS_PUBLISHER_SEED="$TEST_SEED" go run ./scripts/sign-module-bundle pubkey)"
test -n "$TEST_PUBLISHER_KEY"
test "$TEST_PUBLISHER_KEY" != "$DEV_PUBLIC_KEY"

release() {
    local out="$1"
    shift
    bash scripts/release/build-reproducible.sh \
        --version v0.0.0-pb016-test \
        --commit "$COMMIT" \
        --source-date-epoch "$EPOCH" \
        --output "$out" \
        --platform linux/amd64 \
        --allow-untagged \
        --allow-dirty \
        "$@"
}

# expect_release_failure <name> <expected-stderr-fragment> <publisher-key> [env...]
# Runs the release script and requires a non-zero exit with the expected message,
# and that no output directory was produced (aborted before assembling anything).
expect_release_failure() {
    local name="$1" fragment="$2" key="$3"
    shift 3
    local out="$TEST_DIR/out-$name"
    local status=0
    env "$@" bash -c '
        out="$1"; key="$2"; shift 2
        source /dev/stdin <<<"$(declare -f release)"
        release "$out" --publisher-key "$key"
    ' _ "$out" "$key" > "$TEST_DIR/$name.log" 2>&1 || status=$?
    if [[ $status -eq 0 ]]; then
        echo "FAIL: $name: release unexpectedly succeeded" >&2
        exit 1
    fi
    if ! grep -qF -- "$fragment" "$TEST_DIR/$name.log"; then
        echo "FAIL: $name: expected message containing: $fragment" >&2
        cat "$TEST_DIR/$name.log" >&2
        exit 1
    fi
    if [[ -e "$out" ]]; then
        echo "FAIL: $name: output directory was created before the abort" >&2
        exit 1
    fi
    echo "release failure test $name: PASS"
}
export -f release
export COMMIT EPOCH

# An absent seed is a hard failure, never a silent fall back to the dev key.
expect_release_failure no-seed "CFGMS_PUBLISHER_SEED is not set" "$TEST_PUBLISHER_KEY" \
    -u CFGMS_PUBLISHER_SEED

# A seed whose public half is not the key baked into the steward ships bundles no
# steward can verify.
expect_release_failure key-mismatch "does not match the key baked into the steward" "$TEST_PUBLISHER_KEY" \
    CFGMS_PUBLISHER_SEED="$(head -c 32 /dev/zero | tr '\0' '\7' | base64)"

# The zero-seed dev key is refused even when it agrees with --publisher-key.
expect_release_failure dev-seed "dev key" "$DEV_PUBLIC_KEY" \
    CFGMS_PUBLISHER_SEED="$(head -c 32 /dev/zero | base64)"

CFGMS_PUBLISHER_SEED="$TEST_SEED" release "$TEST_DIR/out" --publisher-key "$TEST_PUBLISHER_KEY"

ARCHIVE="$TEST_DIR/out/cfgms-linux-amd64.tar.gz"
test -s "$ARCHIVE"
tar -tzf "$ARCHIVE" > "$TEST_DIR/archive-files"
grep -qx 'cfgms-controller' "$TEST_DIR/archive-files"
grep -qx 'cfgms-steward' "$TEST_DIR/archive-files"
grep -qx 'cfgms-steward-launcher' "$TEST_DIR/archive-files"
grep -qx 'MANIFEST.sha256' "$TEST_DIR/archive-files"
# Every stdlib module ships as an installation root, not a flat binary.
for module in cert_trust file firewall hostname package patch script service time user; do
    grep -qx "modules/$module/module.yaml" "$TEST_DIR/archive-files"
    grep -qx "modules/$module/bundle.yaml" "$TEST_DIR/archive-files"
    grep -qx "modules/$module/cfgms-module-$module" "$TEST_DIR/archive-files"
    if grep -qx "cfgms-module-$module" "$TEST_DIR/archive-files"; then
        echo "FAIL: flat cfgms-module-$module binary still in the archive" >&2
        exit 1
    fi
done
(
    cd "$TEST_DIR/out"
    sha256sum -c SHA256SUMS
)
echo "reproducible release artifact test: PASS"
