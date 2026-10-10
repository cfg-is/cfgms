#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 Jordan Ritz
#
# Tests for scripts/mirror-ci-images.sh (Issue #4858).
#
# Covers: --check passes on a matching fixture and on this repo; it fails when a
# compose image is missing from the list, when a digest differs, when a compose
# image has no digest, and when a Dockerfile FROM or workflow pull_with_retry
# ref is missing; --dry-run prints exactly one copy per list entry to
# ghcr.io/cfg-is/ci-mirror/<name>:<tag> with the digest preserved and needs no
# credentials or docker; --only maps a new digest to its entry's mirror name and
# refuses an unlisted image.
#
# Usage: bash scripts/mirror-ci-images_test.sh

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$REPO_ROOT/scripts/mirror-ci-images.sh"

PASS=0
FAIL=0
pass() { echo "  ✅ $1"; PASS=$((PASS + 1)); }
fail() { echo "  ❌ $1"; FAIL=$((FAIL + 1)); }

D1="$(printf 'a%.0s' $(seq 64))"
D2="$(printf 'b%.0s' $(seq 64))"
D3="$(printf 'c%.0s' $(seq 64))"
D4="$(printf 'd%.0s' $(seq 64))"

# make_fixture echoes a throwaway repo whose list matches its consumers.
make_fixture() {
    local dir
    dir="$(mktemp -d)"
    mkdir -p "$dir/.github/workflows" "$dir/cmd/x"
    cat > "$dir/.github/ci-images.yml" <<LIST
# comment
- upstream: redis:7-alpine@sha256:$D1
  mirror: redis
- upstream: acme/db:latest-pg15@sha256:$D2
  mirror: db
- upstream: golang:1.27-alpine@sha256:$D3
  mirror: golang
- upstream: alpine:3.24@sha256:$D4
  mirror: alpine
LIST
    cat > "$dir/docker-compose.test.yml" <<COMPOSE
services:
  redis:
    image: redis:7-alpine@sha256:$D1
  db:
    image: acme/db:latest-pg15@sha256:$D2 # pinned
COMPOSE
    cat > "$dir/cmd/x/Dockerfile" <<DOCKER
FROM golang:1.27-alpine@sha256:$D3 AS builder
RUN true
FROM alpine:3.24@sha256:$D4
COPY --from=builder /a /a
DOCKER
    cat > "$dir/.github/workflows/w.yml" <<WF
jobs:
  a:
    steps:
    - run: |
        pull_with_retry() {
          until docker pull "\$image"; do :; done
        }
        pull_with_retry alpine:3.24@sha256:$D4
WF
    echo "$dir"
}

echo "check"
fx="$(make_fixture)"
if "$SCRIPT" --root "$fx" --check >/dev/null 2>&1; then pass "matching fixture passes"; else fail "matching fixture passes"; fi

fx="$(make_fixture)"
sed -i '/^- upstream: redis/,+1d' "$fx/.github/ci-images.yml"
out="$("$SCRIPT" --root "$fx" --check 2>&1)"; rc=$?
if [ "$rc" -ne 0 ] && grep -q "redis:7-alpine.*missing" <<<"$out"; then pass "compose image missing from list fails and is named"; else fail "compose image missing from list fails and is named ($rc: $out)"; fi

fx="$(make_fixture)"
sed -i "s/sha256:$D2/sha256:$D1/" "$fx/.github/ci-images.yml"
out="$("$SCRIPT" --root "$fx" --check 2>&1)"; rc=$?
if [ "$rc" -ne 0 ] && grep -q "acme/db:latest-pg15.*digest differs" <<<"$out"; then pass "digest mismatch fails and is named"; else fail "digest mismatch fails and is named ($rc: $out)"; fi

fx="$(make_fixture)"
sed -i "s#image: redis:7-alpine@sha256:$D1#image: redis:7-alpine#" "$fx/docker-compose.test.yml"
out="$("$SCRIPT" --root "$fx" --check 2>&1)"; rc=$?
if [ "$rc" -ne 0 ] && grep -q "no @sha256 digest" <<<"$out"; then pass "digest-less compose image fails"; else fail "digest-less compose image fails ($rc: $out)"; fi

fx="$(make_fixture)"
sed -i "s/sha256:$D3/sha256:$D1/" "$fx/cmd/x/Dockerfile"
if ! "$SCRIPT" --root "$fx" --check >/dev/null 2>&1; then pass "Dockerfile FROM digest mismatch fails"; else fail "Dockerfile FROM digest mismatch fails"; fi

fx="$(make_fixture)"
sed -i "s/pull_with_retry alpine:3.24@sha256:$D4/pull_with_retry debian:trixie@sha256:$D4/" "$fx/.github/workflows/w.yml"
if ! "$SCRIPT" --root "$fx" --check >/dev/null 2>&1; then pass "workflow pull_with_retry ref missing from list fails"; else fail "workflow pull_with_retry ref missing from list fails"; fi

if "$SCRIPT" --check >/dev/null 2>&1; then pass "this repository's list matches its consumers"; else fail "this repository's list matches its consumers"; "$SCRIPT" --check 2>&1 | sed 's/^/     /'; fi

echo "dry-run"
fx="$(make_fixture)"
# Empty PATH entries for docker: prove no docker and no credentials are needed.
out="$(env -i PATH=/usr/bin:/bin "$SCRIPT" --root "$fx" --dry-run 2>&1)"; rc=$?
[ "$rc" -eq 0 ] && pass "dry-run exits 0 with a bare environment" || fail "dry-run exits 0 with a bare environment ($rc)"
[ "$(grep -c '^copy ' <<<"$out")" -eq 4 ] && pass "one copy line per list entry" || fail "one copy line per list entry: $out"
grep -qx "copy redis:7-alpine@sha256:$D1 -> ghcr.io/cfg-is/ci-mirror/redis:7-alpine@sha256:$D1" <<<"$out" \
    && pass "destination is ghcr.io/cfg-is/ci-mirror/<name>:<tag> with digest preserved" \
    || fail "destination format: $out"
grep -q "ci-mirror/db:latest-pg15@sha256:$D2" <<<"$out" && pass "namespaced upstream maps to its mirror name" || fail "namespaced upstream mapping"

real_entries="$(grep -c '^- upstream:' "$REPO_ROOT/.github/ci-images.yml")"
real_out="$("$SCRIPT" --dry-run 2>&1)"
[ "$(grep -c '^copy ' <<<"$real_out")" -eq "$real_entries" ] && pass "real list: one copy per entry ($real_entries)" || fail "real list: copy count differs from $real_entries"

echo "only"
out="$("$SCRIPT" --root "$fx" --dry-run --only "redis:7-alpine@sha256:$D3" 2>&1)"; rc=$?
if [ "$rc" -eq 0 ] && [ "$out" = "copy redis:7-alpine@sha256:$D3 -> ghcr.io/cfg-is/ci-mirror/redis:7-alpine@sha256:$D3" ]; then pass "--only mirrors a new digest to the entry's name:tag"; else fail "--only new digest ($rc: $out)"; fi
out="$("$SCRIPT" --root "$fx" --dry-run --only "unknown:1@sha256:$D3" 2>&1)"; rc=$?
[ "$rc" -ne 0 ] && pass "--only refuses an image absent from the list" || fail "--only refuses unlisted image"
out="$("$SCRIPT" --root "$fx" --dry-run --only "redis:7-alpine" 2>&1)"; rc=$?
[ "$rc" -ne 0 ] && pass "--only refuses a digest-less ref" || fail "--only refuses digest-less ref"

echo
echo "Results: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
