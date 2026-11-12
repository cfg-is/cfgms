#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 Jordan Ritz
#
# go-fetch-retry.sh — run a network-touching `go` command, retrying transient
# module-proxy transport errors.
#
# `go mod download`, `go install pkg@version`, `go get` and `go mod tidy` fail the
# whole CI job on a single proxy stream error, and GOPROXY=...,direct falls back
# only on 404/410 — never on a transport error. This wrapper runs `go "$@"` and
# retries, with linear backoff, only when the combined output matches a transport
# error pattern. Anything else (unknown version, checksum or go.sum mismatch,
# compile error) fails on the first try. The command's original exit code and
# output are preserved.
#
# Usage:   bash scripts/go-fetch-retry.sh <go arguments...>
#   bash scripts/go-fetch-retry.sh mod download
#   bash scripts/go-fetch-retry.sh install example.com/tool@v1.2.3
#
# Invoke it as `bash scripts/go-fetch-retry.sh` (not by path) so it also works
# from a Windows `pwsh` step.
#
# Environment:
#   GO_FETCH_RETRY_ATTEMPTS  total attempts, default 3
#   GO_FETCH_RETRY_DELAY     base backoff in seconds, default 5 (attempt N waits N*delay)
#
# Portable to bash 3.2 (macOS) and Git Bash on Windows.

set -u

if [ "$#" -eq 0 ]; then
    echo "usage: go-fetch-retry.sh <go arguments...>" >&2
    exit 2
fi

max_attempts="${GO_FETCH_RETRY_ATTEMPTS:-3}"
base_delay="${GO_FETCH_RETRY_DELAY:-5}"
case "$max_attempts" in
    '' | *[!0-9]* | 0) max_attempts=3 ;;
esac
case "$base_delay" in
    '' | *[!0-9]*) base_delay=5 ;;
esac

# Transient transport failures between the go command and the module proxy.
transport_pattern='stream error|INTERNAL_ERROR|GOAWAY|connection reset|unexpected EOF|TLS handshake timeout|i/o timeout|timeout awaiting response headers|Client\.Timeout|: 5[0-9][0-9] [A-Za-z]|Bad Gateway|Service Unavailable|Gateway Timeout|Internal Server Error'

# Real resolution errors. Never retried, even if a transport line is also present.
fatal_pattern='checksum mismatch|SECURITY ERROR|missing go\.sum entry|go\.sum|unknown revision|invalid version|no matching versions|malformed module path'

out="$(mktemp "${TMPDIR:-/tmp}/go-fetch-retry.XXXXXX")" || exit 1
trap 'rm -f "$out"' EXIT

cmd_text="go $*"
attempt=1
while :; do
    go "$@" 2>&1 | tee "$out"
    rc="${PIPESTATUS[0]}"

    if [ "$rc" -eq 0 ]; then
        exit 0
    fi

    if grep -Eq "$fatal_pattern" "$out" || ! grep -Eq "$transport_pattern" "$out"; then
        # Not a transient proxy error: fail at once with the original exit code.
        exit "$rc"
    fi

    failure="$(grep -E "$transport_pattern" "$out" | head -n 1)"
    if [ "$attempt" -ge "$max_attempts" ]; then
        echo "go-fetch-retry: '${cmd_text}' failed after ${attempt} attempts (transient proxy error): ${failure}" >&2
        exit "$rc"
    fi

    delay=$((base_delay * attempt))
    echo "go-fetch-retry: '${cmd_text}' attempt ${attempt}/${max_attempts} hit a transient proxy error: ${failure}" >&2
    echo "go-fetch-retry: retrying in ${delay}s" >&2
    sleep "$delay"
    attempt=$((attempt + 1))
done
