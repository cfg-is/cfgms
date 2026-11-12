#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 Jordan Ritz
#
# go-fetch-retry_test.sh — Tests for scripts/go-fetch-retry.sh.
#
# A stub `go` placed first on PATH replays scripted outcomes, so the wrapper's
# retry decisions are asserted without touching the network. The stub counts its
# invocations in a file; its behaviour for call N is read from $STUB_PLAN
# (one "<exit-code>:<message>" line per call, the last line repeats).
#
# Run: bash scripts/go-fetch-retry_test.sh
# Exit codes: 0 = all tests passed, 1 = any test failed

set -u

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WRAPPER="$REPO_ROOT/scripts/go-fetch-retry.sh"

SCRATCH="$(mktemp -d "${TMPDIR:-/tmp}/cfgms-go-fetch-retry.XXXXXX")"
trap 'rm -rf "$SCRATCH"' EXIT INT TERM

mkdir -p "$SCRATCH/bin"
cat > "$SCRATCH/bin/go" <<'STUB'
#!/usr/bin/env bash
n=$(( $(cat "$STUB_COUNT" 2>/dev/null || echo 0) + 1 ))
echo "$n" > "$STUB_COUNT"
echo "$*" >> "$STUB_ARGS"
line="$(sed -n "${n}p" "$STUB_PLAN")"
[ -n "$line" ] || line="$(tail -n 1 "$STUB_PLAN")"
code="${line%%:*}"
msg="${line#*:}"
[ -z "$msg" ] || echo "$msg" >&2
exit "$code"
STUB
chmod +x "$SCRATCH/bin/go"

PASS_COUNT=0
FAIL_COUNT=0
_pass() { echo "[PASS] $1"; PASS_COUNT=$((PASS_COUNT + 1)); }
_fail() { echo "[FAIL] $1"; FAIL_COUNT=$((FAIL_COUNT + 1)); }

TRANSPORT='go.opentelemetry.io/otel@v1.47.0: read "https://proxy.golang.org/x.zip": stream error: stream ID 51; INTERNAL_ERROR; received from peer'
CHECKSUM='verifying module: checksum mismatch
	SECURITY ERROR
	This download does NOT match an earlier download recorded in go.sum.'

# run_case <plan-file-content> <go args...>; sets RC, CALLS, OUTPUT.
run_case() {
    local plan="$1"
    shift
    export STUB_COUNT="$SCRATCH/count" STUB_ARGS="$SCRATCH/args" STUB_PLAN="$SCRATCH/plan"
    rm -f "$STUB_COUNT" "$STUB_ARGS"
    printf '%s\n' "$plan" > "$STUB_PLAN"
    OUTPUT="$(PATH="$SCRATCH/bin:$PATH" GO_FETCH_RETRY_DELAY=0 bash "$WRAPPER" "$@" 2>&1)"
    RC=$?
    CALLS="$(cat "$STUB_COUNT" 2>/dev/null || echo 0)"
}

assert_eq() { # <name> <want> <got>
    if [ "$2" = "$3" ]; then _pass "$1"; else _fail "$1 (want '$2', got '$3')"; fi
}
assert_contains() { # <name> <needle> <haystack>
    case "$3" in
        *"$2"*) _pass "$1" ;;
        *) _fail "$1 (missing '$2' in: $3)" ;;
    esac
}

# 1. Transport error then success: retried once, exits 0.
run_case "1:$TRANSPORT
0:" mod download
assert_eq "transport error then success: exit 0" 0 "$RC"
assert_eq "transport error then success: two attempts" 2 "$CALLS"
assert_contains "transport error then success: retry logged" "retrying" "$OUTPUT"

# 2. Repeated transport errors: fails after 3 attempts, names the failure, keeps exit code.
run_case "7:$TRANSPORT" mod download
assert_eq "repeated transport error: original exit code kept" 7 "$RC"
assert_eq "repeated transport error: three attempts" 3 "$CALLS"
assert_contains "repeated transport error: names module" "go.opentelemetry.io/otel@v1.47.0" "$OUTPUT"
assert_contains "repeated transport error: gives up message" "failed after 3 attempts" "$OUTPUT"

# 3. Non-transport error: fails on the first try, no retry.
run_case "1:$CHECKSUM" mod download
assert_eq "checksum mismatch: exit code kept" 1 "$RC"
assert_eq "checksum mismatch: single attempt" 1 "$CALLS"
assert_contains "checksum mismatch: output preserved" "checksum mismatch" "$OUTPUT"

# 4. Unrecognised error: no retry; exit code kept.
run_case "3:go: example.com/x@v9.9.9: unknown revision v9.9.9" install example.com/x@v9.9.9
assert_eq "unknown revision: exit code kept" 3 "$RC"
assert_eq "unknown revision: single attempt" 1 "$CALLS"

# 5. A checksum error is not retried even when a transport line is also present.
run_case "1:$TRANSPORT; verifying module: checksum mismatch" mod download
assert_eq "mixed output with checksum mismatch: single attempt" 1 "$CALLS"

# 6. HTTP 5xx from the proxy is transient.
run_case "1:go: reading https://proxy.golang.org/x/@v/list: 503 Service Unavailable
0:" get example.com/x@v1.0.0
assert_eq "proxy 503: retried then success" 2 "$CALLS"
assert_eq "proxy 503: exit 0" 0 "$RC"

# 7. Arguments are passed to go verbatim.
run_case "0:" install example.com/tool@v1.2.3
assert_eq "arguments forwarded" "install example.com/tool@v1.2.3" "$(cat "$SCRATCH/args")"

# 8. GO_FETCH_RETRY_ATTEMPTS bounds the attempts.
export GO_FETCH_RETRY_ATTEMPTS=2
run_case "1:$TRANSPORT" mod tidy
unset GO_FETCH_RETRY_ATTEMPTS
assert_eq "attempt limit honoured" 2 "$CALLS"

# 9. No arguments is a usage error.
OUTPUT="$(bash "$WRAPPER" 2>&1)"
assert_eq "no arguments: exit 2" 2 "$?"

echo
echo "go-fetch-retry_test: ${PASS_COUNT} passed, ${FAIL_COUNT} failed"
[ "$FAIL_COUNT" -eq 0 ]
