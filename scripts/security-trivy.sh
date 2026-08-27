#!/usr/bin/env bash
# Runs trivy filesystem scan and distinguishes init-errors from real findings.
#
# Exit codes:
#   0 — clean (no blocking security findings)
#   1 — UNKNOWN/MEDIUM/HIGH/CRITICAL vulnerability, secret, or
#       misconfiguration findings (deployment blocked)
#   2 — trivy failed to initialize (DB/network error) — re-run required
#
# The split between exit 1 and exit 2 prevents init-errors (e.g. mirror.gcr.io
# unreachable) from being mis-reported as "vulnerabilities found" (Issue #1402).
#
# TRIVY_CMD: override the trivy binary path (used by tests to inject a mock).

set -euo pipefail

TRIVY_CMD="${TRIVY_CMD:-trivy}"
SCAN_TARGET="${1:-.}"

# Patterns present in trivy's output when the DB cannot be initialised.
# These are infrastructure failures, not security findings.
INIT_ERROR_PATTERN="run error: init error|DB error|failed to download.*DB|FATAL.*init error"

_is_init_error() {
    echo "$1" | grep -qiE "$INIT_ERROR_PATTERN"
}

# --- Blocking vulnerability, secret, and misconfiguration scan ---
echo "🔍 Comprehensive Security Scan (Blocking Issues):"

# Stream trivy's output live via tee instead of buffering the whole scan through
# $(...) — a slow run and a genuinely stuck run were indistinguishable without
# external process monitoring before this (Issue #3650). set -euo pipefail is
# already active above, so the pipeline's reported exit status is trivy's own
# (tee itself only fails on a write error, which pipefail would still surface).
tmp_file="$(mktemp)"
trap 'rm -f "$tmp_file"' EXIT

vuln_exit=0
"$TRIVY_CMD" fs "$SCAN_TARGET" \
    --scanners vuln,secret,misconfig \
    --format table \
    --severity UNKNOWN,CRITICAL,HIGH,MEDIUM \
    --skip-dirs .cache \
    --exit-code 1 2>&1 | tee "$tmp_file" || vuln_exit=$?

vuln_output=$(cat "$tmp_file")

if [[ $vuln_exit -ne 0 ]]; then
    if _is_init_error "$vuln_output"; then
        echo ""
        echo "[trivy] DB download failed — re-run required"
        echo "   The vulnerability database could not be downloaded (network/DNS issue)."
        echo "   This is an infrastructure issue, not a security finding."
        echo "   Ensure mirror.gcr.io is reachable and re-run the scan."
        exit 2
    fi
    echo ""
    echo "❌ Blocking vulnerabilities, secrets, or misconfigurations found."
    echo "   Public-beta policy blocks UNKNOWN/MEDIUM/HIGH/CRITICAL findings."
    exit 1
fi

echo ""
echo "✅ Trivy scan completed"
echo "   No UNKNOWN/MEDIUM/HIGH/CRITICAL vulnerability, secret, or misconfiguration findings"
