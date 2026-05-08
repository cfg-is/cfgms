#!/usr/bin/env bash
# Runs trivy filesystem scan and distinguishes init-errors from real findings.
#
# Exit codes:
#   0 — clean (no blocking vulnerabilities)
#   1 — CRITICAL/HIGH/MEDIUM vulnerabilities found (deployment blocked)
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

# --- Blocking vulnerability scan ---
echo "🔍 Vulnerability Scan (Blocking Issues):"

vuln_output=""
vuln_exit=0
vuln_output=$("$TRIVY_CMD" fs "$SCAN_TARGET" \
    --scanners vuln \
    --format table \
    --severity CRITICAL,HIGH,MEDIUM \
    --skip-dirs .cache \
    --exit-code 1 2>&1) || vuln_exit=$?

echo "$vuln_output"

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
    echo "❌ CRITICAL/HIGH/MEDIUM vulnerabilities found - deployment blocked!"
    echo "   Please update dependencies to fix these security issues."
    echo "   This matches CI/CD severity requirements."
    exit 1
fi

# --- Non-blocking complete scan (vuln + secret + misconfig) ---
echo "🔍 Complete Security Scan (All Issues):"
"$TRIVY_CMD" fs "$SCAN_TARGET" \
    --scanners vuln,secret,misconfig \
    --format table \
    --skip-dirs .cache \
    --exit-code 0 2>&1 || true

echo ""
echo "✅ Trivy scan completed"
echo "   Note: Development certificates detected in features/controller/certs/ are expected"
echo "   Critical/High/Medium vulnerabilities will block deployment (matches CI/CD)"
