#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 Jordan Ritz
#
# npm-audit-gate_test.sh — offline fixture tests for scripts/npm-audit-gate.sh.
#
# The gate runs against a stand-in `npm` executable (NPM_AUDIT_GATE_NPM) that
# prints fixture `npm audit --json` documents and a fixture `npm view` answer,
# with "today" and the newest published picomatch injected. No network needed.
#
# Run: bash scripts/npm-audit-gate_test.sh

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GATE="$REPO_ROOT/scripts/npm-audit-gate.sh"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

PASS_COUNT=0
FAIL_COUNT=0
_pass() { PASS_COUNT=$((PASS_COUNT + 1)); echo "  ✓ $1"; }
_fail() { FAIL_COUNT=$((FAIL_COUNT + 1)); echo "  ✗ $1"; }

echo "=== npm-audit-gate_test.sh ==="

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------
PICO_ADV='{"source":1247710,"name":"picomatch","dependency":"picomatch","title":"picomatch ReDoS","url":"https://github.com/advisories/GHSA-fc5q-39xc-vjpf","severity":"high","range":"<=4.0.7"}'
OTHER_ADV='{"source":1999999,"name":"other-pkg","dependency":"other-pkg","title":"other issue","url":"https://github.com/advisories/GHSA-aaaa-bbbb-cccc","severity":"high","range":"<2.0.0"}'
OTHER_ON_PICO_ADV='{"source":1999998,"name":"picomatch","dependency":"picomatch","title":"second picomatch issue","url":"https://github.com/advisories/GHSA-dddd-eeee-ffff","severity":"high","range":"<=4.0.7"}'
MODERATE_ADV='{"source":1888888,"name":"mod-pkg","dependency":"mod-pkg","title":"moderate issue","url":"https://github.com/advisories/GHSA-mmmm-oooo-dddd","severity":"moderate","range":"<1.0.0"}'
LOW_ADV='{"source":1777777,"name":"low-pkg","dependency":"low-pkg","title":"low issue","url":"https://github.com/advisories/GHSA-llll-oooo-wwww","severity":"low","range":"<1.0.0"}'

# audit_doc <vuln-entries-json-object> — wrap in an npm audit v2 document.
audit_doc() {
    echo "{\"auditReportVersion\":2,\"vulnerabilities\":$1,\"metadata\":{}}"
}

# vuln <name> <severity> <via-json-array>
vuln() {
    echo "\"$1\":{\"name\":\"$1\",\"severity\":\"$2\",\"isDirect\":false,\"via\":$3,\"effects\":[],\"range\":\"*\",\"nodes\":[],\"fixAvailable\":true}"
}

# The shape the real report has: picomatch plus dependents whose via is the
# string "picomatch" (and a chain: vitest -> vite -> tinyglobby -> picomatch).
PICO_ONLY="$(audit_doc "{$(vuln picomatch high "[$PICO_ADV]"),$(vuln fdir high '["picomatch"]'),$(vuln tinyglobby high '["fdir","picomatch"]'),$(vuln vite high '["picomatch","tinyglobby"]'),$(vuln vitest high '["vite"]')}")"
PICO_ALONE="$(audit_doc "{$(vuln picomatch high "[$PICO_ADV]")}")"
PICO_PLUS_OTHER="$(audit_doc "{$(vuln picomatch high "[$PICO_ADV]"),$(vuln other-pkg high "[$OTHER_ADV]")}")"
OTHER_ONLY="$(audit_doc "{$(vuln other-pkg high "[$OTHER_ADV]")}")"
CRITICAL_ONLY="$(audit_doc "{$(vuln other-pkg critical "[$OTHER_ADV]")}")"
MIXED_CHAIN="$(audit_doc "{$(vuln picomatch high "[$PICO_ADV,$OTHER_ON_PICO_ADV]"),$(vuln vite high '["picomatch"]')}")"
DEPENDENT_MIXED_VIA="$(audit_doc "{$(vuln picomatch high "[$PICO_ADV]"),$(vuln other-pkg high "[$OTHER_ADV]"),$(vuln vite high '["picomatch","other-pkg"]')}")"
CYCLE="$(audit_doc "{$(vuln picomatch high "[$PICO_ADV]"),$(vuln a high '["b","picomatch"]'),$(vuln b high '["a"]')}")"
CYCLE_WITH_OTHER="$(audit_doc "{$(vuln a high '["b"]'),$(vuln b high "[\"a\",$OTHER_ADV]")}")"
DANGLING_VIA="$(audit_doc "{$(vuln vite high '["not-in-report"]')}")"
MODERATE_LOW_ONLY="$(audit_doc "{$(vuln mod-pkg moderate "[$MODERATE_ADV]"),$(vuln low-pkg low "[$LOW_ADV]")}")"
CLEAN="$(audit_doc '{}')"
NO_VULNERABILITIES='{"auditReportVersion":2,"metadata":{}}'
NPM_ERROR='{"error":{"code":"ENOTFOUND","summary":"audit endpoint unreachable"}}'
EVIL_PKG_ADV="${PICO_ADV/\"name\":\"picomatch\"/\"name\":\"evil\"}"
SPOOF="$(audit_doc "{$(vuln evil high "[$EVIL_PKG_ADV]")}")"

# Lockfile with a root-level and a nested picomatch (newest locked = 4.0.7).
cat >"$WORK/package-lock.json" <<'JSON'
{"name":"web","lockfileVersion":3,"packages":{
 "":{"name":"web"},
 "node_modules/picomatch":{"version":"4.0.7","dev":true},
 "node_modules/foo/node_modules/picomatch":{"version":"2.3.1","dev":true},
 "node_modules/micromatch-not-picomatch":{"version":"9.9.9"}
}}
JSON
echo '{"name":"web","lockfileVersion":3,"packages":{"":{"name":"web"}}}' >"$WORK/package-lock-nopico.json"

# Stand-in npm. `audit --json` prints $FAKE_AUDIT_FILE (exit 1 like npm does
# when it finds vulnerabilities); `view` prints $FAKE_VIEW or fails.
cat >"$WORK/fake-npm" <<'FAKE'
#!/usr/bin/env bash
case "$1" in
audit)
    [ -n "${FAKE_AUDIT_FILE:-}" ] && cat "$FAKE_AUDIT_FILE"
    exit 1
    ;;
view)
    if [ -n "${FAKE_VIEW_FAIL:-}" ]; then
        echo "npm ERR! network" >&2
        exit 1
    fi
    echo "${FAKE_VIEW:-}"
    ;;
*) exit 2 ;;
esac
FAKE
chmod +x "$WORK/fake-npm"

# Exception file with the same entry the repo commits.
GOOD_EXC="$WORK/exceptions.txt"
printf '%s\n' '# comment line' \
    'GHSA-fc5q-39xc-vjpf package=picomatch until=2026-12-02   # trailing comment' >"$GOOD_EXC"

n=0
# write_audit <json> — prints the fixture path.
write_audit() {
    n=$((n + 1))
    printf '%s' "$1" >"$WORK/audit-$n.json"
    echo "$WORK/audit-$n.json"
}

# run_gate <audit-json> <today> <latest-picomatch> [exceptions-file] — sets RC/OUT.
run_gate() {
    local audit_file exc="${4:-$GOOD_EXC}"
    audit_file="$(write_audit "$1")"
    OUT="$(FAKE_AUDIT_FILE="$audit_file" NPM_AUDIT_GATE_NPM="$WORK/fake-npm" \
        NPM_AUDIT_GATE_TODAY="$2" NPM_AUDIT_GATE_LATEST_PICOMATCH="$3" \
        NPM_AUDIT_GATE_EXCEPTIONS="$exc" NPM_AUDIT_GATE_LOCKFILE="$WORK/package-lock.json" \
        bash "$GATE" 2>&1)"
    RC=$?
}

assert_pass() { # name audit today latest [exc]
    run_gate "$2" "$3" "$4" "${5:-}"
    if [ "$RC" -eq 0 ]; then _pass "$1"; else _fail "$1 (expected exit 0, got $RC): $OUT"; fi
}
# assert_fail name audit today latest [exc]; $EXPECT, when set, must appear in the output.
assert_fail() {
    run_gate "$2" "$3" "$4" "${5:-}"
    if [ "$RC" -eq 0 ]; then
        _fail "$1 (expected non-zero exit, got 0): $OUT"
    elif [ -n "${EXPECT:-}" ] && ! grep -qF -- "$EXPECT" <<<"$OUT"; then
        _fail "$1 (failed as expected but output lacks '$EXPECT'): $OUT"
    else
        _pass "$1"
    fi
    EXPECT=""
}

# run_gate_npm_view <audit-json> — no injected latest version: the stand-in npm
# answers `npm view`. Env FAKE_VIEW / FAKE_VIEW_FAIL are taken from the caller.
run_gate_npm_view() {
    local audit_file
    audit_file="$(write_audit "$1")"
    OUT="$(FAKE_AUDIT_FILE="$audit_file" NPM_AUDIT_GATE_NPM="$WORK/fake-npm" \
        NPM_AUDIT_GATE_TODAY=2026-12-01 NPM_AUDIT_GATE_EXCEPTIONS="$GOOD_EXC" \
        NPM_AUDIT_GATE_LOCKFILE="${LOCK:-$WORK/package-lock.json}" bash "$GATE" 2>&1)"
    RC=$?
}

# ---------------------------------------------------------------------------
# (a) only the exempt advisory (incl. dependents via the string "picomatch")
# ---------------------------------------------------------------------------
assert_pass "(a) picomatch-only high findings pass before expiry" "$PICO_ONLY" 2026-12-01 4.0.7
assert_pass "(a) picomatch alone passes" "$PICO_ALONE" 2026-11-18 4.0.7
assert_pass "(a) via cycle that ends in the exempt advisory passes" "$CYCLE" 2026-12-01 4.0.7

# (b) expiry boundary: the until= date itself and later fail
EXPECT="expired" assert_fail "(b) fails on the until= date (2026-12-02)" "$PICO_ONLY" 2026-12-02 4.0.7
EXPECT="expired" assert_fail "(b) fails after the until= date" "$PICO_ONLY" 2027-01-15 4.0.7

# (c) any other high advisory fails, with and without the exempt one
EXPECT="GHSA-aaaa-bbbb-cccc" assert_fail "(c) other high advisory alone fails" "$OTHER_ONLY" 2026-12-01 4.0.7
EXPECT="GHSA-aaaa-bbbb-cccc" assert_fail "(c) other high advisory alongside the exempt one fails" "$PICO_PLUS_OTHER" 2026-12-01 4.0.7
EXPECT="GHSA-aaaa-bbbb-cccc" assert_fail "(c) critical advisory fails" "$CRITICAL_ONLY" 2026-12-01 4.0.7
EXPECT="GHSA-dddd-eeee-ffff" assert_fail "(c) second picomatch advisory is not covered by the first exception" "$MIXED_CHAIN" 2026-12-01 4.0.7
EXPECT="GHSA-aaaa-bbbb-cccc" assert_fail "(c) dependent whose via holds picomatch and a different GHSA fails" "$DEPENDENT_MIXED_VIA" 2026-12-01 4.0.7
EXPECT="GHSA-aaaa-bbbb-cccc" assert_fail "(c) via cycle containing a non-exempt advisory fails" "$CYCLE_WITH_OTHER" 2026-12-01 4.0.7
EXPECT="unresolvable" assert_fail "(c) via naming a package absent from the report fails" "$DANGLING_VIA" 2026-12-01 4.0.7
EXPECT="does not match exception package" assert_fail "(c) exempt id reported for a different package name fails" "$SPOOF" 2026-12-01 4.0.7

# (d) patched release published
EXPECT="patched release published" assert_fail "(d) fails when a newer picomatch is published" "$PICO_ONLY" 2026-12-01 4.0.8
EXPECT="patched release published" assert_fail "(d) newer major published fails" "$PICO_ONLY" 2026-12-01 5.0.0
EXPECT="patched release published" assert_fail "(d) version sort is numeric (4.0.10 > 4.0.7)" "$PICO_ONLY" 2026-12-01 4.0.10
assert_pass "(d) passes when published equals locked" "$PICO_ONLY" 2026-12-01 4.0.7
assert_pass "(d) older published than locked does not fail" "$PICO_ONLY" 2026-12-01 4.0.6

# (e) fail closed
EXPECT="no output" assert_fail "(e) empty npm audit output fails" "" 2026-12-01 4.0.7
EXPECT=".vulnerabilities" assert_fail "(e) JSON without .vulnerabilities fails" "$NO_VULNERABILITIES" 2026-12-01 4.0.7
EXPECT=".vulnerabilities" assert_fail "(e) npm error document fails" "$NPM_ERROR" 2026-12-01 4.0.7
EXPECT=".vulnerabilities" assert_fail "(e) non-JSON output fails" "Error: getaddrinfo ENOTFOUND" 2026-12-01 4.0.7
EXPECT="exception file not found" assert_fail "(e) missing exception file fails" "$PICO_ONLY" 2026-12-01 4.0.7 "$WORK/does-not-exist.txt"

# Unreachable npm view (nothing injected; the stand-in npm fails).
FAKE_VIEW_FAIL=1 run_gate_npm_view "$PICO_ONLY"
if [ "$RC" -ne 0 ] && grep -q "npm view failed" <<<"$OUT"; then _pass "(e) unreachable npm view fails closed"; else _fail "(e) unreachable npm view (rc=$RC): $OUT"; fi

FAKE_VIEW="" run_gate_npm_view "$PICO_ONLY"
if [ "$RC" -ne 0 ] && grep -q "npm view failed" <<<"$OUT"; then _pass "(e) empty npm view answer fails closed"; else _fail "(e) empty npm view answer (rc=$RC): $OUT"; fi

FAKE_VIEW=4.0.7 run_gate_npm_view "$PICO_ONLY"
if [ "$RC" -eq 0 ]; then _pass "(d) npm view answer equal to locked passes"; else _fail "(d) npm view equal to locked (rc=$RC): $OUT"; fi

FAKE_VIEW=4.1.0 run_gate_npm_view "$PICO_ONLY"
if [ "$RC" -ne 0 ]; then _pass "(d) npm view answer newer than locked fails"; else _fail "(d) npm view newer than locked passed: $OUT"; fi

# A lockfile without picomatch cannot prove the version relation: fail closed.
FAKE_VIEW=4.0.7 LOCK="$WORK/package-lock-nopico.json" run_gate_npm_view "$PICO_ONLY"
if [ "$RC" -ne 0 ] && grep -q "no resolved 'picomatch'" <<<"$OUT"; then _pass "(e) lockfile without picomatch fails closed"; else _fail "(e) lockfile without picomatch (rc=$RC): $OUT"; fi

# (f) malformed exception entries — each alone must fail the gate on a clean report.
bad=0
assert_bad_entry() { # name content
    bad=$((bad + 1))
    printf '%s\n' "$2" >"$WORK/bad-$bad.txt"
    assert_fail "(f) $1" "$CLEAN" 2026-12-01 4.0.7 "$WORK/bad-$bad.txt"
}
assert_bad_entry "missing until=" "GHSA-fc5q-39xc-vjpf package=picomatch"
assert_bad_entry "empty until=" "GHSA-fc5q-39xc-vjpf package=picomatch until="
assert_bad_entry "unparseable date" "GHSA-fc5q-39xc-vjpf package=picomatch until=not-a-date"
assert_bad_entry "impossible calendar date" "GHSA-fc5q-39xc-vjpf package=picomatch until=2026-02-31"
assert_bad_entry "wrong date format" "GHSA-fc5q-39xc-vjpf package=picomatch until=12-02-2026"
assert_bad_entry "non zero-padded date" "GHSA-fc5q-39xc-vjpf package=picomatch until=2026-12-2"
assert_bad_entry "wildcard id" "GHSA-* package=picomatch until=2026-12-02"
assert_bad_entry "partial wildcard id" "GHSA-fc5q-39xc-???? package=picomatch until=2026-12-02"
assert_bad_entry "prefix id" "GHSA-fc5q package=picomatch until=2026-12-02"
assert_bad_entry "non-GHSA literal (CVE)" "CVE-2026-12345 package=picomatch until=2026-12-02"
assert_bad_entry "non-GHSA literal (package name)" "picomatch package=picomatch until=2026-12-02"
assert_bad_entry "missing package=" "GHSA-fc5q-39xc-vjpf until=2026-12-02"
assert_bad_entry "unknown token" "GHSA-fc5q-39xc-vjpf package=picomatch until=2026-12-02 extra"
assert_bad_entry "duplicate id" "GHSA-fc5q-39xc-vjpf package=picomatch until=2026-12-02
GHSA-fc5q-39xc-vjpf package=picomatch until=2026-12-01"
assert_bad_entry "malformed second entry after a good one" "GHSA-fc5q-39xc-vjpf package=picomatch until=2026-12-02
GHSA-aaaa-bbbb-cccc package=other until=bad"

# (g) moderate / low findings never fail
assert_pass "(g) moderate and low findings pass" "$MODERATE_LOW_ONLY" 2026-12-01 4.0.7
assert_pass "(g) moderate and low findings pass after expiry" "$MODERATE_LOW_ONLY" 2027-01-01 4.0.7
assert_pass "clean audit passes" "$CLEAN" 2026-12-01 4.0.7

# Invalid injected date fails closed.
assert_fail "invalid injected today fails" "$PICO_ONLY" 2026-13-45 4.0.7

# ---------------------------------------------------------------------------
# The committed exception file and package.json wiring.
# ---------------------------------------------------------------------------
REAL_EXC="$REPO_ROOT/web/npm-audit-exceptions.txt"
entries="$(sed 's/#.*$//' "$REAL_EXC" | grep -cE '[^[:space:]]')"
if [ "$entries" = "1" ] && grep -qE '^GHSA-fc5q-39xc-vjpf package=picomatch until=2026-12-02[[:space:]]*$' "$REAL_EXC"; then
    _pass "committed exception file has exactly the GHSA-fc5q-39xc-vjpf entry, until=2026-12-02"
else
    _fail "committed exception file must contain exactly one entry: GHSA-fc5q-39xc-vjpf package=picomatch until=2026-12-02"
fi
assert_pass "committed exception file applies on 2026-12-01" "$PICO_ONLY" 2026-12-01 4.0.7 "$REAL_EXC"
assert_fail "committed exception file lapses on 2026-12-02" "$PICO_ONLY" 2026-12-02 4.0.7 "$REAL_EXC"

if grep -q '"audit": "bash ../scripts/npm-audit-gate.sh"' "$REPO_ROOT/web/package.json"; then
    _pass "web/package.json audit script runs the gate"
else
    _fail "web/package.json audit script must be: bash ../scripts/npm-audit-gate.sh"
fi

echo ""
echo "=== Results: $PASS_COUNT passed, $FAIL_COUNT failed ==="
[ "$FAIL_COUNT" -eq 0 ]
