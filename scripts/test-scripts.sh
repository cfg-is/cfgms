#!/bin/bash
# Test Script Validation
# Runs smoke tests on all critical shell scripts to catch syntax/logic errors

set -euo pipefail

# Python's stdout defaults to the Windows console codepage (cp1252) unless
# told otherwise, which crashes print() on any emoji/Unicode output --
# confirmed on generate-mockups-index.py's ✅ and resolve_conflict.test.sh's
# embedded checker's → (Issue #3686). Set once here rather than patching every
# script this suite invokes.
export PYTHONIOENCODING=utf-8

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

PASS_COUNT=0
FAIL_COUNT=0

log_test() {
    echo -e "${BLUE}▶${NC} $1"
}

log_pass() {
    echo -e "${GREEN}✓${NC} $1"
    ((PASS_COUNT++)) || true
}

log_fail() {
    echo -e "${RED}✗${NC} $1"
    ((FAIL_COUNT++)) || true
}

log_skip() {
    echo -e "${YELLOW}⊘${NC} $1"
}

# --group <name>[,<name>...] narrows the run to one or more of the named
# suite groups (Issue #4301). No flag at all ⇒ run everything, unchanged from
# before this flag existed — the only calling convention any caller uses today.
VALID_GROUPS=(core devinfra)
GROUP_FLAG_GIVEN=false
declare -A SELECTED_GROUPS=()

usage() {
    echo "Usage: $0 [--group <name>[,<name>...]]" >&2
    echo "  Valid groups: ${VALID_GROUPS[*]}" >&2
}

is_valid_group() {
    local candidate="$1" vg
    for vg in "${VALID_GROUPS[@]}"; do
        [[ "$candidate" == "$vg" ]] && return 0
    done
    return 1
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --group)
            if [[ $# -lt 2 ]]; then
                echo "❌ --group requires a value" >&2
                usage
                exit 1
            fi
            GROUP_FLAG_GIVEN=true
            IFS=',' read -ra _requested_groups <<< "$2"
            for _g in "${_requested_groups[@]}"; do
                if ! is_valid_group "$_g"; then
                    echo "❌ Unknown --group value: '${_g}'" >&2
                    usage
                    exit 1
                fi
                SELECTED_GROUPS["$_g"]=1
            done
            shift 2
            ;;
        *)
            echo "❌ Unknown argument: $1" >&2
            usage
            exit 1
            ;;
    esac
done

group_selected() {
    [[ -n "${SELECTED_GROUPS[$1]:-}" ]]
}

# Test 1: Validate syntax of all shell scripts
test_syntax() {
    log_test "Testing shell script syntax..."

    local scripts_tested=0
    for script in scripts/*.sh .github/scripts/*.sh; do
        if [ -f "$script" ]; then
            if bash -n "$script" 2>/dev/null; then
                log_pass "$(basename "$script"): Valid syntax"
                ((scripts_tested++)) || true
            else
                log_fail "$(basename "$script"): Syntax error"
            fi
        fi
    done

    echo "  Tested $scripts_tested scripts"
}

# Test 3: License header checker
test_license_checker() {
    log_test "Testing license header checker..."

    if [ -f scripts/check-license-headers.sh ]; then
        # Just verify it runs without crashing (may find missing headers, that's ok)
        if bash scripts/check-license-headers.sh >/dev/null 2>&1 || [ $? -eq 1 ]; then
            log_pass "check-license-headers.sh: Executes without crash"
        else
            log_fail "check-license-headers.sh: Crashed"
        fi
    else
        log_skip "check-license-headers.sh: Not found"
    fi
}

# Test: mockups index structural check (Issues #3042, #3166)
# check-mockups-index.sh is the structural backstop for the generated index:
# it must pass on the real README and must reject a duplicated row or header,
# so that any corruption (e.g. from a bad merge resolution) is caught in CI.
# Also exercises the generator freshness check: the committed README.md must
# match what scripts/generate-mockups-index.py produces from current *.yaml
# metadata.
test_check_mockups_index() {
    log_test "Testing mockups index structural check..."

    if [ ! -f scripts/check-mockups-index.sh ]; then
        log_fail "check-mockups-index.sh: Not found (Issue #3042 requires it)"
        return
    fi

    if bash scripts/check-mockups-index.sh docs/design/mockups/README.md >/dev/null 2>&1; then
        log_pass "check-mockups-index.sh: Passes against the real, deduplicated index"
    else
        log_fail "check-mockups-index.sh: Rejected the real index (should be clean)"
    fi

    local tmp_dupe
    tmp_dupe=$(mktemp)
    cp docs/design/mockups/README.md "$tmp_dupe"
    # Duplicate the first row — catches any accidental double-inclusion.
    sed -n '/^| \[`/{p;q}' docs/design/mockups/README.md >> "$tmp_dupe"

    if bash scripts/check-mockups-index.sh "$tmp_dupe" >/dev/null 2>&1; then
        log_fail "check-mockups-index.sh: Did not detect a duplicated row"
    else
        log_pass "check-mockups-index.sh: Detects a duplicated row (fails loudly)"
    fi

    rm -f "$tmp_dupe"
}

# Test: mockups index generator (Issue #3166)
# Verifies that scripts/generate-mockups-index.py:
#   1. Produces output that matches the committed README.md (freshness check).
#   2. Detects drift when a new *.yaml is present but README is not regenerated.
#   3. Fixes the drift with --write (demonstrating the no-shared-edit contract:
#      adding a mockup requires only new html+yaml files, then one generator run).
test_mockups_index_generator() {
    log_test "Testing mockups index generator (Issue #3166)..."

    if [ ! -f scripts/generate-mockups-index.py ]; then
        log_fail "generate-mockups-index.py: Not found (Issue #3166 requires it)"
        return
    fi

    # 1. Freshness: committed README must match generator output right now.
    local gen_out rc=0
    gen_out=$(python3 scripts/generate-mockups-index.py --check 2>&1) || rc=$?
    if [ "$rc" -eq 0 ]; then
        log_pass "generate-mockups-index.py --check: committed README matches *.yaml metadata"
    else
        log_fail "generate-mockups-index.py --check: README is stale — $gen_out"
        return
    fi

    # 2. Drift detection: add a dummy *.yaml, README is not yet regenerated.
    local tmp_dir
    tmp_dir=$(mktemp -d)

    # Mirror the mockups dir into tmp so we can add a yaml without touching the repo.
    cp -r docs/design/mockups/. "$tmp_dir/"
    cat > "${tmp_dir}/test-only-fixture.yaml" <<'YAML'
file: test-only-fixture.html
order: 999
status: Test
what: Ephemeral fixture used by test_mockups_index_generator only.
YAML

    # Run the generator against the temp dir (monkeypatched paths via env).
    # We need the generator to read from tmp_dir but compare against the real README.
    # Build a self-contained test: copy the current README into tmp_dir too, then
    # run --check pointing the generator at tmp_dir. We do this by running the
    # generator's --write against a copy of README.
    local tmp_readme="${tmp_dir}/README.md"
    cp docs/design/mockups/README.md "$tmp_readme"

    # Inline the generator logic against our temp dir to simulate the "stale" state:
    # the tmp README was generated without the fixture yaml; with it present, --write
    # should produce a different file.
    python3 - "$tmp_dir" "$tmp_readme" <<'PYEOF'
import sys, os, re

mockups_dir = sys.argv[1]
readme_path = sys.argv[2]

BEGIN = "<!-- BEGIN GENERATED TABLE -->"
END   = "<!-- END GENERATED TABLE -->"

def parse(p):
    m = {}
    with open(p, encoding="utf-8") as f:
        for ln in f:
            ln = ln.rstrip("\n").strip()
            if ln and not ln.startswith("#"):
                k, _, v = ln.partition(":")
                m[k.strip()] = v.strip()
    return m

entries = []
for fn in sorted(os.listdir(mockups_dir)):
    if fn.endswith(".yaml"):
        e = parse(os.path.join(mockups_dir, fn))
        if "file" in e:
            entries.append(e)
entries.sort(key=lambda e: (int(e.get("order", 999)), e.get("file", "")))

lines = [BEGIN, "| File | What it is | Status |", "|------|------------|--------|"]
for e in entries:
    lines.append(f"| [`{e['file']}`]({e['file']}) | {e.get('what','')} | {e.get('status','')} |")
lines.append(END)
section = "\n".join(lines)

with open(readme_path, encoding="utf-8") as f:
    cur = f.read()
bi = cur.find(BEGIN)
ei = cur.find(END)
updated = cur[:bi] + section + cur[ei + len(END):]
with open(readme_path, "w", encoding="utf-8") as f:
    f.write(updated)
PYEOF

    # tmp_readme now has the fixture row; the real README does not — they differ.
    if diff -q docs/design/mockups/README.md "$tmp_readme" >/dev/null 2>&1; then
        log_fail "generator drift test: adding a yaml did not change the generated output"
    else
        log_pass "generator drift test: new yaml produces different output (drift detected)"
    fi

    # 3. --write on the real repo is idempotent (the committed README is already
    #    current, so --write should not change it).
    local before_hash after_hash
    before_hash=$(sha256sum docs/design/mockups/README.md | awk '{print $1}')
    python3 scripts/generate-mockups-index.py --write >/dev/null 2>&1
    after_hash=$(sha256sum docs/design/mockups/README.md | awk '{print $1}')
    if [ "$before_hash" = "$after_hash" ]; then
        log_pass "generator --write: idempotent when README is already current"
    else
        log_fail "generator --write: unexpectedly changed a current README"
    fi

    rm -rf "$tmp_dir"
}

# Test: log-injection linter wrapper (Issue #1771 AC #1)
# The wrapper is a thin shim over `go run ./scripts/lint-log-injection`. Both
# the Makefile target and the pre-commit hook invoke the Go binary directly,
# so without this smoke test the wrapper's runtime path (cd to repo root,
# exec the linter) has no functional coverage — a silent breakage (e.g. wrong
# relative path after a repo restructure) would slip past `bash -n`.
test_log_injection_linter() {
    log_test "Testing log-injection linter wrapper..."

    if [ ! -f scripts/lint-log-injection.sh ]; then
        log_fail "lint-log-injection.sh: Not found (Issue #1771 AC #1 requires it)"
        return
    fi

    if [ ! -x scripts/lint-log-injection.sh ]; then
        log_fail "lint-log-injection.sh: Not executable"
        return
    fi

    # Wrapper must succeed from a CWD outside the repo — its job is to cd to
    # the repo root before invoking `go run`. Running it from /tmp catches the
    # class of regression where the script trusts caller CWD.
    local tmp_cwd
    tmp_cwd=$(mktemp -d)
    local script_abs
    script_abs="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lint-log-injection.sh"

    # Capture stderr so a CI failure shows the underlying go/lint diagnostic
    # (the test previously discarded it, leaving "broken cd?" as the only clue).
    # The `|| rc=$?` form is load-bearing: this file runs under `set -e`, so a
    # bare `(...); rc=$?` would abort the whole suite the instant the wrapper
    # returns non-zero — silently skipping the log_fail diagnostic and leaving
    # CI showing "❌ Script tests failed" with no clue why.
    local out_file rc=0
    out_file=$(mktemp)
    (cd "$tmp_cwd" && "$script_abs") >"$out_file" 2>&1 || rc=$?
    if [ "$rc" -eq 0 ]; then
        log_pass "lint-log-injection.sh: Exits 0 on clean tree from foreign CWD"
    elif [ "$rc" -eq 1 ]; then
        # TEMPORARY (Issue #4088, tracked by follow-up #4103): #4088 widened
        # the taint model, and its repo-wide run surfaced a set of residual
        # findings — each individually traced during #4088 and confirmed a
        # false positive (server-generated IDs, crypto-random values, fixed
        # hardcoded vocabularies, and three named linter-precision gaps; see
        # the #4088 PR description and #4103 for the full root-cause
        # breakdown).
        #
        # #4089 (same-package interprocedural parameter-taint propagation)
        # fixed the new findings its own widening surfaced, and — as a side
        # effect of the same-package result-type resolution that work needed
        # anyway — shrank this snapshot from 40 to 31: the linter can now pin
        # the static type of a value returned by a same-package callee, so
        # scalar counters it previously flagged (handlers_accounts.go's revoked
        # counts, handlers_stewards.go's page.Total and tail) are suppressed
        # correctly rather than sanitized at the call site. Two entries also
        # moved to their true line numbers (handlers_runs.go 519 -> 529,
        # handlers_upgrade.go 589 -> 593), correcting pre-existing staleness in
        # the #4088 snapshot. The remaining 31 are the same-package baseline
        # #4103 is expected to own; none is #4089's to fix.
        #
        # This is a pinned SNAPSHOT, not a blanket allowlist: any finding
        # outside this exact set — new OR missing — still fails the test below,
        # loudly, so this list must be updated (normally shrunk) as #4103
        # lands. Delete this branch entirely once #4103 restores a clean,
        # zero-finding tree.
        local known_findings
        known_findings=$(cat <<'EOF'
features/controller/api/handlers_certificates.go:135: tainted value "err" logged without logging.SanitizeLogValue
features/controller/api/handlers_certificates.go:168: tainted value "err" logged without logging.SanitizeLogValue
features/controller/api/handlers_certificates.go:206: tainted value "err" logged without logging.SanitizeLogValue
features/controller/api/handlers_credential_requests_collect.go:311: tainted value "issued.SerialNumber" logged without logging.SanitizeLogValue
features/controller/api/handlers_jobs.go:219: tainted value "err" logged without logging.SanitizeLogValue
features/controller/api/handlers_registration.go:741: tainted value "err" logged without logging.SanitizeLogValue
features/controller/api/handlers_registration.go:768: tainted value "err" logged without logging.SanitizeLogValue
features/controller/api/handlers_registration.go:843: tainted value "token.ExpiresAt" logged without logging.SanitizeLogValue
features/controller/api/handlers_registration.go:1018: tainted value "pendingID" logged without logging.SanitizeLogValue
features/controller/api/handlers_registration.go:1021: tainted value "pendingID" logged without logging.SanitizeLogValue
features/controller/api/handlers_registration.go:1028: tainted value "pendingID" logged without logging.SanitizeLogValue
features/controller/api/handlers_registration_refresh.go:688: tainted value "err" logged without logging.SanitizeLogValue
features/controller/api/handlers_registration_refresh.go:710: tainted value "err" logged without logging.SanitizeLogValue
features/controller/api/handlers_registration_tokens.go:155: tainted value "err" logged without logging.SanitizeLogValue
features/controller/api/handlers_registration_tokens.go:171: tainted value "err" logged without logging.SanitizeLogValue
features/controller/api/handlers_rollout.go:244: tainted value "qErr" logged without logging.SanitizeLogValue
features/controller/api/handlers_runs.go:399: tainted value "patternName" logged without logging.SanitizeLogValue
features/controller/api/handlers_runs.go:529: tainted value "err" logged without logging.SanitizeLogValue
features/controller/api/handlers_scripts.go:321: tainted value "err" logged without logging.SanitizeLogValue
features/controller/api/handlers_scripts.go:433: tainted value "err" logged without logging.SanitizeLogValue
features/controller/api/handlers_scripts.go:459: tainted value "since" logged without logging.SanitizeLogValue
features/controller/api/handlers_signing_credential.go:137: tainted value "issuedCert.SerialNumber" logged without logging.SanitizeLogValue
features/controller/api/handlers_stewards.go:168: tainted value "searchErr" logged without logging.SanitizeLogValue
features/controller/api/handlers_stewards.go:591: tainted value "matched" logged without logging.SanitizeLogValue
features/controller/api/handlers_stewards.go:1490: tainted value "err" logged without logging.SanitizeLogValue
features/controller/api/handlers_test_admin.go:103: tainted value "err" logged without logging.SanitizeLogValue
features/controller/api/handlers_test_admin.go:110: tainted value "err" logged without logging.SanitizeLogValue
features/controller/api/handlers_upgrade.go:280: tainted value "createErr" logged without logging.SanitizeLogValue
features/controller/api/handlers_upgrade.go:593: tainted value "createErr" logged without logging.SanitizeLogValue
features/workflow/debug_api.go:76: tainted value "session.ID" logged without logging.SanitizeLogValue
features/workflow/debug_api.go:228: tainted value "breakpoint.ID" logged without logging.SanitizeLogValue
EOF
)
        local actual_findings
        actual_findings=$(grep -E '^  features/.*: tainted value' "$out_file" | sed 's/^  //' || true)

        # Compare on (file, message) only, never the embedded line number.
        # Unrelated merges routinely shift line numbers within these files
        # without touching the flagged statement itself (Issue #4113 — this
        # exact drift broke `make test` on a clean develop twice: #4088's
        # snapshot going stale between PRs, corrected by #4089, then drifting
        # again). Baking the line number into the compared key means the next
        # unrelated edit to either file reintroduces the same false failure,
        # so strip it from both sides before comparing; sort so a same-file
        # reordering of findings doesn't register as a diff either.
        local strip_line='s/^([^:]+):[0-9]+:/\1:/'
        local known_normalized actual_normalized
        known_normalized=$(echo "$known_findings" | sed -E "$strip_line" | sort)
        actual_normalized=$(echo "$actual_findings" | sed -E "$strip_line" | sort)

        if [ "$actual_normalized" == "$known_normalized" ]; then
            log_pass "lint-log-injection.sh: only the tracked #4103 false-positive baseline present (31 findings)"
        else
            log_fail "lint-log-injection.sh: findings differ from the tracked #4103 baseline (rc=$rc) — output below"
            sed 's/^/    /' "$out_file" >&2
        fi
    else
        log_fail "lint-log-injection.sh: Failed from CWD outside repo (rc=$rc) — output below"
        sed 's/^/    /' "$out_file" >&2
    fi

    rm -f "$out_file"
    rm -rf "$tmp_cwd"
}

# Test 4: Invalid certificate generation (dry run)
test_invalid_cert_generation() {
    log_test "Testing invalid certificate generation script..."

    if [ -f scripts/generate-invalid-test-certs.sh ]; then
        # Test with --help or check syntax at minimum
        if bash -n scripts/generate-invalid-test-certs.sh 2>/dev/null; then
            log_pass "generate-invalid-test-certs.sh: Valid syntax"
        else
            log_fail "generate-invalid-test-certs.sh: Syntax error"
        fi
    else
        log_skip "generate-invalid-test-certs.sh: Not found"
    fi
}

# Test 5: Credential generation (dry run)
test_credential_generation() {
    log_test "Testing credential generation script..."

    if [ -f scripts/generate-test-credentials.sh ]; then
        if bash -n scripts/generate-test-credentials.sh 2>/dev/null; then
            log_pass "generate-test-credentials.sh: Valid syntax"
        else
            log_fail "generate-test-credentials.sh: Syntax error"
        fi
    else
        log_skip "generate-test-credentials.sh: Not found"
    fi
}

# Test 6: Wait for services script
test_wait_for_services() {
    log_test "Testing wait-for-services script..."

    if [ -f scripts/wait-for-services.sh ]; then
        # Test --help flag if available, or just syntax
        if bash -n scripts/wait-for-services.sh 2>/dev/null; then
            log_pass "wait-for-services.sh: Valid syntax"
        else
            log_fail "wait-for-services.sh: Syntax error"
        fi
    else
        log_skip "wait-for-services.sh: Not found"
    fi
}

# Test 7: Verify scripts are executable
test_executable_permissions() {
    log_test "Testing script executable permissions..."

    local critical_scripts=(
        "scripts/generate-invalid-test-certs.sh"
        "scripts/generate-test-credentials.sh"
        "scripts/wait-for-services.sh"
        "scripts/test-with-infrastructure.sh"
        "scripts/tier1-smoke-test.sh"
        "scripts/tier1-smoke-test_test.sh"
        "scripts/tier1-bootstrap.sh"
        "scripts/tier1-bootstrap_test.sh"
        "scripts/check-binary-artifacts.sh"
        "scripts/check-binary-artifacts_test.sh"
        "scripts/go-fetch-retry.sh"
        "scripts/go-fetch-retry_test.sh"
        "scripts/check-docs-boundary.sh"
        "scripts/check-docs-boundary_test.sh"
        "scripts/install-git-hooks.sh"
        "scripts/install-git-hooks_test.sh"
        "scripts/verify-nancy-ignore-scope.sh"
        "scripts/verify-nancy-ignore-scope_test.sh"
        "scripts/lab-datasvc-bootstrap.sh"
        "scripts/lab-datasvc-bootstrap_test.sh"
        "scripts/ha-cluster-node-bootstrap.sh"
        "scripts/ha-cluster-node-bootstrap_test.sh"
        "scripts/cfgms-bundle-load"
    )

    for script in "${critical_scripts[@]}"; do
        if [ -f "$script" ]; then
            if [ -x "$script" ]; then
                log_pass "$(basename "$script"): Executable"
            else
                log_fail "$(basename "$script"): Not executable (chmod +x needed)"
            fi
        fi
    done
}








# Test check-providers.sh: exit-code behaviour (AC 2 through AC 5)
test_check_providers() {
    log_test "Testing check-providers.sh exit-code behaviour..."

    local script
    script="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/check-providers.sh"

    local tmp_dir
    tmp_dir=$(mktemp -d)

    # Initialise a minimal git repo so git ls-files works
    git init "$tmp_dir" >/dev/null 2>&1
    git -C "$tmp_dir" config user.email "test@test.com"
    git -C "$tmp_dir" config user.name "Test"

    # --- AC2: clean tree exits 0 -----------------------------------------
    local output
    local exit_code
    exit_code=0
    output=$(cd "$tmp_dir" && bash "$script" 2>&1) || exit_code=$?
    if [ "$exit_code" -eq 0 ]; then
        log_pass "check-providers.sh: Exits 0 on clean tree (AC 2)"
    else
        log_fail "check-providers.sh: Should exit 0 on clean tree (exit $exit_code, output: $output)"
    fi
    if echo "$output" | grep -q "No storage provider import violations found."; then
        log_pass "check-providers.sh: Prints clean summary on empty tree (AC 2)"
    else
        log_fail "check-providers.sh: Missing clean summary line (output: $output)"
    fi

    # --- AC3: tracked violation exits 1, output must include file:line -----
    mkdir -p "$tmp_dir/pkg/somefeature"
    cat > "$tmp_dir/pkg/somefeature/foo.go" << 'GOEOF'
package somefeature

import _ "github.com/cfgis/cfgms/pkg/storage/providers/git"
GOEOF
    git -C "$tmp_dir" add pkg/somefeature/foo.go >/dev/null 2>&1
    git -C "$tmp_dir" commit -m "add violation" >/dev/null 2>&1

    exit_code=0
    output=$(cd "$tmp_dir" && bash "$script" 2>&1) || exit_code=$?
    if [ "$exit_code" -eq 1 ]; then
        log_pass "check-providers.sh: Exits 1 when violation found (AC 3)"
    else
        log_fail "check-providers.sh: Should exit 1 when violation found (exit $exit_code)"
    fi
    # AC 3 requires file:line format, not just filename
    if echo "$output" | grep -qE "pkg/somefeature/foo.go:[0-9]+:"; then
        log_pass "check-providers.sh: Reports file:line in violation output (AC 3)"
    else
        log_fail "check-providers.sh: Should report file:line format (output: $output)"
    fi

    # Remove the violation before testing allowed paths
    git -C "$tmp_dir" rm pkg/somefeature/foo.go >/dev/null 2>&1
    git -C "$tmp_dir" commit -m "remove violation" >/dev/null 2>&1

    # --- AC4: all 7 allowed paths do NOT trigger violations -----------------
    # Each path gets its own add/check/remove cycle on a clean base tree.
    local allowed_paths
    allowed_paths=(
        "pkg/storage/providers/myprovider/foo.go"
        "pkg/testing/foo.go"
        "test/integration/foo.go"
        "cmd/controller/main.go"
        "cmd/cfg/cmd/storage.go"
        "features/controller/initialization/initialization.go"
        "features/controller/server/server.go"
        "features/rbac/continuous/providers_test.go"
        "pkg/audit/providers_test.go"
    )
    local allowed_file
    for allowed_file in "${allowed_paths[@]}"; do
        mkdir -p "$tmp_dir/$(dirname "$allowed_file")"
        printf 'package p\n\nimport _ "github.com/cfgis/cfgms/pkg/storage/providers/git"\n' \
            > "$tmp_dir/$allowed_file"
        git -C "$tmp_dir" add "$allowed_file" >/dev/null 2>&1
        git -C "$tmp_dir" commit -m "add allowed $allowed_file" >/dev/null 2>&1

        exit_code=0
        output=$(cd "$tmp_dir" && bash "$script" 2>&1) || exit_code=$?
        if [ "$exit_code" -eq 0 ]; then
            log_pass "check-providers.sh: Allowed path '$allowed_file' does not trigger (AC 4)"
        else
            log_fail "check-providers.sh: Allowed path '$allowed_file' should not trigger (exit $exit_code)"
        fi

        git -C "$tmp_dir" rm "$allowed_file" >/dev/null 2>&1
        git -C "$tmp_dir" commit -m "remove $allowed_file" >/dev/null 2>&1
    done

    # --- AC5: --staged-only scans only staged files -------------------------
    # Untracked/unstaged violation must be ignored
    mkdir -p "$tmp_dir/pkg/unstaged"
    cat > "$tmp_dir/pkg/unstaged/bar.go" << 'GOEOF'
package unstaged

import _ "github.com/cfgis/cfgms/pkg/storage/providers/git"
GOEOF
    # Do NOT git add — file is untracked and unstaged

    exit_code=0
    output=$(cd "$tmp_dir" && bash "$script" --staged-only 2>&1) || exit_code=$?
    if [ "$exit_code" -eq 0 ]; then
        log_pass "check-providers.sh: --staged-only ignores unstaged violation (AC 5)"
    else
        log_fail "check-providers.sh: --staged-only should ignore unstaged file (exit $exit_code, output: $output)"
    fi

    # Stage the violation and verify --staged-only now catches it
    git -C "$tmp_dir" add pkg/unstaged/bar.go >/dev/null 2>&1

    exit_code=0
    output=$(cd "$tmp_dir" && bash "$script" --staged-only 2>&1) || exit_code=$?
    if [ "$exit_code" -eq 1 ]; then
        log_pass "check-providers.sh: --staged-only detects staged violation (AC 5)"
    else
        log_fail "check-providers.sh: --staged-only should detect staged violation (exit $exit_code)"
    fi

    rm -rf "$tmp_dir"
}

# Fixture suite for scripts/check-binary-artifacts.sh — the compiled-artifact
# merge gate. Delegates to scripts/check-binary-artifacts_test.sh, which builds
# throwaway git repositories and asserts every magic signature, the extension
# fallback, and the fail-closed paths.
test_check_binary_artifacts() {
    log_test "Testing check-binary-artifacts.sh..."

    local gate_script="scripts/check-binary-artifacts.sh"
    local test_script="scripts/check-binary-artifacts_test.sh"

    if [[ ! -f "$gate_script" ]]; then
        log_fail "check-binary-artifacts.sh: Not found"
        return
    fi

    if [[ ! -x "$gate_script" ]]; then
        log_fail "check-binary-artifacts.sh: Not executable (chmod +x needed)"
        return
    fi

    if [[ ! -f "$test_script" ]]; then
        log_fail "check-binary-artifacts_test.sh: Not found"
        return
    fi

    if [[ ! -x "$test_script" ]]; then
        log_fail "check-binary-artifacts_test.sh: Not executable (chmod +x needed)"
        return
    fi

    local out_file rc=0
    out_file=$(mktemp)
    bash "$test_script" >"$out_file" 2>&1 || rc=$?

    if [[ $rc -eq 0 ]]; then
        log_pass "check-binary-artifacts_test.sh: All fixture tests passed"
    else
        log_fail "check-binary-artifacts_test.sh: Fixture tests failed (exit $rc)"
        sed 's/^/    /' "$out_file" >&2
    fi
    rm -f "$out_file"
}

# Fixture suite for scripts/go-fetch-retry.sh — the retry wrapper for transient
# Go module proxy errors. Delegates to scripts/go-fetch-retry_test.sh, which puts
# a stub `go` on PATH and asserts retry, give-up, fail-fast and exit-code behaviour.
test_go_fetch_retry() {
    log_test "Testing go-fetch-retry.sh..."

    local wrapper="scripts/go-fetch-retry.sh"
    local test_script="scripts/go-fetch-retry_test.sh"

    if [[ ! -f "$wrapper" ]]; then
        log_fail "go-fetch-retry.sh: Not found"
        return
    fi

    if [[ ! -x "$wrapper" ]]; then
        log_fail "go-fetch-retry.sh: Not executable (chmod +x needed)"
        return
    fi

    if [[ ! -f "$test_script" ]]; then
        log_fail "go-fetch-retry_test.sh: Not found"
        return
    fi

    if [[ ! -x "$test_script" ]]; then
        log_fail "go-fetch-retry_test.sh: Not executable (chmod +x needed)"
        return
    fi

    local out_file rc=0
    out_file=$(mktemp)
    bash "$test_script" >"$out_file" 2>&1 || rc=$?

    if [[ $rc -eq 0 ]]; then
        log_pass "go-fetch-retry_test.sh: All tests passed"
    else
        log_fail "go-fetch-retry_test.sh: Tests failed (exit $rc)"
        sed 's/^/    /' "$out_file" >&2
    fi
    rm -f "$out_file"
}

# Fixture suite for scripts/check-docs-boundary.sh — the documentation-boundary
# gate (Issue #3417, Epic #3412). Delegates to scripts/check-docs-boundary_test.sh,
# which builds throwaway git repositories and asserts both execution paths: exit 0
# on a clean docs tree and exit 1 (naming the offending file) on every identifier
# in the gate's own denylist, plus the fail-closed paths.
#
# Also runs the gate against the real docs/ tree, so a document reintroducing a
# private-deployment identifier fails `make test` rather than merging green.
test_check_docs_boundary() {
    log_test "Testing check-docs-boundary.sh..."

    local gate_script="scripts/check-docs-boundary.sh"
    local test_script="scripts/check-docs-boundary_test.sh"

    if [[ ! -f "$gate_script" ]]; then
        log_fail "check-docs-boundary.sh: Not found"
        return
    fi

    if [[ ! -x "$gate_script" ]]; then
        log_fail "check-docs-boundary.sh: Not executable (chmod +x needed)"
        return
    fi

    if [[ ! -f "$test_script" ]]; then
        log_fail "check-docs-boundary_test.sh: Not found"
        return
    fi

    if [[ ! -x "$test_script" ]]; then
        log_fail "check-docs-boundary_test.sh: Not executable (chmod +x needed)"
        return
    fi

    local out_file rc=0
    out_file=$(mktemp)
    bash "$test_script" >"$out_file" 2>&1 || rc=$?

    if [[ $rc -eq 0 ]]; then
        log_pass "check-docs-boundary_test.sh: All fixture tests passed"
    else
        log_fail "check-docs-boundary_test.sh: Fixture tests failed (exit $rc)"
        sed 's/^/    /' "$out_file" >&2
    fi
    rm -f "$out_file"

    rc=0
    out_file=$(mktemp)
    bash "$gate_script" >"$out_file" 2>&1 || rc=$?
    if [[ $rc -eq 0 ]]; then
        log_pass "check-docs-boundary.sh: Real docs/ tree is clean"
    else
        log_fail "check-docs-boundary.sh: Real docs/ tree failed the gate (exit $rc)"
        sed 's/^/    /' "$out_file" >&2
    fi
    rm -f "$out_file"
}

# Fixture suite for scripts/check-no-python-in-core.sh — the core-product
# Python gate (Issue #4303, Epic #4296). Delegates to
# scripts/check-no-python-in-core_test.sh, which builds throwaway git
# repositories and asserts both execution paths: exit 0 on a clean tree and
# exit 1 (naming the offending file) for a planted .py under each of the six
# declared paths, plus the fail-closed path.
#
# Also runs the gate against the real repo, so a .py file reintroduced under
# cmd/, pkg/, features/, api/, web/, or test/ fails `make test` rather than
# merging green.
test_check_no_python_in_core() {
    log_test "Testing check-no-python-in-core.sh..."

    local gate_script="scripts/check-no-python-in-core.sh"
    local test_script="scripts/check-no-python-in-core_test.sh"

    if [[ ! -f "$gate_script" ]]; then
        log_fail "check-no-python-in-core.sh: Not found"
        return
    fi

    if [[ ! -x "$gate_script" ]]; then
        log_fail "check-no-python-in-core.sh: Not executable (chmod +x needed)"
        return
    fi

    if [[ ! -f "$test_script" ]]; then
        log_fail "check-no-python-in-core_test.sh: Not found"
        return
    fi

    if [[ ! -x "$test_script" ]]; then
        log_fail "check-no-python-in-core_test.sh: Not executable (chmod +x needed)"
        return
    fi

    local out_file rc=0
    out_file=$(mktemp)
    bash "$test_script" >"$out_file" 2>&1 || rc=$?

    if [[ $rc -eq 0 ]]; then
        log_pass "check-no-python-in-core_test.sh: All fixture tests passed"
    else
        log_fail "check-no-python-in-core_test.sh: Fixture tests failed (exit $rc)"
        sed 's/^/    /' "$out_file" >&2
    fi
    rm -f "$out_file"

    rc=0
    out_file=$(mktemp)
    bash "$gate_script" >"$out_file" 2>&1 || rc=$?
    if [[ $rc -eq 0 ]]; then
        log_pass "check-no-python-in-core.sh: Real repo tree is clean"
    else
        log_fail "check-no-python-in-core.sh: Real repo tree failed the gate (exit $rc)"
        sed 's/^/    /' "$out_file" >&2
    fi
    rm -f "$out_file"
}

# Fixture suite for scripts/check-build-boundary.sh — the gate that keeps
# controller code out of the steward binary, steward code out of the controller
# binary, and features/controller and features/steward imports out of pkg/
# (Issues #5747, #5887). Delegates to scripts/check-build-boundary_test.sh,
# which builds throwaway Go modules and asserts exit 0 on a clean tree, exit 1
# (naming the package) for each rule's violations, and the fail-closed path for
# each rule. Also runs the gate against the real repo.
test_check_build_boundary() {
    log_test "Testing check-build-boundary.sh..."

    local gate_script="scripts/check-build-boundary.sh"
    local test_script="scripts/check-build-boundary_test.sh"

    if [[ ! -f "$gate_script" ]]; then
        log_fail "check-build-boundary.sh: Not found"
        return
    fi

    if [[ ! -x "$gate_script" ]]; then
        log_fail "check-build-boundary.sh: Not executable (chmod +x needed)"
        return
    fi

    if [[ ! -f "$test_script" ]]; then
        log_fail "check-build-boundary_test.sh: Not found"
        return
    fi

    if [[ ! -x "$test_script" ]]; then
        log_fail "check-build-boundary_test.sh: Not executable (chmod +x needed)"
        return
    fi

    local out_file rc=0
    out_file=$(mktemp)
    bash "$test_script" >"$out_file" 2>&1 || rc=$?

    if [[ $rc -eq 0 ]]; then
        log_pass "check-build-boundary_test.sh: All fixture tests passed"
    else
        log_fail "check-build-boundary_test.sh: Fixture tests failed (exit $rc)"
        sed 's/^/    /' "$out_file" >&2
    fi
    rm -f "$out_file"

    rc=0
    out_file=$(mktemp)
    bash "$gate_script" >"$out_file" 2>&1 || rc=$?
    if [[ $rc -eq 0 ]]; then
        log_pass "check-build-boundary.sh: Real repo tree is clean"
    else
        log_fail "check-build-boundary.sh: Real repo tree failed the gate (exit $rc)"
        sed 's/^/    /' "$out_file" >&2
    fi
    rm -f "$out_file"
}

# Fixture suite for scripts/check-no-banned-exec-patterns.sh — the
# banned-execution-pattern gate for windows-setup.ps1 and the script
# templates (Issue #4343). Delegates to
# scripts/check-no-banned-exec-patterns_test.sh, which asserts each banned
# pattern (iex, Invoke-Expression, powershell -Command "<string>",
# -EncodedCommand, -ExecutionPolicy Bypass, bash -c "<string>", eval,
# python -c) is independently detected, that a comment merely naming one does
# not self-trip, and that the gate fails closed on a missing file.
#
# Also runs the gate against the real repo, so a piped-installer or
# composed-command-string pattern reintroduced into windows-setup.ps1 or
# either template fails `make test` rather than merging green.
test_check_no_banned_exec_patterns() {
    log_test "Testing check-no-banned-exec-patterns.sh..."

    local gate_script="scripts/check-no-banned-exec-patterns.sh"
    local test_script="scripts/check-no-banned-exec-patterns_test.sh"

    if [[ ! -f "$gate_script" ]]; then
        log_fail "check-no-banned-exec-patterns.sh: Not found"
        return
    fi

    if [[ ! -x "$gate_script" ]]; then
        log_fail "check-no-banned-exec-patterns.sh: Not executable (chmod +x needed)"
        return
    fi

    if [[ ! -f "$test_script" ]]; then
        log_fail "check-no-banned-exec-patterns_test.sh: Not found"
        return
    fi

    if [[ ! -x "$test_script" ]]; then
        log_fail "check-no-banned-exec-patterns_test.sh: Not executable (chmod +x needed)"
        return
    fi

    local out_file rc=0
    out_file=$(mktemp)
    bash "$test_script" >"$out_file" 2>&1 || rc=$?

    if [[ $rc -eq 0 ]]; then
        log_pass "check-no-banned-exec-patterns_test.sh: All fixture tests passed"
    else
        log_fail "check-no-banned-exec-patterns_test.sh: Fixture tests failed (exit $rc)"
        sed 's/^/    /' "$out_file" >&2
    fi
    rm -f "$out_file"

    rc=0
    out_file=$(mktemp)
    bash "$gate_script" >"$out_file" 2>&1 || rc=$?
    if [[ $rc -eq 0 ]]; then
        log_pass "check-no-banned-exec-patterns.sh: Real repo tree is clean"
    else
        log_fail "check-no-banned-exec-patterns.sh: Real repo tree failed the gate (exit $rc)"
        sed 's/^/    /' "$out_file" >&2
    fi
    rm -f "$out_file"
}

# Fixture suite for scripts/check-dead-packages.sh — the package-reachability
# gate (Issue #4317). Delegates to scripts/check-dead-packages_test.sh, which
# builds throwaway Go modules (each with its own go.mod, so `go list` resolves
# offline) and asserts the reachability-closure algorithm: a reachable child of
# an unreachable parent is not flagged, every link of an importer chain that no
# main package reaches IS flagged, allowlisted packages pass, a missing entry
# fails naming only that package, a stale entry fails, test-only-reachable
# packages need no entry, and the gate fails closed (exit 2) outside a module
# root. These assertions are the only thing validating that algorithm, so they
# must run under `make test`, not only under `make check-architecture` — which
# runs the gate but nothing that proves the gate is correct, and which no CI
# workflow invokes at all (`unit-tests-scripts` is this gate's only automated
# runner). Same shape as test_check_no_python_in_core above.
#
# Also runs the gate against the real repo (2s, four `go list` passes), so a
# package that stops being reachable from any main package — or an allowlist
# entry that goes stale — fails `make test` rather than merging green.
test_check_dead_packages() {
    log_test "Testing check-dead-packages.sh..."

    local gate_script="scripts/check-dead-packages.sh"
    local test_script="scripts/check-dead-packages_test.sh"

    if [[ ! -f "$gate_script" ]]; then
        log_fail "check-dead-packages.sh: Not found"
        return
    fi

    if [[ ! -x "$gate_script" ]]; then
        log_fail "check-dead-packages.sh: Not executable (chmod +x needed)"
        return
    fi

    if [[ ! -f "$test_script" ]]; then
        log_fail "check-dead-packages_test.sh: Not found"
        return
    fi

    if [[ ! -x "$test_script" ]]; then
        log_fail "check-dead-packages_test.sh: Not executable (chmod +x needed)"
        return
    fi

    local out_file rc=0
    out_file=$(mktemp)
    bash "$test_script" >"$out_file" 2>&1 || rc=$?

    if [[ $rc -eq 0 ]]; then
        log_pass "check-dead-packages_test.sh: All fixture tests passed"
    else
        log_fail "check-dead-packages_test.sh: Fixture tests failed (exit $rc)"
        sed 's/^/    /' "$out_file" >&2
    fi
    rm -f "$out_file"

    rc=0
    out_file=$(mktemp)
    bash "$gate_script" >"$out_file" 2>&1 || rc=$?
    if [[ $rc -eq 0 ]]; then
        log_pass "check-dead-packages.sh: Real repo has no unallowlisted unreachable package"
    else
        log_fail "check-dead-packages.sh: Real repo failed the gate (exit $rc)"
        sed 's/^/    /' "$out_file" >&2
    fi
    rm -f "$out_file"
}

# Regression guard for the `unit-tests` aggregator's no-Python gate (Issue
# #4303). Extracts the "Aggregate group results" step's actual `run:` block
# from .github/workflows/test-suite.yml -- rather than reimplementing the
# logic by hand, which could drift from what CI really runs or paper over a
# bug in the nested `if:` -- substitutes the `${{ }}` expressions GitHub
# Actions would normally interpolate with test values, and executes it under
# bash to check its exit code and messaging for all three trigger shapes:
#   A. pull_request with a planted .py under pkg/ (no_python_ok=false) -> fail
#   B. a clean pull_request (no_python_ok=true)                        -> pass
#   C. push-to-main / workflow_dispatch, where the `changes` job never runs
#      and no_python_ok is empty                                       -> pass
# Case C is the specific bug this gate must not reintroduce: an unguarded
# `!= 'true'` comparison against an empty output would fail every such run.
test_unit_tests_aggregator_no_python_gate() {
    log_test "Testing unit-tests aggregator's no-Python gate (Issue #4303)..."

    local workflow="${1:-.github/workflows/test-suite.yml}"
    if [[ ! -f "$workflow" ]]; then
        log_fail "unit-tests aggregator no-Python gate: $workflow not found"
        return
    fi

    local block
    block="$(awk '
        /^      - name: Aggregate group results$/ { infound=1; next }
        infound && /^        run: \|$/ { inrun=1; next }
        inrun {
          if ($0 ~ /^          /) { print substr($0, 11) }
          else if ($0 == "") { print "" }
          else { exit }
        }
        ' "$workflow")"

    if [[ -z "$block" ]]; then
        log_fail "unit-tests aggregator no-Python gate: could not extract the 'Aggregate group results' run block from $workflow"
        return
    fi

    # run_case <event_name> <no_python_ok> <code> — substitutes the extracted
    # block's GitHub Actions expressions with the given test values (the five
    # unit-tests-*.result expressions are always "success": this gate only
    # cares about the no_python_ok/code short-circuits ahead of that check),
    # executes it, and sets AGG_RC / AGG_OUT.
    run_case() {
        local event_name="$1" no_python_ok="$2" code="$3"
        local substituted="$block"
        substituted="${substituted//\$\{\{ github.event_name \}\}/$event_name}"
        substituted="${substituted//\$\{\{ needs.changes.outputs.no_python_ok \}\}/$no_python_ok}"
        substituted="${substituted//\$\{\{ needs.changes.outputs.code \}\}/$code}"
        substituted="${substituted//\$\{\{ needs.unit-tests-controller-core.result \}\}/success}"
        substituted="${substituted//\$\{\{ needs.unit-tests-heavy-providers.result \}\}/success}"
        substituted="${substituted//\$\{\{ needs.unit-tests-rest.result \}\}/success}"
        substituted="${substituted//\$\{\{ needs.unit-tests-api.result \}\}/success}"
        substituted="${substituted//\$\{\{ needs.unit-tests-scripts.result \}\}/success}"
        # `|| AGG_RC=$?` is load-bearing: this file runs under `set -e`, and
        # case A below deliberately expects exit 1 — without the `||` guard
        # the bare non-zero exit from this command substitution would abort
        # the whole test-scripts.sh run right here (see the identical fix
        # documented on test_log_injection_linter above).
        AGG_RC=0
        AGG_OUT=$(bash -c "$substituted" 2>&1) || AGG_RC=$?
    }

    # A. PR with a planted .py file under pkg/ — must fail with the named message.
    run_case "pull_request" "false" "true"
    if [[ "$AGG_RC" -eq 1 ]] && [[ "$AGG_OUT" == *"contains a tracked .py file"* ]]; then
        log_pass "aggregator fails a PR with no_python_ok=false, naming the reason"
    else
        log_fail "aggregator should fail (exit 1, naming the reason) when no_python_ok=false on a PR (rc=$AGG_RC, out: $AGG_OUT)"
    fi

    # B. A clean PR — must pass.
    run_case "pull_request" "true" "true"
    if [[ "$AGG_RC" -eq 0 ]]; then
        log_pass "aggregator passes a clean PR (no_python_ok=true)"
    else
        log_fail "aggregator should pass a clean PR (rc=$AGG_RC, out: $AGG_OUT)"
    fi

    # C. push-to-main / workflow_dispatch: `changes` never runs, so
    # no_python_ok is empty. The bug this guard fixes: without the nested
    # `github.event_name == 'pull_request'` check, an empty output reads as
    # `!= 'true'` and fails every such run.
    run_case "push" "" ""
    if [[ "$AGG_RC" -eq 0 ]]; then
        log_pass "aggregator does not fail a push/workflow_dispatch run when no_python_ok is empty"
    else
        log_fail "aggregator must not fail when changes never ran and no_python_ok is empty (rc=$AGG_RC, out: $AGG_OUT)"
    fi

    run_case "workflow_dispatch" "" ""
    if [[ "$AGG_RC" -eq 0 ]]; then
        log_pass "aggregator does not fail a workflow_dispatch run when no_python_ok is empty"
    else
        log_fail "aggregator must not fail a workflow_dispatch run when no_python_ok is empty (rc=$AGG_RC, out: $AGG_OUT)"
    fi
}



# The `CodeQL` ruleset context must exist on merge_group (Issue #5973). The
# required status check `CodeQL` is satisfied by the codeql-summary job in
# codeql-analysis.yml; codeql-stub.yml is pull_request-only. If neither workflow
# runs a `CodeQL`-named job on merge_group, a `CodeQL`-required merge queue
# waits forever for a context that never arrives (the failure Issue #2609 fixed).
# codeql_merge_group_context_ok passes when at least one of the given workflow
# files (a) lists `merge_group` under `on:` and (b) defines a job whose `name:`
# is exactly `CodeQL` with a job-level `if:` that is absent or exactly
# `always()`. Any other `if:` fails on purpose: a condition that could skip the
# job on merge_group must update this test deliberately. Extraction is plain
# awk over the fixed layout these workflows use (2-space job keys, 4-space job
# properties); no YAML library is used.
codeql_merge_group_context_ok() {
    local file verdict
    for file in "$@"; do
        [[ -f "$file" ]] || continue
        verdict="$(awk '
            function val(line,    v) {
                v = line
                sub(/^[^:]*:[[:space:]]*/, "", v)
                sub(/[[:space:]]+#.*$/, "", v)
                sub(/[[:space:]]+$/, "", v)
                gsub(/^["\047]|["\047]$/, "", v)
                return v
            }
            /^[A-Za-z_"\047-]+:/ { top = $0; sub(/:.*/, "", top); gsub(/["\047]/, "", top); next }
            top == "on" && /^  merge_group:/ { mg = 1; next }
            top == "jobs" && /^  [A-Za-z0-9_-]+:[[:space:]]*$/ { job = $1; sub(/:$/, "", job); next }
            top == "jobs" && /^    name:/ { jname[job] = val($0); next }
            top == "jobs" && /^    if:/ { jif[job] = val($0); hasif[job] = 1; next }
            END {
                ok = 0
                for (j in jname) {
                    if (jname[j] != "CodeQL") continue
                    if (!(j in hasif) || jif[j] == "always()") ok = 1
                    else { ok = 0; bad = 1 }
                }
                print (mg && ok && !bad) ? "ok" : "no"
            }
        ' "$file")"
        [[ "$verdict" == "ok" ]] && return 0
    done
    return 1
}

test_codeql_context_present_on_merge_group() {
    log_test "Testing a CodeQL job runs on merge_group (Issue #5973)..."

    local analysis="${1:-.github/workflows/codeql-analysis.yml}"
    local stub="${2:-.github/workflows/codeql-stub.yml}"
    if [[ ! -f "$analysis" || ! -f "$stub" ]]; then
        log_fail "CodeQL merge_group context: $analysis or $stub not found"
        return
    fi

    if codeql_merge_group_context_ok "$analysis" "$stub"; then
        log_pass "a workflow lists merge_group and defines an unconditional job named CodeQL"
    else
        log_fail "no workflow lists merge_group and defines a job named CodeQL with no job-level if: (or if: always()); the merge queue would wait forever for the required CodeQL context"
    fi

    local tmp_dir
    tmp_dir="$(mktemp -d)"

    # Negative 1: merge_group trigger (and its branches: block) removed.
    awk '
        /^  merge_group:/ { skip = 1; next }
        skip && /^    / { next }
        { skip = 0; print }
    ' "$analysis" > "$tmp_dir/no-merge-group.yml"
    if cmp -s "$analysis" "$tmp_dir/no-merge-group.yml"; then
        log_fail "CodeQL merge_group negative case: removing merge_group from $analysis changed nothing (test is vacuous)"
    elif codeql_merge_group_context_ok "$tmp_dir/no-merge-group.yml" "$stub"; then
        log_fail "CodeQL merge_group check accepted a copy with the merge_group trigger removed"
    else
        log_pass "CodeQL merge_group check rejects a copy with the merge_group trigger removed"
    fi

    # Negative 2: the CodeQL job's job-level if: restricted to pull_request.
    sed "s/^    if: always()\$/    if: github.event_name == 'pull_request'/" "$analysis" > "$tmp_dir/pr-only-if.yml"
    if cmp -s "$analysis" "$tmp_dir/pr-only-if.yml"; then
        log_fail "CodeQL merge_group negative case: no job-level 'if: always()' found in $analysis to replace (test is vacuous)"
    elif codeql_merge_group_context_ok "$tmp_dir/pr-only-if.yml" "$stub"; then
        log_fail "CodeQL merge_group check accepted a copy whose CodeQL job has if: github.event_name == 'pull_request'"
    else
        log_pass "CodeQL merge_group check rejects a copy whose CodeQL job has a pull_request-only if:"
    fi

    # Positive: an absent job-level if: is accepted (always() is optional).
    sed "/^    if: always()\$/d" "$analysis" > "$tmp_dir/no-if.yml"
    if codeql_merge_group_context_ok "$tmp_dir/no-if.yml" "$stub"; then
        log_pass "CodeQL merge_group check accepts a CodeQL job with no job-level if:"
    else
        log_fail "CodeQL merge_group check rejected a CodeQL job with no job-level if:"
    fi

    rm -rf "$tmp_dir"
}

# Fixture suite for scripts/install-git-hooks.sh (Issue #4150). A pre-push hook run
# from a linked worktree inherits GIT_DIR; running make test with it set let one
# `git init` in a scratch directory flip the MAIN repository to core.bare=true.
# Delegates to scripts/install-git-hooks_test.sh, which installs the real hooks
# into a throwaway repository and pushes from a linked worktree and the main
# checkout with `make` stubbed.
test_install_git_hooks() {
    log_test "Testing install-git-hooks.sh..."

    local test_script="scripts/install-git-hooks_test.sh"

    if [[ ! -x "$test_script" ]]; then
        log_fail "install-git-hooks_test.sh: Not found or not executable"
        return
    fi

    local out_file rc=0
    out_file=$(mktemp)
    bash "$test_script" >"$out_file" 2>&1 || rc=$?

    if [[ $rc -eq 0 ]]; then
        log_pass "install-git-hooks_test.sh: worktree pushes leave the main repo intact"
    else
        log_fail "install-git-hooks_test.sh: Fixture tests failed (exit $rc)"
        sed 's/^/    /' "$out_file" >&2
    fi
    rm -f "$out_file"
}


# Fixture suite for scripts/verify-nancy-ignore-scope.sh — the gate that proves
# .nancy-ignore can only ever suppress the exact CVE/OSS-Index IDs it lists
# (Issue #3366). Delegates to scripts/verify-nancy-ignore-scope_test.sh, which
# runs the gate against the repo's real suppression file plus synthetic fixtures
# for every way an entry could widen scope or silently drop coverage.
#
# Wired here because the gate itself only runs inside `make security-deps`,
# which skips without a GUIDE_TOKEN — without this delegation a regression in
# the scope-verification logic would never be caught locally or in CI.
test_verify_nancy_ignore_scope() {
    log_test "Testing verify-nancy-ignore-scope.sh..."

    local gate_script="scripts/verify-nancy-ignore-scope.sh"
    local test_script="scripts/verify-nancy-ignore-scope_test.sh"

    if [[ ! -f "$gate_script" ]]; then
        log_fail "verify-nancy-ignore-scope.sh: Not found"
        return
    fi

    if [[ ! -x "$gate_script" ]]; then
        log_fail "verify-nancy-ignore-scope.sh: Not executable (chmod +x needed)"
        return
    fi

    if [[ ! -f "$test_script" ]]; then
        log_fail "verify-nancy-ignore-scope_test.sh: Not found"
        return
    fi

    if [[ ! -x "$test_script" ]]; then
        log_fail "verify-nancy-ignore-scope_test.sh: Not executable (chmod +x needed)"
        return
    fi

    local out_file rc=0
    out_file=$(mktemp)
    bash "$test_script" >"$out_file" 2>&1 || rc=$?

    if [[ $rc -eq 0 ]]; then
        log_pass "verify-nancy-ignore-scope_test.sh: All fixture tests passed"
    else
        log_fail "verify-nancy-ignore-scope_test.sh: Fixture tests failed (exit $rc)"
        sed 's/^/    /' "$out_file" >&2
    fi
    rm -f "$out_file"
}








# Tests for scripts/security-trivy.sh — trivy init-error vs real-findings distinction

test_security_trivy_init_error() {
    log_test "Testing security-trivy.sh: trivy init error → clear DB-download message, NOT vulnerability message..."

    local script
    script="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/security-trivy.sh"

    if [[ ! -f "$script" ]]; then
        log_fail "security-trivy.sh: Script not found at $script"
        return
    fi

    local tmp_dir
    tmp_dir=$(mktemp -d)

    # Mock trivy that emits the exact FATAL init-error output seen in production
    cat > "$tmp_dir/trivy" << 'MOCKEOF'
#!/bin/bash
echo "2026-05-08T00:00:00.000Z	FATAL	Fatal error	run error: init error: DB error: failed to download vulnerability DB:"
echo "Get \"https://mirror.gcr.io/v2/\": dial tcp: lookup mirror.gcr.io on 127.0.0.1:53: server misbehaving"
exit 1
MOCKEOF
    chmod +x "$tmp_dir/trivy"

    local output exit_code=0
    output=$(TRIVY_CMD="$tmp_dir/trivy" bash "$script" 2>&1) || exit_code=$?

    if [[ $exit_code -eq 2 ]]; then
        log_pass "security-trivy.sh: Exits 2 on trivy init error (distinct from findings exit 1)"
    else
        log_fail "security-trivy.sh: Expected exit 2 on init error, got $exit_code"
    fi

    if echo "$output" | grep -q "DB download failed"; then
        log_pass "security-trivy.sh: Prints clear DB-download-failed message"
    else
        log_fail "security-trivy.sh: Missing DB-download-failed message (output: $output)"
    fi

    if echo "$output" | grep -q "Blocking vulnerabilities, secrets, or misconfigurations found"; then
        log_fail "security-trivy.sh: Must NOT print false security-findings message on init error"
    else
        log_pass "security-trivy.sh: Does NOT emit a false security-findings message on init error"
    fi

    rm -rf "$tmp_dir"
}

test_security_trivy_findings() {
    log_test "Testing security-trivy.sh: actual vulnerability findings → deployment-blocked message..."

    local script
    script="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/security-trivy.sh"

    if [[ ! -f "$script" ]]; then
        log_fail "security-trivy.sh: Script not found at $script"
        return
    fi

    local tmp_dir
    tmp_dir=$(mktemp -d)

    # Mock trivy that exits 1 with table output (no init-error text)
    cat > "$tmp_dir/trivy" << 'MOCKEOF'
#!/bin/bash
echo "pkg/go.mod (gomod)"
echo "Total: 1 (CRITICAL: 1)"
echo "CRITICAL  CVE-2024-99999  some-pkg  1.0.0  1.0.1  Example critical vuln"
exit 1
MOCKEOF
    chmod +x "$tmp_dir/trivy"

    local output exit_code=0
    output=$(TRIVY_CMD="$tmp_dir/trivy" bash "$script" 2>&1) || exit_code=$?

    if [[ $exit_code -eq 1 ]]; then
        log_pass "security-trivy.sh: Exits 1 on real vulnerability findings"
    else
        log_fail "security-trivy.sh: Expected exit 1 on findings, got $exit_code"
    fi

    if echo "$output" | grep -q "Blocking vulnerabilities, secrets, or misconfigurations found"; then
        log_pass "security-trivy.sh: Prints deployment-blocked message for real findings"
    else
        log_fail "security-trivy.sh: Missing deployment-blocked message for real findings (output: $output)"
    fi

    if echo "$output" | grep -q "DB download failed"; then
        log_fail "security-trivy.sh: Must NOT print DB-download-failed message for real findings"
    else
        log_pass "security-trivy.sh: Does NOT emit spurious DB-download-failed message for real findings"
    fi

    rm -rf "$tmp_dir"
}

test_security_trivy_clean_scan() {
    log_test "Testing security-trivy.sh: clean scan → exits 0..."

    local script
    script="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/security-trivy.sh"

    if [[ ! -f "$script" ]]; then
        log_fail "security-trivy.sh: Script not found at $script"
        return
    fi

    local tmp_dir
    tmp_dir=$(mktemp -d)

    # Mock trivy that exits 0 (no vulnerabilities)
    cat > "$tmp_dir/trivy" << 'MOCKEOF'
#!/bin/bash
echo "No vulnerabilities found."
exit 0
MOCKEOF
    chmod +x "$tmp_dir/trivy"

    local output exit_code=0
    output=$(TRIVY_CMD="$tmp_dir/trivy" bash "$script" 2>&1) || exit_code=$?

    if [[ $exit_code -eq 0 ]]; then
        log_pass "security-trivy.sh: Exits 0 on clean scan"
    else
        log_fail "security-trivy.sh: Expected exit 0 on clean scan, got $exit_code (output: $output)"
    fi

    if echo "$output" | grep -q "Trivy scan completed"; then
        log_pass "security-trivy.sh: Prints completion message on clean scan"
    else
        log_fail "security-trivy.sh: Missing completion message on clean scan (output: $output)"
    fi

    rm -rf "$tmp_dir"
}








test_check_cla_signed() {
    log_test "Testing check-cla-signed.sh: exit 0 for known contributor, exit 1 for absent login..."

    local script
    script="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/check-cla-signed.sh"

    if [[ ! -f "$script" ]]; then
        log_fail "check-cla-signed.sh: Script not found at $script"
        return
    fi

    if [[ ! -x "$script" ]]; then
        log_fail "check-cla-signed.sh: Not executable"
        return
    fi

    local tmp_dir
    tmp_dir=$(mktemp -d)
    trap 'rm -rf "$tmp_dir"; trap - RETURN' RETURN

    # Build a temp repo layout: $tmp_dir/CONTRIBUTORS.md + $tmp_dir/scripts/check-cla-signed.sh
    # The script derives repo root as $(dirname "$0")/.. — so placing it under scripts/ makes
    # it pick up $tmp_dir/CONTRIBUTORS.md without modifying the script under test.
    mkdir -p "${tmp_dir}/scripts"
    cp "$script" "${tmp_dir}/scripts/check-cla-signed.sh"

    cat > "${tmp_dir}/CONTRIBUTORS.md" << 'CONTRIBEOF'
# Test Contributors
@alice-contributor
github.com/bob-contributor
[carol-contributor] carol@example.com
CONTRIBEOF

    local exit_code output

    # --- AC7 Part 1: login present via @login pattern → exit 0 ----------------
    exit_code=0
    output=$("${tmp_dir}/scripts/check-cla-signed.sh" "alice-contributor" 2>&1) || exit_code=$?
    if [[ $exit_code -eq 0 ]]; then
        log_pass "check-cla-signed.sh: exit 0 for login matched via @login pattern"
    else
        log_fail "check-cla-signed.sh: expected exit 0 for @alice-contributor, got $exit_code (output: $output)"
    fi
    if echo "$output" | grep -q "CLA_SIGNED:alice-contributor"; then
        log_pass "check-cla-signed.sh: prints CLA_SIGNED:<login> on success"
    else
        log_fail "check-cla-signed.sh: expected CLA_SIGNED:alice-contributor in output, got: $output"
    fi

    # --- AC7 Part 2: login present via github.com/login pattern → exit 0 ------
    exit_code=0
    output=$("${tmp_dir}/scripts/check-cla-signed.sh" "bob-contributor" 2>&1) || exit_code=$?
    if [[ $exit_code -eq 0 ]]; then
        log_pass "check-cla-signed.sh: exit 0 for login matched via github.com/login pattern"
    else
        log_fail "check-cla-signed.sh: expected exit 0 for bob-contributor, got $exit_code"
    fi
    if echo "$output" | grep -q "CLA_SIGNED:bob-contributor"; then
        log_pass "check-cla-signed.sh: prints CLA_SIGNED:<login> for github.com/login pattern"
    else
        log_fail "check-cla-signed.sh: expected CLA_SIGNED:bob-contributor in output, got: $output"
    fi

    # --- AC7 Part 3: login present via [login] pattern → exit 0 ---------------
    exit_code=0
    output=$("${tmp_dir}/scripts/check-cla-signed.sh" "carol-contributor" 2>&1) || exit_code=$?
    if [[ $exit_code -eq 0 ]]; then
        log_pass "check-cla-signed.sh: exit 0 for login matched via [login] pattern"
    else
        log_fail "check-cla-signed.sh: expected exit 0 for carol-contributor, got $exit_code"
    fi
    if echo "$output" | grep -q "CLA_SIGNED:carol-contributor"; then
        log_pass "check-cla-signed.sh: prints CLA_SIGNED:<login> for [login] pattern"
    else
        log_fail "check-cla-signed.sh: expected CLA_SIGNED:carol-contributor in output, got: $output"
    fi

    # --- AC7 Part 4: login absent from CONTRIBUTORS.md → exit 1 ---------------
    exit_code=0
    output=$("${tmp_dir}/scripts/check-cla-signed.sh" "unknown-outsider" 2>&1) || exit_code=$?
    if [[ $exit_code -eq 1 ]]; then
        log_pass "check-cla-signed.sh: exit 1 for login absent from CONTRIBUTORS.md"
    else
        log_fail "check-cla-signed.sh: expected exit 1 for absent login, got $exit_code"
    fi
    if echo "$output" | grep -q "CLA_NOT_SIGNED:unknown-outsider"; then
        log_pass "check-cla-signed.sh: prints CLA_NOT_SIGNED:<login> when absent"
    else
        log_fail "check-cla-signed.sh: expected CLA_NOT_SIGNED:unknown-outsider in output, got: $output"
    fi

    # --- AC7 Part 5: CONTRIBUTORS.md absent → exit 1 with ERROR message -------
    local no_contrib_dir
    no_contrib_dir=$(mktemp -d)
    mkdir -p "${no_contrib_dir}/scripts"
    cp "$script" "${no_contrib_dir}/scripts/check-cla-signed.sh"
    # No CONTRIBUTORS.md created in no_contrib_dir

    exit_code=0
    output=$("${no_contrib_dir}/scripts/check-cla-signed.sh" "anyone" 2>&1) || exit_code=$?
    rm -rf "$no_contrib_dir"
    if [[ $exit_code -eq 1 ]]; then
        log_pass "check-cla-signed.sh: exit 1 when CONTRIBUTORS.md does not exist"
    else
        log_fail "check-cla-signed.sh: expected exit 1 for missing CONTRIBUTORS.md, got $exit_code"
    fi
    if echo "$output" | grep -q "ERROR:"; then
        log_pass "check-cla-signed.sh: prints ERROR: message when CONTRIBUTORS.md missing"
    else
        log_fail "check-cla-signed.sh: expected ERROR: in output when CONTRIBUTORS.md missing, got: $output"
    fi

    # --- AC7 Part 6: no argument → non-zero exit (usage guard) ----------------
    exit_code=0
    output=$("${tmp_dir}/scripts/check-cla-signed.sh" 2>&1) || exit_code=$?
    if [[ $exit_code -ne 0 ]]; then
        log_pass "check-cla-signed.sh: non-zero exit when invoked with no argument"
    else
        log_fail "check-cla-signed.sh: expected non-zero exit with no argument, got 0"
    fi
}

# Helper: returns 0 when the file has no non-trusted tooling-script path and no
# cleanup-issue command line; prints offending lines and returns 1 otherwise.
_reviewer_def_clean() {
    local file="$1" bad=0 m
    m=$(grep -nP '(?<!/opt/cfgms-trusted/)\.claude/tooling/scripts/' "$file" 2>/dev/null) || true
    if [[ -n "$m" ]]; then echo "$m"; bad=1; fi
    m=$(grep -nE '^[^`]*agent-dispatch\.sh cleanup-issue' "$file" 2>/dev/null \
        | grep -E '^[0-9]+:([[:space:]]|/|\.|bash)') || true
    if [[ -n "$m" ]]; then echo "$m"; bad=1; fi
    return "$bad"
}

test_acceptance_reviewer_trusted_tooling_paths() {
    log_test "Testing: acceptance-reviewer.md runs tooling only from the trusted root..."

    local root
    root="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/.."

    local tmp_dir
    tmp_dir=$(mktemp -d)
    trap 'rm -rf "$tmp_dir"; trap - RETURN' RETURN

    # Falsifiability probes: the helper must reject relative paths and cleanup-issue
    # commands, and accept trusted-root invocations.
    printf './.claude/tooling/scripts/project-queue.sh get-item X\n' > "$tmp_dir/bad.md"
    printf '/opt/cfgms-trusted/.claude/tooling/scripts/agent-dispatch.sh cleanup-issue 1\n' > "$tmp_dir/bad2.md"
    printf '/opt/cfgms-trusted/.claude/tooling/scripts/project-queue.sh get-item X\n' > "$tmp_dir/good.md"
    if ! _reviewer_def_clean "$tmp_dir/bad.md" >/dev/null; then
        log_pass "acceptance_reviewer_trusted_tooling_paths: probe rejects relative tooling path"
    else
        log_fail "acceptance_reviewer_trusted_tooling_paths: probe failed to reject relative tooling path"
        return
    fi
    if ! _reviewer_def_clean "$tmp_dir/bad2.md" >/dev/null; then
        log_pass "acceptance_reviewer_trusted_tooling_paths: probe rejects cleanup-issue command"
    else
        log_fail "acceptance_reviewer_trusted_tooling_paths: probe failed to reject cleanup-issue command"
        return
    fi
    if _reviewer_def_clean "$tmp_dir/good.md" >/dev/null; then
        log_pass "acceptance_reviewer_trusted_tooling_paths: probe accepts trusted path"
    else
        log_fail "acceptance_reviewer_trusted_tooling_paths: probe rejected a trusted path"
        return
    fi

    local def="${root}/.claude/agents/acceptance-reviewer.md" out
    if out=$(_reviewer_def_clean "$def"); then
        log_pass "acceptance_reviewer_trusted_tooling_paths: no untrusted tooling path or cleanup-issue command"
    else
        log_fail "acceptance_reviewer_trusted_tooling_paths: violations in acceptance-reviewer.md:"
        while IFS= read -r line; do echo "    $line"; done <<< "$out"
    fi

    if grep -q '/opt/cfgms-trusted/\.claude/tooling/scripts/project-queue\.sh' "$def" \
        && grep -q '/opt/cfgms-trusted/\.claude/tooling/scripts/pipeline-helper\.sh comment' "$def"; then
        log_pass "acceptance_reviewer_trusted_tooling_paths: trusted project-queue.sh and pipeline-helper.sh comment present"
    else
        log_fail "acceptance_reviewer_trusted_tooling_paths: missing trusted project-queue.sh or pipeline-helper.sh comment invocation"
    fi
}


test_no_pipeline_label_refs() {
    log_test "Testing: no pipeline:* or agent:* label references in .claude/ or scripts/..."

    local root
    root="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/.."

    # Falsifiability check: inject a prohibited label into a temp file and verify
    # the grep pattern fires, so a broken grep doesn't silently always pass.
    local tmp_dir
    tmp_dir=$(mktemp -d)
    trap 'rm -rf "$tmp_dir"; trap - RETURN' RETURN
    printf '# prohibited: pipeline:story label reference\n' > "$tmp_dir/probe.sh"
    local probe_matches
    probe_matches=$(grep -rn \
        "pipeline:story\|pipeline:draft\|pipeline:review\|pipeline:ready\|agent:ready\|agent:success\|agent:in-progress\|agent:failed" \
        "$tmp_dir/" \
        2>/dev/null) || true
    if [[ -n "$probe_matches" ]]; then
        log_pass "no_pipeline_label_refs: grep pattern correctly detects violations (falsifiability)"
    else
        log_fail "no_pipeline_label_refs: grep pattern failed to detect injected violation — grep is broken"
        return
    fi

    # Real check: assert zero matches in the actual codebase directories.
    # Exclude .claude/worktrees/ — that's the agent-dispatch root containing
    # nested repo copies, not source for this checkout.
    local matches
    matches=$(grep -rn \
        "pipeline:story\|pipeline:draft\|pipeline:review\|pipeline:ready\|agent:ready\|agent:success\|agent:in-progress\|agent:failed" \
        "${root}/.claude/" "${root}/scripts/" \
        --exclude="test-scripts.sh" \
        --exclude-dir="worktrees" \
        --exclude-dir="tooling" \
        2>/dev/null) || true

    if [[ -z "$matches" ]]; then
        log_pass "no_pipeline_label_refs: zero prohibited label references in .claude/ and scripts/"
    else
        log_fail "no_pipeline_label_refs: found prohibited label references (remove them):"
        while IFS= read -r line; do
            echo "    $line"
        done <<< "$matches"
    fi
}


















# Test: resource-sampler.sh loop guard (Issue #2485 AC2)
# Verifies that every per-iteration read in the sampling loop is guarded with
# || true / || echo 0 so a single transient failure skips one sample instead
# of killing the loop under set -euo pipefail.
test_resource_sampler_loop_guard() {
    log_test "Testing resource-sampler.sh: per-iteration read guard survives set -e failures..."

    local script_dir
    script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/.github/scripts"

    if [[ ! -f "${script_dir}/resource-sampler.sh" ]]; then
        log_fail "resource-sampler.sh: not found at ${script_dir}/resource-sampler.sh"
        return
    fi

    if [[ ! -x "${script_dir}/resource-sampler.sh" ]]; then
        log_fail "resource-sampler.sh: not executable"
        return
    fi

    local tmp_dir
    tmp_dir=$(mktemp -d)
    trap 'rm -rf "$tmp_dir"; trap - RETURN' RETURN

    # Write a mini-script that mirrors resource-sampler.sh's guarded loop body
    # and runs it under set -euo pipefail.  Iteration 1 injects failures on all
    # three reads (CPU_PCT, MEM_TOTAL, MEM_AVAIL).  With guards (|| echo 0) the
    # loop must complete all iterations; without guards set -e would kill it.
    local guard_script="${tmp_dir}/guard_test.sh"
    local guard_out="${tmp_dir}/guard_out.txt"
    cat > "$guard_script" << 'SCRIPTEOF'
#!/usr/bin/env bash
set -euo pipefail
PREV=""
OUT="${GUARD_OUT}"
for ITER in 0 1 2; do
    CURR=$(echo "1 2 3 4 5 6 7" 2>/dev/null || true)
    if [ -n "$PREV" ] && [ -n "$CURR" ]; then
        if [ "$ITER" -eq 1 ]; then
            # Simulate all three transient read failures; each is guarded.
            CPU_PCT=$(false 2>/dev/null || echo 0)
            MEM_TOTAL=$(false 2>/dev/null || echo 0)
            MEM_AVAIL=$(false 2>/dev/null || echo 0)
        else
            CPU_PCT=50
            MEM_TOTAL=8192
            MEM_AVAIL=4096
        fi
        MEM_USED=$(( ${MEM_TOTAL:-0} - ${MEM_AVAIL:-0} ))
        printf 'iter%d cpu_pct=%d mem_used_mb=%d/%d\n' \
            "$ITER" "${CPU_PCT:-0}" "$MEM_USED" "${MEM_TOTAL:-0}" \
            >> "$OUT" || true
    fi
    PREV="$CURR"
done
echo "LOOP_COMPLETE"
SCRIPTEOF
    chmod +x "$guard_script"

    local guard_output guard_exit=0
    guard_output=$(GUARD_OUT="$guard_out" bash "$guard_script" 2>&1) || guard_exit=$?

    if [[ $guard_exit -eq 0 ]]; then
        log_pass "resource-sampler.sh guard: loop body exits 0 under set -euo pipefail with all reads guarded"
    else
        log_fail "resource-sampler.sh guard: loop body exited $guard_exit — unguarded read killed it under set -e"
    fi

    if echo "$guard_output" | grep -q "LOOP_COMPLETE"; then
        log_pass "resource-sampler.sh guard: LOOP_COMPLETE reached (loop not killed by failed iteration)"
    else
        log_fail "resource-sampler.sh guard: LOOP_COMPLETE not reached (output: $guard_output)"
    fi

    if [[ -f "$guard_out" ]]; then
        local guard_lines
        guard_lines=$(wc -l < "$guard_out" | tr -d ' ')
        if [[ "$guard_lines" -ge 2 ]]; then
            log_pass "resource-sampler.sh guard: $guard_lines samples produced (failure on iter 1 skipped one sample, did not stop loop)"
        else
            log_fail "resource-sampler.sh guard: only $guard_lines samples (expected ≥2 from 3 iterations)"
        fi
    else
        log_fail "resource-sampler.sh guard: no output file produced"
    fi

    # Also verify start/report pipeline exits cleanly on a real system.
    local state_dir="${tmp_dir}/state"
    local start_exit=0
    bash "${script_dir}/resource-sampler.sh" start "$state_dir" >/dev/null 2>&1 || start_exit=$?

    if [[ $start_exit -eq 0 ]]; then
        log_pass "resource-sampler.sh start: exits 0"
    else
        log_fail "resource-sampler.sh start: exited $start_exit"
    fi

    if [[ -f "${state_dir}/sampler.pid" ]]; then
        log_pass "resource-sampler.sh start: created sampler.pid"
        # Kill the background sampler immediately so the test is fast.
        kill "$(cat "${state_dir}/sampler.pid" 2>/dev/null)" 2>/dev/null || true
    else
        log_fail "resource-sampler.sh start: sampler.pid not created"
    fi
}









# Regression guard for Makefile's test-framework-api-sharded (Issue #4151):
# the partition of features/controller/api tests across shards must be
# complete (every test lands in exactly one shard, none dropped or
# duplicated) and even (no shard starves while another does most of the
# work). Uses CFGMS_API_TEST_SHARD_PLAN_ONLY=1 so this runs in milliseconds
# instead of paying for a full -race run just to check the partition math.
test_api_shard_partition_covers_all_tests() {
    log_test "Testing test-framework-api-sharded: partition is complete and even..."

    local list_out list_rc total
    list_out=$(go test -list '.*' ./features/controller/api/... 2>&1)
    list_rc=$?
    if [[ $list_rc -ne 0 ]]; then
        log_fail "go test -list ./features/controller/api/...: exited ${list_rc}"
        echo "$list_out" | tail -20
        return
    fi
    total=$(echo "$list_out" | grep -c '^Test')
    if [[ "$total" -eq 0 ]]; then
        log_fail "go test -list found no tests in features/controller/api"
        return
    fi

    local shards=4
    local plan_out plan_rc
    plan_out=$(CFGMS_API_TEST_SHARDS=$shards CFGMS_API_TEST_SHARD_PLAN_ONLY=1 make test-framework-api-sharded 2>&1)
    plan_rc=$?
    if [[ $plan_rc -ne 0 ]]; then
        log_fail "make test-framework-api-sharded (plan-only): exited ${plan_rc}"
        echo "$plan_out" | tail -20
        return
    fi

    local counts sum min max
    counts=$(echo "$plan_out" | grep -oE '^shard [0-9]+: [0-9]+ tests' | grep -oE '[0-9]+ tests' | grep -oE '^[0-9]+')
    if [[ -z "$counts" ]]; then
        log_fail "could not parse shard counts from plan-only output"
        echo "$plan_out" | tail -20
        return
    fi

    sum=0
    min=""
    max=""
    while read -r n; do
        sum=$((sum + n))
        if [[ -z "$min" || "$n" -lt "$min" ]]; then min=$n; fi
        if [[ -z "$max" || "$n" -gt "$max" ]]; then max=$n; fi
    done <<< "$counts"

    if [[ "$sum" -ne "$total" ]]; then
        log_fail "shard counts sum to ${sum}, go test -list reports ${total} tests — partition drops or duplicates tests"
        return
    fi

    if [[ $((max - min)) -gt 1 ]]; then
        log_fail "shard sizes range from ${min} to ${max} tests (across ${shards} shards) — partition is not even"
        return
    fi

    log_pass "test-framework-api-sharded: ${total} tests partitioned evenly across ${shards} shards (sizes ${min}-${max})"
}

# Regression guard for the -test.run pattern cap in test-framework-api-sharded
# (Issue #5245): a shard's single "^(A|B|...)$" argument outgrew the Windows
# command-line limit (32,767 characters). With one shard at the current test
# count every test lands in one shard, so unchunked it would be a single
# pattern far above the cap. Asserts every planned chunk is within the cap and
# that the chunks together cover the full test list exactly once.
test_api_shard_chunks_respect_pattern_cap() {
    log_test "Testing test-framework-api-sharded: -test.run chunks stay under the cap and cover every test once..."

    local list_out list_rc
    list_out=$(go test -list '.*' ./features/controller/api/... 2>&1)
    list_rc=$?
    if [[ $list_rc -ne 0 ]]; then
        log_fail "go test -list ./features/controller/api/...: exited ${list_rc}"
        return
    fi

    local cap=16000 shards plan_out plan_rc
    for shards in 1 4; do
        plan_out=$(CFGMS_API_TEST_SHARDS=$shards CFGMS_API_TEST_SHARD_PLAN_ONLY=1 make --no-print-directory test-framework-api-sharded 2>&1)
        plan_rc=$?
        if [[ $plan_rc -ne 0 ]]; then
            log_fail "plan-only run with ${shards} shard(s) exited ${plan_rc}"
            return
        fi

        local expected planned over
        expected=$(echo "$list_out" | grep '^Test' | sort)
        planned=$(echo "$plan_out" | grep '^chunk ' | awk '{print $5}' | tr '|' '\n' | sort)
        if [[ -z "$planned" ]]; then
            log_fail "no chunk lines in plan-only output with ${shards} shard(s)"
            return
        fi
        over=$(echo "$plan_out" | grep '^chunk ' | awk -v cap=$cap '{ if (length($5) + 4 > cap || $4 > cap) print $1, $2, $3, $4 }')
        if [[ -n "$over" ]]; then
            log_fail "chunk pattern over ${cap} bytes with ${shards} shard(s): ${over}"
            return
        fi
        if [[ "$expected" != "$planned" ]]; then
            log_fail "chunks do not cover the test list exactly once with ${shards} shard(s)"
            return
        fi
    done

    log_pass "test-framework-api-sharded: every -test.run chunk is within ${cap} bytes and covers each test exactly once"
}

# test-fast must not run features/controller/api in its bulk `go test` call: the
# package needs ~540s under -race alone and trips the 10m hang detector under
# load. It must go through test-framework-api-sharded, as `make test` does.
# `make -n` prints the recipe without running tests; the sharded sub-make is
# expanded inline, so its presence is asserted via the shard recipe text.
test_test_fast_shards_api_package() {
    log_test "Testing test-fast excludes features/controller/api from the bulk run and shards it..."

    local recipe rc
    recipe=$(make --no-print-directory -n test-fast 2>&1)
    rc=$?
    if [[ $rc -ne 0 ]]; then
        log_fail "make -n test-fast exited ${rc}"
        echo "$recipe" | tail -20
        return
    fi

    if ! echo "$recipe" | grep -qF "grep -v '/features/controller/api\$'"; then
        log_fail "test-fast bulk run does not exclude '/features/controller/api\$' via grep -v"
        return
    fi
    if ! echo "$recipe" | grep -qE 'CFGMS_TEST_SHORT=1 (make|\$\(MAKE\)) .*test-framework-api-sharded'; then
        log_fail "test-fast does not invoke test-framework-api-sharded with CFGMS_TEST_SHORT=1"
        return
    fi
    if echo "$recipe" | grep -E 'go test .*\./features/\.\.\.' >/dev/null; then
        log_fail "test-fast still passes ./features/... to go test unsharded"
        return
    fi
    log_pass "test-fast shards features/controller/api and excludes it from the bulk run"
}

# Regression guard for the Makefile's test-go-group-controller-core /
# test-go-group-heavy-providers / test-go-group-rest split (Issue #4151): the
# three groups must partition the exact package list the pre-split single
# `go test ./...` call used — no package dropped, none picked up by two
# groups. Unlike test-framework-api-sharded above, this split is a
# hand-maintained package-name partition, not something `go test -list`
# itself verifies, so a renamed package or a new sub-package under one of the
# heavy-providers paths could silently drift out of sync with no other
# signal. Uses CFGMS_TEST_GROUP_LIST_ONLY=1 so this costs a few `go list`
# calls, not three full -race runs.
test_go_group_split_partition_covers_all_packages() {
    log_test "Testing go-group split: controller-core/heavy-providers/rest partition all packages, no drops or duplicates..."

    # Every captured stream is filtered to lines that actually look like this
    # module's import paths. Not cosmetic: test-go-group-* is invoked here via
    # `make` from inside a shell that (in CI, via `make test` -> make test-scripts
    # -> this script) already inherited MAKEFLAGS/MAKELEVEL from an enclosing
    # make process, which makes GNU Make auto-print "Entering directory" /
    # "Leaving directory" around the nested invocation — two extra non-empty
    # lines per call that a bare `grep -c .` counts as packages. Reproduced only
    # in that nested context, never when running the make target directly from
    # an interactive shell, which is why this passed locally and failed in CI.
    local pkg_filter='^github\.com/cfgis/cfgms/'

    local full full_rc
    full=$(go list ./... 2>&1 | grep -v '/features/modules/' | grep -v '/test/integration' | grep -v '/test/e2e' | grep -v '/features/controller/api$' | grep -E "$pkg_filter")
    full_rc=$?
    if [[ $full_rc -ne 0 ]]; then
        log_fail "go list ./...: exited ${full_rc}"
        echo "$full" | tail -20
        return
    fi

    local core heavy rest core_rc heavy_rc rest_rc
    core=$(CFGMS_TEST_GROUP_LIST_ONLY=1 make --no-print-directory test-go-group-controller-core 2>&1 | grep -E "$pkg_filter")
    core_rc=$?
    heavy=$(CFGMS_TEST_GROUP_LIST_ONLY=1 make --no-print-directory test-go-group-heavy-providers 2>&1 | grep -E "$pkg_filter")
    heavy_rc=$?
    rest=$(CFGMS_TEST_GROUP_LIST_ONLY=1 make --no-print-directory test-go-group-rest 2>&1 | grep -E "$pkg_filter")
    rest_rc=$?
    if [[ $core_rc -ne 0 || $heavy_rc -ne 0 || $rest_rc -ne 0 ]]; then
        log_fail "CFGMS_TEST_GROUP_LIST_ONLY=1 exited non-zero (core=${core_rc}, heavy=${heavy_rc}, rest=${rest_rc})"
        return
    fi

    local full_count core_count heavy_count rest_count union_count
    full_count=$(echo "$full" | sort -u | grep -c .)
    core_count=$(echo "$core" | grep -c .)
    heavy_count=$(echo "$heavy" | grep -c .)
    rest_count=$(echo "$rest" | grep -c .)

    if [[ $((core_count + heavy_count + rest_count)) -ne "$full_count" ]]; then
        log_fail "controller-core (${core_count}) + heavy-providers (${heavy_count}) + rest (${rest_count}) = $((core_count + heavy_count + rest_count)), go list reports ${full_count} packages — partition drops or duplicates packages"
        return
    fi

    union_count=$(printf '%s\n%s\n%s\n' "$core" "$heavy" "$rest" | sort -u | grep -c .)
    if [[ "$union_count" -ne "$full_count" ]]; then
        log_fail "union of the three groups has ${union_count} unique packages, go list reports ${full_count} — a package appears in more than one group"
        return
    fi

    # Name any package missing from the groups (Issue #5958): the counts above
    # catch a drop, this says which package it was.
    local missing
    missing=$(comm -23 <(echo "$full" | sort -u) <(printf '%s\n%s\n%s\n' "$core" "$heavy" "$rest" | sort -u))
    if [[ -n "$missing" ]]; then
        log_fail "packages in go list ./... but in no group: $(echo "$missing" | tr '\n' ' ')"
        return
    fi

    log_pass "go-group split: ${full_count} packages partitioned across controller-core (${core_count}), heavy-providers (${heavy_count}), rest (${rest_count}) — complete, no duplicates"
}

# Regression guard for Makefile's test-go-group-rest (Issue #4420): the recipe
# runs four things in one shell — the framework package list, a per-module loop,
# and a final adapter/conformance run. A make recipe's exit status is the status
# of its LAST command, so without `set -e` a failing framework run followed by
# three passing ones exited 0, and `make test` -> test-commit ->
# test-agent-complete all reported success over a genuine test failure. This
# drives the target with a stub `go` whose FIRST `go test` fails and whose
# later ones pass — the exact shape that was silently swallowed — so the guard
# fails if the propagation is ever removed. Costs milliseconds: no real
# compilation happens.
test_go_group_rest_propagates_early_failure() {
    log_test "Testing test-go-group-rest: a failure in the first go test run propagates to a non-zero exit..."

    local tmp_dir
    tmp_dir=$(mktemp -d)
    trap 'rm -rf "$tmp_dir"; trap - RETURN' RETURN

    local bin_dir="${tmp_dir}/bin"
    mkdir -p "$bin_dir"

    # Stub go: `go list` reports one package this module's filters keep, the
    # first `go test` fails, every subsequent `go test` succeeds.
    cat > "${bin_dir}/go" <<'STUB'
#!/bin/sh
if [ "$1" = "list" ]; then
    echo "github.com/cfgis/cfgms/pkg/stubpkg"
    exit 0
fi
if [ "$1" = "test" ]; then
    if [ -e "${CFGMS_STUB_STATE}/first-test-ran" ]; then
        echo "ok  	stub	0.01s"
        exit 0
    fi
    : > "${CFGMS_STUB_STATE}/first-test-ran"
    echo "FAIL	github.com/cfgis/cfgms/pkg/stubpkg	0.01s"
    echo "FAIL"
    exit 1
fi
exit 0
STUB
    chmod +x "${bin_dir}/go"

    local out rc=0
    out=$(PATH="${bin_dir}:$PATH" CFGMS_STUB_STATE="$tmp_dir" \
        make --no-print-directory test-go-group-rest 2>&1) || rc=$?

    if [[ ! -e "${tmp_dir}/first-test-ran" ]]; then
        log_fail "test-go-group-rest never invoked \`go test\` — the stub was not exercised, so this guard proves nothing"
        echo "$out" | tail -20
        return
    fi

    if [[ $rc -eq 0 ]]; then
        log_fail "test-go-group-rest exited 0 with a failing framework test run — \`make test\` would report a false green (needs \`set -e\` or \`&&\` chaining in the recipe)"
        echo "$out" | tail -20
        return
    fi

    log_pass "test-go-group-rest: a failing framework run exits ${rc}, so the failure reaches make test"
}

# Regression guard for Makefile's ALL_MODULES (Issue #4164): ALL_MODULES drives
# CHANGED_MODULES, which is how `make test`'s smart mode decides which module's
# tests to run for a change. A hand-maintained ALL_MODULES list silently drops
# modules added later -- 5 of 10 stdlib modules and 3 of 5 extended modules were
# missing before this fix, so a change to one of them never triggered its tests
# locally even though CI's unbounded `features/...` run still covered it. This
# independently rediscovers every features/modules/**/module.yaml directory
# (the same discriminator the Makefile derivation uses) and diffs it against
# what the Makefile actually reports via `make test-module`'s usage output, so
# reverting the derivation back to a hand list fails this the moment the tree
# grows past that list.
test_all_modules_covers_module_yaml_tree() {
    log_test "Testing ALL_MODULES: every features/modules/**/module.yaml directory is included..."

    local discovered
    discovered=$(find features/modules -mindepth 1 -name module.yaml -exec dirname {} \; \
        | sed 's#^features/modules/##' | sort -u)
    if [[ -z "$discovered" ]]; then
        log_fail "found no module.yaml files under features/modules — discovery command itself is broken"
        return
    fi

    local make_out reported
    make_out=$(make --no-print-directory test-module 2>&1 || true)
    reported=$(echo "$make_out" | grep '^  All: ' | sed 's/^  All: //' | tr ' ' '\n' | sort -u)
    if [[ -z "$reported" ]]; then
        log_fail "could not parse ALL_MODULES from 'make test-module' usage output"
        echo "$make_out" | tail -20
        return
    fi

    local missing extra
    missing=$(comm -23 <(echo "$discovered") <(echo "$reported"))
    extra=$(comm -13 <(echo "$discovered") <(echo "$reported"))

    if [[ -n "$missing" ]]; then
        log_fail "ALL_MODULES is missing modules present in the tree: $(echo "$missing" | tr '\n' ' ')"
        return
    fi
    if [[ -n "$extra" ]]; then
        log_fail "ALL_MODULES lists modules with no module.yaml in the tree: $(echo "$extra" | tr '\n' ' ')"
        return
    fi

    log_pass "ALL_MODULES matches the module.yaml tree ($(echo "$discovered" | grep -c .) modules)"
}

# Regression guard for Makefile's test-framework-api-sharded (Issue #4151):
# shard aggregation must fail closed. A shard subshell that dies before it can
# record its exit status (OOM kill, signal, unwritable temp dir) used to be
# skipped by the aggregation loop, so `make test` reported success while a
# whole shard of tests never ran. Driven with a stub `go` on PATH so it costs
# milliseconds instead of a real -race run: the stub kills its own parent
# subshell for one shard, reproducing the OOM-kill case exactly.
test_api_shard_aggregation_fails_closed() {
    log_test "Testing test-framework-api-sharded: a shard with no exit status fails closed..."

    local tmp_dir
    tmp_dir=$(mktemp -d)
    trap 'rm -rf "$tmp_dir"; trap - RETURN' RETURN

    local bin_dir="${tmp_dir}/bin"
    mkdir -p "$bin_dir"

    # Stub go: enumerates four tests for -list, reports one package for `go
    # list`, and for `go test -c -o <path>` writes a stub test binary in place
    # of a real compile. That stub binary is what the shards exec: for the
    # shard whose -test.run pattern includes TestB it SIGKILLs the subshell
    # that launched it, so no shard-N.exit file is ever written.
    cat > "${bin_dir}/go" <<'STUB'
#!/bin/sh
for arg in "$@"; do
    if [ "$arg" = "-list" ]; then
        printf 'TestA\nTestB\nTestC\nTestD\nok\tfeatures/controller/api\t0.01s\n'
        exit 0
    fi
done
if [ "$1" = "list" ]; then
    case "$*" in
        *features/controller/api*) echo "github.com/cfgis/cfgms/features/controller/api" ;;
        *) echo "github.com/cfgis/cfgms/pkg/stubpkg" ;;
    esac
    exit 0
fi
prev=""
for arg in "$@"; do
    if [ "$prev" = "-o" ]; then
        cat > "$arg" <<'BIN'
#!/bin/sh
case "$*" in
    *TestB*) kill -9 "$PPID"; exit 0 ;;
esac
echo "ok  features/controller/api  0.01s"
exit 0
BIN
        chmod +x "$arg"
        exit 0
    fi
    prev="$arg"
done
echo "ok  features/controller/api  0.01s"
exit 0
STUB
    chmod +x "${bin_dir}/go"

    # rc captured via || so a non-zero make does not trip the suite's set -e.
    local out rc=0
    out=$(PATH="${bin_dir}:$PATH" CFGMS_API_TEST_SHARDS=2 make test-framework-api-sharded 2>&1) || rc=$?

    if [[ $rc -eq 0 ]]; then
        log_fail "a shard that died without recording an exit status still produced a passing target (exit 0) — false green in make test"
        echo "$out" | tail -20
        return
    fi

    if ! echo "$out" | grep -q 'no readable exit status'; then
        log_fail "target failed but printed no diagnostic naming the shard with the missing exit status"
        echo "$out" | tail -20
        return
    fi

    # A temp dir that cannot be created must also fail closed rather than
    # running zero shards and reporting success.
    local not_a_dir="${tmp_dir}/tmpdir-is-a-file"
    : > "$not_a_dir"

    local mk_out mk_rc=0
    mk_out=$(PATH="${bin_dir}:$PATH" TMPDIR="$not_a_dir" CFGMS_API_TEST_SHARDS=2 make test-framework-api-sharded 2>&1) || mk_rc=$?

    if [[ $mk_rc -eq 0 ]]; then
        log_fail "target reported success when mktemp -d could not create the shard output dir"
        echo "$mk_out" | tail -20
        return
    fi

    # The shards exec one prebuilt test binary (Issue #4239), so a build that
    # exits 0 without producing that binary must stop the target rather than
    # launch N shards that all fail for an unrelated reason — or worse, a
    # future edit that treats "no binary" as "nothing to run".
    local nobin_dir="${tmp_dir}/nobin"
    mkdir -p "$nobin_dir"
    cat > "${nobin_dir}/go" <<'STUB'
#!/bin/sh
for arg in "$@"; do
    if [ "$arg" = "-list" ]; then
        printf 'TestA\nTestB\nTestC\nTestD\nok\tfeatures/controller/api\t0.01s\n'
        exit 0
    fi
done
if [ "$1" = "list" ]; then
    echo "github.com/cfgis/cfgms/features/controller/api"
    exit 0
fi
# `go test -c` succeeds but writes nothing to the -o path.
exit 0
STUB
    chmod +x "${nobin_dir}/go"

    local nobin_out nobin_rc=0
    nobin_out=$(PATH="${nobin_dir}:$PATH" CFGMS_API_TEST_SHARDS=2 make test-framework-api-sharded 2>&1) || nobin_rc=$?

    if [[ $nobin_rc -eq 0 ]]; then
        log_fail "a test build that produced no binary still produced a passing target (exit 0) — zero tests ran"
        echo "$nobin_out" | tail -20
        return
    fi

    if ! echo "$nobin_out" | grep -q 'no runnable binary'; then
        log_fail "target failed but printed no diagnostic explaining that the test build produced no binary"
        echo "$nobin_out" | tail -20
        return
    fi

    log_pass "test-framework-api-sharded: missing shard exit status, unusable temp dir and a binary-less build all fail closed"
}


# Regression guard for Makefile's test-framework-api-sharded (Issue #4151):
# CFGMS_API_TEST_SHARDS must be validated as a decimal integer before it
# reaches any arithmetic context. Bash re-evaluates the contents of a variable
# used inside $(( )) as an arithmetic expression, so an unvalidated value is
# both command execution (an array-subscript payload runs) and a silent
# fail-open (a non-numeric value makes `seq 0 $((shards - 1))` emit nothing,
# so zero shards launch and the target exits 0 with the whole suite unrun).
# Driven with a stub `go` on PATH so it costs milliseconds.
test_api_shard_count_rejects_non_integer() {
    log_test "Testing test-framework-api-sharded: a non-integer shard count is rejected, not executed..."

    local tmp_dir
    tmp_dir=$(mktemp -d)
    trap 'rm -rf "$tmp_dir"; trap - RETURN' RETURN

    local bin_dir="${tmp_dir}/bin"
    mkdir -p "$bin_dir"

    # Stub go: enumerates four tests for -list, reports one package for `go
    # list`, writes a succeeding stub test binary for `go test -c -o <path>`,
    # and reports success for any run.
    cat > "${bin_dir}/go" <<'STUB'
#!/bin/sh
for arg in "$@"; do
    if [ "$arg" = "-list" ]; then
        printf 'TestA\nTestB\nTestC\nTestD\nok\tfeatures/controller/api\t0.01s\n'
        exit 0
    fi
done
if [ "$1" = "list" ]; then
    case "$*" in
        *features/controller/api*) echo "github.com/cfgis/cfgms/features/controller/api" ;;
        *) echo "github.com/cfgis/cfgms/pkg/stubpkg" ;;
    esac
    exit 0
fi
prev=""
for arg in "$@"; do
    if [ "$prev" = "-o" ]; then
        printf '#!/bin/sh\necho "ok  features/controller/api  0.01s"\nexit 0\n' > "$arg"
        chmod +x "$arg"
        exit 0
    fi
    prev="$arg"
done
echo "ok  features/controller/api  0.01s"
exit 0
STUB
    chmod +x "${bin_dir}/go"

    # 1. Arithmetic-injection payload must not execute its command substitution.
    local marker="${tmp_dir}/injection-executed"
    local inj_out inj_rc=0
    inj_out=$(PATH="${bin_dir}:$PATH" CFGMS_API_TEST_SHARDS="a[\$(touch ${marker})]" \
        make test-framework-api-sharded 2>&1) || inj_rc=$?

    if [[ -e "$marker" ]]; then
        log_fail "CFGMS_API_TEST_SHARDS reached bash arithmetic unvalidated — the injected command substitution executed"
        echo "$inj_out" | tail -20
        return
    fi

    if [[ $inj_rc -eq 0 ]]; then
        log_fail "an injection payload in CFGMS_API_TEST_SHARDS produced a passing target (exit 0) — false green in make test"
        echo "$inj_out" | tail -20
        return
    fi

    # 2. A plain non-integer must fail closed rather than launching zero shards.
    local bad_out bad_rc=0
    bad_out=$(PATH="${bin_dir}:$PATH" CFGMS_API_TEST_SHARDS=abc \
        make test-framework-api-sharded 2>&1) || bad_rc=$?

    if [[ $bad_rc -eq 0 ]]; then
        log_fail "CFGMS_API_TEST_SHARDS=abc produced a passing target (exit 0) — zero shards ran and make test still reported success"
        echo "$bad_out" | tail -20
        return
    fi

    if ! echo "$bad_out" | grep -q 'shard count must be a positive integer'; then
        log_fail "target failed but printed no diagnostic explaining the invalid shard count"
        echo "$bad_out" | tail -20
        return
    fi

    # 3. Zero is not a positive integer and must not be accepted either.
    local zero_out zero_rc=0
    zero_out=$(PATH="${bin_dir}:$PATH" CFGMS_API_TEST_SHARDS=0 \
        make test-framework-api-sharded 2>&1) || zero_rc=$?

    if [[ $zero_rc -eq 0 ]]; then
        log_fail "CFGMS_API_TEST_SHARDS=0 produced a passing target (exit 0) — zero shards ran"
        echo "$zero_out" | tail -20
        return
    fi

    # 4. A valid count still runs: validation must not break the normal path.
    local ok_out ok_rc=0
    ok_out=$(PATH="${bin_dir}:$PATH" CFGMS_API_TEST_SHARDS=2 \
        make test-framework-api-sharded 2>&1) || ok_rc=$?

    if [[ $ok_rc -ne 0 ]]; then
        log_fail "a valid CFGMS_API_TEST_SHARDS=2 was rejected (exit ${ok_rc}) — validation is too strict"
        echo "$ok_out" | tail -20
        return
    fi

    # 5. The macOS CI-job-level shard target reimplements the partition instead
    #    of delegating here, so it must carry the same two properties against
    #    its own variable pair: no command execution, and no fail-open.
    #    Their injection vector is awk rather than bash arithmetic — an unquoted
    #    `awk -v s=$shard` lets a value containing whitespace word-split into a
    #    replacement awk program, whose system() runs arbitrary commands.
    local pair shard_var shards_var target
    for pair in "CFGMS_MACOS_REST_SHARD CFGMS_MACOS_REST_SHARDS test-go-group-macos-rest"; do
        # shellcheck disable=SC2086 # deliberate word split of the fixture triple
        set -- $pair
        shard_var="$1"; shards_var="$2"; target="$3"

        local awk_marker="${tmp_dir}/awk-injection-executed"
        local payload_out payload_rc var_name
        for var_name in "$shard_var" "$shards_var"; do
            rm -f "$awk_marker"
            payload_rc=0
            # The payload carries no literal space of its own — word splitting
            # would break it into separate argv entries and awk would reject the
            # fragment as a syntax error — so the command's argument separator
            # is awk's own FS. Verified to create the marker against an
            # unquoted `awk -v n=$shards`, and not to against a quoted one.
            payload_out=$(PATH="${bin_dir}:$PATH" \
                env "${var_name}=1 BEGIN{system(\"touch\"FS\"${awk_marker}\")}" \
                make --no-print-directory "$target" 2>&1) || payload_rc=$?

            if [[ -e "$awk_marker" ]]; then
                log_fail "${var_name} reached awk unvalidated — the injected awk program executed a command in ${target}"
                echo "$payload_out" | tail -20
                return
            fi

            if [[ $payload_rc -eq 0 ]]; then
                log_fail "an injection payload in ${var_name} produced a passing ${target} (exit 0) — false green behind Build Gate"
                echo "$payload_out" | tail -20
                return
            fi

            # A plain non-integer must fail closed rather than emptying the
            # partition and reporting a pass with zero tests run.
            local nonint_out nonint_rc=0
            nonint_out=$(PATH="${bin_dir}:$PATH" env "${var_name}=abc" \
                make --no-print-directory "$target" 2>&1) || nonint_rc=$?

            if [[ $nonint_rc -eq 0 ]]; then
                log_fail "${var_name}=abc produced a passing ${target} (exit 0) — an empty partition ran zero tests and still reported success"
                echo "$nonint_out" | tail -20
                return
            fi

            if ! echo "$nonint_out" | grep -q "${var_name} must be a"; then
                log_fail "${target} failed but printed no diagnostic naming the invalid ${var_name}"
                echo "$nonint_out" | tail -20
                return
            fi
        done

        # Zero shards is not a positive integer (and is a fatal modulus for the
        # BWK awk that macOS runners actually use).
        local zeroshards_out zeroshards_rc=0
        zeroshards_out=$(PATH="${bin_dir}:$PATH" env "${shards_var}=0" \
            make --no-print-directory "$target" 2>&1) || zeroshards_rc=$?

        if [[ $zeroshards_rc -eq 0 ]]; then
            log_fail "${shards_var}=0 produced a passing ${target} (exit 0) — zero shards ran"
            echo "$zeroshards_out" | tail -20
            return
        fi

        # An index outside the partition assigns nothing; that must fail, not
        # report a green leg with no tests.
        local oob_out oob_rc=0
        oob_out=$(PATH="${bin_dir}:$PATH" env "${shard_var}=2" "${shards_var}=2" \
            make --no-print-directory "$target" 2>&1) || oob_rc=$?

        if [[ $oob_rc -eq 0 ]]; then
            log_fail "${shard_var}=2 with ${shards_var}=2 produced a passing ${target} (exit 0) — an out-of-range shard index ran nothing"
            echo "$oob_out" | tail -20
            return
        fi

        # Valid inputs must still run: validation must not break the CI path.
        local valid_out valid_rc=0
        valid_out=$(PATH="${bin_dir}:$PATH" env "${shard_var}=1" "${shards_var}=2" \
            make --no-print-directory "$target" 2>&1) || valid_rc=$?

        if [[ $valid_rc -ne 0 ]]; then
            log_fail "valid ${shard_var}=1 ${shards_var}=2 was rejected by ${target} (exit ${valid_rc}) — validation is too strict"
            echo "$valid_out" | tail -20
            return
        fi
    done

    log_pass "test-framework-api-sharded and the macOS shard groups: injection payloads, non-integer, zero and out-of-range shard values all fail closed; valid counts still run"
}

# Acceptance rule for a skipped macOS leg at the PR-side Build Gate (Issue
# #5974). Table-driven over scripts/macos-gate-rule.sh, the script
# build-gate-pr-stub calls — plus a check that the job's run: block calls it for
# all six macOS legs, so removing the call (or the script) fails here.
test_macos_gate_rule() {
    log_test "Testing macos-gate-rule.sh: skipped macOS legs are accepted only when changes succeeded and macos is exactly false..."

    local rule=scripts/macos-gate-rule.sh
    if [[ ! -f "$rule" ]]; then
        log_fail "$rule is missing"
        return
    fi

    # changes_result|macos_output|leg_result|expected (pass|fail)
    local -a table=(
        "success|false|skipped|pass"
        "success|true|success|pass"
        "success|false|success|pass"
        "success||skipped|fail"
        "success|maybe|skipped|fail"
        "failure|false|skipped|fail"
        "cancelled||skipped|fail"
        "success|true|skipped|fail"
        "success|true|failure|fail"
        "success|false|failure|fail"
        "success|true|cancelled|fail"
    )
    local row changes macos leg want rc
    for row in "${table[@]}"; do
        IFS='|' read -r changes macos leg want <<< "$row"
        rc=0
        bash "$rule" "$changes" "$macos" "$leg" >/dev/null 2>&1 || rc=$?
        if [[ "$want" == "pass" && $rc -ne 0 ]] || [[ "$want" == "fail" && $rc -eq 0 ]]; then
            log_fail "macos-gate-rule.sh changes='${changes}' macos='${macos}' leg='${leg}': want ${want}, exit ${rc}"
            return
        fi
    done

    local wf=.github/workflows/cross-platform-build-pr.yml run_block
    run_block=$(awk '/^  build-gate-pr-stub:/ { on = 1 } on' "$wf")
    if [[ -z "$run_block" ]]; then
        log_fail "build-gate-pr-stub not found in $wf"
        return
    fi
    local leg_var
    for leg_var in MACOS_PROVIDERS_RESULT MACOS_STEWARD_RESULT MACOS_CMD_STEWARD_1_RESULT MACOS_CMD_STEWARD_2_RESULT MACOS_REST_1_RESULT MACOS_REST_2_RESULT; do
        if ! grep -qF "\"\$${leg_var}\"" <<< "$run_block"; then
            log_fail "build-gate-pr-stub does not check ${leg_var}"
            return
        fi
    done
    # The six legs sit in their own loop whose body calls the rule script;
    # none of them may also sit in the generic loop that accepts a skipped
    # result on any docs-only PR, or the rule would be bypassed.
    local macos_loop_re='for result in "\$MACOS_PROVIDERS_RESULT" "\$MACOS_STEWARD_RESULT" "\$MACOS_CMD_STEWARD_1_RESULT" "\$MACOS_CMD_STEWARD_2_RESULT" "\$MACOS_REST_1_RESULT" "\$MACOS_REST_2_RESULT"; do'
    if ! grep -A2 -E "$macos_loop_re" <<< "$run_block" | grep -qE 'macos-gate-rule\.sh "\$CHANGES_RESULT" "\$MACOS_CHANGES" "\$result"'; then
        log_fail "the six macOS legs are not each passed to macos-gate-rule.sh (changes result, macos output, leg result) in one loop"
        return
    fi
    if grep -E '^[[:space:]]*for result in ' <<< "$run_block" | grep -vE "$macos_loop_re" | grep -qE 'MACOS_(PROVIDERS|STEWARD|CMD_STEWARD_1|CMD_STEWARD_2|REST_1|REST_2)_RESULT'; then
        log_fail "a macOS leg is also checked by another loop in build-gate-pr-stub"
        return
    fi
    if ! grep -q 'MACOS_CHANGES: \${{ needs.changes.outputs.macos }}' <<< "$run_block"; then
        log_fail "build-gate-pr-stub does not pass needs.changes.outputs.macos through env:"
        return
    fi

    # The six legs themselves are gated on the macos output; the Windows and
    # e2e legs still on code.
    local leg
    for leg in macos-providers macos-steward macos-cmd-steward-1 macos-cmd-steward-2 macos-rest-1 macos-rest-2; do
        if ! awk -v job="  ${leg}:" '$0 == job { on = 1; next } on && /^  [a-z0-9-]+:$/ { exit } on && /^    if:/ { print }' "$wf" \
            | grep -qF "needs.changes.outputs.macos == 'true'"; then
            log_fail "$leg is not gated on needs.changes.outputs.macos == 'true'"
            return
        fi
    done
    for leg in windows-api windows-controller windows-steward windows-cmd windows-cmd-steward-1 windows-cmd-steward-2 windows-rest e2e; do
        if ! awk -v job="  ${leg}:" '$0 == job { on = 1; next } on && /^  [a-z0-9-]+:$/ { exit } on && /^    if:/ { print }' "$wf" \
            | grep -qF "needs.changes.outputs.code == 'true'"; then
            log_fail "$leg is no longer gated on needs.changes.outputs.code == 'true'"
            return
        fi
    done

    log_pass "macos-gate-rule.sh: 11-row table holds; build-gate-pr-stub calls it for all six macOS legs and the legs are gated on the macos output"
}

# The macOS legs are skipped on a PR outside the macOS package closure, so the
# Linux compile job is what still fails a PR that breaks only the darwin test
# build (Issue #5974). The Build Gate must need it, check its result in the
# leg loop and the job must run `make test-macos-compile`.
test_build_gate_requires_macos_test_compile() {
    log_test "Testing build-gate-pr-stub needs macos-test-compile, checks it, and the job runs make test-macos-compile..."

    local wf=.github/workflows/cross-platform-build-pr.yml
    local gate job
    gate=$(awk '/^  build-gate-pr-stub:/ { on = 1 } on' "$wf")
    job=$(awk '$0 == "  macos-test-compile:" { on = 1; next } on && /^  [a-z0-9-]+:$/ { exit } on' "$wf")
    if [[ -z "$gate" || -z "$job" ]]; then
        log_fail "build-gate-pr-stub or macos-test-compile not found in $wf"
        return
    fi

    if ! grep -qE '^      - macos-test-compile$' <<< "$gate"; then
        log_fail "build-gate-pr-stub does not list macos-test-compile in needs:"
        return
    fi
    if ! grep -qF 'MACOS_COMPILE_RESULT: ${{ needs.macos-test-compile.result }}' <<< "$gate"; then
        log_fail "build-gate-pr-stub does not read needs.macos-test-compile.result"
        return
    fi
    # It sits in the loop that accepts skipped only on a docs-only PR.
    if ! grep -E '^[[:space:]]*for result in ' <<< "$gate" | grep -qF '"$MACOS_COMPILE_RESULT"'; then
        log_fail "MACOS_COMPILE_RESULT is not in build-gate-pr-stub's leg loop"
        return
    fi
    if ! grep -qE '^    if: always\(\) && needs\.changes\.outputs\.code == .true.$' <<< "$job"; then
        log_fail "macos-test-compile is not gated on needs.changes.outputs.code == 'true'"
        return
    fi
    if ! grep -qE '^      run: make test-macos-compile$' <<< "$job"; then
        log_fail "macos-test-compile does not run make test-macos-compile"
        return
    fi
    if ! grep -qE '^    runs-on: ubuntu-latest$' <<< "$job"; then
        log_fail "macos-test-compile does not run on ubuntu-latest"
        return
    fi
    if ! grep -qE '^test-macos-compile:' Makefile || ! grep -A12 -E '^test-macos-compile:' Makefile | grep -q 'GOOS=darwin GOARCH=arm64 go test'; then
        log_fail "Makefile target test-macos-compile does not compile the test binaries with GOOS=darwin GOARCH=arm64 go test"
        return
    fi

    log_pass "build-gate-pr-stub needs macos-test-compile and checks its result; the job runs make test-macos-compile on Linux"
}

# scripts/macos-pr-filter.sh against the real repository (Issue #5974): the
# six macOS legs may be skipped only when no changed file is in the closure.
test_macos_pr_filter() {
    log_test "Testing macos-pr-filter.sh against the real package closure..."

    local filter=scripts/macos-pr-filter.sh
    if [[ ! -f "$filter" ]]; then
        log_fail "$filter is missing"
        return
    fi

    local tmp
    tmp=$(mktemp -d)

    # decide <name> <file>...: prints the filter's stdout for that changed set.
    decide() {
        local list="$tmp/files.txt"
        printf '%s\n' "$@" > "$list"
        bash "$filter" --files "$list" 2>/dev/null
    }

    local mod=github.com/cfgis/cfgms/
    local shipped closure
    shipped=$(bash "$filter" --print-shipped-closure 2>/dev/null) || shipped=""
    closure=$(bash "$filter" --print-closure 2>/dev/null) || closure=""
    if [[ -z "$shipped" || -z "$closure" ]]; then
        log_fail "the filter printed no closure (shipped: $(echo "$shipped" | wc -l), full: $(echo "$closure" | wc -l))"
        rm -rf "$tmp"
        return
    fi

    # features/controller/api must be reached only through test imports, and
    # features/controller/fleet must be in step 1; the cases below rely on both.
    local test_deps
    test_deps=$(GOOS=darwin go list -deps -test -f '{{.ImportPath}}' $(GOOS=darwin go list -deps -f '{{if and (not .Standard) .Module}}{{if .Module.Main}}{{.ImportPath}}{{end}}{{end}}' ./cmd/steward ./cmd/cfgms-steward-launcher ./cmd/cfg) 2>/dev/null) || test_deps=""
    if grep -qxF "features/controller/api" <<< "$shipped"; then
        log_fail "features/controller/api is in step 1 (production imports); the controller-exclusion case no longer tests step 2"
        rm -rf "$tmp"
        return
    fi
    if ! grep -qxF "${mod}features/controller/api" <<< "$test_deps"; then
        log_fail "features/controller/api is no longer reached through closure test imports; pick another controller package for this case"
        rm -rf "$tmp"
        return
    fi
    if ! grep -qxF "features/controller/fleet" <<< "$shipped"; then
        log_fail "features/controller/fleet is not in step 1 any more; pick another production-imported controller package"
        rm -rf "$tmp"
        return
    fi

    local testdata_dir="" d
    for d in $shipped; do
        if [[ -d "$d/testdata" ]]; then
            testdata_dir="$d"
            break
        fi
    done
    if [[ -z "$testdata_dir" ]]; then
        log_fail "no closure package has a testdata/ directory to exercise the testdata rule"
        rm -rf "$tmp"
        return
    fi

    local out
    check() {
        local want="$1" label="$2"
        shift 2
        out=$(decide "$@") || out="<filter error>"
        if [[ "$out" != "macos=${want}" ]]; then
            log_fail "macos-pr-filter: ${label}: want macos=${want}, got '${out}'"
            return 1
        fi
    }

    check false "docs-only change" docs/development/ci-test-tiers.md docs/product/vision.md || { rm -rf "$tmp"; return; }
    check true "Go file in pkg/cert" pkg/cert/zz_changed.go || { rm -rf "$tmp"; return; }
    check true "non-Go file in a closure package directory" pkg/cert/zz_changed.txt || { rm -rf "$tmp"; return; }
    check true "file under a closure package's testdata/ (${testdata_dir})" "${testdata_dir}/testdata/zz/nested.json" || { rm -rf "$tmp"; return; }
    check true "go.mod" go.mod || { rm -rf "$tmp"; return; }
    check true "go.sum" go.sum || { rm -rf "$tmp"; return; }
    check true "Makefile" Makefile || { rm -rf "$tmp"; return; }
    check true "the PR workflow" .github/workflows/cross-platform-build-pr.yml || { rm -rf "$tmp"; return; }
    check true "the filter script itself" scripts/macos-pr-filter.sh || { rm -rf "$tmp"; return; }
    check false "Go file in features/controller/api (test-import only)" features/controller/api/zz_changed.go || { rm -rf "$tmp"; return; }
    check true "Go file in features/controller/fleet (production import)" features/controller/fleet/zz_changed.go || { rm -rf "$tmp"; return; }
    check true "docs plus one closure file" docs/a.md pkg/cert/zz_changed.go || { rm -rf "$tmp"; return; }

    # Embedded files outside the package directory itself are triggers.
    local embed_file
    embed_file=$(GOOS=darwin go list -deps -f '{{if and (not .Standard) .Module}}{{if .Module.Main}}{{$d := .Dir}}{{range .EmbedFiles}}{{$d}}/{{.}}{{"\n"}}{{end}}{{end}}{{end}}' ./cmd/steward ./cmd/cfgms-steward-launcher ./cmd/cfg 2>/dev/null \
        | grep -E "^$PWD/.+/.+/" | head -1 | sed "s#^$PWD/##") || embed_file=""
    if [[ -n "$embed_file" ]]; then
        check true "embedded file ${embed_file}" "$embed_file" || { rm -rf "$tmp"; return; }
    fi

    # Renamed files: the pre-rename name counts, even when the new name is docs.
    printf 'docs/moved.md\n' > "$tmp/files.txt"
    printf 'pkg/cert/zz_old_name.go\n' > "$tmp/renamed.txt"
    out=$(bash "$filter" --files "$tmp/files.txt" --renamed "$tmp/renamed.txt" 2>/dev/null) || out="<filter error>"
    if [[ "$out" != "macos=true" ]]; then
        log_fail "macos-pr-filter: a rename out of a closure package: want macos=true, got '${out}'"
        rm -rf "$tmp"
        return
    fi
    printf 'docs/old.md\n' > "$tmp/renamed.txt"
    out=$(bash "$filter" --files "$tmp/files.txt" --renamed "$tmp/renamed.txt" 2>/dev/null) || out="<filter error>"
    if [[ "$out" != "macos=false" ]]; then
        log_fail "macos-pr-filter: a docs-to-docs rename: want macos=false, got '${out}'"
        rm -rf "$tmp"
        return
    fi

    # Fail-closed defects: every one must resolve to macos=true.
    : > "$tmp/empty.txt"
    out=$(bash "$filter" --files "$tmp/empty.txt" 2>/dev/null) || out="<filter error>"
    if [[ "$out" != "macos=true" ]]; then
        log_fail "macos-pr-filter: an empty input list: want macos=true, got '${out}'"
        rm -rf "$tmp"
        return
    fi
    out=$(bash "$filter" --files "$tmp/does-not-exist.txt" 2>/dev/null) || out="<filter error>"
    if [[ "$out" != "macos=true" ]]; then
        log_fail "macos-pr-filter: an unreadable input list: want macos=true, got '${out}'"
        rm -rf "$tmp"
        return
    fi
    out=$(bash "$filter" 2>/dev/null) || out="<filter error>"
    if [[ "$out" != "macos=true" ]]; then
        log_fail "macos-pr-filter: no --files argument: want macos=true, got '${out}'"
        rm -rf "$tmp"
        return
    fi
    # A forced go list failure: a module root with the Makefile roots but no
    # go.mod, so `go list` itself errors.
    mkdir -p "$tmp/nomod"
    cp Makefile "$tmp/nomod/Makefile"
    printf 'docs/a.md\n' > "$tmp/files.txt"
    out=$(bash "$filter" --files "$tmp/files.txt" --root "$tmp/nomod" 2>/dev/null) || out="<filter error>"
    if [[ "$out" != "macos=true" ]]; then
        log_fail "macos-pr-filter: a go list failure on a docs-only list: want macos=true, got '${out}'"
        rm -rf "$tmp"
        return
    fi
    out=$(bash "$filter" --files "$tmp/files.txt" --root "$tmp/missing-dir" 2>/dev/null) || out="<filter error>"
    if [[ "$out" != "macos=true" ]]; then
        log_fail "macos-pr-filter: a nonexistent module root: want macos=true, got '${out}'"
        rm -rf "$tmp"
        return
    fi
    out=$(bash "$filter" --bogus-flag 2>/dev/null) || out="<filter error>"
    if [[ "$out" != "macos=true" ]]; then
        log_fail "macos-pr-filter: an unknown flag: want macos=true, got '${out}'"
        rm -rf "$tmp"
        return
    fi
    # Nothing but the result line may reach stdout, which the workflow appends
    # to $GITHUB_OUTPUT.
    out=$(bash "$filter" --files "$tmp/files.txt" 2>/dev/null)
    if [[ "$(echo "$out" | wc -l | tr -d ' ')" != "1" ]]; then
        log_fail "macos-pr-filter: stdout is not exactly one line: '${out}'"
        rm -rf "$tmp"
        return
    fi

    # The closure must contain every package the macOS legs test.
    local legs_pkgs missing="" p rel
    legs_pkgs=$(GOOS=darwin go list -deps -f '{{if and (not .Standard) (or .TestGoFiles .XTestGoFiles)}}{{.ImportPath}}{{end}}' \
        ./cmd/steward ./cmd/cfgms-steward-launcher ./cmd/cfg 2>/dev/null | grep -E "^${mod}") || legs_pkgs=""
    if [[ -z "$legs_pkgs" ]]; then
        log_fail "GOOS=darwin go list produced no macOS-shipped test packages"
        rm -rf "$tmp"
        return
    fi
    for p in $legs_pkgs; do
        rel="${p#"$mod"}"
        grep -qxF "$rel" <<< "$closure" || missing+="$rel "
    done
    if [[ -n "$missing" ]]; then
        log_fail "package(s) tested by the macOS legs are outside the filter's closure: $missing"
        rm -rf "$tmp"
        return
    fi

    # The roots are defined once, in the Makefile, and used by both.
    if ! grep -qE '^MACOS_SHIPPED_ROOTS = \./cmd/steward \./cmd/cfgms-steward-launcher \./cmd/cfg$' Makefile \
        || ! grep -E '^MACOS_SHIPPED_PKGS = ' Makefile | grep -qF '$(MACOS_SHIPPED_ROOTS)' \
        || grep -E '^MACOS_SHIPPED_PKGS = ' Makefile | grep -qF './cmd/'; then
        log_fail "MACOS_SHIPPED_PKGS must use the MACOS_SHIPPED_ROOTS variable and not repeat the binary roots"
        rm -rf "$tmp"
        return
    fi
    if grep -vE '^[[:space:]]*#' "$filter" | grep -qE '\./cmd/(steward|cfg)'; then
        log_fail "$filter hardcodes a binary root instead of reading MACOS_SHIPPED_ROOTS from the Makefile"
        rm -rf "$tmp"
        return
    fi

    rm -rf "$tmp"
    log_pass "macos-pr-filter.sh: closure of $(echo "$closure" | wc -l | tr -d ' ') dirs; docs skip, closure/testdata/go.mod trigger, controller test-only skips, every defect fails closed"
}

# Regression guard for the macOS unit-test legs (Issue #5746): the union of the
# test-go-group-macos-* package lists must equal the in-module packages with
# test files in the GOOS=darwin dependency closure of the three macOS-shipped
# binaries — nothing outside it (no controller-only package), nothing in it
# left out. GOOS=darwin is pinned on both sides so this holds on a Linux host.
test_macos_groups_cover_exactly_shipped_packages() {
    log_test "Testing macOS groups: union equals the GOOS=darwin shipped-package set exactly..."

    local pkg_filter='^github\.com/cfgis/cfgms/'
    local expected expected_rc=0
    expected=$(GOOS=darwin go list -deps -f '{{if and (not .Standard) (or .TestGoFiles .XTestGoFiles)}}{{.ImportPath}}{{end}}' \
        ./cmd/steward ./cmd/cfgms-steward-launcher ./cmd/cfg 2>&1 | grep -E "$pkg_filter" | sort -u) || expected_rc=$?
    if [[ $expected_rc -ne 0 || -z "$expected" ]]; then
        log_fail "GOOS=darwin go list -deps produced no shipped packages (rc=${expected_rc})"
        return
    fi

    # Every macos group target in the Makefile, discovered rather than listed,
    # so a newly added group is included in the union automatically. The name
    # pattern admits digits and hyphens (test-go-group-macos-cmd-steward-1), so
    # a numbered or hyphenated shard target cannot fall out of the union.
    # Rest is enumerated across two shards.
    local targets target
    targets=$(grep -oE '^test-go-group-macos-[a-z0-9-]+:' Makefile | tr -d ':')
    if [[ -z "$targets" ]]; then
        log_fail "no test-go-group-macos-* targets found in Makefile"
        return
    fi

    # cmd/steward (Issue #6033) is the one package that may appear in several
    # targets, and only as name shards: a target whose package list is exactly
    # cmd/steward and whose go test line carries a -run pattern. A target that
    # lists cmd/steward together with other packages, or without -run, is an
    # ordinary group, so a second appearance is a duplicate.
    local steward_pkg="github.com/cfgis/cfgms/cmd/steward"
    local actual="" out shard pkgs gotest pattern
    local -a shard_targets=() shard_patterns=()
    local plain_steward_targets=0
    for target in $targets; do
        for shard in 0 1; do
            local rc=0
            out=$(CFGMS_TEST_GROUP_LIST_ONLY=1 CFGMS_MACOS_REST_SHARD=$shard CFGMS_MACOS_REST_SHARDS=2 \
                make --no-print-directory "$target" 2>&1) || rc=$?
            if [[ $rc -ne 0 ]]; then
                log_fail "${target} (shard ${shard}) failed in list-only mode"
                echo "$out" | tail -10
                return
            fi
            pkgs=$(echo "$out" | grep -E "$pkg_filter" || true)
            if grep -qxF "$steward_pkg" <<< "$pkgs"; then
                gotest=$(make -n --no-print-directory "$target" 2>&1 | grep -oE 'go test [^;]*' | head -1)
                pattern=$(sed -nE "s/.* -run '([^']*)'.*/\1/p" <<< "$gotest")
                if [[ "$(wc -l <<< "$pkgs" | tr -d ' ')" == "1" && -n "$pattern" ]]; then
                    shard_targets+=("$target")
                    shard_patterns+=("$pattern")
                    # cmd/steward is listed once however many shards run it.
                    break
                fi
                plain_steward_targets=$((plain_steward_targets + 1))
            fi
            actual+="$pkgs"$'\n'
            # Non-sharded targets are identical across shard values.
            [[ "$target" == "test-go-group-macos-rest" ]] || break
        done
    done
    if [[ ${#shard_targets[@]} -gt 0 ]]; then
        if [[ $plain_steward_targets -gt 0 ]]; then
            log_fail "cmd/steward is name-sharded (${shard_targets[*]}) but also appears in a target that is not a -run shard of cmd/steward alone"
            return
        fi
        actual+="$steward_pkg"$'\n'
    fi

    # The two heaviest rest packages must not share a shard (Issue #5967).
    local heavy_a heavy_b
    heavy_a=$(CFGMS_TEST_GROUP_LIST_ONLY=1 CFGMS_MACOS_REST_SHARD=0 CFGMS_MACOS_REST_SHARDS=2 \
        make --no-print-directory test-go-group-macos-rest 2>&1 | grep -cE '/(features/workflow|pkg/storage/interfaces)$')
    heavy_b=$(CFGMS_TEST_GROUP_LIST_ONLY=1 CFGMS_MACOS_REST_SHARD=1 CFGMS_MACOS_REST_SHARDS=2 \
        make --no-print-directory test-go-group-macos-rest 2>&1 | grep -cE '/(features/workflow|pkg/storage/interfaces)$')
    if [[ "$heavy_a" != "1" || "$heavy_b" != "1" ]]; then
        log_fail "macOS rest shards are not weight-balanced: heavy packages split ${heavy_a}/${heavy_b}, want 1/1"
        return
    fi

    local dups
    dups=$(echo "$actual" | grep . | sort | uniq -d)
    if [[ -n "$dups" ]]; then
        log_fail "package(s) appear in more than one macOS group: $(echo "$dups" | head -5 | tr '\n' ' ')"
        return
    fi

    local extra missing
    actual=$(echo "$actual" | grep . | sort -u)
    extra=$(comm -13 <(echo "$expected") <(echo "$actual"))
    missing=$(comm -23 <(echo "$expected") <(echo "$actual"))
    if [[ -n "$extra" ]]; then
        log_fail "macOS group(s) test package(s) outside the shipped set: $(echo "$extra" | head -5 | tr '\n' ' ')"
        return
    fi
    if [[ -n "$missing" ]]; then
        log_fail "shipped package(s) left out of every macOS group: $(echo "$missing" | head -5 | tr '\n' ' ')"
        return
    fi

    if grep -qE 'test-go-group-macos-(api|controller)' Makefile .github/workflows/cross-platform-build-pr.yml; then
        log_fail "a macos-api or macos-controller target/leg still exists"
        return
    fi

    if [[ ${#shard_targets[@]} -lt 2 ]]; then
        log_fail "cmd/steward has ${#shard_targets[@]} -run shard target(s) on macOS; a single shard is not a partition and none leaves it unrun or in an unbounded group"
        return
    fi
    # go test -run has no "everything else", so the shards are explicit
    # patterns; every probe test name must match exactly one of them. The probes
    # are Test followed by every combination of up to three characters from
    # A-Z a-z 0-9 _ and two non-ASCII letters (the patterns look at no more than
    # three), plus bare "Test" (a valid test name). Example*/Fuzz*/Benchmark*
    # names would not match any shard, so the package must have none, or those
    # tests would be dropped. TestMain is not filtered by -run.
    if grep -qE '^func (Example|Fuzz|Benchmark)' cmd/steward/*_test.go; then
        log_fail "cmd/steward has Example/Fuzz/Benchmark functions that no ^Test shard runs"
        return
    fi
    local probes matched dist_counts probe_count matched_distinct
    probes=$(awk 'BEGIN {
        n = split("A B C D E F G H I J K L M N O P Q R S T U V W X Y Z a b c d e f g h i j k l m n o p q r s t u v w x y z 0 1 2 3 4 5 6 7 8 9 _ é Ω", c, " ")
        print "Test"
        for (i = 1; i <= n; i++) {
            print "Test" c[i]
            for (j = 1; j <= n; j++) {
                print "Test" c[i] c[j]
                for (k = 1; k <= n; k++) print "Test" c[i] c[j] c[k]
            }
        }
        print "TestRegisterAndConnect_X"; print "TestRegTokenX"; print "TestRunSteward_X"; print "TestRepair_X"
    }')
    probe_count=$(printf '%s\n' "$probes" | LC_ALL=C sort -u | wc -l | tr -d ' ')
    matched=$(
        for pattern in "${shard_patterns[@]}"; do
            printf '%s\n' "$probes" | LC_ALL=C.UTF-8 grep -E -- "$pattern" || true
        done | LC_ALL=C sort
    )
    # A name matching two shards appears twice in the match stream; a name
    # matching none does not appear, so the distinct count falls short.
    dist_counts=$(uniq -c <<< "$matched" | awk '{print $1}' | sort -u | tr '\n' ' ')
    matched_distinct=$(uniq <<< "$matched" | wc -l | tr -d ' ')
    if [[ "$dist_counts" != "1 " || "$matched_distinct" != "$probe_count" ]]; then
        log_fail "macOS cmd/steward shard patterns are not an exact partition of ^Test names (${matched_distinct} of ${probe_count} probe names matched; matches-per-name values: ${dist_counts}); patterns: ${shard_patterns[*]}"
        return
    fi
    for pattern in "${shard_patterns[@]}"; do
        if printf '%s\n' ExampleFoo FuzzFoo BenchmarkFoo | grep -qE -- "$pattern"; then
            log_fail "macOS cmd/steward shard pattern '${pattern}' matches a non-Test name"
            return
        fi
    done

    log_pass "macOS groups: $(echo "$actual" | wc -l | tr -d ' ') packages, exactly the GOOS=darwin shipped set, no duplicates, cmd/steward in ${#shard_targets[@]} -run shards that exactly partition ^Test names"
}

test_windows_steward_groups_cover_exactly_steward_and_cmd() {
    log_test "Testing Windows steward groups: union equals ./features/steward/... plus ./cmd/... exactly, cmd/steward shards partition its tests..."

    local expected expected_rc=0
    expected=$(go list ./features/steward/... ./cmd/... 2>&1 | sort -u) || expected_rc=$?
    if [[ $expected_rc -ne 0 || -z "$expected" ]]; then
        log_fail "go list ./features/steward/... ./cmd/... produced no packages (rc=${expected_rc})"
        return
    fi

    # Every windows-steward / windows-cmd group target, discovered rather than
    # listed, so a newly added split leg joins the union automatically.
    local targets target
    targets=$(grep -oE '^test-go-group-windows-(steward|cmd)[a-z0-9-]*:' Makefile | tr -d ':')
    if [[ -z "$targets" ]]; then
        log_fail "no test-go-group-windows-steward/cmd targets found in Makefile"
        return
    fi

    # cmd/steward (Issue #6010) is the one package that may appear in several
    # targets, and only as name shards: a target whose package list is exactly
    # cmd/steward and whose go test line carries a -run pattern. A target that
    # lists cmd/steward together with other packages, or without -run, is an
    # ordinary group, so a second appearance is a duplicate.
    local steward_pkg="github.com/cfgis/cfgms/cmd/steward"
    local actual="" out rc pkgs gotest pattern
    local -a shard_targets=() shard_patterns=()
    local steward_targets=0 plain_steward_targets=0
    for target in $targets; do
        rc=0
        out=$(CFGMS_TEST_GROUP_LIST_ONLY=1 make --no-print-directory "$target" 2>&1) || rc=$?
        if [[ $rc -ne 0 ]]; then
            log_fail "${target} failed in list-only mode"
            echo "$out" | tail -10
            return
        fi
        pkgs=$(echo "$out" | grep -E '^github\.com/cfgis/cfgms/' || true)
        if grep -qxF "$steward_pkg" <<< "$pkgs"; then
            steward_targets=$((steward_targets + 1))
            gotest=$(make -n --no-print-directory "$target" 2>&1 | grep -oE 'go test [^;]*' | head -1)
            pattern=$(sed -nE "s/.* -run '([^']*)'.*/\1/p" <<< "$gotest")
            if [[ "$(wc -l <<< "$pkgs" | tr -d ' ')" == "1" && -n "$pattern" ]]; then
                shard_targets+=("$target")
                shard_patterns+=("$pattern")
                # cmd/steward is listed once however many shards run it.
                continue
            fi
            plain_steward_targets=$((plain_steward_targets + 1))
        fi
        actual+="$pkgs"$'\n'
    done
    if [[ ${#shard_targets[@]} -gt 0 ]]; then
        if [[ $plain_steward_targets -gt 0 ]]; then
            log_fail "cmd/steward is name-sharded (${shard_targets[*]}) but also appears in a target that is not a -run shard of cmd/steward alone"
            return
        fi
        actual+="$steward_pkg"$'\n'
    fi

    local dups extra missing
    dups=$(echo "$actual" | grep . | sort | uniq -d)
    if [[ -n "$dups" ]]; then
        log_fail "package(s) appear in more than one Windows steward group: $(echo "$dups" | head -5 | tr '\n' ' ')"
        return
    fi
    actual=$(echo "$actual" | grep . | sort -u)
    extra=$(comm -13 <(echo "$expected") <(echo "$actual"))
    missing=$(comm -23 <(echo "$expected") <(echo "$actual"))
    if [[ -n "$extra" ]]; then
        log_fail "Windows steward group(s) list package(s) outside steward/cmd: $(echo "$extra" | head -5 | tr '\n' ' ')"
        return
    fi
    if [[ -n "$missing" ]]; then
        log_fail "steward/cmd package(s) left out of every Windows steward group: $(echo "$missing" | head -5 | tr '\n' ' ')"
        return
    fi

    if [[ ${#shard_targets[@]} -eq 1 ]]; then
        log_fail "cmd/steward has one -run shard (${shard_targets[0]}); a single shard is not a partition"
        return
    fi
    local shard_note=""
    if [[ ${#shard_targets[@]} -gt 1 ]]; then
        # go test -run has no "everything else", so the shards are explicit
        # patterns; every probe test name must match exactly one of them. The
        # probes are Test followed by every combination of up to three
        # characters from A-Z a-z 0-9 _ and two non-ASCII letters (the
        # patterns look at no more than three), plus bare "Test" (a valid test
        # name). Example*/Fuzz*/Benchmark* names would not match any shard, so
        # the package must have none, or those tests would be dropped.
        if grep -qE '^func (Example|Fuzz|Benchmark)' cmd/steward/*_test.go; then
            log_fail "cmd/steward has Example/Fuzz/Benchmark functions that no ^Test shard runs"
            return
        fi
        local probes matched dist_counts probe_count matched_distinct
        probes=$(awk 'BEGIN {
            n = split("A B C D E F G H I J K L M N O P Q R S T U V W X Y Z a b c d e f g h i j k l m n o p q r s t u v w x y z 0 1 2 3 4 5 6 7 8 9 _ é Ω", c, " ")
            print "Test"
            for (i = 1; i <= n; i++) {
                print "Test" c[i]
                for (j = 1; j <= n; j++) {
                    print "Test" c[i] c[j]
                    for (k = 1; k <= n; k++) print "Test" c[i] c[j] c[k]
                }
            }
            print "TestRegisterAndConnect_X"; print "TestRunSteward_X"; print "TestRepair_X"
        }')
        probe_count=$(printf '%s\n' "$probes" | LC_ALL=C sort -u | wc -l | tr -d ' ')
        matched=$(
            for pattern in "${shard_patterns[@]}"; do
                printf '%s\n' "$probes" | LC_ALL=C.UTF-8 grep -E -- "$pattern" || true
            done | LC_ALL=C sort
        )
        # A name matching two shards appears twice in the match stream; a name
        # matching none does not appear, so the distinct count falls short.
        dist_counts=$(uniq -c <<< "$matched" | awk '{print $1}' | sort -u | tr '\n' ' ')
        matched_distinct=$(uniq <<< "$matched" | wc -l | tr -d ' ')
        if [[ "$dist_counts" != "1 " || "$matched_distinct" != "$probe_count" ]]; then
            log_fail "cmd/steward shard patterns are not an exact partition of ^Test names (${matched_distinct} of ${probe_count} probe names matched; matches-per-name values: ${dist_counts}); patterns: ${shard_patterns[*]}"
            return
        fi
        for pattern in "${shard_patterns[@]}"; do
            if printf '%s\n' ExampleFoo FuzzFoo BenchmarkFoo | grep -qE -- "$pattern"; then
                log_fail "cmd/steward shard pattern '${pattern}' matches a non-Test name"
                return
            fi
        done
        shard_note=", cmd/steward in ${#shard_targets[@]} -run shards that exactly partition ^Test names"
    fi

    log_pass "Windows steward groups: $(echo "$actual" | wc -l | tr -d ' ') packages, exactly features/steward + cmd, no duplicates${shard_note}"
}

# Issues #6010 (Windows) and #6033 (macOS). A job that runs cmd/steward must
# end in Go's own "panic: test timed out" naming the running test, not in a job
# cancel with no output. -timeout counts from the test binary's start, which is
# up to ~7.2 minutes after the job starts on Windows (setup up to 152s plus
# ~280s from the make step to the binary start) and up to ~5.6 minutes on macOS
# (setup 51-65s plus 179-268s), so -timeout must be at most the job's
# timeout-minutes minus 9; and go test streams -v output only for a single
# package or with -json, so cmd/steward must not share an invocation with other
# packages unless -json is set.
#
# check_cmd_steward_timeout_and_streaming <runs-on label> <display name>: checks
# every `runs-on: <label>` job whose make target lists cmd/steward in
# CFGMS_TEST_GROUP_LIST_ONLY=1 mode (the group targets pass $$pkgs, so the
# package count is read from list-only mode, not from `make -n`). Fails when
# no such job exists.
check_cmd_steward_timeout_and_streaming() {
    local runs_on="$1" name="$2"
    local wf=.github/workflows/cross-platform-build-pr.yml
    local steward_pkg="github.com/cfgis/cfgms/cmd/steward"
    local jobs job
    # job|timeout-minutes|make target for every runs-on: <label> job.
    jobs=$(awk -v label="$runs_on" '
        function flush() { if (job != "" && hit) print job "|" tmo "|" tgt }
        /^  [a-z0-9-]+:[[:space:]]*$/ { flush(); job = $1; sub(/:$/, "", job); hit = 0; tmo = ""; tgt = ""; next }
        /^[^ #]/ { flush(); job = "" }
        job != "" && $1 == "runs-on:" && $2 == label { hit = 1 }
        job != "" && /^    timeout-minutes:/ { tmo = $2 }
        job != "" && /run:[[:space:]]*make[[:space:]]+[a-z0-9-]+/ { for (i = 1; i <= NF; i++) if ($i == "make") tgt = $(i + 1) }
        END { flush() }
    ' "$wf")
    if [[ -z "$jobs" ]]; then
        log_fail "no runs-on: ${runs_on} jobs found in $wf"
        return 1
    fi

    local checked=0 tmo tgt out rc pkgs gotest n npkgs
    while IFS='|' read -r job tmo tgt; do
        [[ -z "$tgt" ]] && continue
        rc=0
        out=$(CFGMS_TEST_GROUP_LIST_ONLY=1 make --no-print-directory "$tgt" 2>&1) || rc=$?
        if [[ $rc -ne 0 ]]; then
            log_fail "${job}: make ${tgt} failed in list-only mode"
            return 1
        fi
        pkgs=$(echo "$out" | grep -E '^github\.com/cfgis/cfgms/' || true)
        grep -qxF "$steward_pkg" <<< "$pkgs" || continue
        checked=$((checked + 1))

        if [[ ! "$tmo" =~ ^[0-9]+$ ]]; then
            log_fail "${job}: no integer timeout-minutes (got '${tmo}')"
            return 1
        fi
        gotest=$(make -n --no-print-directory "$tgt" 2>&1 | grep -oE 'go test [^;]*' | head -1)
        if [[ -z "$gotest" ]]; then
            log_fail "${job}: make ${tgt} has no go test invocation"
            return 1
        fi
        n=$(sed -nE 's/.* -timeout=([0-9]+)m( .*|$)/\1/p' <<< "$gotest")
        if [[ -z "$n" ]]; then
            log_fail "${job}: ${tgt} has no go test -timeout=<N>m (${gotest})"
            return 1
        fi
        if (( n > tmo - 9 )); then
            log_fail "${job}: ${tgt} -timeout=${n}m exceeds timeout-minutes ${tmo} minus 9 (${tmo}-9=$((tmo - 9))m); the timeout panic would land at or after the job cancel"
            return 1
        fi
        npkgs=$(wc -l <<< "$pkgs" | tr -d ' ')
        if (( npkgs > 1 )) && ! grep -qE ' -json( |$)' <<< "$gotest"; then
            log_fail "${job}: ${tgt} runs cmd/steward with ${npkgs} packages without -json, so go test buffers its output until the package ends"
            return 1
        fi
    done <<< "$jobs"

    if (( checked == 0 )); then
        log_fail "no ${name} job in $wf runs cmd/steward"
        return 1
    fi
    CMD_STEWARD_CHECKED_JOBS=$checked
}

test_windows_cmd_steward_timeout_and_streaming() {
    log_test "Testing Windows jobs running cmd/steward: go test -timeout <= timeout-minutes - 9, streamed output..."

    CMD_STEWARD_CHECKED_JOBS=0
    check_cmd_steward_timeout_and_streaming windows-latest Windows || return 0
    log_pass "Windows jobs running cmd/steward (${CMD_STEWARD_CHECKED_JOBS}): -timeout at most timeout-minutes minus 9, output streamed"
}

# Issue #6033: the same rule for the macOS legs. The shared steward leg ran
# cmd/steward with 22 other packages under -timeout=10m in a 15-minute job
# without -json, and was cancelled with no output naming a test.
test_macos_cmd_steward_timeout_and_streaming() {
    log_test "Testing macOS jobs running cmd/steward: go test -timeout <= timeout-minutes - 9, streamed output..."

    CMD_STEWARD_CHECKED_JOBS=0
    check_cmd_steward_timeout_and_streaming macos-latest macOS || return 0
    log_pass "macOS jobs running cmd/steward (${CMD_STEWARD_CHECKED_JOBS}): -timeout at most timeout-minutes minus 9, output streamed"
}

test_resource_sampler_no_placeholder() {
    log_test "Testing resource-sampler.sh: RESOURCE_PROFILE line contains no literal \${ placeholder..."

    local script_dir
    script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/.github/scripts"

    if [[ ! -f "${script_dir}/resource-sampler.sh" ]]; then
        log_fail "resource-sampler.sh: not found at ${script_dir}/resource-sampler.sh"
        return
    fi

    local tmp_dir
    tmp_dir=$(mktemp -d)
    trap 'rm -rf "$tmp_dir"; trap - RETURN' RETURN

    # Fixture: state dir with a known samples file and a dead-PID file.
    local state_dir="${tmp_dir}/state"
    mkdir -p "$state_dir"
    echo "99999999" > "${state_dir}/sampler.pid"   # kill is a no-op for non-existent PID
    cat > "${state_dir}/samples.txt" << 'EOF'
12:00:01 cpu_pct=25 mem_used_mb=1024/4096
12:00:06 cpu_pct=30 mem_used_mb=1100/4096
12:00:11 cpu_pct=22 mem_used_mb=1050/4096
EOF

    local artifact="${tmp_dir}/artifact.txt"
    local profile_line report_exit=0
    profile_line=$(bash "${script_dir}/resource-sampler.sh" report "$state_dir" "$artifact" 2>&1) || report_exit=$?

    if [[ $report_exit -ne 0 ]]; then
        log_fail "resource-sampler.sh report (no-placeholder): exited $report_exit (output: $profile_line)"
        return
    fi

    if echo "$profile_line" | grep -q 'RESOURCE_PROFILE:'; then
        log_pass "resource-sampler.sh: emits a RESOURCE_PROFILE: line"
    else
        log_fail "resource-sampler.sh: no RESOURCE_PROFILE: line in output (got: '$profile_line')"
        return
    fi

    if echo "$profile_line" | grep -qF '${'; then
        log_fail "resource-sampler.sh: RESOURCE_PROFILE line contains literal '\${' placeholder (got: '$profile_line')"
    else
        log_pass "resource-sampler.sh: RESOURCE_PROFILE line contains no literal '\${' placeholder"
    fi

    # Peak values must match the fixture (cpu_peak=30, mem_peak=1100/4096).
    if echo "$profile_line" | grep -q 'cpu_peak_pct=30'; then
        log_pass "resource-sampler.sh: correct peak CPU (30) computed from fixture"
    else
        log_fail "resource-sampler.sh: expected cpu_peak_pct=30 from fixture (got: '$profile_line')"
    fi

    if echo "$profile_line" | grep -q 'mem_peak_mb=1100/4096'; then
        log_pass "resource-sampler.sh: correct peak memory (1100/4096) computed from fixture"
    else
        log_fail "resource-sampler.sh: expected mem_peak_mb=1100/4096 from fixture (got: '$profile_line')"
    fi

    # vm= must not contain 0vCPU/0GB on a real Linux system (nproc should return ≥1).
    # The sampler probes nproc + /proc/meminfo, which only exist on Linux — skip the
    # host-derived assertion elsewhere (fixture-based assertions above still run).
    if [[ "$(uname -s)" != "Linux" ]]; then
        log_pass "resource-sampler.sh: vm= spec check skipped (host-derived, Linux-only)"
    elif echo "$profile_line" | grep -qE 'vm=[1-9][0-9]*vCPU/[0-9]+GB'; then
        log_pass "resource-sampler.sh: vm= spec contains a non-zero vCPU count"
    else
        log_fail "resource-sampler.sh: vm= spec has zero vCPU count (got: '$profile_line')"
    fi
}

test_tier1_smoke_test() {
    log_test "Testing tier1-smoke-test.sh fixtures..."

    local smoke_script="scripts/tier1-smoke-test.sh"
    local test_script="scripts/tier1-smoke-test_test.sh"

    if [[ ! -f "$smoke_script" ]]; then
        log_fail "tier1-smoke-test.sh: Not found"
        return
    fi

    if [[ ! -x "$smoke_script" ]]; then
        log_fail "tier1-smoke-test.sh: Not executable (chmod +x needed)"
        return
    fi

    if [[ ! -f "$test_script" ]]; then
        log_fail "tier1-smoke-test_test.sh: Not found"
        return
    fi

    if [[ ! -x "$test_script" ]]; then
        log_fail "tier1-smoke-test_test.sh: Not executable (chmod +x needed)"
        return
    fi

    local out_file rc=0
    out_file=$(mktemp)
    bash "$test_script" >"$out_file" 2>&1 || rc=$?

    if [[ $rc -eq 0 ]]; then
        log_pass "tier1-smoke-test_test.sh: All fixture tests passed"
    else
        log_fail "tier1-smoke-test_test.sh: Fixture tests failed (exit $rc)"
        sed 's/^/    /' "$out_file" >&2
    fi
    rm -f "$out_file"
}

# Test: resource-sampler.ps1 never uses pwsh (AC1 — static, runs on Linux without PS infra)
test_resource_sampler_ps1_no_pwsh() {
    log_test "Testing resource-sampler.ps1: AC1 — Start-Process uses powershell not pwsh..."

    local ps1
    ps1="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/.github/scripts/resource-sampler.ps1"

    if [[ ! -f "$ps1" ]]; then
        log_fail "resource-sampler.ps1: not found at $ps1"
        return
    fi

    if grep -qE 'Start-Process[[:space:]]+pwsh' "$ps1"; then
        log_fail "resource-sampler.ps1: found 'Start-Process pwsh' — must use 'Start-Process powershell' (AC1)"
    else
        log_pass "resource-sampler.ps1: no 'Start-Process pwsh' — Start-Process correctly uses powershell"
    fi

    if grep -qE "shell[[:space:]]*:[[:space:]]*pwsh" "$ps1"; then
        log_fail "resource-sampler.ps1: found shell: pwsh reference — forbidden (AC1)"
    else
        log_pass "resource-sampler.ps1: no shell: pwsh reference"
    fi
}

test_datasvc_bootstrap() {
    log_test "Testing lab-datasvc-bootstrap.sh..."

    local bootstrap_script="scripts/lab-datasvc-bootstrap.sh"
    local test_script="scripts/lab-datasvc-bootstrap_test.sh"

    if [[ ! -f "$bootstrap_script" ]]; then
        log_fail "lab-datasvc-bootstrap.sh: Not found"
        return
    fi

    if [[ ! -x "$bootstrap_script" ]]; then
        log_fail "lab-datasvc-bootstrap.sh: Not executable (chmod +x needed)"
        return
    fi

    if [[ ! -f "$test_script" ]]; then
        log_fail "lab-datasvc-bootstrap_test.sh: Not found"
        return
    fi

    if [[ ! -x "$test_script" ]]; then
        log_fail "lab-datasvc-bootstrap_test.sh: Not executable (chmod +x needed)"
        return
    fi

    local out_file rc=0
    out_file=$(mktemp)
    bash "$test_script" >"$out_file" 2>&1 || rc=$?

    if [[ $rc -eq 0 ]]; then
        log_pass "lab-datasvc-bootstrap_test.sh: All tests passed"
    else
        log_fail "lab-datasvc-bootstrap_test.sh: Tests failed (exit $rc)"
        sed 's/^/    /' "$out_file" >&2
    fi
    rm -f "$out_file"
}

test_ha_cluster_bootstrap() {
    log_test "Testing ha-cluster-node-bootstrap.sh..."

    local bootstrap_script="scripts/ha-cluster-node-bootstrap.sh"
    local test_script="scripts/ha-cluster-node-bootstrap_test.sh"

    if [[ ! -f "$bootstrap_script" ]]; then
        log_fail "ha-cluster-node-bootstrap.sh: Not found"
        return
    fi

    if [[ ! -x "$bootstrap_script" ]]; then
        log_fail "ha-cluster-node-bootstrap.sh: Not executable (chmod +x needed)"
        return
    fi

    if [[ ! -f "$test_script" ]]; then
        log_fail "ha-cluster-node-bootstrap_test.sh: Not found"
        return
    fi

    if [[ ! -x "$test_script" ]]; then
        log_fail "ha-cluster-node-bootstrap_test.sh: Not executable (chmod +x needed)"
        return
    fi

    local out_file rc=0
    out_file=$(mktemp)
    bash "$test_script" >"$out_file" 2>&1 || rc=$?

    if [[ $rc -eq 0 ]]; then
        log_pass "ha-cluster-node-bootstrap_test.sh: All tests passed"
    else
        log_fail "ha-cluster-node-bootstrap_test.sh: Tests failed (exit $rc)"
        sed 's/^/    /' "$out_file" >&2
    fi
    rm -f "$out_file"
}

test_tier1_bootstrap() {
    log_test "Testing tier1-bootstrap.sh..."

    local bootstrap_script="scripts/tier1-bootstrap.sh"
    local test_script="scripts/tier1-bootstrap_test.sh"

    if [[ ! -f "$bootstrap_script" ]]; then
        log_fail "tier1-bootstrap.sh: Not found"
        return
    fi

    if [[ ! -x "$bootstrap_script" ]]; then
        log_fail "tier1-bootstrap.sh: Not executable (chmod +x needed)"
        return
    fi

    if [[ ! -f "$test_script" ]]; then
        log_fail "tier1-bootstrap_test.sh: Not found"
        return
    fi

    if [[ ! -x "$test_script" ]]; then
        log_fail "tier1-bootstrap_test.sh: Not executable (chmod +x needed)"
        return
    fi

    local out_file rc=0
    out_file=$(mktemp)
    bash "$test_script" >"$out_file" 2>&1 || rc=$?

    if [[ $rc -eq 0 ]]; then
        log_pass "tier1-bootstrap_test.sh: All tests passed"
    else
        log_fail "tier1-bootstrap_test.sh: Tests failed (exit $rc)"
        sed 's/^/    /' "$out_file" >&2
    fi
    rm -f "$out_file"
}

# Regression test (Issue #5972): the merge queue's Linux native build is one job
# that runs `make build` plus the api and controller-core groups. The
# heavy-providers and rest groups already run on every pull request
# (test-suite.yml), so a second shard rerunning them in the queue is cost with
# no coverage. `build-gate` must still `needs:` both the native build and the
# Postgres job and require both to be `success`, or a failure in either would
# stop failing the required `Build Gate` context. The workflow path is an
# optional argument so the test can be pointed at a fixture.
test_queue_native_build_runs_only_shard_1_content() {
    log_test "Testing queue native build runs only the build + api + controller-core content (Issue #5972)..."

    local workflow="${1:-.github/workflows/cross-platform-build.yml}"
    if [[ ! -f "$workflow" ]]; then
        log_fail "queue native build: $workflow not found"
        return
    fi

    # job_block <job-id> prints the lines of one top-level job under `jobs:`
    # (two-space indented key) up to the next job key or end of file.
    job_block() {
        awk -v job="$1" '
            $0 ~ "^  " job ":[[:space:]]*$" { injob=1; next }
            injob && /^  [A-Za-z0-9_-]+:[[:space:]]*$/ { exit }
            injob { print }
        ' "$workflow"
    }

    local native gate
    native="$(job_block native-builds)"
    gate="$(job_block build-gate)"
    if [[ -z "$native" ]]; then
        log_fail "queue native build: no native-builds job found in $workflow"
        return
    fi
    if [[ -z "$gate" ]]; then
        log_fail "queue native build: no build-gate job found in $workflow"
        return
    fi

    # Comments are dropped so explanatory text naming a removed group cannot
    # satisfy or trip an assertion.
    local native_code
    native_code="$(echo "$native" | sed -E 's/^[[:space:]]*#.*$//')"

    # (a) neither group the PR legs already cover runs in the queue job.
    local group ok=true
    for group in test-go-group-heavy-providers test-go-group-rest; do
        if echo "$native_code" | grep -qE "(^|[^A-Za-z0-9-])${group}([^A-Za-z0-9-]|\$)"; then
            log_fail "queue native-builds runs ${group}, which every pull request already runs (test-suite.yml)"
            ok=false
        fi
    done

    # (b) the combined-revision check is still there, and the job is not
    # sharded (a matrix could reintroduce a second shard).
    local target
    for target in "make build" "test-framework-api-sharded" "test-go-group-controller-core"; do
        if ! echo "$native_code" | grep -qE "(^|[^A-Za-z0-9-])${target}([^A-Za-z0-9-]|\$)"; then
            log_fail "queue native-builds no longer runs '${target}'"
            ok=false
        fi
    done
    if echo "$native_code" | grep -qE '^[[:space:]]+(matrix|shard):'; then
        log_fail "queue native-builds is sharded again (matrix/shard key present)"
        ok=false
    fi

    # (c) build-gate needs both jobs and requires both to be success.
    local needs_line
    needs_line="$(echo "$gate" | grep -E '^    needs:' || true)"
    if [[ -z "$needs_line" ]] \
        || ! echo "$needs_line" | grep -qE '(\[|[ ,])native-builds([],]|$)' \
        || ! echo "$needs_line" | grep -qE '(\[|[ ,])postgres-integration([],]|$)'; then
        log_fail "build-gate must 'needs:' both native-builds and postgres-integration (got: ${needs_line:-none})"
        ok=false
    fi
    local gate_code
    gate_code="$(echo "$gate" | sed -E 's/^[[:space:]]*#.*$//')"
    if ! echo "$gate_code" | grep -qE 'NATIVE_RESULT: \$\{\{ needs\.native-builds\.result \}\}' \
        || ! echo "$gate_code" | grep -qE 'POSTGRES_RESULT: \$\{\{ needs\.postgres-integration\.result \}\}' \
        || ! echo "$gate_code" | grep -qF '[[ "$NATIVE_RESULT" == "success" && "$POSTGRES_RESULT" == "success" ]]'; then
        log_fail "build-gate's result check must require both native-builds and postgres-integration to be success"
        ok=false
    fi

    if [[ "$ok" == true ]]; then
        log_pass "queue native-builds: build + api + controller-core only, one job; build-gate needs and requires both native-builds and postgres-integration"
    fi
}

# Regression test (Issue #4113): asserts the script-test suite itself never
# mutates tracked files. Compares the git status snapshot taken before any
# test ran (GIT_STATUS_BEFORE_TESTS, captured just above the "Main execution"
# block) against the status now, after every other test function has run. A
# test must report drift in tracked files, never silently rewrite and stage
# them — that silent staging is what let a hand-edited baseline fix ride along
# into an unrelated commit --amend during a story promotion.
test_no_tracked_file_mutation() {
    log_test "Testing script-test suite does not mutate tracked files..."

    local git_status_after
    git_status_after=$(git status --porcelain)

    if [ "$GIT_STATUS_BEFORE_TESTS" == "$git_status_after" ]; then
        log_pass "test-scripts.sh: working tree and index unchanged after full run"
    else
        log_fail "test-scripts.sh: working tree or index was modified during the run"
        echo "  git status --porcelain before run:" >&2
        echo "$GIT_STATUS_BEFORE_TESTS" | sed 's/^/    /' >&2
        echo "  git status --porcelain after run:" >&2
        echo "$git_status_after" | sed 's/^/    /' >&2
    fi
}

# Regression guard (Issue #4113): the suite as a whole must never leave the
# working tree or index dirty as a side effect of running. A staged edit left
# behind by a test is invisible until the next unrelated `git commit -a` or
# `--amend` sweeps it in — which is exactly how a hand-fixed baseline drift
# once rode along into an unrelated pin-bump commit during story promotion.
# Snapshot status before any test runs and diff it against the snapshot taken
# after the last one, right before the pass/fail summary below.
GIT_STATUS_BEFORE_TESTS=$(git status --porcelain)

# --- Suite group composition (Issue #4301) ----------------------------------
# Ordered (function:group) pairs, in the exact historical dispatch order. The
# default (no --group) path below replays this table unfiltered, so it stays
# byte-identical to the pre-#4301 dispatch; `--group <csv>` replays it filtered
# to the requested group(s). Do not resort this table by group — its order,
# not just its membership, is what the default path's output depends on.
DISPATCH_TABLE=(
    "test_syntax:core"
    "test_license_checker:core"
    "test_check_mockups_index:core"
    "test_mockups_index_generator:core"
    "test_log_injection_linter:core"
    "test_invalid_cert_generation:core"
    "test_credential_generation:core"
    "test_wait_for_services:core"
    "test_executable_permissions:core"
    "test_check_providers:core"
    "test_check_binary_artifacts:core"
    "test_go_fetch_retry:core"
    "test_check_docs_boundary:core"
    "test_check_no_python_in_core:core"
    "test_check_build_boundary:core"
    "test_check_no_banned_exec_patterns:core"
    "test_check_dead_packages:core"
    "test_unit_tests_aggregator_no_python_gate:core"
    "test_codeql_context_present_on_merge_group:core"
    "test_install_git_hooks:core"
    "test_verify_nancy_ignore_scope:core"
    "test_security_trivy_init_error:core"
    "test_security_trivy_findings:core"
    "test_security_trivy_clean_scan:core"
    "test_check_cla_signed:core"
    "test_no_pipeline_label_refs:core"
    "test_acceptance_reviewer_trusted_tooling_paths:core"
    "test_tier1_smoke_test:core"
    "test_tier1_bootstrap:core"
    "test_ha_cluster_bootstrap:core"
    "test_datasvc_bootstrap:core"
    "test_resource_sampler_ps1_no_pwsh:devinfra"
    "test_resource_sampler_loop_guard:devinfra"
    "test_resource_sampler_no_placeholder:devinfra"
    "test_api_shard_partition_covers_all_tests:core"
    "test_api_shard_chunks_respect_pattern_cap:core"
    "test_go_group_split_partition_covers_all_packages:core"
    "test_test_fast_shards_api_package:core"
    "test_go_group_rest_propagates_early_failure:core"
    "test_all_modules_covers_module_yaml_tree:core"
    "test_api_shard_aggregation_fails_closed:core"
    "test_api_shard_count_rejects_non_integer:core"
    "test_macos_groups_cover_exactly_shipped_packages:core"
    "test_macos_gate_rule:core"
    "test_macos_pr_filter:core"
    "test_build_gate_requires_macos_test_compile:core"
    "test_windows_steward_groups_cover_exactly_steward_and_cmd:core"
    "test_windows_cmd_steward_timeout_and_streaming:core"
    "test_macos_cmd_steward_timeout_and_streaming:core"
    "test_queue_native_build_runs_only_shard_1_content:core"
    "test_no_tracked_file_mutation:core"
)

# The one call pair in the historical dispatch with no blank-line separator
# between them — preserved here so the flag-omitted default run's output
# stays byte-identical to before this story.
NO_TRAILING_BLANK="test_create_clone_stale_branch_deletion"

# Runs every DISPATCH_TABLE entry whose group matches $1, in table order,
# reproducing the historical blank-line spacing between calls. An empty $1
# runs the whole table (used by the flag-omitted default path).
run_dispatch_entries() {
    local filter_group="$1"
    local entry fn grp
    for entry in "${DISPATCH_TABLE[@]}"; do
        fn="${entry%%:*}"
        grp="${entry##*:}"
        if [[ -n "$filter_group" && "$grp" != "$filter_group" ]]; then
            continue
        fi
        "$fn"
        if [[ "$fn" != "$NO_TRAILING_BLANK" ]]; then
            echo ""
        fi
    done
}

run_core_suites() { run_dispatch_entries "core"; }
run_devinfra_suites() { run_dispatch_entries "devinfra"; }

# Validates DISPATCH_TABLE's own consistency (Issue #4301): every test_*
# function defined in this file must appear in it exactly once, tagged with
# one of the four valid groups. Runs silently and unconditionally at startup
# (regardless of --group) so a suite added or renamed without updating the
# table fails loud immediately, before any test runs, rather than silently
# vanishing from every --group invocation (including the flag-omitted
# default) while `make test-scripts` still reports green.
validate_dispatch_table() {
    local self_script="${BASH_SOURCE[0]}"

    local -a defined_fns=()
    while IFS= read -r fn; do
        defined_fns+=("$fn")
    done < <(grep -oE '^test_[a-zA-Z0-9_]+\(\) \{' "$self_script" | sed -E 's/\(\) \{$//')

    local -a table_fns=() table_groups=()
    while IFS=: read -r fn grp; do
        table_fns+=("$fn")
        table_groups+=("$grp")
    done < <(grep -oE '^[[:space:]]+"test_[a-zA-Z0-9_]+:[a-zA-Z-]+"' "$self_script" | tr -d ' "')

    # Membership and counts use associative arrays, not `printf | grep -q`:
    # under `set -o pipefail`, grep -q exits on its first match and printf
    # (line-buffered) can then take SIGPIPE, so the pipeline reports 141 and
    # a defined function is misreported as "not a defined function" under load.
    local fn grp
    local -A defined_set=() table_count=()
    local -a missing=() dup=() extra=() bad_groups=()
    for fn in "${defined_fns[@]}"; do
        defined_set["$fn"]=1
    done
    for fn in "${table_fns[@]}"; do
        table_count["$fn"]=$(( ${table_count["$fn"]:-0} + 1 ))
    done
    for fn in "${defined_fns[@]}"; do
        [[ ${table_count["$fn"]:-0} -eq 0 ]] && missing+=("$fn")
        [[ ${table_count["$fn"]:-0} -gt 1 ]] && dup+=("$fn")
    done
    for fn in "${table_fns[@]}"; do
        [[ -n "${defined_set["$fn"]:-}" ]] || extra+=("$fn")
    done
    for grp in "${table_groups[@]}"; do
        case "$grp" in
            core | devinfra) ;;
            *) bad_groups+=("$grp") ;;
        esac
    done

    if [[ ${#missing[@]} -gt 0 || ${#dup[@]} -gt 0 || ${#extra[@]} -gt 0 || ${#bad_groups[@]} -gt 0 ]]; then
        echo "❌ DISPATCH_TABLE is inconsistent with this file's test_* functions:" >&2
        [[ ${#missing[@]} -gt 0 ]] && echo "  missing from DISPATCH_TABLE: ${missing[*]}" >&2
        [[ ${#dup[@]} -gt 0 ]] && echo "  duplicated in DISPATCH_TABLE: ${dup[*]}" >&2
        [[ ${#extra[@]} -gt 0 ]] && echo "  in DISPATCH_TABLE but not a defined function: ${extra[*]}" >&2
        [[ ${#bad_groups[@]} -gt 0 ]] && echo "  unrecognized group values: ${bad_groups[*]}" >&2
        exit 1
    fi
}
validate_dispatch_table

# Main execution
echo "🔍 Script Validation Test Suite"
echo "================================"
echo ""

if [[ "$GROUP_FLAG_GIVEN" != true ]]; then
    # No --group flag: run every suite, in the historical order (unchanged) —
    # byte-identical to the pre-#4301 dispatch.
    run_dispatch_entries ""
else
    # core runs last (regardless of CSV order) so test_no_tracked_file_mutation,
    # its final suite, still observes the working tree after every other
    # selected group has run, not just after core's own suites.
    group_selected devinfra && run_devinfra_suites
    group_selected core && run_core_suites
fi

echo "📊 Test Summary"
echo "==============="
echo "  ✓ Passed: $PASS_COUNT"
echo "  ✗ Failed: $FAIL_COUNT"
echo ""

if [ $FAIL_COUNT -eq 0 ]; then
    echo "✅ All script tests passed!"
    exit 0
else
    echo "❌ $FAIL_COUNT script test(s) failed"
    exit 1
fi
