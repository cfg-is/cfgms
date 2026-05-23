#!/bin/bash
# Test Script Validation
# Runs smoke tests on all critical shell scripts to catch syntax/logic errors

set -euo pipefail

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

# Test 1: Validate syntax of all shell scripts
test_syntax() {
    log_test "Testing shell script syntax..."

    local scripts_tested=0
    for script in scripts/*.sh .claude/scripts/*.sh; do
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


# Test 8: create-clone deletes stale remote branch before cloning
test_create_clone_stale_branch_deletion() {
    log_test "Testing create-clone deletes stale remote branch..."

    local tmp_dir
    tmp_dir=$(mktemp -d)
    local remote_dir="${tmp_dir}/remote.git"
    local host_dir="${tmp_dir}/host"
    local worktree_dir="${tmp_dir}/worktrees"
    local story_num="99997"
    local branch_name="feature/story-${story_num}-agent"
    local dispatch_script
    dispatch_script="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/../.claude/scripts/agent-dispatch.sh"

    # Create a bare "remote" repo with a develop branch
    git init --bare -b develop "$remote_dir" >/dev/null 2>&1
    git init -b develop "$host_dir" >/dev/null 2>&1
    git -C "$host_dir" config user.email "test@test.com"
    git -C "$host_dir" config user.name "Test"
    git -C "$host_dir" remote add origin "$remote_dir"
    git -C "$host_dir" commit --allow-empty -m "initial commit" >/dev/null 2>&1
    git -C "$host_dir" push origin develop >/dev/null 2>&1

    # Create a stale feature branch on the remote with a marker commit
    git -C "$host_dir" checkout -b "$branch_name" >/dev/null 2>&1
    git -C "$host_dir" commit --allow-empty -m "stale marker commit" >/dev/null 2>&1
    local marker_sha
    marker_sha=$(git -C "$host_dir" rev-parse HEAD)
    git -C "$host_dir" push origin "$branch_name" >/dev/null 2>&1
    git -C "$host_dir" checkout develop >/dev/null 2>&1

    mkdir -p "$worktree_dir"

    local output
    output=$(CFGMS_TEST_REPO_ROOT="$host_dir" CFGMS_TEST_WORKTREE_BASE="$worktree_dir"         bash "$dispatch_script" create-clone "$story_num" 2>&1)
    local exit_code=$?

    if [[ $exit_code -ne 0 ]]; then
        log_fail "create-clone: Command failed (exit ${exit_code}): ${output}"
        rm -rf "$tmp_dir"
        return
    fi

    # Log line must appear for dispatch trail visibility
    if echo "$output" | grep -q "Cleaning stale remote branch: ${branch_name}"; then
        log_pass "create-clone: Logs 'Cleaning stale remote branch' message"
    else
        log_fail "create-clone: Missing 'Cleaning stale remote branch' log line"
    fi

    # Stale branch must be gone from remote
    if ! git -C "$host_dir" ls-remote --heads origin "$branch_name" | grep -q .; then
        log_pass "create-clone: Stale remote branch deleted before cloning"
    else
        log_fail "create-clone: Stale remote branch still exists after create-clone"
    fi

    # New clone HEAD must match develop on remote (not the stale marker commit)
    local clone_head develop_sha
    clone_head=$(git -C "$worktree_dir/story-${story_num}" rev-parse HEAD 2>/dev/null || echo "missing")
    develop_sha=$(git -C "$remote_dir" rev-parse develop 2>/dev/null || echo "unknown")
    if [[ "$clone_head" == "$develop_sha" && "$clone_head" != "$marker_sha" ]]; then
        log_pass "create-clone: New branch based on develop HEAD, not stale marker commit"
    else
        log_fail "create-clone: New branch HEAD (${clone_head}) does not match develop (${develop_sha})"
    fi

    rm -rf "$tmp_dir"
}

# Test 9: create-clone --keep-remote preserves existing remote branch
test_create_clone_keep_remote() {
    log_test "Testing create-clone --keep-remote preserves stale remote branch..."

    local tmp_dir
    tmp_dir=$(mktemp -d)
    local remote_dir="${tmp_dir}/remote.git"
    local host_dir="${tmp_dir}/host"
    local worktree_dir="${tmp_dir}/worktrees"
    local story_num="99998"
    local branch_name="feature/story-${story_num}-agent"
    local dispatch_script
    dispatch_script="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/../.claude/scripts/agent-dispatch.sh"

    # Create a bare "remote" repo with a develop branch
    git init --bare -b develop "$remote_dir" >/dev/null 2>&1
    git init -b develop "$host_dir" >/dev/null 2>&1
    git -C "$host_dir" config user.email "test@test.com"
    git -C "$host_dir" config user.name "Test"
    git -C "$host_dir" remote add origin "$remote_dir"
    git -C "$host_dir" commit --allow-empty -m "initial commit" >/dev/null 2>&1
    git -C "$host_dir" push origin develop >/dev/null 2>&1

    # Create a stale feature branch on the remote
    git -C "$host_dir" checkout -b "$branch_name" >/dev/null 2>&1
    git -C "$host_dir" commit --allow-empty -m "stale marker commit" >/dev/null 2>&1
    local stale_sha
    stale_sha=$(git -C "$host_dir" rev-parse HEAD)
    git -C "$host_dir" push origin "$branch_name" >/dev/null 2>&1
    git -C "$host_dir" checkout develop >/dev/null 2>&1

    mkdir -p "$worktree_dir"

    local output
    output=$(CFGMS_TEST_REPO_ROOT="$host_dir" CFGMS_TEST_WORKTREE_BASE="$worktree_dir"         bash "$dispatch_script" create-clone --keep-remote "$story_num" 2>&1)
    local exit_code=$?

    if [[ $exit_code -ne 0 ]]; then
        log_fail "create-clone --keep-remote: Command failed (exit ${exit_code}): ${output}"
        rm -rf "$tmp_dir"
        return
    fi

    # Remote branch must still exist
    if git -C "$host_dir" ls-remote --heads origin "$branch_name" | grep -q .; then
        log_pass "create-clone --keep-remote: Stale remote branch preserved"
    else
        log_fail "create-clone --keep-remote: Stale remote branch was deleted (should be preserved)"
    fi

    # Remote branch must still point at the stale commit
    local remote_branch_sha
    remote_branch_sha=$(git -C "$remote_dir" rev-parse "$branch_name" 2>/dev/null || echo "missing")
    if [[ "$remote_branch_sha" == "$stale_sha" ]]; then
        log_pass "create-clone --keep-remote: Remote branch still points at original stale commit"
    else
        log_fail "create-clone --keep-remote: Remote branch SHA changed (expected ${stale_sha}, got ${remote_branch_sha})"
    fi

    rm -rf "$tmp_dir"
}


# Test 10: create-clone exits 1 when stale branch deletion fails (no silent proceed)
test_create_clone_deletion_failure() {
    log_test "Testing create-clone exits 1 when stale branch deletion fails..."

    local tmp_dir
    tmp_dir=$(mktemp -d)
    local remote_dir="${tmp_dir}/remote.git"
    local host_dir="${tmp_dir}/host"
    local worktree_dir="${tmp_dir}/worktrees"
    local story_num="99996"
    local branch_name="feature/story-${story_num}-agent"
    local dispatch_script
    dispatch_script="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/../.claude/scripts/agent-dispatch.sh"

    # Create a bare "remote" repo with a develop branch
    git init --bare -b develop "$remote_dir" >/dev/null 2>&1
    git init -b develop "$host_dir" >/dev/null 2>&1
    git -C "$host_dir" config user.email "test@test.com"
    git -C "$host_dir" config user.name "Test"
    git -C "$host_dir" remote add origin "$remote_dir"
    git -C "$host_dir" commit --allow-empty -m "initial commit" >/dev/null 2>&1
    git -C "$host_dir" push origin develop >/dev/null 2>&1

    # Create a stale feature branch on the remote
    git -C "$host_dir" checkout -b "$branch_name" >/dev/null 2>&1
    git -C "$host_dir" commit --allow-empty -m "stale marker commit" >/dev/null 2>&1
    git -C "$host_dir" push origin "$branch_name" >/dev/null 2>&1
    git -C "$host_dir" checkout develop >/dev/null 2>&1

    # Install a pre-receive hook that rejects branch deletions — simulates a
    # protected branch or insufficient permissions on the remote.
    mkdir -p "${remote_dir}/hooks"
    cat > "${remote_dir}/hooks/pre-receive" << 'HOOKEOF'
#!/bin/bash
while read old_sha new_sha ref; do
    if [[ "$new_sha" == "0000000000000000000000000000000000000000" ]]; then
        echo "ERROR: Branch deletion rejected (protected branch)" >&2
        exit 1
    fi
done
HOOKEOF
    chmod +x "${remote_dir}/hooks/pre-receive"

    mkdir -p "$worktree_dir"

    local output exit_code=0
    # Use || to prevent set -e from aborting the test on expected non-zero exit
    output=$(CFGMS_TEST_REPO_ROOT="$host_dir" CFGMS_TEST_WORKTREE_BASE="$worktree_dir" \
        bash "$dispatch_script" create-clone "$story_num" 2>&1) || exit_code=$?

    if [[ $exit_code -ne 0 ]]; then
        log_pass "create-clone: Exits non-zero when stale branch deletion fails"
    else
        log_fail "create-clone: Should have failed when branch deletion is rejected (exit was 0)"
    fi

    if echo "$output" | grep -q "ERROR:"; then
        log_pass "create-clone: Prints ERROR message when deletion fails"
    else
        log_fail "create-clone: Missing ERROR message when deletion fails (output: ${output})"
    fi

    # Clone directory must NOT exist — script must not proceed after deletion failure
    local clone_dir="${worktree_dir}/story-${story_num}"
    if [[ ! -d "$clone_dir" ]]; then
        log_pass "create-clone: Clone directory not created when deletion fails (no partial state)"
    else
        log_fail "create-clone: Clone directory was created despite deletion failure"
        rm -rf "$clone_dir"
    fi

    rm -rf "$tmp_dir"
}

# Test 11: create-clone refuses dispatch when an open PR already fixes the issue
test_create_clone_duplicate_pr_gate() {
    log_test "Testing create-clone refuses dispatch when open PR already fixes the issue..."

    local tmp_dir
    tmp_dir=$(mktemp -d)
    local remote_dir="${tmp_dir}/remote.git"
    local host_dir="${tmp_dir}/host"
    local worktree_dir="${tmp_dir}/worktrees"
    local story_num="99995"
    local dispatch_script
    dispatch_script="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/../.claude/scripts/agent-dispatch.sh"

    git init --bare -b develop "$remote_dir" >/dev/null 2>&1
    git init -b develop "$host_dir" >/dev/null 2>&1
    git -C "$host_dir" config user.email "test@test.com"
    git -C "$host_dir" config user.name "Test"
    git -C "$host_dir" remote add origin "$remote_dir"
    git -C "$host_dir" commit --allow-empty -m "initial commit" >/dev/null 2>&1
    git -C "$host_dir" push origin develop >/dev/null 2>&1

    mkdir -p "$worktree_dir"

    # Canned "open PR 777 fixes 99995" — gate must refuse and exit 2
    local mock_output="OPEN_PR_EXISTS:${story_num}:777:duplicate work for issue ${story_num}"
    local output exit_code=0
    output=$(CFGMS_TEST_REPO_ROOT="$host_dir" CFGMS_TEST_WORKTREE_BASE="$worktree_dir" \
        CFGMS_TEST_MOCK_EXISTING_PRS="$mock_output" \
        bash "$dispatch_script" create-clone "$story_num" 2>&1) || exit_code=$?

    if [[ $exit_code -eq 2 ]]; then
        log_pass "create-clone: Exits 2 when open PR already references the issue"
    else
        log_fail "create-clone: Expected exit 2 when duplicate PR exists, got ${exit_code} (output: ${output})"
    fi

    if echo "$output" | grep -q "Open PR(s) already reference issue #${story_num}"; then
        log_pass "create-clone: Prints clear duplicate-PR refusal message"
    else
        log_fail "create-clone: Missing duplicate-PR refusal message (output: ${output})"
    fi

    if [[ ! -d "${worktree_dir}/story-${story_num}" ]]; then
        log_pass "create-clone: Clone directory not created when duplicate PR gate trips"
    else
        log_fail "create-clone: Clone directory was created despite duplicate PR gate"
        rm -rf "${worktree_dir}/story-${story_num}"
    fi

    # --allow-duplicate-pr override must bypass the gate and proceed with the clone
    exit_code=0
    output=$(CFGMS_TEST_REPO_ROOT="$host_dir" CFGMS_TEST_WORKTREE_BASE="$worktree_dir" \
        CFGMS_TEST_MOCK_EXISTING_PRS="$mock_output" \
        bash "$dispatch_script" create-clone --allow-duplicate-pr "$story_num" 2>&1) || exit_code=$?

    if [[ $exit_code -eq 0 ]]; then
        log_pass "create-clone --allow-duplicate-pr: Overrides gate and proceeds"
    else
        log_fail "create-clone --allow-duplicate-pr: Should succeed despite open PR (exit ${exit_code}, output: ${output})"
    fi

    rm -rf "$tmp_dir"
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

    if echo "$output" | grep -q "CRITICAL/HIGH/MEDIUM vulnerabilities found"; then
        log_fail "security-trivy.sh: Must NOT print false vulnerability-found message on init error"
    else
        log_pass "security-trivy.sh: Does NOT emit false '❌ CRITICAL/HIGH/MEDIUM vulnerabilities found' on init error"
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

    if echo "$output" | grep -q "CRITICAL/HIGH/MEDIUM vulnerabilities found"; then
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

# ── Tests for scripts/project-queue.sh ───────────────────────────────────────

test_project_queue_no_gh_issue_calls() {
    log_test "Testing project-queue.sh: no subcommand calls gh issue or modifies labels..."

    local script
    script="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/project-queue.sh"

    if [[ ! -f "$script" ]]; then
        log_fail "project-queue.sh: Script not found at $script"
        return
    fi

    # Verify script does not call 'gh issue' anywhere (exclude comment-only lines)
    # grep -n output format is "linenum:content"; filter lines where content starts with optional whitespace then #
    if grep -n 'gh issue' "$script" 2>/dev/null | grep -vE ':[[:space:]]*#' | grep -q .; then
        log_fail "project-queue.sh: Contains 'gh issue' call (AC 5 violation)"
        grep -n 'gh issue' "$script" | grep -vE ':[[:space:]]*#'
    else
        log_pass "project-queue.sh: No 'gh issue' calls found (AC 5)"
    fi

    # Verify script does not manipulate issue labels
    if grep -n '\-\-add-label\|--remove-label\|--label' "$script" 2>/dev/null | grep -v '^\s*#' | grep -q .; then
        log_fail "project-queue.sh: Contains label manipulation (AC 5 violation)"
    else
        log_pass "project-queue.sh: No issue label manipulation found (AC 5)"
    fi
}

test_project_queue_invalid_args() {
    log_test "Testing project-queue.sh: invalid arguments return exit code 2..."

    local script
    script="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/project-queue.sh"

    if [[ ! -f "$script" ]]; then
        log_skip "project-queue.sh: Script not found"
        return
    fi

    local exit_code=0
    bash "$script" 2>/dev/null || exit_code=$?
    if [[ $exit_code -eq 2 ]]; then
        log_pass "project-queue.sh: No-args exits 2 (invalid args code)"
    else
        log_fail "project-queue.sh: No-args should exit 2, got $exit_code"
    fi

    exit_code=0
    bash "$script" unknown-command 2>/dev/null || exit_code=$?
    if [[ $exit_code -eq 2 ]]; then
        log_pass "project-queue.sh: Unknown subcommand exits 2"
    else
        log_fail "project-queue.sh: Unknown subcommand should exit 2, got $exit_code"
    fi

    exit_code=0
    bash "$script" create-draft 2>/dev/null || exit_code=$?
    if [[ $exit_code -eq 2 ]]; then
        log_pass "project-queue.sh: create-draft with missing args exits 2"
    else
        log_fail "project-queue.sh: create-draft with missing args should exit 2, got $exit_code"
    fi

    exit_code=0
    bash "$script" list-by-status 2>/dev/null || exit_code=$?
    if [[ $exit_code -eq 2 ]]; then
        log_pass "project-queue.sh: list-by-status with missing args exits 2"
    else
        log_fail "project-queue.sh: list-by-status with missing args should exit 2, got $exit_code"
    fi

    exit_code=0
    bash "$script" get-item 2>/dev/null || exit_code=$?
    if [[ $exit_code -eq 2 ]]; then
        log_pass "project-queue.sh: get-item with missing args exits 2"
    else
        log_fail "project-queue.sh: get-item with missing args should exit 2, got $exit_code"
    fi

    exit_code=0
    bash "$script" update-field 2>/dev/null || exit_code=$?
    if [[ $exit_code -eq 2 ]]; then
        log_pass "project-queue.sh: update-field with missing args exits 2"
    else
        log_fail "project-queue.sh: update-field with missing args should exit 2, got $exit_code"
    fi

    exit_code=0
    bash "$script" add-issue 2>/dev/null || exit_code=$?
    if [[ $exit_code -eq 2 ]]; then
        log_pass "project-queue.sh: add-issue with missing args exits 2"
    else
        log_fail "project-queue.sh: add-issue with missing args should exit 2, got $exit_code"
    fi

    exit_code=0
    bash "$script" add-pr 2>/dev/null || exit_code=$?
    if [[ $exit_code -eq 2 ]]; then
        log_pass "project-queue.sh: add-pr with missing args exits 2"
    else
        log_fail "project-queue.sh: add-pr with missing args should exit 2, got $exit_code"
    fi

    exit_code=0
    bash "$script" delete-item 2>/dev/null || exit_code=$?
    if [[ $exit_code -eq 2 ]]; then
        log_pass "project-queue.sh: delete-item with missing args exits 2"
    else
        log_fail "project-queue.sh: delete-item with missing args should exit 2, got $exit_code"
    fi

    exit_code=0
    bash "$script" set-pr 2>/dev/null || exit_code=$?
    if [[ $exit_code -eq 2 ]]; then
        log_pass "project-queue.sh: set-pr with no args exits 2"
    else
        log_fail "project-queue.sh: set-pr with no args should exit 2, got $exit_code"
    fi

    exit_code=0
    bash "$script" set-pr "ITEM_ID_ONLY" 2>/dev/null || exit_code=$?
    if [[ $exit_code -eq 2 ]]; then
        log_pass "project-queue.sh: set-pr with one arg exits 2"
    else
        log_fail "project-queue.sh: set-pr with one arg should exit 2, got $exit_code"
    fi
}

test_project_queue_integration() {
    log_test "Testing project-queue.sh: integration against live cfgms-pipeline project..."

    local script
    script="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/project-queue.sh"

    if [[ ! -f "$script" ]]; then
        log_skip "project-queue.sh: Script not found"
        return
    fi

    # Skip if gh is not available or not authenticated
    if ! command -v gh >/dev/null 2>&1; then
        log_skip "project-queue.sh integration: gh CLI not available"
        return
    fi
    if ! gh auth status >/dev/null 2>&1; then
        log_skip "project-queue.sh integration: gh not authenticated — skipping live tests"
        return
    fi

    local tmp_dir
    tmp_dir=$(mktemp -d)

    # Accumulate item IDs to clean up on exit, even if the test fails partway
    local created_items=()
    cleanup_items() {
        for cid in "${created_items[@]:-}"; do
            [[ -z "$cid" ]] && continue
            bash "$script" delete-item "$cid" >/dev/null 2>&1 || true
        done
        rm -rf "$tmp_dir"
    }
    trap cleanup_items RETURN

    # Write a test body file
    local body_content="Integration test body content for project-queue.sh test run."
    echo "$body_content" > "$tmp_dir/body.md"

    # ── AC 1: create-draft ────────────────────────────────────────────────────
    local create_out exit_code=0
    create_out=$(bash "$script" create-draft 42 "test story pq-sh" "$tmp_dir/body.md" 2>&1) || exit_code=$?

    if [[ $exit_code -ne 0 ]]; then
        log_fail "project-queue.sh create-draft: failed (exit $exit_code): $create_out"
        return
    fi

    local item_id
    item_id=$(echo "$create_out" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d['item_id'])" 2>/dev/null) || {
        log_fail "project-queue.sh create-draft: output is not valid JSON with item_id key: $create_out"
        return
    }
    created_items+=("$item_id")

    if [[ -n "$item_id" ]]; then
        log_pass "project-queue.sh create-draft: returns item_id in JSON (AC 1)"
    else
        log_fail "project-queue.sh create-draft: item_id is empty"
        return
    fi

    # ── AC 3: get-item ────────────────────────────────────────────────────────
    local get_out
    exit_code=0
    get_out=$(bash "$script" get-item "$item_id" 2>&1) || exit_code=$?
    if [[ $exit_code -ne 0 ]]; then
        log_fail "project-queue.sh get-item: failed (exit $exit_code): $get_out"
        return
    fi

    # Verify required JSON keys exist
    local has_keys
    has_keys=$(echo "$get_out" | python3 -c "
import json, sys
d = json.load(sys.stdin)
missing = [k for k in ['item_id', 'title', 'body', 'status'] if k not in d]
print(','.join(missing) if missing else 'ok')
" 2>/dev/null) || has_keys="parse-error"

    if [[ "$has_keys" == "ok" ]]; then
        log_pass "project-queue.sh get-item: returns JSON with item_id, title, body, status (AC 3)"
    else
        log_fail "project-queue.sh get-item: missing keys [$has_keys] in: $get_out"
    fi

    # Verify body content matches what was passed to create-draft
    local returned_body
    returned_body=$(echo "$get_out" | python3 -c "import json,sys; print(json.load(sys.stdin).get('body',''))" 2>/dev/null) || returned_body=""
    if [[ "$returned_body" == *"$body_content"* ]]; then
        log_pass "project-queue.sh get-item: body field matches create-draft body_file content (AC 3)"
    else
        log_fail "project-queue.sh get-item: body mismatch — expected '$body_content', got '$returned_body'"
    fi

    # Verify status is Draft (set by create-draft)
    local returned_status
    returned_status=$(echo "$get_out" | python3 -c "import json,sys; print(json.load(sys.stdin).get('status',''))" 2>/dev/null) || returned_status=""
    if [[ "$returned_status" == "Draft" ]]; then
        log_pass "project-queue.sh create-draft: Status=Draft confirmed via get-item (AC 1)"
    else
        log_fail "project-queue.sh create-draft: Status should be Draft, got '$returned_status'"
    fi

    # ── AC 2: list-by-status Draft ────────────────────────────────────────────
    # GitHub Projects V2 has ~2s eventual consistency for newly created items.
    # Retry up to 5 times with 1s delay to let the item become visible.
    local list_out found is_array attempt
    exit_code=0
    list_out=$(bash "$script" list-by-status Draft 2>&1) || exit_code=$?
    if [[ $exit_code -ne 0 ]]; then
        log_fail "project-queue.sh list-by-status Draft: failed (exit $exit_code): $list_out"
    else
        is_array=$(echo "$list_out" | python3 -c "import json,sys; d=json.load(sys.stdin); print('yes' if isinstance(d,list) else 'no')" 2>/dev/null) || is_array="parse-error"
        if [[ "$is_array" == "yes" ]]; then
            log_pass "project-queue.sh list-by-status: returns valid JSON array (AC 2)"
        else
            log_fail "project-queue.sh list-by-status: output is not a JSON array: $list_out"
        fi

        # Retry until item is visible (accounts for GitHub API eventual consistency)
        found="no"
        for attempt in 1 2 3 4 5; do
            list_out=$(bash "$script" list-by-status Draft 2>&1) || true
            found=$(echo "$list_out" | python3 -c "
import json, sys
try:
    items = json.load(sys.stdin)
    print('yes' if any(i.get('item_id') == '$item_id' for i in items) else 'no')
except Exception:
    print('no')
" 2>/dev/null) || found="no"
            [[ "$found" == "yes" ]] && break
            sleep 1
        done

        if [[ "$found" == "yes" ]]; then
            log_pass "project-queue.sh list-by-status: created item appears in Draft list (AC 2)"
        else
            log_fail "project-queue.sh list-by-status: created item $item_id not found in Draft list after retries"
        fi
    fi

    # ── AC 4: update-field status → Ready ────────────────────────────────────
    exit_code=0
    local update_out
    update_out=$(bash "$script" update-field "$item_id" status "Ready" 2>&1) || exit_code=$?
    if [[ $exit_code -ne 0 ]]; then
        log_fail "project-queue.sh update-field status: failed (exit $exit_code): $update_out"
    else
        local update_ok
        update_ok=$(echo "$update_out" | python3 -c "
import json,sys
d=json.load(sys.stdin)
print('yes' if d.get('updated') == True else 'no')
" 2>/dev/null) || update_ok="parse-error"
        if [[ "$update_ok" == "yes" ]]; then
            log_pass "project-queue.sh update-field: returns updated=true JSON (AC 4)"
        else
            log_fail "project-queue.sh update-field: unexpected output: $update_out"
        fi

        # Verify the change via get-item
        local verify_out verify_status
        verify_out=$(bash "$script" get-item "$item_id" 2>/dev/null) || verify_out=""
        verify_status=$(echo "$verify_out" | python3 -c "import json,sys; print(json.load(sys.stdin).get('status',''))" 2>/dev/null) || verify_status=""
        if [[ "$verify_status" == "Ready" ]]; then
            log_pass "project-queue.sh update-field: status change reflected in get-item (AC 4)"
        else
            log_fail "project-queue.sh update-field: get-item shows status='$verify_status' instead of Ready"
        fi
    fi

    # ── AC 4 (text field): update-field Title → exercises text branch ────────
    exit_code=0
    local text_field_out
    text_field_out=$(bash "$script" update-field "$item_id" Title "test story pq-sh updated" 2>&1) || exit_code=$?
    if [[ $exit_code -ne 0 ]]; then
        log_fail "project-queue.sh update-field text: failed (exit $exit_code): $text_field_out"
    else
        local text_field_ok
        text_field_ok=$(echo "$text_field_out" | python3 -c "
import json,sys
d=json.load(sys.stdin)
print('yes' if d.get('updated') == True else 'no')
" 2>/dev/null) || text_field_ok="parse-error"
        if [[ "$text_field_ok" == "yes" ]]; then
            log_pass "project-queue.sh update-field text: returns updated=true JSON (AC 4 text field)"
        else
            log_fail "project-queue.sh update-field text: unexpected output: $text_field_out"
        fi

        # Verify via get-item fields dict (project field values, not content.title)
        local text_get_out text_get_field
        text_get_out=$(bash "$script" get-item "$item_id" 2>/dev/null) || text_get_out=""
        text_get_field=$(echo "$text_get_out" | python3 -c "
import json,sys
d=json.load(sys.stdin)
print(d.get('fields',{}).get('Title',''))
" 2>/dev/null) || text_get_field=""
        if [[ "$text_get_field" == "test story pq-sh updated" ]]; then
            log_pass "project-queue.sh update-field text: title change reflected in get-item fields dict (AC 4 text field)"
        else
            log_fail "project-queue.sh update-field text: get-item fields[Title]='$text_get_field' instead of 'test story pq-sh updated'"
        fi
    fi

    # ── AC 2: list-by-status Ready (item moved from Draft) ───────────────────
    exit_code=0
    local ready_list
    ready_list=$(bash "$script" list-by-status Ready 2>&1) || exit_code=$?
    if [[ $exit_code -ne 0 ]]; then
        log_fail "project-queue.sh list-by-status Ready: failed (exit $exit_code): $ready_list"
    else
        local found_ready
        found_ready=$(echo "$ready_list" | python3 -c "
import json, sys
items = json.load(sys.stdin)
print('yes' if any(i.get('item_id') == '$item_id' for i in items) else 'no')
" 2>/dev/null) || found_ready="parse-error"
        if [[ "$found_ready" == "yes" ]]; then
            log_pass "project-queue.sh list-by-status Ready: item appears after status update (AC 2)"
        else
            log_fail "project-queue.sh list-by-status Ready: item $item_id not found in Ready list"
        fi
    fi

    # ── add-issue: add a real cfgms issue to the project ─────────────────────
    exit_code=0
    local link_issue_out link_issue_item_id
    link_issue_out=$(bash "$script" add-issue 1477 2>&1) || exit_code=$?
    if [[ $exit_code -ne 0 ]]; then
        log_fail "project-queue.sh add-issue: failed (exit $exit_code): $link_issue_out"
    else
        link_issue_item_id=$(echo "$link_issue_out" | python3 -c "
import json, sys
d = json.load(sys.stdin)
print(d.get('item_id', ''))
" 2>/dev/null) || link_issue_item_id=""

        if [[ -n "$link_issue_item_id" ]]; then
            log_pass "project-queue.sh add-issue: returns item_id for added issue"
            created_items+=("$link_issue_item_id")
        else
            log_fail "project-queue.sh add-issue: no item_id in output: $link_issue_out"
        fi

        local linked_num
        linked_num=$(echo "$link_issue_out" | python3 -c "
import json, sys
d = json.load(sys.stdin)
print(d.get('linked_issue', ''))
" 2>/dev/null) || linked_num=""
        if [[ "$linked_num" == "1477" ]]; then
            log_pass "project-queue.sh add-issue: linked_issue field matches requested issue number"
        else
            log_fail "project-queue.sh add-issue: linked_issue='$linked_num' (expected 1477)"
        fi
    fi

    # ── add-pr: add a PR to the project ──────────────────────────────────────
    # Use a known-merged PR so this test is unconditional (no dynamic lookup,
    # no skip path). PR #1484 is permanently merged in cfgms.
    local test_pr_num=1484
    exit_code=0
    local link_pr_out link_pr_item_id
    link_pr_out=$(bash "$script" add-pr "$test_pr_num" 2>&1) || exit_code=$?
    if [[ $exit_code -ne 0 ]]; then
        log_fail "project-queue.sh add-pr: failed (exit $exit_code): $link_pr_out"
    else
        link_pr_item_id=$(echo "$link_pr_out" | python3 -c "
import json, sys
d = json.load(sys.stdin)
print(d.get('item_id', ''))
" 2>/dev/null) || link_pr_item_id=""
        if [[ -n "$link_pr_item_id" ]]; then
            log_pass "project-queue.sh add-pr: returns item_id for added PR"
            created_items+=("$link_pr_item_id")
        else
            log_fail "project-queue.sh add-pr: no item_id in output: $link_pr_out"
        fi
    fi

    # ── delete-item ───────────────────────────────────────────────────────────
    exit_code=0
    local delete_out
    delete_out=$(bash "$script" delete-item "$item_id" 2>&1) || exit_code=$?
    if [[ $exit_code -ne 0 ]]; then
        log_fail "project-queue.sh delete-item: failed (exit $exit_code): $delete_out"
    else
        local deleted_id
        deleted_id=$(echo "$delete_out" | python3 -c "
import json, sys
d = json.load(sys.stdin)
print(d.get('deleted_item_id', ''))
" 2>/dev/null) || deleted_id=""
        if [[ -n "$deleted_id" ]]; then
            log_pass "project-queue.sh delete-item: returns deleted_item_id in JSON"
            # Remove from cleanup list since it's already deleted
            local new_items=()
            for cid in "${created_items[@]:-}"; do
                [[ -n "$cid" && "$cid" != "$item_id" ]] && new_items+=("$cid")
            done
            if [[ ${#new_items[@]} -gt 0 ]]; then
                created_items=("${new_items[@]}")
            else
                created_items=()
            fi
        else
            log_fail "project-queue.sh delete-item: no deleted_item_id in output: $delete_out"
        fi
    fi
}

test_project_queue_set_pr() {
    log_test "Testing project-queue.sh: set-pr integration against live cfgms-pipeline project..."

    local script
    script="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/project-queue.sh"

    if [[ ! -f "$script" ]]; then
        log_skip "project-queue.sh set-pr: Script not found"
        return
    fi

    # Skip if gh is not available or not authenticated
    if ! command -v gh >/dev/null 2>&1; then
        log_skip "project-queue.sh set-pr integration: gh CLI not available"
        return
    fi
    if ! gh auth status >/dev/null 2>&1; then
        log_skip "project-queue.sh set-pr integration: gh not authenticated — skipping live tests"
        return
    fi

    local tmp_dir
    tmp_dir=$(mktemp -d)

    local created_item_id=""
    cleanup_set_pr() {
        if [[ -n "$created_item_id" ]]; then
            bash "$script" delete-item "$created_item_id" >/dev/null 2>&1 || true
        fi
        rm -rf "$tmp_dir"
    }
    trap cleanup_set_pr RETURN

    echo "Integration test body for set-pr test." > "$tmp_dir/body.md"

    # Create a draft item
    local create_out exit_code=0
    create_out=$(bash "$script" create-draft 0 "set-pr integration test" "$tmp_dir/body.md" 2>&1) || exit_code=$?

    if [[ $exit_code -ne 0 ]]; then
        log_fail "project-queue.sh set-pr: create-draft failed (exit $exit_code): $create_out"
        return
    fi

    created_item_id=$(echo "$create_out" | python3 -c "import json,sys; print(json.load(sys.stdin)['item_id'])" 2>/dev/null) || {
        log_fail "project-queue.sh set-pr: create-draft output not valid JSON: $create_out"
        return
    }

    if [[ -z "$created_item_id" ]]; then
        log_fail "project-queue.sh set-pr: create-draft returned empty item_id"
        return
    fi

    # Call set-pr with PR number 9999
    local set_pr_out
    exit_code=0
    set_pr_out=$(bash "$script" set-pr "$created_item_id" "9999" 2>&1) || exit_code=$?

    if [[ $exit_code -ne 0 ]]; then
        log_fail "project-queue.sh set-pr: failed (exit $exit_code): $set_pr_out"
        return
    fi

    local set_pr_ok
    set_pr_ok=$(echo "$set_pr_out" | python3 -c "
import json,sys
d=json.load(sys.stdin)
print('yes' if d.get('updated') == True else 'no')
" 2>/dev/null) || set_pr_ok="parse-error"

    if [[ "$set_pr_ok" == "yes" ]]; then
        log_pass "project-queue.sh set-pr: returns updated=true JSON"
    else
        log_fail "project-queue.sh set-pr: unexpected output: $set_pr_out"
    fi

    # Verify via get-item that .fields.PR == "9999"
    local get_out pr_field
    exit_code=0
    get_out=$(bash "$script" get-item "$created_item_id" 2>&1) || exit_code=$?

    if [[ $exit_code -ne 0 ]]; then
        log_fail "project-queue.sh set-pr: get-item failed (exit $exit_code): $get_out"
        return
    fi

    pr_field=$(echo "$get_out" | python3 -c "
import json,sys
d=json.load(sys.stdin)
print(d.get('fields',{}).get('PR',''))
" 2>/dev/null) || pr_field=""

    if [[ "$pr_field" == "9999" ]]; then
        log_pass "project-queue.sh set-pr: get-item fields.PR == '9999' (round-trip verified)"
    else
        log_fail "project-queue.sh set-pr: get-item fields.PR='$pr_field' (expected '9999')"
    fi
}

test_trust_boundary() {
    log_test "Running trust boundary regression suite (test/security/trust_boundary_test.sh)..."

    local script
    script="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/test/security/trust_boundary_test.sh"

    if [[ ! -f "$script" ]]; then
        log_fail "trust_boundary: test script not found at $script"
        return
    fi

    local exit_code=0
    # Run external script; its per-test ✓/✗ lines flow through for visibility
    bash "$script" || exit_code=$?

    if [[ $exit_code -eq 0 ]]; then
        log_pass "trust_boundary: all regression tests passed"
    else
        log_fail "trust_boundary: one or more regression tests failed (see output above)"
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
    trap 'rm -rf "$tmp_dir"' RETURN
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

test_preflight_item_dispatch() {
    log_test "Testing po-cycle-preflight.py: project_queue_list_by_status includes pure draft items via CFGMS_TEST_PROJECT_QUEUE..."

    local preflight_script
    preflight_script="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/../.claude/scripts/po-cycle-preflight.py"

    if [[ ! -f "$preflight_script" ]]; then
        log_fail "po-cycle-preflight.py: not found at $preflight_script"
        return
    fi

    local tmp_dir
    tmp_dir=$(mktemp -d)
    trap 'rm -rf "$tmp_dir"' RETURN

    # Mock project-queue.sh: responds to list-by-status Ready with a pure draft item,
    # all other subcommands return empty array.
    local mock_pq="${tmp_dir}/project-queue.sh"
    cat > "$mock_pq" << 'MOCKEOF'
#!/usr/bin/env bash
subcmd="${1:-}"
status="${2:-}"
if [[ "$subcmd" == "list-by-status" && "$status" == "Ready" ]]; then
    printf '[{"item_id":"PVTI_test123456789012","issue_num":null,"title":"pure draft"}]\n'
else
    printf '[]\n'
fi
exit 0
MOCKEOF
    chmod +x "$mock_pq"

    local tmp_py
    tmp_py=$(mktemp --suffix=.py)
    # Use importlib.util to load the hyphen-named file (matching existing test pattern).
    cat > "$tmp_py" << PYEOF
import sys, os, importlib.util
os.environ['CFGMS_TEST_PROJECT_QUEUE'] = '${mock_pq}'
spec = importlib.util.spec_from_file_location('preflight', '${preflight_script}')
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
r = mod.project_queue_list_by_status('Ready')
assert any(i.get('item_id') == 'PVTI_test123456789012' and i.get('number') is None for i in r), f'FAIL: {r}'
print('PASS')
PYEOF

    local output exit_code=0
    output=$(python3 "$tmp_py" 2>&1) || exit_code=$?
    rm -f "$tmp_py"

    if [[ $exit_code -eq 0 ]] && echo "$output" | grep -q "^PASS"; then
        log_pass "preflight item dispatch: pure draft item_id preserved, number=null, included in results"
    else
        log_fail "preflight item dispatch: assertion failed (exit $exit_code): $output"
    fi
}

test_done_on_merge() {
    log_test "Testing po-cycle-preflight.py: auto_close_merged_items marks Done when PR is MERGED..."

    local preflight_script
    preflight_script="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/../.claude/scripts/po-cycle-preflight.py"

    if [[ ! -f "$preflight_script" ]]; then
        log_fail "po-cycle-preflight.py: not found at $preflight_script"
        return
    fi

    local tmp_dir
    tmp_dir=$(mktemp -d)
    trap 'rm -rf "$tmp_dir"' RETURN

    local calls_file="${tmp_dir}/calls.txt"
    touch "$calls_file"

    # Mock project-queue.sh:
    # - list-by-status "In Progress" → item with PR field
    # - get-item PVTI_dmtest → item with PR=1234
    # - update-field → records call and succeeds
    local mock_pq="${tmp_dir}/project-queue.sh"
    cat > "$mock_pq" << MOCKEOF
#!/usr/bin/env bash
subcmd="\${1:-}"
case "\$subcmd" in
  list-by-status)
    printf '[{"item_id":"PVTI_dmtest","issue_num":null,"title":"t","status":"In Progress"}]\n'
    ;;
  get-item)
    printf '{"item_id":"PVTI_dmtest","fields":{"PR":"1234"},"status":"In Progress","title":"t","body":""}\n'
    ;;
  update-field)
    echo "\$@" >> "${calls_file}"
    printf '{"updated":true}\n'
    ;;
  *)
    printf '[]\n'
    ;;
esac
exit 0
MOCKEOF
    chmod +x "$mock_pq"

    # Use a temp Python script (importlib.util pattern matching existing tests).
    # auto_close_merged_items now batches PR state checks via GraphQL (Issue
    # #1581) so we stub gh_graphql_pr_states instead of mocking `gh pr view`.
    local tmp_py
    tmp_py=$(mktemp --suffix=.py)
    cat > "$tmp_py" << PYEOF
import sys, os, importlib.util
os.environ['CFGMS_TEST_PROJECT_QUEUE'] = '${mock_pq}'
spec = importlib.util.spec_from_file_location('preflight', '${preflight_script}')
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
mod.gh_graphql_pr_states = lambda nums: {int(n): 'MERGED' for n in nums}
count = mod.auto_close_merged_items()
assert count == 1, f'Expected count=1 (one item closed), got count={count}'
print(f'COUNT:{count}')
PYEOF

    local output exit_code=0
    output=$(python3 "$tmp_py" 2>&1) || exit_code=$?
    rm -f "$tmp_py"

    if [[ $exit_code -eq 0 ]] && echo "$output" | grep -q "^COUNT:1"; then
        log_pass "done_on_merge: auto_close_merged_items exits 0 and returned count=1"
    else
        log_fail "done_on_merge: expected exit 0 and COUNT:1 (exit=$exit_code): $output"
    fi

    if grep -q "update-field PVTI_dmtest status Done" "$calls_file" 2>/dev/null; then
        log_pass "done_on_merge: update-field PVTI_dmtest status Done was called"
    else
        log_fail "done_on_merge: update-field call not recorded (calls: $(cat "$calls_file" 2>/dev/null))"
    fi

    # Test that a failing update-field is still non-fatal
    local fail_pq="${tmp_dir}/fail-project-queue.sh"
    cat > "$fail_pq" << MOCKEOF2
#!/usr/bin/env bash
subcmd="\${1:-}"
case "\$subcmd" in
  list-by-status)
    printf '[{"item_id":"PVTI_dmtest","issue_num":null,"title":"t","status":"In Progress"}]\n'
    ;;
  get-item)
    printf '{"item_id":"PVTI_dmtest","fields":{"PR":"1234"},"status":"In Progress","title":"t","body":""}\n'
    ;;
  update-field)
    echo "simulated failure" >&2
    exit 1
    ;;
  *)
    printf '[]\n'
    ;;
esac
exit 0
MOCKEOF2
    chmod +x "$fail_pq"

    local tmp_py2
    tmp_py2=$(mktemp --suffix=.py)
    cat > "$tmp_py2" << PYEOF2
import sys, os, importlib.util
os.environ['CFGMS_TEST_PROJECT_QUEUE'] = '${fail_pq}'
spec = importlib.util.spec_from_file_location('preflight', '${preflight_script}')
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
mod.gh_graphql_pr_states = lambda nums: {int(n): 'MERGED' for n in nums}
mod.auto_close_merged_items()
PYEOF2

    local fail_exit=0
    python3 "$tmp_py2" 2>/dev/null || fail_exit=$?
    rm -f "$tmp_py2"

    if [[ $fail_exit -eq 0 ]]; then
        log_pass "done_on_merge: failing update-field does not cause auto_close_merged_items to exit non-zero"
    else
        log_fail "done_on_merge: auto_close_merged_items should be non-fatal even when update-field fails (exit $fail_exit)"
    fi
}

test_create_clone_item() {
    log_test "Testing create-clone-item: branch and worktree created from item_id LAST12..."

    local tmp_dir
    tmp_dir=$(mktemp -d)
    local remote_dir="${tmp_dir}/remote.git"
    local host_dir="${tmp_dir}/host"
    local worktree_dir="${tmp_dir}/worktrees"
    local item_id="PVTI_abc123456789012"
    # LAST12 = last 12 alphanumeric chars of item_id: "PVTIabc123456789012" → last 12 = "123456789012"
    local expected_last12="123456789012"
    local expected_branch="feature/item-${expected_last12}-agent"
    local dispatch_script
    dispatch_script="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/../.claude/scripts/agent-dispatch.sh"

    git init --bare -b develop "$remote_dir" >/dev/null 2>&1
    git init -b develop "$host_dir" >/dev/null 2>&1
    git -C "$host_dir" config user.email "test@test.com"
    git -C "$host_dir" config user.name "Test"
    git -C "$host_dir" remote add origin "$remote_dir"
    git -C "$host_dir" commit --allow-empty -m "initial commit" >/dev/null 2>&1
    git -C "$host_dir" push origin develop >/dev/null 2>&1

    mkdir -p "$worktree_dir"

    local output exit_code=0
    output=$(CFGMS_TEST_REPO_ROOT="$host_dir" CFGMS_TEST_WORKTREE_BASE="$worktree_dir" \
        bash "$dispatch_script" create-clone-item "$item_id" 2>&1) || exit_code=$?

    if [[ $exit_code -eq 0 ]]; then
        log_pass "create-clone-item: exits 0 for valid item_id"
    else
        log_fail "create-clone-item: exited $exit_code: $output"
        rm -rf "$tmp_dir"
        return
    fi

    if echo "$output" | grep -q "CLONE_OK:item-${expected_last12}:${expected_branch}"; then
        log_pass "create-clone-item: output contains CLONE_OK:item-<LAST12>:<branch>"
    else
        log_fail "create-clone-item: expected 'CLONE_OK:item-${expected_last12}:${expected_branch}' not found in: $output"
    fi

    local clone_dir="${worktree_dir}/item-${expected_last12}"
    if [[ -d "$clone_dir" ]]; then
        log_pass "create-clone-item: clone directory created at item-<LAST12>"
    else
        log_fail "create-clone-item: clone directory '${clone_dir}' not created"
    fi

    if git -C "$clone_dir" branch --show-current 2>/dev/null | grep -q "^${expected_branch}$"; then
        log_pass "create-clone-item: cloned repo is on branch feature/item-<LAST12>-agent"
    else
        local actual_branch
        actual_branch=$(git -C "$clone_dir" branch --show-current 2>/dev/null || echo "(unknown)")
        log_fail "create-clone-item: expected branch '${expected_branch}', got '${actual_branch}'"
    fi

    rm -rf "$tmp_dir"
}

test_preflight_gh_call_budget() {
    log_test "Testing po-cycle-preflight.py: ≤3 direct gh invocations per cycle (Issue #1581)..."

    local preflight_script
    preflight_script="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/../.claude/scripts/po-cycle-preflight.py"

    if [[ ! -f "$preflight_script" ]]; then
        log_fail "po-cycle-preflight.py: not found at $preflight_script"
        return
    fi

    local tmp_dir
    tmp_dir=$(mktemp -d)
    trap 'rm -rf "$tmp_dir"' RETURN

    # Mock project-queue.sh: returns one Ready issue (#9001) referencing dep #9002.
    local mock_pq="${tmp_dir}/project-queue.sh"
    cat > "$mock_pq" << 'MOCKEOF'
#!/usr/bin/env bash
subcmd="${1:-}"
status="${2:-}"
case "$subcmd" in
  list-by-status)
    if [[ "$status" == "Ready" ]]; then
      printf '[{"item_id":"PVTI_test001","issue_num":9001,"title":"ready story"}]\n'
    elif [[ "$status" == "In Progress" ]]; then
      printf '[{"item_id":"PVTI_test002","issue_num":9003,"title":"in-progress story"}]\n'
    else
      printf '[]\n'
    fi
    ;;
  get-item)
    printf '{"item_id":"%s","fields":{},"status":"","title":"","body":""}\n' "${2:-}"
    ;;
  *)
    printf '[]\n'
    ;;
esac
exit 0
MOCKEOF
    chmod +x "$mock_pq"

    # Run preflight via importlib, counting how many times the gh() / tolerant
    # wrappers were entered. The two wrappers share the _GH_CALL_COUNT global.
    local tmp_py
    tmp_py=$(mktemp --suffix=.py)
    cat > "$tmp_py" << PYEOF
import os, sys, importlib.util
os.environ['CFGMS_TEST_PROJECT_QUEUE'] = '${mock_pq}'

spec = importlib.util.spec_from_file_location('preflight', '${preflight_script}')
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

# Stub the four gh entrypoints so no network call is made. Each stub records
# the request via the real counter (incremented inside gh / gh_graphql_tolerant
# before they return), so we measure call sites, not network requests.
def fake_gh(*args, check=True):
    mod._GH_CALL_COUNT += 1
    a = list(args)
    # gh api graphql query=...
    if a[:2] == ['api', 'graphql']:
        query = ''
        for tok in a:
            if tok.startswith('query='):
                query = tok[len('query='):]
        if 'mergeQueue' in query:
            # pipeline_overview shape
            return {'data': {'repository': {
                'issues': {'nodes': []},
                'mergeQueue': {'entries': {'nodes': []}},
            }, 'storyPRs': {'nodes': []}, 'bodyRefs': {'nodes': []}}}
        return {'data': {'repository': {}}}
    return None

def fake_tolerant(query):
    mod._GH_CALL_COUNT += 1
    # Aliased issues batch — return CLOSED state for #9002 so dep gating works.
    if 'i9002' in query:
        return {'data': {'repository': {
            'i9002': {'number': 9002, 'title': 'dep', 'body': '', 'state': 'CLOSED', 'labels': {'nodes': []}},
        }}}
    # Aliased issues batch for story bodies
    return {'data': {'repository': {
        'i9001': {'number': 9001, 'title': 'ready', 'body': '## Dependencies\n#9002\n', 'state': 'OPEN', 'labels': {'nodes': []}},
        'i9003': {'number': 9003, 'title': 'in-progress', 'body': '', 'state': 'OPEN', 'labels': {'nodes': []}},
    }}}

mod.gh = fake_gh
mod.gh_graphql_tolerant = fake_tolerant

# Stub code_health_check so we don't run make + go build in the test.
mod.code_health_check = lambda: {'ok': True, 'skipped': True, 'skipped_reason': 'stub', 'develop_sha': None, 'checks': {}}

mod._GH_CALL_COUNT = 0
data = mod.main()
print(f'GH_CALL_COUNT={mod._GH_CALL_COUNT}')
assert mod._GH_CALL_COUNT <= 3, f'gh call budget exceeded: {mod._GH_CALL_COUNT} > 3'
print('PASS')
PYEOF

    local output exit_code=0
    output=$(python3 "$tmp_py" 2>&1) || exit_code=$?
    rm -f "$tmp_py"

    if [[ $exit_code -eq 0 ]] && echo "$output" | grep -q "^PASS$"; then
        local count
        count=$(echo "$output" | grep -oE 'GH_CALL_COUNT=[0-9]+' | head -1)
        log_pass "preflight gh call budget: ${count} (≤3 enforced by AC #1581)"
    else
        log_fail "preflight gh call budget: exceeded or test crashed (exit $exit_code): $output"
    fi
}

test_preflight_forged_acceptance_review() {
    log_test "Testing po-cycle-preflight.py: forged acceptance review comment rejected (author-gate)..."

    local preflight_script
    preflight_script="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/../.claude/scripts/po-cycle-preflight.py"

    if [[ ! -f "$preflight_script" ]]; then
        log_fail "po-cycle-preflight.py: not found at $preflight_script"
        return
    fi

    local tmp_py
    tmp_py=$(mktemp --suffix=.py)
    trap 'rm -f "$tmp_py"' RETURN

    cat > "$tmp_py" << 'PYEOF'
import sys, importlib.util, os

script_path = os.environ["PREFLIGHT_SCRIPT"]
spec = importlib.util.spec_from_file_location("preflight", script_path)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

# --- Part (a): has_acceptance_review_comment must be False for forged comment ---
# Call the production module's is_trusted_review_comment function directly so
# any regression in the author-gate logic causes this assertion to fail.
forged_comment = {"author": {"login": "evil-actor"}, "body": "acceptance review: LGTM"}
has_review = mod.is_trusted_review_comment(forged_comment)
if has_review:
    print("FAIL_A: forged comment accepted as trusted (has_acceptance_review_comment=True)")
    sys.exit(1)
print("PASS_A: forged comment yields has_acceptance_review_comment=False")

# --- Part (b): compute_review_recommendations must recommend spawn_acceptance_reviewer ---
# A PR with CI green, no trusted review comment -> must recommend review, not skip
pr_summary = {
    "pr": 9999,
    "story_number": 9998,
    "has_acceptance_review_comment": has_review,
    "wip_session_failed": False,
    "merge_state_status": "CLEAN",
    "mergeable": "MERGEABLE",
    "auto_merge_enabled": False,
    "ci_summary": {
        "overall": "green",
        "pass": 4, "pending": 0, "fail": 0, "skipped": 0,
        "pending_checks": [], "failed_checks": [],
    },
}
recs = mod.compute_review_recommendations([pr_summary], set(), set())
if not recs:
    print("FAIL_B: compute_review_recommendations returned empty list")
    sys.exit(1)
action = recs[0].get("action", "")
if action != "spawn_acceptance_reviewer":
    print("FAIL_B: expected spawn_acceptance_reviewer, got " + repr(action))
    sys.exit(1)
print("PASS_B: compute_review_recommendations recommends spawn_acceptance_reviewer")
PYEOF

    local exit_code=0
    local output
    output=$(PREFLIGHT_SCRIPT="$preflight_script" python3 "$tmp_py" 2>&1) || exit_code=$?

    while IFS= read -r line; do
        case "$line" in
            PASS_A:*) log_pass "preflight author-gate: ${line#PASS_A: }" ;;
            PASS_B:*) log_pass "preflight recommend: ${line#PASS_B: }" ;;
            FAIL_A:*) log_fail "preflight author-gate: ${line#FAIL_A: }" ;;
            FAIL_B:*) log_fail "preflight recommend: ${line#FAIL_B: }" ;;
        esac
    done <<< "$output"

    if [[ $exit_code -ne 0 ]] && ! grep -q "^FAIL" <<< "$output"; then
        log_fail "preflight forged acceptance review: Python test crashed (exit $exit_code): $output"
    fi
}

test_agent_dispatch_create_clone_item() {
    log_test "Testing agent-dispatch.sh create-clone-item: LAST12 derivation and clone creation..."

    local tmp_dir
    tmp_dir=$(mktemp -d)
    local remote_dir="${tmp_dir}/remote.git"
    local host_dir="${tmp_dir}/host"
    local worktree_dir="${tmp_dir}/worktrees"
    # item_id from AC: PVTI_lADOtest000000012345
    # Strip non-alphanumeric → PVTIlADOtest000000012345 (24 chars)
    # Rightmost 12 → 000000012345
    local item_id="PVTI_lADOtest000000012345"
    local expected_last12="000000012345"
    local expected_branch="feature/item-${expected_last12}-agent"
    local dispatch_script
    dispatch_script="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/../.claude/scripts/agent-dispatch.sh"

    git init --bare -b develop "$remote_dir" >/dev/null 2>&1
    git init -b develop "$host_dir" >/dev/null 2>&1
    git -C "$host_dir" config user.email "test@test.com"
    git -C "$host_dir" config user.name "Test"
    git -C "$host_dir" remote add origin "$remote_dir"
    git -C "$host_dir" commit --allow-empty -m "initial commit" >/dev/null 2>&1
    git -C "$host_dir" push origin develop >/dev/null 2>&1

    mkdir -p "$worktree_dir"

    local output exit_code=0
    output=$(CFGMS_TEST_REPO_ROOT="$host_dir" CFGMS_TEST_WORKTREE_BASE="$worktree_dir" \
        bash "$dispatch_script" create-clone-item "$item_id" 2>&1) || exit_code=$?

    if [[ $exit_code -eq 0 ]]; then
        log_pass "agent_dispatch_create_clone_item: exits 0 for item_id ${item_id}"
    else
        log_fail "agent_dispatch_create_clone_item: exited ${exit_code}: ${output}"
        rm -rf "$tmp_dir"
        return
    fi

    # Full match: verifies correct LAST12 and branch name, not just prefix
    if echo "$output" | grep -q "CLONE_OK:item-${expected_last12}:${expected_branch}"; then
        log_pass "agent_dispatch_create_clone_item: stdout contains full CLONE_OK:item-${expected_last12}:${expected_branch}"
    else
        log_fail "agent_dispatch_create_clone_item: expected 'CLONE_OK:item-${expected_last12}:${expected_branch}' in output: ${output}"
    fi

    local clone_dir="${worktree_dir}/item-${expected_last12}"
    if [[ -d "$clone_dir" ]]; then
        log_pass "agent_dispatch_create_clone_item: clone directory created at item-${expected_last12}"
    else
        log_fail "agent_dispatch_create_clone_item: clone directory '${clone_dir}' not created"
    fi

    # Verify checked-out branch matches expected item branch name
    local actual_branch
    actual_branch=$(git -C "$clone_dir" branch --show-current 2>/dev/null || echo "(unknown)")
    if [[ "$actual_branch" == "$expected_branch" ]]; then
        log_pass "agent_dispatch_create_clone_item: cloned repo is on expected branch ${expected_branch}"
    else
        log_fail "agent_dispatch_create_clone_item: expected branch '${expected_branch}', got '${actual_branch}'"
    fi

    rm -rf "$tmp_dir"
}

test_cleanup_issue_item_mode() {
    log_test "Testing agent-dispatch.sh cleanup-issue: non-numeric item_id targets item container/clone..."

    local tmp_dir
    tmp_dir=$(mktemp -d)
    local worktree_dir="${tmp_dir}/worktrees"
    # item_id: PVTI_itemcleanup123 → strip non-alnum → PVTIitemcleanup123 (18) → last 12 = itemcleanup123... wait
    # PVTIitemcleanup123: P(1)V(2)T(3)I(4)i(5)t(6)e(7)m(8)c(9)l(10)e(11)a(12)n(13)u(14)p(15)1(16)2(17)3(18)
    # last 12 = cleanup123...
    # Actually: nup123 is wrong. Let me use a simpler example.
    # PVTI_testclean99 → PVTItestclean99 (15 chars) → last 12 = testclean99... that's 11...
    # PVTItestclean99: P(1)V(2)T(3)I(4)t(5)e(6)s(7)t(8)c(9)l(10)e(11)a(12)n(13)9(14)9(15) → last 12: testclean99 (only 11 after index 4)
    # Let me use PVTI_abcdefghij0123 → PVTIabcdefghij0123 (18 chars) → last 12 = bcdefghij0123...
    # Wait that's 13. Let me count: PVTIabcdefghij0123: P,V,T,I,a,b,c,d,e,f,g,h,i,j,0,1,2,3 = 18 chars
    # last 12 = chars 7-18 = efghij0123... that's 12 chars: e,f,g,h,i,j,0,1,2,3 = only 10
    # OK let me just compute it properly:
    # Strip non-alnum from PVTI_testcleanXY123 → PVTItestcleanXY123 → 18 chars
    # Last 12: chars 7-18 = "eanXY123" ... hmm let me just pick a clear item_id
    # PVTI_item000000000042 → strip non-alnum → PVTIitem000000000042 (20 chars) → last 12 = 000000000042
    local item_id="PVTI_item000000000042"
    local expected_last12="000000000042"
    local dispatch_script
    dispatch_script="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/../.claude/scripts/agent-dispatch.sh"

    mkdir -p "$worktree_dir"
    local clone_dir="${worktree_dir}/item-${expected_last12}"
    # Pre-create the clone directory so cleanup can remove it and we can verify

    mkdir -p "$clone_dir"

    local output exit_code=0
    output=$(CFGMS_TEST_REPO_ROOT="$(pwd)" CFGMS_TEST_WORKTREE_BASE="$worktree_dir" \
        bash "$dispatch_script" cleanup-issue "$item_id" 2>&1) || exit_code=$?

    # Container removal will fail (not found is fine — docker not available or container absent)
    # We check the SKIP or CLEANED message uses the correct item container name

    if echo "$output" | grep -q "cfg-agent-item-${expected_last12}"; then
        log_pass "cleanup_issue_item_mode: targets correct container name cfg-agent-item-${expected_last12}"
    else
        log_fail "cleanup_issue_item_mode: expected container name 'cfg-agent-item-${expected_last12}' in output: ${output}"
    fi

    if echo "$output" | grep -q "CLEANED:clone:${clone_dir}"; then
        log_pass "cleanup_issue_item_mode: clone directory ${clone_dir} cleaned"
    else
        log_fail "cleanup_issue_item_mode: expected 'CLEANED:clone:${clone_dir}' in output: ${output}"
    fi

    if [[ ! -d "$clone_dir" ]]; then
        log_pass "cleanup_issue_item_mode: clone directory removed on disk"
    else
        log_fail "cleanup_issue_item_mode: clone directory still exists after cleanup"
    fi

    if echo "$output" | grep -q "CLEANUP_DONE:${item_id}"; then
        log_pass "cleanup_issue_item_mode: CLEANUP_DONE reports original item_id"
    else
        log_fail "cleanup_issue_item_mode: expected 'CLEANUP_DONE:${item_id}' in output: ${output}"
    fi

    rm -rf "$tmp_dir"
}

test_review_pr_item_branch() {
    log_test "Testing review-pr item-branch: scans project queue and refuses when item_id not found..."

    local tmp_dir
    tmp_dir=$(mktemp -d)
    local worktree_dir="${tmp_dir}/worktrees"
    local pq_calls_file="${tmp_dir}/pq-calls.txt"
    touch "$pq_calls_file"
    local dispatch_script
    dispatch_script="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/../.claude/scripts/agent-dispatch.sh"

    mkdir -p "$worktree_dir"

    # Fake repo root with a scripts/project-queue.sh that records calls and returns empty
    local fake_repo="${tmp_dir}/repo"
    mkdir -p "${fake_repo}/scripts"
    cat > "${fake_repo}/scripts/project-queue.sh" << PQEOF
#!/usr/bin/env bash
echo "\$@" >> "${pq_calls_file}"
printf '[]\n'
exit 0
PQEOF
    chmod +x "${fake_repo}/scripts/project-queue.sh"

    # Mock gh: returns an open item-branch PR
    cat > "${tmp_dir}/gh" << 'GHEOF'
#!/usr/bin/env bash
if [[ "$1" == "pr" && "$2" == "view" ]]; then
    printf '{"state":"OPEN","headRefName":"feature/item-ABCD12345678-agent","body":"No fixes link","labels":[],"headRepositoryOwner":{"login":"cfg-is"}}\n'
elif [[ "$1" == "auth" && "$2" == "token" ]]; then
    echo "fake-token"
else
    printf '{}\n'
fi
exit 0
GHEOF
    chmod +x "${tmp_dir}/gh"

    # Mock docker: returns empty (no existing containers or images)
    cat > "${tmp_dir}/docker" << 'DOCKEREOF'
#!/usr/bin/env bash
exit 0
DOCKEREOF
    chmod +x "${tmp_dir}/docker"

    local output exit_code=0
    output=$(
        PATH="${tmp_dir}:${PATH}" \
        CFGMS_TEST_REPO_ROOT="$fake_repo" \
        CFGMS_TEST_WORKTREE_BASE="$worktree_dir" \
        CFGMS_TEST_CREDS_STATUS="CREDS_OK:60" \
        bash "$dispatch_script" review-pr 77 2>&1
    ) || exit_code=$?

    if [[ $exit_code -eq 3 ]]; then
        log_pass "review_pr_item_branch: exits 3 when no item_id found for item branch"
    else
        log_fail "review_pr_item_branch: expected exit 3, got ${exit_code}: ${output}"
    fi

    if echo "$output" | grep -q "REVIEW_REFUSED:77:no_story_link"; then
        log_pass "review_pr_item_branch: emits REVIEW_REFUSED:77:no_story_link after scans find nothing"
    else
        log_fail "review_pr_item_branch: expected 'REVIEW_REFUSED:77:no_story_link' in: ${output}"
    fi

    # Verify that the item-branch scan path was actually executed (list-by-status called)
    if grep -q "list-by-status" "$pq_calls_file" 2>/dev/null; then
        log_pass "review_pr_item_branch: project-queue list-by-status was called (scan attempted)"
    else
        log_fail "review_pr_item_branch: list-by-status not called — item-branch scan path not exercised"
    fi

    rm -rf "$tmp_dir"
}

test_entrypoint_set_pr_call() {
    log_test "Testing entrypoint.sh: set-pr called after PR creation with CFGMS_PROJECT_ITEM_ID..."

    local tmp_dir
    tmp_dir=$(mktemp -d)
    trap 'rm -rf "$tmp_dir"' RETURN

    local calls_file="${tmp_dir}/pq-calls.txt"
    touch "$calls_file"

    # Fake HOME with credentials (far-future expiry so token check passes)
    local fake_home="${tmp_dir}/home"
    mkdir -p "${fake_home}/.claude"
    cat > "${fake_home}/.claude/.credentials.json" << 'CREDEOF'
{"claudeAiOauth":{"expiresAt":9999999999999,"accessToken":"fake","refreshToken":"fake"}}
CREDEOF
    cat > "${fake_home}/.claude.json" << 'CONFIGEOF'
{"hasCompletedOnboarding":true}
CONFIGEOF

    # Git repo with correct branch so git branch --show-current returns story branch
    local git_dir="${tmp_dir}/repo"
    git init -b develop "$git_dir" >/dev/null 2>&1
    git -C "$git_dir" config user.email "test@test.com"
    git -C "$git_dir" config user.name "Test"
    git -C "$git_dir" commit --allow-empty -m "initial" >/dev/null 2>&1
    git -C "$git_dir" checkout -b "feature/story-999-agent" >/dev/null 2>&1

    # Mock setup-env.sh — minimal: just git config (no firewall/credentials setup needed)
    cat > "${tmp_dir}/setup-env.sh" << 'SETUPEOF'
#!/usr/bin/env bash
git config --global user.name "test-agent" 2>/dev/null || true
git config --global user.email "agent@test.com" 2>/dev/null || true
SETUPEOF
    chmod +x "${tmp_dir}/setup-env.sh"

    # Mock claude: creates validation marker and exits 0
    cat > "${tmp_dir}/claude" << 'CLAUDEOF'
#!/usr/bin/env bash
touch /tmp/agent-validation-passed
exit 0
CLAUDEOF
    chmod +x "${tmp_dir}/claude"

    # Mock gh: returns PR URL for pr list, {} for everything else
    cat > "${tmp_dir}/gh" << 'GHEOF'
#!/usr/bin/env bash
if [[ "$1" == "pr" && "$2" == "list" ]]; then
    echo "https://github.com/cfg-is/cfgms/pull/42"
else
    echo "{}"
fi
exit 0
GHEOF
    chmod +x "${tmp_dir}/gh"

    # Mock project-queue.sh: records all calls, responds to get-item and set-pr
    local pq_recorder="${tmp_dir}/pq-recorder.sh"
    cat > "$pq_recorder" << PQEOF
#!/usr/bin/env bash
echo "\$@" >> "${calls_file}"
subcmd="\${1:-}"
case "\$subcmd" in
    get-item)
        printf '{"item_id":"PVTI_testitem","title":"Test Story 999","body":"Test body content.","status":"In Progress","fields":{}}\n'
        ;;
    set-pr)
        printf '{"updated":true}\n'
        ;;
    *)
        printf '[]\n'
        ;;
esac
exit 0
PQEOF
    chmod +x "$pq_recorder"

    local entrypoint_script
    entrypoint_script="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/.devcontainer/entrypoint.sh"

    if [[ ! -f "$entrypoint_script" ]]; then
        log_fail "entrypoint_set_pr_call: entrypoint.sh not found at ${entrypoint_script}"
        return
    fi

    # Run entrypoint.sh from the temp git repo (so git branch --show-current works)
    rm -f /tmp/agent-validation-passed
    local output exit_code=0
    output=$(
        cd "$git_dir"
        PATH="${tmp_dir}:${PATH}" \
        HOME="${fake_home}" \
        CFGMS_PROJECT_ITEM_ID="PVTI_testitem" \
        CFGMS_TEST_PROJECT_QUEUE="$pq_recorder" \
        bash "$entrypoint_script" 999 2>&1
    ) || exit_code=$?

    if [[ $exit_code -eq 0 ]]; then
        log_pass "entrypoint_set_pr_call: entrypoint exits 0 with valid mocks"
    else
        log_fail "entrypoint_set_pr_call: entrypoint exited ${exit_code}: ${output}"
        return
    fi

    if grep -q "set-pr PVTI_testitem 42" "$calls_file" 2>/dev/null; then
        log_pass "entrypoint_set_pr_call: set-pr called with correct item_id and PR number (42)"
    else
        log_fail "entrypoint_set_pr_call: set-pr not called correctly (calls: $(cat "$calls_file" 2>/dev/null))"
    fi

    # Non-fatal assertion: set-pr failure must not cause entrypoint to fail
    local fail_pq="${tmp_dir}/fail-pq.sh"
    cat > "$fail_pq" << FAILPQEOF
#!/usr/bin/env bash
subcmd="\${1:-}"
case "\$subcmd" in
    get-item)
        printf '{"item_id":"PVTI_testitem","title":"Test Story 999","body":"Test body.","status":"In Progress","fields":{}}\n'
        ;;
    set-pr)
        echo "simulated set-pr failure" >&2
        exit 1
        ;;
    *)
        printf '[]\n'
        ;;
esac
FAILPQEOF
    chmod +x "$fail_pq"

    rm -f /tmp/agent-validation-passed
    local fail_exit=0
    local fail_output
    fail_output=$(
        cd "$git_dir"
        PATH="${tmp_dir}:${PATH}" \
        HOME="${fake_home}" \
        CFGMS_PROJECT_ITEM_ID="PVTI_testitem" \
        CFGMS_TEST_PROJECT_QUEUE="$fail_pq" \
        bash "$entrypoint_script" 999 2>&1
    ) || fail_exit=$?

    if [[ $fail_exit -eq 0 ]]; then
        log_pass "entrypoint_set_pr_call: entrypoint exits 0 even when set-pr fails (non-fatal)"
    else
        log_fail "entrypoint_set_pr_call: entrypoint should exit 0 when set-pr fails, got ${fail_exit}"
    fi

    if echo "$fail_output" | grep -q "WARN"; then
        log_pass "entrypoint_set_pr_call: entrypoint emits WARN when set-pr fails"
    else
        log_fail "entrypoint_set_pr_call: should emit WARN when set-pr fails (output: ${fail_output})"
    fi
}

test_dispatch_creds_gate() {
    log_test "Testing agent-dispatch.sh: launch/review-pr gate on CREDS_LOW/EXPIRED, emit DISPATCH_DEFERRED..."

    local dispatch_script
    dispatch_script="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/../.claude/scripts/agent-dispatch.sh"

    if [[ ! -f "$dispatch_script" ]]; then
        log_fail "dispatch_creds_gate: script not found at $dispatch_script"
        return
    fi

    # CREDS_LOW causes launch to exit non-zero with DISPATCH_DEFERRED token
    local output exit_code=0
    output=$(CFGMS_TEST_CREDS_STATUS="CREDS_LOW:5" bash "$dispatch_script" launch 99 2>&1) || exit_code=$?
    if [[ $exit_code -ne 0 ]]; then
        log_pass "dispatch_creds_gate launch CREDS_LOW: exits non-zero"
    else
        log_fail "dispatch_creds_gate launch CREDS_LOW: expected non-zero exit, got 0: ${output}"
    fi
    if echo "$output" | grep -q "DISPATCH_DEFERRED:creds_low:CREDS_LOW:5"; then
        log_pass "dispatch_creds_gate launch CREDS_LOW: emits DISPATCH_DEFERRED:creds_low:CREDS_LOW:5"
    else
        log_fail "dispatch_creds_gate launch CREDS_LOW: expected DISPATCH_DEFERRED:creds_low:CREDS_LOW:5 in output: ${output}"
    fi

    # CREDS_EXPIRED causes launch to exit non-zero with DISPATCH_DEFERRED token
    exit_code=0
    output=$(CFGMS_TEST_CREDS_STATUS="CREDS_EXPIRED:-3" bash "$dispatch_script" launch 99 2>&1) || exit_code=$?
    if [[ $exit_code -ne 0 ]]; then
        log_pass "dispatch_creds_gate launch CREDS_EXPIRED: exits non-zero"
    else
        log_fail "dispatch_creds_gate launch CREDS_EXPIRED: expected non-zero exit, got 0: ${output}"
    fi
    if echo "$output" | grep -q "DISPATCH_DEFERRED:creds_low:CREDS_EXPIRED:-3"; then
        log_pass "dispatch_creds_gate launch CREDS_EXPIRED: emits DISPATCH_DEFERRED:creds_low:CREDS_EXPIRED:-3"
    else
        log_fail "dispatch_creds_gate launch CREDS_EXPIRED: expected DISPATCH_DEFERRED:creds_low:CREDS_EXPIRED:-3 in output: ${output}"
    fi

    # CREDS_LOW causes review-pr to exit non-zero with DISPATCH_DEFERRED token
    exit_code=0
    output=$(CFGMS_TEST_CREDS_STATUS="CREDS_LOW:2" bash "$dispatch_script" review-pr 1589 2>&1) || exit_code=$?
    if [[ $exit_code -ne 0 ]]; then
        log_pass "dispatch_creds_gate review-pr CREDS_LOW: exits non-zero"
    else
        log_fail "dispatch_creds_gate review-pr CREDS_LOW: expected non-zero exit, got 0: ${output}"
    fi
    if echo "$output" | grep -q "DISPATCH_DEFERRED:creds_low:CREDS_LOW:2"; then
        log_pass "dispatch_creds_gate review-pr CREDS_LOW: emits DISPATCH_DEFERRED:creds_low:CREDS_LOW:2"
    else
        log_fail "dispatch_creds_gate review-pr CREDS_LOW: expected DISPATCH_DEFERRED:creds_low:CREDS_LOW:2 in output: ${output}"
    fi

    # CREDS_LOW causes launch-generic to exit non-zero with DISPATCH_DEFERRED token
    exit_code=0
    output=$(CFGMS_TEST_CREDS_STATUS="CREDS_LOW:8" bash "$dispatch_script" launch-generic "cfg-agent-test" "/tmp/nonexistent" 2>&1) || exit_code=$?
    if [[ $exit_code -ne 0 ]]; then
        log_pass "dispatch_creds_gate launch-generic CREDS_LOW: exits non-zero"
    else
        log_fail "dispatch_creds_gate launch-generic CREDS_LOW: expected non-zero exit, got 0: ${output}"
    fi
    if echo "$output" | grep -q "DISPATCH_DEFERRED:creds_low:CREDS_LOW:8"; then
        log_pass "dispatch_creds_gate launch-generic CREDS_LOW: emits DISPATCH_DEFERRED:creds_low:CREDS_LOW:8"
    else
        log_fail "dispatch_creds_gate launch-generic CREDS_LOW: expected DISPATCH_DEFERRED:creds_low:CREDS_LOW:8 in output: ${output}"
    fi
}

test_preflight_acceptance_review_comment_match() {
    log_test "Testing po-cycle-preflight.py: is_trusted_review_comment matches sentinel and heading, not just author..."

    local preflight_script
    preflight_script="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/../.claude/scripts/po-cycle-preflight.py"

    if [[ ! -f "$preflight_script" ]]; then
        log_fail "po-cycle-preflight.py: not found at $preflight_script"
        return
    fi

    local tmp_py
    tmp_py=$(mktemp --suffix=.py)
    trap 'rm -f "$tmp_py"' RETURN

    cat > "$tmp_py" << 'PYEOF'
import sys, importlib.util, os

script_path = os.environ["PREFLIGHT_SCRIPT"]
spec = importlib.util.spec_from_file_location("preflight", script_path)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

# Part A: sentinel in body matches regardless of author (forward-compat path)
sentinel_comment = {
    "author": {"login": "jrdnr"},
    "body": "<!-- cfgms-acceptance-review -->\n## Acceptance Review — PASS\n\nAll checks passing.",
}
result = mod.is_trusted_review_comment(sentinel_comment)
if result:
    print("PASS_A: sentinel match accepted (author=jrdnr, sentinel present)")
else:
    print("FAIL_A: sentinel comment rejected — expected True")
    sys.exit(1)

# Part B: ## Acceptance Review heading from jrdnr matches (backward compat, PR #1589 scenario)
heading_comment = {
    "author": {"login": "jrdnr"},
    "body": "## Acceptance Review — FAIL\n\n### Findings\n| 1 | High | ... |",
}
result = mod.is_trusted_review_comment(heading_comment)
if result:
    print("PASS_B: heading match accepted (author=jrdnr, ## Acceptance Review heading present)")
else:
    print("FAIL_B: heading-only comment rejected — expected True for backward compat")
    sys.exit(1)

# Part C: plain body with 'acceptance review' but no ## heading or sentinel is rejected
plain_comment = {
    "author": {"login": "anyone"},
    "body": "acceptance review: LGTM",
}
result = mod.is_trusted_review_comment(plain_comment)
if not result:
    print("PASS_C: plain 'acceptance review' body (no ## heading, no sentinel) correctly rejected")
else:
    print("FAIL_C: plain comment accepted as trusted — expected False")
    sys.exit(1)

# Part D: compute_review_recommendations does NOT recommend spawn_acceptance_reviewer
# for a PR whose comment matches the heading (PR #1589 regression test)
pr_summary = {
    "pr": 1589,
    "story_number": 1570,
    "has_acceptance_review_comment": True,  # already set by preflight using new logic
    "wip_session_failed": False,
    "merge_state_status": "MERGEABLE",
    "mergeable": "MERGEABLE",
    "auto_merge_enabled": False,
    "ci_summary": {
        "overall": "green",
        "pass": 4, "pending": 0, "fail": 0, "skipped": 0,
        "pending_checks": [], "failed_checks": [],
    },
}
recs = mod.compute_review_recommendations([pr_summary], set(), set())
if not recs:
    print("FAIL_D: compute_review_recommendations returned empty list")
    sys.exit(1)
action = recs[0].get("action", "")
if action != "spawn_acceptance_reviewer":
    print(f"PASS_D: PR #1589 with existing review comment gets action={action!r} (not spawn_acceptance_reviewer)")
else:
    print("FAIL_D: PR #1589 recommended spawn_acceptance_reviewer despite existing review comment")
    sys.exit(1)
PYEOF

    local exit_code=0
    local output
    output=$(PREFLIGHT_SCRIPT="$preflight_script" python3 "$tmp_py" 2>&1) || exit_code=$?

    while IFS= read -r line; do
        case "$line" in
            PASS_A:*) log_pass "preflight review match: ${line#PASS_A: }" ;;
            PASS_B:*) log_pass "preflight review match: ${line#PASS_B: }" ;;
            PASS_C:*) log_pass "preflight review match: ${line#PASS_C: }" ;;
            PASS_D:*) log_pass "preflight review match: ${line#PASS_D: }" ;;
            FAIL_A:*) log_fail "preflight review match: ${line#FAIL_A: }" ;;
            FAIL_B:*) log_fail "preflight review match: ${line#FAIL_B: }" ;;
            FAIL_C:*) log_fail "preflight review match: ${line#FAIL_C: }" ;;
            FAIL_D:*) log_fail "preflight review match: ${line#FAIL_D: }" ;;
        esac
    done <<< "$output"

    if [[ $exit_code -ne 0 ]] && ! grep -q "^FAIL" <<< "$output"; then
        log_fail "preflight acceptance review comment match: Python test crashed (exit $exit_code): $output"
    fi
}

test_preflight_review_verdict_routing() {
    log_test "Testing po-cycle-preflight.py: review-FAIL routing by commit-vs-review timestamp; never enqueue/clear-stale a FAIL (Issues #1657, #1731)..."

    local preflight_script
    preflight_script="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/../.claude/scripts/po-cycle-preflight.py"

    if [[ ! -f "$preflight_script" ]]; then
        log_fail "po-cycle-preflight.py: not found at $preflight_script"
        return
    fi

    local tmp_py
    tmp_py=$(mktemp --suffix=.py)
    trap 'rm -f "$tmp_py"' RETURN

    cat > "$tmp_py" << 'PYEOF'
import sys, importlib.util, os

script_path = os.environ["PREFLIGHT_SCRIPT"]
spec = importlib.util.spec_from_file_location("preflight", script_path)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

# createdAt drives the commit-vs-review timestamp comparison (issue #1731):
# a fix counts as landed only when its commit is newer than the review comment.
REVIEW_TS = "2026-05-21T12:00:00Z"
fail_c = {"body": "<!-- cfgms-acceptance-review -->\n## Acceptance Review — FAIL\n",
          "createdAt": REVIEW_TS}
pass_c = {"body": "<!-- cfgms-acceptance-review -->\n## Acceptance Review — PASS\n",
          "createdAt": REVIEW_TS}

# Part A: latest_review_verdict extracts fail/pass/None
if (mod.latest_review_verdict([fail_c]) == "fail"
        and mod.latest_review_verdict([pass_c]) == "pass"
        and mod.latest_review_verdict([]) is None):
    print("PASS_A: latest_review_verdict extracts fail/pass/None")
else:
    print("FAIL_A: latest_review_verdict extraction wrong")
    sys.exit(1)

# Part A2: most recent verdict wins (FAIL then PASS -> pass)
if mod.latest_review_verdict([fail_c, pass_c]) == "pass":
    print("PASS_A2: latest_review_verdict takes the most recent verdict")
else:
    print("FAIL_A2: latest_review_verdict did not take the latest")
    sys.exit(1)

# Part A3: latest_review also returns the review comment's timestamp
if mod.latest_review([fail_c]) == ("fail", REVIEW_TS):
    print("PASS_A3: latest_review returns (verdict, created_at)")
else:
    print(f"FAIL_A3: latest_review returned {mod.latest_review([fail_c])!r}")
    sys.exit(1)

# Part A4: fix_landed_after_review compares commit vs review timestamps and
# fails safe (False) when either timestamp is missing.
if (mod.fix_landed_after_review({"latest_commit_date": "2026-05-21T13:00:00Z",
                                 "latest_review_comment_date": REVIEW_TS}) is True
        and mod.fix_landed_after_review({"latest_commit_date": "2026-05-21T11:00:00Z",
                                         "latest_review_comment_date": REVIEW_TS}) is False
        and mod.fix_landed_after_review({}) is False):
    print("PASS_A4: fix_landed_after_review compares timestamps, fails safe")
else:
    print("FAIL_A4: fix_landed_after_review wrong")
    sys.exit(1)

# review FAIL + CI green, fix commit landed AFTER the review comment.
pr_fail_green = {
    "pr": 2001, "story_number": 3001,
    "has_acceptance_review_comment": True,
    "latest_review_verdict": "fail",
    "latest_review_comment_date": REVIEW_TS,
    "latest_commit_date": "2026-05-21T13:00:00Z",
    "wip_session_failed": False,
    "merge_state_status": "MERGEABLE", "mergeable": "MERGEABLE",
    "auto_merge_enabled": False,
    "ci_summary": {"overall": "green", "pass": 4, "pending": 0, "fail": 0,
                   "skipped": 0, "pending_checks": [], "failed_checks": []},
}
# review FAIL + CI green, but NO fix commit since the review (commit predates it).
pr_fail_nofix = dict(pr_fail_green, pr=2005,
                     latest_commit_date="2026-05-21T11:00:00Z")

# Part B1: review FAIL + CI green + fix commit landed after the review ->
# spawn_acceptance_reviewer (re-review), NOT enqueue_merge.
recs = mod.compute_review_recommendations([pr_fail_green], set(), set())
action = recs[0].get("action") if recs else None
if action == "spawn_acceptance_reviewer":
    print("PASS_B1: review FAIL + CI green + fix landed -> spawn_acceptance_reviewer")
else:
    print(f"FAIL_B1: review FAIL + fix landed got action={action!r}, expected spawn_acceptance_reviewer")
    sys.exit(1)

# Part B2: review FAIL + CI green but NO fix commit since the review -> skip.
# Green CI proves only that the OLD code compiles; re-reviewing unfixed code
# would FAIL again. The fix cycle owns it — never enqueue a FAIL (issue #1731).
recs = mod.compute_review_recommendations([pr_fail_nofix], set(), set())
action = recs[0].get("action") if recs else None
if action == "skip":
    print("PASS_B2: review FAIL + CI green + no fix landed -> skip (fix cycle owns it)")
else:
    print(f"FAIL_B2: review FAIL + no fix got action={action!r}, expected skip")
    sys.exit(1)

# Part C: review PASS + CI green + mergeable -> enqueue_merge (unchanged)
pr_pass_green = dict(pr_fail_green, pr=2002, latest_review_verdict="pass")
recs = mod.compute_review_recommendations([pr_pass_green], set(), set())
action = recs[0].get("action") if recs else None
if action == "enqueue_merge":
    print("PASS_C: review PASS + CI green -> enqueue_merge")
else:
    print(f"FAIL_C: review PASS + CI green got action={action!r}, expected enqueue_merge")
    sys.exit(1)

# Part D1: Fix story whose PR FAILED review, CI green, NO fix commit since the
# review -> dispatch_fix. Must NEVER clear_stale_status — the FAIL is unresolved.
fix_story = {"number": 3001, "title": "t", "item_id": "X"}
recs = mod.compute_fix_recommendations([fix_story], [pr_fail_nofix], set(), set())
action = recs[0].get("action") if recs else None
if action == "dispatch_fix":
    print("PASS_D1: review-FAIL Fix + CI green + no fix landed -> dispatch_fix")
else:
    print(f"FAIL_D1: review-FAIL Fix (no fix landed) got action={action!r}, expected dispatch_fix")
    sys.exit(1)

# Part D2: Fix story whose PR FAILED review, CI green, fix commit landed after
# the review -> skip (the re-review owns it; do not clear_stale_status/enqueue).
recs = mod.compute_fix_recommendations([fix_story], [pr_fail_green], set(), set())
action = recs[0].get("action") if recs else None
if action == "skip":
    print("PASS_D2: review-FAIL Fix + CI green + fix landed -> skip (re-review owns it)")
else:
    print(f"FAIL_D2: review-FAIL Fix (fix landed) got action={action!r}, expected skip")
    sys.exit(1)

# Part E: CI-driven Fix (no review FAIL) + CI green still clears stale status
pr_noreview_green = dict(pr_fail_green, pr=2003, story_number=3002,
                         has_acceptance_review_comment=False,
                         latest_review_verdict=None,
                         latest_review_comment_date=None)
fix_story2 = {"number": 3002, "title": "t", "item_id": "Y"}
recs = mod.compute_fix_recommendations([fix_story2], [pr_noreview_green], set(), set())
action = recs[0].get("action") if recs else None
if action == "clear_stale_status":
    print("PASS_E: CI-driven Fix (no review FAIL) + CI green -> clear_stale_status retained")
else:
    print(f"FAIL_E: CI-driven Fix got action={action!r}, expected clear_stale_status")
    sys.exit(1)
PYEOF

    local exit_code=0
    local output
    output=$(PREFLIGHT_SCRIPT="$preflight_script" python3 "$tmp_py" 2>&1) || exit_code=$?

    while IFS= read -r line; do
        case "$line" in
            PASS_*) log_pass "preflight verdict routing: ${line#*: }" ;;
            FAIL_*) log_fail "preflight verdict routing: ${line#*: }" ;;
        esac
    done <<< "$output"

    if [[ $exit_code -ne 0 ]] && ! grep -q "^FAIL" <<< "$output"; then
        log_fail "preflight review verdict routing: Python test crashed (exit $exit_code): $output"
    fi
}

# Main execution
echo "🔍 Script Validation Test Suite"
echo "================================"
echo ""

test_syntax
echo ""
test_license_checker
echo ""
test_invalid_cert_generation
echo ""
test_credential_generation
echo ""
test_wait_for_services
echo ""
test_executable_permissions

echo ""
test_create_clone_stale_branch_deletion
echo ""
test_create_clone_keep_remote
echo ""
test_create_clone_deletion_failure
echo ""
test_create_clone_duplicate_pr_gate
echo ""
test_check_providers
echo ""
test_security_trivy_init_error
echo ""
test_security_trivy_findings
echo ""
test_security_trivy_clean_scan
echo ""
test_project_queue_no_gh_issue_calls
echo ""
test_project_queue_invalid_args
echo ""
test_project_queue_integration
echo ""
test_project_queue_set_pr
echo ""
test_create_clone_item
echo ""
test_agent_dispatch_create_clone_item
echo ""
test_cleanup_issue_item_mode
echo ""
test_review_pr_item_branch
echo ""
test_entrypoint_set_pr_call
echo ""
test_preflight_item_dispatch
echo ""
test_done_on_merge
echo ""
test_preflight_forged_acceptance_review
echo ""
test_preflight_gh_call_budget
echo ""
test_dispatch_creds_gate
echo ""
test_preflight_acceptance_review_comment_match
echo ""
test_preflight_review_verdict_routing
echo ""
test_trust_boundary
echo ""
test_no_pipeline_label_refs
echo ""
echo ""
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
