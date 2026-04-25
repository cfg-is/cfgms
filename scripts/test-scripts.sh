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

# Test 2: Template validation script (critical for CI)
test_template_validation() {
    log_test "Testing template validation script..."

    # Test structure validation
    if bash scripts/validate-templates.sh structure >/dev/null 2>&1; then
        log_pass "validate-templates.sh structure: Works"
    else
        log_fail "validate-templates.sh structure: Failed"
    fi

    # Test manifest validation
    if bash scripts/validate-templates.sh manifests >/dev/null 2>&1; then
        log_pass "validate-templates.sh manifests: Works"
    else
        log_fail "validate-templates.sh manifests: Failed"
    fi

    # Test README validation
    if bash scripts/validate-templates.sh readme >/dev/null 2>&1; then
        log_pass "validate-templates.sh readme: Works"
    else
        log_fail "validate-templates.sh readme: Failed"
    fi

    # Test compliance validation
    if bash scripts/validate-templates.sh compliance >/dev/null 2>&1; then
        log_pass "validate-templates.sh compliance: Works"
    else
        log_fail "validate-templates.sh compliance: Failed"
    fi

    # Test secrets validation (may have warnings, but should not fail)
    if bash scripts/validate-templates.sh secrets >/dev/null 2>&1; then
        log_pass "validate-templates.sh secrets: Works"
    else
        log_fail "validate-templates.sh secrets: Failed"
    fi
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
        "scripts/validate-templates.sh"
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

# Main execution
echo "🔍 Script Validation Test Suite"
echo "================================"
echo ""

test_syntax
echo ""
test_template_validation
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
