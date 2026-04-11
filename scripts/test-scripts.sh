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
