#!/usr/bin/env bash
# Trust boundary regression test suite (Issue #1481)
#
# Asserts that CFGMS prompt-assembly paths do not ingest content from public
# issue comments. Covers all 4 agent entry points:
#   1. compose_issue_prompt  (entrypoint.sh issue mode)
#   2. compose_branch_prompt (entrypoint.sh branch mode)
#   3. acceptance-reviewer dispatch (spec must not call comment-fetch functions)
#   4. acceptance-checker dispatch  (spec must not call comment-fetch functions)
#
# Two assertion types:
#   - Structural: awk-scoped grep of function bodies returns 0 ac_render_issue_comments
#                 calls; spec files do not reference comment-fetching functions
#   - Behavioral: entrypoint.sh --dry-run with a mock gh that injects SENTINEL into
#                 issue comment responses; assembled prompt must not contain SENTINEL
#
# The mock gh is the key to making the sentinel check non-trivial: if any code
# path calls `gh issue view --json comments`, the SENTINEL propagates into the
# assembled prompt and the assert_not_contains assertion fails. On the correctly-
# closed trust boundary, gh issue view is never called in issue/branch mode, so
# SENTINEL cannot appear.
#
# Run: bash test/security/trust_boundary_test.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ENTRYPOINT="$REPO_ROOT/.devcontainer/entrypoint.sh"

TESTS_RUN=0
TESTS_PASSED=0
FAILURES=()

# SENTINEL: injected into mock gh's issue-comment response.
# A correctly-closed trust boundary never calls `gh issue view --json comments`
# in issue/branch mode, so the sentinel must be absent from every assembled prompt.
# If ac_render_issue_comments is re-introduced, gh issue view would be called,
# the mock would return this sentinel, and the assert_not_contains check would fail.
SENTINEL="TRUST_BOUNDARY_SENTINEL_NONMEMBER_xK7qp9zR"
ITEM_BODY="TRUSTED_PROJECT_ITEM_BODY_pL4mNq8wX"

# ---------------------------------------------------------------------------
# Assertion helpers
# ---------------------------------------------------------------------------

_pass() {
    echo "    ✓ $1"
    TESTS_RUN=$((TESTS_RUN + 1))
    TESTS_PASSED=$((TESTS_PASSED + 1))
}

_fail() {
    echo "    ✗ FAIL: $1"
    TESTS_RUN=$((TESTS_RUN + 1))
    FAILURES+=("$1")
}

assert_eq() {
    local actual="$1" expected="$2" msg="$3"
    if [[ "$actual" == "$expected" ]]; then
        _pass "$msg"
    else
        _fail "$msg — expected $(printf '%q' "$expected"), got $(printf '%q' "$actual")"
    fi
}

assert_contains() {
    local haystack="$1" needle="$2" msg="$3"
    if [[ "$haystack" == *"$needle"* ]]; then
        _pass "$msg"
    else
        _fail "$msg — expected to contain: $(printf '%q' "$needle")"
        echo "      Prompt head (20 lines):"
        echo "$haystack" | head -20 | sed 's/^/        /'
    fi
}

assert_not_contains() {
    local haystack="$1" needle="$2" msg="$3"
    if [[ "$haystack" != *"$needle"* ]]; then
        _pass "$msg"
    else
        _fail "$msg — expected NOT to contain: $(printf '%q' "$needle")"
    fi
}

# ---------------------------------------------------------------------------
# Stub infrastructure for behavioral tests
# ---------------------------------------------------------------------------

STUB_DIR=""
FAKE_HOME=""
ORIGINAL_PATH="$PATH"

# Global cleanup: fires on any script exit so temp dirs are never leaked even
# if the script exits unexpectedly under set -e.
_global_cleanup() {
    [[ -n "${STUB_DIR:-}" ]] && rm -rf "$STUB_DIR" 2>/dev/null || true
    [[ -n "${FAKE_HOME:-}" ]] && rm -rf "$FAKE_HOME" 2>/dev/null || true
}
trap '_global_cleanup' EXIT

setup_stubs() {
    STUB_DIR=$(mktemp -d)
    FAKE_HOME=$(mktemp -d)
    mkdir -p "$FAKE_HOME/.claude"

    # Fake credentials: far-future expiresAt (~year 2286) skips OAuth token refresh.
    cat > "$FAKE_HOME/.claude/.credentials.json" <<'CREDS'
{"claudeAiOauth":{"expiresAt":9999999999999}}
CREDS

    # setup-env.sh stub: entrypoint.sh calls this from PATH (no path prefix).
    cat > "$STUB_DIR/setup-env.sh" <<'STUB'
#!/usr/bin/env bash
STUB
    chmod +x "$STUB_DIR/setup-env.sh"

    # gh stub: injects SENTINEL into `gh issue view --json` responses so that
    # any code path calling `gh issue view --json comments` propagates the sentinel
    # into the assembled prompt. For `gh pr list` (branch mode PR detection),
    # returns empty string so compose_branch_prompt sees no existing PR.
    # This makes the assert_not_contains sentinel check non-trivial: a regression
    # that re-introduces `gh issue view --json comments` into compose_issue_prompt
    # or compose_branch_prompt would cause SENTINEL to appear in the prompt.
    cat > "$STUB_DIR/gh" <<GHSTUB
#!/usr/bin/env bash
case "\$1 \$2" in
    "issue view")
        printf '{"title":"Test Issue","body":"issue body","labels":[],"comments":[{"author":{"login":"evil-attacker"},"body":"${SENTINEL}","createdAt":"2026-01-01T00:00:00Z"}]}\n'
        exit 0
        ;;
    "pr list")
        echo ""
        exit 0
        ;;
    "repo view")
        printf '{"owner":{"login":"test-owner"},"name":"test-repo"}\n'
        exit 0
        ;;
    *)
        echo "[]"
        exit 0
        ;;
esac
GHSTUB
    chmod +x "$STUB_DIR/gh"

    # project-queue.sh mock: returns controlled item JSON with ITEM_BODY.
    # Does NOT include SENTINEL — correctly models the trust boundary: the private
    # project queue returns only what the issue author wrote.
    cat > "$STUB_DIR/mock-project-queue.sh" <<MOCK
#!/usr/bin/env bash
if [[ "\${1:-}" == "get-item" ]]; then
    printf '{"item_id":"TEST_ITEM_1","title":"Test Story","body":"%s","status":"Ready"}\n' "${ITEM_BODY}"
    exit 0
fi
exit 1
MOCK
    chmod +x "$STUB_DIR/mock-project-queue.sh"

    # failing-project-queue.sh: simulates network/API failure for error path test.
    cat > "$STUB_DIR/failing-project-queue.sh" <<'FAILMOCK'
#!/usr/bin/env bash
if [[ "${1:-}" == "get-item" ]]; then
    echo "ERROR: Cannot reach Projects V2 API" >&2
    exit 1
fi
exit 1
FAILMOCK
    chmod +x "$STUB_DIR/failing-project-queue.sh"
}

teardown_stubs() {
    [[ -n "${STUB_DIR:-}" ]] && rm -rf "$STUB_DIR"
    [[ -n "${FAKE_HOME:-}" ]] && rm -rf "$FAKE_HOME"
    STUB_DIR=""
    FAKE_HOME=""
}

run_entrypoint_dry_run() {
    HOME="$FAKE_HOME" \
    PATH="$STUB_DIR:$ORIGINAL_PATH" \
    CFGMS_TEST_PROJECT_QUEUE="$STUB_DIR/mock-project-queue.sh" \
    CFGMS_PROJECT_ITEM_ID="TEST_ITEM_1" \
    bash "$ENTRYPOINT" "$@" --dry-run 2>&1
}

# ===========================================================================
# STRUCTURAL TEST 1: compose_issue_prompt has no ac_render_issue_comments call
# ===========================================================================
test_structural_compose_issue_prompt() {
    echo ""
    echo "--- Structural: compose_issue_prompt body has no ac_render_issue_comments ---"

    local count
    count=$(awk '/^compose_issue_prompt/,/^}/' "$ENTRYPOINT" \
        | grep -c "ac_render_issue_comments" || true)
    assert_eq "$count" "0" \
        "compose_issue_prompt body: zero ac_render_issue_comments calls (AC 2 structural)"
}

# ===========================================================================
# STRUCTURAL TEST 2: compose_branch_prompt has no ac_render_issue_comments call
# ===========================================================================
test_structural_compose_branch_prompt() {
    echo ""
    echo "--- Structural: compose_branch_prompt body has no ac_render_issue_comments ---"

    local count
    count=$(awk '/^compose_branch_prompt/,/^}/' "$ENTRYPOINT" \
        | grep -c "ac_render_issue_comments" || true)
    assert_eq "$count" "0" \
        "compose_branch_prompt body: zero ac_render_issue_comments calls (AC 2 structural)"
}

# ===========================================================================
# STRUCTURAL TESTS 3-4: agent spec files use project-queue.sh, not comment fetchers
# Covers all 4 agent entry points plus ba/tech-lead which share the same surface.
# ===========================================================================
_check_agent_spec() {
    local spec_path="$1" spec_name="$2"

    if grep -q "project-queue.sh get-item" "$spec_path"; then
        _pass "${spec_name}: references project-queue.sh get-item for body content (AC 2)"
    else
        _fail "${spec_name}: missing project-queue.sh get-item reference"
    fi

    # Spec must not instruct agents to call comment-fetching functions from
    # agent-context.sh — those functions expose public GitHub issue comment content.
    local count
    count=$(grep -cE "ac_fetch_issue_with_comments|ac_render_issue_comments" "$spec_path" 2>/dev/null || true)
    assert_eq "$count" "0" \
        "${spec_name}: no ac_fetch/render_issue_comments calls (AC 2 structural)"
}

test_structural_agent_specs() {
    echo ""
    echo "--- Structural: agent spec files use project-queue.sh, not comment-fetching functions ---"

    _check_agent_spec "$REPO_ROOT/.claude/agents/acceptance-reviewer.md" "acceptance-reviewer.md"
    _check_agent_spec "$REPO_ROOT/.claude/agents/acceptance-checker.md"  "acceptance-checker.md"
    _check_agent_spec "$REPO_ROOT/.claude/agents/ba.md"                  "ba.md"
    _check_agent_spec "$REPO_ROOT/.claude/agents/tech-lead.md"           "tech-lead.md"
}

# ===========================================================================
# BEHAVIORAL TEST 1: compose_issue_prompt
# Mock gh injects SENTINEL into issue comment responses.
# If ac_render_issue_comments were called, SENTINEL would appear in the prompt.
# ===========================================================================
test_behavioral_issue_mode() {
    echo ""
    echo "--- Behavioral: compose_issue_prompt (issue mode --dry-run) ---"

    setup_stubs

    local output exit_code=0
    output=$(run_entrypoint_dry_run --issue 999) || exit_code=$?

    assert_eq "$exit_code" "0" \
        "issue mode: entrypoint.sh --dry-run exits 0"
    assert_contains "$output" "$ITEM_BODY" \
        "issue mode: assembled prompt contains project item body (AC 3)"
    # Non-trivial: mock gh returns SENTINEL for any `gh issue view --json` call.
    # If a regression re-introduces ac_render_issue_comments into compose_issue_prompt,
    # the sentinel propagates here and this assertion fails.
    assert_not_contains "$output" "$SENTINEL" \
        "issue mode: assembled prompt excludes non-member comment sentinel (AC 2 behavioral)"

    teardown_stubs
}

# ===========================================================================
# BEHAVIORAL TEST 2: compose_branch_prompt
# Mock gh injects SENTINEL into issue comment responses.
# If ac_render_issue_comments were called, SENTINEL would appear in the prompt.
# ===========================================================================
test_behavioral_branch_mode() {
    echo ""
    echo "--- Behavioral: compose_branch_prompt (branch mode --dry-run) ---"

    setup_stubs

    local output exit_code=0
    # Branch name encodes story number; entrypoint auto-detects ISSUE_NUM=999
    output=$(run_entrypoint_dry_run --branch "feature/story-999-test") || exit_code=$?

    assert_eq "$exit_code" "0" \
        "branch mode: entrypoint.sh --dry-run exits 0"
    assert_contains "$output" "$ITEM_BODY" \
        "branch mode: assembled prompt contains project item body (AC 3)"
    # Non-trivial: mock gh returns SENTINEL for any `gh issue view --json` call.
    assert_not_contains "$output" "$SENTINEL" \
        "branch mode: assembled prompt excludes non-member comment sentinel (AC 2 behavioral)"

    teardown_stubs
}

# ===========================================================================
# ERROR PATH TEST: project-queue.sh failure exits non-zero, no partial prompt
# ===========================================================================
test_error_path_project_queue_failure() {
    echo ""
    echo "--- Error path: project-queue.sh failure exits non-zero, no partial prompt ---"

    setup_stubs

    local output exit_code=0
    output=$(HOME="$FAKE_HOME" \
        PATH="$STUB_DIR:$ORIGINAL_PATH" \
        CFGMS_TEST_PROJECT_QUEUE="$STUB_DIR/failing-project-queue.sh" \
        CFGMS_PROJECT_ITEM_ID="TEST_ITEM_1" \
        bash "$ENTRYPOINT" --issue 999 --dry-run 2>&1) || exit_code=$?

    if [[ $exit_code -ne 0 ]]; then
        _pass "error path: project-queue.sh failure causes non-zero exit"
    else
        _fail "error path: project-queue.sh failure should exit non-zero, got 0"
    fi

    # No partial prompt should be assembled and printed when fetch fails
    assert_not_contains "$output" "$ITEM_BODY" \
        "error path: no partial prompt output when project-queue.sh fails"

    teardown_stubs
}

# ===========================================================================
# REGRESSION GUARD: ac_render_issue_comments absent from entire entrypoint.sh
# Distinct from structural tests 1 and 2: those scope to specific function bodies
# via awk; this test greps the whole file, catching any new call site outside
# compose_issue_prompt and compose_branch_prompt (e.g., a new helper function).
# ===========================================================================
test_regression_comment_render_absent_from_entrypoint() {
    echo ""
    echo "--- Regression: ac_render_issue_comments absent from entire entrypoint.sh ---"

    local count
    count=$(grep -c "ac_render_issue_comments" "$ENTRYPOINT" || true)
    assert_eq "$count" "0" \
        "regression: ac_render_issue_comments has zero invocations in entrypoint.sh (AC 4)"
}

# ===========================================================================
# Main
# ===========================================================================
echo "🔐 Trust Boundary Regression Test Suite"
echo "========================================="
echo "Repo: $REPO_ROOT"
echo "Entrypoint: $ENTRYPOINT"

test_structural_compose_issue_prompt
test_structural_compose_branch_prompt
test_structural_agent_specs
test_behavioral_issue_mode
test_behavioral_branch_mode
test_error_path_project_queue_failure
test_regression_comment_render_absent_from_entrypoint

echo ""
echo "📊 Results: $TESTS_PASSED/$TESTS_RUN passed"
echo ""

if [[ ${#FAILURES[@]} -eq 0 ]]; then
    echo "✅ All trust boundary tests passed"
    exit 0
else
    echo "❌ ${#FAILURES[@]} test(s) failed:"
    for f in "${FAILURES[@]}"; do
        echo "  - $f"
    done
    exit 1
fi
