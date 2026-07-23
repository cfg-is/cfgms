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
TESTS_SKIPPED=0
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
    [[ -n "$haystack" ]] || { _fail "$msg — haystack is empty"; return; }
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

# ---------------------------------------------------------------------------
# Live integration test helpers (skip-safe; require gh credentials)
# ---------------------------------------------------------------------------

log_test() {
    echo ""
    echo "--- $1 ---"
}

log_skip() {
    echo "    ~ SKIP: $1"
    TESTS_RUN=$((TESTS_RUN + 1))
    TESTS_SKIPPED=$((TESTS_SKIPPED + 1))
}

# ===========================================================================
# STRUCTURAL TEST 1: compose_issue_prompt has no ac_render_issue_comments call
# ===========================================================================
test_structural_compose_issue_prompt() {
    echo ""
    echo "--- Structural: compose_issue_prompt body has no ac_render_issue_comments ---"

    local body count
    body=$(awk '/^compose_issue_prompt/,/^}/' "$ENTRYPOINT")
    if [[ -z "$body" ]]; then
        _fail "compose_issue_prompt structural: awk range matched nothing — function may have been renamed or reformatted"
        return
    fi
    count=$(printf '%s' "$body" | grep -c "ac_render_issue_comments" 2>/dev/null || true)
    assert_eq "$count" "0" \
        "compose_issue_prompt body: zero ac_render_issue_comments calls (AC 2 structural)"
}

# ===========================================================================
# STRUCTURAL TEST 2: compose_branch_prompt has no ac_render_issue_comments call
# ===========================================================================
test_structural_compose_branch_prompt() {
    echo ""
    echo "--- Structural: compose_branch_prompt body has no ac_render_issue_comments ---"

    local body count
    body=$(awk '/^compose_branch_prompt/,/^}/' "$ENTRYPOINT")
    if [[ -z "$body" ]]; then
        _fail "compose_branch_prompt structural: awk range matched nothing — function may have been renamed or reformatted"
        return
    fi
    count=$(printf '%s' "$body" | grep -c "ac_render_issue_comments" 2>/dev/null || true)
    assert_eq "$count" "0" \
        "compose_branch_prompt body: zero ac_render_issue_comments calls (AC 2 structural)"
}

# ===========================================================================
# REGRESSION TEST (AC2): structural check must fail when compose_issue_prompt is
# renamed while its body still calls ac_render_issue_comments.
#
# Old code: awk range never opened → count=0 → vacuous pass (the defect).
# Fixed code: empty awk range → _fail (the desired behavior).
# ===========================================================================
test_structural_renamed_function_regression() {
    echo ""
    echo "--- Regression: structural check fails when compose_issue_prompt is renamed (AC2) ---"

    local fixture
    fixture=$(mktemp)
    trap 'rm -f "$fixture"' RETURN

    # Fixture: function renamed so /^compose_issue_prompt/,/^}/ never opens,
    # but body still calls ac_render_issue_comments — rename-disarms-guard defect.
    cat > "$fixture" <<'FIXTURE'
#!/usr/bin/env bash
assemble_issue_prompt() {
    local issue_num="$1"
    ac_render_issue_comments "$issue_num"
    echo "prompt content"
}
FIXTURE

    local subshell_out subshell_rc=0
    subshell_out=$(
        _pass() { printf 'VERDICT:PASS:%s\n' "$1"; }
        _fail() { printf 'VERDICT:FAIL:%s\n' "$1"; }

        body=$(awk '/^compose_issue_prompt/,/^}/' "$fixture")
        if [[ -z "$body" ]]; then
            _fail "compose_issue_prompt structural: awk range matched nothing — function may have been renamed or reformatted"
        else
            count=$(printf '%s' "$body" | grep -c "ac_render_issue_comments" 2>/dev/null || true)
            if [[ "$count" == "0" ]]; then
                _pass "compose_issue_prompt body: zero ac_render_issue_comments calls"
            else
                _fail "compose_issue_prompt body: found $count ac_render_issue_comments calls"
            fi
        fi
    ) || subshell_rc=$?

    if printf '%s' "$subshell_out" | grep -q "^VERDICT:FAIL:"; then
        _pass "regression AC2: structural check fails when compose_issue_prompt is renamed — guard prevents vacuous pass"
    else
        _fail "regression AC2: structural check should FAIL when compose_issue_prompt is renamed, got: $subshell_out"
    fi

    if printf '%s' "$subshell_out" | grep -q "^VERDICT:PASS:"; then
        _fail "regression AC2: spurious PASS emitted when compose_issue_prompt is renamed — guard was bypassed"
    else
        _pass "regression AC2: no spurious PASS when compose_issue_prompt is renamed"
    fi
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
# INTEGRATION TEST: project_queue_integration — connectivity guard
# Verifies gh credentials and project-queue.sh are reachable before the live
# Phase 2 lifecycle test runs. Establishes the skip guard pattern used below.
# ===========================================================================
test_project_queue_integration() {
    log_test "Integration: project-queue.sh basic connectivity"

    if ! gh auth status >/dev/null 2>&1; then
        log_skip "gh auth status failed — skipping live project queue tests (requires GitHub credentials)"
        return 0
    fi

    local pq_script="$REPO_ROOT/scripts/project-queue.sh"
    if [[ ! -f "$pq_script" ]]; then
        _fail "integration: scripts/project-queue.sh not found"
        return
    fi
    _pass "integration: scripts/project-queue.sh exists and gh credentials are valid"
}

# ===========================================================================
# Helper: privacy boundary check for phase 2 step i.
#
# Calls _pass or _fail based on whether `gh issue list` can be queried and
# whether it finds any matching issues. Keeping this as a named function
# makes it testable in isolation (see test_phase2_step_i_fail_open_regression).
# ===========================================================================
_check_phase2_privacy_boundary() {
    local search_title="$1"
    local issues_out issues_rc=0 issues_count=""
    issues_out=$(gh issue list --repo cfg-is/cfgms --search "$search_title" --state all 2>/dev/null) || issues_rc=$?
    if [[ $issues_rc -ne 0 ]]; then
        _fail "phase2 step i: could not verify privacy boundary — gh issue list failed (rc=${issues_rc})"
        return
    fi
    issues_count=$(printf '%s' "$issues_out" | grep -c "$search_title" 2>/dev/null || true)
    # Numeric guard: [[ "" -eq 0 ]] is true in bash; reject non-numeric counts explicitly
    if ! [[ "$issues_count" =~ ^[0-9]+$ ]]; then
        _fail "phase2 step i: could not verify privacy boundary — non-numeric issues_count: '${issues_count}'"
        return
    fi
    if [[ "$issues_count" -eq 0 ]]; then
        _pass "phase2 step i: privacy boundary — no GitHub issue created for draft item"
    else
        _fail "phase2 step i: privacy boundary violated — found GitHub issue matching ${search_title}"
    fi
}

# ===========================================================================
# INTEGRATION TEST: Phase 2 full no-issue project item lifecycle E2E smoke
#
# Agent-container launch is NOT tested here. Docker runtime is unavailable
# in CI and in this harness. Manual verification steps:
#   1. Run po-act.sh dispatch <ITEM_ID> for a Ready item with issue_num == null.
#   2. Verify the container starts, the prompt shows the item body, and the
#      branch name is feature/item-<LAST12>-agent.
#   3. After the agent creates a PR, run project-queue.sh get-item <item_id>
#      and verify .fields.PR == <pr_num>.
#
# Skipped if `gh auth status` fails, matching the guard in
# test_project_queue_integration.
# ===========================================================================
test_phase2_lifecycle() {
    log_test "Integration: Phase 2 full no-issue project item lifecycle (E2E smoke)"

    if ! gh auth status >/dev/null 2>&1; then
        log_skip "gh auth status failed — skipping Phase 2 lifecycle test (requires GitHub credentials)"
        return 0
    fi

    local pq_script="$REPO_ROOT/scripts/project-queue.sh"
    local item_id="" body_file timestamp title attempt
    body_file=$(mktemp)
    timestamp=$(date +%s)
    title="phase2-lifecycle-smoke-${timestamp}"
    printf 'Phase 2 lifecycle smoke test body — %s\n' "$title" > "$body_file"

    # Cleanup: fires on RETURN regardless of pass/fail.
    # A failed delete-item is reported loudly so the leaked item_id can be
    # removed by hand — a silent || true here would leave fixtures on the live
    # board with no signal, which has caused real false-positive pipeline picks.
    trap '
        [[ -n "${body_file:-}" ]] && rm -f "$body_file" 2>/dev/null || true
        if [[ -n "${item_id:-}" ]]; then
            if ! bash "${pq_script}" delete-item "${item_id}" >/dev/null 2>&1; then
                echo "WARNING: fixture item ${item_id} could not be deleted from project board — remove it manually" >&2
                _fail "phase2 cleanup: delete-item ${item_id} failed — fixture may be leaking on live board"
            fi
        fi
    ' RETURN

    # --- Step a: create-draft -----------------------------------------------
    local create_out create_rc=0
    create_out=$(bash "$pq_script" create-draft 0 "$title" "$body_file" 2>&1) || create_rc=$?
    if [[ $create_rc -ne 0 ]]; then
        _fail "phase2 step a: create-draft failed (rc=$create_rc)"
        return
    fi
    item_id=$(printf '%s' "$create_out" | python3 -c \
        'import json,sys; d=json.load(sys.stdin); print(d.get("item_id",""))' 2>/dev/null || true)
    if [[ -z "$item_id" ]]; then
        _fail "phase2 step a: create-draft output missing item_id key"
        return
    fi
    _pass "phase2 step a: create-draft returned non-empty item_id"

    # --- Step b: list-by-status Draft, item_id present with issue_num=null --
    local found_in_draft=false
    for attempt in 1 2 3 4 5; do
        local list_draft_out list_draft_rc=0
        list_draft_out=$(bash "$pq_script" list-by-status Draft 2>&1) || list_draft_rc=$?
        if [[ $list_draft_rc -eq 0 ]] && printf '%s' "$list_draft_out" | ITEM_ID="$item_id" python3 -c '
import json,sys,os
items=json.load(sys.stdin)
t=os.environ["ITEM_ID"]
for it in items:
    if it.get("item_id")==t and it.get("issue_num") is None:
        sys.exit(0)
sys.exit(1)
' 2>/dev/null; then
            found_in_draft=true; break
        fi
        sleep 1
    done
    if $found_in_draft; then
        _pass "phase2 step b: item in Draft list with issue_num=null"
    else
        _fail "phase2 step b: item not found in Draft list with issue_num=null after 5 retries"
        return
    fi

    # --- Step c: update-field status Ready ----------------------------------
    local step_rc=0
    bash "$pq_script" update-field "$item_id" status Ready >/dev/null 2>&1 || step_rc=$?
    if [[ $step_rc -eq 0 ]]; then
        _pass "phase2 step c: update-field status Ready exited 0"
    else
        _fail "phase2 step c: update-field status Ready exited $step_rc"
        return
    fi

    # --- Step d: list-by-status Ready, item_id present ----------------------
    local found_ready=false
    for attempt in 1 2 3 4 5; do
        local list_ready_out list_ready_rc=0
        list_ready_out=$(bash "$pq_script" list-by-status Ready 2>&1) || list_ready_rc=$?
        if [[ $list_ready_rc -eq 0 ]] && printf '%s' "$list_ready_out" | ITEM_ID="$item_id" python3 -c '
import json,sys,os
items=json.load(sys.stdin)
t=os.environ["ITEM_ID"]
sys.exit(0 if any(it.get("item_id")==t for it in items) else 1)
' 2>/dev/null; then
            found_ready=true; break
        fi
        sleep 1
    done
    if $found_ready; then
        _pass "phase2 step d: item appears in Ready list"
    else
        _fail "phase2 step d: item not found in Ready list after 5 retries"
        return
    fi

    # --- Step e: set-pr with synthetic PR number 99999 ----------------------
    step_rc=0
    bash "$pq_script" set-pr "$item_id" "99999" >/dev/null 2>&1 || step_rc=$?
    if [[ $step_rc -eq 0 ]]; then
        _pass "phase2 step e: set-pr exited 0"
    else
        _fail "phase2 step e: set-pr exited $step_rc"
        return
    fi

    # --- Step f: get-item, assert .fields.PR == "99999" ---------------------
    local get_out get_rc=0 pr_val
    get_out=$(bash "$pq_script" get-item "$item_id" 2>&1) || get_rc=$?
    if [[ $get_rc -ne 0 ]]; then
        _fail "phase2 step f: get-item exited $get_rc"
        return
    fi
    pr_val=$(printf '%s' "$get_out" | python3 -c \
        'import json,sys; d=json.load(sys.stdin); print(d.get("fields",{}).get("PR",""))' 2>/dev/null || true)
    if [[ "$pr_val" == "99999" ]]; then
        _pass "phase2 step f: get-item .fields.PR == \"99999\""
    else
        _fail "phase2 step f: get-item .fields.PR expected \"99999\", got \"${pr_val}\""
        return
    fi

    # --- Step g: update-field status Done -----------------------------------
    step_rc=0
    bash "$pq_script" update-field "$item_id" status Done >/dev/null 2>&1 || step_rc=$?
    if [[ $step_rc -eq 0 ]]; then
        _pass "phase2 step g: update-field status Done exited 0"
    else
        _fail "phase2 step g: update-field status Done exited $step_rc"
        return
    fi

    # --- Step h: list-by-status Done, item_id present -----------------------
    local found_done=false
    for attempt in 1 2 3 4 5; do
        local list_done_out list_done_rc=0
        list_done_out=$(bash "$pq_script" list-by-status Done 2>&1) || list_done_rc=$?
        if [[ $list_done_rc -eq 0 ]] && printf '%s' "$list_done_out" | ITEM_ID="$item_id" python3 -c '
import json,sys,os
items=json.load(sys.stdin)
t=os.environ["ITEM_ID"]
sys.exit(0 if any(it.get("item_id")==t for it in items) else 1)
' 2>/dev/null; then
            found_done=true; break
        fi
        sleep 1
    done
    if $found_done; then
        _pass "phase2 step h: item appears in Done list"
    else
        _fail "phase2 step h: item not found in Done list after 5 retries"
        return
    fi

    # --- Step i: privacy boundary — no GitHub issue created -----------------
    _check_phase2_privacy_boundary "phase2-lifecycle-smoke"
}

# ===========================================================================
# REGRESSION TEST: phase2 step i fails open — failing gh must yield FAIL
#
# This test is the regression guard for Issue #2867. It proves that when the
# `gh issue list` query itself fails (e.g. rate limit, network error, revoked
# token), the privacy boundary check reports a FAIL rather than a spurious PASS.
#
# The defect: 2>&1 folded stderr into issues_out, and || true discarded the
# exit status, so a failing gh with no stdout would produce issues_count=0 and
# _pass the check — a false green on a security gate.
# ===========================================================================
test_phase2_step_i_fail_open_regression() {
    log_test "Regression: phase2 step i — failing gh query yields FAIL, not PASS (Issue #2867)"

    local stub_dir
    stub_dir=$(mktemp -d)
    trap 'rm -rf "$stub_dir"' RETURN

    # Stub gh that exits non-zero and writes only to stderr (no stdout).
    # Models API rate limit / network failure / revoked token scenarios.
    cat > "$stub_dir/gh" <<'GHSTUB'
#!/usr/bin/env bash
echo "gh: error: HTTP 401: Unauthorized (Bad credentials)" >&2
exit 1
GHSTUB
    chmod +x "$stub_dir/gh"

    # Run the privacy boundary helper in a subshell so it cannot mutate the
    # outer FAILURES/TESTS_RUN globals. Redefine _pass/_fail to emit tagged
    # lines that the outer test can inspect.
    local subshell_out subshell_rc=0
    subshell_out=$(
        _pass() { printf 'VERDICT:PASS:%s\n' "$1"; }
        _fail() { printf 'VERDICT:FAIL:%s\n' "$1"; }
        PATH="$stub_dir:$PATH" _check_phase2_privacy_boundary "phase2-lifecycle-smoke-regression-stub"
    ) || subshell_rc=$?

    if [[ $subshell_rc -ne 0 ]]; then
        _fail "regression: step i subshell exited non-zero ($subshell_rc) — output: $subshell_out"
        return
    fi

    if printf '%s' "$subshell_out" | grep -q "^VERDICT:FAIL:"; then
        _pass "regression: failing gh query yields FAIL verdict (not PASS) — defect from issue #2867 fixed"
    else
        _fail "regression: failing gh query should have produced FAIL verdict but got: $subshell_out"
    fi

    if printf '%s' "$subshell_out" | grep -q "^VERDICT:PASS:"; then
        _fail "regression: spurious PASS emitted when gh query failed — defect from issue #2867 still present"
    else
        _pass "regression: no spurious PASS on failing gh query"
    fi
}

# ===========================================================================
# REGRESSION TEST (AC7): log_skip must not count as passed; an all-skipped run
# must not print "All trust boundary tests passed".
# ===========================================================================
test_skip_tracking_and_verdict_regression() {
    log_test "Regression: skip counter tracking and unauthenticated-run verdict (AC7)"

    # Part 1: log_skip must increment TESTS_SKIPPED, not TESTS_PASSED
    local counter_out
    counter_out=$(
        TESTS_RUN=0
        TESTS_PASSED=0
        TESTS_SKIPPED=0
        FAILURES=()
        log_skip "gh auth status failed — skipping integration test"
        printf 'RUN=%s PASSED=%s SKIPPED=%s\n' "$TESTS_RUN" "$TESTS_PASSED" "$TESTS_SKIPPED"
    )

    if printf '%s' "$counter_out" | grep -q "PASSED=0" && printf '%s' "$counter_out" | grep -q "SKIPPED=1"; then
        _pass "regression AC7: log_skip increments TESTS_SKIPPED only (TESTS_PASSED unchanged)"
    else
        _fail "regression AC7: log_skip counter tracking wrong — got: $counter_out"
    fi

    # Part 2: an all-skipped run must not emit "All trust boundary tests passed"
    local verdict_out
    verdict_out=$(
        TESTS_PASSED=0
        TESTS_SKIPPED=2
        FAILURES=()

        # Replicate the summary verdict logic from the main section below
        if [[ ${#FAILURES[@]} -gt 0 ]]; then
            echo "FAIL_PATH"
        elif [[ $TESTS_SKIPPED -gt 0 ]]; then
            echo "⚠️  $TESTS_SKIPPED trust boundary assertion(s) skipped — requires GitHub credentials (gh auth status)"
        else
            echo "✅ All trust boundary tests passed"
        fi
    )

    if ! printf '%s' "$verdict_out" | grep -q "All trust boundary tests passed"; then
        _pass "regression AC7: all-skipped run does not print 'All trust boundary tests passed'"
    else
        _fail "regression AC7: all-skipped run incorrectly prints 'All trust boundary tests passed'"
    fi

    if printf '%s' "$verdict_out" | grep -q "skipped"; then
        _pass "regression AC7: all-skipped run reports skips distinctly"
    else
        _fail "regression AC7: all-skipped run did not report skips distinctly — got: $verdict_out"
    fi
}

# ===========================================================================
# Helper: build a zero-work-retry driver script.
#
# Extracts _zero_work_retry() from entrypoint.sh (by name-anchored awk range),
# prepends a minimal bash header, and appends the caller-supplied environment
# assignments.  The driver is written to a caller-managed temp file so that the
# caller can chmod+execute it with a PATH-injected stub directory.
#
# Arguments:
#   $1  path to driver file (already created by caller)
#   $2  path to mock project-queue.sh
#   $3  project item id
#   $4  issue number
#   $5  exit code to simulate (default 1)
# ===========================================================================
_build_zw_driver() {
    local driver="$1" mock_pq="$2" item_id="$3" issue_num="$4" exit_code="${5:-1}"

    printf '#!/usr/bin/env bash\nset -euo pipefail\n' > "$driver"

    # Extract the _zero_work_retry function body from entrypoint.sh.
    # The awk range opens on the exact function header line and closes on the
    # first bare "}" at column 0 — the function's closing brace.  This is
    # reliable because bash uses fi/done/esac to close control structures, so
    # the only ^}$ inside a well-formatted function is its own closing brace.
    awk '/^_zero_work_retry\(\) \{$/,/^}$/' "$ENTRYPOINT" >> "$driver"

    # Append environment setup with values from the caller's shell.
    cat >> "$driver" <<DRIVER_ENV
PROJECT_QUEUE="${mock_pq}"
CFGMS_PROJECT_ITEM_ID="${item_id}"
ISSUE_NUM="${issue_num}"
EXIT_CODE="${exit_code}"
_zero_work_retry
DRIVER_ENV

    chmod +x "$driver"
}

# ===========================================================================
# TEST (AC5): zero-work retry reads field count, not comment count.
#
# Setup: get-item returns ZeroWorkRetries=0; gh returns 10 marker comments.
# If the code still counted comments (count=10 ≥ 3), it would set Blocked.
# Correct code reads the field (count=0 < 3) and sets Ready.
# ===========================================================================
test_zw_field_ignores_comments() {
    echo ""
    echo "--- AC5: zero-work retry reads project field, not issue comment count ---"

    local stub_dir status_file driver
    stub_dir=$(mktemp -d)
    status_file="$stub_dir/status.txt"
    driver=$(mktemp)
    trap 'rm -rf "$stub_dir" "$driver" 2>/dev/null || true' RETURN

    # Mock project-queue.sh: get-item returns ZeroWorkRetries=0; captures status.
    cat > "$stub_dir/project-queue.sh" <<PQMOCK
#!/usr/bin/env bash
case "\${1:-}" in
    get-item)
        printf '{"item_id":"TEST1","title":"T","body":"B","status":"In Progress","fields":{"ZeroWorkRetries":"0"}}\n'
        exit 0
        ;;
    update-field)
        if [[ "\${3:-}" == "status" ]]; then
            echo "\${4:-}" > "${status_file}"
        fi
        exit 0
        ;;
esac
exit 0
PQMOCK
    chmod +x "$stub_dir/project-queue.sh"

    # Mock gh: returns 10 marker comments.  If the code still counted these,
    # it would treat zw_count=10 ≥ 3 and set Blocked instead of Ready.
    cat > "$stub_dir/gh" <<'GHSTUB'
#!/usr/bin/env bash
case "$1 $2" in
    "issue comment") exit 0 ;;
    "issue view")
        printf '{"comments":[{"body":"<!-- cfgms-zero-work-retry --> a1"},{"body":"<!-- cfgms-zero-work-retry --> a2"},{"body":"<!-- cfgms-zero-work-retry --> a3"},{"body":"<!-- cfgms-zero-work-retry --> a4"},{"body":"<!-- cfgms-zero-work-retry --> a5"},{"body":"<!-- cfgms-zero-work-retry --> a6"},{"body":"<!-- cfgms-zero-work-retry --> a7"},{"body":"<!-- cfgms-zero-work-retry --> a8"},{"body":"<!-- cfgms-zero-work-retry --> a9"},{"body":"<!-- cfgms-zero-work-retry --> a10"}]}\n'
        exit 0 ;;
    *) exit 0 ;;
esac
GHSTUB
    chmod +x "$stub_dir/gh"

    _build_zw_driver "$driver" "$stub_dir/project-queue.sh" "TEST1" "999" "1"

    PATH="$stub_dir:$PATH" bash "$driver" 2>/dev/null || true

    local status
    status=$(cat "$status_file" 2>/dev/null || echo "NOT_SET")
    assert_eq "$status" "Ready" \
        "AC5: ZeroWorkRetries field=0 with 10 marker comments → status Ready (field count wins, not comment count)"
}

# ===========================================================================
# TEST (AC6): a failed retry-count read must not produce Ready.
#
# Setup: get-item fails (API error); update-field captures status updates.
# Correct code detects the read failure and sets Blocked (conservative).
# ===========================================================================
test_zw_read_failure_blocks() {
    echo ""
    echo "--- AC6: zero-work retry read failure → Blocked (not Ready) ---"

    local stub_dir status_file driver
    stub_dir=$(mktemp -d)
    status_file="$stub_dir/status.txt"
    driver=$(mktemp)
    trap 'rm -rf "$stub_dir" "$driver" 2>/dev/null || true' RETURN

    # Mock project-queue.sh: get-item FAILS; captures status updates.
    cat > "$stub_dir/project-queue.sh" <<PQMOCK
#!/usr/bin/env bash
case "\${1:-}" in
    get-item)
        echo "ERROR: Cannot reach GitHub API" >&2
        exit 1
        ;;
    update-field)
        if [[ "\${3:-}" == "status" ]]; then
            echo "\${4:-}" > "${status_file}"
        fi
        exit 0
        ;;
esac
exit 0
PQMOCK
    chmod +x "$stub_dir/project-queue.sh"

    # Minimal gh stub (comment calls are best-effort; ignored for the decision).
    cat > "$stub_dir/gh" <<'GHSTUB'
#!/usr/bin/env bash
exit 0
GHSTUB
    chmod +x "$stub_dir/gh"

    _build_zw_driver "$driver" "$stub_dir/project-queue.sh" "TEST1" "999" "1"

    PATH="$stub_dir:$PATH" bash "$driver" 2>/dev/null || true

    local status
    status=$(cat "$status_file" 2>/dev/null || echo "NOT_SET")

    if [[ "$status" != "Ready" ]]; then
        _pass "AC6: get-item failure → status NOT set to Ready (read failure is conservative)"
    else
        _fail "AC6: get-item failure must NOT set status to Ready — got Ready"
    fi

    if [[ "$status" == "Blocked" ]]; then
        _pass "AC6: get-item failure → status set to Blocked"
    else
        _fail "AC6: get-item failure should set status to Blocked — got: ${status}"
    fi
}

# ===========================================================================
# STRUCTURAL TEST: _zero_work_retry contains no gh issue view call.
#
# Regression guard: the function must not call `gh issue view` (comment
# fetching) — only `project-queue.sh get-item` for the retry count.
# ===========================================================================
test_structural_zero_work_retry_no_comment_fetch() {
    echo ""
    echo "--- Structural: _zero_work_retry contains no gh issue view call ---"

    local body count
    body=$(awk '/^_zero_work_retry\(\) \{$/,/^}$/' "$ENTRYPOINT")
    if [[ -z "$body" ]]; then
        _fail "_zero_work_retry structural: awk range matched nothing — function may have been renamed"
        return
    fi
    count=$(printf '%s' "$body" | grep -c "gh issue view" 2>/dev/null || true)
    assert_eq "$count" "0" \
        "_zero_work_retry body: zero 'gh issue view' calls (dispatch state must not derive from comments)"
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
test_structural_renamed_function_regression
test_structural_agent_specs
test_behavioral_issue_mode
test_behavioral_branch_mode
test_error_path_project_queue_failure
test_regression_comment_render_absent_from_entrypoint
test_project_queue_integration
test_phase2_lifecycle
test_phase2_step_i_fail_open_regression
test_skip_tracking_and_verdict_regression
test_zw_field_ignores_comments
test_zw_read_failure_blocks
test_structural_zero_work_retry_no_comment_fetch

echo ""
echo "📊 Results: $TESTS_PASSED/$TESTS_RUN passed, $TESTS_SKIPPED skipped"
echo ""

if [[ ${#FAILURES[@]} -gt 0 ]]; then
    echo "❌ ${#FAILURES[@]} test(s) failed:"
    for f in "${FAILURES[@]}"; do
        echo "  - $f"
    done
    exit 1
elif [[ $TESTS_SKIPPED -gt 0 ]]; then
    echo "⚠️  $TESTS_SKIPPED trust boundary assertion(s) skipped — requires GitHub credentials (gh auth status)"
    exit 0
else
    echo "✅ All trust boundary tests passed"
    exit 0
fi
