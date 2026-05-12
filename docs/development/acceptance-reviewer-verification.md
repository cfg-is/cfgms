# Code-Reference Verification (Acceptance Checking)

This document describes the verification model used by two agents to prevent PASS verdicts on work that ships undelivered acceptance criteria:

- **`.claude/agents/acceptance-checker.md`** — runs **pre-PR**, inside the dev agent's container, as part of `/story-complete`'s parallel review team. Reads files from the working tree directly.
- **`.claude/agents/acceptance-reviewer.md`** — runs **post-PR**, in a dedicated review container spawned by the PO autonomous cycle. Reads files from the PR's HEAD ref via `gh api`.

Both agents use the same Phase 2.5 extraction + Phase 3 verification model. The fetch mechanism and the verdict actions differ (the in-container checker reports to a team lead and routes failures to the developer agent; the post-PR reviewer posts a PR comment and enqueues or applies fix labels). The verification semantics — what counts as a FAIL — are identical and documented below.

## The failure mode this prevents

Closed stories #1380, #1381, #1321, #1295 all received `## Acceptance Review — PASS` verdicts and merged, but their named acceptance criteria were not delivered. The pattern:

1. Story acceptance criteria name specific existing code: "replace stub `startApprovalWorkflow` at `features/rbac/jit/access_manager.go:653`".
2. The dev agent adds new helper functions elsewhere in the file but leaves the named function unchanged.
3. New tests for the new functions pass; existing tests still pass; CI is green.
4. The reviewer searches `gh pr diff` for evidence the AC is met. The diff shows +500 lines of new code containing the relevant domain words. The reviewer marks the AC met.
5. The named stub function is still there. The AC is not delivered.

The root cause is **diff blindness**: `gh pr diff` only shows additions and deletions. An unchanged stub is invisible to a diff search. The reviewer needs to verify the post-change state of named code by reading the file directly — from the working tree (pre-PR) or from the PR's head ref (post-PR), but never from the diff alone.

A secondary contributing failure was that the story-complete in-container review team had no AC-alignment reviewer at all. The team's three reviewers (qa-test-runner, qa-code-reviewer, security-engineer) judge the diff against test-quality and security standards but never read the story body. So the failure was a two-layer miss: in-container team didn't catch it, and the post-PR reviewer couldn't either. Adding `acceptance-checker` to the in-container team plus tightening `acceptance-reviewer`'s post-PR check restores defense in depth.

## Verification mechanism

Both agents enforce two anchors:

1. **Phase 2 (extraction)** parses the story body for every concrete reference (file paths, function/symbol names, line numbers, banned-phrase quotes, required test names).
2. **Phase 3 (verification)** reads each named file and mechanically checks each reference. Banned phrases that remain in still-stubbed locations are FAIL.

The fetch mechanism differs:

- **acceptance-checker (in-container, pre-PR)**: reads files directly from the working tree on the agent's clone. No `gh api` calls — the working tree IS the would-be post-change state.
- **acceptance-reviewer (post-PR)**: fetches files from the PR's HEAD ref via `gh api repos/cfg-is/cfgms/contents/<path>?ref=$HEAD_SHA`. The diff alone is not sufficient (unchanged stubs are invisible to a diff).

Both agents report a Code-Reference Verification table listing each check and its outcome. Any FAIL row forces an overall FAIL verdict. The post-PR reviewer renders this as a PR comment; the in-container checker sends it to the team lead, which routes failures to the developer agent for fixing.

## Banned-phrase canonical list

The Phase 4 diff-additions scan and Phase 3 named-file scan both grep for these phrases (case-insensitive):

- `for now`
- `simulate`
- `would implement`
- `tracked internally`
- `placeholder implementation`
- `In a real implementation`
- `In a full implementation`

A match outside of a `// Deferred: tracked in #NNN — <summary>` annotation is a finding. The Deferred annotation is the only escape hatch for legitimately-deferred work, and it must reference an open `pipeline:story` or `pipeline:epic` issue.

## Regression scenarios

The following scenarios describe expected reviewer behavior. They are not executable tests — agent prompts have no integration-test harness — but they are the contract a future change to the reviewer's verification model must preserve.

### Scenario 1 — Unchanged named stub (the #1380 failure mode)

**Setup**

Story body contains:

```
- [ ] Replace the stub `startApprovalWorkflow` at `features/rbac/jit/access_manager.go:653` with real multi-stage progression.
```

PR diff:

```diff
+ func (jam *JITAccessManager) advanceWorkflowStage(...) error {
+     ...
+ }
+ func TestJITAccessManager_MultiStageApproval_AdvancesStages(t *testing.T) {
+     ...
+ }
```

`startApprovalWorkflow` body on PR HEAD:

```go
func (jam *JITAccessManager) startApprovalWorkflow(ctx context.Context, request *JITAccessRequest, workflow *ApprovalWorkflow) error {
    // Implementation would integrate with workflow engine
    // For now, simulate by notifying first stage approvers
    if len(workflow.Approvers) > 0 {
        firstStage := workflow.Approvers[0]
        return jam.sendApprovalNotifications(ctx, request, firstStage.Approvers)
    }
    return nil
}
```

**Expected verdict**: `## Acceptance Review — FAIL`

**Expected verification table** (subset):

| AC # | Reference | Expected | Actual | Pass/Fail |
|------|-----------|----------|--------|-----------|
| 1 | startApprovalWorkflow @ access_manager.go:653 | multi-stage progression body | function body still contains `// For now, simulate by notifying...` | FAIL |
| 1 | grep "for now" access_manager.go | 0 matches in the named function | 1 match @ line 655 | FAIL |
| 1 | grep "simulate" access_manager.go | 0 matches | 1 match @ line 655 | FAIL |
| 1 | grep "would implement" access_manager.go | 0 matches | 1 match @ line 654 | FAIL |

**Why this matters**: under the previous prompt, the +500 lines of new code in the diff caused the reviewer to mark the AC met. Under the new prompt, the FAIL rows force FAIL regardless of how much surrounding code was added.

### Scenario 2 — Unchanged stub with banned phrase (the #1381 failure mode)

**Setup**

Story body contains:

```
- [ ] `activateAccess` persists the grant to `SessionStore` as `SessionTypeJIT`
- [ ] `scheduleDeactivation` no longer spawns a goroutine; the per-grant goroutine pattern is fully removed from the file
- [ ] Verification: grep -nE "For now, the grant is tracked internally|For now, we'll implement a simple goroutine" features/rbac/jit/access_manager.go returns zero matches
```

`scheduleDeactivation` body on PR HEAD:

```go
func (jam *JITAccessManager) scheduleDeactivation(ctx context.Context, grant *JITAccessGrant) {
    // In a real implementation, this would schedule a background job
    // For now, we'll implement a simple goroutine
    go func() { ... }()
}
```

**Expected verdict**: `## Acceptance Review — FAIL`

**Expected verification table** (subset):

| AC # | Reference | Expected | Actual | Pass/Fail |
|------|-----------|----------|--------|-----------|
| 2 | scheduleDeactivation @ access_manager.go:688 | no `go func()` in body | line 691 contains `go func() {` | FAIL |
| 3 | grep "tracked internally" access_manager.go | 0 matches | 1 match @ line 671 | FAIL |
| 3 | grep "In a real implementation" access_manager.go | 0 matches | 1 match @ line 689 | FAIL |

### Scenario 3 — Legitimate PASS

**Setup**

Story body contains:

```
- [ ] Replace the stub `startApprovalWorkflow` at `features/rbac/jit/access_manager.go:653` with real multi-stage progression.
```

`startApprovalWorkflow` body on PR HEAD:

```go
func (jam *JITAccessManager) startApprovalWorkflow(ctx context.Context, request *JITAccessRequest, workflow *ApprovalWorkflow) error {
    state := newWorkflowState(workflow)
    jam.approvalWorkflows[request.ID] = state
    return jam.notifyStageApprovers(ctx, request, workflow.Approvers[0].Approvers)
}
```

No banned phrases anywhere in the file (excluding test files and `// Deferred:` annotations).

**Expected verdict**: `## Acceptance Review — PASS`

**Expected verification table** (subset):

| AC # | Reference | Expected | Actual | Pass/Fail |
|------|-----------|----------|--------|-----------|
| 1 | startApprovalWorkflow @ access_manager.go:653 | multi-stage progression body | function calls newWorkflowState + notifyStageApprovers | PASS |
| 1 | grep "for now" access_manager.go | 0 matches | 0 matches | PASS |
| 1 | grep "simulate" access_manager.go | 0 matches | 0 matches | PASS |

### Scenario 4 — Deferred annotation (escape hatch)

**Setup**

Story body lists "feature X is out of scope; track in a follow-up issue".

PR introduces:

```go
// Deferred: tracked in #1500 — full implementation needs SessionStore integration
// For now, returns the in-memory snapshot only.
return jam.activeGrants, nil
```

Issue #1500 is open and labeled `pipeline:story`.

**Expected verdict**: `## Acceptance Review — PASS` (no findings from the banned-phrase scan)

**Why**: the Deferred annotation immediately above the banned phrase, plus the open tracking issue, satisfies the escape-hatch criteria. The phrase appearing in a Deferred-annotated block is not a finding.

### Scenario 5 — Deferred annotation pointing at a closed issue

**Setup**

Same as Scenario 4, but issue #1500 is closed.

**Expected verdict**: `## Acceptance Review — FAIL` (Medium finding for invalid Deferred reference)

**Why**: Deferred annotations must reference open tracking issues; closed references mask abandoned work as deferred work.

## What this verification does not catch

- **AC ambiguity**: if the story body never names specific code, Phase 2.5 has nothing to extract. The reviewer falls back to conventional AC matching. The Tech Lead pass is responsible for catching ambiguous AC during validation, not the reviewer.
- **Subtle correctness bugs in newly-added code**: the verification model only checks that named code has changed; it doesn't verify that the new code is correct. That's the job of the unit tests, integration tests, and Phase 4 code review.
- **Unrelated regressions outside named files**: the named-file scan is targeted. Broad regressions are caught by CI, not by the verification model.

## When to update this document

Update this document when:

1. The banned-phrase canonical list changes (add new phrases that indicate stubbed work, or retire phrases that have become noisy).
2. A new failure mode emerges where a PASS verdict ships undelivered work — add a Scenario describing the new pattern and the verification rule that catches it.
3. The Phase 2.5/3 extraction or verification logic in `.claude/agents/acceptance-reviewer.md` changes substantively.

This document is the contract for what the verification model must catch. The prompt is the implementation. Keep them aligned.
