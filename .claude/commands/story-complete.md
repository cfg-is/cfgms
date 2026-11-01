---
name: story-complete
description: Complete story with parallel adversarial team review (acceptance checker + QA test runner + QA code reviewer + Security), Developer on-demand, and PR creation
parameters:
  - name: story_number
    description: Story number to complete (optional - auto-detects from branch)
    required: false
---

# Story Complete Command

Final validation gate before PR creation. Orchestrates a **parallel adversarial team review** where AC verification, test execution, code quality review, and security review run simultaneously. A Developer agent fixes any issues found.

## Execution Flow

### 1. Story Context (invoke story-context skill)

Auto-detect story from branch and fetch issue details. Verify all acceptance criteria are complete (100%). If < 100%, warn and confirm with user before proceeding.

### 2. Run the review-fix-verify workflow

The adversarial review, developer fix loop, and re-verification run as a single deterministic workflow — `.claude/workflows/story-review.js`. It fans out the four review lenses in parallel (acceptance check, `make test-quality`, QA code review, security scans + review), collects schema-validated verdicts, spawns a **developer** to fix any blocking findings, and re-runs **only the lenses that failed** — up to 3 fix rounds — then returns a structured verdict.

Invoke it via the Workflow tool:

```
Workflow({
  name: "story-review",
  args: {
    changedFiles: [ ...files from `git diff --name-only origin/develop...HEAD` and `git status` ],
    testTarget: "test-quality",          // interactive gate uses the full Docker-inclusive target
    includeAcceptanceChecker: true,      // 4-lens review (AC verified pre-PR)
    storyRef: "#<issue-number> — <title>"
  }
})
```

The workflow returns `{ passed, reviewRounds, fixRounds, perRound, remainingFindings }`.

- **`passed: true`** → proceed to §3.
- **`passed: false`** (fix loop exhausted after 3 rounds) → do NOT create the PR. Report `remainingFindings` (each has `file`, `severity`, `detail`) to the user for manual intervention.

The developer stage is told to fix root causes only — NO mocks, NO `t.Skip()`, NO hacky workarounds, and NO helper-function-instead-of-the-named-fix when an AC names existing code that must change. The acceptance lens catches "AC names a stub but the stub is still there" before the PR exists (see `docs/development/acceptance-reviewer-verification.md`); the security lens is the sole owner of security scanning + review.

### 3. Documentation Review (invoke doc-review skill)

Scan for internal tracking documents that must be removed before PR. Blocks if found.

### 4. Roadmap Update

Update `docs/product/roadmap.md` on the story branch:
```markdown
# Before:
- [ ] **Story Name** (Issue #NNN) - X points

# After:
- [x] **Story Name** (Issue #NNN) - X points
```

Commit roadmap changes to the story branch so they're included in the single PR.

### 5. Push to Remote

```bash
git push -u origin HEAD
```

Verify push succeeds before creating PR.

### 6. PR Creation (git-workflow skill provides rules)

**Git workflow rules**: Feature/tooling branches ALWAYS target `develop`. Never `main`.

Check for existing PR on this branch. First get the branch name with `git branch --show-current`, then use it:
```bash
git branch --show-current
```
```bash
gh pr list --head <branch-name-from-above> --state=open
```

- **If existing PR found**: Update it with `gh pr edit [number] --body "[template]" --base develop`
- **If no existing PR**: Create with `gh pr create --base develop --title "..." --body "..."`

**PR template includes**:
- Summary (auto-generated from story title and changes)
- Changes made (extracted from commit history)
- Test results (from qa-test-runner)
- QA code review summary (from qa-code-reviewer)
- Security review summary (from security-engineer)
- `Fixes #<issue-number>` on its own line (REQUIRED — develop uses squash merge, so the PR body becomes the merged commit message; without this keyword GitHub will not auto-close the linked issue)
- `Co-Authored-By: Claude <noreply@anthropic.com>`

### 7. GitHub Project Update (optional)

Move issue to "Done" on project board if accessible.

## Error Handling

- **Workflow fails to launch**: Fall back to sequential validation (`make test-complete` then manual review).
- **A reviewer errors mid-workflow**: the workflow treats an errored lens as blocking (fails safe); re-run `/story-complete` after resolving the cause.
- **Fix iterations exhausted (3 rounds, `passed: false`)**: Report `remainingFindings` to the user for manual intervention; do NOT create the PR.
- **Doc review fails**: Block, report problematic files. User must remove/transform them.
- **Push fails**: Block PR creation. Report error.
- **PR creation fails**: Report error with manual alternative URL.
