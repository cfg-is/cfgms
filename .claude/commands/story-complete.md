---
name: story-complete
description: Complete story with adversarial team review (QA + Security + Developer agents), mandatory validation gates, and PR creation
parameters:
  - name: story_number
    description: Story number to complete (optional - auto-detects from branch)
    required: false
---

# Story Complete Command

Final validation gate before PR creation. This command orchestrates an **adversarial team review** where QA and Security agents independently review the code, and a Developer agent fixes any issues found. This prevents the shortcuts (mocks, skipped tests, hacky fixes) that a single agent would make.

## Execution Flow

### 1. Story Context (invoke story-context skill)

Auto-detect story from branch and fetch issue details. Verify all acceptance criteria are complete (100%). If < 100%, warn and confirm with user before proceeding.

### 2. Complete Test Validation (BLOCKING)

```bash
make test-complete
```

This is the comprehensive CI-parity gate:
- Unit tests with race detection
- Code linting and quality checks
- License header validation
- Secret scanning (gitleaks + trufflehog)
- Architecture compliance checking
- Security scanning (Trivy, Nancy, gosec, staticcheck)
- E2E tests (MQTT+QUIC + Docker deployment)

**BLOCKS** completion if ANY validation fails. Do NOT proceed to team review.

If validation fails, spawn the **developer** agent (via Task tool, `subagent_type: developer`) with the specific failures to fix them. After fixes, re-run `make test-complete`. Iterate until passing.

### 3. Adversarial Team Review (BLOCKING)

Spawn QA and Security review agents **in parallel** via the Task tool:

**QA Engineer** (`subagent_type: qa-engineer`):
- Reviews all changed files for test quality issues
- Catches mocks, t.Skip(), empty assertions, hacky workarounds
- Reports blocking issues with file:line references

**Security Engineer** (`subagent_type: security-engineer`):
- Reviews all changed files for security vulnerabilities
- Runs make security-precommit, check-architecture, security-scan
- Catches hardcoded secrets, injection risks, central provider violations
- Reports blocking issues with file:line references

**Wait for both agents to complete.** Collect their findings.

### 4. Fix Issues (if any found)

If QA or Security reported blocking issues, spawn the **developer** agent (`subagent_type: developer`) with the combined findings. The developer agent:
- Reads QA and Security reports
- Fixes root causes properly (NO mocks, NO skips, NO hacks)
- Stages fixes

After developer fixes, **re-run step 3** (QA + Security review of the updated code). Iterate until both report PASS. Maximum 3 iterations — if issues persist after 3 rounds, report to user for manual intervention.

### 5. Documentation Review (invoke doc-review skill)

Scan for internal tracking documents that must be removed before PR. Blocks if found.

### 6. Roadmap Update

Update `docs/product/roadmap.md` on the story branch:
```markdown
# Before:
- [ ] **Story Name** (Issue #NNN) - X points

# After:
- [x] **Story Name** (Issue #NNN) - X points
```

Commit roadmap changes to the story branch so they're included in the single PR.

### 7. Push to Remote

```bash
git push -u origin $(git branch --show-current)
```

Verify push succeeds before creating PR.

### 8. PR Creation (git-workflow skill provides rules)

**Git workflow rules**: Feature/tooling branches ALWAYS target `develop`. Never `main`.

Check for existing PR on this branch:
```bash
gh pr list --head $(git branch --show-current) --state=open
```

- **If existing PR found**: Update it with `gh pr edit [number] --body "[template]" --base develop`
- **If no existing PR**: Create with `gh pr create --base develop --title "..." --body "..."`

**PR template includes**:
- Summary (auto-generated from story title and changes)
- Changes made (extracted from commit history)
- Story progress (all acceptance criteria checked)
- Test results (from make test-complete)
- QA review summary (from QA agent)
- Security review summary (from Security agent)
- `Co-Authored-By: Claude <noreply@anthropic.com>`

### 9. GitHub Project Update (optional)

Move issue to "Done" on project board if accessible.

## Error Handling

- **Validation fails**: Block, report failures. Spawn developer agent to fix. Re-validate.
- **Team review finds issues**: Block, spawn developer agent. Re-review. Max 3 iterations.
- **Doc review fails**: Block, report problematic files. User must remove/transform them.
- **Push fails**: Block PR creation. Report error.
- **PR creation fails**: Report error with manual alternative URL.
