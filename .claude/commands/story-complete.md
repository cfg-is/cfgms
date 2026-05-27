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

### 2. Create Review Team

```
TeamCreate(team_name: "story-review")
```

Create four tasks on the team task list:
1. **Acceptance check** — Verify the working tree delivers the story's named code references
2. **Run test-quality** — Tests, linting, and builds (no security scans)
3. **QA code review** — Review changed files for test quality
4. **Security review** — All security scans + security code review

### 3. Spawn Review Teammates (ALL IN PARALLEL)

Spawn four teammates simultaneously via the Task tool. For each, use `subagent_type: general-purpose` with the `team_name` and `name` parameters. Read the corresponding agent file in `.claude/agents/` and include its instructions in the prompt.

**acceptance-checker** (sonnet):
- Agent file: `.claude/agents/acceptance-checker.md`
- Reads the story body, extracts concrete code references (file paths, function names, line numbers, banned-phrase quotes, required test names), and verifies each against the working tree
- Catches "AC names a stub function but the stub is still there" before the PR is created
- Reports blocking issues with file:line references and AC numbers
- See `docs/development/acceptance-reviewer-verification.md` for the verification model and regression scenarios

**qa-test-runner** (sonnet):
- Agent file: `.claude/agents/qa-test-runner.md`
- Runs `make test-quality` — unit tests, lint, production-critical, cross-platform builds, Docker integration (no security scans, no E2E)
- Reports pass/fail with specific test names and error details

**qa-code-reviewer** (sonnet):
- Agent file: `.claude/agents/qa-code-reviewer.md`
- Reviews all changed files for test quality issues
- Catches mocks, t.Skip(), empty assertions, hacky workarounds
- Reports blocking issues with file:line references
- Does NOT check AC alignment — that's acceptance-checker's concern

**security-engineer** (opus):
- Agent file: `.claude/agents/security-engineer.md`
- Sole owner of all security scanning and security code review
- Runs make security-precommit, check-architecture, security-scan
- Reviews changed files for vulnerabilities, central provider violations
- Reports blocking issues with file:line references

### 4. Collect Results

Wait for all four teammates to complete and send their reports. Collect findings from each.

### 5. Fix Issues (if any blocking issues found)

If ANY teammate reported blocking issues, spawn a **developer** teammate:

- Agent file: `.claude/agents/developer.md`
- Model: opus
- Provide combined findings from all reviewers with file:line references
- For acceptance-checker FAILs specifically, tell the developer the AC number, the named symbol/file/line, and the AC's "after" behavior — and remind them that adding helper functions elsewhere is NOT a valid fix when the AC names existing code that must change
- Developer fixes root causes properly (NO mocks, NO skips, NO hacks)

After developer completes, re-spawn the reviewers that reported failures to verify fixes. Maximum 3 fix iterations. If issues persist after 3 rounds, shut down team and report to user for manual intervention.

### 6. Shut Down Team

Send shutdown requests to all active teammates. Wait for confirmations. Delete the team:
```
TeamDelete()
```

### 7. Documentation Review (invoke doc-review skill)

Scan for internal tracking documents that must be removed before PR. Blocks if found.

### 8. Roadmap Update

Update `docs/product/roadmap.md` on the story branch:
```markdown
# Before:
- [ ] **Story Name** (Issue #NNN) - X points

# After:
- [x] **Story Name** (Issue #NNN) - X points
```

Commit roadmap changes to the story branch so they're included in the single PR.

### 9. Push to Remote

```bash
git push -u origin HEAD
```

Verify push succeeds before creating PR.

### 10. PR Creation (git-workflow skill provides rules)

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

### 11. GitHub Project Update (optional)

Move issue to "Done" on project board if accessible.

## Error Handling

- **Team creation fails**: Fall back to sequential validation (make test-complete then manual review).
- **Teammate fails**: Report error, suggest re-running `/story-complete`.
- **Fix iterations exhausted (3 rounds)**: Report remaining issues to user for manual intervention.
- **Doc review fails**: Block, report problematic files. User must remove/transform them.
- **Push fails**: Block PR creation. Report error.
- **PR creation fails**: Report error with manual alternative URL.
