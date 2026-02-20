---
name: story-complete
description: Complete story with parallel adversarial team review (QA test runner + QA code reviewer + Security), Developer on-demand, and PR creation
parameters:
  - name: story_number
    description: Story number to complete (optional - auto-detects from branch)
    required: false
---

# Story Complete Command

Final validation gate before PR creation. Orchestrates a **parallel adversarial team review** where test execution, code quality review, and security review run simultaneously. A Developer agent fixes any issues found.

## Execution Flow

### 1. Story Context (invoke story-context skill)

Auto-detect story from branch and fetch issue details. Verify all acceptance criteria are complete (100%). If < 100%, warn and confirm with user before proceeding.

### 2. Create Review Team

```
TeamCreate(team_name: "story-review")
```

Create three tasks on the team task list:
1. **Run test-complete** — Full CI-parity validation suite
2. **QA code review** — Review changed files for test quality
3. **Security review** — Review security + run security scans

### 3. Spawn Review Teammates (ALL IN PARALLEL)

Spawn three teammates simultaneously via the Task tool. For each, use `subagent_type: general-purpose` with the `team_name` and `name` parameters. Read the corresponding agent file in `.claude/agents/` and include its instructions in the prompt.

**qa-test-runner** (sonnet):
- Agent file: `.claude/agents/qa-test-runner.md`
- Runs `make test-complete` — the comprehensive CI-parity gate
- Reports pass/fail with specific test names and error details

**qa-code-reviewer** (sonnet):
- Agent file: `.claude/agents/qa-code-reviewer.md`
- Reviews all changed files for test quality issues
- Catches mocks, t.Skip(), empty assertions, hacky workarounds
- Reports blocking issues with file:line references

**security-engineer** (opus):
- Agent file: `.claude/agents/security-engineer.md`
- Reviews all changed files for security vulnerabilities
- Runs make security-precommit, check-architecture, security-scan
- Reports blocking issues with file:line references

### 4. Collect Results

Wait for all three teammates to complete and send their reports. Collect findings from each.

### 5. Fix Issues (if any blocking issues found)

If ANY teammate reported blocking issues, spawn a **developer** teammate:

- Agent file: `.claude/agents/developer.md`
- Model: opus
- Provide combined findings from all reviewers with file:line references
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
git push -u origin $(git branch --show-current)
```

Verify push succeeds before creating PR.

### 10. PR Creation (git-workflow skill provides rules)

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
- Test results (from qa-test-runner)
- QA code review summary (from qa-code-reviewer)
- Security review summary (from security-engineer)
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
