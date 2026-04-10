# Agent Dispatch Developer Reference

Developer reference for the CFGMS agent dispatch system — containerized headless Claude agents that implement GitHub issues and produce reviewed PRs.

## Quick Start

```bash
# 1. One-time setup (builds container image, configures credentials)
/agent-setup

# 2. Write a well-scoped issue (see story writing guidelines below)
gh issue create --title "feat: add X" --label "agent:ready"

# 3. Dispatch one or more agents
/dispatch 123 124 125

# 4. Monitor progress (agents typically complete in 15-45 min)
/isoagents

# 5. Review and merge
/pr-review 456
gh pr merge 456 --squash
```

## Architecture

```
Developer (architect)
│
├── /dispatch <issue#>          deterministic, no LLM
│     ├── scripts/agent-dispatch.sh create-clone <N>
│     │     └── git worktree add -b feature/story-N-agent ../worktrees/story-N develop
│     └── scripts/agent-dispatch.sh launch <N>
│           └── docker run --detach cfg-agent:latest
│                 ├── Mounts: worktree (rw), claude-creds (ro), gh-creds (ro)
│                 ├── Firewall: GitHub + Anthropic API + Go proxy only
│                 ├── entrypoint: gh issue view N → agent prompt
│                 ├── claude --dangerously-skip-permissions
│                 │     Phase 1: Implement (TDD, follow CLAUDE.md patterns)
│                 │     Phase 2: make test-agent-complete
│                 │     Phase 3: self-review (QA + security checks, max 3 rounds)
│                 │     Phase 4: commit + push + gh pr create --base develop
│                 │     On failure: draft PR with diagnostics, exit non-zero
│                 └── Resource limits: 8GB RAM, 4 CPUs, 1h timeout
│
├── /isoagents                  monitor containers, view logs
│
└── Developer reviews PR        /pr-review or GitHub mobile → merge
```

## Workflow Mapping: Interactive → Headless

| Interactive (human present)            | Headless (agent container)                    |
|----------------------------------------|-----------------------------------------------|
| `/story-start` pre-flight              | Worktree created from known-good `develop`    |
| `/story-start` branch creation         | `git worktree add -b feature/story-N develop` |
| Developer implements                   | Claude implements autonomously                |
| `/story-commit` validation             | Agent runs `make test-commit`                 |
| `/story-complete` QA + security review | Agent runs `make test-agent-complete`         |
| `/story-complete` fix loop             | Agent fixes issues, re-validates (max 3×)     |
| `/story-complete` push + PR            | Agent pushes, `gh pr create --base develop`   |
| Docker/E2E tests                       | CI required checks on PR                      |
| Roadmap updates                        | Human only (architect concern)                |
| PR review + merge                      | `/pr-review` or phone → human merges          |

## Credential Management

### Refresh Claude OAuth Token

Claude credentials expire periodically. If `/dispatch` reports `CREDS_EXPIRED`:

```bash
# Run in a real terminal (requires TTY — not in Claude session)
./scripts/refresh-agent-creds.sh
```

Then verify: `/agent-setup creds`

### Rotate GitHub PAT

```bash
# Generate new token at: github.com → Settings → Developer settings → Personal access tokens
# Required scopes: repo, workflow, read:org

# Re-run agent setup to update stored credentials
/agent-setup creds
```

### Check Credential Status

```bash
./scripts/agent-dispatch.sh check-creds
# CREDS_OK:<minutes>     — valid, minutes until expiry
# CREDS_LOW:<minutes>    — valid but expiring soon, refresh recommended
# CREDS_EXPIRED:<N>      — run ./scripts/refresh-agent-creds.sh
# CREDS_MISSING:*        — run /agent-setup
```

## Writing Good Agent Stories

Agents cannot ask clarifying questions. Everything they need must be in the issue.

### Checklist

- [ ] **Self-contained**: all context in the issue body, no "see our discussion in Slack"
- [ ] **Reference files explicitly**: "follow the pattern in `pkg/storage/providers/git/`" not "follow existing patterns"
- [ ] **Testable acceptance criteria**: `- [ ]` checkboxes that can be mechanically verified
- [ ] **Single concern**: one focused change, not "refactor X and also add Y"
- [ ] **No vague verbs**: "add", "implement", "fix" — not "improve", "enhance", "clean up"

### Examples

**Good** — agent can succeed:
```
Add `RetryConfig` field to `pkg/config/types.go` following the pattern in
`pkg/config/timeout_config.go`. Add validation in `pkg/config/validate.go`
following `validateTimeoutConfig`. Tests in `pkg/config/config_test.go`.

Acceptance criteria:
- [ ] RetryConfig struct has MaxAttempts (int), BackoffMs (int), fields
- [ ] Validation rejects MaxAttempts < 1 or > 100
- [ ] `make test-commit` passes
```

**Bad** — agent will guess wrong:
```
Improve the retry handling in the config system. Make it more robust and
follow best practices. Should be well-tested.
```

## Story Sizing Guidelines

| Category | Characteristics | Action |
|----------|-----------------|--------|
| **Agent-ready** | ≤5 files, ≤300 lines, single concern, has reference impl | Dispatch directly |
| **Likely agent-ready** | New feature following established pattern, clear spec, no ref impl | Write detailed task description |
| **Needs human** | Cross-cutting architectural change, establishes new pattern, >5 files | Interactive session |
| **Not agent-ready** | Vague requirements, needs clarification, touches CI/CD or `.github/` | Clarify first, then re-evaluate |

**When no reference implementation exists**: write the task description as if explaining to a new team member on their first week — specify the exact files, function signatures, and error handling expectations.

## CI Failure Recovery

When an agent creates a PR but CI fails, three options:

### Option 1: Fix interactively (preferred for small CI failures)

```bash
/pr-review 456          # review the PR, identify failures
# make manual edits to the agent's branch
git push origin feature/story-N-agent
```

### Option 2: Re-dispatch (preferred when issue needs richer context)

```bash
gh pr close 456         # close the failed PR
# Update the issue with the CI failure output and what to fix
gh issue edit 123 --body "$(gh issue view 123 --json body -q .body)\n\n## CI Failure\n..."
/dispatch 123           # re-dispatch with updated context
```

### Option 3: Fix in interactive session on agent branch

```bash
git fetch origin
git checkout feature/story-N-agent
# fix the issue
make test-commit
git push origin feature/story-N-agent
```

## Troubleshooting

### Agent container exits immediately

**Cause**: OAuth token expired or credentials missing.
**Fix**: Run `/agent-setup creds` to refresh credentials, then re-dispatch.

### "Image not found" on dispatch

**Cause**: First run, or image was deleted.
**Fix**: `/agent-setup` — builds the container image (3-5 min).

### Agent creates draft PR with test failures

**Cause**: Story scope too large, or ambiguous requirements.
**Fix**: Read the draft PR description for the specific failure. Either fix interactively (Option 1 above) or update the issue and re-dispatch (Option 2).

### Agent creates PR that touches unrelated files

**Cause**: Story wasn't scoped to specific files.
**Fix**: Close PR, update issue to specify exact files in scope, re-dispatch.

### `/isoagents` shows container "Exited (1)" with no PR

**Cause**: Agent hit max fix iterations and created a draft PR, OR dispatch itself failed.
**Fix**: `docker logs cfg-agent-story-N` — look for the draft PR URL or the failure reason.

### Credential check passes but agent still fails auth mid-run

**Cause**: Token valid at dispatch time but expired during the ~45 min run.
**Fix**: Refresh credentials before dispatching long-running stories. Credentials with <60 min remaining trigger a `CREDS_LOW` warning.

## Relationship to Interactive Workflow

Agent dispatch and interactive slash commands coexist — they're complementary, not alternatives:

- **Agent dispatch**: well-scoped stories with clear acceptance criteria, while you do other work
- **Interactive session**: architecture decisions, new patterns, stories that need iteration, reviewing agent PRs

The same `CLAUDE.md` conventions, validation gates, and PR standards apply to both. Agent PRs go through the same CI pipeline and require the same human PR review before merging.

Run multiple agents in parallel while working interactively on a different story. The only constraint: don't dispatch an issue that depends on an in-progress agent's work — wait for the PR and merge first.

## Max Plan Usage Tips

- Dispatch during off-hours — agents run ~15-45 min per story
- Batch independent stories: `/dispatch 123 124 125` launches three containers in parallel
- Stories with reference implementations use fewer tokens (agent spends less time exploring)
- If an agent is stuck at 45+ min, check `/isoagents` — it may have already finished
