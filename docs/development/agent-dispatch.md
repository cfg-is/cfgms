# Agent Dispatch Developer Reference

Developer reference for the CFGMS agent dispatch system — headless Claude agents that implement GitHub issues in isolated containers, under a host-side supervisor that validates and publishes their work as PRs.

## Quick Start

```bash
# 1. One-time setup (builds container image, configures credentials)
/agent-setup

# 2. Have a well-scoped story at status Ready on the project board
#    (pipeline stories come from `pipeline-helper.sh create-story` and are
#    promoted by the Tech Lead; see story writing guidelines below)

# 3. Dispatch one or more agents
/dispatch 123 124 125

# 4. Monitor progress
/isoagents

# 5. Review and merge
/pr-review 456
./.claude/tooling/scripts/po-act.sh enqueue 456
```

## Architecture

Dev, fix-pr, resolve-conflict and branch work runs as an **FSM supervisor run**
(`.claude/tooling/scripts/fsm/`; design: `.claude/tooling/scripts/fsm/DESIGN.md`).
The supervisor is a trusted host process that owns every transition and side
effect. Agent containers only edit files in a scratch workspace and hold no
GitHub credential.

```
Developer (architect)
│
├── /dispatch <issue#>           deterministic, no LLM
│     └── .claude/tooling/scripts/po-act.sh dispatch <N>
│           ├── gates: capacity, image staleness, Dependencies, unfinished run
│           ├── lease story-<item>, claim Ready → In Progress
│           └── supervisor.py run issue <N> --lease-handoff --detach   (host)
│                 PREPARE   gates, candidate repo at develop, workspace, context/ (spec from the project item)
│                 AGENT     docker run cfg-agent:latest   (no GH_TOKEN, no gh/git credentials)
│                 │           ├── Firewall: GitHub + Anthropic API + Go proxy only
│                 │           ├── Claude auth via CLAUDE_CODE_OAUTH_TOKEN (token mode) or host ~/.claude/.credentials.json (fallback)
│                 │           └── claude: implement (TDD), own advisory checks/story-review, write /fsm/out/*
│                 SNAPSHOT  workspace → candidate tree; path filters, conflict markers, secret scan
│                 VALIDATE  agent-free validator container: make test-agent-complete on the candidate
│                 SYNC      rebase onto current origin/develop, re-validate
│                 PUBLISH   commit the validated tree, push, open/update the PR (supervisor token)
│                 REPORT    board, follow-ups, manifest, ledger, lease release
│                 (a failed validation loops back to AGENT(fix), up to the fix budget;
│                  FAILED keeps the work as a WIP draft PR)
│
├── /isoagents                   monitor runs and containers, view logs
│
└── Developer reviews PR         /pr-review or GitHub mobile → merge
```

Timeouts (env-overridable): agent session 180 min (`CFGMS_FSM_AGENT_TIMEOUT_MIN`),
validator 75 min (`CFGMS_FSM_VALIDATE_TIMEOUT_MIN`), whole run 480 min
(`CFGMS_FSM_RUN_TIMEOUT_MIN`). Agent and validator containers run with
`--memory=4g --cpus=4`. `po-act.sh dispatch status` lists runs;
`po-act.sh dispatch resume <RUN_ID>` resumes a crashed one.

## Workflow Mapping: Interactive → Headless

| Interactive (human present)            | Headless (FSM run)                                         |
|----------------------------------------|------------------------------------------------------------|
| `/story-start` pre-flight              | po-act gates; supervisor PREPARE gates                     |
| `/story-start` branch creation         | Supervisor publishes `feature/story-N-agent` from develop  |
| Developer implements                   | Agent implements autonomously in a scratch workspace       |
| `/story-commit` validation             | Agent runs its own checks (advisory only)                  |
| `/story-complete` QA + security review | Agent may run story-review (advisory only); supervisor runs `make test-agent-complete` in an agent-free validator — only that counts |
| `/story-complete` fix loop             | Supervisor sends validation failures back to the agent (fix budget 3) |
| `/story-complete` push + PR            | Supervisor commits the validated tree, pushes, opens the PR |
| Docker/E2E tests                       | CI required checks on PR                                   |
| Roadmap updates                        | Human only (architect concern)                             |
| PR review + merge                      | `/pr-review` or phone → human merges                       |

## Credential Management

### Claude OAuth Token

Headless agent containers authenticate with a separate long-lived subscription token (`claude setup-token`) passed as `CLAUDE_CODE_OAUTH_TOKEN`, so they no longer share the host's refreshing OAuth session (a refresh by either side used to invalidate the other). The token is a TPM2-bound `systemd-creds` credential at `~/.config/cfgms/claude-oauth-token.cred`; the launcher decrypts it under a 15 s timeout, hands it to `docker run` through the process environment only (`-e CLAUDE_CODE_OAUTH_TOKEN`, never in argv, never on disk), and does not mount the host credentials file. One-time operator setup and rotation: `/agent-setup` ("Agent token setup").

If the credential is absent, cannot be decrypted, or times out, the launch falls back to bind-mounting the host's live `~/.claude/.credentials.json` and prints one `WARN:agent_token:<absent|decrypt_failed|timeout>` line. In fallback mode a `LOW` or `EXPIRED` token is not a dispatch blocker; only a missing or unparseable file blocks a launch (`CREDS_MISSING`; a dev dispatch prints `DISPATCH_DEFERRED:<N>:creds` and exits 10). `po-live` still bind-mounts the whole host `~/.claude` directory.

### Rotate GitHub PAT

```bash
# Generate new token at: github.com → Settings → Developer settings → Personal access tokens
# Required scopes: repo, workflow, read:org

# Re-run agent setup to update stored credentials
/agent-setup creds
```

### Check Credential Status

```bash
./.claude/tooling/scripts/agent-dispatch.sh check-creds
# CREDS_MODE:token       — long-lived agent token decrypts; host token freshness is not checked
# CREDS_OK:<minutes>     — valid, minutes until expiry
# CREDS_LOW:<minutes>    — expiring soon, advisory only (agent refreshes the live file in place)
# CREDS_EXPIRED:<N>      — advisory only; the host's own token rotation covers it
# CREDS_MISSING:*        — run `claude` on the host to authenticate, then /agent-setup
```

## Writing Good Agent Stories

Agents cannot ask clarifying questions. Everything they need must be in the issue.

### Checklist

- [ ] **Self-contained**: all context in the issue body, no "see our discussion in Slack"
- [ ] **Reference files explicitly**: "follow the pattern in `pkg/storage/providers/sqlite/`" not "follow existing patterns"
- [ ] **Testable acceptance criteria**: `- [ ]` checkboxes that can be mechanically verified
- [ ] **Single concern**: one focused change, not "refactor X and also add Y"
- [ ] **No vague verbs**: "add", "implement", "fix" — not "improve", "enhance", "clean up"

### Examples

Do not ask the agent to commit, push, open a PR, run `gh` or put CI run numbers in the PR body: it has no GitHub access, and the supervisor publishes (see `docs/development/story-template.md`).

**Good** — agent can succeed:
```
Add `RetryConfig` field to `pkg/config/manager.go` following the pattern in
`pkg/config/rollback_types.go`. Add validation in `pkg/config/validation.go`
following `validateResources`. Tests in `pkg/config/manager_test.go`.

Acceptance criteria:
- [ ] RetryConfig struct has MaxAttempts (int), BackoffMs (int), fields
- [ ] Validation rejects MaxAttempts < 1 or > 100
- [ ] `make test-agent-complete` passes
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
# (the run reads the spec from the story's project item, whose content is this issue)
gh issue edit 123 --body "$(gh issue view 123 --json body -q .body)\n\n## CI Failure\n..."
# Set the story back to Ready on the board, then:
/dispatch 123           # re-dispatch with updated context
```

> **Existing branch on re-dispatch:** the run does not delete an existing
> `feature/story-N-agent` branch. When that branch's head is not already in develop,
> the run starts from it and builds on its commits; it pushes with
> `--force-with-lease` against the head it saw at the start, and updates the branch's
> open PR if there is one. Delete the old remote branch first to start from develop.

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

### Dispatch refused with `image_stale`

**Cause**: `cfg-agent:latest`'s `cfgms.build_inputs_hash` label is not this checkout's `.claude/tooling/devcontainer` tree — usually after a `.claude/tooling` bump that changed `devcontainer/`. The dev-agent launch path never rebuilds the image.
**Fix**: `/agent-setup rebuild`, then dispatch again.

### `WIP:` draft PR (run ended in FAILED)

**Cause**: The run spent its fix budget on failing validation, or an agent session died (for example, its login was revoked mid-run), and the run ended in `FAILED` with unsaved work. The supervisor commits its latest candidate as `WIP: agent attempt for issue #N (<reason>)`, pushes it and opens (or keeps) a draft PR titled `WIP: <branch> (agent failed)`, whose body starts `Agent session failed with exit code 1` and carries `FSM-Reason:` and `FSM-Attempt:` trailers. It never pushes unvalidated work onto a PR that is already ready for review; it comments there instead. The pipeline then dispatches a `fix-pr` run onto the draft.
**Behaviour**: The `fix-pr` run validates the draft's work like any other candidate. When its validation passes, the supervisor pushes, retitles the draft, rewrites its body and marks it ready, so it goes to acceptance review. If the agent finds nothing to change on a WIP draft, the draft's head is still validated before it is promoted; nothing is promoted on the agent's say-so. Once two runs for the story have failed, the next run is refused at PREPARE (`fsm_attempt_cap`) and the story is set Blocked.

### Agent creates PR that touches unrelated files

**Cause**: Story wasn't scoped to specific files.
**Fix**: Close PR, update issue to specify exact files in scope, re-dispatch.

### Run ended with no PR

**Cause**: The run was refused at PREPARE, ended in `FAILED` with no unsaved work, or crashed.
**Fix**: `./.claude/tooling/scripts/po-act.sh dispatch status` — find the run, then `po-act.sh dispatch status <RUN_ID>` for its state and reason. The supervisor's log is `~/.cache/cfgms-fsm-runs/<RUN_ID>/logs/supervisor.log`, and the launcher's log under `~/.cache/cfgms-fsm-runs/launch-logs/`. A `crashed` run is resumed with `po-act.sh dispatch resume <RUN_ID>`, not re-dispatched.

## Relationship to Interactive Workflow

Agent dispatch and interactive slash commands coexist — they're complementary, not alternatives:

- **Agent dispatch**: well-scoped stories with clear acceptance criteria, while you do other work
- **Interactive session**: architecture decisions, new patterns, stories that need iteration, reviewing agent PRs

The same `CLAUDE.md` conventions, validation gates, and PR standards apply to both. Agent PRs go through the same CI pipeline and require the same human PR review before merging.

Run multiple agents in parallel while working interactively on a different story. The only constraint: don't dispatch an issue that depends on an in-progress agent's work — wait for the PR and merge first.

## Max Plan Usage Tips

- Dispatch during off-hours — a run includes the agent session plus one or more `make test-agent-complete` validations
- Batch independent stories: `/dispatch 123 124 125` launches three containers in parallel
- Stories with reference implementations use fewer tokens (agent spends less time exploring)
- If a run looks stuck, check `/isoagents`: a run without an agent container may be validating (`cfg-validate-<N>`), syncing or publishing, and a `hung` run (stale heartbeat) is reported by the pipeline watcher
