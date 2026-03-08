# PRD: Agent Dispatch Infrastructure for CFGMS

## Overview

Build an isolated, containerized agent dispatch system that enables a solo developer on a Claude Max plan to shift from interactive Claude Code sessions to an unattended dispatch-and-review workflow. The system takes well-scoped GitHub Issues as input and produces reviewed Pull Requests as output, with each agent running in a Docker container that provides full OS-level isolation.

This adapts Stripe's "Minion" model for a solo developer context: the developer focuses on PRDs, sprint planning, and story decomposition (architect role), while headless Claude sessions in sandboxed containers handle implementation up to the PR. The developer reviews PRs, handles CI failures if needed, and merges.

This PRD is designed to be executed incrementally. Each story is scoped for a single Claude Code session to complete in one shot. Stories should be implemented sequentially within each epic, but epics 1-3 can be parallelized once the Dockerfile from Story 1.1 is built.

## Architecture

```
Developer (architect role)
|
+-- Claude CLI session -- PRDs, story decomposition, architecture, sprint planning
|     Model: Opus (planning work)
|
+-- dispatch.sh <issue#> [issue#...] -- deterministic bash, no LLM involvement
|     +-- Creates git worktree per issue from develop (GitFlow)
|     +-- docker run --detach per worktree (no --rm; monitor.sh handles cleanup)
|     |     +-- Mounts: worktree (rw), claude creds (ro), gh creds (ro)
|     |     +-- Firewall: allowlist only (GitHub, Anthropic API, Go proxy)
|     |     +-- entrypoint.sh fetches GH issue as prompt
|     |     +-- claude --dangerously-skip-permissions --model claude-sonnet-4-6
|     |     +-- Agent follows Agent Workflow in CLAUDE.md (4 phases)
|     |     +-- Phase 1: Implement (TDD, follow patterns)
|     |     +-- Phase 2: Validate (test-commit + test-fast + cross-compile)
|     |     +-- Phase 3: Self-review (QA + security checks, fix loop x3)
|     |     +-- Phase 4: Commit + push + PR targeting develop
|     |     +-- On failure: draft PR with diagnostics, exit non-zero
|     |     +-- Resource limits: 8GB RAM, 4 CPUs, 1 hour timeout
|     |     +-- Exit
|     +-- Returns immediately (fire-and-forget)
|
+-- monitor.sh -- background daemon
|     +-- Polls for exited containers labeled cfg-agent
|     +-- Extracts PR URL from completed agents
|     +-- Logs exit status, duration, PR links
|     +-- Cleans up containers and worktrees
|     +-- Desktop notification on completion with PR link
|
+-- Developer reviews PR
|     +-- Option A: /pr-review in interactive session, merge if good
|     +-- Option B: Review on phone via GitHub mobile, merge if good
|     +-- Option C: If CI fails, fix interactively or re-dispatch
|
+-- Phone -- review PRs in GitHub mobile, merge or request changes
```

### Workflow Mapping: Interactive -> Headless

The existing CFGMS development workflow uses mandatory slash commands (`/story-start`,
`/story-commit`, `/story-complete`) that assume an interactive session with the developer
present. The agent dispatch system replaces these with headless equivalents while
preserving all safety gates:

| Current (interactive)                        | Headless (container)                          | Owner           |
|----------------------------------------------|-----------------------------------------------|-----------------|
| `/story-start` pre-flight (`make test`)      | Worktree created from known-good `develop`    | `dispatch.sh`   |
| `/story-start` branch creation               | `git worktree add -b feature/story-N develop` | `dispatch.sh`   |
| `/story-start` GitHub project update         | Label `agent:in-progress` applied             | `dispatch.sh`   |
| Developer implements feature                 | Claude implements autonomously                | Agent container  |
| `/story-commit` validation (`test-commit`)   | Agent runs `make test-commit`                 | Agent container  |
| `/story-commit` message generation           | Agent generates per CLAUDE.md conventions     | Agent container  |
| `/story-complete` QA test runner             | Agent runs `make test-agent-complete`          | Agent container  |
| `/story-complete` QA code review             | Agent reviews own code for quality issues      | Agent container  |
| `/story-complete` security review            | Agent runs security scans + code review        | Agent container  |
| `/story-complete` developer fix loop         | Agent fixes issues, re-validates (max 3 rounds)| Agent container  |
| `/story-complete` doc review                 | Agent scans for internal tracking docs         | Agent container  |
| `/story-complete` cross-platform build       | Agent runs `make build-cross-validate`         | Agent container  |
| `/story-complete` push + PR creation         | Agent pushes + creates PR targeting `develop`  | Agent container  |
| `/story-complete` Docker integration tests   | CI required checks on PR to develop            | GitHub Actions   |
| `/story-complete` E2E tests                  | CI required checks on PR to develop            | GitHub Actions   |
| `/story-complete` roadmap update             | Architect concern, agent does not touch        | Human            |
| PR review + merge                            | `/pr-review` or phone review + merge           | Human            |

**Safety gates preserved in container (no Docker daemon needed):**
- `make test-commit` — tests + lint + security scans + architecture checks
- `make test-fast` — fast comprehensive tests (pure Go)
- `make test-production-critical` — production critical tests (pure Go)
- `make build-cross-validate` — cross-platform compilation (Go cross-compile, no Docker)
- `make security-scan` — gosec, staticcheck, trivy, nancy (CLI tools installed in image)
- `make security-precommit` — gitleaks + truffleHog (CLI tools installed in image)
- `make check-architecture` — central provider violation detection (script-based)
- QA code review — agent reads changed files, checks for mocks/skips/hacks
- Security code review — agent reviews changed files for vulnerabilities
- Developer fix loop — agent fixes issues found by QA/security, re-validates (max 3 rounds)
- Doc review — scans for internal tracking docs that must be removed

**Safety gates deferred to CI (require Docker daemon):**
- `test-integration-docker` — needs PostgreSQL + Gitea containers
- `test-e2e-fast` — needs MQTT+QUIC infrastructure containers

**Safety gates deferred to human:**
- Roadmap updates — architect responsibility
- Final PR review and merge decision

**New Makefile target for agent containers:**

A new `make test-agent-complete` target combines everything from `test-complete` that
does NOT require Docker-in-Docker:

```makefile
# Agent container validation - everything from test-complete minus Docker targets
test-agent-complete: test-commit test-fast test-production-critical build-cross-validate
```

This gives agent containers ~95% of the `test-complete` validation. The remaining ~5%
(Docker integration + E2E) runs via GitHub Actions CI on the PR.

## Constraints

- **Budget:** Claude Max plan (5x or 20x). All Claude Code sessions (architect + agents) share the same 5-hour rolling usage window. No separate API key spend.
- **Infrastructure:** Linux dev box (HP ProDesk 600 G5 SFF, part of Hyper-V/S2D cluster). Docker available. No macOS dependencies.
- **Concurrency:** Target 2-3 simultaneous agent containers. Dispatch script should support a configurable --max-parallel flag.
- **Isolation:** Each agent runs in its own Docker container with only the worktree mounted. Agents cannot access the host filesystem, other worktrees, or other containers. The `--dangerously-skip-permissions` flag is only safe because of container isolation.
- **Resource Limits:** Each container: 8GB RAM, 4 CPUs, 1 hour timeout. Prevents runaway agents.
- **Credentials:** Claude Max OAuth token and GitHub fine-grained PAT are mounted read-only from persistent Docker volumes. One-time setup, reused across all container launches.
- **Model:** Agent containers use claude-sonnet-4-6 for implementation (more generous Max plan limits). Opus reserved for architect planning sessions.
- **Language:** CFGMS is a Go monorepo. The container image must include the Go toolchain matching go.mod, golangci-lint, ripgrep, git, gh CLI, jq, curl, and make.
- **GitFlow:** All branches created from `develop`, all PRs target `develop`. Never `main`.
- **No Docker-in-Docker:** Agent containers do not have access to Docker. The only validation targets that require Docker are `test-integration-docker` (PostgreSQL + Gitea) and `test-e2e-fast` (MQTT+QUIC infrastructure). These are deferred to GitHub Actions CI. All other validation — including security scans, cross-platform compilation, and the full test suite — runs inside the container.

## Credential Strategy

### GitHub CLI (gh)

- Create a fine-grained Personal Access Token scoped to ONLY the cfgms repository.
- Permissions: Issues (read/write), Pull Requests (read/write), Contents (read/write).
- Authenticate on the host: `gh auth login --with-token < token-file`
- Store at: `~/.config/gh/` on host
- Mount into containers as: `-v "$HOME/.config/gh:/home/agent/.config/gh:ro"`

### Claude Code (Max Plan)

- Authenticate once in a throwaway container, persist to a named Docker volume.
- Two files required:
  - `~/.claude/.credentials.json` — OAuth token (must be persisted)
  - `~/.claude/.claude.json` — Onboarding flag (can be generated: `{"hasCompletedOnboarding":true,"installMethod":"native"}`)
- Docker volume: `claude-creds`
- One-time setup:
  ```bash
  docker volume create claude-creds
  docker run --rm -it \
    -v claude-creds:/persist \
    cfg-agent:latest \
    bash -c "claude && cp ~/.claude/.credentials.json /persist/"
  ```
- Entrypoint restores credentials from volume on each launch.
- Token expires periodically (weeks). When agents fail on auth, re-run one-time setup.

### Credentials NOT Needed in Containers

- **M365 credentials** — Only needed for `test-ci` / `test-m365-integration`. Agents run `test-commit` level only.
- **SOPS/age keys** — Only needed if stories touch encrypted config. Excluded from agent scope initially.
- **OS keychain (secret-tool)** — Not available in containers. Not needed at `test-commit` level.

## Firewall Policy

The devcontainer firewall uses iptables with a default-deny outbound policy. Allowlisted destinations:

| Destination | Port | Purpose |
|---|---|---|
| api.anthropic.com | 443 | Claude API |
| statsig.anthropic.com | 443 | Claude Code telemetry |
| sentry.io | 443 | Claude Code error reporting |
| github.com | 443 | Git push/pull, gh CLI |
| api.github.com | 443 | GitHub REST API |
| proxy.golang.org | 443 | Go module proxy |
| sum.golang.org | 443 | Go module checksum |
| storage.googleapis.com | 443 | Go module storage |
| DNS (system resolver) | 53 | DNS resolution |

All other outbound traffic is blocked. No inbound ports are exposed.

---

## Epic 0: Prerequisites

### Story 0.1: Close CI Coverage Gap for Controller E2E Tests

Add `integration-tests-controller` as a required status check on the `develop` branch
ruleset in GitHub.

**Problem:** The agent container skips `test-e2e-fast` (requires Docker-in-Docker), relying
on CI to catch failures. The `test-integration-docker` target is fully covered by the
`Build Gate` required check. However, the controller E2E tests (`test-e2e-controller`)
only run in `production-gates.yml`'s `integration-tests-controller` job, which is NOT a
required status check. This means a PR could merge to develop with failing controller E2E
tests.

**Requirements:**
- Add `integration-tests-controller` as a required status check on the develop branch ruleset
- Verify the job name in `production-gates.yml` matches the required check name exactly
- Confirm the job runs on PRs to develop (it already does — just not blocking)
- No code changes needed — GitHub settings only

**Acceptance Criteria:**
- [ ] `integration-tests-controller` appears as a required check in develop branch ruleset
- [ ] A PR with failing controller E2E tests is blocked from merging
- [ ] Existing passing PRs are not affected (job already runs, just becomes required)
- [ ] Combined with existing required checks, all targets from `make test-complete` are
      covered: either by the agent container (`test-agent-complete`) or by CI

**Why this must be done first:** Without this, the agent dispatch system has a coverage gap
where controller E2E failures could slip through to develop. This story closes that gap
before any agent containers are deployed.

---

## Epic 1: Devcontainer Image

### Story 1.1: Base Dockerfile

Create `.devcontainer/Dockerfile` for the agent container image.

**Requirements:**
- Base image: `golang:1.24-bookworm` (or match go.mod version)
- Install dev tools: `golangci-lint` (latest stable), `ripgrep`, `git`, `jq`, `curl`, `make`, `gh` CLI, `iptables`, `sudo`
- Install security tools (required for `make security-scan` and `make security-precommit`):
  - `gosec` — Go security analyzer
  - `staticcheck` — Advanced Go static analysis
  - `trivy` — Vulnerability scanner
  - `nancy` — Go dependency vulnerability scanner
  - `gitleaks` — Secret detection in git repos
  - `trufflehog` — Secret scanning (staged files)
- Install Claude Code: `npm install -g @anthropic-ai/claude-code` (or `curl -fsSL https://claude.ai/install.sh | bash`)
- Create non-root user `agent` with home at `/home/agent`, add to sudoers for iptables only
- Set WORKDIR to `/workspace`
- Pre-populate Trivy vulnerability database: `trivy fs --download-db-only` at build time
  (avoids runtime download that would be blocked by firewall; DB will be stale but usable,
  rebuild image periodically to refresh)
- Pre-download Go module cache: copy go.mod and go.sum, run `go mod download` (will be stale but saves time on common deps)
- Copy `entrypoint.sh` and `init-firewall.sh` into image
- Set environment: `CFGMS_AGENT_MODE=true`
- ENTRYPOINT set to `entrypoint.sh`

**Acceptance Criteria:**
- [ ] `docker build -t cfg-agent:latest .devcontainer/` succeeds
- [ ] Container starts and `go version`, `golangci-lint --version`, `gh --version`, `claude --version`, `rg --version`, `make --version` all return valid output
- [ ] Security tools available: `gosec --version`, `staticcheck --version`, `trivy --version`, `nancy --version`, `gitleaks version`
- [ ] Runs as non-root `agent` user
- [ ] `CFGMS_AGENT_MODE` environment variable is set to `true`
- [ ] Go module cache is pre-populated with common dependencies
- [ ] `make test-commit` can run inside the container (all tool dependencies met)
- [ ] `make build-cross-validate` can run inside the container (Go cross-compilation works)

**Reference Files:**
- Anthropic reference devcontainer: https://github.com/anthropics/claude-code/tree/main/.devcontainer
- `go.mod` in repo root for Go version

---

### Story 1.2: Firewall Script

Create `.devcontainer/init-firewall.sh` that locks down container networking.

**Requirements:**
- Flush existing iptables rules
- Allow loopback traffic
- Allow established/related connections
- Allow DNS (UDP 53) outbound
- Allow HTTPS (TCP 443) outbound to allowlisted domains only (resolve IPs at container startup)
- Default deny all other outbound
- Log blocked connections (rate-limited to avoid log spam)
- Script runs as root via sudo in entrypoint before dropping to agent user
- Validate rules on startup: test connectivity to github.com (should work) and example.com (should fail)

**Acceptance Criteria:**
- [ ] `curl https://api.github.com` succeeds from inside container
- [ ] `curl https://example.com` is blocked from inside container
- [ ] `go mod download` works (proxy.golang.org reachable)
- [ ] `claude --version` works (api.anthropic.com reachable)
- [ ] `gh auth status` works (github.com reachable)

**Reference:**
- Anthropic reference `init-firewall.sh`: https://github.com/anthropics/claude-code/blob/main/.devcontainer/init-firewall.sh

---

### Story 1.3: Entrypoint Script

Create `.devcontainer/entrypoint.sh` — the container's main process.

**Requirements:**
- Accept issue number as first argument: `entrypoint.sh <ISSUE_NUM>`
- Accept optional `--dry-run` flag to print prompt without running Claude
- Initialize firewall (call init-firewall.sh with sudo)
- Restore Claude credentials:
  - Copy `/persist/.credentials.json` to `~/.claude/.credentials.json`
  - Generate minimal `~/.claude/.claude.json` with `hasCompletedOnboarding: true`
- Configure git:
  - Identity: `cfg-agent <agent@cfg.is>`
  - Set `push.autoSetupRemote true`
- Fetch issue content via `gh issue view $ISSUE_NUM --json title,body,labels --jq ...`
- If issue fetch fails, exit 1 with error logged
- Compose prompt (see Agent Prompt Template below)
- Run: `claude --dangerously-skip-permissions --model claude-sonnet-4-6 -p "$PROMPT"`
- Capture Claude exit code
- On completion (success or failure):
  - Extract PR URL if one was created: `gh pr list --head "$(git branch --show-current)" --json url -q '.[0].url'`
  - Write result summary to `/tmp/agent-result.json`:
    ```json
    {"issue": 42, "exit_code": 0, "pr_url": "https://...", "branch": "feature/story-42-agent"}
    ```
- If Claude exits non-zero and no PR was created:
  - Create a draft PR with failure details in the description
  - Comment on the issue: "Agent session failed. See draft PR for details."
- Update issue label: remove `agent:in-progress`, add `agent:success` or `agent:failed`
- Exit with Claude's exit code

**Agent Prompt Template:**
```
You are implementing GitHub issue #<NUM>: <TITLE>

<ISSUE_BODY>

## Instructions

You are running inside an isolated container with --dangerously-skip-permissions.
Your branch `feature/story-<NUM>-agent` is already checked out from `develop`.
Follow the CLAUDE.md file in the repository root — it contains all project conventions,
architecture rules, and coding standards.

## Phase 1: Implement

1. Read and understand the full issue including acceptance criteria
2. Read CLAUDE.md for project conventions (central providers, storage architecture, etc.)
3. If the issue mentions reference files or patterns, read them first
4. Implement the change following existing patterns and TDD approach

## Phase 2: Validate

5. Run `make test-agent-complete` which runs all validation that works without Docker:
   - test-commit (tests + lint + security + architecture checks)
   - test-fast (fast comprehensive tests)
   - test-production-critical (production critical tests)
   - build-cross-validate (cross-platform compilation)
6. If validation fails, fix issues and retry. Maximum 3 fix iterations.
7. The only validation NOT included (deferred to CI): Docker integration tests
   and E2E tests (these require a Docker daemon which is not available in the container)

## Phase 3: Self-Review

11. Review your own changes for quality issues:
    - Check for mocks, t.Skip(), empty assertions, hacky workarounds
    - Check for hardcoded secrets, SQL injection, information disclosure
    - Check for central provider violations (see CLAUDE.md Central Provider System)
    - Check for unsanitized user input in logs
    - Fix any issues found
12. Scan for internal tracking documents that should not be in the PR
    (check docs/ for any files that look like personal notes or drafts)

## Phase 4: Commit and PR

13. Run `go mod tidy` if dependencies changed
14. Stage all changes
15. Commit with message: `<scope>: <description> (Issue #<NUM>)`
    - Follow commit message format in CLAUDE.md (15-25 lines, WHY + WHAT)
    - Include `Co-Authored-By: Claude <noreply@anthropic.com>`
16. Push branch: `git push -u origin $(git branch --show-current)`
17. Open PR targeting `develop` (NEVER `main`):
    `gh pr create --base develop --title "<scope>: <title> (Issue #<NUM>)" --body "..."`
    PR description must include:
    - Summary with what changed and why
    - Changes made (3-5 bullets)
    - Validation results (which make targets passed/failed)
    - `Fixes #<NUM>`
18. Exit zero

## Failure Handling

If `make test-commit` fails after 3 fix iterations:
- Stage all changes and commit with message describing what was attempted
- Push the branch
- Open a DRAFT PR with failure details in the description body:
  - What was implemented
  - Which validation step failed
  - Error output from the failing step
  - What was tried to fix it
- Exit non-zero

## Scope Constraints

- Do NOT modify these files unless the issue explicitly requires it:
  CLAUDE.md, Makefile, .github/*, docs/product/roadmap.md
- Do NOT add external dependencies without justification in commit message
- Do NOT skip tests or use build tags to exclude them
- Do NOT push directly to main or create PRs targeting main
- ALWAYS check central providers in pkg/ before creating new functionality
```

**Acceptance Criteria:**
- [ ] `entrypoint.sh 1` fetches issue #1 and constructs prompt correctly (test with --dry-run flag)
- [ ] Claude credentials are wired up without interactive login prompt
- [ ] Git identity is set before any git operations
- [ ] Firewall is active before Claude starts
- [ ] Non-zero exit propagates correctly
- [ ] Result summary is written to `/tmp/agent-result.json`
- [ ] Issue labels are updated on completion
- [ ] Draft PR is created on failure with diagnostic details
- [ ] Works when run as non-root `agent` user (firewall init uses sudo)

---

## Epic 2: Dispatch and Lifecycle Scripts

### Story 2.1: dispatch.sh

Create `scripts/dispatch.sh` — the main developer-facing dispatch command.

**Requirements:**
- Usage: `dispatch.sh [--max-parallel N] [--dry-run] [--timeout SECONDS] <issue#> [issue#...]`
- Default `--max-parallel`: 3
- Default `--timeout`: 3600 (1 hour)
- For each issue number:
  - Validate issue exists and has `agent:ready` label (skip with warning if not)
  - **Pre-dispatch story quality check** (warnings only, does not block):
    - Check issue body has acceptance criteria (`- [ ]` checkboxes)
    - Check issue body length (warn if < 200 chars — likely under-specified)
    - Check for reference implementation mention (warn if absent — lower success probability)
    - Print quality score: "Story #42: acceptance criteria [YES], reference impl [NO], body length [OK]"
    - `--strict` flag: promote warnings to errors (block dispatch if quality checks fail)
  - Create git worktree: `git worktree add ../worktrees/story-<NUM> -b feature/story-<NUM>-agent develop`
  - If worktree or branch already exists, skip with warning
  - Launch container detached:
    ```bash
    docker run -d \
      --name "cfg-agent-${NUM}" \
      --label "cfg-agent=true" \
      --label "issue=${NUM}" \
      --label "worktree=../worktrees/story-${NUM}" \
      --memory=8g \
      --cpus=4 \
      --stop-timeout="${TIMEOUT}" \
      -v "$(realpath ../worktrees/story-${NUM}):/workspace" \
      -v "claude-creds:/persist:ro" \
      -v "${GH_CONFIG:-$HOME/.config/gh}:/home/agent/.config/gh:ro" \
      --cap-add NET_ADMIN \
      cfg-agent:latest \
      "$NUM"
    ```
  - `--cap-add NET_ADMIN` is required for iptables in the firewall script
  - Print: "Dispatched issue #NUM -> container cfg-agent-NUM"
- Respect `--max-parallel`: if N containers with label `cfg-agent` are already running, wait (poll every 30s) until a slot opens before launching next
- `--dry-run`: print what would be done without creating worktrees or containers
- Update GitHub issue: remove `agent:ready` label, add `agent:in-progress` label
- Script is pure bash — no LLM calls, no token cost

**Acceptance Criteria:**
- [ ] `dispatch.sh 42 43 44` creates 3 worktrees from develop and launches 3 containers
- [ ] `dispatch.sh --max-parallel 2 42 43 44` launches 2 immediately, queues 44
- [ ] `dispatch.sh --dry-run 42` prints plan without side effects
- [ ] Duplicate dispatch of same issue is handled gracefully (skip with warning)
- [ ] GitHub issue labels are updated on dispatch
- [ ] Worktrees are created from `develop` branch (not `main`)
- [ ] Branch naming follows `feature/story-<NUM>-agent` convention
- [ ] Pre-dispatch quality check warns on missing acceptance criteria
- [ ] Pre-dispatch quality check warns on missing reference implementation
- [ ] Pre-dispatch quality check warns on short issue body
- [ ] `--strict` flag blocks dispatch on quality warnings
- [ ] Script exits 0 after all containers are launched (does NOT wait for completion)

---

### Story 2.2: monitor.sh

Create `scripts/monitor.sh` — background cleanup daemon.

**Requirements:**
- Runs in a loop (default interval: 60 seconds, configurable via `--interval`)
- On each tick:
  - `docker ps -a --filter "label=cfg-agent" --filter "status=exited"` to find completed agents
  - For each exited container:
    - Read exit code: `docker inspect --format '{{.State.ExitCode}}'`
    - Read issue number from label
    - Read worktree path from label
    - Copy `/tmp/agent-result.json` from container before removal:
      `docker cp cfg-agent-${NUM}:/tmp/agent-result.json ./logs/` (best-effort)
    - Extract PR URL from result file or via `gh pr list --head "feature/story-${NUM}-agent"`
    - Log: timestamp, issue number, exit code, duration, PR URL
    - If exit code 0: log success, show PR URL
    - If exit code non-zero: log failure with warning
    - Remove container: `docker rm`
    - Remove worktree: `git worktree remove <path> --force`
    - Prune worktree list: `git worktree prune`
  - Also list currently running agent containers with uptime (status line)
- Send desktop notification on completion (via `notify-send` if available):
  - Success: "Agent #42 completed - PR: <url>"
  - Failure: "Agent #42 failed - check draft PR"
- Write structured log to `logs/agent-dispatch.jsonl` (append):
  ```json
  {"ts":"...","issue":42,"exit_code":0,"duration_sec":180,"container":"cfg-agent-42","pr_url":"https://..."}
  ```
- Graceful shutdown on SIGINT/SIGTERM

**Acceptance Criteria:**
- [ ] Detects and cleans up exited containers
- [ ] Removes associated git worktrees
- [ ] Extracts and logs PR URLs
- [ ] Logs structured output to jsonl file
- [ ] Does not interfere with running containers
- [ ] Can run as a background process: `monitor.sh &`
- [ ] Desktop notifications include PR links
- [ ] Status line shows running agents on each tick

---

### Story 2.3: status.sh

Create `scripts/status.sh` — quick view of agent state.

**Requirements:**
- Show all running agent containers: issue number, uptime, resource usage
- Show all exited agent containers not yet cleaned up: issue number, exit code
- Show all active worktrees under `../worktrees/`
- Show recent completion log (last 10 entries from `logs/agent-dispatch.jsonl`)
- Show Max plan usage hint: count of active sessions (informational, not from API)
- No arguments needed, pure read-only inspection

**Acceptance Criteria:**
- [ ] Shows running and completed agents in a readable table format
- [ ] Shows worktree count and paths
- [ ] Shows recent dispatch history with PR links
- [ ] Works when no agents are running (clean state)
- [ ] Exits 0 always (informational only)

---

## Epic 3: Project Configuration

### Story 3.1: CLAUDE.md Agent Mode Section

Add an agent mode section to the existing CLAUDE.md. This is NOT a rewrite — the existing
CLAUDE.md contains critical project-specific guidance (central providers, storage architecture,
certificate management, tenant model, etc.) that agents must follow.

**Requirements:**

Add a new section near the top of the existing CLAUDE.md:

```markdown
## Execution Mode

This file is used by both interactive Claude Code sessions and headless agent containers.

**Mode detection:**
- If `CFGMS_AGENT_MODE=true` environment variable is set -> follow the Agent Workflow below
- Otherwise -> use mandatory slash commands (/story-start, /story-commit, /story-complete)

Agent mode is set automatically by the container entrypoint. Never set it manually
in interactive sessions.
```

Add agent workflow section (adapts the prompt template from Story 1.3 into CLAUDE.md
for reference, but the entrypoint prompt is the authoritative source):

```markdown
## Agent Implementation Workflow

This section applies ONLY when CFGMS_AGENT_MODE=true (headless container execution).
Interactive sessions MUST use slash commands instead.

### Phase 1: Implement
1. Read the full issue including acceptance criteria and any referenced files
2. Check if the feature overlaps with existing central providers (see Central Provider System)
3. Implement following existing patterns and TDD approach

### Phase 2: Validate
4. Run `make test-commit` — ALL checks must pass (tests + lint + security + architecture)
5. If validation fails, fix and retry. Maximum 3 fix iterations.
6. Run `make test-fast` for broader test coverage
7. Run `make test-production-critical` for production critical tests
8. Run `make build-cross-validate` for cross-platform compilation
9. If any of steps 6-8 fail, fix and retry (best-effort, non-blocking for PR)

### Phase 3: Self-Review
10. Review your changes for quality issues:
    - Mocks, t.Skip(), empty assertions, hacky workarounds (see qa-code-reviewer rules)
    - Hardcoded secrets, SQL injection, information disclosure (see security-engineer rules)
    - Central provider violations (see Central Provider System section)
    - Unsanitized user input in logs
11. Fix any issues found. Scan for internal tracking documents in docs/.

### Phase 4: Commit and PR
12. Commit with message format: `<scope>: <description> (Issue #NUM)`
13. Push and open PR targeting develop (NEVER main)
14. PR description includes: summary, changes, validation results, `Fixes #NUM`
15. Exit 0

### Failure Handling
If `make test-commit` fails after 3 fix iterations:
- Commit work, push, open DRAFT PR with failure details and error output
- Exit non-zero

### Agent Scope Constraints

Do NOT modify without explicit instruction in the issue:
- CLAUDE.md, Makefile, .github/*, docs/product/roadmap.md

Do NOT:
- Add external dependencies without justification
- Skip tests or use build tags to exclude them
- Create PRs targeting main
- Create custom cache/storage/logging implementations (use central providers)
```

Update the "Development Workflow" section to acknowledge both modes:
- Keep slash commands as mandatory for interactive sessions
- Reference agent workflow for headless execution
- Make clear that both paths enforce the same quality gates

**Acceptance Criteria:**
- [ ] Existing CLAUDE.md content is preserved (no deletions from current content)
- [ ] Agent mode section is added near the top
- [ ] Agent workflow section references correct make targets (test-commit, test-fast, test-production-critical, build-cross-validate)
- [ ] Self-review phase covers QA code reviewer and security engineer checks
- [ ] Interactive workflow section still mandates slash commands
- [ ] File stays under 650 lines (current ~500 + ~120 new lines)
- [ ] Both modes enforce same validation gates

---

### Story 3.2: Makefile Agent Target

Add `make test-agent-complete` target to the Makefile.

**Requirements:**
- New target `test-agent-complete` that runs everything from `test-complete` that does NOT require Docker:
  ```makefile
  test-agent-complete: test-commit test-fast test-production-critical build-cross-validate
  ```
- Prints summary showing what was validated and what is deferred to CI
- Documents that this target is for agent containers (comment in Makefile)

**Acceptance Criteria:**
- [ ] `make test-agent-complete` runs successfully on a machine without Docker
- [ ] Includes all validation from `test-commit` (tests, lint, security, architecture)
- [ ] Includes `test-fast`, `test-production-critical`, and `build-cross-validate`
- [ ] Does NOT include `test-integration-docker` or `test-e2e-fast`
- [ ] Summary output clearly states what is deferred to CI

---

### Story 3.3: GitHub Issue Template

Create `.github/ISSUE_TEMPLATE/agent-story.yml` — the structured issue template for agent-dispatchable stories.

**Requirements:**
- YAML-based GitHub issue form (not markdown template)
- Fields:
  - **Title** (text, required): One-line implementation goal
  - **Task Description** (textarea, required): What to implement and why
  - **Scope** (dropdown, required): Which area of the codebase (pkg/, features/, cmd/, test/, docs/)
  - **Reference Implementation** (textarea, optional but strongly recommended): Path to existing file that follows the same pattern (e.g., `features/modules/file/resource.go`). Stories with reference implementations have significantly higher agent success rates. When unavailable, provide more detailed implementation guidance in the Task Description.
  - **Key Files** (textarea, optional): Files the agent should read before starting. One path per line.
  - **Acceptance Criteria** (textarea, required): Checkbox list of requirements. Must be specific and testable — agents cannot ask clarifying questions.
  - **Scope Constraints** (textarea, optional): Files or directories the agent should NOT modify
  - **External References** (textarea, optional): Links to API docs, design docs, RFCs
- Auto-label: `agent:ready` (indicates story is ready for dispatch)
- Template name: "Agent Story"
- Description: "A well-scoped implementation task for automated agent dispatch"

**Acceptance Criteria:**
- [ ] Template renders correctly in GitHub "New Issue" UI
- [ ] All fields have clear descriptions and placeholder text
- [ ] `agent:ready` label is applied automatically
- [ ] A human can fill this out in under 3 minutes for a well-understood task
- [ ] Issue body is self-contained (agent gets no interactive clarification)

---

### Story 3.4: GitHub Labels

Create the label set used by the dispatch workflow. These can be created via `gh label create` commands in a setup script.

**Labels:**
- `agent:ready` — Story is fully scoped and ready for dispatch (green #0E8A16)
- `agent:in-progress` — dispatch.sh has launched a container for this issue (yellow #FBCA04)
- `agent:success` — Agent completed successfully and opened a PR (blue #0075CA)
- `agent:failed` — Agent failed and opened a draft PR (red #D73A4A)
- `agent:blocked` — Story needs human intervention before dispatch (orange #E4E669)
- `story` — Identifies agent-dispatchable implementation tasks (gray #CCCCCC)

**Acceptance Criteria:**
- [ ] Script creates all labels idempotently (skip if exists)
- [ ] Colors are set for visual distinction in GitHub UI
- [ ] Labels have descriptions

---

## Epic 4: One-Time Setup and Documentation

### Story 4.1: Setup Script

Create `scripts/setup-agent-dispatch.sh` — one-time bootstrap for agent dispatch.

**Requirements:**
- Check prerequisites: Docker, git, gh, jq, curl
- Build the agent container image: `docker build -t cfg-agent:latest .devcontainer/`
- Create Docker volume for Claude credentials: `docker volume create claude-creds`
- Prompt for Claude Code authentication (interactive):
  - Launch a temporary container, run `claude`, user completes OAuth flow
  - Persist `.credentials.json` to the `claude-creds` volume
- Verify gh authentication: `gh auth status`
  - If not authenticated, prompt user to run `gh auth login`
- Create GitHub labels (call Story 3.4 script)
- Create `../worktrees/` directory (sibling to repo, for worktree storage)
- Create `logs/` directory for monitor output (add to .gitignore)
- Print summary of what was set up

**Acceptance Criteria:**
- [ ] Running `setup-agent-dispatch.sh` on a fresh box with Docker and gh installed produces a working environment
- [ ] Running `setup-agent-dispatch.sh` again is safe (idempotent)
- [ ] Claude credentials are persisted to Docker volume
- [ ] Agent container image builds successfully
- [ ] `logs/` directory is in .gitignore

---

### Story 4.2: README for Agent Infrastructure

Create `docs/development/agent-dispatch.md` — developer reference for the dispatch system.

**Requirements:**
- Quick start: setup-agent-dispatch.sh -> write issue -> dispatch -> review PR
- Architecture diagram (text-based, same as this PRD)
- Workflow mapping table (interactive -> headless)
- Credential management: how to refresh Claude token, how to rotate GH PAT
- Writing good agent stories:
  - Self-contained (agent cannot ask questions)
  - Reference files and patterns explicitly when available (biggest predictor of success)
  - Specific acceptance criteria (testable, not vague)
  - Appropriate scope (one focused change, not refactoring epics)
  - Examples of good vs bad story scoping
- Story sizing guidelines (what's agent-ready vs needs a human):
  - Agent-ready: touches ≤5 files, ≤300 lines changed, single concern, has reference impl
  - Likely agent-ready: new feature following established pattern, no reference but clear spec
  - Needs human: cross-cutting architectural changes, establishing new patterns, >5 files
  - Not agent-ready: vague requirements, requires back-and-forth clarification, touches CI/CD
  - Rule of thumb: if you can't write clear acceptance criteria in checkboxes, it's not ready
  - When no reference implementation exists, write a more detailed task description with
    explicit instructions on which patterns and conventions to follow
- CI failure workflow: how to handle CI failures on agent PRs
  - Option 1: Fix interactively with `/pr-review` + manual edits
  - Option 2: Close PR, update issue, re-dispatch
  - Option 3: Fix in interactive session, force-push to agent branch
- Troubleshooting: common failures and fixes
  - Agent auth failure -> re-run credential setup
  - Agent can't reach GitHub -> check firewall script
  - Agent hit retry cap -> review draft PR, fix manually or re-dispatch
  - Worktree conflicts -> `git worktree prune`
  - Container resource exhaustion -> increase --memory/--cpus limits
- Max plan usage tips: use Sonnet for agents, batch dispatch at start of session window, monitor with status.sh
- Relationship to existing workflow: how agent dispatch coexists with interactive slash commands

**Acceptance Criteria:**
- [ ] A developer unfamiliar with the system can get running from this doc
- [ ] Troubleshooting section covers the 5 most common failure modes
- [ ] CI failure recovery workflow is documented
- [ ] Under 300 lines

---

## Story Dependency Graph

```
Epic 0 (Prereq)             Epic 1 (Container)          Epic 2 (Scripts)           Epic 3 (Config)
---------------             -----------------          ----------------           ---------------
0.1 CI coverage gap         1.1 Dockerfile ----------> 2.1 dispatch.sh            3.1 CLAUDE.md agent mode
       |                           |                         |                     3.2 Makefile target
       v                           v                         v                     3.3 Issue Template
  (all epics)               1.2 Firewall               2.2 monitor.sh             3.4 Labels
                                   |                         |                          |
                                   v                         v                          |
                            1.3 Entrypoint              2.3 status.sh                   |
                                                                                        v
                                                        Epic 4 (Setup)
                                                        --------------
                                                        4.1 setup.sh <-- requires 1.x, 2.x, 3.4
                                                        4.2 README   <-- requires all above
```

**Parallelization:** Epic 0 must be done first (closes CI coverage gap). After that,
Epic 3 (all stories) has no code dependencies and can be implemented in parallel with
Epics 1 and 2. Stories within Epic 1 and Epic 2 are sequential.

**Recommended execution order:**
1. Story 0.1 (CI coverage gap) — prerequisite, GitHub settings only, no code
2. Story 3.1 (CLAUDE.md agent mode) + 3.2 (Makefile target) — must exist before any agent runs
3. Story 3.3 + 3.4 (template + labels) — parallel, no code deps
4. Story 1.1 (Dockerfile) — foundation for container
5. Story 1.2 (Firewall) — depends on 1.1
6. Story 1.3 (Entrypoint) — depends on 1.1, 1.2
7. Story 2.1 (dispatch.sh) — depends on 1.x
8. Story 2.2 (monitor.sh) — depends on 2.1 loosely
9. Story 2.3 (status.sh) — independent utility
10. Story 4.1 (setup.sh) — integration of everything
11. Story 4.2 (README) — last, references everything

**Note:** Story 0.1 is a GitHub settings change with no code. Stories 3.1-3.4 can be done
in the current interactive workflow since they don't require the container infrastructure.
All other stories should also be done interactively since the agent dispatch system doesn't
exist yet (bootstrapping problem).

## Success Criteria

- **One-shot rate:** 90%+ of well-scoped stories produce a CI-passing PR without iteration
- **Throughput:** 10-20 PRs/week from 2-3 parallel agent sessions
- **Token efficiency:** Agent sessions use Sonnet only; Opus reserved for architect planning
- **Isolation:** No agent can affect the host OS, other worktrees, or other containers
- **Developer time split:** 70% architecture/planning/stories, 20% PR review, 10% dispatch/monitoring
- **Safety parity:** ~95% of `test-complete` runs in container (everything except Docker integration + E2E). Remaining ~5% enforced by CI. No regression from interactive workflow.
- **GitFlow compliance:** All agent PRs target develop, branch naming follows conventions

## Operational Considerations

### Rate Limiting (Claude Max Plan)

All sessions (architect + agent containers) share the same Claude Max 5-hour rolling
usage window. With 3 concurrent agents, you can exhaust the window faster than expected.
If an agent hits the rate limit mid-work, Claude will stall or fail, and the container
will eventually exit non-zero (draft PR with partial work).

**Mitigation strategies:**
- Batch dispatches at the start of a usage window (not the end)
- Use `status.sh` to track active session count before dispatching more
- Keep architect planning sessions lightweight during heavy agent dispatch periods
- If budget allows, 20x Max plan provides significantly more headroom

### Develop Branch Staleness and Merge Queuing

Each worktree branches from `develop` at dispatch time. After the first agent PR merges,
remaining agent PRs are branched from stale `develop`. GitHub's "strict up-to-date branch
enforcement" will block merge until the PR branch is updated.

**This is by design** — it prevents merge conflicts from reaching develop. But it means:
- Only one agent PR can merge at a time
- After merging PR #1, PRs #2 and #3 need branch updates before they can merge
- GitHub can auto-update branches, or you can do it manually

**Impact on throughput:** Not a problem in practice. Agent PRs are typically independent
(different files/packages). The update-and-merge cycle takes seconds per PR. Only becomes
an issue if agents modify the same files, which well-scoped stories should avoid.

### Container Image Freshness

The Docker image pre-populates Go module cache and Trivy vulnerability DB at build time.
These go stale over time:
- **Go modules**: New dependencies added by stories won't be cached. `go mod download`
  runs at implementation time and works fine (just slower on first fetch).
- **Trivy DB**: Stale DB may miss new vulnerabilities. Rebuild image weekly:
  `docker build --no-cache -t cfg-agent:latest .devcontainer/`

## Future Enhancements (Not In Scope)

- **Auto-pickup daemon:** Script polls GitHub for issues ready for dispatch (`gh issue list --label "agent:ready" --assignee "cfg-agent"`) and automatically calls `dispatch.sh` for each. Removes manual dispatch step entirely — developer just labels/assigns issues and the system picks them up. Requires a dedicated GitHub machine user or bot account for the assignee filter.
- **CI reaction loop:** Agent watches for CI failure on its PR and self-heals (requires GitHub Actions integration with re-dispatch)
- **Claude Protocol hooks:** Mechanical enforcement of retry caps, commit discipline via Claude Code hook system (`.claude/hooks/`)
- **Agent sub-agents in container:** Spawn separate QA/security sub-agents (vs current self-review approach) for independent validation inside the container
- **Re-dispatch on CI failure:** Automatic re-dispatch when CI fails on an agent PR, passing failure context as additional prompt
- **Claude Code web sessions:** Use Anthropic's hosted sandbox instead of local containers if/when it supports GitHub Issue MCP connector
- **`@claude` on PRs:** GitHub Action for iterating on review feedback without re-dispatching
- **Multi-repo support:** Extend dispatch to work across cfg.is repositories beyond cfgms
- **Metrics dashboard:** Track one-shot rate, average agent duration, common failure modes over time
