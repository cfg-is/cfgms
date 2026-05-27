# CFGMS — Autonomous Agent Development System

## Product Requirements Document — v2.1 (GitHub-Native Pipeline)

**Author:** Jordan Ritz, Founder — cfg.is / Eberly Systems
**Date:** April 2026
**Status:** Draft
**Key Changes from v2.0:** BA/Tech Lead/QA agents are subagents (not containers). PO split into interactive and cron modes. QA Agent replaces `/pr-review` for agent PRs. `pipeline:fix` label added for autonomous fix cycle. Sub-issues confirmed as GA GitHub feature.
**Repository:** github.com/cfg-is/cfgms

-----

## 1. Executive Summary

CFGMS is a pre-revenue B2B SaaS platform built by a solo founder who simultaneously operates an MSP business. Development velocity is constrained not by capital or compute — it is constrained by the founder's time. This PRD defines an autonomous agent development system that restructures how software is built: the founder acts as Product Manager, a persistent Claude Code session acts as Product Owner, and a pipeline of specialised agents handles every downstream role from Business Analyst through to QA.

The pipeline coordination layer uses GitHub Issues and GitHub Projects — the infrastructure already used for code coordination. This eliminates a parallel state store, gives the founder mobile access to pipeline status, and means every agent uses the `gh` CLI it already knows rather than a bespoke file format.

> **Goal:** Reduce the founder's active involvement in software delivery from PM + PO + BA + Tech Lead + Developer + QA, to PM only — while increasing overall delivery throughput.

-----

## 2. The Agent Team — Roles & Responsibilities

The system mirrors a standard product delivery org. Each role is either a Claude Code skill (slash command in the founder's interactive session), a subagent (spawned by the PO for non-code work), or a container agent (for code changes).

| Role | Type | Invokes | Primary Output |
|------|------|---------|----------------|
| **Founder (PM)** | Human | `/po` in terminal | Leader intent, roadmap direction, merge decisions |
| **Product Owner** | Skill — `/po` (interactive) + Scheduled remote agent (cron) | Planning Team (BA + Tech Lead), QA subagent; `/dispatch` for dev agents | GitHub epics, pipeline orchestration, session dashboard |
| **Business Analyst** | Planning Team member | `SendMessage` (proposals to PO/Tech Lead) | Story proposals for team review; GitHub writes handled by PO after consensus |
| **Tech Lead** | Planning Team member | `SendMessage` (verdicts to PO/BA) | Story validation verdicts; challenges BA on feasibility and scope |
| **Developer** | Container Agent | `make test-complete`, `gh pr create` | PR against develop (existing infrastructure, unchanged) |
| **QA** | Subagent | `gh pr review`, `gh issue edit` | Structured verdict comment on PR; `pipeline:review` or `pipeline:fix` label |

> **Planning Team model:** During epic decomposition, the PO creates a temporary team (via `TeamCreate`) with BA and Tech Lead as teammates. All three communicate via `SendMessage` — BA proposes stories, Tech Lead challenges and validates, PO mediates and makes product decisions. Stories are only created on GitHub after all three agree. This replaces the previous sequential model where BA and Tech Lead operated independently.

### 2.1 PO Split — Interactive vs. Cron

The PO operates in two modes with distinct responsibilities. They coordinate through GitHub labels — no shared process state.

| Concern | Interactive PO (`/po`) | Cron PO (scheduled remote agent) |
|---------|------------------------|----------------------------------|
| **Audience** | PM-facing | Team-facing |
| **Trigger** | Founder runs `/po` | Scheduled interval |
| **Responsibilities** | Intent capture, dashboard, merge decisions, targeted unblocks | Full pipeline orchestration cycle |
| **Subagent launches** | Only for targeted unblocks | BA, Tech Lead, QA as needed |
| **Container launches** | None | Dev agents via `/dispatch` |
| **Blocks founder** | Yes — synchronous conversation | No — runs independently |

**Race condition mitigation:** The interactive PO and cron PO have distinct responsibilities. The only overlap is unblocking — when the founder resolves a `pipeline:blocked` item during an interactive session, the PO changes the label and launches one subagent. Label changes are atomic; if the cron agent picks it up first, there's nothing left for the interactive PO to do, and vice versa.

-----

## 3. Why GitHub-Native Pipeline

Pipeline coordination uses GitHub Issues and GitHub Projects rather than local files. The rationale:

| Concern | Alternative (local files) | GitHub Native |
|---------|---------------------------|---------------|
| Blocked items | Files in repo | GitHub Issue, `pipeline:blocked` label, assigned to founder. Triggers notification. Accessible on mobile. |
| Draft stories | YAML front-matter files | GitHub sub-issues on epic, `pipeline:draft` label. No bespoke format to maintain. |
| Ready stories | Directory of files | `agent:ready` label — existing pattern, unchanged. |
| In-progress tracking | Directory of files | `agent:in-progress` label — existing pattern, unchanged. |
| Review queue | Directory of files | `pipeline:review` label on PR, assigned to founder. |
| Audit trail | Git history on pipeline files | GitHub Issue / PR / comment history — richer, searchable, linked. |
| Mobile access | None | Full — GitHub mobile, push notifications, PR assignments. |
| Multi-person routing | Not supported | Assignee field routes blocked items to correct person automatically. |
| Git history cleanliness | Pipeline churn pollutes code history | Pipeline state lives in GitHub — code history stays clean. |

### 3.1 What Is Lost

Offline operation is the only meaningful loss. Since all agents require the Anthropic API regardless, this is not a practical constraint.

The intent capture scratch file (written during `/po intent` conversation) remains local and is deleted once the epic Issue is created. It is never committed.

> **Note:** The intent buffer is the only local artifact. All pipeline state is in GitHub.

-----

## 4. GitHub Structure — Issues, Labels, and Projects

### 4.1 Label Taxonomy

Two namespaces: the existing `agent:` namespace (unchanged) and a new `pipeline:` namespace for orchestration concerns.

| Label | Set By | Meaning |
|-------|--------|---------|
| `agent:ready` | Tech Lead subagent | Story passed Tech Lead review — eligible for dispatch |
| `agent:in-progress` | `/dispatch` skill | Dev agent container running for this Issue |
| `agent:success` | Dev Agent | Dev agent completed, PR opened |
| `agent:failed` | Dev Agent | Dev agent hit max retries, draft PR created |
| `pipeline:epic` | PO (`/po` skill) | Top-level epic Issue — decomposed from founder intent |
| `pipeline:story` | BA subagent | Story sub-issue — child of an epic |
| `pipeline:draft` | BA subagent | Story created, awaiting Tech Lead review |
| `pipeline:blocked` | Any agent | Escalation — agents could not resolve. Assigned to correct person. |
| `pipeline:review` | QA subagent | PR passed QA verdict — founder merge decision needed |
| `pipeline:fix` | QA subagent | PR failed QA — fix agent dispatched for one autonomous fix attempt |

### 4.2 Issue Hierarchy

A two-level hierarchy using GitHub's native sub-issues (GA, supported via GraphQL API).

The PO creates epic Issues. The BA subagent creates story Issues as sub-issues of the epic using the `addSubIssue` GraphQL mutation. Dev agents close story Issues via PR. No deeper nesting is needed.

```bash
# BA subagent creates a story and links it as sub-issue
CHILD_URL=$(gh issue create --title "Story title" --body "..." --label "pipeline:story,pipeline:draft")
PARENT_ID=$(gh issue view 123 --json id -q .id)
gh api graphql -f query='
  mutation($parentId: ID!, $childUrl: String!) {
    addSubIssue(input: {issueId: $parentId, subIssueUrl: $childUrl}) {
      issue { number }
      subIssue { number }
    }
  }
' -f parentId="$PARENT_ID" -f childUrl="$CHILD_URL"
```

| Level | Created By | Labels | Content |
|-------|-----------|--------|---------|
| Epic Issue | PO (`/po` skill) | `pipeline:epic` | Goal, success criteria, non-goals, constraints. Sub-issues linked automatically. |
| Story — draft | BA subagent | `pipeline:story` + `pipeline:draft` | Implementation spec: files in scope, reference impl, acceptance criteria checkboxes. |
| Story — ready | Tech Lead subagent | `pipeline:story` + `agent:ready` | As above plus implementation notes, dependency order, Tech Lead sign-off. |
| Blocked Issue | Any agent | `pipeline:blocked` | One specific question. Context to answer without re-reading everything. Assigned. |

### 4.3 GitHub Projects Board

A single Projects board provides the kanban view. The PO reads this at session start to reconstruct pipeline state.

| Column | Contains | Moves Here When |
|--------|----------|-----------------|
| Backlog | Epic Issues not yet decomposed | PO creates epic Issue |
| Draft Stories | Issues: `pipeline:draft` | BA subagent creates story Issues |
| Ready | Issues: `agent:ready` | Tech Lead subagent promotes |
| In Progress | Issues: `agent:in-progress` | Dev agent dispatched |
| Fix In Progress | PRs: `pipeline:fix` | QA subagent flags issues, fix agent dispatched |
| PR Review | PRs: `pipeline:review` | QA subagent passes verdict |
| Blocked | Issues/PRs: `pipeline:blocked` | Any agent escalation (after autonomous fix attempt if applicable) |
| Done | Closed Issues, merged PRs | PR merge or Issue close |

-----

## 5. Pipeline Flow — End to End

Work moves through the pipeline in one direction. Each stage is triggered by a label change or Issue/PR event. No agent blocks the founder — all escalations create assigned `pipeline:blocked` Issues.

### 5.1 Intent Capture (Founder + PO, synchronous)

- Founder runs `/po intent <topic>` in terminal
- PO conducts structured conversation: goal, success criteria, non-goals, constraints
- PO writes local scratch file during conversation (never committed)
- Founder confirms intent is correct
- PO creates GitHub epic Issue with `pipeline:epic` label and full intent in body
- Scratch file deleted — all state now in GitHub

### 5.2 Collaborative Planning (Planning Team, async)

The PO creates a temporary team for epic decomposition. BA and Tech Lead collaborate in real time via `SendMessage`, with the PO mediating and making product decisions. Stories are only created on GitHub after all three agree.

- PO cron cycle finds `pipeline:epic` Issues with no child stories
- PO reads the epic body and gathers architectural context
- PO creates a planning team: `TeamCreate(team_name: "planning-epic-<NUM>")`
- PO spawns BA and Tech Lead as teammates (in parallel, both using `SendMessage` for communication)
- PO broadcasts epic context (goal, success criteria, non-goals, constraints, PM notes) to both teammates

**Planning conversation:**
1. BA surveys the codebase and sends story proposals to PO via `SendMessage`
2. PO relays proposals to Tech Lead for validation
3. Tech Lead validates each proposal against the codebase (dependency ordering, implementation notes, scope, constraints, ambiguity) and sends per-story verdicts: APPROVED or REVISION NEEDED
4. If revisions needed: PO relays feedback to BA → BA revises → PO relays to Tech Lead → repeat (max 3 rounds)
5. BA and Tech Lead can also message each other directly for quick clarifications
6. PO makes product decisions when BA and Tech Lead disagree on scope or priority

**After consensus:**
- PO creates all agreed stories on GitHub via `pipeline-helper.sh create-ready-story` with labels `pipeline:story` + `agent:ready` — stories skip `pipeline:draft` entirely since the Tech Lead already validated them
- PO posts a planning summary comment on the epic
- PO shuts down the team (`TeamDelete`)

**Convergence failure:** If BA and Tech Lead cannot agree after 3 revision rounds, PO makes a unilateral decision — accept, modify, or drop the disputed stories. Dropped stories produce a `pipeline:blocked` Issue with both perspectives documented.

> **Legacy path:** Stories with `pipeline:draft` label from before the Planning Team was introduced are still processed by a standalone Tech Lead pass in the pipeline cycle. New epics always use the collaborative Planning Team.

### 5.3 Legacy: Standalone Tech Lead Review

The standalone Tech Lead pass (PO agent §4.1 Step 2) handles `pipeline:draft` stories created before the Planning Team model. It operates identically to the previous sequential approach: PO spawns Tech Lead as an independent subagent, Tech Lead validates and promotes or blocks stories. Once the backlog of legacy `pipeline:draft` stories clears, this step becomes a no-op. All new epics use the collaborative Planning Team (§5.2).

### 5.4 Dispatch (PO cron, async)

- PO cron cycle finds Issues with `agent:ready` label not yet dispatched
- PO calls existing `/dispatch` skill — behaviour unchanged
- `/dispatch` applies `agent:in-progress` label (existing behaviour)
- Dev agent containers run, produce PRs (existing infrastructure unchanged)

### 5.5 QA Review (QA Subagent, async)

- PO cron cycle finds new PRs from dev agents (`headRefName: feature/story-N-*`)
- PO spawns QA subagent, passing PR number and parent story Issue number
- QA subagent reads PR diff, CI status, story Issue acceptance criteria checkboxes
- QA subagent posts structured review comment: criteria met / missed / pass-fail verdict
- On pass: applies `pipeline:review` label to PR, assigns to founder
- On fail: applies `pipeline:fix` label, posts review comments detailing what needs fixing

### 5.6 Fix Cycle (PO cron, async)

- PO cron cycle finds PRs with `pipeline:fix` label
- PO dispatches a fix agent container against the PR branch
- Fix agent pushes changes
- QA subagent re-reviews the PR
- On pass: removes `pipeline:fix`, applies `pipeline:review`, assigns to founder
- On second fail: removes `pipeline:fix`, applies `pipeline:blocked`, assigns to founder with specific failure detail. Agent container and clone are cleaned up.

### 5.7 Merge Decision (Founder, synchronous)

- Founder runs `/po` — dashboard shows PRs with `pipeline:review` label
- Founder reads QA verdict comment — no further investigation needed
- Founder merges or requests changes
- On merge: story Issue auto-closes, agent container and clone cleaned up, PO checks if any dependent draft stories are now unblocked

### 5.8 Container Cleanup (PO cron, automatic)

Agent containers and clones are cleaned up at three points:
- **On auto-merge:** Acceptance Reviewer removes the container immediately after merge
- **On escalation:** Acceptance Reviewer cleans up when a story is blocked after the fix cycle
- **PO cron sweep:** Each cycle runs `agent-dispatch.sh cleanup-stale` before dispatch, removing any remaining containers whose stories are closed, `agent:failed`, or `pipeline:blocked`

Failed or stale containers are preserved until the cron sweep so logs remain available for debugging.

-----

## 6. /po Command — Specification Summary

The `/po` command is the founder's only required interface. It bootstraps from GitHub state, surfaces a prioritised dashboard, and handles targeted unblocks. Full specification is in `.claude/commands/po.md`.

### 6.1 Session Bootstrap — GitHub Reads (in priority order)

- `pipeline:blocked` Issues assigned to founder — read first, always
- PRs with `pipeline:review` label assigned to founder — merge decisions pending
- PRs with `pipeline:fix` label — fix cycle in progress
- Issues with `agent:in-progress` or `agent:failed` labels — active dev containers
- Issues with `pipeline:draft` label — stories awaiting Tech Lead review
- Issues with `agent:ready` label — stories queued for dispatch
- Issues with `pipeline:epic` label — active epics, child issue completion percentage (via `subIssuesSummary`)
- `docs/product/roadmap.md` — active milestone, next milestone definition quality
- `./.claude/scripts/agent-dispatch.sh list-running` — container status cross-reference

### 6.2 Session Dashboard — Priority Order

| # | Section | Content |
|---|---------|---------|
| 1 | **NEEDS ATTENTION** | `pipeline:blocked` Issues assigned to founder. Items stale >7 days flagged. Always shown first. |
| 2 | **MERGE DECISIONS** | PRs with `pipeline:review` — QA verdict summary, CI status, one-line decision prompt. |
| 3 | **ACTIVE MILESTONE** | Current roadmap milestone, open item count, blockers to closing. |
| 4 | **AGENT TEAM** | Running containers, open PRs, fix cycle PRs, queued stories. |
| 5 | **PIPELINE DEPTH** | Epics, draft stories, ready stories, fix-in-progress, in-review PRs — counts by stage. |
| 6 | **FORWARD EDGE** | Next milestone definition quality. Prompts founder if thin. |

### 6.3 Cron PO — Autonomous Pipeline Cycle

The cron PO runs as a scheduled remote agent. It executes the full pipeline cycle as a single pass, spawning subagents for non-code work and containers for code work. Each step creates a `pipeline:blocked` Issue on unrecoverable failure and continues to the next.

The cron PO is idle-aware: if no actionable work exists in the pipeline, it skips the cycle. It can disable itself when the pipeline is empty and re-enable when new epics are created.

**Processing order:**

1. **Unblock check** — find merged PRs that unblock `pipeline:draft` stories with satisfied dependencies
2. **Tech Lead pass** — spawn Tech Lead subagent on `pipeline:draft` stories not yet reviewed
3. **Dispatch** — call `/dispatch` on all `agent:ready` Issues not yet dispatched
4. **Fix cycle** — dispatch fix agents for PRs with `pipeline:fix` label
5. **QA pass** — spawn QA subagent on new dev agent PRs without a review comment
6. **BA pass** — spawn BA subagent on `pipeline:epic` Issues with no child stories
7. **Forward edge** — if active milestone >80% complete and next milestone has no epics, create `pipeline:blocked` Issue requesting founder intent
8. **Session log** — post timestamped summary comment on each active epic Issue

### 6.4 Interactive PO — Targeted Unblocks

When the founder resolves a `pipeline:blocked` item during an interactive `/po` session, the PO can immediately unblock that work by changing the label and spawning the appropriate subagent. This avoids waiting for the next cron cycle. The interactive PO does not run the full pipeline cycle.

### 6.5 Intent Capture — /po intent <topic>

Structured conversation that ends only when the PO can state all five fields back to the founder and receive confirmation. Checks intent against existing roadmap items and the Apache/Elastic licensing boundary before writing the epic Issue.

| Field | What the PO Confirms Before Writing the Epic Issue |
|-------|---------------------------------------------------|
| Goal | Outcome the founder wants — not a feature list |
| Success Criteria | How we know it is done — testable, not qualitative |
| Non-Goals | What we are explicitly not solving in this epic |
| Constraints | Platform, dependency, licensing boundary (Apache vs Elastic), timeline |
| PM Notes | Verbatim important statements preserved for BA subagent context |

-----

## 7. Skills vs. Subagents vs. Containers — Implementation Taxonomy

Three execution models, determined by what the agent does:

| Property | Skill | Subagent | Container Agent |
|----------|-------|----------|-----------------|
| Runs in | Founder's Claude Code session | Spawned by PO (interactive or cron) | Docker container |
| Used for | PM-facing interaction | GitHub read/write (issues, PRs, comments) | Code changes |
| Blocks founder | Yes — synchronous | No | No |
| Failure surface | Terminal output | PO receives response directly | `pipeline:blocked` Issue |
| Code access | Read/write | Read-only | Read/write (isolated worktree) |
| GitHub access | Read/write | Read/write | Read/write |
| Permission mode | Default | `auto` — no approval prompts | Unrestricted (container) |
| Timeout | None (session-bounded) | None (short-lived by nature) | 1 hour hard limit |
| Examples | `/po`, `/dispatch`, `/pr-review` | BA, Tech Lead, QA | Dev agents, fix agents |

**Decision rule:** Touching code → container. Touching GitHub only → subagent.

### 7.1 Existing Skills — Unchanged

- `/dispatch` — launch containerised dev agents for Issues, branches, or PRs
- `/isoagents` — monitor containers: dashboard, logs, cleanup, lifecycle
- `/agent-setup` — one-time bootstrap: image build, credentials, labels
- `/pr-review` — 6-phase PR review with CI verification (used for manual reviews; pipeline QA replaces this for agent PRs)
- `/story-start`, `/story-commit`, `/story-complete` — interactive development workflow

### 7.2 New Skills — This PRD

- `/po` — PO bootstrap, dashboard, targeted unblocks
- `/po intent <topic>` — structured intent capture, writes GitHub epic Issue on completion
- `/po status` — dashboard only, no processing
- `/po next` — single most valuable next action recommendation

### 7.3 New Subagents — This PRD

- **BA Subagent** — reads `pipeline:epic` Issue, creates `pipeline:story` + `pipeline:draft` sub-issues
- **Tech Lead Subagent** — reads `pipeline:draft` Issues, validates for agent executability, annotates, promotes to `agent:ready`
- **QA Subagent** — reads PR diff + story Issue, posts verdict comment, applies `pipeline:review` or `pipeline:fix`

### 7.4 QA Scope Distinction

Two QA passes exist with distinct scope and timing:

| QA Pass | Timing | Scope | Run By |
|---------|--------|-------|--------|
| `/story-complete` QA | Pre-PR, inside dev agent | Code quality, test correctness, security scan | Dev agent's `/story-complete` skill |
| Pipeline QA subagent | Post-PR | PR diff review, acceptance criteria verification, CI status, merge readiness | PO-spawned QA subagent |

The `/story-complete` QA asks "is the code clean?" The pipeline QA asks "does this PR fulfill the story and should it be merged?"

-----

## 8. Multi-Person Scaling

The GitHub-native model extends naturally to a small team.

### 8.1 Solo Founder (Current)

All `pipeline:blocked` Issues assigned to founder. All `pipeline:review` PRs assigned to founder. Single `/po` session. This is the target state for this PRD.

### 8.2 Two to Three People

Epic Issues gain an assignee (owner). `pipeline:blocked` Issues route to the epic owner, not always the founder. Multiple `/po` sessions can run simultaneously scoped to different epics. The founder retains merge authority or delegates by PR assignee. No architectural changes required.

### 8.3 Three to Five People

GitHub Projects becomes the canonical coordination surface for human team members. Each person runs `/po` scoped to their assigned epics. `pipeline:blocked` routing is fully automatic via GitHub assignee. The agent team (BA, Tech Lead, QA) operates identically — only epic ownership configuration changes.

> **Design intent:** The system is optimised for solo founder with abundant compute. Multi-person scaling is a natural extension of the GitHub-native model, not a redesign. Epic ownership is the only configuration change needed when a second human joins the pipeline.

-----

## 9. Build Sequence

Each phase delivers independent value. Later phases build on earlier ones but do not require them to be complete.

| Phase | Deliverable | Value Delivered | Unblocks |
|-------|-------------|-----------------|----------|
| 1 | `/po status` + bootstrap | Dashboard from GitHub state. Replaces 5+ manual `gh` commands at session start. | Phase 2 |
| 2 | `/po intent` + epic creation | Intent conversation writes GitHub epic Issue. Founder stops writing epics manually. | Phase 3 |
| 3 | BA subagent | Epic Issues decomposed into story Issues autonomously while founder is at Eberly. | Phase 4 |
| 4 | Tech Lead subagent | Draft stories validated, annotated, promoted to `agent:ready` without founder. | Phase 5 |
| 5 | `/po` cron dispatch | PO cron calls `/dispatch` in autonomous cycle. Founder only sees PRs. | Phase 6 |
| 6 | QA subagent + fix cycle | PRs reviewed against acceptance criteria. One autonomous fix attempt before escalation. Founder makes merge decisions only. | Phase 7 |
| 7 | Cron idle-awareness | Fully autonomous overnight. Cron PO skips empty cycles, re-enables on new work. Founder opens terminal to review queue and blocked items. | — |

-----

## 10. Constraints & Design Decisions

### 10.1 GitHub Is the Single Source of Truth

No pipeline state exists outside GitHub (except the ephemeral intent scratch buffer). Subagent failures are known to the PO directly — no half-written local state to recover.

### 10.2 pipeline:blocked Is the Last Resort

No agent sends notifications, posts Slack messages, or opens PR comments to surface ambiguity. All escalations create a `pipeline:blocked` Issue assigned to the correct person. For PRs, the system attempts one autonomous fix cycle (`pipeline:fix`) before escalating to `pipeline:blocked`. The founder's attention surface is predictable: one label, checked at session start.

### 10.3 CLAUDE.md and roadmap.md Are Read-Only for Agents

BA, Tech Lead, and QA subagents read these files for context. They do not modify them. Agents that believe a `CLAUDE.md` rule needs changing create a `pipeline:blocked` Issue rather than editing the file.

### 10.4 Agents Write Minimum Necessary GitHub State

Agents do not create Issues speculatively or post incremental progress comments. The PO creates stories on GitHub only after the Planning Team (BA + Tech Lead) reaches consensus. QA posts one structured comment per PR. Verbosity degrades the signal-to-noise ratio of GitHub as a coordination surface.

### 10.5 Sub-Issues via GraphQL API

GitHub's native sub-issues are GA. The PO uses `pipeline-helper.sh create-ready-story` (which calls the `addSubIssue` GraphQL mutation) to link story Issues as children of epic Issues after Planning Team consensus. The PO queries `subIssues` and `subIssuesSummary` on epics to track completion. No fallback format needed.

### 10.6 Developer Agents Are Unchanged

Docker containers, git worktrees, credential mounting, `cfg-agent:latest` image, `CFGMS_AGENT_MODE` execution, `make test-complete` validation — all unchanged. Dev agents and fix agents are the only containerised agents.

### 10.7 Agent Execution Models

Agents operate in two modes depending on the pipeline phase:

**Team mode (Planning Team — BA + Tech Lead):** During epic decomposition, BA and Tech Lead are spawned as teammates via `TeamCreate`/`Agent` with `team_name` and `name` parameters. They communicate with each other and the PO via `SendMessage`. Team communication is ephemeral — not persisted to GitHub. The PO creates all GitHub state after the team reaches consensus. Teams are temporary and cleaned up via `TeamDelete` after each planning session.

**Standalone subagent mode (QA, legacy Tech Lead pass):** QA runs as an independent subagent spawned by the PO with `mode: "auto"` (no approval prompts). It has read-only access to the repo and read/write access to GitHub via `gh`. The PO receives its response directly and knows if it completed or failed. The legacy standalone Tech Lead pass uses the same model for processing pre-existing `pipeline:draft` stories.

All non-developer agents have read-only access to the repo and do not modify code files. No explicit timeout — agents are short-lived by nature.

-----

## 11. Success Metrics

The system is working when all of the following are true:

- Founder spends less than 60 minutes per day on active development work
- Stories reach `agent:ready` without founder involvement after intent capture
- `pipeline:blocked` Issues are the only surface the founder checks for items needing input
- PRs in `pipeline:review` require no further investigation — QA verdict is sufficient for a merge decision
- Development continues overnight: founder captures intent in one session, returns to `pipeline:review` PRs the next morning
- GitHub Projects board reflects accurate pipeline state at all times without manual updates
- `pipeline:fix` resolves most QA failures without founder involvement

-----

## 12. Out of Scope

- Automated merge without founder approval — merge decisions remain human
- Agent-to-agent direct communication beyond the planning phase — the Planning Team uses `SendMessage` for ephemeral collaboration during epic decomposition, but all persistent pipeline state remains in GitHub
- External project management tools (Jira, Linear, Notion)
- Web UI for pipeline management — GitHub and terminal are the interface
- Multi-PM support — single PM model, multi-person via epic ownership
- LLM provider flexibility — Claude only

-----

## Appendix A — Existing Infrastructure Reference

The following are unchanged by this PRD.

| Command / Artefact | Purpose |
|---------------------|---------|
| `/dispatch` | Launch containerised dev agents for Issues, branches, or PRs |
| `/isoagents` | Monitor agent containers: status, logs, cleanup, lifecycle |
| `/agent-setup` | One-time bootstrap: build container image, configure credentials and labels |
| `/pr-review` | 6-phase PR review with CI verification — used for manual reviews |
| `agent-dispatch.sh` | Shell helper: clone management, container launch, auth checks, status |
| `refresh-agent-creds.sh` | Refresh Claude OAuth token (requires TTY — run outside Claude session) |
| `.agent-dispatch.yaml` | Container settings, branch patterns, label configuration |
| `cfg-agent:latest` | Docker image: Go toolchain, security tools, Claude Code, pre-cached modules |
| `CLAUDE.md` | Dual-mode agent execution rules, architecture constraints, validation gates |
| `docs/product/roadmap.md` | Milestone definitions — read by PO and agents, written by founder only |

-----

## Appendix B — Agent Story Quality Bar

Every story Issue created by the BA subagent must satisfy all of the following before the Tech Lead subagent will promote it to `agent:ready`. Documented in `docs/development/agent-dispatch.md`.

- **Self-contained:** all context in the Issue body, no external references
- **Reference files explicit:** named files and functions, not "follow existing patterns"
- **Testable acceptance criteria:** `- [ ]` checkboxes that can be mechanically verified
- **Single concern:** one focused change, not "refactor X and also add Y"
- **No vague verbs:** add, implement, fix — not improve, enhance, clean up
- **`make test-complete` pass:** always the final acceptance checkbox
