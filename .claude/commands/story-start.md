---
name: story-start
description: Start a new story with mandatory pre-flight validation and roadmap auto-detection. MUST use when beginning any new development work, picking up an issue, or the user says "start story", "new story", "work on issue", "begin work on #X", or similar.
parameters:
  - name: story_number
    description: The story/issue number (optional - auto-detects from roadmap if omitted)
    required: false
  - name: description
    description: Brief description for branch name (optional if auto-detecting)
    required: false
---

# Story Start Command

Start a new story with mandatory pre-flight checks that establish an **accountability baseline**. If tests pass now, any failures during development are unambiguously caused by the current work.

## Execution Flow

### 1. Auto-Detection (when no story number provided)

Invoke the **story-context skill** to do the detection — it runs in a Haiku fork, so the roadmap file and `gh issue list` output never enter this session's context. It parses `docs/product/roadmap.md` for `- [ ] **...** (Issue #NNN)` lines, cross-references `gh issue list`, and returns only the candidate list.

- If one candidate: confirm with user
- If multiple: present selection menu with AskUserQuestion

Do **not** read `roadmap.md` or run `gh issue list` inline in this session — always go through the fork.

### 2. Pre-Flight Validation (BLOCKING)

**CRITICAL**: This establishes the clean baseline. No starting work on top of failures.

**Run the pre-flight in a subagent — never inline.** Spawn the `qa-test-runner` agent (Sonnet) so the full test output stays in the fork and never enters this Opus session (where it would be billed on the priciest model *and* persist across every later turn). The prompt:

> From the repo root, run a fast non-race smoke of the tree:
> ```bash
> go build ./... && \
> go test -short -timeout=5m $(go list ./... | grep -v '/features/modules/' | grep -v '/test/integration' | grep -v '/test/e2e')
> ```
> Report back ONLY: overall PASS or FAIL; and if FAIL, the failing test/package names (or the build error) with the single most relevant line for each. Do not paste full logs or passing-test output.

- **BLOCKS** if the fork reports FAIL — fix failures before starting new work
- **BLOCKS** if the tree does not build
- Must achieve a 100% clean baseline

**Why non-race here (and not `make test`):** the dev tip you branch from has *already* passed the full `-race` unit gate in CI (`test-suite.yml`) and again at pre-push, so re-running `-race` on unchanged code is triplicated work — a separate instrumented compile (~+60%) plus a forced full re-run (`make test` wipes the testcache), for a nondeterministic single-shot probe that adds almost no signal. The pre-flight's job is only to prove *this environment* builds and passes green, so a failure found later during development is unambiguously the current work's fault. `-race` still runs where it catches *new* code: pre-push, CI, and `make test-complete`. **Do not narrow the package scope** below the set above — the baseline must stay broad enough that a later failure can't be dismissed as pre-existing or out-of-scope.

**Why this matters**: With a documented clean baseline, there is zero ambiguity about who owns test failures found later. If it passed at start and fails during development, the current work caused it. No excuses.

### 3. Git Status Validation

- Verify on `develop` branch (or prompt to switch)
- Check for uncommitted changes (warn if dirty)
- Ensure local branch is up-to-date: `git pull origin develop`

### 4. Branch Creation

```bash
git checkout -b feature/story-[NUMBER]-[description]
```

Verify: `git branch --show-current` shows new feature branch.

### 5. GitHub Project Update

```bash
# Move issue to "In Progress" on project board
gh project item-edit [project-id] --id [item-id] --field-id [status-field-id] --value "In Progress"
```

### 6. Story Context (invoke story-context skill)

Use the story-context skill to fetch issue details and display acceptance criteria for the story being started.

## Error Handling

- **Pre-flight fails**: Report specific failures, block branch creation. User must fix and retry.
- **Roadmap parse fails**: Fall back to manual story entry — prompt user for story number.
- **GitHub CLI unavailable**: Create branch locally, warn that project update requires manual action.
