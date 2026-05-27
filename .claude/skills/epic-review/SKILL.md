---
name: epic-review
description: Review every open epic — confirm sub-task completion is reflected in the epic body, verify the desired functionality was actually delivered for fully-complete epics, close passing epics with a closeout comment, and draft remediation stories under epics whose AC verification fails. Use when sweeping for closeable epics, after a story batch lands, or as part of /pipeline-sweep.
context: fork
agent: general-purpose
allowed-tools: Bash, Read, Grep, Glob
---

# Epic Review Skill

You review every OPEN epic and decide one of three outcomes per epic:

1. **CLOSE** — sub-tasks all done, AC verification passes on `origin/develop`
2. **FLAG + REMEDIATE** — sub-tasks all done, but AC verification fails → draft a remediation story
3. **KEEP OPEN (no-op)** — sub-tasks still in progress, or epic not yet decomposed

Always verify against `origin/develop`, never your local checkout (memory `feedback_verify_against_origin_develop.md`).

## Inputs

`$ARGUMENTS` is one of:
- empty — sweep every open epic
- `<issue_num>` — focused single-epic run (e.g. `1714`)

## Phase 1: Discover

```bash
git fetch origin develop --quiet
gh issue list --repo cfg-is/cfgms --label "epic" --state open \
  --json number,title,id,body --limit 100
```

If `$ARGUMENTS` names a specific epic, filter to that one and error clearly if it isn't open / isn't labeled `epic`.

For each epic, query sub-issue status (parallel where possible — separate `gh api graphql` calls in one assistant turn):

```bash
gh api graphql -f query='
  query($id: ID!) {
    node(id: $id) {
      ... on Issue {
        subIssuesSummary { total completed }
        subIssues(first: 50) {
          nodes {
            number
            title
            state
            closedAt
            closedByPullRequestsReferences(first: 5) {
              nodes { number mergedAt }
            }
          }
        }
      }
    }
  }
' -f id="<EPIC_NODE_ID>"
```

## Phase 2: Bucket

For each epic:

| Condition | Bucket | Next phase |
|---|---|---|
| `total == 0` | **Not decomposed** | Skip; record only |
| `completed < total` | **In progress** | Skip; record only |
| `completed == total && total > 0` | **Candidate** | → Phase 3 AC verification |

## Phase 3: AC verification (candidates only)

Read the epic body. Extract 2-4 verifiable claims from its Acceptance Criteria / Success Criteria / Goal sections. Prefer claims most central to the epic's stated outcome.

Verifiable claim types:
- file paths exist on origin/develop (`pkg/foo/bar.go`)
- exported function / type / method names (`Manager.Install`, `CertificateTypeServer`)
- test names (`TestControllerRestart`, `TestDriftAutoCorrection`)
- CLI subcommands (`cfg steward run-script`)
- script paths (`scripts/foo.sh`)
- doc file content (`docs/legal/CLA.md` contains "Version 2.0")
- negative claims (e.g. *"zero hits for `import ... steward/config`"* — these are the highest-signal because they catch incomplete removals)

For each claim, verify on origin/develop:

```bash
# File existence
git cat-file -e "origin/develop:pkg/foo/bar.go" 2>/dev/null && echo PRESENT || echo MISSING

# Function / type / symbol presence
git grep -nE 'func \(.*\) Install\b' origin/develop -- 'pkg/cert/'

# Test name
git grep -nE 'func TestControllerRestart\b' origin/develop -- 'test/e2e/fleet/'

# CLI subcommand
git grep -nE '"run-script"' origin/develop -- 'cmd/cfg/'

# Negative claim — hits should be zero
git grep -l 'features/steward/config' origin/develop -- 'features/controller/' || echo NONE
```

Verdict:
- **PASS** — every spot-checked claim verified
- **FAIL** — one or more claims unverified despite sub-tasks all closed

When choosing claims, balance coverage and confidence: 2 strong negative claims beat 4 weak file-existence checks. The point is to catch *"epic AC says X, sub-issue closed but X was deferred or never built"*, not to re-run per-story acceptance.

## Phase 4: Act on verdict

### PASS — close the epic

Compose a closeout comment that maps each AC to its delivering sub-issue + PR + merge date. Pull PR numbers and merge dates from the `closedByPullRequestsReferences` query in Phase 1.

```bash
cat > /tmp/epic-closeout-<N>.md <<'EOF'
## Epic closeout — <YYYY-MM-DD>

All <N> sub-issues closed; AC verification PASSED on `origin/develop`.

**Delivery map:**

| Acceptance Criterion | Sub-issue | PR | Merged |
|---|---|---|---|
| <claim 1> | #<sub> | #<pr> | YYYY-MM-DD |
| <claim 2> | #<sub> | #<pr> | YYYY-MM-DD |
| <claim 3> | #<sub> | #<pr> | YYYY-MM-DD |

**Verification commands run:**
```
<command 1>  → PASS
<command 2>  → PASS
```

**Follow-up work captured elsewhere:**
- #<NNN> — <brief description if relevant>

Closing.
EOF

gh issue comment <epic_num> --body-file /tmp/epic-closeout-<N>.md
gh issue close <epic_num> --reason completed
```

### FAIL — flag the gap, draft remediation

Post a comment naming the gap. Then create one Draft remediation story under the epic. If multiple claims fail, list all in one story — never create more than one remediation per epic per run.

```bash
cat > /tmp/epic-acfail-<N>.md <<'EOF'
## Epic AC verification FAIL — <YYYY-MM-DD>

All <N> sub-issues are closed, but the following claim(s) from the epic body could not be verified on `origin/develop`:

- **<claim 1>** — <why: grep returned X matches expected zero / file missing / function not present>
  ```
  <command run>
  <output>
  ```
- **<claim 2>** — <reason>

Drafted remediation story: #<remediation_num>.
Epic stays OPEN until remediation lands.
EOF

gh issue comment <epic_num> --body-file /tmp/epic-acfail-<N>.md

# Create remediation story
cat > /tmp/epic-remediation-<N>.md <<'EOF'
## Parent epic
#<epic_num> — <epic title>

## Gap
The epic's sub-issues are all closed, but AC verification on `origin/develop` failed:

- <claim 1> — <reason, verbatim from the fail comment>
- <claim 2> — <reason>

## Acceptance Criteria
- [ ] <claim 1> satisfied on origin/develop (verifiable via `<command>`)
- [ ] <claim 2> satisfied on origin/develop (verifiable via `<command>`)
- [ ] Re-running /epic-review on #<epic_num> reports PASS

## Notes
Drafted by /epic-review on <YYYY-MM-DD>. Tech Lead to refine implementation notes before dispatch.
EOF

remediation_num=$(gh issue create --repo cfg-is/cfgms \
  --title "remediation: <shortened epic title> — <one-line gap>" \
  --label "epic-followup" \
  --body-file /tmp/epic-remediation-<N>.md | grep -oE '/[0-9]+$' | tr -d /)

item_id=$(/workspace/scripts/project-queue.sh add-issue "$remediation_num" | jq -r '.item_id')
/workspace/scripts/project-queue.sh update-field "$item_id" status Draft
```

### KEEP OPEN — record only

No mutations. Just log the bucket and the current `completed/total` for the report.

## Phase 5: Report

Print one verdict table:

| Epic | Title | Sub-issues | Verdict | Action |
|---|---|---|---|---|
| #1523 | steward job execution | 9/9 | PASS | CLOSED with closeout comment |
| #1754 | controller decoupling | 5/6 | IN PROGRESS | — |
| #XXXX | <title> | N/N | FAIL | Remediation #YYYY drafted |
| #YYYY | <title> | 0/0 | NOT DECOMPOSED | — |

Then a one-line summary: `Reviewed: X. Closed: Y. Remediation drafted: Z. In progress: W. Not decomposed: V.`

## Conventions

- `git fetch origin develop` is mandatory before any AC verification. The skill is designed for long-running sessions where the local checkout drifts behind develop.
- AC spot-check uses 2-4 claims chosen for signal, not coverage. Per-sub-issue exhaustive verification is the acceptance-checker agent's job, not this skill's.
- Closeout comments must cross-link follow-up work that landed in *other* epics — readers should never have to guess whether a deferred concern was tracked forward.
- Maximum one remediation story per epic per run. Multi-claim failures get one story listing all claims.
- Never modify CLAUDE.md, roadmap.md, or any doc the epic itself listed as untouchable per its body.
