---
name: doc-review
description: Scan for internal tracking documents that must be removed before PR creation. Use during story completion to enforce documentation hygiene.
context: fork
agent: general-purpose
allowed-tools: Bash, Grep, Glob
---

# Documentation Review Gate

## Purpose
Detect internal tracking documents in the diff that should NOT be in PRs. These are progress trackers, sprint reports, and story summaries that pollute the repo.

## Scan Steps

Run the doc scan helper (wraps pipe+regex commands to avoid approval prompts):

```bash
./.claude/scripts/pr-review-helper.sh doc-scan
```

Parse the output sections:
- **Changed docs in PR** — Files matching internal tracking patterns (status, summary, report, etc.)
- **Version-specific internal reports** — Files with version numbers in their name
- **New docs with Story references** — Changed docs containing "Story #NNN" references
- `(none)` means that section found nothing

## Classification Rules

**ALWAYS REMOVE** (internal tracking):
- `*-status.md`, `*-progress.md` — Progress tracking
- `INTERNAL_*.md`, `*_REVIEW_STATUS.md` — Internal reviews
- `v[0-9].*-validation.md`, `sprint-*.md` — Sprint reports
- `story-*-summary.md`, `*-implementation-summary.md` — Story summaries

**REVIEW FOR CURRENT PURPOSE** (contributor-facing):
- Security audits and ADRs may retain evidence or decision lineage relevant to
  current constraints; verify their status and references.
- Guides and design documents must describe current behavior or clearly approved
  future direction. Update/consolidate/delete superseded or inaccurate material
  and repair inbound references. A historical header alone is not a reason to keep
  it; Git history preserves prior versions.
- Apply `docs/development/product-planning.md` → Documentation currency.

## Decision Tree
```
Does this document help future contributors?
  YES → Verify current accuracy and purpose; update or consolidate as needed
  NO  → Does it document completed internal work?
    YES → Remove
    NO  → Remove superseded material once its current replacement is established
```

## Return
- List of problematic files found (with classification)
- PASS if no internal tracking documents detected
- FAIL with file list if internal tracking documents found — blocks PR creation
