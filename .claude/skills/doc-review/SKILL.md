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

1. **Find potentially problematic files in the diff**:
   ```bash
   git diff --name-only develop...HEAD -- docs/ | grep -iE '(status|summary|validation|report|review|sprint|milestone|story-[0-9]+)'
   ```

2. **Check for version-specific internal reports**:
   ```bash
   git ls-files docs/ | grep -E 'v[0-9]+\.[0-9]+\.[0-9]+'
   ```

3. **Look for "Story #" references in new docs** (may indicate internal tracking):
   ```bash
   git diff --name-only develop...HEAD -- docs/ | xargs grep -l "Story #[0-9]" 2>/dev/null
   ```

## Classification Rules

**ALWAYS REMOVE** (internal tracking):
- `*-status.md`, `*-progress.md` — Progress tracking
- `INTERNAL_*.md`, `*_REVIEW_STATUS.md` — Internal reviews
- `v[0-9].*-validation.md`, `sprint-*.md` — Sprint reports
- `story-*-summary.md`, `*-implementation-summary.md` — Story summaries

**ALWAYS KEEP** (contributor-facing):
- Security audits (demonstrates due diligence)
- Architecture decision records (ADRs)
- Contributor-facing guides and documentation
- Historical design documents (with "HISTORICAL DOCUMENT" header)

## Decision Tree
```
Does this document help future contributors?
  YES → Keep
  NO  → Does it document completed internal work?
    YES → Remove
    NO  → Keep but mark as historical
```

## Return
- List of problematic files found (with classification)
- PASS if no internal tracking documents detected
- FAIL with file list if internal tracking documents found — blocks PR creation
