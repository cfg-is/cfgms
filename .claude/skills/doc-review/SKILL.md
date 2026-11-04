---
name: doc-review
description: Review changed documentation for current purpose, accuracy, ownership, and artifact hygiene before PR creation.
context: fork
agent: general-purpose
allowed-tools: Bash, Grep, Glob
---

# Documentation Review Gate

Review the changed documentation, not the whole repository on every story.
Apply `docs/development/standards/documentation-standards.md` and the currency
contract in `docs/development/product-planning.md`.

## Scope and triage

Identify the actual PR base and head. Include added, modified, renamed and deleted
Markdown, agent instructions and relevant config examples. Read affected current
owners and known consumers when necessary.

Run `./.claude/tooling/scripts/pr-review-helper.sh doc-scan` for artifact triage. Its
filename/story-marker hits are candidates, not deletion instructions; `(none)`
is not a review verdict. The helper compares local `develop...HEAD`, so reconcile
its output with the actual PR refs when that local branch is stale or the PR
uses another base. Do not inspect only helper hits.

## Required checks

For every changed document or coherent group, establish:

1. **Purpose:** a concrete current reader task, tool consumer or required evidence.
2. **Owner:** one authoritative contract; remove or consolidate competing rules.
3. **Accuracy:** claims match source and wiring, accepted decisions or approved
   intent, with those categories explicit. Examples match real flags/config keys;
   source inspection alone does not prove runtime verification.
4. **Proportion:** retain the information the task requires; remove generic
   boilerplate, redundant copies and temporary work tracking. A date or line
   count is not a reason by itself to keep or delete anything.
5. **Change safety:** check inbound links/anchors and non-Markdown loaders,
   fixtures, tests and scripts for every move/deletion. Preserve unique relevant
   decision or security evidence, not every adjacent historical memo.
6. **Validation:** run applicable docs structure/link/boundary checks. Report
   examples or operational claims that lack required validation evidence.

Progress/sprint/story-summary naming patterns are strong triage signals. Confirm
actual purpose before removing: a functional test fixture or unique evidence
record may have such a name. Historical headers do not excuse stale guidance.

## Return

Return a compact table: path/group, purpose/owner, disposition, evidence and
remaining finding. Use KEEP, SHORTEN, CONSOLIDATE, REWRITE or DELETE as needed.

PASS requires the changed documentation's relevant checks to pass with no
unresolved acceptance finding. FAIL names each inaccurate claim, competing rule,
unnecessary artifact, broken consumer or required evidence gap and its remedy.
Do not declare PASS solely because the helper found no tracker files. Keep this
review in the normal review response; do not add another permanent audit report
unless the task explicitly calls for one.
