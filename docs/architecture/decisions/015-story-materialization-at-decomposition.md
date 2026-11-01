# ADR-015: Story Materialization at Decomposition

**Status:** Accepted

**Date:** 2026-07-03

**Deciders:** Founder, PO

**Related:** Epic #1469 (private-draft cutover — the decision this ADR partially supersedes). [008](008-durable-execution-substrate.md) (pipeline substrate). `scripts/pipeline-helper.sh`, `scripts/project-queue.sh`, `.claude/scripts/po-act.sh`, `.claude/scripts/po-cycle-preflight.py` (the machinery this ADR reshapes).

---

## Context

Epic #1469 moved all pipeline work-item tracking to a **private GitHub Projects V2 board** and made GitHub issue creation a **dispatch-time** step: decomposition produced private draft items, and a draft was converted (`convertProjectV2DraftIssueItemToIssue`) into a locked, `internal`-labelled issue only when a dev agent was dispatched on it. The motivations were reducing prompt-injection surface (public issue comments feeding autonomous agents) and keeping un-worked backlog off the public tracker.

Operating this model surfaced a systemic cost: **between decomposition and dispatch, stories had no issue number and no machine-visible linkage to their epic.** Consequences, each observed repeatedly in production:

- **Decomposition state was inferred, not recorded.** The preflight's two signals (epic `sub_issues_total`, `Parent epic: #NNN` body refs on open issues) are both materialization-dependent, so draft-based decompositions were invisible to both. Correctness fell back to a manual "decomposition-complete marker comment" convention — sessions forgot to post it, other sessions failed to find or misread it, and epics were re-flagged (or nearly re-decomposed) as undecomposed.
- **Dependencies could not use real references.** Sibling stories in one decomposition had no `#NNN` at authoring time, forcing `#SIBLING-S1` placeholder tokens and a two-pass create-then-edit flow, plus a manual "promote dependents after siblings merge" follow-up. Placeholder and prose dependencies triggered parser warnings that read as "blocked" to sessions and held stories indefinitely (see the dispatch dep-gate MERGED-PR incident, fixed separately).
- **Session misinterpretation was structural, not behavioral.** Multiple independent failure classes (epics believed undecomposed, drafts believed blocked, duplicated planning) traced to LLM sessions re-deriving state from distributed, convention-dependent signals.

Re-examining what dispatch-time deferral actually protected:

1. **Injection: nothing.** Materialized issues are born **locked** (locked issues accept no external comments), with `lock-sweep` as the idempotent backstop. A locked issue is equally inert whether created at decomposition or at dispatch — the *lock*, not the *deferral*, closes the injection surface.
2. **Leak exposure: a real but narrow window.** The repo is public and GitHub has no private issues, so early creation makes story bodies world-readable for their full queue life instead of only from dispatch to merge. This matters for a minority of bodies (security fixes describing unfixed vulnerabilities, business-adjacent specifics) and is irrelevant for the majority (the project is AGPL with a public roadmap).
3. **Backlog churn: cosmetic.** Killed or re-scoped drafts vanish silently; issues leave closed-as-not-planned noise. Untidy, not unsafe.

## Decision

**Materialize stories at decomposition.** `pipeline-helper.sh create-story` creates the project draft and immediately converts it into a GitHub issue — born **locked**, labelled **`internal` + `story`**, added to the board with its authored Status, and **sub-issue-linked under its epic**. Creation remains convert-based (`project-queue.sh materialize`); nothing in the pipeline runs `gh issue create`, and the `CFGMS_AUTONOMOUS` hook gate is unchanged.

**`--defer` is the exception path.** A story whose body must not be world-readable while queued — a security fix describing a live vulnerability, business/customer specifics — is created with `create-story ... --defer`. It stays a private draft and is materialized by `po-act.sh dispatch` exactly as under the #1469 model. Deferral is a deliberate per-story call, never the default.

**Public-body hygiene becomes a standing authoring rule.** Story bodies are public at creation: no secrets, no credentials, no customer/business specifics, no exploit-grade detail about unfixed vulnerabilities. Content that fails this test either moves to a `--defer` draft or is rewritten.

Corollaries:

- **Dependencies always use real `#NNN`.** Stories are created in dependency order; each `create-story` returns its issue number immediately. `#SIBLING-*` placeholders, the two-pass edit flow, and the promote-after-sibling-merges follow-up are retired.
- **Decomposition state is machine-visible by construction.** Sub-issue links exist from creation, so `sub_issues_total` is authoritative for new epics. The marker-comment convention survives only for the rare epic decomposed *entirely* into `--defer` drafts.
- **The work-product test is unchanged.** Non-repo deliverables (business, legal, ops) remain project items forever and never become issues.
- **Dispatch simplifies.** For the common case the dispatcher receives an issue number and just flips Status and launches; the materialize-at-dispatch branch remains solely for deferred drafts.

## Alternatives Considered

- **Keep drafts, add state machinery** — an `Epic` board field, item-ID dependency references (`item:PVTI_*`), a canonical `epic-state` query command, and preflight lints. Works, but adds a second identity scheme (item IDs alongside issue numbers) and new tooling to maintain, in exchange for a leak-window benefit the `--defer` flag captures at near-zero cost. Rejected as complexity in the wrong place.
- **Private mirror repo for issues** — full confidentiality, but breaks same-repo sub-issue linking, `Fixes #NNN` auto-close ergonomics, and every `#NNN`-based tool in the pipeline. Rejected.
- **Status quo with better session discipline** — repeatedly attempted; misinterpretation is structural (inferred state), not a prompting deficiency. Rejected.

## Consequences

- Story bodies are public for their entire queue life; the hygiene rule and `--defer` carry the confidentiality load previously carried (incidentally) by deferral. **The BA/Tech Lead/PO must apply the hygiene test to every body.**
- Planning churn (re-scoped or dropped stories) is publicly visible as edited or closed-as-not-planned issues. Accepted.
- Issue numbers are consumed at decomposition; a dropped story burns a number. Accepted.
- The preflight's undecomposed-epic detection is now accurate by construction for standard decompositions; its caveat text documents the `--defer`-only edge.
- Existing queued drafts created under the old model continue to work — the dispatch-time materialize path is retained for them and for future `--defer` stories.
