// epic-completion-audit — reproducible "is this epic actually DONE, and does the
// delivered work fulfill the epic's INTENT?" audit.
//
// WHY THIS EXISTS
// The epic-review skill decides closeability largely from `subIssuesSummary`
// (N/N sub-tasks closed). That count is not the same as "the intent shipped":
//   - unlinked decomposition drafts carry unbuilt success criteria that never
//     show up in the sub-issue count (this false-closed #2198);
//   - a sub-issue can be CLOSED without a merged PR (won't-do, dedup, manual);
//   - a merged PR can leave a stub / TODO / unwired path that satisfies the
//     checkbox but not the capability the epic promised.
// This workflow verifies the CAPABILITY against real code on origin/develop and
// uses adversarial verifiers whose job is to REFUTE completeness, so a passing
// verdict means "we looked for reasons it's NOT done and couldn't find one."
//
// FLOW (pipelined per epic — each epic advances independently):
//   Discover  -> list open epics (or one, via args.epic)
//   Scope     -> intent + acceptance criteria + sub-issues (delivered-by-merged-PR?)
//                + UNLINKED drafts + merged PRs
//   Evidence  -> map every acceptance criterion to concrete proof on
//                origin/develop (file:line symbol / test name / doc path) or a gap
//   Adversarial -> N independent skeptics, each a distinct lens, TRY TO REFUTE
//                that the intent is fully delivered (skeptical bias)
//   Verdict   -> COMPLETE (evidence + majority-not-refuted, no blocking gap) or
//                INCOMPLETE (gap list + remediation-story specs) + a closeout
//                comment; optionally close COMPLETE epics when args.close is set.
//
// REPRODUCIBLE: deterministic orchestration, always verifies origin/develop
// (never a local checkout), same epic -> same process. Report-only by default.
//
// args:
//   epic:        number   — audit ONE epic; omit to sweep every open epic
//   close:       boolean  — default false (dry-run). true => post the closeout
//                           comment and `gh issue close` epics judged COMPLETE.
//   verifiers:   integer  — adversarial skeptics per epic (default 3, max 3 lenses)
//   founderOwned:number[] — epics never auto-closed in SWEEP mode even if COMPLETE
//                           (default [565]; targeting one explicitly via `epic`
//                           overrides this so a human can still close it on purpose)
//
// Invoke: Workflow({ name: 'epic-completion-audit', args: { epic: 565 } })

export const meta = {
  name: 'epic-completion-audit',
  description: 'Reproducible epic-completeness + intent-delivery audit: extract intent, map every acceptance criterion to concrete evidence on origin/develop, adversarially verify (skeptics try to refute completeness), emit COMPLETE/INCOMPLETE verdict + closeout comment. Report-only unless args.close.',
  phases: [
    { title: 'Discover' },
    { title: 'Scope' },
    { title: 'Evidence' },
    { title: 'Adversarial' },
    { title: 'Verdict' },
  ],
}

const cfg = args || {}
const targetEpic = cfg.epic != null ? String(cfg.epic) : null
const doClose = cfg.close === true
const N_VERIFIERS = Math.max(1, Math.min(3, cfg.verifiers || 3))
const FOUNDER_OWNED = new Set((cfg.founderOwned || [565]).map(String))

// ── schemas ────────────────────────────────────────────────────────────────
const EPIC_LIST_SCHEMA = {
  type: 'object', additionalProperties: false, required: ['epics'],
  properties: {
    epics: {
      type: 'array',
      items: {
        type: 'object', additionalProperties: false, required: ['number', 'title'],
        properties: {
          number: { type: 'integer' },
          title: { type: 'string' },
          nodeId: { type: 'string' },
        },
      },
    },
  },
}

const SCOPE_SCHEMA = {
  type: 'object', additionalProperties: false,
  required: ['intent', 'acceptanceCriteria', 'subIssues', 'unlinkedDrafts', 'mergedPRs'],
  properties: {
    intent: { type: 'string', description: '1-3 sentences: the desired END STATE / capability the epic promises' },
    acceptanceCriteria: { type: 'array', items: { type: 'string' }, description: 'concrete "done when" criteria, from the epic body and its sub-issues' },
    subIssues: {
      type: 'array',
      items: {
        type: 'object', additionalProperties: false, required: ['number', 'state', 'deliveredByMergedPR'],
        properties: {
          number: { type: 'integer' },
          title: { type: 'string' },
          state: { type: 'string' },
          deliveredByMergedPR: { type: 'boolean', description: 'CLOSED and closed by a MERGED PR (not won-fix/dedup/manual)' },
          mergedPR: { type: 'integer' },
        },
      },
    },
    unlinkedDrafts: { type: 'array', items: { type: 'string' }, description: 'decomposition drafts / project items that belong to this epic but are NOT linked as sub-issues — each may carry unshipped success criteria' },
    mergedPRs: { type: 'array', items: { type: 'integer' } },
  },
}

const EVIDENCE_SCHEMA = {
  type: 'object', additionalProperties: false, required: ['criteria', 'allMet'],
  properties: {
    criteria: {
      type: 'array',
      items: {
        type: 'object', additionalProperties: false, required: ['criterion', 'met', 'evidence'],
        properties: {
          criterion: { type: 'string' },
          met: { type: 'boolean' },
          evidence: { type: 'string', description: 'concrete proof on origin/develop (file:line + symbol, test name, doc path) OR why it is absent/a stub' },
          gap: { type: 'string' },
        },
      },
    },
    allMet: { type: 'boolean', description: 'true only if every criterion has real, non-stub evidence on origin/develop' },
  },
}

const REFUTE_SCHEMA = {
  type: 'object', additionalProperties: false, required: ['lens', 'refuted', 'gaps'],
  properties: {
    lens: { type: 'string' },
    refuted: { type: 'boolean', description: 'true if you found the epic intent is NOT fully delivered (skeptical bias: refuted=true when uncertain)' },
    confidence: { type: 'string', enum: ['low', 'medium', 'high'] },
    gaps: { type: 'array', items: { type: 'string' }, description: 'specific reasons the epic is not done (empty only if you genuinely could not refute)' },
  },
}

const VERDICT_SCHEMA = {
  type: 'object', additionalProperties: false, required: ['verdict', 'rationale', 'gaps'],
  properties: {
    verdict: { type: 'string', enum: ['COMPLETE', 'INCOMPLETE'] },
    confidence: { type: 'string', enum: ['low', 'medium', 'high'] },
    rationale: { type: 'string' },
    gaps: { type: 'array', items: { type: 'string' } },
    closeoutComment: { type: 'string', description: 'markdown closeout comment to post iff COMPLETE — cite the concrete evidence per criterion' },
    remediationStories: {
      type: 'array',
      items: {
        type: 'object', additionalProperties: false, required: ['title', 'why'],
        properties: { title: { type: 'string' }, why: { type: 'string' } },
      },
      description: 'if INCOMPLETE: one story per gap, titled per the story convention',
    },
  },
}

// ── prompts ──────────────────────────────────────────────────────────────────
const ORIGIN = 'ALWAYS verify against `origin/develop`, never a local checkout. Run `git fetch origin develop --quiet` first; read code with `git show origin/develop:<path>` or grep a fresh checkout of that ref. A symbol merely existing is not proof it is implemented — read the body and look for stubs (ErrNotImplemented, panic("TODO"), bare `return nil`, empty handlers).'

const scopePrompt = (e) => `Scope epic #${e.number} ("${e.title}") for a completeness audit.

${ORIGIN}

1. Read the epic body: \`gh issue view ${e.number} --repo cfg-is/cfgms --json body,title\`.
2. Distill the epic's INTENT — the desired end-state / capability it promises (1-3 sentences), not a restatement of its tasks.
3. Extract concrete ACCEPTANCE CRITERIA (from the epic body AND from each sub-issue's own acceptance criteria).
4. Enumerate SUB-ISSUES via GraphQL subIssues (number, title, state, and — crucially — whether each CLOSED one was closed by a MERGED PR vs won't-do/dedup/manual):
   \`gh api graphql -f query='query($id:ID!){node(id:$id){... on Issue{subIssues(first:50){nodes{number title state closedByPullRequestsReferences(first:5){nodes{number mergedAt}}}}}}}' -f id="<EPIC_NODE_ID>"\` (get the node id from \`gh issue view ${e.number} --json id\`).
5. Find UNLINKED drafts: decomposition drafts or project items that reference this epic (search issue/PR/project text for "#${e.number}" or the epic title) but are NOT in the sub-issue list — these carry success criteria the sub-issue count misses.
6. List the MERGED PRs that delivered this epic's work.

Return the structured scope. Be exhaustive on acceptanceCriteria and unlinkedDrafts — those are where false-"done" hides.`

const evidencePrompt = (e, scope) => `Map every acceptance criterion for epic #${e.number} ("${e.title}") to CONCRETE evidence on origin/develop.

${ORIGIN}

Intent: ${scope.intent}
Acceptance criteria:
${(scope.acceptanceCriteria || []).map((c, i) => `${i + 1}. ${c}`).join('\n') || '(none extracted — treat the intent itself as the criterion)'}
Sub-issues not delivered by a merged PR: ${(scope.subIssues || []).filter(s => !s.deliveredByMergedPR).map(s => '#' + s.number).join(', ') || 'none'}
Unlinked drafts to account for: ${(scope.unlinkedDrafts || []).join(' | ') || 'none'}

For EACH criterion, find the real proof on origin/develop and record it, verifying by executor-kind / package path (e.g. a steward-hyperv capability lives under features/.../hyperv or cmd/steward, NOT pkg/ha, even though both share cluster/failover vocab). Evidence must be one of: a named symbol at file:line whose body actually implements it, a test that exercises it, a doc/config that ships it. If a criterion's only "proof" is a closed issue with no corresponding code/test, mark met=false with that as the gap. Set allMet=true ONLY if every criterion has real, non-stub evidence.`

const LENSES = [
  {
    key: 'functional',
    focus: `FUNCTIONAL end-to-end delivery. Try to prove the epic's INTENT does not actually work as a capability on origin/develop: trace the real code paths that would deliver it and look for stubs, TODOs, unwired plumbing, a feature reachable in tests but not from any real entrypoint, or a "half" of the capability missing. If you cannot fully trace the promised capability through real code, that is a refutation.`,
  },
  {
    key: 'coverage',
    focus: `COVERAGE / hidden scope. Try to prove there are UNBUILT criteria the sub-issue count hides: unlinked decomposition drafts with unshipped success criteria; sub-issues CLOSED without a merged PR; acceptance criteria in the epic body or a sub-issue body with no corresponding code/test; a "closed 6/6" that silently dropped a criterion. Cross-check every unlinked draft and every non-merged-PR closure.`,
  },
  {
    key: 'evidence',
    focus: `VALIDATION. Try to prove delivery is CLAIMED but not VALIDATED: acceptance criteria whose only evidence is a closed issue or a PR title (not code/tests), behavior with no test exercising it, or docs promising a CLI/API verb that does not exist. "It merged" is not "it works."`,
  },
]

const refutePrompt = (bundle, lens) => {
  const { epic, scope, evidence } = bundle
  return `You are a skeptical epic-completion verifier. Epic #${epic.number} ("${epic.title}"). LENS: ${lens.key}.

${ORIGIN}

Intent: ${scope.intent}
Evidence mapping so far (do NOT trust it — re-check on origin/develop):
${(evidence.criteria || []).map(c => `- [${c.met ? 'MET' : 'GAP'}] ${c.criterion} — ${c.met ? c.evidence : (c.gap || 'no evidence')}`).join('\n') || '(none)'}
Unlinked drafts: ${(scope.unlinkedDrafts || []).join(' | ') || 'none'}
Sub-issues not delivered by merged PR: ${(scope.subIssues || []).filter(s => !s.deliveredByMergedPR).map(s => '#' + s.number).join(', ') || 'none'}

${lens.focus}

Your job is to REFUTE "this epic is fully delivered." Read real code on origin/develop. Default to refuted=true when uncertain — a passing verdict must survive genuine scrutiny. List every specific gap you find (empty gaps only if you truly could not refute).`
}

const verdictPrompt = (bundle) => {
  const { epic, scope, evidence, votes } = bundle
  const refuteCount = votes.filter(v => v && v.refuted).length
  return `Synthesize the completion verdict for epic #${epic.number} ("${epic.title}").

Intent: ${scope.intent}
Evidence allMet: ${evidence.allMet}
Criteria gaps: ${(evidence.criteria || []).filter(c => !c.met).map(c => c.criterion).join(' | ') || 'none'}
Adversarial verifiers refuting: ${refuteCount}/${votes.length}
All verifier gaps:
${votes.flatMap(v => (v && v.gaps) || []).map(g => '- ' + g).join('\n') || '(none)'}

Decision rule (be conservative — false-closing an epic is worse than keeping it open):
- COMPLETE only if evidence.allMet is true AND a majority of verifiers did NOT refute AND there is no blocking gap. Every acceptance criterion must have real, non-stub evidence on origin/develop.
- Otherwise INCOMPLETE. List the concrete gaps and, for each meaningful gap, a remediation story spec (title in the repo's "<scope>: <what> (under epic #${epic.number})" style + why).

If COMPLETE, write a closeoutComment (markdown) that cites the concrete per-criterion evidence so the closure is auditable — not just "all sub-tasks done."`
}

const closePrompt = (epic, verdict) => `Close epic #${epic.number} ("${epic.title}") — it passed the completion audit as COMPLETE.

Post the closeout comment, then close the issue:
1. Write the following to a temp file and post it: \`gh issue comment ${epic.number} --repo cfg-is/cfgms --body-file <file>\`.
   Comment body:
---
${verdict.closeoutComment || 'Epic completion audit: COMPLETE. All acceptance criteria verified against origin/develop.'}
---
2. \`gh issue close ${epic.number} --repo cfg-is/cfgms --reason completed\`
Report CLOSED:${epic.number} on success.`

// ── orchestration ────────────────────────────────────────────────────────────
phase('Discover')
const discovered = await agent(
  targetEpic
    ? `Run \`git fetch origin develop --quiet\`, then \`gh issue view ${targetEpic} --repo cfg-is/cfgms --json number,title,id,state,labels\`. Return it as a one-element epics array ONLY if it is state OPEN and labeled "epic" (put the GraphQL node id in nodeId). If it is closed or not an epic, return {"epics":[]} and say why in your text.`
    : `Run \`git fetch origin develop --quiet\`, then \`gh issue list --repo cfg-is/cfgms --label epic --state open --json number,title,id --limit 100\`. Return every open epic (map the id field to nodeId).`,
  { label: 'discover-epics', phase: 'Discover', schema: EPIC_LIST_SCHEMA, agentType: 'general-purpose' },
)

const epics = (discovered && discovered.epics) || []
if (!epics.length) {
  log(targetEpic ? `Epic #${targetEpic} is not an open epic — nothing to audit.` : 'No open epics to audit.')
  return { audited: 0, closed: 0, results: [] }
}
log(`Auditing ${epics.length} epic(s)${doClose ? ' (close=ON)' : ' (dry-run — report only)'}.`)

const results = await pipeline(
  epics,
  // Scope
  (epic) => agent(scopePrompt(epic), { label: `scope:#${epic.number}`, phase: 'Scope', schema: SCOPE_SCHEMA, agentType: 'general-purpose' })
    .then(scope => ({ epic, scope })),
  // Evidence
  (bundle, epic) => agent(evidencePrompt(epic, bundle.scope), { label: `evidence:#${epic.number}`, phase: 'Evidence', schema: EVIDENCE_SCHEMA, agentType: 'general-purpose' })
    .then(evidence => ({ ...bundle, evidence })),
  // Adversarial — N skeptics in parallel, each a distinct lens
  (bundle) => parallel(
    LENSES.slice(0, N_VERIFIERS).map(lens => () =>
      agent(refutePrompt(bundle, lens), { label: `refute:${lens.key}:#${bundle.epic.number}`, phase: 'Adversarial', schema: REFUTE_SCHEMA, agentType: 'general-purpose' }),
    ),
  ).then(votes => ({ ...bundle, votes: votes.filter(Boolean) })),
  // Verdict (+ optional close)
  async (bundle, epic) => {
    const verdict = await agent(verdictPrompt(bundle), { label: `verdict:#${epic.number}`, phase: 'Verdict', schema: VERDICT_SCHEMA, agentType: 'general-purpose' })
    const founderHeld = FOUNDER_OWNED.has(String(epic.number)) && !targetEpic
    let closed = false
    if (doClose && verdict.verdict === 'COMPLETE' && !founderHeld) {
      const res = await agent(closePrompt(epic, verdict), { label: `close:#${epic.number}`, phase: 'Verdict', agentType: 'general-purpose' })
      closed = typeof res === 'string' && res.includes(`CLOSED:${epic.number}`)
    }
    return {
      epic: epic.number,
      title: epic.title,
      verdict: verdict.verdict,
      confidence: verdict.confidence,
      rationale: verdict.rationale,
      gaps: verdict.gaps || [],
      remediationStories: verdict.remediationStories || [],
      refuted: bundle.votes.filter(v => v && v.refuted).length,
      verifiers: bundle.votes.length,
      evidenceAllMet: bundle.evidence.allMet,
      unlinkedDrafts: bundle.scope.unlinkedDrafts || [],
      closeoutComment: verdict.closeoutComment || '',
      founderHeld,
      closed,
    }
  },
)

const clean = results.filter(Boolean)
const complete = clean.filter(r => r.verdict === 'COMPLETE')
const closedCount = clean.filter(r => r.closed).length
log(`Done: ${clean.length} audited · ${complete.length} COMPLETE · ${clean.length - complete.length} INCOMPLETE · ${closedCount} closed${doClose ? '' : ' (dry-run)'}.`)
const heldComplete = complete.filter(r => r.founderHeld).map(r => r.epic)
if (heldComplete.length) log(`COMPLETE but founder-owned (not auto-closed): ${heldComplete.map(n => '#' + n).join(', ')} — target explicitly to close.`)

return { audited: clean.length, complete: complete.length, closed: closedCount, results: clean }
