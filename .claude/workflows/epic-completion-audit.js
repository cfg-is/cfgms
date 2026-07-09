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
//   Remediate -> (args.remediate) for INCOMPLETE epics, a BA authors remediation
//                stories via create-story for UNCOVERED gaps / annotates already-
//                open covering stories (never duplicating); undecomposed epics get
//                a full decomposition. The BA — not the audit — decides the HOW.
//   Validate  -> a Tech Lead validates each newly-created story for dev-agent
//                executability and promotes passing ones to Ready.
//
// REPRODUCIBLE: deterministic orchestration, always verifies origin/develop
// (never a local checkout), same epic -> same process. Report-only by default;
// close and remediate are separate opt-in flags.
//
// args:
//   epic:        number   — audit ONE epic; omit to sweep every open epic
//   close:       boolean  — default false (dry-run). true => post the closeout
//                           comment and `gh issue close` epics judged COMPLETE.
//   remediate:   boolean  — default false. true => BA files/annotates remediation
//                           stories for INCOMPLETE epics + Tech Lead marks them Ready.
//   founderNotes:object   — { "<epic#>": "architectural decision the BA authors TO" }.
//                           The audit finds the gap; the founder/BA decide the fix —
//                           the audit agent never prescribes an implementation.
//   verifiers:   integer  — adversarial skeptics per epic (default 3, max 3 lenses)
//   founderOwned:number[] — epics never auto-closed in SWEEP mode even if COMPLETE
//                           (default [565]; targeting one explicitly via `epic`
//                           overrides this so a human can still close it on purpose)
//
// Invoke (audit only):  Workflow({ name: 'epic-completion-audit', args: { epic: 565 } })
// Invoke (remediate):   Workflow({ name: 'epic-completion-audit', args: {
//                          epic: 565, remediate: true,
//                          founderNotes: { "565": "interim: register github_runner in the builtin factory like hyperv; do NOT gate on the ADR-006 pull path" } } })

export const meta = {
  name: 'epic-completion-audit',
  description: 'Reproducible epic-completeness + intent-delivery audit: extract intent, map every acceptance criterion to concrete evidence on origin/develop, adversarially verify (skeptics try to refute completeness), emit COMPLETE/INCOMPLETE verdict + closeout comment. Report-only unless args.close.',
  phases: [
    { title: 'Discover' },
    { title: 'Scope' },
    { title: 'Evidence' },
    { title: 'Adversarial' },
    { title: 'Verdict' },
    { title: 'Remediate' },
    { title: 'Validate' },
  ],
}

const cfg = args || {}
const targetEpic = cfg.epic != null ? String(cfg.epic) : null
const doClose = cfg.close === true
// remediate: for INCOMPLETE epics, hand gaps+evidence to a BA to author remediation
// stories (via create-story) / annotate already-open covering stories, then a Tech
// Lead validates each new story and promotes it to Ready. Report-only when false.
const doRemediate = cfg.remediate === true
// founderNotes: { "<epic#>": "architectural decision the BA must author TO" } — e.g.
// { "565": "interim fix = register github_runner in the builtin factory like hyperv;
//   do NOT gate on the ADR-006 pull path" }. The audit finds the gap; the founder/BA
// (not the audit agent) decide the HOW.
const founderNotes = cfg.founderNotes || {}
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

const BA_SCHEMA = {
  type: 'object', additionalProperties: false, required: ['created', 'annotated'],
  properties: {
    created: {
      type: 'array',
      items: {
        type: 'object', additionalProperties: false, required: ['number', 'title'],
        properties: { number: { type: 'integer' }, title: { type: 'string' }, gap: { type: 'string' } },
      },
      description: 'new remediation stories filed via create-story under this epic',
    },
    annotated: {
      type: 'array',
      items: {
        type: 'object', additionalProperties: false, required: ['number'],
        properties: { number: { type: 'integer' }, note: { type: 'string' } },
      },
      description: 'existing OPEN sub-issues updated with the audit gap (NOT duplicated)',
    },
    decomposed: { type: 'boolean', description: 'true if this was a full decomposition of a previously-undecomposed epic' },
    blocked: { type: 'string', description: 'if a gap needs a founder decision you do not have: the specific question (else empty)' },
  },
}

const TL_SCHEMA = {
  type: 'object', additionalProperties: false, required: ['story', 'ready'],
  properties: {
    story: { type: 'integer' },
    ready: { type: 'boolean', description: 'true iff promoted to Ready (passes all executability checks)' },
    revisionNeeded: { type: 'string', description: 'if not ready: exactly what the BA must fix' },
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

const baRemediatePrompt = (epic, bundle, verdict, note) => {
  const { scope } = bundle
  const openCovering = (scope.subIssues || []).filter(s => s.state && String(s.state).toUpperCase() === 'OPEN')
  return `Remediate INCOMPLETE epic #${epic.number} ("${epic.title}"). You are the BA. Author real work via \`./scripts/pipeline-helper.sh\` ONLY (create-story / comment) — never \`gh issue create\`. Ground EVERY code reference with serena before you write it (a wrong symbol becomes a dev-agent gap).

Epic intent: ${scope.intent}
Confirmed gaps (evidence-backed completion audit vs origin/develop):
${(verdict.gaps || []).map((g, i) => `${i + 1}. ${g}`).join('\n') || '(see the epic verdict rationale)'}
Existing OPEN sub-issues (do NOT duplicate — annotate one if a gap is already its scope): ${openCovering.map(s => '#' + s.number).join(', ') || 'none'}
Unlinked drafts to fold in or file: ${(scope.unlinkedDrafts || []).join(' | ') || 'none'}
${note ? `\n>>> FOUNDER ARCHITECTURAL DECISION for this epic — author TO THIS, not your own reading of the code:\n${note}\n` : ''}
Rules:
1. If a gap is already covered by an OPEN sub-issue above, DO NOT create a new story. Instead post the precise audit finding (file:line evidence + what's still missing) to that issue: \`./scripts/pipeline-helper.sh comment <issue> <body-file>\`, and record it in "annotated" — so the dev agent that picks it up knows exactly what remains.
2. For each UNCOVERED gap, create a right-sized remediation story: \`./scripts/pipeline-helper.sh create-story ${epic.number} "<scope>: <title> (under epic #${epic.number})" <body-file>\`. Full spec: ## Goal, ## Story Dependencies, ## Files In Scope, ## Out of Scope, ## Docs In Scope, ## Acceptance Criteria (mark [REQUIRED TEST] where the audit named a missing test). Record each in "created".
3. If this epic has ZERO sub-issues (undecomposed), do a normal full decomposition driven by the audit gaps instead; set decomposed=true. Never exceed 10 stories.
4. If a gap needs a founder decision you do not have (and no founder note above covers it), DO NOT guess — set "blocked" with the specific question and skip that gap.

Return the created / annotated stories.`
}

const tlPrompt = (storyNum, epic) => `Validate story #${storyNum} (just authored to remediate epic #${epic.number}) for dev-agent executability, per your full Tech Lead rubric. Read its body and verify every code reference against origin/develop with serena. If it passes, promote it to Ready (project Status change via \`./scripts/pipeline-helper.sh\` / \`project-queue.sh\`). If it fails, leave it Draft and report exactly what the BA must fix. Return {story:${storyNum}, ready:<bool>, revisionNeeded:<text if not ready>}.`

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

    // Remediate INCOMPLETE epics: BA authors/annotates stories -> Tech Lead validates -> Ready.
    let created = [], annotated = [], readied = [], remediationBlocked = ''
    if (doRemediate && verdict.verdict === 'INCOMPLETE') {
      const ba = await agent(
        baRemediatePrompt(epic, bundle, verdict, founderNotes[String(epic.number)]),
        { label: `ba:remediate:#${epic.number}`, phase: 'Remediate', schema: BA_SCHEMA, agentType: 'ba' },
      )
      created = (ba && ba.created) || []
      annotated = (ba && ba.annotated) || []
      remediationBlocked = (ba && ba.blocked) || ''
      if (created.length) {
        const tlVotes = await parallel(created.map(s => () =>
          agent(tlPrompt(s.number, epic), { label: `tl:validate:#${s.number}`, phase: 'Validate', schema: TL_SCHEMA, agentType: 'tech-lead' }),
        ))
        readied = tlVotes.filter(Boolean).filter(v => v.ready).map(v => v.story)
      }
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
      created,
      annotated,
      readied,
      remediationBlocked,
    }
  },
)

const clean = results.filter(Boolean)
const complete = clean.filter(r => r.verdict === 'COMPLETE')
const closedCount = clean.filter(r => r.closed).length
log(`Done: ${clean.length} audited · ${complete.length} COMPLETE · ${clean.length - complete.length} INCOMPLETE · ${closedCount} closed${doClose ? '' : ' (dry-run)'}.`)
const heldComplete = complete.filter(r => r.founderHeld).map(r => r.epic)
if (heldComplete.length) log(`COMPLETE but founder-owned (not auto-closed): ${heldComplete.map(n => '#' + n).join(', ')} — target explicitly to close.`)

const createdCount = clean.reduce((a, r) => a + ((r.created && r.created.length) || 0), 0)
const readiedCount = clean.reduce((a, r) => a + ((r.readied && r.readied.length) || 0), 0)
const annotatedCount = clean.reduce((a, r) => a + ((r.annotated && r.annotated.length) || 0), 0)
const remediationBlocked = clean.filter(r => r.remediationBlocked).map(r => `#${r.epic}: ${r.remediationBlocked}`)
if (doRemediate) {
  log(`Remediation: ${createdCount} stories created · ${readiedCount} promoted to Ready · ${annotatedCount} existing stories annotated.`)
  if (remediationBlocked.length) log(`Remediation BLOCKED (needs founder decision): ${remediationBlocked.join(' ; ')}`)
}

return {
  audited: clean.length,
  complete: complete.length,
  closed: closedCount,
  remediation: doRemediate ? { created: createdCount, readied: readiedCount, annotated: annotatedCount, blocked: remediationBlocked } : null,
  results: clean,
}
