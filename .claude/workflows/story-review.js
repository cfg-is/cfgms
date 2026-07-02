// story-review — shared adversarial review-fix-verify gate.
//
// One implementation for BOTH callers, replacing two hand-maintained (and
// already drifted) copies of the same review team:
//   - /story-complete (interactive):        4 lenses, testTarget=test-quality
//   - .devcontainer/entrypoint.sh (headless -p): 3 lenses, testTarget=test-agent-complete
//
// Flow: parallel reviewers -> collect blocking findings -> developer fix loop
// (re-running ONLY the lenses that failed) -> structured verdict.
//
// The orchestration in this script was validated end-to-end locally (seeded a
// "new production code without a test" defect: reviewers flagged it, the
// developer wrote a real passing table test, only the failed lenses re-ran, and
// it converged with {passed:true, fixRounds:1}). The `tests`/`security` lenses
// below use the same real specialist agents the existing gate already uses.
//
// args:
//   changedFiles: string[]           — files under review (else discovered via git)
//   testTarget: string               — make target for the test lens
//                                       (default 'test-quality'; container passes 'test-agent-complete')
//   includeAcceptanceChecker: bool   — 4th lens (default true; container passes false —
//                                       AC is verified post-PR by the cron acceptance-reviewer)
//   maxRounds: int                   — fix-loop cap (default 3)
//   storyRef: string                 — story/issue reference for the acceptance checker

export const meta = {
  name: 'story-review',
  description: 'Shared adversarial review-fix-verify gate: parallel reviewers -> collect -> developer fix loop -> structured verdict. Serves /story-complete and entrypoint.sh.',
  phases: [{ title: 'Review' }, { title: 'Fix' }],
}

const cfg = args || {}
const files = cfg.changedFiles || []
const filesList = files.length ? files.map(f => `- ${f}`).join('\n') : '(discover changed files via `git diff --name-only origin/develop...HEAD` and `git status`)'
const testTarget = cfg.testTarget || 'test-quality'
const includeAcceptanceChecker = cfg.includeAcceptanceChecker !== false
const maxRounds = cfg.maxRounds || 3
const scopeNote = `Changed files under review:\n${filesList}\n\nReview ONLY these changes; ignore unrelated pre-existing code.`

const VERDICT_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  required: ['passed', 'findings'],
  properties: {
    passed: { type: 'boolean', description: 'true ONLY if there are zero blocking issues' },
    summary: { type: 'string' },
    findings: {
      type: 'array',
      items: {
        type: 'object',
        additionalProperties: false,
        required: ['file', 'severity', 'detail'],
        properties: {
          file: { type: 'string' },
          line: { type: 'integer' },
          severity: { type: 'string', enum: ['blocking', 'warning'] },
          detail: { type: 'string' },
        },
      },
    },
  },
}

// Each reviewer's thunk produces a FRESH agent() call so only the lenses that
// failed a round get re-run after a developer fix.
const REVIEWERS = [
  includeAcceptanceChecker && {
    key: 'acceptance',
    thunk: () => agent(
      `${scopeNote}\nAcceptance reference: ${cfg.storyRef || '(none)'}.\nVerify the working tree delivers the story's named code references (file paths, function names, required test names, banned-phrase removals). Emit a blocking finding for any named symbol/behavior that is missing or still a stub.`,
      { label: 'review:acceptance', phase: 'Review', schema: VERDICT_SCHEMA, agentType: 'acceptance-checker' }
    ),
  },
  {
    key: 'code',
    thunk: () => agent(
      `${scopeNote}\nReview the changed files for test quality. Emit a blocking finding for: new production code without a corresponding _test.go containing functional tests; mocks of CFGMS components; t.Skip without justification; empty assertions; hacky workarounds. If clean, return passed=true with empty findings.`,
      { label: 'review:code', phase: 'Review', schema: VERDICT_SCHEMA, agentType: 'qa-code-reviewer' }
    ),
  },
  {
    key: 'tests',
    thunk: () => agent(
      `Run \`make ${testTarget}\` (tests, lint, builds — no security scans). ${testTarget === 'test-agent-complete' ? 'This is the container target (no Docker).' : ''} Report pass/fail: if it exits non-zero, return passed=false with a blocking finding naming the failing test/package; if it exits zero, return passed=true. Do NOT modify files.`,
      { label: 'review:tests', phase: 'Review', schema: VERDICT_SCHEMA, agentType: 'qa-test-runner' }
    ),
  },
  {
    key: 'security',
    thunk: () => agent(
      `${scopeNote}\nRun all security scans (gosec, Trivy, Nancy, staticcheck, secret scanning) and check-architecture, and review the changed files for vulnerabilities, unsanitized logging (must use logging.SanitizeLogValue), hardcoded secrets, and central-provider violations. Emit blocking findings for genuine issues; passed=true if none. Do NOT modify files.`,
      { label: 'review:security', phase: 'Review', schema: VERDICT_SCHEMA, agentType: 'security-engineer' }
    ),
  },
].filter(Boolean)

function developerPrompt(findings) {
  const list = findings.map(f => `- [${f.reviewer}] ${f.file}${f.line ? ':' + f.line : ''} — ${f.detail}`).join('\n')
  return `Fix the ROOT CAUSE of each blocking finding below. NO mocks, NO t.Skip, NO hacky workarounds, NO helper-function-instead-of-the-named-fix (when an AC names existing code that must change, change it). Only touch the files under review and their tests.\n\nBlocking findings:\n${list}\n\nAfter fixing, make sure \`make ${testTarget}\` passes.`
}

phase('Review')
let round = 0
let toRun = REVIEWERS
let lastFindings = []
const perRound = []
let passed = false

while (round < maxRounds) {
  const results = await parallel(toRun.map(r => () =>
    r.thunk().then(v => ({ key: r.key, v })).catch(e => ({ key: r.key, v: null, error: String(e) }))
  ))
  const blocking = []
  for (const res of results) {
    if (!res) continue
    const { key, v, error } = res
    if (!v) { blocking.push({ key, findings: [{ file: '(agent error)', severity: 'blocking', detail: error || 'reviewer agent errored' }] }); continue }
    const bfs = (v.findings || []).filter(f => f.severity === 'blocking')
    if (v.passed === false || bfs.length) {
      blocking.push({ key, findings: bfs.length ? bfs : [{ file: '(unspecified)', severity: 'blocking', detail: v.summary || 'reviewer reported not-passed' }] })
    }
  }
  perRound.push({ round: round + 1, ran: toRun.map(r => r.key), failed: blocking.map(b => b.key) })
  log(`Round ${round + 1}: ran [${toRun.map(r => r.key).join(', ')}] -> blocking from [${blocking.map(b => b.key).join(', ') || 'none'}]`)
  if (blocking.length === 0) { passed = true; break }
  lastFindings = blocking.flatMap(b => b.findings.map(f => ({ ...f, reviewer: b.key })))
  phase('Fix')
  await agent(developerPrompt(lastFindings), { label: `fix:round${round + 1}`, phase: 'Fix', agentType: 'developer' })
  const failedKeys = new Set(blocking.map(b => b.key))
  toRun = REVIEWERS.filter(r => failedKeys.has(r.key))
  round++
  phase('Review')
}

return {
  passed,
  reviewRounds: perRound.length,
  fixRounds: passed ? perRound.length - 1 : perRound.length,
  perRound,
  remainingFindings: passed ? [] : lastFindings,
}
