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
//   injectFailure: bool              — SELF-TEST ONLY (Issue #2459): replaces all review
//                                       lenses with one synthetic always-failing lens whose
//                                       finding instructs the developer to create a marker
//                                       file. Exercises the snapshot -> fix -> restore path
//                                       end-to-end without real reviewers. Never set in
//                                       production invocations.
//
// Working-tree hygiene (Issue #2459): the developer fix stage edits the invoking
// session's working tree directly (re-review rounds must see the fixes in place,
// so worktree isolation is not an option). Before the FIRST fix round a snapshot
// agent records the exact tree+index state; if the gate ultimately returns
// passed:false, a restore agent saves the abandoned fix-round delta as a diff
// artifact and puts the tree back byte-for-byte (verified by comparing
// `git status --porcelain` before/after — a mismatch is reported loudly in the
// result, never papered over). On passed:true the edits are the deliverable and
// the snapshot is simply left unused (a small dir under /tmp, reported in the
// result for traceability).

export const meta = {
  name: 'story-review',
  description: 'Shared adversarial review-fix-verify gate: parallel reviewers -> collect -> developer fix loop -> structured verdict. Serves /story-complete and entrypoint.sh.',
  phases: [{ title: 'Review' }, { title: 'Fix' }],
}

// args may arrive as a JSON-encoded string rather than an object depending on
// the caller (observed 2026-07-09 on run wf_7e7730d8-36a: an object-shaped args
// value reached the script as a string, silently disabling every option) —
// parse defensively so option flags can never be dropped that way again.
let cfg = args || {}
if (typeof cfg === 'string') {
  try { cfg = JSON.parse(cfg) } catch (e) { log(`WARNING: args was a non-JSON string (${e}); running with defaults`); cfg = {} }
}
const injectFailure = cfg.injectFailure === true
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

// Self-test lens (Issue #2459): always fails, and its finding tells the developer
// to create a marker file — so a run with injectFailure exercises snapshot, a real
// tree-modifying fix round, and the failure-exit restore, deterministically.
const SELFTEST_REVIEWERS = [{
  key: 'selftest',
  thunk: async () => ({
    passed: false,
    summary: 'synthetic always-fail lens (injectFailure self-test)',
    findings: [{
      file: '.story-review-selftest-marker.txt',
      severity: 'blocking',
      detail: 'SELF-TEST: create the file .story-review-selftest-marker.txt at the repo root containing the single line "story-review selftest". Do nothing else. (This lens always fails again afterwards by design.)',
    }],
  }),
}]

const SNAPSHOT_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  required: ['snapDir', 'indexTree', 'baseStash'],
  properties: {
    snapDir: { type: 'string', description: 'absolute path of the snapshot directory' },
    indexTree: { type: 'string', description: 'git write-tree SHA of the pre-fix index' },
    baseStash: { type: 'string', description: 'git stash create SHA of the pre-fix worktree, or empty string if the tree was clean' },
  },
}

const RESTORE_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  required: ['statusMatches', 'rejectDiff'],
  properties: {
    statusMatches: { type: 'boolean', description: 'true iff git status --porcelain is byte-identical to the pre-fix snapshot' },
    rejectDiff: { type: 'string', description: 'absolute path of the saved rejected-fix diff artifact' },
    residual: { type: 'string', description: 'when statusMatches is false: the status diff that could not be reconciled' },
  },
}

// The snapshot/restore agents execute these exact command blocks (workflow
// scripts have no shell access of their own). git stash create snapshots the
// worktree without touching anything; write-tree records the index; untracked
// files are tar-backed-up since neither covers them.
const SNAPSHOT_PROMPT = `You are a mechanical executor. Run EXACTLY this bash block from the repo root (the session cwd), fix nothing, interpret nothing, and report the three printed values in your structured output. If any command fails, report its stderr verbatim in baseStash and set snapDir/indexTree to "ERROR".

set -euo pipefail
git update-index -q --refresh || true
INDEX_TREE=$(git write-tree)
BASE_STASH=$(git stash create "story-review pre-fix baseline" || true)
SNAP="\${TMPDIR:-/tmp}/story-review-snap-$(git rev-parse --short HEAD)-$$"
mkdir -p "$SNAP"
git status --porcelain=v1 > "$SNAP/status-before.txt"
git ls-files --others --exclude-standard > "$SNAP/untracked-list.txt"
if [ -s "$SNAP/untracked-list.txt" ]; then tar -cf "$SNAP/untracked-backup.tar" -T "$SNAP/untracked-list.txt"; fi
echo "SNAP=$SNAP"
echo "INDEX_TREE=$INDEX_TREE"
echo "BASE_STASH=\${BASE_STASH:-}"`

function restorePrompt(snap) {
  return `You are a mechanical executor. Run EXACTLY this bash block from the repo root (the session cwd), fix nothing, interpret nothing, and report the printed MATCH / REJECT_DIFF values (and RESIDUAL content if MATCH=false) in your structured output.

set -u
SNAP="${snap.snapDir}"
INDEX_TREE="${snap.indexTree}"
BASE="${snap.baseStash || 'HEAD'}"
# 1. Preserve the abandoned fix delta BEFORE reverting anything.
git diff --binary "$BASE" > "$SNAP/rejected-fix.diff" 2>/dev/null || true
# 2. Index back to the pre-fix state (staged-new fix files become untracked).
git read-tree "$INDEX_TREE"
# 3. Remove files the fix rounds created (untracked now, absent from baseline).
git ls-files --others --exclude-standard > "$SNAP/untracked-after.txt"
sort "$SNAP/untracked-list.txt" > "$SNAP/.ul.sorted"; sort "$SNAP/untracked-after.txt" > "$SNAP/.ua.sorted"
comm -13 "$SNAP/.ul.sorted" "$SNAP/.ua.sorted" > "$SNAP/created-files.txt"
if [ -s "$SNAP/created-files.txt" ]; then
  tar -cf "$SNAP/rejected-created.tar" -T "$SNAP/created-files.txt" 2>/dev/null || true
  xargs -a "$SNAP/created-files.txt" -r rm -f --
fi
# 4. Worktree content back to the pre-fix snapshot (full tree, restores edits and deletions).
git checkout -f "$BASE" -- . 2>/dev/null || true
# 4b. checkout <tree-ish> -- . writes the index too — put the index back to the
#     pre-fix state a second time or every unstaged edit shows up staged
#     (caught by this script's own status assertion on run wf_eda09145-d08).
git read-tree "$INDEX_TREE"
# 5. Pre-existing untracked files back (fix rounds may have edited or deleted them).
if [ -f "$SNAP/untracked-backup.tar" ]; then tar -xf "$SNAP/untracked-backup.tar"; fi
# 6. Re-delete paths that were deleted in the baseline (checkout may resurrect them).
awk 'substr($0,2,1)=="D" || (substr($0,1,1)=="D" && substr($0,2,1)==" ") {print substr($0,4)}' "$SNAP/status-before.txt" | while IFS= read -r p; do rm -f -- "$p"; done
# 7. Assert byte-identical status.
git update-index -q --refresh || true
git status --porcelain=v1 > "$SNAP/status-after.txt"
if diff -u "$SNAP/status-before.txt" "$SNAP/status-after.txt" > "$SNAP/status-residual.txt" 2>&1; then MATCH=true; else MATCH=false; fi
echo "MATCH=$MATCH"
echo "REJECT_DIFF=$SNAP/rejected-fix.diff"
if [ "$MATCH" = false ]; then echo "RESIDUAL:"; cat "$SNAP/status-residual.txt"; fi`
}

function developerPrompt(findings) {
  const list = findings.map(f => `- [${f.reviewer}] ${f.file}${f.line ? ':' + f.line : ''} — ${f.detail}`).join('\n')
  return `Fix the ROOT CAUSE of each blocking finding below. NO mocks, NO t.Skip, NO hacky workarounds, NO helper-function-instead-of-the-named-fix (when an AC names existing code that must change, change it). Only touch the files under review and their tests.\n\nBlocking findings:\n${list}\n\nAfter fixing, make sure \`make ${testTarget}\` passes.`
}

phase('Review')
const ACTIVE_REVIEWERS = injectFailure ? SELFTEST_REVIEWERS : REVIEWERS
if (injectFailure) log('injectFailure self-test mode: real review lenses replaced by the synthetic always-fail lens')
let round = 0
let toRun = ACTIVE_REVIEWERS
let lastFindings = []
const perRound = []
let passed = false
let snapshot = null

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
  if (!snapshot) {
    // First fix round is about to modify the invoking session's working tree —
    // snapshot it so a failed gate can put everything back (Issue #2459).
    snapshot = await agent(SNAPSHOT_PROMPT, { label: 'fix:tree-snapshot', phase: 'Fix', schema: SNAPSHOT_SCHEMA, effort: 'low' })
    if (!snapshot || snapshot.indexTree === 'ERROR') {
      log('tree snapshot FAILED — aborting before any fix round modifies the working tree')
      return { passed: false, reviewRounds: perRound.length, fixRounds: 0, perRound, remainingFindings: lastFindings, treeRestore: { attempted: false, error: 'snapshot failed; no fix round was run', snapshot } }
    }
    log(`tree snapshot taken: ${snapshot.snapDir} (baseline ${snapshot.baseStash || 'clean@HEAD'})`)
  }
  await agent(developerPrompt(lastFindings), { label: `fix:round${round + 1}`, phase: 'Fix', agentType: 'developer' })
  const failedKeys = new Set(blocking.map(b => b.key))
  toRun = ACTIVE_REVIEWERS.filter(r => failedKeys.has(r.key))
  round++
  phase('Review')
}

// Failed gate after >=1 fix round: the working tree holds unverified rejects.
// Save the delta as an artifact, then restore the tree to the pre-fix snapshot
// (Issue #2459). On a passed run the fix edits ARE the deliverable — keep them.
let treeRestore = null
if (!passed && snapshot) {
  const restored = await agent(restorePrompt(snapshot), { label: 'fix:tree-restore', phase: 'Fix', schema: RESTORE_SCHEMA, effort: 'low' })
  treeRestore = { attempted: true, ...(restored || { statusMatches: false, rejectDiff: `${snapshot.snapDir}/rejected-fix.diff`, residual: 'restore agent returned no result' }) }
  if (treeRestore.statusMatches) {
    log(`working tree restored to pre-fix state; rejected fix diff preserved at ${treeRestore.rejectDiff}`)
  } else {
    log(`WARNING: working tree restore INCOMPLETE — inspect ${snapshot.snapDir}/status-residual.txt and reconcile by hand. Rejected fix diff: ${treeRestore.rejectDiff}`)
  }
} else if (!passed) {
  log('gate failed before any fix round ran — working tree was never modified, nothing to restore')
}

return {
  passed,
  reviewRounds: perRound.length,
  fixRounds: passed ? perRound.length - 1 : perRound.length,
  perRound,
  remainingFindings: passed ? [] : lastFindings,
  treeRestore,
  snapshotDir: snapshot ? snapshot.snapDir : null,
}
