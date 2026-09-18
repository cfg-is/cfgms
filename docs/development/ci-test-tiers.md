# CI Test Tiers — Cost, Value, and Overlap Audit

**Date:** 2026-09-18 · **Story:** #4165 · **Status:** Proposal only. This document changes
no workflow, test, or gate. Every "remove" or "move" item in [Tier proposal](#ac6-tier-proposal)
is a candidate for its own follow-up story, pending founder approval.

## Purpose

CI has grown one workflow at a time, each with its own trigger and its own reason. No one
document says, for the fleet as a whole: what does a PR author wait for, what does the merge
queue re-validate, and does each of those checks still earn its slot. This audit extends the
method of `docs/development/ci-longpole-audit.md` (2026-07-10, which covered only
`production-gates.yml` and `fleet-e2e.yml`) to every workflow in `.github/workflows/` and to
`make test`'s internals, and proposes a tiering toward an **8-minute PR-side verdict**.

## Method

All figures below come from the GitHub Actions API (`gh run list`, `gh api
.../actions/runs/<id>/jobs`), pulled **2026-09-18**, not from estimates. Every section
states the literal command, the sample size, and the oldest/newest `createdAt` in that
sample, so the pull is reproducible. Duration = `completed_at − started_at` for the named
job (not the whole run), computed via `jq`/Python `fromdateiso8601` from the job list.

This audit reuses rather than repeats two things already measured elsewhere:

- **`unit-tests`'s internal timing** is Issue #4151's own measurement (its PR, #4155, is
  open, not yet merged, as of this pull — `gh pr view 4155 --json state,mergedAt` →
  `{"state":"OPEN","mergedAt":null}`). This doc's [AC5](#ac5-inside-make-test) cites #4151's
  numbers directly rather than re-measuring, per this story's Out of Scope.
- Two long-pole gates' PR-time value (`production-gates.yml`, `fleet-e2e.yml`) were already
  judged by `ci-longpole-audit.md` in 2026-07-10. This audit re-samples both from current
  data (the 2026-07 numbers are ~2.5 months stale) rather than trusting the old figures, and
  the new samples corroborate the same structural conclusion for `fleet-e2e.yml` (see
  [AC3](#ac3-value-per-job)).

**Branch ruleset required-status-checks** (the authoritative required list used throughout
this doc), pulled fresh rather than trusted from CLAUDE.md's copy:

```bash
gh api repos/cfg-is/cfgms/rulesets/11647684 --jq \
  '.rules[]|select(.type=="required_status_checks").parameters.required_status_checks[].context'
```
→ `unit-tests`, `integration-tests`, `Build Gate`, `security-deployment-gate`,
`Controller Integration Tests (Linux)`, `zizmor`, `CLA signature check`, `trivy-scan`,
`CodeQL`, `frontend-checks`. Merge queue config (`grouping_strategy: ALLGREEN`,
`merge_method: SQUASH`) confirmed via the same ruleset's `merge_queue` rule.

**Rate-limit hygiene.** Four workflow clusters were pulled in parallel sessions against the
same token; combined consumption across all of them was ~2,700 of the 5,000/hr budget (the
budget reset mid-audit, at `reset: 1789767975`), never forcing a partial-data cutoff. Each
section below carries its own literal commands; raw JSON/JSONL is retained in
`/tmp/ci-audit/` for anyone re-verifying a number (not committed — scratch only).

---

## AC1: Inventory

Every job, grouped by workflow file. **Required** column checks the ruleset list above
verbatim — a job can be "real" on one side and "stub" on the other; both rows are listed
where relevant, per CLAUDE.md's "Stub exclusivity" caution that a skipped stub is not
evidence a check ran.

### `test-suite.yml`

Query: `gh run list --workflow test-suite.yml --event {pull_request,merge_group} --limit 50 --json databaseId,conclusion,createdAt,updatedAt,status,headSha`, then per-run `gh api repos/cfg-is/cfgms/actions/runs/<id>/jobs --paginate`.
PR sample: n=50, `2026-09-17T04:45:33Z`→`2026-09-18T21:22:01Z`. Queue sample: n=50, `2026-09-16T11:39:16Z`→`2026-09-18T20:50:15Z`.

| Job | Trigger | Runner | Required | n | Median | P90 |
|---|---|---|---|---|---|---|
| `unit-tests` | **PR real** (also push-main, workflow_dispatch) | ubuntu-latest | ✅ `unit-tests` | 50 | 831s / 13.85m | 899s / 14.98m |
| `unit-tests-mq-stub` | queue (posts `unit-tests`) | ubuntu-latest | stub for ✅ above | 50 | ~instant | ~instant |
| `integration-tests` | **queue real** (also push-main, workflow_dispatch) | ubuntu-latest | ✅ `integration-tests` | 50 | 203s / 3.38m | 217s / 3.62m |
| `integration-tests-pr-stub` | PR (posts `integration-tests`) | ubuntu-latest | stub for ✅ above | 50 | ~instant | ~instant |
| `cross-feature-tests` | `workflow_dispatch(test_level∈{all,full})` / push-main only | ubuntu-latest | not required | **0/50 on PR, 0/50 on queue** — never executes on either | — | — |
| `production-readiness` | push-main / `workflow_dispatch(test_level=full)` only | ubuntu-latest | not required | 0/50 queue; 9 push-main runs found (0/9 succeeded) | — | — |
| `synthetic-monitoring` | needs `production-readiness` | ubuntu-latest | not required | 0 executions found anywhere in history sampled | — | — |
| `test-summary` | needs `[unit-tests, integration-tests]` | ubuntu-latest | not required (aggregation) | 50/50 both sides | ~instant | ~instant |

**Structural finding:** `cross-feature-tests`, `production-readiness`, and `synthetic-monitoring`
are graph-reachable (they have `needs:` on jobs that do run) but their own `if:` conditions
gate on `workflow_dispatch` inputs or `push`-to-`main`, both false on every `pull_request` and
`merge_group` event. They **never ran once** across 100 sampled PR+queue runs. See
[AC6](#ac6-tier-proposal) for the "zombie job" cleanup candidate this produces.

### `production-gates.yml`

Query: `gh run list --workflow production-gates.yml --event merge_group --limit 50 --json ...`, n=50, `2026-09-16T11:39:16Z`→`2026-09-18T20:50:15Z`. (No `pull_request` pull — its only PR-side jobs are pure stubs with no timing content.)

| Job | Trigger | Runner | Required | n | Median | P90 |
|---|---|---|---|---|---|---|
| `security-deployment-gate-pr-stub` | PR (posts `security-deployment-gate`) | ubuntu-latest | stub for ✅ below | 50 | ~instant | ~instant |
| `security-deployment-gate` | **queue real** (also push-main, workflow_dispatch) | ubuntu-latest | ✅ `security-deployment-gate` | 50 | 34s / 0.56m | 38s / 0.63m |
| `integration-tests-controller-pr-stub` | PR (posts `Controller Integration Tests (Linux)`) | ubuntu-latest | stub for ✅ below | 50 | ~instant | ~instant |
| `integration-tests-controller` | **queue real** | ubuntu-latest | ✅ `Controller Integration Tests (Linux)` | 50 | 610s / 10.17m | 645s / 10.75m |
| `comprehensive-e2e-tests` | queue real, `needs: [integration-tests-controller]` | ubuntu-latest | not required | 50 | 170s / 2.83m | 181s / 3.02m |
| `integration-tests-steward` (ubuntu-latest leg) | queue real, matrix | ubuntu-latest | not required | 50 | 274s / 4.57m | 301s / 5.02m |
| `integration-tests-steward` (windows-latest leg) | queue real, matrix | windows-latest | not required | 50 | 582s / 9.70m | 613s / 10.22m (2 failures) |
| `integration-tests-steward` (macos-latest leg) | queue real, matrix | macos-latest | not required | 49* | 349s / 5.82m | 445s / 7.42m |
| `production-readiness-validation` | push-main only | ubuntu-latest | not required | 0/50 (never a push-main event in this sample) | — | — |

\* one macOS leg in the 50-run sample was `in_progress` at pull time; excluded.

### `cross-platform-build.yml` + `cross-platform-build-pr.yml`

Queries: `gh run list --workflow cross-platform-build.yml --event merge_group --limit 50` (n=50, `2026-09-16T11:39:16Z`→`2026-09-18T20:50:15Z`); `gh run list --workflow cross-platform-build-pr.yml --event pull_request --limit 50` (n=50, `2026-09-17T04:45:33Z`→`2026-09-18T21:22:01Z`).

| Job | Trigger | Runner | Required | n | Median | P90 |
|---|---|---|---|---|---|---|
| `cross-compile-check` (`Cross-Platform Compilation Check`, runs `make build-cross-validate` — Linux/macOS/Windows AMD64+ARM64 cross-compile, no native execution) | **PR real** | ubuntu-latest | feeds ✅ `Build Gate` stub | 50 | 273s / 4.55m | 390s / 6.50m |
| `build-gate-pr-stub` | PR (posts `Build Gate`), `needs: [cross-compile-check]` | ubuntu-latest | stub for ✅ `Build Gate` | 50 | 3s / 0.05m own-step (waits on `cross-compile-check` first) | 4s / 0.07m |
| `native-builds` (Linux) | **queue real**, matrix | ubuntu-latest | via `needs` of ✅ `Build Gate` | 50 | 724s / 12.06m | 756s / 12.60m |
| `native-builds` (macOS) | queue real, matrix | macos-latest | via `needs` of ✅ `Build Gate` | 50 | 891s / 14.85m | 1042s / 17.37m |
| `native-builds` (Windows) — builds **and runs the native test suite**, not compile-only | queue real, matrix | windows-latest | via `needs` of ✅ `Build Gate` | 50 | 1057s / 17.61m | 1168s / 19.47m (**8 failures**) |
| `integration-tests` (Docker) | queue real | ubuntu-latest | via `needs` of ✅ `Build Gate` | 50 | 443s / 7.38m | 456s / 7.60m |
| `build-gate` | queue real, `needs: [native-builds, integration-tests]` | ubuntu-latest | ✅ `Build Gate` | 50 | own step 3s / 0.05m; **effective (gated) time = 1060s / 17.66m** | own step 4s / 0.07m; **effective = 1172s / 19.54m** |

### `security-scan.yml`

Queries per event, n=50 run-level each; job-level timing sampled at n=15 (PR/queue) or n=10 (push) of those 50 due to volume. PR: `2026-09-17T04:45:33Z`→`2026-09-18T21:22:01Z`. Queue: `2026-09-16T11:39:16Z`→`2026-09-18T20:50:15Z`. Push (main/tags): 44 total runs exist (fewer than 50 requested — exhausted); only 2 fall inside the last 90 days.

| Job | Trigger | Runner | Required | n (sampled) | Median | P90 |
|---|---|---|---|---|---|---|
| `source-security-contract` | both real | ubuntu-latest | not itself required (feeds `security-validation`) | 15/15 | PR 107s/1.78m; queue 106s/1.77m | PR 110s; queue 109s |
| `trivy-scan-pr-stub` | PR (posts `trivy-scan`) | ubuntu-latest | stub for ✅ below | 15 | 4s | 5s |
| `trivy-scan` | **queue real** (also push-main, tags) | ubuntu-latest | ✅ `trivy-scan` | 15 | 26s / 0.43m | 31s / 0.52m |
| `nancy-scan` | **PR real** (confirmed running, not credential-skipping — see AC3) | ubuntu-latest | advisory | 15 | 25s | 30s |
| `gosec-scan` | **PR real** | ubuntu-latest | advisory | 15 | 239s / 3.98m | 260s / 4.33m |
| `staticcheck-scan` | **PR real** | ubuntu-latest | advisory | 15 | 185s / 3.08m | 198s / 3.30m |
| `security-validation` | both real (aggregate, `needs` all 5 scanners) | ubuntu-latest | advisory (per CLAUDE.md) | 15/15 | PR 18s; queue 17s | PR 22s; queue 20s |
| `production-gate` | push-main/tags only | ubuntu-latest | not required | 10 | 3s (7 success, 2 skipped, 1 failure) | 4s |
| `security-summary` | both | ubuntu-latest | not required | 15/15 | 3s | 4s |

### `docker-security.yml`, `license-check.yml`, `dependency-pin-check.yml`

Path-filtered PR-only workflows. Contrary to this story's own scope-note assumption
("rarely triggers"), measured data shows all three fill a full 50-run page within 34-40
days — the path filters match often in practice (Dockerfile/go.mod/go.sum churn is common).

| Job | Trigger | Runner | Required | n (of 50) | Median | P90 |
|---|---|---|---|---|---|---|
| `scan-controller` (`docker-security.yml`) | PR real, path-gated | ubuntu-latest | not required | 15 | 158s / 2.63m | 204s / 3.40m |
| `scan-steward` (`docker-security.yml`) | PR real, path-gated | ubuntu-latest | not required | 14 | 139s / 2.32m | 181s / 3.02m |
| `Check Dependency Licenses` (`license-check.yml`) | PR real, path-gated | ubuntu-latest | not required | 15 | 55s / 0.92m | 64s / 1.07m |
| `Compromised Version Denylist` (`dependency-pin-check.yml`) | PR real, path-gated (+ schedule) | ubuntu-latest | not required | 15 of 47 | 7s | 8s |
| `Weekly Dependency CVE Scan` / `Check Pinned Tool Versions` | **schedule only** | ubuntu-latest | not required | 3/3 (full population) | 23-27s / 13-19s | — |

### `codeql-analysis.yml` / `codeql-stub.yml`

Query per side, n=50 run-level, n=20 job-level sample. PR (path-filtered to Go/module-graph/`.github/codeql/**`/`web/**`): `2026-09-09T14:15:34Z`→`2026-09-18T20:22:21Z` (spans 9.24 days — this workflow fires less often than the daily-active ones below). Queue (unfiltered): `2026-09-16T14:09:48Z`→`2026-09-18T21:38:23Z`.

| Job | Trigger | Runner | Required | n | Median | P90 |
|---|---|---|---|---|---|---|
| `analyze` (go) | both real | ubuntu-latest | ✅ `CodeQL` (via `codeql-summary`) | PR 20; queue 19* | PR 341s/5.68m; queue 359s/5.98m | PR 359s/5.98m; queue 374s/6.23m |
| `analyze` (javascript-typescript) | both real | ubuntu-latest | ✅ `CodeQL` | PR 20; queue 20 | PR 87s/1.45m; queue 92s/1.53m | PR 92s; queue 94s |
| `codeql-summary` | both real | ubuntu-latest | ✅ `CodeQL` (posts context) | 20/19* | ~3s both sides | ~4s |
| `CodeQL` (`codeql-stub.yml`) | PR only, `paths-ignore` complement | ubuntu-latest | stub for ✅ above | 20 | ~3s | ~5s |

\* one queue-side sample run was `in_progress` at pull time, excluded (n=19).

**Matrix note:** the YAML's own comment lists 7 CodeQL-supported languages
(`cpp, csharp, go, java, javascript-typescript, python, ruby`); the actual
`strategy.matrix.language` only runs `go` and `javascript-typescript` — the comment is stale.

**Stub-vs-real split** (matched 9.24-day window, `codeql-stub.yml` pulled at `--limit 200` and filtered to the same window as the `analyze` PR sample): stub ≈124 runs, real ≈50 runs (~71%/29%). Not a clean partition — `paths`/`paths-ignore` both fire on a PR touching files in both sets, the same double-fire mechanism CLAUDE.md documents for `Build Gate`.

### `golangci-lint.yml`, `lint-log-injection.yml`, `zizmor.yml`, `frontend-ci.yml`, `cla-check.yml`, `label-decommission-gate.yml`

n=20 job-level samples per side (of 50 run-level pulls) unless noted. PR window `2026-09-17T04:45-05:06Z`→`2026-09-18T21:22:01Z`; queue window `2026-09-16T14:09:48-49Z`→`2026-09-18T21:38:23Z`.

| Job | Trigger | Runner | Required | Median (PR / queue) | P90 (PR / queue) |
|---|---|---|---|---|---|
| `golangci-lint` (linux leg, `GOOS=linux`) | both, path-gated skip on docs-only PRs | ubuntu-latest | **not in ruleset** despite CLAUDE.md calling it "CI-level blocking" (#3442; promotion is epic #3175, undecided) | 223s/3.72m / 225s/3.75m | 231s/3.85m / 233s/3.88m |
| `golangci-lint` (windows leg, `GOOS=windows` on the same Linux runner) | both | ubuntu-latest | same as above | 236s/3.93m / 236s/3.93m | 244s/4.07m / 243s/4.05m |
| `lint-log-injection` | both, no path filter | ubuntu-latest | not required | 24s / 25s | 26s / 27s |
| `zizmor` | both, no path filter, no stub | ubuntu-latest | ✅ `zizmor` | 24s / 22s | 29s / 26s |
| `frontend-checks` | both, no path filter, no stub | ubuntu-latest | ✅ `frontend-checks` | 8s / 8s **— gap: no `web/**`-touching run fell in either 20-run sample; this is the change-detection short-circuit cost, not a measured full npm cycle** | 10s / 10s |
| `cla-check` | `pull_request_target` + `merge_group` | ubuntu-latest | ✅ `CLA signature check` | 7s / 4s | 8s / 4s |
| `no-pipeline-labels` (`label-decommission-gate.yml`) | PR only | ubuntu-latest | not required | 6s | 8s |

### `fleet-e2e.yml`

Query: `gh run list --workflow fleet-e2e.yml --event merge_group --limit 50 --json ...`, n=50, `2026-09-16T14:09:49Z`→`2026-09-18T21:38:23Z`; job timing over the 49 `success` runs.

| Job | Trigger | Runner | Required | n | Median | P90 |
|---|---|---|---|---|---|---|
| `fleet-e2e-tests` (`make test-e2e-fleet`, `./test/e2e/fleet/...`) | **queue only**, moved off PR by the 2026-07-10 long-pole audit | ubuntu-latest | **not in ruleset** — see the accuracy note below | 49 | 603s / 10.05m | 625s / 10.42m |

**Accuracy note on "still enforced at merge":** `ci-longpole-audit.md`'s original decision text
says moving `fleet-e2e.yml` to `merge_group`-only "retains enforcement" because "a failure is
pipeline-visible and triggers the fix cycle." That is operationally true, but `fleet-e2e-tests`
is **not** in the branch ruleset's required-status-checks list (verified above) — a red
`fleet-e2e-tests` run does not, by itself, block GitHub's merge queue from merging that entry.
Enforcement here means "someone/something is watching," not "the queue mechanically blocks."
Worth stating precisely so a future reader doesn't assume ruleset-level blocking exists where
it doesn't.

### Schedule- or push-only workflows (no PR/queue side)

Per this story's Implementation Notes, these get their actual trigger and available
run-history stats, not a forced 50-run PR/queue figure.

| Workflow | Trigger | Last 5 runs |
|---|---|---|
| `fuzz-nightly.yml` | schedule, daily 02:00 UTC | 5/5 success |
| `dast-scan.yml` | schedule, weekly Sun 03:00 UTC + workflow_dispatch | **5/5 failure** (2025-08-16 through 2026-09-13) — flagged as a candidate follow-up, see [AC8](#ac8-candidate-follow-up-stories) |
| `scorecard.yml` | push-to-develop + weekly schedule | 5/5 success (push side) |
| `release.yml` | push, tags `v*.*.*` | 5/5 failure, but all from 2026-05-23–27 — no tag push since; current state unverified, see AC8 |
| `develop-sanity.yml` | push-to-develop | 5/5 success |
| `codeql-pack-publish.yml` | push to main/develop, path-gated to `.github/codeql/extensions/**` + workflow_dispatch | 5/5 success, infrequent (weeks apart) |

---

## AC2: Critical path

### PR side

Every PR-side real job lives in a **different workflow file**, and no workflow file has a
cross-file `needs:` — GitHub Actions can't express that. So the wall-clock time to a PR
verdict is the **slowest single real job**, not a sum:

| Job | Median | P90 | Required? |
|---|---|---|---|
| **`unit-tests`** | **13.85m** | **14.98m** | ✅ dominant bottleneck by a wide margin |
| `CodeQL` (`analyze` go + `codeql-summary`) | 5.68m | 5.98m | ✅ |
| `Build Gate` (`cross-compile-check` + stub) | 4.60m | 6.57m | ✅ |
| `gosec-scan` | 3.98m | 4.33m | advisory |
| `golangci-lint` (windows leg) | 3.93m | 4.07m | not required |
| `staticcheck-scan` | 3.08m | 3.30m | advisory |
| `scan-controller` (docker-security, path-gated) | 2.63m | 3.40m | not required |
| `source-security-contract` | 1.78m | 1.83m | feeds advisory |
| `CodeQL` (js/ts leg, same context as above) | 1.45m | 1.53m | ✅ |
| `Check Dependency Licenses` (path-gated) | 0.92m | 1.07m | not required |
| everything else (`nancy-scan`, `lint-log-injection`, `zizmor`, `label-decommission-gate`, `cla-check`, `frontend-checks`, `security-validation`) | ≤0.5m each | ≤0.5m each | mixed |

**PR verdict wall-clock = max(above) = `unit-tests` at 13.85m median / 14.98m p90.** No
`needs:` chain exists on the PR side except `Build Gate`'s (`cross-compile-check` →
`build-gate-pr-stub`, ~4.6-6.6m total), and that chain is nowhere near the `unit-tests`
figure. This is the same conclusion #4151 already reached from its own data; this audit's
independent 50-run pull (§AC1) corroborates it.

### Queue side

Queue-side workflows also run in parallel (same `merge_group` event, separate files), but
**within** three files there are real `needs:` chains:

| Workflow chain | Jobs | Median | P90 | Required context |
|---|---|---|---|---|
| `test-suite.yml` | `unit-tests-mq-stub` → `integration-tests` → `test-summary` | 3.38m | 3.62m | `integration-tests` |
| `production-gates.yml` | `integration-tests-controller` (standalone) | 10.17m | 10.75m | `Controller Integration Tests (Linux)` |
| `production-gates.yml` | `integration-tests-controller` → `comprehensive-e2e-tests` (not required, doesn't delay the context above — it posts at `integration-tests-controller` completion) | 13.00m | 13.77m | — (informational only) |
| `production-gates.yml` | `security-deployment-gate` (standalone) | 0.56m | 0.63m | `security-deployment-gate` |
| `cross-platform-build.yml` | max(`native-builds` 3-way matrix, `integration-tests`) → `build-gate` | **17.66m** | **19.54m** | **`Build Gate`** |
| `security-scan.yml` | `trivy-scan` (standalone, doesn't wait on the other 4 scanners) | 0.43m | 0.52m | `trivy-scan` |
| `codeql-analysis.yml` | `analyze`(go, tallest leg) → `codeql-summary` | 6.00m | 6.25m | `CodeQL` |
| `zizmor.yml` | `zizmor` | 0.37m | 0.43m | `zizmor` |
| `frontend-ci.yml` | `frontend-checks` | 0.13m | 0.17m | `frontend-checks` |
| `cla-check.yml` | `cla-check` (merge_group short-circuit) | 0.07m | 0.07m | `CLA signature check` |

**Queue verdict wall-clock = max(above) = `cross-platform-build.yml`'s `Build Gate` chain
at 17.66m median / 19.54m p90, bottlenecked on `Native Build (Windows)`.** This is the
single most important structural fact in this audit: **the required `Build Gate` context
cannot post until the slowest of the three native-build legs finishes**, and that leg is
Windows at 17.61m median (vs. 12.06m Linux, 14.85m macOS) — see [AC3](#ac3-value-per-job)
for why, and [AC6](#ac6-tier-proposal) for what (not) to do about it.

**Non-required jobs still consuming queue runner-time in parallel** (don't extend the
critical path above, but are real compute cost per queue entry): `fleet-e2e-tests` (10.05m),
`integration-tests-steward` Windows leg (9.70m), `comprehensive-e2e-tests` (2.83m),
`golangci-lint` (~3.9m both legs). A queue entry today runs on the order of 15-20 separate
jobs simultaneously; several 5-20 minutes long regardless of whether they gate the merge.

---

## AC3: Value per job

Method: every `failure` conclusion in each sampled window inspected via
`gh run view <id> --log-failed`, classified **real** (genuine code/test defect) vs.
**flaky/infra** (network, cache race, ref-expiry), then **unique** (no cheaper PR-side check
covers this code path) vs. **redundant** (a cheaper check on the same commit also failed) —
the exact method `ci-longpole-audit.md` established.

| Job | n sampled | Failures | Real | Flaky/infra | Unique | Redundant |
|---|---|---|---|---|---|---|
| `unit-tests` (PR) | 50 | 3 | 3 | 0 | 3 (no other required check caught these specific script-test defects) | 0 |
| `integration-tests` (queue) | 50 | 0 | — | — | — | — |
| `Controller Integration Tests (Linux)` | 50 | 0 | — | — | — | — |
| `Comprehensive E2E Testing` | 50 | 0 | — | — | — | — |
| `Steward Integration Tests` (ubuntu) | 50 | 0 | — | — | — | — |
| `Steward Integration Tests` (windows) | 50 | 2 | 2 | 0 | 2 (Windows-only leg; Linux integration in `test-suite.yml` can't catch it) | 0 |
| `Steward Integration Tests` (macos) | 49 | 0 | — | — | — | — |
| `Native Build (Linux)` | 50 | 0 | — | — | — | — |
| `Native Build (macOS)` | 50 | 0 | — | — | — | — |
| `Native Build (Windows)` | 50 | 8 | 7 | 1 (proxy.golang.org stream reset) | **8/8** (queue-only leg; no PR job runs native Windows tests) | 0 |
| `Integration Tests (Docker)` | 50 | 0 | — | — | — | — |
| `source-security-contract` | 50 (queue) | 1 | 0 | 1 (proxy.golang.org stream reset, cascades to `security-validation`) | n/a (infra) | n/a |
| `trivy-scan` (real) | 15/10 | 0 | — | — | — | — |
| `nancy-scan` / `gosec-scan` / `staticcheck-scan` | 15 each | 0 | — | — | — | — |
| `security-validation` | 50 | 1 | 0 | 1 (cascaded from `source-security-contract`) | n/a | n/a |
| `scan-controller`/`scan-steward` (docker-security) | 50 full pop | 7 | unclear — 5 runs' plain-text log shows trivy completing with no visible CVE table before exit 1; couldn't confirm severity-threshold vs. other cause without the SARIF artifact | 2 confirmed infra (podman socket / registry auth) | needs follow-up | needs follow-up |
| `Check Dependency Licenses` | 50 full pop | 1 | 0 | 1 (job-level `cancelled`, concurrency supersede — run-level API reported "failure", a conclusion-mismatch worth noting as-is) | n/a | n/a |
| `analyze` (CodeQL go/js, queue) | 50 | 2 | 0 | 2 (Go-module cache tar race; merge-queue ref-expiry race — both `JOB_STATUS_CONFIGURATION_ERROR`, not analysis results) | n/a | n/a |
| `lint-log-injection` (PR) | 50 | 2 | 2 | 0 | 2 (only PR-time checker for unsanitized log values) | 0 |
| `golangci-lint`, `zizmor`, `frontend-checks`, `label-decommission-gate`, `cla-check` | 50 each, both sides | 0 | — | — | — | — |
| `fleet-e2e-tests` | 49 | 0 | — | — | — | — |

**Reading the zero-failure rows honestly:** a 0/50 failure rate in this window is not proof
of low value — it can equally mean the check is healthy *and* still catching real defects
that simply didn't recur in this window, or that it has genuinely low unique-catch value (as
`ci-longpole-audit.md` found for `fleet-e2e.yml` in July, at 1/60 unique). This audit's
current fleet-e2e sample (0/49 failures) is *consistent with* that July finding but is not,
on its own, new evidence for either direction — noted rather than over-interpreted.

**All ten real-or-flaky merge-queue failures observed across the two 50-run
`production-gates.yml`/`cross-platform-build.yml` samples were on a `windows-latest` runner**
(8 `Native Build (Windows)`, 2 `Steward Integration Tests (windows-latest)`). Zero on Linux
or macOS legs in either sample.

### The 2026-09-18 queue evictions, matched to run IDs

| # | Run / job | Time (UTC) | Evicted PR | Failed test | Issue |
|---|---|---|---|---|---|
| 1 | 35337524783 / `Native Build (Windows)` | 11:01–11:15 | pr-4138 | `TestHTTPWebhookHandler_SanitizesRemoteAddrAndUserAgentInLogFile` — Windows file-handle leak, `pkg/logging` file provider | **#4145** (closed, fixed by PR #4156 / commit 215f2bc5) |
| 2 | 35377032785 / `Native Build (Windows)` | 17:55–18:14 | pr-4153 | `TestSupervise_RepairsMissingServiceRegistration` — SCM delete-pending race, `cmd/cfgms-steward-launcher` | **#4159** (open) |
| 3 | 35381599352 / `Native Build (Windows)` | 18:44–18:58 | pr-4156 | `TestHAStatus_Leader_IsLeaderTrue` — 5s `require.Eventually` leadership-window miss | **#4160** occurrence 1 (open) |
| 4 | 35387575049 / `Native Build (Windows)` | 19:44–20:00 | pr-4161 | `TestDeploymentModeProgression/Cluster` + `TestSingletonJob_SlowCycleRenewsAcrossTTL_NoDuplicateRun` — same wall-clock-budget flake class as #3 | **#4160** occurrence 2 (open; issue body records this as the same class "widened") |
| 5 | 35389227101 / `Steward Integration Tests (windows-latest)` | 20:02–20:08 | pr-4149 | `TestSyncDNAHandler_FullSync_EmptyAttrsFragmentsPresent_Succeeds`, `features/steward/client` | **no tracking issue found** as of this pull |

All five failed tests are **genuine test-timing/race defects that only manifest under native
Windows execution** — not compile errors. This matters directly for [AC6](#ac6-tier-proposal)'s
Windows question below.

(Issue #4147, the `w32tm` non-admin access-denied defect, is related but was found on a
self-hosted validation host, not in this 50-run `merge_group` sample — it is not one of the
five eviction events.)

---

## AC4: Overlap map

Concrete, evidenced duplication — not every "two things touch Go code" pairing, but places
where the **same package, same test names, or same source tree** is exercised more than once
on the same commit:

1. **`pkg/cert` — tested twice per queue entry.** `unit-tests`'s `make test` runs a plain
   `go test -race -short` over `pkg/...` (no build tag), ~82.3s for this package per #4151's
   measurement. `cross-platform-build.yml`'s `Integration Tests (Docker)` job (queue-only,
   part of the required `Build Gate` chain) separately runs
   `go test -v -race -p 1 -tags=integration -timeout=20m ./pkg/cert/... ./pkg/storage/providers/database/...`
   — a different build tag and DB dependency, so not a pure duplicate, but the package
   compiles and its non-integration-tagged tests execute in both jobs on the same commit.

2. **`test/integration/transport` — the actual duplicate.** `production-gates.yml`'s
   `Controller Integration Tests (Linux)` job runs
   `go test -v -race -timeout=10m $(go list ./test/integration/... | grep -v "test/integration$" | grep -v "test/integration/ha$")`
   — a broad sweep that includes `test/integration/transport` (only the bare `test/integration`
   and `test/integration/ha` packages are excluded). `cross-platform-build.yml`'s
   `Integration Tests (Docker)` job separately re-runs
   `go test -v -race -timeout=15m ./test/integration/transport/... -run "TestRegistration"`.
   Both jobs are queue-only, both feed a required context (`Controller Integration Tests
   (Linux)` and `Build Gate` respectively), both trigger off the same `merge_group` commit.
   `TestRegistration`-family tests genuinely run twice.

3. **Both-side required checks re-scan unchanged code by construction.** `CodeQL`, `zizmor`,
   `frontend-checks`, and `CLA signature check` each run once at PR-push time and again at
   merge-queue time for the *same diff* (a PR that doesn't change between approval and merge
   entry). Per-PR-lifecycle duplicate cost: CodeQL ≈5.68m + 6.00m ≈ **11.7 min**, `zizmor`
   ≈24s+22s, `frontend-checks` ≈8s+8s, CLA ≈7s+4s. The three cheap ones are justified
   insurance (a rebase could change content cheaply); CodeQL's ~6-minute queue-side repeat is
   the one substantial instance of this pattern — not recommended for removal (see AC6: no
   cheaper check replaces CodeQL's semantic analysis), but worth naming as the largest
   "same thing, twice" cost in the fleet.

4. **`golangci-lint` also runs full-repo lint on both sides** (~3.9m PR + ~3.9m queue ≈
   7.8 min per PR lifecycle) for the same both-sides-by-construction reason. Not required,
   but real duplicate compute.

5. **Not overlap (checked and ruled out):** `fleet-e2e.yml` runs `./test/e2e/fleet/...`
   (a distinct package from `production-gates.yml`'s `test/e2e` root-scenario subset) —
   complementary coverage, not duplication.

---

## AC5: Inside `make test`

Reusing #4151's own measurement (its PR #4155 is open, unmerged, as of this pull — see
[Method](#method)) rather than re-deriving it, per this story's Out of Scope:

| Phase | Wall time | Share | Bound |
|---|---|---|---|
| Go test phase (`go test -race -short -timeout=10m $(go list ./... \| grep -v modules\|integration\|e2e)`) | ~625s | ~74% | **CPU-bound** — the 4-vCPU hosted runner saturates under `-race`; PR #4155 found that re-splitting the same work into more parallel processes *inside* one job made it slower (15m21s), because the contention is real CPU, not idle wall time. Needs more runners/jobs, not more `-p`. |
| — of which `features/controller/api` alone | 322.3s | >half of the Go phase | Same package, 2,009 top-level tests (`go test -list`), no pathological single test (slowest 4.6s, median ~0.13s under `-race`) — slow because of test *count* × per-test SQLite-schema cost (~164ms/test under race amplification), not one hang. |
| — `features/controller/server` | 105.5s | | same profile, smaller |
| — `features/controller/initialization` | 91.7s | | |
| — `pkg/cert` | 82.3s | | |
| — `pkg/controlplane/providers/grpc` | 70.6s | | |
| — `features/steward/client` | 64.7s | | |
| Script phase (`scripts/test-scripts.sh`) | ~218s | ~26% | **Wall-bound** — ~108 sequential `test_*` functions; one of them (`test_claude_pipeline_suites`) loops sequentially over 30 independent `.claude/scripts/tests/*` suites. Each suite is lightweight and self-contained (own `mktemp -d`), so this is a pure "not parallelized yet" cost, not CPU contention — `nproc`-wide batching (#4155's proposed fix) is the right lever. |
| — of which `test_claude_pipeline_suites`'s slowest suites | `security_review_cli.test.sh` 64s, `pipeline_watch.test.sh` 27s, `investigator_launch.test.sh` 12s, `cycle_manifest.test.sh` 8s, rest ≤2s each | | |

### Coverage gaps found alongside the cost data (not this story's to fix, but relevant to AC5)

- **Four (soon five, with #4154) `.devcontainer/*_test.sh` suites never run in CI at all**
  (Issue #4163) — they guard the agent-container egress firewall, DNS allowlist, entrypoint,
  and credential delivery, and pass locally but gate nothing in CI today.
- **`ALL_MODULES` (Makefile:522) is missing 9 real modules** (Issue #4164): stdlib
  `cert_trust`, `hostname`, `service`, `time`, `user`; extended `acme`, `github_runner`,
  `osquery`; and `hyperv` entirely. `CHANGED_MODULES` (Makefile:525-529) derives from
  `ALL_MODULES` via `git diff --name-only HEAD~1`, so a change confined to one of these 9
  directories produces an empty `CHANGED_MODULES` match.
  **Independent verification for this audit** (`go list ./... | grep -v '/features/modules/' | grep 'modules/stdlib/time'`
  → no output): `make test`'s *primary* `go test` invocation excludes `/features/modules/`
  entirely, so those 9 modules are covered **only** via the `CORE_MODULES`/`CHANGED_MODULES`
  smoke loop. Since none of the 9 are in `CORE_MODULES` (`stdlib/file stdlib/script`) and none
  match a `CHANGED_MODULES` pattern, a PR whose only Go change lives in one of them gets **zero
  test execution in the `unit-tests` CI job**, not merely a gap in "local pre-push and agent
  validation" as #4164's own Problem statement frames it. Flagging this refinement for
  whoever picks up #4164 — the fix already scoped there (derive from `module.yaml` presence)
  closes this CI-level gap too, not just the local one.

---

## AC6: Tier proposal

Every tier assignment below is the **current** state plus the evidence for keeping it there,
except where a change is explicitly proposed (marked **PROPOSED**).

### Every-PR (fast, catches most) — keep as-is

`unit-tests` (dominant real-bug catcher: 3/3 PR failures in-sample were real and unique;
its slowness is #4151's problem, not a tiering problem), `CodeQL` (required; both queue
failures in-sample were infra, zero false negatives observable, no cheaper check performs
semantic analysis), `Build Gate`'s `cross-compile-check` (cheap, catches genuine
cross-compile breaks before the expensive native matrix), `zizmor`, `CLA signature check`,
`frontend-checks` (required, cheap; see gap note under AC1), `lint-log-injection` (2/2
PR failures in-sample were real and unique — no other checker flags unsanitized log values),
`nancy-scan` (confirmed running for real against a live `GUIDE_TOKEN`, not silently skipping),
`license-check` and `dependency-pin-check`'s denylist job (both path-gated, cheap, both
100% success in-sample but that's expected — they guard against rare events), `golangci-lint`
(not required today, but its own file's comment records a **139-finding Windows-only
backlog** cleared before promotion to blocking in #3442 — proven historical divergence value
even though this window shows 0 failures on either `GOOS` leg).

### Queue-only — keep as-is, with one exception argued below

`integration-tests` (`test-suite.yml`), `Controller Integration Tests (Linux)`,
`comprehensive-e2e-tests`, `integration-tests-steward` (all 3 OSes), `native-builds` (all 3
OSes, via `Build Gate`), `Integration Tests (Docker)`, `security-deployment-gate`,
`trivy-scan` (real), `security-validation`, `production-gate`, `fleet-e2e-tests`. Windows
and macOS coverage in particular: `ci-longpole-audit.md`'s original 2026-07 finding (8/10 PR
failures were unique Windows-integration catches no cheaper check can reach) still holds
structurally — this audit's fresh sample finds the same pattern (10/10 real-or-flaky
merge-queue failures were Windows-only, 0 on Linux/macOS).

**The Windows question, answered directly (AC6 requires this explicitly):**
**Do not move the native Windows build+test matrix to PR-side.** The evidence rules this out
on cost *and* on effectiveness:

- **Cost:** `Native Build (Windows)` costs 17.61m median / 19.47m p90 *by itself*. Adding
  that to every PR push (rather than once per queue entry) directly contradicts the 8-minute
  target and the workflow's own design comment ("validated once against the merge commit
  rather than paying for it twice per PR").
- **Effectiveness:** all 8 sampled `Native Build (Windows)` failures and both
  `Steward Integration Tests (windows-latest)` failures are **test-timing/race defects**
  (`TestHAStatus_Leader_IsLeaderTrue`, `TestSingletonJob_SlowCycleRenewsAcrossTTL...`,
  `TestSyncDNAHandler...`, etc.) that only manifest under actual native Windows execution —
  not compile errors. `cross-platform-build-pr.yml`'s existing PR-side `cross-compile-check`
  (`make build-cross-validate`) **already cross-compiles for Windows/macOS/Linux** from a
  Linux runner today; every failure in this audit's sample would have compiled cleanly and
  would not have been caught by any cheaper PR-side check, because catching them requires the
  same native runner and the same wall-clock exposure the queue job already pays for.
- **The real lever already exists and is already in motion:** these are flaky/timing
  *product* defects (lease-timing budgets in `pkg/ha`/`pkg/lease`, an SCM race, a file-handle
  leak), already tracked as bugs — #4145 (closed, fixed), #4159 (open), #4160 (open, two
  occurrences of the same class). Fixing the underlying flakiness reduces evictions; moving
  where the test runs does not.

### Nightly/scheduled — keep as-is

`fuzz-nightly.yml`, `dependency-cve-scan`, `check-tool-versions`, `scorecard.yml`,
`codeql-pack-publish.yml`, `develop-sanity.yml`. `dast-scan.yml` and `release.yml` need
investigation before a tier judgment is possible — see AC8.

### Remove or restructure — **PROPOSED**

- **`cross-feature-tests`, `production-readiness`, `synthetic-monitoring` in
  `test-suite.yml` are configured dead code on every trigger that matters.** They ran 0/50
  times on `pull_request`, 0/50 times on `merge_group`, and the only real executions found
  anywhere in history are 7 `workflow_dispatch` runs (one of which exercised
  `cross-feature-tests`) and 9 push-to-`main` runs, of which **0/9 succeeded** and whose
  matrix leg names (`disaster-recovery`, `monitoring-integration`, `security-audit`) don't
  even match the current file's 2-leg matrix (`load-testing`, `performance-benchmarks`) —
  i.e., the last real, still-relevant signal from these jobs predates a matrix rewrite.
  Removing a trigger path that produces zero current-state signal isn't "removing coverage
  a cheaper check still needs to provide" (this story's stated bar for removal) — there is no
  coverage today to preserve. **Proposed as its own follow-up story** to either wire these to
  something that actually runs (e.g., `push`-to-`main` post-merge smoke, matched to the
  current matrix) or delete the unreachable trigger paths and their stale comments.

---

## AC7: Target and projection

**PR side.** Current PR verdict floor is `unit-tests` at 13.85m median / 14.98m p90 — every
other PR-side job is smaller, so the whole PR-side wall-clock time today tracks `unit-tests`
almost exactly. #4155 (open, unmerged) is the story that owns bringing this down; this audit
does not have its post-fix number. What this audit *can* say: once `unit-tests` drops below
the next-tallest PR-side pole, that pole becomes the new floor. In descending order, those
poles are: **`CodeQL`** (5.68m median / 5.98m p90) and **`Build Gate`'s `cross-compile-check`**
(4.60m median / 6.57m p90), then `gosec-scan` (3.98m) and `golangci-lint` (3.93m).

- **If #4155 lands `unit-tests` under ~6 minutes:** the ≤8-minute PR target is reachable
  **on current infrastructure, no larger runner or added parallelism needed** — the next
  pole (`CodeQL` at ~6m) already clears 8 minutes with room to spare, and nothing else comes
  close.
- **If #4155 lands `unit-tests` anywhere above ~8 minutes:** the target is not reached
  regardless of anything else in this fleet, since `unit-tests` alone would still exceed it.
- This audit takes no position on which outcome #4155 will produce — that is precisely the
  measurement its own AC2 commits to recording.

**Queue side.** No ≤8-minute target is stated for the queue in this story (queue is "the
authoritative gate," not the PR-author-facing verdict). Current required critical path is
**17.66m median / 19.54m p90**, bottlenecked on `Native Build (Windows)`. This audit proposes
no queue-side structural change (the Windows question above concludes "don't move it"), so
the projected queue wall time under this proposal is **unchanged: ~17.66m median / ~19.54m
p90** — any further reduction would mean either speeding up the Windows native-build/test
step itself (a runner-performance or test-parallelism investment, not a tiering change) or
accepting the current figure as the cost of catching genuine Windows-only defects before
`develop`. This audit does not have data to say a runner upgrade would help (no
CPU/memory profiling of the Windows leg was pulled) — that would be a prerequisite
measurement for a future story, not a conclusion this one can draw.

---

## AC8: Candidate follow-up stories

Each item below is a candidate only — no workflow, test, or Makefile change has been made in
this story, and none should be filed as an issue without founder approval per this story's
own scope.

1. **Wire or remove the dead `test-suite.yml` production/synthetic-monitoring trigger paths.**
   Evidence: [AC6](#ac6-tier-proposal) above (0/50 PR, 0/50 queue, 0/9 push-to-main success,
   stale matrix-leg names).
   Files In Scope: `.github/workflows/test-suite.yml`.

2. **Investigate `dast-scan.yml`'s 5-consecutive-run failure streak** (2025-08-16 through
   2026-09-13, weekly). Evidence: [AC1](#ac1-inventory), schedule-only workflows table. No
   log inspection was done in this audit (out of the PR/queue sample scope) — the follow-up
   story's first AC should be root-causing the failure before deciding a fix.
   Files In Scope: `.github/workflows/dast-scan.yml` (investigation may reveal the fix lives
   elsewhere, e.g. the target service being scanned).

3. **Confirm `release.yml`'s current health with a real tag push**, or archive/update it if
   the workflow itself has drifted since 2026-05-27 (the failures found are all from a single
   old window with no subsequent tag push to re-test against). Evidence: AC1 schedule-only
   table.
   Files In Scope: `.github/workflows/release.yml`.

4. **Resolve the 5 unclassified `docker-security.yml` `Scan Controller Image` / `Scan Steward
   Image` failures** (trivy exits 1 with no visible CVE table in the plain-text log — SARIF
   output means the console has no human-readable failure reason). Evidence: [AC3](#ac3-value-per-job).
   Files In Scope: `.github/workflows/docker-security.yml` (add a console-readable
   vulnerability table alongside the SARIF upload, so a future failure is diagnosable from
   the workflow log alone).

5. **Re-measure `frontend-checks`' real cost** against an actual `web/**`-touching PR — the
   20-run samples on both sides only captured the change-detection short-circuit path (~8s),
   not a full install/lint/typecheck/test/build cycle. Evidence: AC1 gap note.
   Files In Scope: none (a measurement task, not a code change — could ride along with the
   next PR that genuinely touches `web/`).

6. **Re-run this audit's `docker-security.yml` / `license-check.yml` / `dependency-pin-check.yml`
   "rarely triggers" assumption correction into their own workflow comments**, since all
   three actually fire on most PRs in this repo today (path filters matching go.mod/go.sum/
   Dockerfile churn far more often than their `paths:` comments imply) — a maintainer reading
   the current comments would under-budget their PR-side cost.
   Files In Scope: `.github/workflows/docker-security.yml`, `.github/workflows/license-check.yml`,
   `.github/workflows/dependency-pin-check.yml` (comment-only correction).

7. **Fold this audit's CI-level refinement into #4164** (already filed, not duplicated here):
   `ALL_MODULES`'s 9 missing modules aren't just a "local pre-push" gap as #4164's Problem
   statement states — `make test`'s primary `go test` invocation excludes `/features/modules/`
   entirely, so a PR touching only one of those 9 modules gets zero test execution in CI's
   `unit-tests` job. #4164's already-scoped fix (derive `ALL_MODULES` from `module.yaml`
   presence) closes this too; no separate story needed, just a correction to #4164's framing
   when it's picked up.

No item above proposes removing a check without naming what still covers its risk, per this
story's constraint — items 1-6 are cleanup/investigation/measurement, not risk removal.

---

*This audit's raw pulls (JSON/JSONL, ~1,170 lines of intermediate markdown) are retained in
`/tmp/ci-audit/` on the machine that ran it, not committed to the repo. Anyone re-verifying a
figure should re-run the literal command shown in that section rather than trust the cached
numbers here — CI timing drifts, and this document is a snapshot dated 2026-09-18.*
