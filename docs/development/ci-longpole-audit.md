# CI Long-Pole Gate Audit — PR-time value of the heavy gates

**Date:** 2026-07-10  ·  **Story:** #2550  ·  **Epic:** #565 (self-hosted CI runners)

## Purpose

Two long-pole gates dominate PR CI wall-clock: **Production Risk Gates**
(`production-gates.yml`, ~21 min) and **Fleet E2E** (`fleet-e2e.yml`, ~10 min).
This audit asks, per gate, from real run history: do its `pull_request` failures
represent **real, unique** bugs it caught *before merge* — or are they mostly
flaky/infra noise or failures a cheaper check already caught? Gates that don't
earn their PR slot move to **`merge_group`-only** (still enforced at the
authoritative merge gate, where a failure is pipeline-visible and triggers the
fix cycle); gates that demonstrably catch unique PR bugs stay on `pull_request`.

**The data drives the decision.** A gate is not moved without evidence.

## Method

For each workflow, the most recent **60 `pull_request` runs** (as of 2026-07-10)
were pulled via `gh run list --workflow <file> --event pull_request`. Every
`failure` run was inspected at the job level (`gh run view --json jobs`) and, for
classification, at the failed-step log level (`gh run view --log-failed`):

- **Real vs flaky/infra** — genuine code/test defect, or a flake/network/timeout?
- **Unique vs redundant** — did a *cheaper* check on the same PR also fail (so the
  long pole added no unique early signal), or was this gate the only one that
  could catch it?

The key structural fact for "unique": **`production-gates.yml` is the only PR gate
that runs the Windows + macOS steward/controller integration matrix.**
`test-suite.yml` (the cheap integration gate) runs integration tests on **Linux
only**. So a Windows/macOS integration failure is, by construction, catchable
*only* by `production-gates`.

## Production Risk Gates (`production-gates.yml`) — **KEEP on `pull_request`**

| Metric | Value |
|---|---|
| PR runs sampled | 60 |
| Failures | 10 (**16.7%**) |
| Real vs flaky | 10 real / 0 flaky |
| Unique vs redundant | **8 unique / 2 redundant** |

**Failure breakdown:**

| PR | Failed job(s) | Real? | Unique? | Notes |
|---|---|---|---|---|
| #2516 (dex Windows ETW/WMI spike) | Steward Integration Tests (windows-latest) ×6 | Real | **Unique** | Windows integration failing on an in-progress Windows PoC; no cheaper gate runs Windows integration. |
| #2464 (SQLite UpgradeStore) | Steward Integration Tests (windows-latest) ×2 | Real | **Unique** | `--- FAIL: TestE2EScenarios` at `test/e2e/scenarios_test.go:60` on windows-latest. Merged after fix. |
| #2491 (frontend CI lane) | Controller Integration Tests (Linux) ×1 | Real | Redundant | Linux controller integration is also covered by `test-suite.yml`. |
| #2469 (modules split) | Controller + Steward Integration (Linux) ×1 | Real | Redundant | Build/package error — any build gate catches it. |

**Decision — KEEP on `pull_request` (retain `merge_group`).** 8 of 10 PR failures
were **unique** Windows steward-integration test failures that **no cheaper PR
check can catch** (`test-suite.yml` runs Linux-only integration). Moving this gate
to `merge_group`-only would defer discovery of Windows/macOS integration breakage
to merge time — a queue **ejection + full merge_group re-run** — for precisely the
failure class this gate uniquely owns. At a 16.7% PR failure rate that is real,
unique early signal worth its slot. (Its per-run cost is separately reduced by the
GOCACHE work in #2551.)

## Fleet E2E (`fleet-e2e.yml`) — **MOVE to `merge_group`-only**

| Metric | Value |
|---|---|
| PR runs sampled | 60 |
| Failures | 3 (**5.0%**) + 1 cancelled (superseded push, excluded) |
| Real vs flaky | 2 real / 1 flaky |
| Unique vs redundant | **1 unique / 2 redundant-or-flaky** |

**Failure breakdown:**

| PR | Real? | Unique? | Root cause (from `--log-failed`) |
|---|---|---|---|
| #2522 (sync_dna) | Real | **Unique** | e2e scenario: `Registration refresh rejected … no valid client certificate`. Fleet E2E is the only gate that runs this. Merged after fix. |
| #2469 (modules split) | Real | Redundant | Build error: `no required module provides package …/features/modules/stdlib/script` — a compile failure every build/unit gate catches. |
| `fix/gofmt-clusterregistry-test` | **Flaky/infra** | — | `proxy.golang.org … stream error … INTERNAL_ERROR; received from peer` during `go mod download`. Transient network. |

**Decision — MOVE to `merge_group`-only (remove `pull_request`; retain
`merge_group`).** At a 5% PR failure rate, only **1 of 3** failures was a unique
real catch; the other two were a transient network flake and a compile error any
cheaper gate also flags. Fleet E2E's unique-real PR failure rate is ~1.7%
(1/60) — its ~10-min per-PR cost buys almost no early signal that a cheaper gate
or the merge_group run wouldn't. `merge_group` retention keeps it enforced at the
authoritative merge gate, where a failure is pipeline-visible and triggers the fix
cycle.

**Tradeoff acknowledged.** `merge_group`-only means a failure surfaces at merge
(ejection → re-queue re-runs the full `merge_group` suite), so it is a net win
only for gates that *rarely* fail. Fleet E2E's 5% rate — mostly flaky/redundant —
fits that profile: minimal ejection churn, meaningful per-PR time saved. This is
safe under the pipeline model and complements #2549 (the redundant
`push`-to-develop re-run was already removed) — a would-be post-merge red is now
handled by the pipeline, not by an unactionable branch run.

## Summary

| Gate | PR fail rate | Verdict | Action |
|---|---|---|---|
| `production-gates.yml` | 16.7% (8/10 unique-real) | Earns its PR slot | **Keep** on `pull_request` |
| `fleet-e2e.yml` | 5.0% (1/3 unique-real) | Mostly flaky/redundant | **Move** to `merge_group`-only |

Both gates retain `merge_group`, so both remain enforced before any commit lands
on `develop`.
