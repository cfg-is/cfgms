# Duplication Gate Calibration

Measured replay of the three [duplication gate rules](duplication-gate.md#gate-rules) over the last 30 merged develop PRs at window thresholds 100, 150 and 200 tokens, produced by `make duplication-replay`. Counts, tables and file:line ranges below are copied from that run's output; the cause column is a reviewer classification made by reading the first lines of each range.

## Method

- Window: `git log --first-parent --max-count=30` on `develop`; for each commit C with parent P, P and C are materialised with `materializeRef` and measured with `measureDuplication`, the touched set is `git diff --name-only P C`, and `gate.Evaluate` runs rules 1, 2 and 3 with P as previous, the same path `duplication check` uses. A PR fires when any rule produces a finding.
- Each distinct tree is measured once per run (31 trees for 30 commits) and the result reused for the commit that is both a child and a parent.
- Each firing records the file:line range of the run the finding points at and the ranges of the other current runs sharing a window with it. Rule 1 has no location.
- Unmeasurable commits (analysis error) would be reported with a reason and never counted as pass.
- Commands: `make duplication-replay DUPLICATION_THRESHOLD=<100|150|200>`; the 200 run also set `DUPLICATION_BASELINE=71ce9e7e`.
- Wall time is measured with `time` around `make`, one run per threshold.

| Run | Wall time |
|-----|-----------|
| threshold 150 with baseline | 59 s |
| threshold 100 | 62 s |
| threshold 200 | 57 s |
| threshold 200 with baseline | 69 s |

## Window

| Item | Value |
|------|-------|
| develop SHA | `aa9fdc929e28216f42eae66256a3d04586682030` |
| Window | 30 first-parent commits, `#5898` back to `#5769` |
| PRs replayed | 30 |
| Unmeasurable | 0 at every threshold |

## Results

| Threshold | PRs fired | Fire rate | Rule 1 | Rule 2 | Rule 3 | Unmeasurable |
|-----------|-----------|-----------|--------|--------|--------|--------------|
| 100 | 11 | 36.7% | 5 | 9 | 7 | 0 |
| 150 | 5 | 16.7% | 1 | 4 | 1 | 0 |
| 200 | 2 | 6.7% | 2 | 1 | 1 | 0 |

Run summaries:

```text
threshold 100: PRs replayed 30, fires on 11 (36.7%), rule 1 on 5, rule 2 on 9, rule 3 on 7, unmeasurable 0
threshold 150: PRs replayed 30, fires on 5 (16.7%), rule 1 on 1, rule 2 on 4, rule 3 on 1, unmeasurable 0
threshold 200: PRs replayed 30, fires on 2 (6.7%), rule 1 on 2, rule 2 on 1, rule 3 on 1, unmeasurable 0
```

### Per-PR outcome at 100

| Commit | PR | Files | Rule 1 | Rule 2 | Rule 3 | Outcome |
|--------|----|-------|--------|--------|--------|---------|
| `aa9fdc929e` | #5898 | 12 | 0 | 4 | 0 | fires |
| `bbb735f464` | #5808 | 1 | 0 | 0 | 0 | pass |
| `1f39644a06` | #5895 | 8 | 0 | 0 | 0 | pass |
| `26bed2875a` | #5889 | 2 | 0 | 2 | 0 | fires |
| `cd354285dc` | #5809 | 14 | 1 | 1 | 1 | fires |
| `587e693e09` | #5891 | 3 | 0 | 0 | 0 | pass |
| `ba3761cc26` | #5810 | 21 | 0 | 4 | 4 | fires |
| `934029d4e1` | #5890 | 18 | 1 | 2 | 0 | fires |
| `15743a6078` | #5816 | 3 | 0 | 0 | 0 | pass |
| `b27ad48b24` | #5888 | 1 | 0 | 0 | 0 | pass |
| `33c3bcc028` | #5817 | 5 | 0 | 0 | 0 | pass |
| `9eefd16388` | #5815 | 7 | 0 | 0 | 0 | pass |
| `d79c9ed342` | #5811 | 11 | 0 | 0 | 0 | pass |
| `06f8292d0b` | #5814 | 13 | 1 | 3 | 2 | fires |
| `08e392d944` | #5812 | 16 | 1 | 3 | 8 | fires |
| `19ab685ba2` | #5806 | 9 | 0 | 0 | 0 | pass |
| `2810e3c152` | #5805 | 8 | 0 | 0 | 0 | pass |
| `17ee4caa40` | #5804 | 27 | 1 | 7 | 2 | fires |
| `aacb7a3228` | #5803 | 3 | 0 | 0 | 0 | pass |
| `afb4b57a54` | #5800 | 5 | 0 | 0 | 0 | pass |
| `6c1fddaef4` | #5784 | 17 | 0 | 1 | 0 | fires |
| `d563980b67` | #5776 | 20 | 0 | 0 | 0 | pass |
| `4acf8a28e2` | #5775 | 4 | 0 | 0 | 0 | pass |
| `e25ba60e48` | #5777 | 12 | 0 | 0 | 0 | pass |
| `595de9b003` | #5781 | 3 | 0 | 0 | 2 | fires |
| `63fc4738f7` | #5780 | 2 | 0 | 0 | 0 | pass |
| `7a9d2358b2` | #5774 | 28 | 0 | 0 | 0 | pass |
| `5095a0efab` | #5771 | 6 | 0 | 0 | 0 | pass |
| `0f7eb89ec6` | #5770 | 30 | 0 | 0 | 3 | fires |
| `71ce9e7e20` | #5769 | 8 | 0 | 0 | 0 | pass |

### Per-PR outcome at 150

| Commit | PR | Files | Rule 1 | Rule 2 | Rule 3 | Outcome |
|--------|----|-------|--------|--------|--------|---------|
| `aa9fdc929e` | #5898 | 12 | 0 | 4 | 0 | fires |
| `bbb735f464` | #5808 | 1 | 0 | 0 | 0 | pass |
| `1f39644a06` | #5895 | 8 | 0 | 0 | 0 | pass |
| `26bed2875a` | #5889 | 2 | 0 | 0 | 0 | pass |
| `cd354285dc` | #5809 | 14 | 0 | 0 | 0 | pass |
| `587e693e09` | #5891 | 3 | 0 | 0 | 0 | pass |
| `ba3761cc26` | #5810 | 21 | 0 | 1 | 0 | fires |
| `934029d4e1` | #5890 | 18 | 0 | 0 | 0 | pass |
| `15743a6078` | #5816 | 3 | 0 | 0 | 0 | pass |
| `b27ad48b24` | #5888 | 1 | 0 | 0 | 0 | pass |
| `33c3bcc028` | #5817 | 5 | 0 | 0 | 0 | pass |
| `9eefd16388` | #5815 | 7 | 0 | 0 | 0 | pass |
| `d79c9ed342` | #5811 | 11 | 0 | 0 | 0 | pass |
| `06f8292d0b` | #5814 | 13 | 0 | 0 | 0 | pass |
| `08e392d944` | #5812 | 16 | 1 | 0 | 5 | fires |
| `19ab685ba2` | #5806 | 9 | 0 | 0 | 0 | pass |
| `2810e3c152` | #5805 | 8 | 0 | 0 | 0 | pass |
| `17ee4caa40` | #5804 | 27 | 0 | 2 | 0 | fires |
| `aacb7a3228` | #5803 | 3 | 0 | 0 | 0 | pass |
| `afb4b57a54` | #5800 | 5 | 0 | 0 | 0 | pass |
| `6c1fddaef4` | #5784 | 17 | 0 | 0 | 0 | pass |
| `d563980b67` | #5776 | 20 | 0 | 0 | 0 | pass |
| `4acf8a28e2` | #5775 | 4 | 0 | 0 | 0 | pass |
| `e25ba60e48` | #5777 | 12 | 0 | 0 | 0 | pass |
| `595de9b003` | #5781 | 3 | 0 | 0 | 0 | pass |
| `63fc4738f7` | #5780 | 2 | 0 | 0 | 0 | pass |
| `7a9d2358b2` | #5774 | 28 | 0 | 0 | 0 | pass |
| `5095a0efab` | #5771 | 6 | 0 | 0 | 0 | pass |
| `0f7eb89ec6` | #5770 | 30 | 0 | 2 | 0 | fires |
| `71ce9e7e20` | #5769 | 8 | 0 | 0 | 0 | pass |

### Per-PR outcome at 200

| Commit | PR | Files | Rule 1 | Rule 2 | Rule 3 | Outcome |
|--------|----|-------|--------|--------|--------|---------|
| `aa9fdc929e` | #5898 | 12 | 0 | 0 | 0 | pass |
| `bbb735f464` | #5808 | 1 | 0 | 0 | 0 | pass |
| `1f39644a06` | #5895 | 8 | 0 | 0 | 0 | pass |
| `26bed2875a` | #5889 | 2 | 0 | 0 | 0 | pass |
| `cd354285dc` | #5809 | 14 | 0 | 0 | 0 | pass |
| `587e693e09` | #5891 | 3 | 0 | 0 | 0 | pass |
| `ba3761cc26` | #5810 | 21 | 0 | 0 | 0 | pass |
| `934029d4e1` | #5890 | 18 | 0 | 0 | 0 | pass |
| `15743a6078` | #5816 | 3 | 0 | 0 | 0 | pass |
| `b27ad48b24` | #5888 | 1 | 0 | 0 | 0 | pass |
| `33c3bcc028` | #5817 | 5 | 0 | 0 | 0 | pass |
| `9eefd16388` | #5815 | 7 | 0 | 0 | 0 | pass |
| `d79c9ed342` | #5811 | 11 | 0 | 0 | 0 | pass |
| `06f8292d0b` | #5814 | 13 | 0 | 0 | 0 | pass |
| `08e392d944` | #5812 | 16 | 1 | 0 | 6 | fires |
| `19ab685ba2` | #5806 | 9 | 0 | 0 | 0 | pass |
| `2810e3c152` | #5805 | 8 | 0 | 0 | 0 | pass |
| `17ee4caa40` | #5804 | 27 | 1 | 2 | 0 | fires |
| `aacb7a3228` | #5803 | 3 | 0 | 0 | 0 | pass |
| `afb4b57a54` | #5800 | 5 | 0 | 0 | 0 | pass |
| `6c1fddaef4` | #5784 | 17 | 0 | 0 | 0 | pass |
| `d563980b67` | #5776 | 20 | 0 | 0 | 0 | pass |
| `4acf8a28e2` | #5775 | 4 | 0 | 0 | 0 | pass |
| `e25ba60e48` | #5777 | 12 | 0 | 0 | 0 | pass |
| `595de9b003` | #5781 | 3 | 0 | 0 | 0 | pass |
| `63fc4738f7` | #5780 | 2 | 0 | 0 | 0 | pass |
| `7a9d2358b2` | #5774 | 28 | 0 | 0 | 0 | pass |
| `5095a0efab` | #5771 | 6 | 0 | 0 | 0 | pass |
| `0f7eb89ec6` | #5770 | 30 | 0 | 0 | 0 | pass |
| `71ce9e7e20` | #5769 | 8 | 0 | 0 | 0 | pass |

## Firing PRs

Causes: **real copy** (new or grown copy of logic), **boilerplate** (declarative tables, option lists, command declarations that repeat by construction), **tool artifact** (a measurement defect). No tool artifact was found. Ranges are `file:start-end` in the PR's tree; the first is the run the finding points at, the second a partner copy.

### Threshold 200 (2 PRs)

| PR | Rules | Ranges | Cause |
|----|-------|--------|-------|
| #5812 | 1 (21146 -> 21162), 3 | `features/controller/api/permissions.go:10-316` (119 -> 121 copies of its own block); `features/rbac/defaults.go:31-103` copies `defaults.go:52-110`, `59-117`, `66-124` (3 -> 5 copies) | boilerplate: two new permission-table entries |
| #5804 | 1 (21134 -> 21146), 2 | `features/controller/batchjob/executor.go:238-284` copies `features/controller/batchjob/rollback.go:119-165` (289 tokens) | real copy: dispatch loop duplicated across executor and rollback |

### Threshold 150 (5 PRs)

| PR | Rules | Ranges | Cause |
|----|-------|--------|-------|
| #5898 | 2 | `pkg/entitygraph/providers/database/neighborhood.go:17-53` copies `pkg/entitygraph/providers/sqlite/neighborhood.go:17-54`; `database/watch.go:28-62` copies `sqlite/watch.go:26-56` | real copy: second dialect provider repeats the first |
| #5810 | 2 | `cmd/cfg/cmd/installer.go:95-119` copies `cmd/cfg/cmd/controller_upgrade.go:410-455` | boilerplate: cobra command declarations |
| #5812 | 1, 3 | `features/controller/api/assurance.go:54-73` copies `assurance.go:82-161`; `permissions.go:10-316`; `features/rbac/defaults.go:31-124` copies `defaults.go:140-193`, `193-268`, `features/terminal/security.go:17-58` | boilerplate: permission and assurance tables |
| #5804 | 2 | `features/controller/batchjob/executor.go:238-284` copies `rollback.go:119-165` | real copy |
| #5770 | 2 | `features/controller/batchjob/store_sqlite.go:211-242` copies `store_sqlite.go:261-290` | real copy: list-and-scan loop repeated |

### Threshold 100 (11 PRs)

| PR | Rules | Ranges | Cause |
|----|-------|--------|-------|
| #5898 | 2 | `pkg/entitygraph/providers/database/neighborhood.go:17-53` / `sqlite/neighborhood.go:17-54`; `database/watch.go:28-62` / `sqlite/watch.go:26-56` | real copy |
| #5889 | 2 | `features/controller/config/config.go:1461-1482` / `config.go:1660-1683` | boilerplate: environment-override accessor closures |
| #5809 | 1, 2, 3 | `features/controller/server/server.go:2287-2311` / `server.go:2312-2337` | boilerplate: struct-literal field lists |
| #5810 | 2, 3 | `features/controller/api/handlers_installer.go:186-222` / `446-475`, `498-525`; `pkg/modules/trust/installer.go:16-40` / `pkg/modules/trust/steward_binary.go:24-61`; `cmd/cfg/cmd/installer.go:77-121` / `connect.go:30-66` | real copy (trust message builders); boilerplate (handler and cobra declarations) |
| #5890 | 1, 2 | `features/steward/commands/execute_script.go:623-638` / `features/steward/operatorroster/revocation.go:299-314` | real copy: PEM decode and certificate verify |
| #5814 | 1, 2, 3 | `features/controller/tagstore/tagstore.go:46-59` / `features/controller/run/run.go:217-242`, `pkg/storage/providers/sqlite/upgrade_store.go:20-48`; `pkg/entitygraph/providers/sqlite/schema.go:121-139` / `pkg/storage/providers/sqlite/plugin.go:175-199` | real copy: SQLite open and pragma sequence |
| #5812 | 1, 2, 3 | `cmd/cfg/cmd/steward_tamper.go:114-142` / `steward_clones.go:244-274`; `steward_tamper.go:130-147` / `151-168`; `features/controller/api/assurance.go:54-73`; `permissions.go:10-316`; `features/rbac/defaults.go:31-141` | boilerplate: cobra declarations and permission tables |
| #5804 | 1, 2, 3 | `features/controller/batchjob/executor.go:238-284` / `rollback.go:119-165`; `features/controller/run/synthesis.go:249-284` / `408-442`, `528-541`; `features/controller/server/lockdown_audit.go:64-76` / `92-104`; `server.go:1340-1360` / `1361-1381` | real copy (dispatch, synthesis enqueue, audit builder); boilerplate (server option list) |
| #5784 | 2 | `pkg/storage/providers/flatfile/lease_store.go:44-65` / `node_registry_store.go:37-90`, `routing_store.go:39-91` | boilerplate: flat-file store constructors |
| #5781 | 3 | `features/controller/server/server.go:1340-1358` / `1359-1377` (111 -> 113 tokens) | boilerplate: gRPC option list |
| #5770 | 3 | `features/controller/batchjob/store_sqlite.go:211-242` / `261-290`; `store_sqlite.go:18-70` / `features/modules/stdlib/script/execution_tracking.go:59-108` | real copy |

## Decision rule

Choose the LOWEST of 100/150/200 for which every PR that fires in the 30-PR window is a real new or grown copy AND the fire rate is 25% or less. "Real copy" is shown by recording both file:line ranges for each firing. If none qualifies, choose the threshold with the lowest fire rate, record why, and do not block the story.

## Chosen default: 200 tokens

- 100 fails both tests: 36.7% fire rate and boilerplate firings (#5889, #5809, #5784, #5781).
- 150 meets the rate (16.7%) but fires on boilerplate (#5810, #5812).
- 200 meets the rate (6.7%) but still fires on boilerplate (#5812: rows added to permission tables).
- No threshold qualifies, so the fallback applies: the lowest fire rate, 200. `detector.DefaultThreshold` is 200.

Trade-off: at 200 the gate does not fire on the 193-token and 163-token copies of #5898 or the 186-token copy of #5770, which 150 catches. Lowering the threshold is a one-line change to `detector.DefaultThreshold`.

## Known limits

- Declarative tables (permission lists, option lists, cobra command declarations) repeat token-for-token by construction and are counted as copies at every threshold. A new row in an existing table fires rule 3 (#5812). Annotate a table that is intentionally repetitive with the justification comment described in [the gate document](duplication-gate.md#annotations).
- The cause column is a classification from reading the opening lines of each range, not an exhaustive review.

## Baseline at `71ce9e7e`

Measured by this tool at threshold 200 through `materializeRef` (`make duplication-replay DUPLICATION_THRESHOLD=200 DUPLICATION_BASELINE=71ce9e7e`). `71ce9e7e` is the oldest commit of the window (#5769).

| Item | Value |
|------|-------|
| Threshold | 200 tokens |
| Production files | 1353 |
| Production lines | 426898 |
| Duplicated lines | 21651 (5.07%) in 536 runs |
| Annotated lines | 0 (0.00%) |

Duplicated lines per package (`by_package`, all 72 packages). The cleanup stories under #5773 read their "before" figures from this table.

| Package | Duplicated lines |
|---------|------------------|
| `cmd/cfg/cmd` | 1169 |
| `cmd/cfgms-steward-launcher` | 37 |
| `cmd/controller/service` | 61 |
| `cmd/steward` | 72 |
| `cmd/steward/service` | 110 |
| `features/config/diff` | 40 |
| `features/config/rollback` | 106 |
| `features/config/stewardtypes` | 111 |
| `features/controller/api` | 3728 |
| `features/controller/batchjob` | 74 |
| `features/controller/cutover` | 38 |
| `features/controller/fleet/storage` | 591 |
| `features/controller/health` | 117 |
| `features/controller/registration` | 70 |
| `features/controller/server` | 35 |
| `features/controller/service` | 286 |
| `features/modules` | 80 |
| `features/modules/hyperv` | 250 |
| `features/modules/stdlib/firewall` | 25 |
| `features/modules/stdlib/hostname` | 32 |
| `features/modules/stdlib/package` | 222 |
| `features/modules/stdlib/patch` | 50 |
| `features/modules/stdlib/service` | 41 |
| `features/modules/stdlib/time` | 32 |
| `features/modules/stdlib/user` | 41 |
| `features/rbac` | 262 |
| `features/rbac/continuous` | 68 |
| `features/rbac/memory` | 48 |
| `features/reports/api` | 187 |
| `features/reports/provider` | 50 |
| `features/steward/client` | 68 |
| `features/steward/config` | 159 |
| `features/steward/dna` | 113 |
| `features/steward/modules/runtime` | 253 |
| `features/steward/modules/runtime/testdata/echo_module` | 34 |
| `features/steward/modules/runtime/testdata/env_module` | 53 |
| `features/steward/registration` | 97 |
| `features/workflow` | 366 |
| `features/workflow/modules/m365` | 143 |
| `features/workflow/modules/m365/auth` | 473 |
| `features/workflow/modules/m365/conditional_access` | 58 |
| `features/workflow/modules/m365/entra_admin_unit` | 148 |
| `features/workflow/modules/m365/entra_application` | 110 |
| `features/workflow/modules/m365/entra_group` | 78 |
| `features/workflow/modules/m365/entra_user` | 42 |
| `features/workflow/modules/m365/graph` | 340 |
| `features/workflow/modules/m365/intune_policy` | 58 |
| `features/workflow/nodes` | 60 |
| `features/workflow/runtime` | 253 |
| `features/workflow/runtime/testdata/echo_module` | 36 |
| `features/workflow/runtime/testdata/env_module` | 53 |
| `features/workflow/trigger` | 94 |
| `pkg/cache` | 75 |
| `pkg/cert` | 126 |
| `pkg/config` | 61 |
| `pkg/controlplane/providers/grpc` | 67 |
| `pkg/dataplane/providers/grpc` | 64 |
| `pkg/directory/dna` | 517 |
| `pkg/directory/interfaces` | 386 |
| `pkg/entitygraph/providers/database` | 1501 |
| `pkg/entitygraph/providers/sqlite` | 1589 |
| `pkg/entitygraph/writers/dnasync` | 113 |
| `pkg/logging` | 65 |
| `pkg/logging/providers/timescale` | 63 |
| `pkg/migrate/storage` | 292 |
| `pkg/secrets/interfaces` | 116 |
| `pkg/storage/interfaces` | 739 |
| `pkg/storage/providers/blobstore/filesystem` | 72 |
| `pkg/storage/providers/database` | 2520 |
| `pkg/storage/providers/flatfile` | 472 |
| `pkg/storage/providers/sqlite` | 1631 |
| `pkg/testutil` | 60 |
