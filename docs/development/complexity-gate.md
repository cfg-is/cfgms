# Complexity Report

`make complexity-report` measures every production Go function in the repository, partitions the population into seven segments from a committed manifest, and writes a versioned machine-readable metric file. The report is report-only: high complexity never fails it. The `check` subcommand (see [Gate rules](#gate-rules)) enforces no-worsening rules against a baseline, and the ratchet, freeze and staleness commands maintain the baselines (see [Ratchet](#ratchet-frozen-baseline-and-staleness)).

The in-repo analyzer exists because the per-function Halstead metrics and the exact counting rules below are not available from an off-the-shelf linter, and the measurement must be reproducible from the repository alone with no new module dependency.

## What is measured

Every production function or method with a body, in all build configurations (grep-level view: `//go:build windows` files are measured on Linux). Excluded: `_test.go`, `*.pb.go`, generated files, and the top-level `test/`, `web/` and `scripts/` trees, plus `bin/`, `build/`, `data/`, `node_modules/`, `vendor/`, dot-directories and nested modules.

Per function: cyclomatic complexity (CC) and Halstead volume, difficulty and effort. Function literals are folded into their declaring function.

### Counting rules (summary)

CC is 1 plus one for each `if`, `for`, `range`, non-default `case` of a switch or type switch, non-default `select` clause, and each `&&` / `||`. `else`, `default`, the switch statement itself, `defer` and `go` add nothing. `if err != nil { return err }` counts like any other `if`. The authoritative rules are in `scripts/complexity/analyzer`.

A **hotspot** is a function with CC > 10. **Excess** is the sum of `max(CC - 10, 0)` over functions.

## Segments

The manifest (`scripts/complexity/manifest.json`) assigns every function to exactly one of seven segments by repo-relative path prefix.

| Segment | Paths | Covers | Cannot see |
|---------|-------|--------|------------|
| `controller` | `features/controller/` | Controller-private feature logic | Shared packages, steward-side logic, `features-shared` |
| `steward` | `features/steward/` | Steward-private feature logic | Shared packages, controller-side logic, `features-shared` |
| `workflow` | `features/workflow/` | Workflow engine and execution logic | Modules it invokes, shared packages, hosting controller services |
| `modules` | `features/modules/` | Module implementations | Module runtime and packaging in `pkg/`, invoking steward/controller code |
| `pkg` | `pkg/`, `api/` | Shared packages, central providers, non-generated `api/` Go | Feature logic, command wiring, generated protobuf code |
| `cmd` | `cmd/` | Command entry points | The logic the commands call into |
| `features-shared` | `features/config/`, `features/monitoring/`, `features/rbac/`, `features/reports/`, `features/tenant/`, `features/terminal/` | Cross-component feature packages shared by controller and steward | Component-private logic in `features/controller` and `features/steward` |

The seventh segment, `features-shared`, is a product-owner decision beyond the epic's six named segments: without it the six feature directories shared by controller and steward would be unclassified.

`features-shared` names its directories one by one and never uses `features/` or a glob, so a new `features/<dir>` is reported as unclassified by name and a person decides its segment.

### Partition checks

The run exits 1 and sets `status: "fail"` when any function is:

- **unclassified** — in the aggregate but in no segment;
- **claimed twice** — in two segments;
- **foreign** — in a segment but absent from the aggregate;

or when segment function counts or excess do not sum to the aggregate, or two functions share an identity. The loader rejects a manifest with a missing `covers` or `cannot_see`, an unknown or duplicate segment name, empty paths, a bare `features/` prefix, or overlapping prefixes.

A manifest prefix with no measured production function (for example an all-test directory) prints a `WARN` and does not fail the run.

Exit codes: 0 report written and partition clean; 1 partition or duplicate-identity violation; 2 IO or parse error.

## Metric file contract

`-out` (default `bin/complexity/metrics.json`) is written on every run, whether it passes or fails; on an error before measurement completes it is written with `status: "error"` if the directory is writable.

| Field | Meaning |
|-------|---------|
| `schema_version` | Metric-file schema version (1) |
| `base_commit` | `git rev-parse origin/develop` at run time (`-base-commit` overrides) |
| `analyzer_version` | Version of the counting rules |
| `manifest_sha256` | sha256 of the committed `manifest.json` bytes |
| `hotspot_threshold` | 10 |
| `status` | `pass`, `fail` or `error` |
| `form` | `full` or `hotspots` |
| `violations` | Partition and error messages |
| `aggregate`, `segments` | `functions, hotspots, aggregate_excess, mean_cc, p95_volume, p95_effort, over20, over30, over50` |
| `functions` | One object per line: `id, file, line, seg, cc, n1, n2, N1, N2, vol, diff, eff` |

Percentiles use nearest rank: the element at index `ceil(p*n)-1` of the ascending series. The model, writers, reader and `NearestRank` live in `scripts/complexity/metrics` so later tooling can import them.

The per-run metric file is gitignored (`bin/`) and uploaded as a CI artifact, never committed, because a committed per-run file would conflict on every concurrent PR. Only baselines are committed.

## Baseline inventory

`scripts/complexity/baselines/inventory.json` is the committed Phase 0 inventory in the compact hotspot form: aggregate and per-segment totals plus only the functions with CC > 10. The full per-function file stays the gitignored per-run output. Do not edit the inventory by hand.

- Base commit measured from: `06fac0c634a279a2f7b7f145b3047c8d950572f0` (develop at generation time, not the pull request's own commit).
- Size: 264774 bytes.

Regenerate:

```bash
make complexity-report COMPLEXITY_OUT=scripts/complexity/baselines/inventory.json COMPLEXITY_FLAGS=-compact-baseline
```

## Gate rules

`go run ./scripts/complexity check -baseline <file>` measures the current tree, measures **Previous** (the merge-base tree), reads the ratchet baseline from `-baseline`, and evaluates three rules. The current tree goes through the same measure-and-partition path as `report`; a partition violation is a finding printed as `partition: <violation>`. Previous is measured with the analyzer only, with no partition, because older trees predate the manifest. `-current <file>` replaces the current measurement and exists for tests only.

Rules are pure functions in `scripts/complexity/gate`; they do no IO.

### Baseline versus Previous

Rules 1 and 2 compare to the **ratchet baseline**, a committed metric file that moves only when the ratchet is updated. Rule 3 compares to **Previous**, the tree at the merge-base. Judging rule 3 against Previous, not the lagging baseline, means a pull request is never failed for a function an earlier merged pull request changed.

| Rule | Fails when |
|------|-----------|
| 1 aggregate | versus the baseline, hotspot count, aggregate excess or P95 Halstead effort (nearest rank) increases. Equal passes. Each metric is its own finding. |
| 2 hotspot growth | an identity in both baseline and current, with baseline CC > 10, has current CC > baseline CC. |
| 3 changed function | a function is **changed** and has CC > 10, unless it reduces an existing hotspot (Previous CC > 10 and current CC < Previous CC). |

A function is **changed** when its file is in the touched set and any of its metrics (CC or any Halstead field) differ between Previous and current. An identity absent from Previous counts as different. Functions in untouched files and functions identical to Previous are never subject to rule 3.

Deleted hotspots fire nothing under rule 2. A **renamed or moved** hotspot is a new identity: rule 2 no longer sees it, and rule 3 applies, so it must be at CC <= 10 or reduce below its Previous CC (it has none, so it must be <= 10).

### Warn-only and neutral metrics

An increase in mean CC or P95 volume prints `WARN: <metric> <base> -> <cur>` and leaves the exit code unchanged. A change in function count affects nothing. Percentiles use nearest rank (see above).

### Failure format

One line per finding on stdout:

```text
<file>:<line>: rule <2|3>: <identity> CC <base> -> <cur>
aggregate: rule 1: <metric> <base> -> <cur>
partition: <violation>
```

`<line>` is the function's line in the current tree. For rule 3, `<base>` is the Previous CC (0 for a new function).

Exit codes: 0 pass (warnings allowed), 1 any finding, 2 IO or git error.

### Merge-base and touched files

The base ref is `origin/develop`, then `develop`; if neither resolves, `check` exits 2. If `git rev-parse --is-shallow-repository` is true, or `git merge-base HEAD <ref>` fails, `check` exits 2 with `history too shallow to compute merge-base; fetch full history (actions/checkout fetch-depth: 0 or git fetch --unshallow)`. A failure to resolve the merge-base is never treated as "no files touched" or "all files touched".

The touched set is `git diff --name-only <merge-base>` (committed, staged and unstaged tracked changes) united with `git ls-files --others --exclude-standard` (untracked files), because the local pre-commit run happens before the commit exists. Paths are repo-root-relative with forward slashes, and are compared to `Function.File` after slash normalisation.

CI event shapes, all needing full history (`fetch-depth: 0`):

- `pull_request`: the checkout is the PR merge commit, so merge-base..HEAD is the PR diff.
- `merge_group`: the checkout is the queue branch tip, with `origin/develop` as its base.

Previous is materialised by `MaterializeRef` in `gittree.go`, which reads `git archive <ref>` with the standard library tar reader into a temporary directory. It never touches the working tree or index.

Rule 3 has been replayed against recent merged develop PRs with `make complexity-replay`; the measured result is in [complexity-gate-calibration.md](complexity-gate-calibration.md).

## Ratchet, frozen baseline and staleness

Three baselines exist, each with one writer:

| File | Written by | Purpose |
|------|-----------|---------|
| `baselines/inventory.json` | `make complexity-report` | Phase 0 inventory |
| `baselines/ratchet.json` | `make complexity-ratchet` | The baseline rules 1 and 2 compare to |
| `baselines/frozen.json` | `make complexity-freeze` | Starting point of the programme, never moved |

### Make targets

- `make complexity-check` runs `check -baseline scripts/complexity/baselines/ratchet.json`: staleness first, then the gate rules.
- `make complexity-ratchet` runs the gate against the current `ratchet.json` and writes the new baseline (hotspot-only form) **only if zero findings are reported**. A failing rule exits 1 and leaves the file byte-identical. Mean CC and P95 volume worsening only warn and do not block the ratchet. The ratchet never reads or writes `frozen.json`.
- `make complexity-freeze` writes `frozen.json` (`schema_version`, the base commit SHA, hotspot-only compact form) and exits 1 if it already exists. Replacing it takes deleting the file in a reviewed diff and running the target again. It needs `origin/develop` to resolve (or `-base-commit`).

### When to move the ratchet

Move it after a change lowers hotspots, aggregate excess or P95 effort, so the improvement cannot be lost: run `make complexity-ratchet` and commit the new `ratchet.json` in its own reviewed diff. The target refuses while any gate rule fails, so the baseline cannot be moved to hide a regression.

### Init procedure

`ratchet.json` does not exist until the gate is enabled. Create it with `make complexity-ratchet COMPLEXITY_INIT=1` (flag `-init`). Init writes only when the file is absent and refuses (exit 1) otherwise.

### Why frozen is separate

The ratchet baseline moves with every improvement; `frozen.json` records where the programme started so total progress stays measurable. If one file served both roles, each ratchet move would erase the starting point.

### Staleness

`check` (and `go run ./scripts/complexity staleness -baseline <file>`) fails with exit 1 when the ratchet baseline is stale. There are exactly four conditions: the baseline's `schema_version`, `analyzer_version`, `hotspot_threshold` or `manifest_sha256` differs from the running tool or the sha256 of the committed `manifest.json` bytes. Nothing else makes it stale; deleted functions are legitimate and the identity set is not compared.

A manifest change is repaired with `make complexity-ratchet`, which skips the staleness check (it is the remedy) and goes straight to the gate. If `schema_version`, `analyzer_version` or `hotspot_threshold` differ, counts are not comparable and the ratchet refuses with `counting rules changed: delete baselines/ratchet.json in a reviewed diff and run make complexity-ratchet COMPLEXITY_INIT=1`.

## CI and anti-gaming

### Where the gate runs

- `make test-commit` runs `complexity-check` locally.
- The `complexity-gate` job in `.github/workflows/test-suite.yml` runs `make complexity-check` on every `pull_request` and `merge_group`, with a full-history checkout and no path filter. The `unit-tests` aggregator lists it in `needs:` and checks its result before the docs-only exit, so a docs-only pull request cannot skip it.
- In the merge queue the job runs and posts its own `complexity-gate` context, but blocking is pull-request-side only, through the aggregator. The context is not in the branch ruleset's required checks.

### Moving the ratchet in CI

If develop moves while a pull request is queued and `make complexity-check` then fails against the committed baseline, delete `baselines/ratchet.json` and run `make complexity-ratchet COMPLEXITY_INIT=1` in the same pull request. There is no other baseline-writing path.

### Protected paths

`scripts/complexity/manifest.json`, `scripts/complexity/baselines/` and the tooling under `scripts/complexity/` are protected against quiet edits by three controls: the CLAUDE.md scope constraints, a `CODEOWNERS` entry for `/scripts/complexity/`, and an acceptance-reviewer rule that lists every changed path there and treats a manifest or baseline edit as a finding unless the story names it. The `CODEOWNERS` entry adds specificity but no new reviewer, because the default `*` entry already names the same owner.

### Concurrency

Two pull requests that both move `ratchet.json` conflict textually. The merge queue rebases the second, and `check` then re-runs against the new baseline.

## Limits

Blocking is evaluated per pull request; the merge queue can, in principle, let two pull requests merge that each pass alone but together worsen P95 effort. The develop-side run surfaces it.
