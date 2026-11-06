# Duplication Gate

`make duplication-check` measures clone-duplicated lines of the production Go population in the working tree and in a fresh materialisation of the merge-base with `develop`, applies three no-worsening rules and prints any findings. `make duplication-report` writes the same measurement as a versioned metric file without gating. `make duplication-replay` replays the rules over the last `DUPLICATION_REPLAY_N` (default 30) merged develop commits at `DUPLICATION_THRESHOLD` and prints per-PR outcomes and totals; set `DUPLICATION_BASELINE` to a ref to also print its baseline. Results are recorded in [duplication-gate-calibration.md](duplication-gate-calibration.md). The gate is not yet part of `make test-commit` or CI.

## What is measured

The production population is the one the [complexity report](complexity-gate.md#what-is-measured) measures: the file walk `analyzer.WalkProduction` is shared, so both tools see the same files. `_test.go`, `*.pb.go`, generated files, the top-level `test/`, `web/` and `scripts/` trees, `bin/`, `build/`, `data/`, `node_modules/`, `vendor/`, dot-directories and nested modules are excluded.

## The unit

The detector (`scripts/complexity/duplication/detector`) works on `go/scanner` tokens:

- comments are dropped from the token stream; the package clause and import declarations are skipped;
- every identifier is one `IDENT` token and literals are one token per kind, so renaming identifiers or changing constants does not hide a copy (Type-1/2 clones);
- keywords and operators are kept verbatim.

Every window of K consecutive tokens (K is the threshold, default 200, `-threshold` overrides; see [calibration](duplication-gate-calibration.md) for how it was chosen) gets a rolling 64-bit hash. Windows are bucketed tree-wide by hash and each bucket is verified by comparing the actual tokens, so a hash collision never creates a clone. A window is in a clone when its verified bucket holds another window in a different file, or one whose token range does not intersect its own. A **run** is a maximal sequence of consecutive in-clone windows of one file. A line counts as duplicated when it carries a token inside an unannotated run.

These numbers are in scanner tokens over verified windows. They do not transfer from `dupl` or any other tool, which use different units and thresholds.

## Gate rules

The previous measurement is the merge-base tree, measured with the same detector and threshold. Runs are compared by token count, never by line span, so adding a comment inside a clone does not read as growth.

| Rule | Fails when | Allows |
|------|------------|--------|
| 1 aggregate | Current duplicated lines exceed the merge-base's | Reducing or holding the total |
| 2 new clone | A run in a touched file has no window that was duplicated at the merge-base | Touching a file that holds only pre-existing clones |
| 3 growth | A run in a touched file (not already a rule 2 finding) has a window with more copies than at the merge-base, or is longer in tokens than the longest merge-base run of the same path sharing a window with it | Shrinking a clone, editing the rest of a touched file |

A commit that adds a copy fires rules 1 and 2. A pure reflow (identical tokens spread over more token-bearing lines) fires rule 1 only.

## The unannotated metric

Annotated runs are removed before totals are computed. `duplicated_lines` is the unannotated total that rule 1 compares; `annotated_lines` is reported alongside it in the metric file and the report summary, so annotated duplication stays visible.

## Annotations

```go
//duplication:justified <repo-relative-path> -- <reason>
```

The comment attaches to the run containing its line; otherwise to the run that starts within the 3 lines below it (nearest wins). It is valid when the reason is non-empty and the named path is the file of another position in the same verified bucket as some window of the run. Validity is judged on buckets built from all positions, so mutual annotation (A names B, B names A) is valid for both.

## Invalid annotations

An invalid annotation (malformed, empty reason, or a path that is not a duplicate partner) exempts nothing: the copy is an unannotated run and the rules apply to it. Invalid annotations of the working tree are printed as `invalid annotation: <file>:<line>: <reason>`. They never fail the gate alone: a tree whose only problem is an invalid annotation exits 0.

## Failure format

One line per finding on stdout, then exit 1:

```text
aggregate: rule 1: duplicated lines 12 -> 30
pkg/b/b.go:3: rule 2: new duplicated block of 183 tokens
pkg/a/a.go:3: rule 3: duplicated block grew 150 -> 160 tokens
```

On success the command prints `duplication gate: pass`. Exit codes: 0 pass, 1 findings, 2 usage, IO or parse error, or history too shallow to compute the merge-base.

## Merge-base and touched files

`MergeBase` resolves the merge-base with `origin/develop` (falling back to the first of its base refs that exists) and fails closed with exit 2 on a shallow clone, as the complexity check does; CI must fetch full history. The merge-base tree is extracted with `git archive` into a temporary directory and the worktree and index are left unchanged. Touched files are the paths committed since the merge-base plus staged, unstaged and untracked changes. Rules 2 and 3 apply only to runs in touched files; rule 1 is tree-wide.

## CI and anti-gaming

### Where the gate runs

- `make test-commit` runs `duplication-check` locally.
- The `duplication-gate` job in `.github/workflows/test-suite.yml` runs `make duplication-check` on every `pull_request` and `merge_group`, with a full-history checkout and no path filter. The `unit-tests` aggregator lists it in `needs:` and checks its result before the docs-only exit, so a docs-only pull request cannot skip it.
- In the merge queue the job runs and posts its own `duplication-gate` context, but blocking is pull-request-side only, through the aggregator. The context is not in the branch ruleset's required checks.

### Baseline

There is no ratchet file to move. Each run measures the merge-base with develop afresh and compares the working tree against it (see [Merge-base and touched files](#merge-base-and-touched-files)), so the checkout needs full history (`fetch-depth: 0`).

### Protected paths

The tooling under `scripts/complexity/`, including the duplication tree and the `DefaultThreshold` constant, is protected against quiet edits by the CLAUDE.md scope constraints, a `CODEOWNERS` entry for `/scripts/complexity/`, and an acceptance-reviewer rule. That rule treats a diff touching `DefaultThreshold` as a finding unless the story names it, and lists every `//duplication:justified` line the diff adds so annotations stay visible.

## Limits

- Moved or renamed clone code is not flagged: a clone is judged by its windows, so relocating a pre-existing duplicated block is not new duplication.
- An annotated copy is excluded from every rule, including growth. It is visible only in the annotated total.
- Only syntactic (Type-1/2) clones are found; there is no semantic duplication detection.
