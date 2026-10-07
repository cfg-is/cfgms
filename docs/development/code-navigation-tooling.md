# Code Navigation Tooling — serena (gopls) vs grep

This is a **measured**, re-runnable record of how reliable our two code-comprehension
tools are for answering "what work has been done" across the codebase, and the
workflow that follows from the data. It backs the [Code Navigation](../../CLAUDE.md#code-navigation-serena-mcp--grep)
rules in `CLAUDE.md`. Re-run it when the serena or gopls version changes.

**Why this exists:** weak grepping (or over-trusting a single semantic query) produces
*false confidence* — an agent concludes it understands a topic without actually knowing
what is there. The fix is not "pick the better tool"; it is a verification discipline,
because **each tool has a distinct, reproducible failure mode.**

## The two failure modes (verified 2026-06-30, go1.26.4, gopls v0.22.0)

### 1. grep — false confidence on "is it real?"
grep finds *text*. It cannot tell you whether a symbol is wired or a stub, and a
keyword that *looks* covered invites a confident-but-wrong conclusion. In testing,
the grep arm found `RaftConsensus` and **guessed "stub"** without reading the body —
it is fully implemented. grep's strength is the opposite: exhaustive, stable recall of
callers / usages / imports.

### 2. serena (gopls) — false completeness on "who calls this?"
serena's `find_referencing_symbols` / `find_implementations` run on gopls and can
silently return *incomplete* sets:

- **Cold-index miss (timing — fixable).** gopls type-checks packages lazily into an
  in-memory snapshot (no persistent index; every fresh session starts cold). A
  relational query that races the initial workspace load returns partial results.
  *Observed:* the first `find_referencing_symbols(setCluster)` of a session **omitted
  the real caller `vm.go:registerClusteredRole`**; the identical query, re-run warm,
  returned the complete set. **Mitigation:** prime gopls (a `get_symbols_overview` on
  the target + likely caller packages) and union a re-run; don't trust the first
  relational call of a session.

- **Build-tag / `GOOS` blindness (structural — NOT fixable by warming).** gopls
  analyzes one build configuration at a time. *Verified with gopls directly:*

  ```
  # callers of getCluster (features/modules/hyperv/cluster.go:194)
  GOOS=windows gopls references … → cluster_windows.go:79 (pollClusterStatus) + module.go:380
  GOOS=linux   gopls references … → module.go:380 only   # pollClusterStatus vanishes
  ```

  Because Linux dev containers default to `GOOS=linux`, serena there is blind to the
  windows-tagged hyperv surface — confirmed by cross-listing the package:

  ```
  GOOS=linux go list -f '{{.GoFiles}}' ./features/modules/hyperv   # excludes *_windows.go
  ```

  Files invisible to a Linux gopls/serena include `cluster_windows.go` (the entire
  cluster DNA Monitor: `monitorClusterLoop`, `pollClusterStatus`, `dispatchCluster`),
  `monitor_windows.go` (`startClusterMonitorLocked`), and
  `pstransport_dispatch_windows.go` (the closed PS dispatch table). **grep is
  build-tag-agnostic and is the mandatory backstop for these packages.**

## Recommended workflow

1. **Structure first → serena** (`get_symbols_overview` / `find_symbol`): accurate,
   cheap surface + signature maps.
2. **Completeness → grep, exhaustively.** Treat serena's relational finders as hints;
   cross-check and union a warm re-run. Filter `find_implementations` test doubles and
   reconcile with a `var _ Iface = (*T)(nil)` grep.
3. **Build-tagged packages → grep is authoritative.** On a Linux host, do not rely on
   serena for `//go:build windows` code (or set `GOOS` in gopls' config for the task —
   but it is single-GOOS, so you then lose the other platform's variants).
4. **Wired-vs-stub → read the body** + grep stub markers
   (`ErrNotImplemented|panic\("TODO"|return nil //`) + run the real gate
   (`go vet`, `make check-architecture`, tests). Run an authoritative gate rather than
   inferring; e.g. `make check-architecture` is the oracle for provider-import
   violations (note it is two parts: a staged-only delta gate in the `Makefile`, plus
   the full-tree `scripts/check-providers.sh`).
5. **Confidence = verification depth.** One grep keyword or one relational query is
   *low* confidence until cross-verified; "read the body + two methods agree" is *high*.

The adversarial gates (acceptance-checker, tech-lead validation, QA, security review,
`make check-architecture`, tests) are the safety net that converts "thought it
understood" into "verified" — these navigation rules reduce how often the gates must
catch a comprehension error, they do not replace them.

## Re-running the comparison

A repeatable 3-probe harness, each probe with an objective ground truth and a known
blind spot:

| Probe | Domain | Blind spot it targets | Objective oracle |
|---|---|---|---|
| P1 | Controller multi-node/cluster orchestration (#415) | finding the package when it isn't named "cluster"; wired-vs-stub | `go vet`, stub-marker grep, roadmap checkbox |
| P2 | Steward hyperv cluster module | cross-file *indirect* callers; PS verb mapping; build-tagged monitor | verified caller set; `pstransport_dispatch_windows.go` |
| P3 | Pluggable provider system | counting/locating interface *implementations*; provider-import violations | `make check-architecture`; `var _ Iface =` assertions; `pkg/README.md` |

Run two **isolated** agents (fresh context, identical probes, each logging its tool
calls + per-claim confidence): a **GREP-only** arm (no serena) and a **SERENA-only**
arm (no grep/glob for discovery). An **ORACLE** agent (all tools, cross-verified)
builds the scoring key and flags every grep/serena disagreement. A **JUDGE** scores both
arms vs the oracle on **recall / precision / false-confidence count / grounding % /
tool-cost**, per probe and overall.

Score the metric that matters most for our problem — **false-confidence count**: claims
asserted at high confidence that the oracle proves wrong. In the 2026-06-30 run the
worst event was the SERENA arm asserting (High confidence) architecture-violation
"pluggability breaks" that `make check-architecture` shows do not exist — a confident
wrong claim produced by reflexively grepping outside the tool's competence and trusting
the result. That is exactly the failure these rules exist to prevent.
