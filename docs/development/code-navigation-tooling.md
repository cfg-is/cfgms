# Code Navigation Tooling — grep + Read

This is the navigation workflow for answering "what work has been done" across the
codebase, and the measurements behind it. It backs the [Code Navigation](../../CLAUDE.md#code-navigation-grep--read)
rules in `CLAUDE.md`.

**Why this exists:** weak grepping produces *false confidence* — an agent concludes it
understands a topic without actually knowing what is there. The fix is a verification
discipline: every search is paired with a read of the code it found, and with an
authoritative gate where one exists.

## grep's failure mode — false confidence on "is it real?"

grep finds *text*. It cannot tell you whether a symbol is wired or a stub, and a
keyword that *looks* covered invites a confident-but-wrong conclusion. In the
2026-06-30 comparison run, the grep arm found `RaftConsensus` and **guessed "stub"**
without reading the body — it is fully implemented. grep's strength is the opposite:
exhaustive, stable recall of definitions, callers, usages and imports.

## grep is build-tag-agnostic

grep reads every file regardless of `GOOS`. Tools built on `go/packages` analyze one
build configuration at a time, so on a Linux host they drop `//go:build windows`
files from the package:

```
GOOS=linux go list -f '{{.GoFiles}}' ./features/modules/hyperv   # excludes *_windows.go
```

Files outside a Linux build configuration include `cluster_windows.go` (the cluster
DNA Monitor: `monitorClusterLoop`, `pollClusterStatus`, `dispatchCluster`),
`monitor_windows.go` (`startClusterMonitorLocked`), and
`pstransport_dispatch_windows.go` (the closed PS dispatch table). grep is
authoritative for these packages.

## Recommended workflow

1. **Find the definition → grep.** `grep -rnE 'func (\([^)]*\) )?Name\b' --include='*.go' .`
   for functions and methods, `grep -rn 'type Name ' --include='*.go' .` for types.
   A symbol grep cannot find does not exist where a citation says it does.
2. **Completeness → grep, exhaustively.** `grep -rn '\bName(' --include='*.go' .` for
   callers. Reconcile interface implementations with a `var _ Iface = (*T)(nil)` grep
   and filter test doubles.
3. **Read narrowly.** Take the line number from `grep -n` and Read that region with
   `offset`/`limit` rather than pulling the whole file again.
4. **Wired-vs-stub → read the body** + grep stub markers
   (`ErrNotImplemented|panic\("TODO"|return nil //`) + run the real gate
   (`go vet`, `make check-architecture`, tests). Run an authoritative gate rather than
   inferring; e.g. `make check-architecture` is the oracle for provider-import
   violations (note it is two parts: a staged-only delta gate in the `Makefile`, plus
   the full-tree `scripts/check-providers.sh`).
5. **Confidence = verification depth.** One grep keyword is *low* confidence until
   cross-verified; "read the body + two methods agree" is *high*.

The adversarial gates (acceptance-checker, tech-lead validation, QA, security review,
`make check-architecture`, tests) are the safety net that converts "thought it
understood" into "verified" — these navigation rules reduce how often the gates must
catch a comprehension error, they do not replace them.

## Semantic navigation server removed (#5586)

A gopls-backed MCP navigation server was configured for agent sessions until
#5586 removed it. Measured over 783 Claude Code transcripts (Sep–Oct 2026), subagents
made 68 calls to it and main sessions made none, against about 12,500 grep calls.
Every session started its own server and gopls process, about 350 MB RSS each with no
calls made. The 2026-06-30 comparison had already recorded two failure modes for it:
relational queries returned incomplete caller sets on a cold gopls index, and a Linux
gopls could not see `//go:build windows` files.
