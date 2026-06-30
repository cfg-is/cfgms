# Code navigation: serena + grep discipline (CFGMS)

Serena's symbolic tools are best for **structure** (`get_symbols_overview`,
`find_symbol`, `replace_symbol_body`). For **completeness** (callers, usages, impls)
they are *hints, not a complete set* — combine with grep. Measured details +
re-run harness: `docs/development/code-navigation-tooling.md`.

Two reproducible failure modes to guard against:

1. **Cold gopls index → incomplete relational results.** The first
   `find_referencing_symbols` / `find_implementations` of a session can silently
   miss real callers (observed: it dropped `vm.go:registerClusteredRole` as a caller
   of `setCluster`; a warm re-run found it). Mitigation: prime gopls with a
   `get_symbols_overview` on the target + likely caller packages, then re-run and
   union. Don't trust the first relational call of a session.

2. **gopls sees ONE build configuration → blind to other-`GOOS` code.** On Linux
   (the dev containers' default `GOOS=linux`), serena cannot see `//go:build windows`
   files. Verified: a Linux gopls drops `pollClusterStatus`→`getCluster` because
   `cluster_windows.go` is excluded. **Build-tagged packages where serena under-reports
   on Linux — use grep (build-tag-agnostic) as authoritative:**
   - `features/modules/hyperv/*_windows.go` — `cluster_windows.go` (cluster DNA
     Monitor), `monitor_windows.go`, `pstransport_dispatch_windows.go` (PS dispatch
     table), `pstransport_*_windows.go`, `detection_windows.go`, `executor_windows.go`.
   - Generally: any `*_windows.go` / `*_nonwindows.go` / build-tagged file.

Also: `find_implementations` includes test doubles — filter them and reconcile with a
`var _ Iface = (*T)(nil)` grep. For "is it implemented or a stub?", read the body and
run the real gate (`go vet`, `make check-architecture`, tests) — don't infer from a
symbol's existence. Calibrate claim confidence to verification depth.
