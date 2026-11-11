#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 Jordan Ritz
#
# check-dead-packages.sh — fail when a non-test package in this module is
# unreachable from every `main` package (Issue #4317).
#
# 41 non-test product packages (about 52,500 lines, 13.7% of the repo's
# non-test Go) were added as sibling packages and never wired into a
# binary. Nothing detected the drift because nothing computed reachability.
# This gate closes that: it computes the reachable set as the transitive
# production-import closure of every `main` package in the module, and
# fails when a package exists in the module but not in that closure, unless
# the package carries a written-reason entry in the allowlist file
# (scripts/dead-packages-allowlist.yaml by default).
#
# Method (three commands, per Issue #4317's implementation notes):
#   1. mains      = every package in the module with Name == "main"
#   2. reachable  = go list -deps <mains>            (transitive closure)
#   3. all        = go list ./...                    (every module package)
#   unreachable = all - reachable
#
# Cross-OS union (Issue #6161): build constraints decide which files — and so
# which imports — `go list` sees, so a single-GOOS scan gives a verdict that
# depends on the host. Every `go list` call therefore runs once per shipped
# GOOS (linux, windows, darwin), with GOOS set explicitly (never inherited
# from the environment) and CGO_ENABLED=0, and the outputs are merged with
# `sort -u`. `all`, `mains`, the production-reachable set and the _test.go
# import edges are each the union over the three OSes: a package is reachable
# if a main package reaches it on ANY shipped OS, and is test-support if a
# reachable package imports it from a _test.go file on ANY of them. The result
# is identical whichever GOOS the caller exported. A `go list` failure under
# any of the three OSes fails closed (exit 2).
#
# Matching is by exact import path (a flat set), never by string prefix, so
# a parent package being unreachable never marks a reachable child
# unreachable — each is its own entry in `go list ./...`, and `comm` compares
# whole lines. Do not "optimize" this into a prefix/substring check: that
# exact mistake previously inflated a 28-item result to 65 during triage.
#
# `unreachable` packages that are imported — directly or transitively, in
# production code — by the _test.go files of a package that IS
# production-reachable are legitimate test-support packages (pkg/testutil,
# pkg/testing, ...) and are reported separately. They are informational only
# and never require an allowlist entry: only a package reachable from
# NEITHER production code NOR the test graph of production code needs one.
#
# This intentionally does NOT walk importers ("does anything import this
# package?"). A package can have an importer that is itself unreachable from
# every main package — a provider package imported only by another package that
# no main package reaches still looks "imported" to a backward walk. An
# importer-walking implementation reports such a package as reachable; this
# one does not, because it starts from `main` packages and walks forward, not
# from an arbitrary package and walks backward. See
# scripts/check-dead-packages_test.sh for a fixture covering exactly this
# shape.
#
# Usage:
#   scripts/check-dead-packages.sh [allowlist-file]
#     allowlist-file defaults to scripts/dead-packages-allowlist.yaml,
#     resolved relative to the current directory. Run from the module root.
#
# Exit codes:
#   0  every unreachable package is allowlisted, and every allowlist entry
#      still applies (still unreachable, still exists)
#   1  an unreachable, non-allowlisted package was found, or a stale
#      allowlist entry was found
#   2  the scan could not be performed — fails closed (missing tool, not a
#      module root, go list failure)
#
# Tests: scripts/check-dead-packages_test.sh

set -euo pipefail

ALLOWLIST_FILE="${1:-scripts/dead-packages-allowlist.yaml}"

if ! command -v go >/dev/null 2>&1; then
    echo "ERROR: go not found in PATH; package reachability not verified" >&2
    exit 2
fi

if ! command -v jq >/dev/null 2>&1; then
    echo "ERROR: jq not found in PATH; package reachability not verified" >&2
    exit 2
fi

if [ ! -f "go.mod" ]; then
    echo "ERROR: no go.mod in current directory; run from the module root" >&2
    exit 2
fi

workdir="$(mktemp -d)"
trap 'rm -rf "$workdir"' EXIT

MODPATH="$(go list -m)"

# Operating systems CFGMS ships binaries for. Reachability is computed under
# each one and unioned, so the verdict does not depend on the host's GOOS.
SHIPPED_GOOS="linux windows darwin"

# golist <goos> <go list args...> — runs `go list` for one target OS. GOOS is
# always set explicitly (never inherited from the host) and CGO_ENABLED=0 keeps
# a cgo-only file set from changing the result between hosts. A failure is the
# caller's to turn into exit 2.
golist() {
    local os="$1"
    shift
    GOOS="$os" CGO_ENABLED=0 go list "$@"
}

# --- per-OS passes -----------------------------------------------------------
# For each GOOS, in $workdir/<goos>/:
#   all_mod.txt         every module package with a buildable file on that OS
#   mains.txt           every `main` package on that OS
#   prod_reachable.txt  transitive production-import closure of those mains
#   test_edges.tsv      importer<TAB>imported for every _test.go import
for os in $SHIPPED_GOOS; do
    d="$workdir/$os"
    mkdir -p "$d"

    # 1. every non-test package the module contains on this OS
    if ! golist "$os" ./... >"$d/all_raw.txt" 2>"$d/all.err"; then
        echo "ERROR: go list ./... failed (GOOS=$os):" >&2
        cat "$d/all.err" >&2
        exit 2
    fi
    # `go list ./...` descends into vendored third-party trees. `web/node_modules`
    # ships Go sample files inside npm packages: unreachable by definition, not this
    # repository's code, and impossible to either wire in or delete. They are excluded
    # here rather than allowlisted, because the allowlist records deliberate choices
    # about our own packages. `vendor/` needs no exclusion — module mode already omits it.
    awk -v pre="$MODPATH/" -v mod="$MODPATH" \
        '(index($0, pre) == 1 || $0 == mod) && $0 !~ /(^|\/)node_modules(\/|$)/' \
        "$d/all_raw.txt" | sort -u >"$d/all_mod.txt"

    # 2. every `main` package on this OS: the binaries this module can ship
    if ! golist "$os" -f '{{if eq .Name "main"}}{{.ImportPath}}{{end}}' ./... \
        >"$d/mains_raw.txt" 2>"$d/mains.err"; then
        echo "ERROR: go list (main packages) failed (GOOS=$os):" >&2
        cat "$d/mains.err" >&2
        exit 2
    fi
    grep . "$d/mains_raw.txt" | sort -u >"$d/mains.txt" || true

    # 3. transitive production-import closure of every main package. An OS
    # with no main package contributes nothing here; the union check below
    # rejects a module with no main package on any OS.
    : >"$d/prod_reachable.txt"
    if [ -s "$d/mains.txt" ]; then
        if ! xargs env GOOS="$os" CGO_ENABLED=0 go list -deps <"$d/mains.txt" \
            >"$d/prod_reachable_raw.txt" 2>"$d/deps.err"; then
            echo "ERROR: go list -deps failed (GOOS=$os):" >&2
            cat "$d/deps.err" >&2
            exit 2
        fi
        awk -v pre="$MODPATH/" -v mod="$MODPATH" 'index($0, pre) == 1 || $0 == mod' \
            "$d/prod_reachable_raw.txt" | sort -u >"$d/prod_reachable.txt"
    fi

    # 4. _test.go import edges on this OS (build-tagged test files only
    # appear under the OS their tags select)
    if ! golist "$os" -json ./... >"$d/all.json" 2>"$d/json.err"; then
        echo "ERROR: go list -json ./... failed (GOOS=$os):" >&2
        cat "$d/json.err" >&2
        exit 2
    fi
    jq -r --arg mod "$MODPATH" '
      .ImportPath as $ip
      | ((.TestImports // []) + (.XTestImports // []))
      | .[]
      | select(startswith($mod + "/") or . == $mod)
      | "\($ip)\t\(.)"
    ' "$d/all.json" >"$d/test_edges.tsv"
done

# --- union across the shipped OSes ------------------------------------------
# A package counts as production-reachable if a main package reaches it on any
# shipped GOOS; a package that exists on only one OS must not drop out of `all`
# on the others.
for f in all_mod.txt mains.txt prod_reachable.txt test_edges.tsv; do
    for os in $SHIPPED_GOOS; do cat "$workdir/$os/$f"; done | sort -u >"$workdir/$f"
done

if [ ! -s "$workdir/mains.txt" ]; then
    echo "ERROR: no main packages found in module; cannot compute reachability" >&2
    exit 2
fi

# Scan tracked files only: an untracked .go file (a stray generated
# steward/steward.pb.go, say) makes `go list` see a package CI never sees. Drop
# packages whose directory has no tracked .go file. Skipped outside a git
# checkout, where there is no tracked set to compare against.
cp "$workdir/all_mod.txt" "$workdir/all.txt"
if git ls-files --error-unmatch go.mod >/dev/null 2>&1; then
    git ls-files -- '*.go' | sed -E 's|/?[^/]+$||; s|^$|.|' | sort -u >"$workdir/tracked_dirs.txt"
    awk -v mod="$MODPATH" 'NR==FNR{t[$0]=1; next}
        { d = ($0 == mod) ? "." : substr($0, length(mod) + 2); if (d in t) print }' \
        "$workdir/tracked_dirs.txt" "$workdir/all_mod.txt" >"$workdir/all.txt"
fi

comm -23 "$workdir/all.txt" "$workdir/prod_reachable.txt" >"$workdir/unreachable.txt"

# --- test-support frontier: packages imported by _test.go files of a -------
# --- package that IS production-reachable (on any shipped GOOS) -------------
awk -F'\t' 'NR==FNR{prod[$1]=1; next} ($1 in prod){print $2}' \
    "$workdir/prod_reachable.txt" "$workdir/test_edges.tsv" | sort -u >"$workdir/frontier.txt"

# The frontier's own dependencies are walked per OS, restricted to frontier
# packages that have a buildable file there: `go list -deps` on a package whose
# files are all excluded by build constraints (a windows-only helper, seen from
# linux) is an error, not an empty result.
: >"$workdir/frontier_deps.txt"
for os in $SHIPPED_GOOS; do
    d="$workdir/$os"
    comm -12 "$workdir/frontier.txt" "$d/all_mod.txt" >"$d/frontier.txt"
    [ -s "$d/frontier.txt" ] || continue
    if ! xargs env GOOS="$os" CGO_ENABLED=0 go list -deps <"$d/frontier.txt" \
        >"$d/frontier_deps_raw.txt" 2>"$d/fdeps.err"; then
        echo "ERROR: go list -deps (test-support frontier) failed (GOOS=$os):" >&2
        cat "$d/fdeps.err" >&2
        exit 2
    fi
    awk -v pre="$MODPATH/" -v mod="$MODPATH" 'index($0, pre) == 1 || $0 == mod' \
        "$d/frontier_deps_raw.txt" >>"$workdir/frontier_deps.txt"
done
cat "$workdir/frontier.txt" "$workdir/frontier_deps.txt" | sort -u >"$workdir/test_reachable.txt"

comm -12 "$workdir/unreachable.txt" "$workdir/test_reachable.txt" >"$workdir/test_only.txt"
comm -23 "$workdir/unreachable.txt" "$workdir/test_reachable.txt" >"$workdir/dead.txt"

# --- allowlist ---------------------------------------------------------------
: >"$workdir/allowlist_paths.txt"
if [ -f "$ALLOWLIST_FILE" ]; then
    grep -E '^[[:space:]]*-[[:space:]]*path:[[:space:]]*' "$ALLOWLIST_FILE" \
        | sed -E 's/^[[:space:]]*-[[:space:]]*path:[[:space:]]*//' \
        | sed -E 's/[[:space:]]*#.*$//' \
        | sed -E "s/^\"(.*)\"\$/\\1/; s/^'(.*)'\$/\\1/" \
        | sed -E 's/[[:space:]]+$//' \
        | awk -v mod="$MODPATH" '{print mod "/" $0}' \
        | sort -u >"$workdir/allowlist_paths.txt"
fi

fail=0

echo "📦 Non-test packages unreachable from every main package:"
if [ -s "$workdir/dead.txt" ]; then
    sed "s|^|  |" "$workdir/dead.txt"
else
    echo "  none"
fi

echo ""
echo "📦 Packages reachable only from _test.go files (test-support, informational):"
if [ -s "$workdir/test_only.txt" ]; then
    sed "s|^|  |" "$workdir/test_only.txt"
else
    echo "  none"
fi
echo ""

unallowlisted="$(comm -23 "$workdir/dead.txt" "$workdir/allowlist_paths.txt")"
if [ -n "$unallowlisted" ]; then
    echo "❌ Unreachable package(s) not in $ALLOWLIST_FILE:" >&2
    echo "$unallowlisted" | sed 's/^/  /' >&2
    echo "" >&2
    echo "   Either wire the package into a main package, remove the package," >&2
    echo "   or add a written-reason entry to $ALLOWLIST_FILE (see its header)." >&2
    fail=1
fi

stale="$(comm -13 "$workdir/dead.txt" "$workdir/allowlist_paths.txt")"
if [ -n "$stale" ]; then
    echo "❌ Stale $ALLOWLIST_FILE entries (no longer unreachable, or no longer exist):" >&2
    echo "$stale" | sed 's/^/  /' >&2
    echo "" >&2
    echo "   Remove these entries — an allowlist entry for a package that is" >&2
    echo "   actually reachable hides real reachability information." >&2
    fail=1
fi

if [ "$fail" -eq 0 ]; then
    echo "✅ Every unreachable package is allowlisted with a written reason"
fi

exit "$fail"
