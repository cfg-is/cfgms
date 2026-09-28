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
# every main package — pkg/directory/interfaces is imported only by
# features/controller/directory, which is imported only by features/controller,
# and none of the three is reachable from any main package. An
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

# --- 1. every non-test package the module currently contains ---------------
if ! go list ./... >"$workdir/all_raw.txt" 2>"$workdir/all.err"; then
    echo "ERROR: go list ./... failed:" >&2
    cat "$workdir/all.err" >&2
    exit 2
fi
# `go list ./...` descends into vendored third-party trees. `web/node_modules`
# ships Go sample files inside npm packages: unreachable by definition, not this
# repository's code, and impossible to either wire in or delete. They are excluded
# here rather than allowlisted, because the allowlist records deliberate choices
# about our own packages. `vendor/` needs no exclusion — module mode already omits it.
awk -v pre="$MODPATH/" -v mod="$MODPATH" \
    '(index($0, pre) == 1 || $0 == mod) && $0 !~ /(^|\/)node_modules(\/|$)/' \
    "$workdir/all_raw.txt" | sort -u >"$workdir/all.txt"

# --- 2. every `main` package: the set of binaries this module ships --------
go list -f '{{if eq .Name "main"}}{{.ImportPath}}{{end}}' ./... 2>"$workdir/mains.err" \
    | grep . >"$workdir/mains.txt" || true
if [ ! -s "$workdir/mains.txt" ]; then
    echo "ERROR: no main packages found in module; cannot compute reachability" >&2
    cat "$workdir/mains.err" >&2
    exit 2
fi

# --- 3. transitive production-import closure of every main package ---------
if ! xargs go list -deps <"$workdir/mains.txt" >"$workdir/prod_reachable_raw.txt" 2>"$workdir/deps.err"; then
    echo "ERROR: go list -deps failed:" >&2
    cat "$workdir/deps.err" >&2
    exit 2
fi
awk -v pre="$MODPATH/" -v mod="$MODPATH" 'index($0, pre) == 1 || $0 == mod' \
    "$workdir/prod_reachable_raw.txt" | sort -u >"$workdir/prod_reachable.txt"

comm -23 "$workdir/all.txt" "$workdir/prod_reachable.txt" >"$workdir/unreachable.txt"

# --- test-support frontier: packages imported by _test.go files of a -------
# --- package that IS production-reachable -----------------------------------
if ! go list -json ./... >"$workdir/all.json" 2>"$workdir/json.err"; then
    echo "ERROR: go list -json ./... failed:" >&2
    cat "$workdir/json.err" >&2
    exit 2
fi
jq -r --arg mod "$MODPATH" '
  .ImportPath as $ip
  | ((.TestImports // []) + (.XTestImports // []))
  | .[]
  | select(startswith($mod + "/") or . == $mod)
  | "\($ip)\t\(.)"
' "$workdir/all.json" >"$workdir/test_edges.tsv"

awk -F'\t' 'NR==FNR{prod[$1]=1; next} ($1 in prod){print $2}' \
    "$workdir/prod_reachable.txt" "$workdir/test_edges.tsv" | sort -u >"$workdir/frontier.txt"

if [ -s "$workdir/frontier.txt" ]; then
    if ! xargs go list -deps <"$workdir/frontier.txt" >"$workdir/frontier_deps_raw.txt" 2>"$workdir/fdeps.err"; then
        echo "ERROR: go list -deps (test-support frontier) failed:" >&2
        cat "$workdir/fdeps.err" >&2
        exit 2
    fi
    awk -v pre="$MODPATH/" -v mod="$MODPATH" 'index($0, pre) == 1 || $0 == mod' \
        "$workdir/frontier_deps_raw.txt" >"$workdir/frontier_deps.txt"
else
    : >"$workdir/frontier_deps.txt"
fi
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
