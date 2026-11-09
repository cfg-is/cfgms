#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 Jordan Ritz
#
# macos-pr-filter.sh — decide whether a pull request can affect the native
# macOS unit-test legs of cross-platform-build-pr.yml (Issue #5974).
#
# Usage:
#   scripts/macos-pr-filter.sh --files <changed-files> [--renamed <old-names>] [--root <module-dir>]
#   scripts/macos-pr-filter.sh --print-shipped-closure [--root <module-dir>]
#   scripts/macos-pr-filter.sh --print-closure [--root <module-dir>]
#
#   --files    one changed path per line, relative to the module root
#   --renamed  optional: the pre-rename names of renamed files, one per line.
#              Kept in a separate file so the workflow's `listed ==
#              changed_files` completeness check is not affected.
#   --root     module root to evaluate (default: the repository root)
#   --print-shipped-closure  print the module-relative directories of step 1
#              below, one per line, and exit (used by the tests)
#   --print-closure          the same for the full closure (steps 1 and 2)
#
# Output: exactly one line on stdout, `macos=true` or `macos=false`. Warnings
# go to stderr as `::warning::` workflow commands.
#
# THIS FILTER MUST FAIL CLOSED. macOS runs on the PR side only (the merge
# queue does not repeat it), so a wrongly skipped leg ships untested code. Any
# defect — an unreadable or empty input list, a `go list` error or empty
# package list, any unexpected error — resolves to `macos=true`. `macos=false`
# is printed only when the filter ran to completion and matched no file.
#
# Closure rule (a changed file can affect macOS when it is in this set):
#   1. P: in-module packages from `GOOS=darwin go list -deps` of the macOS
#      binaries (MACOS_SHIPPED_ROOTS in the Makefile), with no test-file
#      predicate — a package without tests is still compiled into the test
#      binaries that import it.
#   2. Plus the in-module packages from `GOOS=darwin go list -deps -test` of P
#      (test-only imports such as shared test helpers), except packages under
#      features/controller/ or cmd/controller/ that are not already in P.
#      Those are controller code that closure tests start in-process; it never
#      ships on macOS, and a darwin compile break in it is caught by the
#      macos-test-compile job.
#   3. For each package: its directory, its testdata/ tree and every file in
#      EmbedFiles, TestEmbedFiles and XTestEmbedFiles.
#   A changed file matches when its directory equals a package directory (any
#   file there, not only *.go), it is under such a directory's testdata/, or
#   it is one of those embed files. go.mod, go.sum, the Makefile, the PR
#   workflow and this script always match.
#
# Cross-package file reads by closure tests (a test reading another package's
# source text) are deliberately not triggers: the result does not depend on
# the OS and the Linux unit legs run those tests on every code PR.
#
# Tests: test_macos_pr_filter in scripts/test-scripts.sh.

set -uo pipefail

ALWAYS_TRIGGER=(
    go.mod
    go.sum
    Makefile
    .github/workflows/cross-platform-build-pr.yml
    scripts/macos-pr-filter.sh
)

files_arg=""
renamed_arg=""
root_arg=""
mode="filter"

while [ "$#" -gt 0 ]; do
    case "$1" in
        --files)    files_arg="${2:-}"; shift 2 || break ;;
        --renamed)  renamed_arg="${2:-}"; shift 2 || break ;;
        --root)     root_arg="${2:-}"; shift 2 || break ;;
        --print-shipped-closure) mode="print-shipped"; shift ;;
        --print-closure)         mode="print-closure"; shift ;;
        *) echo "::warning::macos-pr-filter: unknown argument '$1'" >&2; echo "macos=true"; exit 0 ;;
    esac
done

fail_closed() {
    echo "::warning::macos-pr-filter: $1 — assuming the macOS legs are affected" >&2
    echo "macos=true"
    exit 0
}

if [ "$mode" = "filter" ]; then
    [ -n "$files_arg" ] || fail_closed "no --files argument"
    [ -r "$files_arg" ] || fail_closed "changed-file list '$files_arg' is unreadable"
fi

root="${root_arg:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
[ -d "$root" ] || fail_closed "module root '$root' is not a directory"
root=$(cd "$root" && pwd) || fail_closed "cannot enter module root"

# Read the macOS binary roots from the Makefile so they cannot drift from
# MACOS_SHIPPED_PKGS.
roots=""
if [ -r "$root/Makefile" ]; then
    roots=$(sed -n 's/^MACOS_SHIPPED_ROOTS[[:space:]]*=[[:space:]]*//p' "$root/Makefile" | head -1)
fi
[ -n "$roots" ] || fail_closed "MACOS_SHIPPED_ROOTS not found in $root/Makefile"

work=$(mktemp -d) || fail_closed "cannot create a temporary directory"
trap 'rm -rf "$work"' EXIT

# Step 1: in-module packages in the darwin dependency closure of the binaries.
# shellcheck disable=SC2086 # $roots is a space-separated package list
(cd "$root" && GOOS=darwin go list -deps \
    -f '{{if and (not .Standard) .Module}}{{if .Module.Main}}{{.ImportPath}}{{end}}{{end}}' \
    $roots) > "$work/p1.txt" 2> "$work/p1.err" \
    || fail_closed "go list -deps failed: $(head -c 300 "$work/p1.err" | tr '\n' ' ')"
sort -u -o "$work/p1.txt" "$work/p1.txt"
[ -s "$work/p1.txt" ] || fail_closed "go list -deps returned no in-module packages"

# One line per package: D<TAB>dir, plus F<TAB>file<TAB>dir for each embedded
# file. Dir is absolute; the awk below makes it module-relative.
LIST_FMT='{{if and (not .Standard) .Module}}{{if .Module.Main}}D{{"\t"}}{{.Dir}}{{"\n"}}{{range .EmbedFiles}}F{{"\t"}}{{$.Dir}}/{{.}}{{"\t"}}{{$.Dir}}{{"\n"}}{{end}}{{range .TestEmbedFiles}}F{{"\t"}}{{$.Dir}}/{{.}}{{"\t"}}{{$.Dir}}{{"\n"}}{{end}}{{range .XTestEmbedFiles}}F{{"\t"}}{{$.Dir}}/{{.}}{{"\t"}}{{$.Dir}}{{"\n"}}{{end}}{{end}}{{end}}'

# shellcheck disable=SC2046 # package list, one import path per word
(cd "$root" && GOOS=darwin go list -deps -f "$LIST_FMT" $(cat "$work/p1.txt")) \
    > "$work/s1.raw" 2> "$work/s1.err" \
    || fail_closed "go list of step 1 packages failed: $(head -c 300 "$work/s1.err" | tr '\n' ' ')"

# shellcheck disable=SC2046
(cd "$root" && GOOS=darwin go list -deps -test -f "$LIST_FMT" $(cat "$work/p1.txt")) \
    > "$work/s2.raw" 2> "$work/s2.err" \
    || fail_closed "go list -deps -test failed: $(head -c 300 "$work/s2.err" | tr '\n' ' ')"

# Module-relative entries, deduplicated.
relativize() {
    awk -F'\t' -v root="$root/" '
        function rel(p) {
            if (index(p, root) == 1) return substr(p, length(root) + 1)
            if (p == substr(root, 1, length(root) - 1)) return "."
            return p
        }
        $1 == "D" { print "D\t" rel($2) "\t" rel($2) }
        $1 == "F" { print "F\t" rel($2) "\t" rel($3) }' "$1" | sort -u
}
relativize "$work/s1.raw" > "$work/s1.rel" || fail_closed "cannot relativize step 1 paths"
relativize "$work/s2.raw" > "$work/s2.rel" || fail_closed "cannot relativize step 2 paths"
[ -s "$work/s1.rel" ] || fail_closed "step 1 produced no package directories"

awk -F'\t' '$1 == "D" { print $2 }' "$work/s1.rel" | sort -u > "$work/s1.dirs"

if [ "$mode" = "print-shipped" ]; then
    cat "$work/s1.dirs"
    exit 0
fi

# Step 2: test-only imports, minus controller code not already in step 1. An
# embed file follows the package that owns it (third field).
is_controller() {
    case "$1" in
        features/controller|features/controller/*|cmd/controller|cmd/controller/*) return 0 ;;
        *) return 1 ;;
    esac
}
cp "$work/s1.rel" "$work/closure.rel"
while IFS=$'\t' read -r kind path owner; do
    if is_controller "$owner" && ! grep -qxF -- "$owner" "$work/s1.dirs"; then
        continue
    fi
    printf '%s\t%s\t%s\n' "$kind" "$path" "$owner" >> "$work/closure.rel"
done < "$work/s2.rel"
sort -u -o "$work/closure.rel" "$work/closure.rel"

awk -F'\t' '$1 == "D" { print $2 }' "$work/closure.rel" | sort -u > "$work/closure.dirs"
awk -F'\t' '$1 == "F" { print $2 }' "$work/closure.rel" | sort -u > "$work/closure.files"
[ -s "$work/closure.dirs" ] || fail_closed "the closure has no package directories"

if [ "$mode" = "print-closure" ]; then
    cat "$work/closure.dirs"
    exit 0
fi

# Step 3/4: match the changed files.
cat "$files_arg" > "$work/changed.txt" 2>/dev/null || fail_closed "cannot read '$files_arg'"
if [ -n "$renamed_arg" ]; then
    [ -r "$renamed_arg" ] || fail_closed "renamed-file list '$renamed_arg' is unreadable"
    cat "$renamed_arg" >> "$work/changed.txt"
fi
sed -i 's/\r$//; /^[[:space:]]*$/d' "$work/changed.txt" || fail_closed "cannot normalise the changed-file list"
[ -s "$work/changed.txt" ] || fail_closed "the changed-file list is empty"

printf '%s\n' "${ALWAYS_TRIGGER[@]}" > "$work/always.txt"

awk -v always="$work/always.txt" -v dirs="$work/closure.dirs" -v files="$work/closure.files" '
    function load(path, set,   line) {
        while ((getline line < path) > 0) set[line] = 1
        close(path)
    }
    BEGIN {
        load(always, A); load(dirs, D); load(files, F)
    }
    {
        f = $0
        sub(/^\.\//, "", f)
        if (f in A || f in F) { print f; found = 1; exit 0 }
        d = f
        if (index(d, "/") == 0) d = "."; else sub(/\/[^\/]*$/, "", d)
        if (d in D) { print f; found = 1; exit 0 }
        # Under <dir>/testdata/ of a closure package: walk the parents.
        p = f
        while (index(p, "/") > 0) {
            sub(/\/[^\/]*$/, "", p)
            n = split(p, parts, "/")
            if (parts[n] == "testdata") {
                q = p; sub(/\/?testdata$/, "", q)
                # q is the directory that owns this testdata/ ("" -> module root)
                if (q == "") q = "."
                if (q in D) { print f; found = 1; exit 0 }
            }
        }
    }
    END { exit (found ? 0 : 1) }
' "$work/changed.txt" > "$work/match.txt"
status=$?

case "$status" in
    0)
        echo "macOS closure file(s) changed — the macOS legs run: $(head -5 "$work/match.txt" | tr '\n' ' ')" >&2
        echo "macos=true"
        ;;
    1)
        echo "no changed file is in the macOS package closure — the macOS legs are skipped" >&2
        echo "macos=false"
        ;;
    *)
        fail_closed "matching the changed files failed (awk exit ${status})"
        ;;
esac
