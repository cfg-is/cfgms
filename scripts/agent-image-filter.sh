#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 Jordan Ritz
#
# agent-image-filter.sh — decide whether a pull request can affect the agent
# image build that .github/workflows/agent-image-build.yml runs (Issue #6228).
#
# Usage:
#   scripts/agent-image-filter.sh --files <changed-files> [--dockerfile <path>]
#   scripts/agent-image-filter.sh --print-sources [--dockerfile <path>]
#
#   --files       one changed path per line, relative to the repository root
#   --dockerfile  the Dockerfile to read COPY sources from (default:
#                 .claude/tooling/devcontainer/Dockerfile under the repo root)
#   --print-sources  print the cfgms-context paths derived from the Dockerfile
#                 (a trailing `/` marks a directory prefix) and exit
#
# Output: exactly one line on stdout, `build=true` or `build=false`.
# Warnings go to stderr as `::warning::` workflow commands.
#
# The trigger set is DERIVED from the Dockerfile's COPY/ADD sources, so a new
# COPY cannot silently fall outside the filter:
#   - `--from=<stage>` copies are skipped (their sources are other stages);
#   - other `--flag=` options are stripped and the last token (the destination)
#     is dropped; a line may name several sources; `\` continuations are joined;
#   - a source ending in `/` is a directory prefix; any other source matches
#     that exact path (or a path under it, if it names a directory);
#   - a `.` / `./` source (`COPY . .`, the whole context, i.e. Go source) is
#     deliberately NOT a trigger: it would build the image on nearly every PR.
#
# Always-on triggers, hardcoded: the gitlink `.claude/tooling` (a submodule
# bump), anything under `.claude/tooling/devcontainer/`, `.dockerignore`, the
# workflow file, and this script with its test.
#
# THIS FILTER MUST FAIL CLOSED. `build=false` is printed only when the filter
# ran to completion over a non-empty list, a readable Dockerfile with at least
# one COPY/ADD line, and no file matched. Any defect resolves to `build=true`.
#
# Tests: scripts/agent-image-filter_test.sh

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
dockerfile="$REPO_ROOT/.claude/tooling/devcontainer/Dockerfile"
files_arg=""
print_sources=0

fail_closed() {
    echo "::warning::agent-image-filter: $1 — building the image" >&2
    echo "build=true"
    exit 0
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --files)         files_arg="${2:-}"; shift 2 || break ;;
        --dockerfile)    dockerfile="${2:-}"; shift 2 || break ;;
        --print-sources) print_sources=1; shift ;;
        *) fail_closed "unknown argument '$1'" ;;
    esac
done

[ -n "$dockerfile" ] || fail_closed "no --dockerfile value"
[ -f "$dockerfile" ] && [ -r "$dockerfile" ] || fail_closed "Dockerfile '$dockerfile' is unreadable"

# Emits one context source per line, plus a `#copy` marker per COPY/ADD line
# (including --from= ones) so the caller can fail closed on an empty parse.
parse_sources() {
    awk '
        function flush(line,    n, i, t, toks, srcs, kw, k) {
            sub(/^[ \t]+/, "", line)
            if (line == "" || substr(line, 1, 1) == "#") return
            n = split(line, toks, /[ \t]+/)
            kw = toupper(toks[1])
            if (kw != "COPY" && kw != "ADD") return
            print "#copy"
            k = 0
            for (i = 2; i <= n; i++) {
                t = toks[i]
                if (t == "") continue
                if (t ~ /^--from=/) return          # source is another stage
                if (t ~ /^--/) continue
                srcs[++k] = t
            }
            if (k > 0) k--                          # drop the destination
            for (i = 1; i <= k; i++) {
                t = srcs[i]
                if (t ~ /^<</) continue             # heredoc: inline content
                gsub(/^\[|\]$|"|,/, "", t)          # JSON-array form
                if (t == "") continue
                print t
            }
        }
        {
            sub(/\r$/, "")
            if (cur != "") { l = $0; sub(/^[ \t]+/, "", l); if (substr(l, 1, 1) == "#") next }
            if ($0 ~ /\\[ \t]*$/) { sub(/\\[ \t]*$/, ""); cur = cur " " $0; next }
            flush(cur " " $0); cur = ""
        }
        END { if (cur != "") flush(cur) }
    ' "$dockerfile"
}

parsed="$(parse_sources)" || fail_closed "cannot parse Dockerfile '$dockerfile'"
grep -qx '#copy' <<< "$parsed" || fail_closed "Dockerfile '$dockerfile' has no COPY/ADD line"

sources=()
while IFS= read -r src; do
    [ "$src" != "#copy" ] || continue
    [ -n "$src" ] || continue
    case "$src" in
        http://*|https://*) continue ;;                     # remote, not the context
        *'$'*) fail_closed "Dockerfile source '$src' uses a variable" ;;
    esac
    src="${src#./}"
    case "$src" in
        .|""|/) continue ;;                                 # whole context: not a trigger
    esac
    sources+=("$src")
done <<< "$parsed"

if [ "$print_sources" -eq 1 ]; then
    printf '%s\n' "${sources[@]}"
    exit 0
fi

[ -n "$files_arg" ] || fail_closed "no --files argument"
[ -f "$files_arg" ] && [ -r "$files_arg" ] || fail_closed "changed-file list '$files_arg' is unreadable"

# A list with no non-blank line is a listing defect, not "nothing changed".
grep -q '[^[:space:]]' "$files_arg"
status=$?
[ "$status" -ne 2 ] || fail_closed "cannot read changed-file list '$files_arg'"
[ "$status" -eq 0 ] || fail_closed "changed-file list '$files_arg' is empty"

matches() {
    local f="$1" src
    case "$f" in
        .claude/tooling|.claude/tooling/devcontainer/*|.dockerignore) return 0 ;;
        .github/workflows/agent-image-build.yml) return 0 ;;
        scripts/agent-image-filter.sh|scripts/agent-image-filter_test.sh) return 0 ;;
    esac
    for src in "${sources[@]}"; do
        case "$src" in
            */) [[ "$f" == "$src"* ]] && return 0 ;;
            *)  # exact path, a path under a directory source, or a glob
                # (a glob may over-match, which only ever builds more).
                # shellcheck disable=SC2053
                { [[ "$f" == $src ]] || [[ "$f" == "$src"/* ]]; } && return 0 ;;
        esac
    done
    return 1
}

hit=""
while IFS= read -r line || [ -n "$line" ]; do
    line="${line%$'\r'}"
    [ -n "${line//[[:space:]]/}" ] || continue
    if matches "$line"; then
        hit="$line"
        break
    fi
done < "$files_arg"

if [ -n "$hit" ]; then
    echo "agent image input changed (first match: ${hit//[^[:print:]]/?}) — the image is built" >&2
    echo "build=true"
else
    echo "no changed file is an agent image input — the image build is skipped" >&2
    echo "build=false"
fi
