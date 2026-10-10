#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 Jordan Ritz
#
# mirror-ci-images.sh — copy the third-party images CI pulls from Docker Hub to
# the digest-pinned ghcr.io mirror, and verify the image list matches the repo
# (Issue #4858).
#
# The list lives in .github/ci-images.yml: one entry per two lines,
#   - upstream: <image>:<tag>@sha256:<64 hex>
#     mirror: <name>
# It is read with awk only — no YAML parser is available on runners.
#
# Usage:
#   scripts/mirror-ci-images.sh [--dry-run] [--only <image>:<tag>@sha256:<digest>]
#   scripts/mirror-ci-images.sh --check
#
# Modes:
#   (default)   Copy every list entry to ghcr.io/cfg-is/ci-mirror/<name>:<tag>,
#               keeping the manifest digest (full multi-arch index, never a
#               rebuild). An entry whose digest is already in the mirror is
#               skipped. Needs docker buildx and a ghcr.io login.
#   --dry-run   Print one line per copy that would be made. No credentials, no
#               network.
#   --only REF  Mirror just REF (a digest that is not yet in the list, e.g. one
#               the weekly pin check found). The destination is the <name>:<tag>
#               of the list entry with the same image and tag.
#   --check     Verify every upstream reference in docker-compose.test.yml, every
#               Dockerfile FROM line and every workflow pull_with_retry /
#               docker pull step is in the list with the same digest. Exit 1 on
#               any miss or digest mismatch.
#
# Options (for tests): --list FILE, --root DIR.

set -euo pipefail

REGISTRY="ghcr.io/cfg-is/ci-mirror"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LIST=""
MODE="copy"
DRY_RUN=0
ONLY=""

usage() {
    sed -n '2,/^set -/p' "${BASH_SOURCE[0]}" | sed -e '$d' -e 's/^# \{0,1\}//'
}

while [ $# -gt 0 ]; do
    case "$1" in
        --dry-run) DRY_RUN=1 ;;
        --check) MODE="check" ;;
        --only) ONLY="${2:-}"; [ -n "$ONLY" ] || { echo "--only needs a reference" >&2; exit 2; }; shift ;;
        --list) LIST="${2:-}"; shift ;;
        --root) ROOT="${2:-}"; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
    shift
done
[ -n "$LIST" ] || LIST="$ROOT/.github/ci-images.yml"
[ -f "$LIST" ] || { echo "image list not found: $LIST" >&2; exit 2; }

DIGEST_RE='@sha256:[0-9a-f]{64}$'

# list_entries prints "<upstream>\t<mirror>" for each list entry.
list_entries() {
    awk '
        /^- upstream:[[:space:]]/ { sub(/^- upstream:[[:space:]]*/, ""); up = $0; next }
        /^[[:space:]]+mirror:[[:space:]]/ {
            sub(/^[[:space:]]+mirror:[[:space:]]*/, "")
            if (up == "") { print "mirror line without upstream: " $0 > "/dev/stderr"; bad = 1; next }
            print up "\t" $0; up = ""
        }
        END { if (up != "") { print "upstream without mirror: " up > "/dev/stderr"; bad = 1 } exit bad }
    ' "$LIST"
}

# ref_image_tag strips the digest: <image>:<tag>@sha256:x -> <image>:<tag>
ref_image_tag() { printf '%s\n' "${1%%@*}"; }
# tag_of prints the tag of <image>:<tag> (after the last colon past the last slash).
tag_of() {
    local it="$1"
    local last="${it##*/}"
    case "$last" in *:*) printf '%s\n' "${last##*:}" ;; *) printf 'latest\n' ;; esac
}

# repo_refs prints "<file>:<line>\t<ref>" for every image reference CI consumes.
repo_refs() {
    local f
    if [ -f "$ROOT/docker-compose.test.yml" ]; then
        awk -v f="docker-compose.test.yml" '
            /^[[:space:]]*image:[[:space:]]/ {
                r = $0; sub(/^[[:space:]]*image:[[:space:]]*/, "", r)
                sub(/[[:space:]]+#.*$/, "", r); gsub(/["\047]/, "", r)
                print f ":" NR "\t" r
            }' "$ROOT/docker-compose.test.yml"
    fi
    while IFS= read -r f; do
        awk -v f="${f#"$ROOT"/}" '
            toupper($1) == "FROM" {
                i = 2
                while ($i ~ /^--/) i++
                ref = $i
                if (toupper($(i + 1)) == "AS") stages[$(i + 2)] = 1
                if (ref in stages || ref == "scratch" || ref ~ /\$/) next
                print f ":" NR "\t" ref
            }' "$f"
    done < <(find "$ROOT" \( -name .git -o -name node_modules \) -prune -o -type f -name 'Dockerfile*' -print | sort)
    for f in "$ROOT"/.github/workflows/*.yml; do
        [ -f "$f" ] || continue
        awk -v f="${f#"$ROOT"/}" '
            /^[[:space:]]*(pull_with_retry|docker[[:space:]]+pull)[[:space:]]/ {
                r = $0
                sub(/^[[:space:]]*(pull_with_retry|docker[[:space:]]+pull)[[:space:]]+/, "", r)
                sub(/[[:space:]].*$/, "", r); gsub(/["\047]/, "", r)
                if (r ~ /\$/) next
                print f ":" NR "\t" r
            }' "$f"
    done
}

run_check() {
    local entries rc=0 loc ref it known
    entries="$(list_entries)" || { echo "malformed image list: $LIST" >&2; return 1; }
    local upstreams
    upstreams="$(printf '%s\n' "$entries" | cut -f1)"
    local seen=""
    while IFS=$'\t' read -r loc ref; do
        [ -n "$ref" ] || continue
        if printf '%s\n' "$upstreams" | grep -qxF -- "$ref"; then
            seen="$seen$ref"$'\n'
            continue
        fi
        it="$(ref_image_tag "$ref")"
        if ! [[ "$ref" =~ $DIGEST_RE ]]; then
            echo "FAIL $loc: $ref has no @sha256 digest" >&2
        else
            known="$(printf '%s\n' "$upstreams" | grep -F -- "$it@" || true)"
            if [ -n "$known" ]; then
                echo "FAIL $loc: $ref digest differs from list ($(printf '%s' "$known" | head -1))" >&2
            else
                echo "FAIL $loc: $ref is missing from ${LIST#"$ROOT"/}" >&2
            fi
        fi
        rc=1
    done < <(repo_refs)
    # Entries nothing consumes are stale, but not a failure: the list may carry
    # a ref a consumer will adopt in the follow-up that switches CI to the mirror.
    [ "$rc" -eq 0 ] && echo "ci-images: list matches repo ($(printf '%s\n' "$upstreams" | grep -c .) entries)"
    return "$rc"
}

# copy_one <upstream-ref> <mirror-name>
copy_one() {
    local ref="$1" name="$2" it tag digest dest
    [[ "$ref" =~ $DIGEST_RE ]] || { echo "not digest-pinned: $ref" >&2; return 1; }
    it="$(ref_image_tag "$ref")"
    tag="$(tag_of "$it")"
    digest="${ref#*@}"
    dest="$REGISTRY/$name:$tag"
    if [ "$DRY_RUN" -eq 1 ]; then
        echo "copy $ref -> $dest@$digest"
        return 0
    fi
    local have
    have="$(docker buildx imagetools inspect "$dest" --format '{{.Manifest.Digest}}' 2>/dev/null || true)"
    if [ "$have" = "$digest" ]; then
        echo "skip $dest (already at $digest)"
        return 0
    fi
    echo "copy $ref -> $dest"
    docker buildx imagetools create --tag "$dest" "$ref"
    have="$(docker buildx imagetools inspect "$dest" --format '{{.Manifest.Digest}}')"
    if [ "$have" != "$digest" ]; then
        echo "digest changed in copy: $dest is $have, expected $digest" >&2
        return 1
    fi
}

run_copy() {
    local entries up name rc=0
    entries="$(list_entries)" || { echo "malformed image list: $LIST" >&2; return 1; }
    if [ -n "$ONLY" ]; then
        local want
        want="$(ref_image_tag "$ONLY")"
        while IFS=$'\t' read -r up name; do
            if [ "$(ref_image_tag "$up")" = "$want" ]; then
                copy_one "$ONLY" "$name"
                return $?
            fi
        done <<< "$entries"
        echo "no list entry for $want; add it to ${LIST#"$ROOT"/} first" >&2
        return 1
    fi
    while IFS=$'\t' read -r up name; do
        [ -n "$up" ] || continue
        copy_one "$up" "$name" || rc=1
    done <<< "$entries"
    return "$rc"
}

case "$MODE" in
    check) run_check ;;
    copy) run_copy ;;
esac
