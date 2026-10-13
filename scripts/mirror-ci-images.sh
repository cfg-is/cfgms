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
#   scripts/mirror-ci-images.sh --changed-refs <base-list-file>
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
#   --check     Verify every image reference in docker-compose.test.yml, every
#               Dockerfile FROM line and every workflow pull_with_retry /
#               docker pull step is ghcr.io/cfg-is/ci-mirror/<name>:<tag>@sha256:<digest>
#               and equals the mirror form of a list entry. Exit 1 on a
#               reference outside the mirror, a miss or a digest mismatch.
#               Build-stage names and ${...} variables are skipped.
#
#   --changed-refs BASE
#               Print the upstream ref of every entry in the list that is absent
#               from the list file BASE (an added entry or a changed tag or
#               digest), one per line. A removed entry prints nothing. Read-only:
#               no docker, no network. A missing or empty BASE yields every
#               entry. The PR-time mirror job feeds this to --only.
#
# Options (for tests): --list FILE, --root DIR.

set -euo pipefail

REGISTRY="ghcr.io/cfg-is/ci-mirror"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LIST=""
MODE="copy"
DRY_RUN=0
ONLY=""
BASE_LIST=""

usage() {
    sed -n '2,/^set -/p' "${BASH_SOURCE[0]}" | sed -e '$d' -e 's/^# \{0,1\}//'
}

while [ $# -gt 0 ]; do
    case "$1" in
        --dry-run) DRY_RUN=1 ;;
        --check) MODE="check" ;;
        --only) ONLY="${2:-}"; [ -n "$ONLY" ] || { echo "--only needs a reference" >&2; exit 2; }; shift ;;
        --changed-refs) MODE="changed"; BASE_LIST="${2:-}"; [ -n "$BASE_LIST" ] || { echo "--changed-refs needs a base list file" >&2; exit 2; }; shift ;;
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
    local file="${1:-$LIST}"
    awk '
        /^- upstream:[[:space:]]/ { sub(/^- upstream:[[:space:]]*/, ""); up = $0; next }
        /^[[:space:]]+mirror:[[:space:]]/ {
            sub(/^[[:space:]]+mirror:[[:space:]]*/, "")
            if (up == "") { print "mirror line without upstream: " $0 > "/dev/stderr"; bad = 1; next }
            print up "\t" $0; up = ""
        }
        END { if (up != "") { print "upstream without mirror: " up > "/dev/stderr"; bad = 1 } exit bad }
    ' "$file"
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

# mirror_form prints the consumer reference for a list entry:
# ghcr.io/cfg-is/ci-mirror/<name>:<tag>@sha256:<digest>
mirror_form() {
    local up="$1" name="$2" it
    it="$(ref_image_tag "$up")"
    printf '%s/%s:%s@%s\n' "$REGISTRY" "$name" "$(tag_of "$it")" "${up#*@}"
}

# run_check requires every consumer reference to be the mirror form of a list
# entry. A reference outside ghcr.io/cfg-is/ci-mirror/ (Docker Hub or any other
# registry) fails, as does a mirror reference whose digest differs from the list.
run_check() {
    local entries rc=0 loc ref up name
    entries="$(list_entries)" || { echo "malformed image list: $LIST" >&2; return 1; }
    local forms="" count=0
    while IFS=$'\t' read -r up name; do
        [ -n "$up" ] || continue
        forms="$forms$(mirror_form "$up" "$name")"$'\n'
        count=$((count + 1))
    done <<< "$entries"
    while IFS=$'\t' read -r loc ref; do
        [ -n "$ref" ] || continue
        if [[ "$ref" != "$REGISTRY/"* ]]; then
            echo "FAIL $loc: $ref is outside $REGISTRY/" >&2
        elif printf '%s' "$forms" | grep -qxF -- "$ref"; then
            continue
        elif ! [[ "$ref" =~ $DIGEST_RE ]]; then
            echo "FAIL $loc: $ref has no @sha256 digest" >&2
        else
            local known
            known="$(printf '%s' "$forms" | grep -F -- "${ref%%@*}@" || true)"
            if [ -n "$known" ]; then
                echo "FAIL $loc: $ref digest differs from list ($(printf '%s' "$known" | head -1))" >&2
            else
                echo "FAIL $loc: $ref is missing from ${LIST#"$ROOT"/}" >&2
            fi
        fi
        rc=1
    done < <(repo_refs)
    # Entries nothing consumes are stale, but not a failure.
    [ "$rc" -eq 0 ] && echo "ci-images: every consumer reads the mirror and matches the list ($count entries)"
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

# run_changed prints each upstream ref in the list that BASE_LIST lacks.
run_changed() {
    local entries base="" up name
    entries="$(list_entries)" || { echo "malformed image list: $LIST" >&2; return 1; }
    if [ -f "$BASE_LIST" ]; then
        base="$(list_entries "$BASE_LIST")" || { echo "malformed base list: $BASE_LIST" >&2; return 1; }
    fi
    while IFS=$'\t' read -r up name; do
        [ -n "$up" ] || continue
        printf '%s\n' "$base" | cut -f1 | grep -qxF -- "$up" || printf '%s\n' "$up"
    done <<< "$entries"
    return 0
}

case "$MODE" in
    changed) run_changed ;;
    check) run_check ;;
    copy) run_copy ;;
esac
