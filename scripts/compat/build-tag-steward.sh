#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 Jordan Ritz
#
# build-tag-steward.sh — build the steward and steward launcher exactly as a
# past release tag built them, for the steward compat harness (Issue #6314).
#
# The tag's own source is extracted with `git archive` into a fresh directory
# and the TAG's own recipe is run there:
#
#   make build-steward build-steward-launcher VERSION=<tag>
#
# The version, publisher key default and every other ldflag come from that tag's
# Makefile. This script never composes `go build` flags itself: a plain
# `go build` of the tag reports the source default (0.5.0-dev), not the release
# version the compat scenario asserts on.
#
# Usage:   scripts/compat/build-tag-steward.sh <tag> <outdir>
#   scripts/compat/build-tag-steward.sh v0.10.5 /tmp/floor
#
# Output:  <outdir>/cfgms-steward and <outdir>/cfgms-steward-launcher
#
# Environment (optional, passed through to the tag's make recipe when set):
#   STEWARD_CONTROLLER_URL   controller URL baked into the steward binary
#   STEWARD_PUBLISHER_KEY    base64 Ed25519 publisher public key baked in
#
# The launcher needs CFGMS_STEWARD_LAUNCHER_MANAGED=1 in the steward's
# environment when it supervises the steward; the launcher sets it itself.
#
# Exit codes: 0 built, 1 build failure or tag missing, 2 usage error.

set -euo pipefail

usage() {
    echo "usage: build-tag-steward.sh <tag> <outdir>" >&2
}

if [ "$#" -ne 2 ]; then
    usage
    exit 2
fi

tag="$1"
outdir="$2"

# A tag name is interpolated into a git ref and a make variable: restrict it to
# release-tag characters so nothing else can reach either.
case "$tag" in
    '' | -* | *[!A-Za-z0-9._-]*)
        echo "build-tag-steward: invalid tag '$tag' (letters, digits, '.', '_' and '-' only)" >&2
        exit 2
        ;;
esac
if [ -z "$outdir" ]; then
    usage
    exit 2
fi

if ! git rev-parse --verify --quiet "refs/tags/${tag}^{commit}" >/dev/null; then
    echo "build-tag-steward: tag '$tag' not found; fetch tags first (git fetch --tags, or a checkout with fetch-depth: 0)" >&2
    exit 1
fi

mkdir -p "$outdir"
outdir="$(cd "$outdir" && pwd)"

workdir="$(mktemp -d "${TMPDIR:-/tmp}/compat-steward-build.XXXXXX")"
trap 'rm -rf "$workdir"' EXIT

git archive --format=tar "refs/tags/${tag}" | tar -x -C "$workdir"

make_args=("VERSION=${tag}")
if [ -n "${STEWARD_CONTROLLER_URL:-}" ]; then
    make_args+=("STEWARD_CONTROLLER_URL=${STEWARD_CONTROLLER_URL}")
fi
if [ -n "${STEWARD_PUBLISHER_KEY:-}" ]; then
    make_args+=("STEWARD_PUBLISHER_KEY=${STEWARD_PUBLISHER_KEY}")
fi

echo "build-tag-steward: building ${tag} in ${workdir}"
# Subshell so the extracted tree is the make working directory; the tag's
# Makefile writes to ./bin there.
(cd "$workdir" && make build-steward build-steward-launcher "${make_args[@]}")

for bin in cfgms-steward cfgms-steward-launcher; do
    if [ ! -x "$workdir/bin/$bin" ]; then
        echo "build-tag-steward: the ${tag} recipe did not produce bin/$bin" >&2
        exit 1
    fi
    cp "$workdir/bin/$bin" "$outdir/$bin"
done

echo "build-tag-steward: wrote $outdir/cfgms-steward and $outdir/cfgms-steward-launcher"
