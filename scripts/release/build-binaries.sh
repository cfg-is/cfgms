#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 Jordan Ritz
#
# Build the unsigned release binaries, prove a second independent build produces
# the same bytes, and write a SHA256SUMS file covering every artifact.
#
# Artifacts (flat in --output):
#   cfgms-controller-linux-amd64
#   cfgms-steward-<os>-<arch>[.exe]   os: linux, darwin, windows; arch: amd64, arm64
#
# Nothing here signs anything and no secret is read. --publisher-key is a public
# key; when omitted the steward keeps the all-zero development placeholder that
# pkg/modules/trust/identity.go defaults to.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
VERSION=""
COMMIT=""
SOURCE_DATE_EPOCH_VALUE=""
PUBLISHER_KEY=""
OUTPUT_DIR=""
ALLOW_UNTAGGED=false
ALLOW_DIRTY=false
PLATFORMS=()

usage() {
    cat <<'EOF2'
Usage: build-binaries.sh --version vX.Y.Z --commit SHA \
  --source-date-epoch EPOCH --output DIR \
  [--publisher-key BASE64] [--platform OS/ARCH]... \
  [--allow-untagged] [--allow-dirty]

Platforms: linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64
windows/arm64 (default: all). The controller is built for linux/amd64 only.
The release workflow must not use --allow-untagged or --allow-dirty.
EOF2
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --version) VERSION="${2:?missing value for --version}"; shift 2 ;;
        --commit) COMMIT="${2:?missing value for --commit}"; shift 2 ;;
        --source-date-epoch) SOURCE_DATE_EPOCH_VALUE="${2:?missing value for --source-date-epoch}"; shift 2 ;;
        --publisher-key) PUBLISHER_KEY="${2:?missing value for --publisher-key}"; shift 2 ;;
        --output) OUTPUT_DIR="${2:?missing value for --output}"; shift 2 ;;
        --platform) PLATFORMS+=("${2:?missing value for --platform}"); shift 2 ;;
        --allow-untagged) ALLOW_UNTAGGED=true; shift ;;
        --allow-dirty) ALLOW_DIRTY=true; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "Unknown argument: $1" >&2; usage >&2; exit 2 ;;
    esac
done

if [[ -z "$VERSION" || -z "$COMMIT" || -z "$SOURCE_DATE_EPOCH_VALUE" || -z "$OUTPUT_DIR" ]]; then
    usage >&2
    exit 2
fi
if [[ ! "$VERSION" =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-([0-9A-Za-z-]+)(\.[0-9A-Za-z-]+)*)?$ ]]; then
    echo "Error: version must be a canonical v-prefixed semantic version" >&2
    exit 1
fi
if [[ ! "$COMMIT" =~ ^[0-9a-f]{40}$ ]]; then
    echo "Error: commit must be a full lowercase Git object ID" >&2
    exit 1
fi
if [[ ! "$SOURCE_DATE_EPOCH_VALUE" =~ ^[0-9]+$ ]]; then
    echo "Error: source date epoch must be an integer" >&2
    exit 1
fi
if [[ ${#PLATFORMS[@]} -eq 0 ]]; then
    PLATFORMS=(linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64)
fi
for platform in "${PLATFORMS[@]}"; do
    case "$platform" in
        linux/amd64|linux/arm64|darwin/amd64|darwin/arm64|windows/amd64|windows/arm64) ;;
        *) echo "Error: unsupported release platform: $platform" >&2; exit 1 ;;
    esac
done
if [[ -n "$PUBLISHER_KEY" ]]; then
    # The all-zero key is the development placeholder and is deliberately allowed.
    KEY_HEX="$(printf '%s' "$PUBLISHER_KEY" | base64 -d 2>/dev/null | od -An -tx1 | tr -d ' \n' || true)"
    if [[ ${#KEY_HEX} -ne 64 ]]; then
        echo "Error: publisher key must decode to 32 bytes" >&2
        exit 1
    fi
fi

cd "$REPO_ROOT"
if [[ "$(git rev-parse HEAD)" != "$COMMIT" ]]; then
    echo "Error: requested commit does not equal checked-out HEAD" >&2
    exit 1
fi
if [[ "$(git show -s --format=%ct HEAD)" != "$SOURCE_DATE_EPOCH_VALUE" ]]; then
    echo "Error: source date epoch does not equal the HEAD commit timestamp" >&2
    exit 1
fi
if [[ "$ALLOW_DIRTY" != true ]] && [[ -n "$(git status --porcelain --untracked-files=no)" ]]; then
    echo "Error: release worktree is dirty" >&2
    exit 1
fi
if [[ "$ALLOW_UNTAGGED" != true ]]; then
    TAG_TYPE="$(git cat-file -t "refs/tags/$VERSION" 2>/dev/null || true)"
    TAG_COMMIT="$(git rev-list -n 1 "refs/tags/$VERSION" 2>/dev/null || true)"
    if [[ "$TAG_TYPE" != "tag" || "$TAG_COMMIT" != "$COMMIT" ]]; then
        echo "Error: release version must be an annotated tag resolving to HEAD" >&2
        exit 1
    fi
fi

EXPECTED_GO="$(awk '$1 == "toolchain" { print $2; exit }' go.mod)"
ACTUAL_GO="$(go env GOVERSION)"
if [[ -z "$EXPECTED_GO" || "$ACTUAL_GO" != "$EXPECTED_GO" ]]; then
    echo "Error: release toolchain mismatch (required $EXPECTED_GO, found $ACTUAL_GO)" >&2
    exit 1
fi

WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/cfgms-binaries.XXXXXX")"
cleanup() {
    rm -rf "$WORK_DIR"
}
trap cleanup EXIT INT TERM

BUILD_DATE="$(date -u -d "@$SOURCE_DATE_EPOCH_VALUE" '+%Y-%m-%dT%H:%M:%SZ')"
VERSION_PACKAGE="github.com/cfgis/cfgms/pkg/version"
TRUST_PACKAGE="github.com/cfgis/cfgms/pkg/modules/trust"
COMMON_LDFLAGS="-s -w -buildid= -X ${VERSION_PACKAGE}.Version=${VERSION} -X ${VERSION_PACKAGE}.GitCommit=${COMMIT} -X ${VERSION_PACKAGE}.BuildDate=${BUILD_DATE} -X ${VERSION_PACKAGE}.GoVersion=${ACTUAL_GO}"
STEWARD_LDFLAGS="$COMMON_LDFLAGS -X main.SecurityProfile=public-beta"
if [[ -n "$PUBLISHER_KEY" ]]; then
    STEWARD_LDFLAGS="$STEWARD_LDFLAGS -X ${TRUST_PACKAGE}.cfgmsPublisherPublicKey=${PUBLISHER_KEY}"
fi

build_tree() {
    local pass="$1"
    local platform os arch ext
    mkdir -p "$WORK_DIR/$pass"
    for platform in "${PLATFORMS[@]}"; do
        os="${platform%/*}"
        arch="${platform#*/}"
        ext=""
        [[ "$os" == windows ]] && ext=".exe"
        if [[ "$platform" == linux/amd64 ]]; then
            CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" go build -mod=readonly -trimpath -buildvcs=false \
                -ldflags "$COMMON_LDFLAGS" \
                -o "$WORK_DIR/$pass/cfgms-controller-$os-$arch" ./cmd/controller
        fi
        CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" go build -mod=readonly -trimpath -buildvcs=false \
            -ldflags "$STEWARD_LDFLAGS" \
            -o "$WORK_DIR/$pass/cfgms-steward-$os-$arch$ext" ./cmd/steward
    done
}

build_tree first
build_tree second

for built in "$WORK_DIR"/first/*; do
    name="$(basename "$built")"
    if ! cmp -s "$built" "$WORK_DIR/second/$name"; then
        echo "Error: independent builds of $name were not byte-for-byte reproducible" >&2
        exit 1
    fi
done

mkdir -p "$OUTPUT_DIR"
OUTPUT_DIR="$(cd "$OUTPUT_DIR" && pwd)"
cp "$WORK_DIR"/first/* "$OUTPUT_DIR/"
(
    cd "$OUTPUT_DIR"
    find . -maxdepth 1 -type f ! -name SHA256SUMS -printf '%P\0' |
        LC_ALL=C sort -z |
        xargs -0 sha256sum > SHA256SUMS
)
echo "Reproducibility check passed for $(find "$WORK_DIR/first" -type f | wc -l) binaries."
