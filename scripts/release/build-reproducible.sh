#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 Jordan Ritz
#
# Build deterministic, cross-platform release archives and prove that a second
# independent build produces the same bytes. Signing and attestations happen in
# the release workflow after all platform artifacts have been assembled.

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
    cat <<'EOF'
Usage: build-reproducible.sh --version vX.Y.Z --commit SHA \
  --source-date-epoch EPOCH --publisher-key BASE64 --output DIR \
  [--platform OS/ARCH] [--allow-untagged] [--allow-dirty]

The official release workflow must not use --allow-untagged or --allow-dirty.
Those flags exist only for local reproducibility verification.
EOF
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

if [[ -z "$VERSION" || -z "$COMMIT" || -z "$SOURCE_DATE_EPOCH_VALUE" ||
      -z "$PUBLISHER_KEY" || -z "$OUTPUT_DIR" ]]; then
    usage >&2
    exit 2
fi
if [[ ! "$VERSION" =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-([0-9A-Za-z-]+)(\.[0-9A-Za-z-]+)*)?$ ]]; then
    echo "Error: version must be a canonical v-prefixed semantic version" >&2
    exit 1
fi
if [[ "$VERSION" == *-* ]]; then
    IFS='.' read -r -a prerelease_parts <<< "${VERSION#*-}"
    for identifier in "${prerelease_parts[@]}"; do
        if [[ "$identifier" =~ ^[0-9]+$ && ${#identifier} -gt 1 && "$identifier" == 0* ]]; then
            echo "Error: numeric prerelease identifiers cannot have leading zeroes" >&2
            exit 1
        fi
    done
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
    PLATFORMS=(linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64)
fi
for platform in "${PLATFORMS[@]}"; do
    case "$platform" in
        linux/amd64|linux/arm64|darwin/amd64|darwin/arm64|windows/amd64) ;;
        *) echo "Error: unsupported release platform: $platform" >&2; exit 1 ;;
    esac
done

cd "$REPO_ROOT"
HEAD_COMMIT="$(git rev-parse HEAD)"
if [[ "$HEAD_COMMIT" != "$COMMIT" ]]; then
    echo "Error: requested commit does not equal checked-out HEAD" >&2
    exit 1
fi
HEAD_EPOCH="$(git show -s --format=%ct HEAD)"
if [[ "$HEAD_EPOCH" != "$SOURCE_DATE_EPOCH_VALUE" ]]; then
    echo "Error: source date epoch does not equal the HEAD commit timestamp" >&2
    exit 1
fi
if [[ "$ALLOW_DIRTY" != true ]] && [[ -n "$(git status --porcelain)" ]]; then
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

KEY_HEX="$(printf '%s' "$PUBLISHER_KEY" | base64 -d 2>/dev/null | od -An -tx1 | tr -d ' \n')"
if [[ ${#KEY_HEX} -ne 64 || "$KEY_HEX" =~ ^0+$ ]]; then
    echo "Error: publisher key must decode to a non-zero 32-byte Ed25519 public key" >&2
    exit 1
fi

WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/cfgms-release.XXXXXX")"
cleanup() {
    rm -rf "$WORK_DIR"
}
trap cleanup EXIT INT TERM

BUILD_DATE="$(date -u -d "@$SOURCE_DATE_EPOCH_VALUE" '+%Y-%m-%dT%H:%M:%SZ')"
VERSION_PACKAGE="github.com/cfgis/cfgms/pkg/version"
TRUST_PACKAGE="github.com/cfgis/cfgms/pkg/modules/trust"
COMMON_LDFLAGS="-s -w -buildid= -X ${VERSION_PACKAGE}.Version=${VERSION} -X ${VERSION_PACKAGE}.GitCommit=${COMMIT} -X ${VERSION_PACKAGE}.BuildDate=${BUILD_DATE} -X ${VERSION_PACKAGE}.GoVersion=${ACTUAL_GO}"
STDLIB_MODULES=(cert_trust file firewall hostname package patch script service time user)

build_tree() {
    local pass="$1"
    local platform os arch ext root bin module
    for platform in "${PLATFORMS[@]}"; do
        os="${platform%/*}"
        arch="${platform#*/}"
        ext=""
        [[ "$os" == windows ]] && ext=".exe"
        root="$WORK_DIR/$pass/$os-$arch"
        bin="$root"
        mkdir -p "$root"

        CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" go build -mod=readonly -trimpath -buildvcs=false \
            -ldflags "$COMMON_LDFLAGS" -o "$bin/cfgms-controller$ext" ./cmd/controller
        CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" go build -mod=readonly -trimpath -buildvcs=false \
            -ldflags "$COMMON_LDFLAGS" -o "$bin/cfg$ext" ./cmd/cfg
        CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" go build -mod=readonly -trimpath -buildvcs=false \
            -ldflags "$COMMON_LDFLAGS" -o "$bin/cert-manager$ext" ./cmd/cert-manager
        CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" go build -mod=readonly -trimpath -buildvcs=false \
            -ldflags "$COMMON_LDFLAGS" -o "$bin/cfgms-steward-launcher$ext" ./cmd/cfgms-steward-launcher
        CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" go build -mod=readonly -trimpath -buildvcs=false \
            -ldflags "$COMMON_LDFLAGS -X main.SecurityProfile=public-beta -X ${TRUST_PACKAGE}.cfgmsPublisherPublicKey=${PUBLISHER_KEY}" \
            -o "$bin/cfgms-steward$ext" ./cmd/steward

        for module in "${STDLIB_MODULES[@]}"; do
            CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" go build -mod=readonly -trimpath -buildvcs=false \
                -ldflags "$COMMON_LDFLAGS" -o "$bin/cfgms-module-$module$ext" \
                "./features/modules/stdlib/$module/cmd"
        done

        cp LICENSE README.md "$root/"
        if [[ "$os" == linux ]]; then
            cp build/linux/install.sh "$root/install.sh"
            chmod 0755 "$root/install.sh"
        fi
        (
            cd "$root"
            find . -type f ! -name MANIFEST.sha256 -print0 |
                LC_ALL=C sort -z |
                xargs -0 sha256sum > MANIFEST.sha256
        )
    done
}

build_tree first
build_tree second

tree_manifest() {
    local pass="$1"
    (
        cd "$WORK_DIR/$pass"
        find . -type f -print0 | LC_ALL=C sort -z | xargs -0 sha256sum
    )
}
tree_manifest first > "$WORK_DIR/first.sha256"
tree_manifest second > "$WORK_DIR/second.sha256"
if ! cmp -s "$WORK_DIR/first.sha256" "$WORK_DIR/second.sha256"; then
    echo "Error: independent release builds were not byte-for-byte reproducible" >&2
    diff -u "$WORK_DIR/first.sha256" "$WORK_DIR/second.sha256" >&2 || true
    exit 1
fi

mkdir -p "$OUTPUT_DIR"
OUTPUT_DIR="$(cd "$OUTPUT_DIR" && pwd)"

make_archive() {
    local root="$1"
    local destination="$2"
    (
        cd "$root"
        find . -type f -printf '%P\0' |
            LC_ALL=C sort -z |
            tar --null --no-recursion --files-from=- \
                --sort=name --format=pax \
                --pax-option=delete=atime,delete=ctime \
                --owner=0 --group=0 --numeric-owner \
                --mtime="@$SOURCE_DATE_EPOCH_VALUE" \
                -cf -
    ) | gzip -n > "$destination"
}

for platform in "${PLATFORMS[@]}"; do
    os="${platform%/*}"
    arch="${platform#*/}"
    first_root="$WORK_DIR/first/$os-$arch"
    second_root="$WORK_DIR/second/$os-$arch"
    first_archive="$WORK_DIR/first-$os-$arch.tar.gz"
    second_archive="$WORK_DIR/second-$os-$arch.tar.gz"
    find "$first_root" "$second_root" -exec touch -h -d "@$SOURCE_DATE_EPOCH_VALUE" {} +
    make_archive "$first_root" "$first_archive"
    make_archive "$second_root" "$second_archive"
    if ! cmp -s "$first_archive" "$second_archive"; then
        echo "Error: final $os/$arch archives are not byte-for-byte reproducible" >&2
        exit 1
    fi
    cp "$first_archive" "$OUTPUT_DIR/cfgms-$os-$arch.tar.gz"
done

(
    cd "$OUTPUT_DIR"
    find . -maxdepth 1 -type f -name 'cfgms-*.tar.gz' -print0 |
        LC_ALL=C sort -z |
        xargs -0 sha256sum > SHA256SUMS
)
echo "Reproducibility check passed for ${#PLATFORMS[@]} platform tree(s) and archive(s)."
