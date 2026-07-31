#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 Jordan Ritz
#
# Verify a release artifact before installation. GitHub CLI verifies the
# repository-bound GitHub artifact attestation. Cosign verifies the attached
# keyless signature bundle and pins both workflow identity and OIDC issuer.

set -euo pipefail

if [[ $# -ne 3 ]]; then
    echo "Usage: verify-release-artifact.sh <artifact> <sigstore-bundle> <version>" >&2
    exit 2
fi

ARTIFACT="$1"
BUNDLE="$2"
VERSION="$3"

if [[ ! "$VERSION" =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-([0-9A-Za-z-]+)(\.[0-9A-Za-z-]+)*)?$ ]]; then
    echo "Error: release version is not a canonical semantic version" >&2
    exit 1
fi
if [[ "$VERSION" == *-* ]]; then
    IFS='.' read -r -a prerelease_parts <<< "${VERSION#*-}"
    for identifier in "${prerelease_parts[@]}"; do
        if [[ "$identifier" =~ ^[0-9]+$ && ${#identifier} -gt 1 && "$identifier" == 0* ]]; then
            echo "Error: release version is not canonical semantic versioning" >&2
            exit 1
        fi
    done
fi
if [[ ! -s "$ARTIFACT" || ! -s "$BUNDLE" ]]; then
    echo "Error: release artifact or signature bundle is missing/empty" >&2
    exit 1
fi

if command -v gh >/dev/null 2>&1 && gh attestation verify --help >/dev/null 2>&1; then
    if ! gh attestation verify "$ARTIFACT" \
        --repo cfg-is/cfgms \
        --signer-workflow cfg-is/cfgms/.github/workflows/release.yml \
        --source-ref "refs/tags/$VERSION" >/dev/null; then
        echo "Error: GitHub artifact attestation verification failed" >&2
        exit 1
    fi
    echo "Verified GitHub artifact attestation for $(basename "$ARTIFACT")."
    exit 0
fi

if command -v cosign >/dev/null 2>&1; then
    IDENTITY="https://github.com/cfg-is/cfgms/.github/workflows/release.yml@refs/tags/$VERSION"
    ISSUER="https://token.actions.githubusercontent.com"
    if ! cosign verify-blob \
        --bundle "$BUNDLE" \
        --certificate-identity "$IDENTITY" \
        --certificate-oidc-issuer "$ISSUER" \
        "$ARTIFACT" >/dev/null; then
        echo "Error: Sigstore release signature verification failed" >&2
        exit 1
    fi
    echo "Verified Sigstore release signature for $(basename "$ARTIFACT")."
    exit 0
fi

echo "Error: install GitHub CLI with attestation support or Cosign before installing a release artifact" >&2
exit 1
