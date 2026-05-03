#!/usr/bin/env bash
# Verified Trivy install: downloads the project's release archive, verifies the
# SHA-256 against a caller-pinned value, and refuses known-compromised
# versions per the GHSA-69fq-xp46-6x23 advisory (CVE-2026-33634).
#
# Usage: install-trivy.sh <version> <sha256> [dest_dir]
#   version    Trivy version tag (e.g. "v0.70.0")
#   sha256     Expected SHA-256 of trivy_<v>_Linux-64bit.tar.gz from the
#              upstream release's checksums.txt — pinned in caller's env.
#   dest_dir   Install directory (default: /usr/local/bin)
#
# Why this exists rather than `curl install.sh | sh`:
#   The trivy main branch's contrib/install.sh has been tampered with during
#   the supply-chain compromise window. This script verifies the release
#   artifact's SHA-256 against a value pinned in our own repo before extraction.
#
# Defense in depth:
#   1. Compromised-version denylist (refuses v0.69.4 / v0.69.5 / v0.69.6).
#   2. SHA-256 verification against a value pinned by the caller (not fetched
#      at runtime — runtime fetch defeats the purpose if the supply chain is
#      mid-compromise).
#   3. Re-runnable: if any of the above fails, no binary is installed and the
#      script exits non-zero.
#
# Sigstore-bundle (cosign) verification of the .sigstore.json artifact is a
# planned follow-up — requires installing cosign on the runner first. Until
# then, SHA-256 + denylist is the bound.

set -euo pipefail

VERSION="${1:?usage: install-trivy.sh <version> <sha256> [dest_dir]}"
SHA256="${2:?usage: install-trivy.sh <version> <sha256> [dest_dir]}"
DEST_DIR="${3:-/usr/local/bin}"

# Compromised-version denylist (CVE-2026-33634).
case "$VERSION" in
  v0.69.4|v0.69.4-*|v0.69.5|v0.69.5-*|v0.69.6|v0.69.6-*)
    echo "ERROR: $VERSION is a known-compromised release (CVE-2026-33634)." >&2
    echo "Refusing to install. See docs/runbooks/trivy-rollback.md." >&2
    exit 2
    ;;
esac

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

ARCHIVE="trivy_${VERSION#v}_Linux-64bit.tar.gz"
URL="https://github.com/aquasecurity/trivy/releases/download/${VERSION}/${ARCHIVE}"

echo "Downloading $URL"
curl -sSfL -o "$WORK/$ARCHIVE" "$URL"

echo "Verifying SHA-256 against pinned value"
printf '%s  %s\n' "$SHA256" "$WORK/$ARCHIVE" | sha256sum -c -

echo "Extracting trivy binary"
tar -xzf "$WORK/$ARCHIVE" -C "$WORK" trivy
install -m 0755 "$WORK/trivy" "$DEST_DIR/trivy"

echo "Installed: $("$DEST_DIR/trivy" --version | head -1)"
