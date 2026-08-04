#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 Jordan Ritz

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TEST_DIR="$(mktemp -d "${TMPDIR:-/tmp}/cfgms-verify-release.XXXXXX")"
cleanup() {
    rm -rf "$TEST_DIR"
}
trap cleanup EXIT INT TERM

printf 'artifact\n' > "$TEST_DIR/artifact"
printf '{}\n' > "$TEST_DIR/bundle"
mkdir -p "$TEST_DIR/bin"

cat > "$TEST_DIR/bin/gh" <<'EOF'
#!/usr/bin/env bash
if [[ "$*" == "attestation verify --help" ]]; then exit 0; fi
[[ "$*" == *"attestation verify "* ]] &&
    [[ "$*" == *"--repo cfg-is/cfgms"* ]] &&
    [[ "$*" == *"--signer-workflow cfg-is/cfgms/.github/workflows/release.yml"* ]] &&
    [[ "$*" == *"--source-ref refs/tags/v1.2.3"* ]]
EOF
chmod +x "$TEST_DIR/bin/gh"
PATH="$TEST_DIR/bin:/usr/bin:/bin" bash "$REPO_ROOT/scripts/verify-release-artifact.sh" \
    "$TEST_DIR/artifact" "$TEST_DIR/bundle" v1.2.3 >/dev/null

cat > "$TEST_DIR/bin/gh" <<'EOF'
#!/usr/bin/env bash
if [[ "$*" == "attestation verify --help" ]]; then exit 0; fi
exit 1
EOF
cat > "$TEST_DIR/bin/cosign" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
chmod +x "$TEST_DIR/bin/gh" "$TEST_DIR/bin/cosign"
if PATH="$TEST_DIR/bin:/usr/bin:/bin" bash "$REPO_ROOT/scripts/verify-release-artifact.sh" \
    "$TEST_DIR/artifact" "$TEST_DIR/bundle" v1.2.3 >/dev/null 2>&1; then
    echo "Error: a failed available verifier must not fall back" >&2
    exit 1
fi

cat > "$TEST_DIR/bin/gh" <<'EOF'
#!/usr/bin/env bash
exit 1
EOF
cat > "$TEST_DIR/bin/cosign" <<'EOF'
#!/usr/bin/env bash
args="$*"
[[ "$args" == *"--certificate-identity https://github.com/cfg-is/cfgms/.github/workflows/release.yml@refs/tags/v1.2.3"* ]] &&
    [[ "$args" == *"--certificate-oidc-issuer https://token.actions.githubusercontent.com"* ]]
EOF
chmod +x "$TEST_DIR/bin/gh" "$TEST_DIR/bin/cosign"
PATH="$TEST_DIR/bin:/usr/bin:/bin" bash "$REPO_ROOT/scripts/verify-release-artifact.sh" \
    "$TEST_DIR/artifact" "$TEST_DIR/bundle" v1.2.3 >/dev/null

if PATH="$TEST_DIR/bin:/usr/bin:/bin" bash "$REPO_ROOT/scripts/verify-release-artifact.sh" \
    "$TEST_DIR/artifact" "$TEST_DIR/bundle" '../bad' >/dev/null 2>&1; then
    echo "Error: invalid version was accepted" >&2
    exit 1
fi

echo "release artifact verifier tests: PASS"
