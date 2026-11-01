#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 Jordan Ritz

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TEST_DIR="$(mktemp -d "${TMPDIR:-/tmp}/cfgms-changelog-test.XXXXXX")"
trap 'rm -rf "$TEST_DIR"' EXIT INT TERM
cd "$REPO_ROOT"

# The [0.10.5] section of the committed CHANGELOG.md: the lines between its
# heading and the next "## [" heading, extracted by line number.
start="$(grep -n '^## \[0\.10\.5\]' CHANGELOG.md | head -1 | cut -d: -f1)"
next="$(awk -v s="$start" 'NR > s && /^## \[/ { print NR; exit }' CHANGELOG.md)"
test -n "$start" && test -n "$next"
sed -n "$((start + 1)),$((next - 1))p" CHANGELOG.md > "$TEST_DIR/expected"
test -s "$TEST_DIR/expected"

bash scripts/release/changelog-section.sh v0.10.5 > "$TEST_DIR/actual"
if ! cmp -s "$TEST_DIR/expected" "$TEST_DIR/actual"; then
    echo "FAIL: v0.10.5 section differs from CHANGELOG.md" >&2
    diff -u "$TEST_DIR/expected" "$TEST_DIR/actual" >&2 || true
    exit 1
fi
if grep -q '^## \[' "$TEST_DIR/actual"; then
    echo "FAIL: output contains a section heading" >&2
    exit 1
fi
echo "changelog-section test v0.10.5: PASS"

# A prerelease tag matches only a heading with that exact text.
cat > "$TEST_DIR/CHANGELOG.md" <<'EOC'
## [0.11.0-rc.1] - 2026-11-01

rc body

## [0.11.0] - 2026-11-02

final body
EOC
got="$(bash scripts/release/changelog-section.sh v0.11.0-rc.1 "$TEST_DIR/CHANGELOG.md")"
if [[ "$got" != $'\nrc body' ]]; then
    echo "FAIL: prerelease section wrong: $got" >&2
    exit 1
fi
echo "changelog-section test prerelease: PASS"

if bash scripts/release/changelog-section.sh v9.9.9 > /dev/null 2>&1; then
    echo "FAIL: version with no section exited zero" >&2
    exit 1
fi
if bash scripts/release/changelog-section.sh v0.11.1 "$TEST_DIR/CHANGELOG.md" > /dev/null 2>&1; then
    echo "FAIL: missing version in fixture exited zero" >&2
    exit 1
fi
echo "changelog-section test missing version: PASS"
