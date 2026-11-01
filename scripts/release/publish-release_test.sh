#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 Jordan Ritz
#
# Tests scripts/release/publish-release.sh against a stub gh on PATH.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TEST_DIR="$(mktemp -d "${TMPDIR:-/tmp}/cfgms-publish-test.XXXXXX")"
trap 'rm -rf "$TEST_DIR"' EXIT INT TERM

mkdir -p "$TEST_DIR/bin" "$TEST_DIR/assets"
echo binary > "$TEST_DIR/assets/cfgms-controller-linux-amd64"
echo sums > "$TEST_DIR/assets/SHA256SUMS"
echo notes > "$TEST_DIR/notes.md"

cat > "$TEST_DIR/bin/gh" <<'STUB'
#!/usr/bin/env bash
echo "$*" >> "$STUB_GH_LOG"
if [[ "$1 $2" == "release list" ]]; then
    [[ -n "${STUB_GH_RELEASES:-}" ]] && printf '%b\n' "$STUB_GH_RELEASES"
    exit 0
fi
exit 0
STUB
chmod +x "$TEST_DIR/bin/gh"

TAG="v1.2.3"
export GITHUB_REPOSITORY="cfg-is/cfgms"
export STUB_GH_LOG="$TEST_DIR/gh.log"

# run_publish PUBLIC RELEASES: sets EXIT, OUT and the recorded gh calls in LOG.
run_publish() {
    : > "$STUB_GH_LOG"
    EXIT=0
    OUT="$(PATH="$TEST_DIR/bin:$PATH" STUB_GH_RELEASES="$2" \
        bash "$REPO_ROOT/scripts/release/publish-release.sh" "$TAG" "$1" "$TEST_DIR/assets" "$TEST_DIR/notes.md" 2>&1)" || EXIT=$?
    LOG="$(cat "$STUB_GH_LOG")"
}

check() {
    local name="$1" cond="$2"
    if ! eval "$cond"; then
        echo "FAIL: $name" >&2
        echo "  exit=$EXIT out='$OUT'" >&2
        echo "  gh calls:" >&2
        sed 's/^/    /' <<< "$LOG" >&2
        exit 1
    fi
    echo "publish-release test $name: PASS"
}

has() { grep -q -- "$1" <<< "$LOG"; }

# No existing release: a draft is created.
run_publish "" ""
check "no release, unset -> create --draft" '[[ $EXIT -eq 0 ]] && has "release create v1.2.3 .*--draft"'

# No existing release, flag exactly true: created public.
run_publish "true" ""
check "no release, true -> create public" '[[ $EXIT -eq 0 ]] && has "release create v1.2.3" && ! has "--draft"'

# Anything other than exactly "true" stays a draft.
for v in TRUE 1 false yes "true "; do
    run_publish "$v" ""
    check "no release, '$v' -> create --draft" '[[ $EXIT -eq 0 ]] && has "release create v1.2.3 .*--draft"'
done

# Existing draft: upload with --clobber, edit, stay a draft.
run_publish "" "v1.2.3\ttrue"
check "existing draft -> upload --clobber and edit, stays draft" \
    '[[ $EXIT -eq 0 ]] && has "release upload v1.2.3 .*--clobber" && has "release edit v1.2.3 .*--draft$" && ! has "release create"'

# Existing draft, flag true: published after the upload.
run_publish "true" "v1.2.3\ttrue"
check "existing draft, true -> published" \
    '[[ $EXIT -eq 0 ]] && has "release upload v1.2.3 .*--clobber" && has "release edit v1.2.3 .*--draft=false"'

# Other tags in the list do not match.
run_publish "" "v1.2.30\tfalse\nv1.2.2\tfalse"
check "other published tags do not block" '[[ $EXIT -eq 0 ]] && has "release create v1.2.3 .*--draft"'

# Published release, flag not true: refuse, no edit or upload.
for v in "" TRUE 1; do
    run_publish "$v" "v1.2.3\tfalse"
    check "published release, '$v' -> refused" \
        '[[ $EXIT -ne 0 ]] && grep -q "already has a published release" <<< "$OUT" && ! has "release edit" && ! has "release upload" && ! has "release create"'
done

# Published release, flag true: updated as today.
run_publish "true" "v1.2.3\tfalse"
check "published release, true -> upload and edit" \
    '[[ $EXIT -eq 0 ]] && has "release upload v1.2.3 .*--clobber" && has "release edit v1.2.3 .*--draft=false"'

echo "publish-release tests: PASS"
