#!/bin/bash
# Enforce the installer-payload directory/manifest boundary (ADR-016 clause 3).
#
# All five sources that enumerate stdlib modules must agree exactly:
#   1. features/modules/stdlib/  — directory listing (authoritative by ADR-016)
#   2. Makefile STDLIB_MODULES   — drives build-stdlib-modules compilation
#   3. build/windows/cfgms-steward.wxs — Windows MSI installer payload
#   4. build/linux/install.sh STDLIB_MODULES  — Linux install-script payload
#   5. build/darwin/build-pkg.sh STDLIB_MODULES — macOS .pkg payload
#
# Exit code: 0 = all five agree, 1 = any disagreement detected.
# Usage: ./scripts/check-stdlib-payload-boundary.sh
#
# The REPO_ROOT environment variable can override the detected root (used by tests).

set -euo pipefail

# ── Locate repo root ──────────────────────────────────────────────────────────

if [[ -n "${REPO_ROOT:-}" ]]; then
    ROOT="$REPO_ROOT"
else
    ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fi

MAKEFILE="$ROOT/Makefile"
WXS_FILE="$ROOT/build/windows/cfgms-steward.wxs"
INSTALL_SH="$ROOT/build/linux/install.sh"
BUILD_PKG_SH="$ROOT/build/darwin/build-pkg.sh"
STDLIB_DIR="$ROOT/features/modules/stdlib"

# ── Extraction helpers ────────────────────────────────────────────────────────

# Sort a newline-separated list of module names and remove empty lines.
normalize() {
    sort | grep -v '^$' || true
}

# Extract module names from the stdlib directory (one name per line, sorted).
extract_dir() {
    if [[ ! -d "$STDLIB_DIR" ]]; then
        echo "ERROR: stdlib directory not found: $STDLIB_DIR" >&2
        exit 1
    fi
    find "$STDLIB_DIR" -mindepth 1 -maxdepth 1 -type d | sed 's|.*/||' | normalize
}

# Extract module names from the Makefile STDLIB_MODULES variable.
# Handles both single-line and multi-line (backslash-continued) forms.
extract_makefile() {
    if [[ ! -f "$MAKEFILE" ]]; then
        echo "ERROR: Makefile not found: $MAKEFILE" >&2
        exit 1
    fi
    # Collect the continuation block: the STDLIB_MODULES := ... line(s).
    # cont is set before gsub so the backslash check precedes the strip.
    awk '
        /^STDLIB_MODULES[[:space:]]*:=/ { in_block=1; sub(/^STDLIB_MODULES[[:space:]]*:=[[:space:]]*/,""); }
        in_block {
            cont = ($0 ~ /\\[[:space:]]*$/)
            gsub(/\\[[:space:]]*$/, "")
            gsub(/^[[:space:]]+|[[:space:]]+$/, "")
            if ($0 != "") print $0
            if (!cont) in_block=0
        }
    ' "$MAKEFILE" | normalize
}

# Extract module names from the WiX .wxs file.
# Pattern: Name="cfgms-module-<name>.exe" inside the MODULESDIR block.
# Uses grep+sed — no xmllint dependency required.
extract_wxs() {
    if [[ ! -f "$WXS_FILE" ]]; then
        echo "ERROR: WiX file not found: $WXS_FILE" >&2
        exit 1
    fi
    grep -o 'Name="cfgms-module-[^.]*\.exe"' "$WXS_FILE" \
        | sed 's/Name="cfgms-module-//;s/\.exe"//' \
        | normalize
}

# Extract module names from a bash STDLIB_MODULES=(…) array in the given file.
# Handles both single-line and multi-line (one-name-per-line) forms.
# Strips the cfgms-module- prefix so the result is bare module names.
extract_bash_array() {
    local file="$1"
    if [[ ! -f "$file" ]]; then
        echo "ERROR: file not found: $file" >&2
        exit 1
    fi
    # Collect everything inside STDLIB_MODULES=( … )
    awk '
        /STDLIB_MODULES=\(/ { in_block=1; sub(/.*STDLIB_MODULES=\(/,""); }
        in_block {
            # stop at closing paren
            if (/\)/) { sub(/\).*/,""); in_block=0 }
            n = split($0, words)
            for (i=1; i<=n; i++) { if (words[i] != "") print words[i] }
        }
    ' "$file" \
        | sed 's/^cfgms-module-//' \
        | normalize
}

# ── Collect the five sets ─────────────────────────────────────────────────────

DIR_MODULES=$(extract_dir)
MAKEFILE_MODULES=$(extract_makefile)
WXS_MODULES=$(extract_wxs)
INSTALL_SH_MODULES=$(extract_bash_array "$INSTALL_SH")
BUILD_PKG_MODULES=$(extract_bash_array "$BUILD_PKG_SH")

# ── Compare all pairs using comm ──────────────────────────────────────────────

FAILED=0
DIAGNOSTICS=""

# compare_pair <label-a> <set-a> <label-b> <set-b>
# Prints diagnostics if the two sorted sets differ; sets FAILED=1.
compare_pair() {
    local label_a="$1"
    local set_a="$2"
    local label_b="$3"
    local set_b="$4"

    local only_in_a only_in_b
    only_in_a=$(comm -23 <(echo "$set_a") <(echo "$set_b"))
    only_in_b=$(comm -13 <(echo "$set_a") <(echo "$set_b"))

    if [[ -n "$only_in_a" || -n "$only_in_b" ]]; then
        FAILED=1
        DIAGNOSTICS+="  ❌ $label_a vs $label_b differ:\n"
        if [[ -n "$only_in_a" ]]; then
            while IFS= read -r m; do
                [[ -z "$m" ]] && continue
                DIAGNOSTICS+="       only in $label_a: $m\n"
            done <<< "$only_in_a"
        fi
        if [[ -n "$only_in_b" ]]; then
            while IFS= read -r m; do
                [[ -z "$m" ]] && continue
                DIAGNOSTICS+="       only in $label_b: $m\n"
            done <<< "$only_in_b"
        fi
    fi
}

echo "🔍 Checking stdlib payload boundary (ADR-016 clause 3)..."
echo ""

compare_pair "stdlib/ dir"  "$DIR_MODULES"      "Makefile"      "$MAKEFILE_MODULES"
compare_pair "Makefile"     "$MAKEFILE_MODULES"  "WiX .wxs"     "$WXS_MODULES"
compare_pair "WiX .wxs"    "$WXS_MODULES"       "install.sh"    "$INSTALL_SH_MODULES"
compare_pair "install.sh"   "$INSTALL_SH_MODULES" "build-pkg.sh" "$BUILD_PKG_MODULES"

# Also check build-pkg.sh vs dir (catches a module only in build-pkg.sh)
compare_pair "build-pkg.sh" "$BUILD_PKG_MODULES" "stdlib/ dir"  "$DIR_MODULES"

if [[ "$FAILED" -eq 0 ]]; then
    echo "✅ All five stdlib payload sources agree:"
    while IFS= read -r m; do
        [[ -z "$m" ]] && continue
        echo "   - $m"
    done <<< "$DIR_MODULES"
    echo ""
    exit 0
fi

echo "❌ STDLIB PAYLOAD BOUNDARY VIOLATION"
echo "========================================"
echo ""
echo "The following sources disagree on the stdlib module set."
echo "Every stdlib module requires an entry in all five places:"
echo "  1. features/modules/stdlib/<name>/ directory"
echo "  2. Makefile STDLIB_MODULES variable"
echo "  3. build/windows/cfgms-steward.wxs (cfgms-module-<name>.exe Component)"
echo "  4. build/linux/install.sh STDLIB_MODULES array (cfgms-module-<name>)"
echo "  5. build/darwin/build-pkg.sh STDLIB_MODULES array (cfgms-module-<name>)"
echo ""
echo "Disagreements found:"
printf "%b" "$DIAGNOSTICS"
echo ""
echo "Fix: add/remove the module entry from ALL five sources, then re-run"
echo "     make check-stdlib-payload-boundary"
exit 1
