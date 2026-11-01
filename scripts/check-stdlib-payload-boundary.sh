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
# Each installer payload declaration (3-5) must name a per-module installation
# ROOT DIRECTORY (module.yaml + bundle.yaml sidecar + binary), not a flat
# cfgms-module-<name> binary (Issue #4431). That is asserted in addition to the
# five-way name agreement.
#
# Exit code: 0 = all five agree and all payloads are per-module roots, 1 = otherwise.
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
# Pattern: <Directory Id="MODULEDIR_<NAME>" Name="<name>"> — one installation-root
# directory per module under MODULESDIR.
# Uses grep+sed — no xmllint dependency required.
extract_wxs() {
    if [[ ! -f "$WXS_FILE" ]]; then
        echo "ERROR: WiX file not found: $WXS_FILE" >&2
        exit 1
    fi
    grep -o '<Directory[[:space:]]\{1,\}Id="MODULEDIR_[A-Za-z0-9_]*"[[:space:]]\{1,\}Name="[^"]*"' "$WXS_FILE" \
        | sed 's/.*Name="//;s/"$//' \
        | normalize
}

# Extract the names in a bash STDLIB_MODULES=(…) array in the given file, exactly as
# written. Handles both single-line and multi-line (one-name-per-line) forms.
extract_bash_array_raw() {
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
    ' "$file"
}

# Bare module names from a STDLIB_MODULES array. A legacy cfgms-module- prefix is
# stripped so a flat-binary declaration still takes part in the name comparison and
# is then reported by the per-module-root assertion below instead of as a bogus
# "module missing".
extract_bash_array() {
    extract_bash_array_raw "$1" | sed 's/^cfgms-module-//' | normalize
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

# ── Per-module installation-root assertions (Issue #4431) ─────────────────────

# assert_array_names_roots <label> <file>: every array entry is a bare module name
# (a root directory under modules/), never a flat cfgms-module-<name> binary.
assert_array_names_roots() {
    local label="$1" file="$2" entry
    while IFS= read -r entry; do
        [[ -z "$entry" ]] && continue
        if [[ "$entry" == cfgms-module-* ]]; then
            FAILED=1
            DIAGNOSTICS+="  ❌ $label declares a flat binary '$entry', not a per-module root directory\n"
        fi
    done < <(extract_bash_array_raw "$file")
}

# assert_wxs_names_roots: no flat cfgms-module-<name>.exe file directly under
# MODULESDIR, and every module root carries the manifest, the sidecar and the binary
# from its own subdirectory of $(var.ModulesDir).
assert_wxs_names_roots() {
    local module
    local flat
    flat=$(grep -o 'Source="\$(var\.ModulesDir)\\cfgms-module-[^"]*"' "$WXS_FILE" || true)
    if [[ -n "$flat" ]]; then
        FAILED=1
        DIAGNOSTICS+="  ❌ WiX .wxs declares flat binaries (not per-module roots): $flat\n"
    fi
    while IFS= read -r module; do
        [[ -z "$module" ]] && continue
        local f
        for f in "module.yaml" "bundle.yaml" "cfgms-module-$module.exe"; do
            if ! grep -qF "Source=\"\$(var.ModulesDir)\\$module\\$f\"" "$WXS_FILE"; then
                FAILED=1
                DIAGNOSTICS+="  ❌ WiX .wxs root for '$module' does not stage $f from \$(var.ModulesDir)\\$module\\\n"
            fi
        done
    done <<< "$WXS_MODULES"
}

echo "🔍 Checking stdlib payload boundary (ADR-016 clause 3)..."
echo ""

compare_pair "stdlib/ dir"  "$DIR_MODULES"      "Makefile"      "$MAKEFILE_MODULES"
compare_pair "Makefile"     "$MAKEFILE_MODULES"  "WiX .wxs"     "$WXS_MODULES"
compare_pair "WiX .wxs"    "$WXS_MODULES"       "install.sh"    "$INSTALL_SH_MODULES"
compare_pair "install.sh"   "$INSTALL_SH_MODULES" "build-pkg.sh" "$BUILD_PKG_MODULES"

# Also check build-pkg.sh vs dir (catches a module only in build-pkg.sh)
compare_pair "build-pkg.sh" "$BUILD_PKG_MODULES" "stdlib/ dir"  "$DIR_MODULES"

assert_wxs_names_roots
assert_array_names_roots "install.sh" "$INSTALL_SH"
assert_array_names_roots "build-pkg.sh" "$BUILD_PKG_SH"

if [[ "$FAILED" -eq 0 ]]; then
    echo "✅ All five stdlib payload sources agree and name per-module root directories:"
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
echo "  3. build/windows/cfgms-steward.wxs (MODULEDIR_<NAME> root Directory)"
echo "  4. build/linux/install.sh STDLIB_MODULES array (bare <name>)"
echo "  5. build/darwin/build-pkg.sh STDLIB_MODULES array (bare <name>)"
echo ""
echo "Disagreements found:"
printf "%b" "$DIAGNOSTICS"
echo ""
echo "Fix: add/remove the module entry from ALL five sources, then re-run"
echo "     make check-stdlib-payload-boundary"
exit 1
