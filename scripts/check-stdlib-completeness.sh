#!/bin/bash
# Enforce ADR-016 clause 6: stdlib module completeness gate.
#
# For every module listed in STDLIB_MODULES, asserts:
#   2. Has a valid module.yaml with required fields: name, version, publisher, executors
#   3. Has cmd/main.go (bundle entry point, ensures the module builds as a bundle)
#   4. module.yaml declares at least one owns: entry (ADR-016 clause 5)
#   5. No stub_*-prefixed .go filename, no panic("TODO"), no ErrNotImplemented
#      in non-test .go files
#
# Check 1 (stdlib/ directory + installer manifest agreement) is enforced by
# check-stdlib-payload-boundary, which is a Makefile prerequisite of this target.
#
# Exit code: 0 = all checks pass, 1 = any violation detected.
# Usage: ./scripts/check-stdlib-completeness.sh
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
STDLIB_DIR="$ROOT/features/modules/stdlib"

# ── Extract STDLIB_MODULES from Makefile ──────────────────────────────────────
# Handles both single-line and multi-line (backslash-continued) forms.
# Reuses the same awk pattern as check-stdlib-payload-boundary.sh.

extract_modules() {
    if [[ ! -f "$MAKEFILE" ]]; then
        echo "ERROR: Makefile not found: $MAKEFILE" >&2
        exit 1
    fi
    awk '
        /^STDLIB_MODULES[[:space:]]*:=/ { in_block=1; sub(/^STDLIB_MODULES[[:space:]]*:=[[:space:]]*/,""); }
        in_block {
            cont = ($0 ~ /\\[[:space:]]*$/)
            gsub(/\\[[:space:]]*$/, "")
            gsub(/^[[:space:]]+|[[:space:]]+$/, "")
            if ($0 != "") print $0
            if (!cont) in_block=0
        }
    ' "$MAKEFILE" | grep -v '^$' || true
}

# ── Violation accumulator ──────────────────────────────────────────────────────

VIOLATIONS=0
VIOLATION_OUTPUT=""

record_violation() {
    local module="$1"
    local check="$2"
    local detail="$3"
    VIOLATIONS=$((VIOLATIONS + 1))
    VIOLATION_OUTPUT+="  ❌ [$module] $check: $detail\n"
}

# ── Per-module checks ──────────────────────────────────────────────────────────

echo "🔍 Checking stdlib module completeness (ADR-016 clause 6)..."
echo ""

while IFS= read -r module; do
    [[ -z "$module" ]] && continue

    MODULE_DIR="$STDLIB_DIR/$module"
    MANIFEST="$MODULE_DIR/module.yaml"

    # ── Check 2: valid module.yaml with required fields ────────────────────────

    if [[ ! -f "$MANIFEST" ]]; then
        record_violation "$module" "check-2" "module.yaml not found at $MANIFEST"
        # Cannot do further YAML checks without a manifest.
        continue
    fi

    for field in name version publisher executors; do
        if ! grep -qE "^${field}[[:space:]]*:" "$MANIFEST"; then
            record_violation "$module" "check-2" "module.yaml missing required field: $field"
        fi
    done

    # ── Check 3: cmd/main.go exists (bundle entry point) ──────────────────────

    if [[ ! -f "$MODULE_DIR/cmd/main.go" ]]; then
        record_violation "$module" "check-3" "cmd/main.go not found (bundle entry point missing)"
    fi

    # ── Check 4: owns: declared (ADR-016 clause 5) ────────────────────────────

    if ! grep -qE "^owns[[:space:]]*:" "$MANIFEST"; then
        record_violation "$module" "check-4" "module.yaml missing owns: declaration (ADR-016 clause 5)"
    fi

    # ── Check 5: no unresolved stubs in non-test Go files ─────────────────────
    #
    # Three markers indicate unresolved work (ADR-016 clause 6 #5):
    #   a. stub_*-prefixed filename (file STARTS with "stub_")
    #   b. panic("TODO") in the source
    #   c. ErrNotImplemented in the source
    #
    # ErrUnsupportedPlatform in build-tag platform-fallback files (e.g.,
    # executor_stub.go) is intentional and is NOT flagged — the grep targets
    # ErrNotImplemented only.

    # 5a: stub_*-prefixed filenames (recursive, non-test only)
    while IFS= read -r stubfile; do
        [[ -z "$stubfile" ]] && continue
        record_violation "$module" "check-5" "stub_*-prefixed file: $(basename "$stubfile") (rename to *_stub.go)"
    done < <(find "$MODULE_DIR" -name 'stub_*.go' ! -name '*_test.go' 2>/dev/null || true)

    # 5b and 5c: scan non-test Go files for panic("TODO") and ErrNotImplemented
    while IFS= read -r -d '' gofile; do
        relfile="${gofile#"$MODULE_DIR/"}"

        if grep -qE 'panic\("TODO"' "$gofile" 2>/dev/null; then
            while IFS= read -r hit; do
                [[ -z "$hit" ]] && continue
                record_violation "$module" "check-5" "panic(\"TODO\") in $relfile: $hit"
            done < <(grep -n 'panic("TODO"' "$gofile" || true)
        fi

        if grep -qE '\bErrNotImplemented\b' "$gofile" 2>/dev/null; then
            while IFS= read -r hit; do
                [[ -z "$hit" ]] && continue
                record_violation "$module" "check-5" "ErrNotImplemented in $relfile: $hit"
            done < <(grep -n '\bErrNotImplemented\b' "$gofile" || true)
        fi

    done < <(find "$MODULE_DIR" -name '*.go' ! -name '*_test.go' -print0 2>/dev/null || true)

done < <(extract_modules)

echo ""

# ── Report ─────────────────────────────────────────────────────────────────────

if [[ "$VIOLATIONS" -eq 0 ]]; then
    echo "✅ All stdlib modules pass completeness checks (ADR-016 clause 6)"
    echo ""
    exit 0
fi

echo "❌ STDLIB COMPLETENESS VIOLATIONS ($VIOLATIONS total)"
echo "========================================================"
echo ""
printf "%b" "$VIOLATION_OUTPUT"
echo ""
echo "See ADR-016 clause 6 and docs/architecture/modules/README.md for requirements."
echo ""
echo "Common fixes:"
echo "  check-2: add a module.yaml with name, version, publisher, executors"
echo "  check-3: add cmd/main.go as the bundle entry point"
echo "  check-4: add owns: - kind: <name> to module.yaml (ADR-016 clause 5)"
echo "  check-5: rename stub_*.go to *_stub.go, replace panic(\"TODO\") with real"
echo "           implementation, replace ErrNotImplemented with ErrUnsupportedPlatform"
echo "           (legitimate cross-platform fallback) or a module-specific error."
exit 1
