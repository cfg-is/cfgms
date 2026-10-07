#!/bin/bash
# Check for direct pkg/storage/providers/* imports outside allowed locations.
# Exit code 0 = clean, 1 = violations found.
# Usage: ./scripts/check-providers.sh [--staged-only]

set -e

STAGED_ONLY=false
if [[ "${1:-}" == "--staged-only" ]]; then
    STAGED_ONLY=true
fi

IMPORT_PATTERN='"github.com/cfgis/cfgms/pkg/storage/providers/'

VIOLATIONS=0
VIOLATION_OUTPUT=""

get_files() {
    if [ "$STAGED_ONLY" = true ]; then
        git diff --cached --name-only --diff-filter=ACM | grep '\.go$' || true
    else
        git ls-files '*.go'
    fi
}

is_allowed() {
    local file="$1"
    [[ "$file" == pkg/storage/providers/* ]] && return 0
    [[ "$file" == pkg/configrouting/providers/* ]] && return 0
    [[ "$file" == pkg/testing/* ]] && return 0
    [[ "$file" == test/* ]] && return 0
    [[ "$file" == cmd/controller/main.go ]] && return 0
    [[ "$file" == cmd/cfg/cmd/storage.go ]] && return 0
    [[ "$file" == pkg/migrate/storage/* ]] && return 0
    [[ "$file" == pkg/migrate/secrets/* ]] && return 0
    [[ "$file" == pkg/migrate/blob/* ]] && return 0
    [[ "$file" == features/controller/initialization/initialization.go ]] && return 0
    [[ "$file" == features/controller/server/server.go ]] && return 0
    # hyperv provision store: NewFlatFileProvisionStore is the durable-store
    # constructor for the hyperv module's provision store (Issue #2371). It
    # wraps flatfile directly — analogous to controller initialization files.
    [[ "$file" == features/modules/hyperv/provision.go ]] && return 0
    # entra_group workflow-module binary: cmd/main.go registers the flatfile
    # storage provider that the sops secrets provider layers its encrypted
    # secret data on (Issue #4420) — a registry-bootstrap entry point, the same
    # shape as cmd/controller/main.go, for a module binary rather than a
    # long-running server. Listed as one exact path, not a
    # features/workflow/modules/m365/*/cmd/main.go glob: a glob would
    # pre-authorize every future m365 module binary without review, and the
    # other existing one (entra_user/cmd/main.go) does not need it.
    [[ "$file" == features/workflow/modules/m365/entra_group/cmd/main.go ]] && return 0
    [[ "$file" == */providers_test.go ]] && return 0
    return 1
}

if [ "$STAGED_ONLY" = true ]; then
    echo "Checking staged Go files for direct storage provider imports..."
else
    echo "Checking all tracked Go files for direct storage provider imports..."
fi

while IFS= read -r file; do
    [ -z "$file" ] && continue
    is_allowed "$file" && continue

    while IFS= read -r match; do
        [ -z "$match" ] && continue
        VIOLATION_OUTPUT="${VIOLATION_OUTPUT}  ${file}:${match}\n"
        VIOLATIONS=$((VIOLATIONS + 1))
    done < <(grep -n "$IMPORT_PATTERN" "$file" 2>/dev/null || true)
done < <(get_files)

if [ "$VIOLATIONS" -eq 0 ]; then
    echo "No storage provider import violations found."
    exit 0
else
    echo ""
    echo "STORAGE PROVIDER IMPORT VIOLATIONS: $VIOLATIONS violation(s) found"
    echo ""
    printf "%b" "$VIOLATION_OUTPUT"
    echo ""
    echo "Direct pkg/storage/providers/* imports are only allowed in:"
    echo "  pkg/storage/providers/                                      (provider-internal)"
    echo "  pkg/configrouting/providers/                                (provider-internal)"
    echo "  pkg/testing/                                                (test registration helpers)"
    echo "  test/                                                       (integration and e2e tests)"
    echo "  cmd/controller/main.go                                      (registry bootstrap)"
    echo "  cmd/cfg/cmd/storage.go                                      (CLI registry bootstrap)"
    echo "  pkg/migrate/storage/                                        (migration engine registry bootstrap)"
    echo "  pkg/migrate/secrets/                                        (migration engine registry bootstrap)"
    echo "  pkg/migrate/blob/                                           (migration engine registry bootstrap)"
    echo "  features/controller/initialization/initialization.go        (registry bootstrap)"
    echo "  features/controller/server/server.go                        (registry bootstrap)"
    echo "  features/modules/hyperv/provision.go                        (hyperv durable store constructor, Issue #2371)"
    echo "  features/workflow/modules/m365/entra_group/cmd/main.go      (entra_group module binary registry bootstrap, Issue #4420)"
    echo "  */providers_test.go                                         (per-package test provider registration)"
    exit 1
fi
