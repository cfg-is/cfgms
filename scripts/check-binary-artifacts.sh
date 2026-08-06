#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 Jordan Ritz
set -euo pipefail

if ! command -v file >/dev/null 2>&1; then
    echo "binary-artifact check requires the 'file' utility" >&2
    exit 2
fi

blocked=0
while IFS= read -r -d '' tracked; do
    [[ -f "$tracked" ]] || continue

    description="$(file --brief -- "$tracked")"
    case "$description" in
        *"ELF "*|*"Mach-O "*|*"PE32 "*|*"MS-DOS executable"*|*"WebAssembly binary module"*)
            echo "tracked compiled artifact: $tracked ($description)" >&2
            blocked=1
            ;;
    esac

    case "$tracked" in
        *.a|*.o|*.obj|*.lib|*.dll|*.dylib|*.so|*.wasm|*.exe)
            echo "tracked compiled artifact extension: $tracked" >&2
            blocked=1
            ;;
    esac
done < <(git ls-files -z)

if [[ "$blocked" -ne 0 ]]; then
    echo "compiled artifacts must be produced by the release pipeline, not committed to source" >&2
    exit 1
fi

echo "binary-artifact check passed"
