#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 Jordan Ritz
set -euo pipefail

# Compiled artifacts are identified from their leading magic bytes rather than by
# shelling out to file(1). This gate runs in CI, in dev containers and from the
# Makefile security targets; file(1) is an optional distro package, and a gate
# that hard-fails wherever it is absent is a gate that gets bypassed or ignored.
# Header bytes are read with od(1), which ships with coreutils and is present
# anywhere git is.
#
# Magic values:
#   7f454c46  \x7fELF                      ELF executable / shared object / object file
#   feedface  feedfacf cefaedfe cffaedfe   Mach-O 32/64-bit, both byte orders
#   cafebabe  bebafeca                     Mach-O universal binary (also Java class data)
#   4d5a....  MZ                           PE32/PE32+ and MS-DOS executables
#   0061736d  \0asm                        WebAssembly binary module
artifact_kind() {
    local header
    header="$(od -An -v -tx1 -N4 -- "$1" | tr -d ' \n')"

    case "$header" in
        7f454c46) echo "ELF binary" ;;
        feedface|feedfacf|cefaedfe|cffaedfe) echo "Mach-O binary" ;;
        cafebabe|bebafeca) echo "Mach-O universal binary or Java class data" ;;
        4d5a*) echo "PE32/MS-DOS executable" ;;
        0061736d) echo "WebAssembly binary module" ;;
        *) return 0 ;;
    esac
}

blocked=0
while IFS= read -r -d '' tracked; do
    [[ -f "$tracked" ]] || continue

    kind="$(artifact_kind "$tracked")"
    if [[ -n "$kind" ]]; then
        echo "tracked compiled artifact: $tracked ($kind)" >&2
        blocked=1
    fi

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
