#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 Jordan Ritz
set -euo pipefail

# Compiled artifacts are identified from their leading magic bytes rather than by
# shelling out to file(1). This gate runs in CI, in dev containers and from the
# Makefile security targets; file(1) is an optional distro package, and a gate
# that hard-fails wherever it is absent is a gate that gets bypassed or ignored.
#
# Magic values:
#   7f454c46  \x7fELF                      ELF executable / shared object / object file
#   feedface  feedfacf cefaedfe cffaedfe   Mach-O 32/64-bit, both byte orders
#   cafebabe  bebafeca                     Mach-O universal binary (also Java class data)
#   4d5a....  MZ                           PE32/PE32+ and MS-DOS executables
#   0061736d  \0asm                        WebAssembly binary module
#
# Reading and classifying are separate so an unreadable file is distinguishable
# from a readable one with no recognised header. Folding them together meant a
# failed read produced an empty header, which fell through to "not an artifact" —
# so a committed binary whose permissions were stripped (`chmod 000`) passed the
# gate silently. A security gate must fail closed on a file it cannot inspect.
#
# magic_hex returns non-zero when the file cannot be read, and the caller must
# treat that as blocking: errexit does NOT propagate out of a command
# substitution evaluated in a conditional context, so the failure is signalled
# explicitly rather than left to `set -e`.
#
# Whitespace is stripped with bash parameter expansion rather than tr(1). od(1)
# is the one external tool this gate needs; adding tr(1) would reintroduce
# exactly the fragility that replacing file(1) removed, and the gate is exercised
# under a deliberately minimal PATH (bash, git, od) to keep it that way.
magic_hex() {
    local raw
    raw="$(LC_ALL=C od -An -v -tx1 -N4 -- "$1" 2>/dev/null)" || return 1
    printf '%s' "${raw//[[:space:]]/}"
}

describe_magic() {
    case "$1" in
        7f454c46) echo "ELF binary" ;;
        feedface|feedfacf|cefaedfe|cffaedfe) echo "Mach-O binary" ;;
        cafebabe|bebafeca) echo "Mach-O universal binary or Java class data" ;;
        4d5a*) echo "PE32/MS-DOS executable" ;;
        0061736d) echo "WebAssembly binary module" ;;
        *) return 0 ;;
    esac
}

# Performance: checking every tracked file by shelling out to od(1) per file is
# fine on Linux's fast fork/exec, but on Windows each spawn carries real
# overhead (e.g. real-time antivirus scanning per process creation) that
# compounds across a multi-thousand-file repo into several minutes —
# indistinguishable from a genuine hang against a test timeout. The real fix
# is scripts/check-binary-artifacts/main.go, which reads every tracked file's
# header in ONE process — not an optimization of the subprocess approach, a
# different approach that isn't subject to per-process overhead at all. It
# implements the same fail-closed-on-unreadable-file contract as the bash
# fallback below.
#
# This script builds that program once to a *stable* path (bin/, already
# gitignored — see Makefile's other `go build -o bin/...` targets) and execs
# the same file on every subsequent call, rebuilding only when main.go
# changes. `go run` was measured and rejected here: it links a *fresh* temp
# binary at a new path every invocation, and something in this class of host
# environment (observed: real-time antivirus) re-inspects each new
# executable before letting it run — so `go run` cost 60-90+ seconds on
# *every* call, even with a warm build cache and near-zero actual CPU time.
# A stable, reused file path lets that overhead amortize to (at most) once
# per source change instead of once per invocation.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# GOEXE is determined from uname, not `go env GOEXE` — deliberately: some
# callers (test/unit/build's security-gate tests) put a mock `go` stub earlier
# on PATH to exercise unrelated make-target behavior, and that stub cannot
# answer `go env` correctly. Keeping the extension decision independent of
# whatever `go` currently resolves to means a stale-but-valid prior build is
# still found and reused even when PATH is shadowed like that.
BIN_EXT=""
case "$(uname -s)" in
    MINGW*|MSYS*|CYGWIN*) BIN_EXT=".exe" ;;
esac
BIN_DIR="${SCRIPT_DIR}/../bin"
BIN_PATH="${BIN_DIR}/check-binary-artifacts${BIN_EXT}"
SRC_DIR="${SCRIPT_DIR}/check-binary-artifacts"

if command -v go &>/dev/null; then
    if [[ ! -x "$BIN_PATH" ]] || [[ "${SRC_DIR}/main.go" -nt "$BIN_PATH" ]]; then
        mkdir -p "$BIN_DIR"
        # A shadowed/mock `go` on PATH (see the GOEXE comment above) would
        # "succeed" here without producing a binary. Don't trust this build's
        # own exit code — the -x check right below is the real verdict, and
        # a failed build here must fall through to the bash implementation
        # rather than abort the whole script under `set -e`.
        go build -o "$BIN_PATH" "$SRC_DIR" 2>/dev/null || true
    fi
fi

if [[ -x "$BIN_PATH" ]]; then
    exec "$BIN_PATH" "$@"
fi

echo "check-binary-artifacts: no usable compiled checker at ${BIN_PATH}, falling back to the slower od(1)-based scan" >&2

blocked=0
while IFS= read -r -d '' tracked; do
    [[ -f "$tracked" ]] || continue

    # An empty tracked file has no magic bytes to read and is not an artifact;
    # skipping it keeps `od` from being asked to classify nothing. Checked before
    # readability so an empty file is never reported as unreadable.
    kind=""
    if [[ -s "$tracked" ]]; then
        if ! header="$(magic_hex "$tracked")" || [[ -z "$header" ]]; then
            echo "unreadable tracked file: $tracked (cannot inspect magic bytes)" >&2
            blocked=1
            continue
        fi
        kind="$(describe_magic "$header")"
    fi

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
    echo "" >&2
    echo "compiled artifacts must be produced by the release pipeline, not committed to source" >&2
    exit 1
fi

echo "binary-artifact check passed"
