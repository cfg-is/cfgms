#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 Jordan Ritz
#
# check-binary-artifacts_test.sh — Tests for scripts/check-binary-artifacts.sh.
#
# The gate blocks tracked compiled artifacts from reaching source control, so
# every assertion here is about a merge-gating decision: a false negative lets a
# binary land in the repo, a false positive blocks every commit. Fixtures are
# real git repositories under a scratch directory; the gate is invoked with that
# repository as its working directory, exactly as the Makefile and
# security-scan.yml invoke it.
#
# Dependencies: bash >= 4, git, od (coreutils). Deliberately NOT file(1).
#
# Run: bash scripts/check-binary-artifacts_test.sh
# Exit codes: 0 = all tests passed, 1 = any test failed

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GATE="$REPO_ROOT/scripts/check-binary-artifacts.sh"

SCRATCH="$(mktemp -d "${TMPDIR:-/tmp}/cfgms-binary-artifacts.XXXXXX")"
cleanup() {
    # Fixtures may contain mode-000 files; restore permissions so rm can recurse.
    chmod -R u+rwX "$SCRATCH" 2>/dev/null || true
    rm -rf "$SCRATCH"
}
trap cleanup EXIT INT TERM

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

PASS_COUNT=0
FAIL_COUNT=0

_pass() {
    echo -e "${GREEN}[PASS]${NC} $1"
    PASS_COUNT=$((PASS_COUNT + 1))
}

_fail() {
    echo -e "${RED}[FAIL]${NC} $1"
    FAIL_COUNT=$((FAIL_COUNT + 1))
}

# ---------------------------------------------------------------------------
# Fixture helpers
# ---------------------------------------------------------------------------

# new_repo prints the path to a fresh git repository under the scratch dir.
new_repo() {
    local dir
    dir="$(mktemp -d "$SCRATCH/repo.XXXXXX")"
    git -C "$dir" init -q
    printf '%s' "$dir"
}

# write_bytes <repo> <relative path> <printf format>
# The format is passed to bash's printf, so octal (\177) and hex (\xcf) escapes
# produce exact bytes.
write_bytes() {
    local repo="$1" rel="$2" fmt="$3"
    mkdir -p "$repo/$(dirname "$rel")"
    # shellcheck disable=SC2059 # the format string is the fixture payload
    printf "$fmt" > "$repo/$rel"
}

# deny_read <path> — remove read access from the current user.
# POSIX mode bits are advisory on Windows: Git-Bash `chmod 000` leaves the file
# fully readable (verified — the fixture below still classified as an ELF
# binary), because read access there is governed by the NTFS ACL. Denying the
# ACE explicitly is what actually stages the condition under test; without it
# the "unreadable file" case silently degenerates into "a readable binary is
# blocked", which other tests already cover.
deny_read() {
    case "$OSTYPE" in
        msys*|cygwin*|win32*)
            # MSYS2_ARG_CONV_EXCL keeps the msys argument mangler away from
            # icacls' /deny switch, which it otherwise rewrites into a
            # filesystem path ("Invalid parameter C:/Program Files/Git/deny").
            MSYS2_ARG_CONV_EXCL='*' icacls "$(cygpath -w "$1")" \
                /deny "$(whoami):(R)" >/dev/null 2>&1 || true
            ;;
        *) chmod 000 "$1" ;;
    esac
}

# restore_read <path> — undo deny_read so the scratch tree can be cleaned up.
restore_read() {
    case "$OSTYPE" in
        msys*|cygwin*|win32*)
            MSYS2_ARG_CONV_EXCL='*' icacls "$(cygpath -w "$1")" \
                /remove:d "$(whoami)" >/dev/null 2>&1 || true
            ;;
        *) chmod 644 "$1" ;;
    esac
}

# is_readable <path> — an actual read attempt, not `[[ -r ]]`: the test bit
# reports mode bits, which are exactly what does not govern access on Windows.
is_readable() {
    head -c 1 -- "$1" >/dev/null 2>&1
}

# populate_minimal_bin <dest> <tool>... — fill <dest> with just these tools.
# On POSIX a symlink is enough. On Windows it is not: a copied or linked .exe
# resolves its runtime DLLs from its OWN directory first, so a bare link to
# bash.exe placed outside /usr/bin cannot load msys-2.0.dll and dies with exit
# 127 before the gate under test ever starts. Copy each tool together with the
# in-tree DLLs ldd reports for it (system DLLs live in System32 and resolve
# regardless of PATH), which yields a self-contained minimal bin directory.
populate_minimal_bin() {
    local dest="$1" tool src dep
    shift
    for tool in "$@"; do
        src="$(command -v "$tool")"
        case "$OSTYPE" in
            msys*|cygwin*|win32*)
                cp -- "$src" "$dest/${tool}.exe"
                while read -r _ _ dep _; do
                    case "$dep" in
                        /usr/*|/mingw*) cp -n -- "$dep" "$dest/" 2>/dev/null || true ;;
                    esac
                done < <(ldd "$src" 2>/dev/null)
                ;;
            *) ln -sf "$src" "$dest/$tool" ;;
        esac
    done
}

# track <repo> <relative path>...
track() {
    local repo="$1"
    shift
    git -C "$repo" add -- "$@"
}

GATE_OUT=""
GATE_RC=0

# run_gate <repo> [env assignments...] — runs the gate with <repo> as cwd and
# captures combined output plus exit status.
run_gate() {
    local repo="$1"
    GATE_RC=0
    GATE_OUT="$( (cd "$repo" && bash "$GATE") 2>&1 )" || GATE_RC=$?
}

assert_rc() {
    local want="$1" name="$2"
    if [[ "$GATE_RC" == "$want" ]]; then
        _pass "$name (exit $GATE_RC)"
    else
        _fail "$name: expected exit $want, got $GATE_RC"
        echo "$GATE_OUT" | sed 's/^/      /' >&2
    fi
}

assert_contains() {
    local needle="$1" name="$2"
    if [[ "$GATE_OUT" == *"$needle"* ]]; then
        _pass "$name"
    else
        _fail "$name: output missing '$needle'"
        echo "$GATE_OUT" | sed 's/^/      /' >&2
    fi
}

assert_not_contains() {
    local needle="$1" name="$2"
    if [[ "$GATE_OUT" != *"$needle"* ]]; then
        _pass "$name"
    else
        _fail "$name: output unexpectedly contains '$needle'"
        echo "$GATE_OUT" | sed 's/^/      /' >&2
    fi
}

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

# A repository of ordinary source files must pass. This is the false-positive
# guard: if it fails, every commit in the project is blocked.
test_clean_repo_passes() {
    local repo
    repo="$(new_repo)"
    write_bytes "$repo" "pkg/thing/thing.go" 'package thing\n\nfunc Do() {}\n'
    write_bytes "$repo" "README.md" '# Title\n\nProse.\n'
    write_bytes "$repo" "scripts/run.sh" '#!/usr/bin/env bash\nexit 0\n'
    write_bytes "$repo" "api/proto/thing.proto" 'syntax = "proto3";\n'
    write_bytes "$repo" "web/app.ts" 'export const x = 1;\n'
    track "$repo" pkg README.md scripts api web

    run_gate "$repo"
    assert_rc 0 "clean source repository passes"
    assert_contains "binary-artifact check passed" "clean repository reports success"
}

# Every magic signature the detector claims to recognise, asserted against the
# exact description string the gate emits. Names carry no compiled-artifact
# extension so that only the magic-byte path can produce the finding.
test_magic_signatures_blocked() {
    local -a cases=(
        'elf-linux|\177ELF\2\1\1\0\0\0\0\0\0\0\0\0\2\0\076\0|ELF binary'
        'macho-32-be|\xfe\xed\xfa\xce\0\0\0\7\0\0\0\3\0\0\0\2|Mach-O binary'
        'macho-32-le|\xce\xfa\xed\xfe\7\0\0\0\3\0\0\0\2\0\0\0|Mach-O binary'
        'macho-64-be|\xfe\xed\xfa\xcf\1\0\0\7\0\0\0\3\0\0\0\2|Mach-O binary'
        'macho-64-le|\xcf\xfa\xed\xfe\7\0\0\1\3\0\0\0\2\0\0\0|Mach-O binary'
        'macho-fat-be|\xca\xfe\xba\xbe\0\0\0\2\1\0\0\7\0\0\0\3|Mach-O universal binary or Java class data'
        'macho-fat-le|\xbe\xba\xfe\xca\2\0\0\0\7\0\0\1\3\0\0\0|Mach-O universal binary or Java class data'
        'pe-windows|MZ\x90\0\3\0\0\0\4\0\0\0\xff\xff\0\0PE\0\0|PE32/MS-DOS executable'
        'wasm-module|\0asm\1\0\0\0\1\7\1\140\0\1\177|WebAssembly binary module'
    )

    local case_spec name fmt want repo
    for case_spec in "${cases[@]}"; do
        name="${case_spec%%|*}"
        fmt="${case_spec#*|}"
        want="${fmt#*|}"
        fmt="${fmt%%|*}"

        repo="$(new_repo)"
        write_bytes "$repo" "build/$name" "$fmt"
        track "$repo" "build/$name"

        run_gate "$repo"
        assert_rc 1 "$name magic is blocked"
        assert_contains "tracked compiled artifact: build/$name ($want)" \
            "$name reports '$want'"
        assert_not_contains "extension" "$name blocked by magic, not by extension"
    done
}

# cafebabe / bebafeca are simultaneously the Mach-O fat-binary magic and the
# Java class-file magic. The gate cannot disambiguate from four bytes, so it
# emits exactly one line naming both formats. Both are compiled artifacts, so
# the blocking decision is correct either way — this pins that contract.
test_ambiguous_cafebabe_emits_single_finding() {
    local repo line_count
    repo="$(new_repo)"
    # Byte-for-byte header of a real Java 8 class file (cafebabe, minor 0,
    # major 52) — the ambiguous twin of the Mach-O universal header.
    write_bytes "$repo" "build/Widget" '\xca\xfe\xba\xbe\0\0\0\064\0\x1d\012\0\6\0\017'
    track "$repo" "build/Widget"

    run_gate "$repo"
    assert_rc 1 "java class file (cafebabe) is blocked"
    line_count="$(printf '%s\n' "$GATE_OUT" | grep -c 'tracked compiled artifact: build/Widget' || true)"
    if [[ "$line_count" == "1" ]]; then
        _pass "ambiguous cafebabe emits exactly one finding line"
    else
        _fail "ambiguous cafebabe emitted $line_count finding lines, expected 1"
        echo "$GATE_OUT" | sed 's/^/      /' >&2
    fi
    assert_contains "Mach-O universal binary or Java class data" \
        "ambiguous cafebabe names both candidate formats"
}

# A genuinely compiled binary produced by a real toolchain, not a hand-written
# header: od(1) itself is a required dependency of the gate, so it exists on
# every host that can run this suite (ELF on Linux, Mach-O on macOS).
test_real_host_binary_blocked() {
    local repo od_path
    od_path="$(command -v od)"
    repo="$(new_repo)"
    # `cat` redirection, not `cp` (Issue #3686): Windows/Git-Bash `cp` silently
    # appends `.exe` to an extensionless destination when the source is an
    # executable, so the subsequent `git add -- vendor-tool` below fails with
    # "pathspec 'vendor-tool' did not match any files".
    cat -- "$od_path" > "$repo/vendor-tool"
    chmod +x "$repo/vendor-tool"
    track "$repo" vendor-tool

    run_gate "$repo"
    assert_rc 1 "real compiled host binary is blocked"
    assert_contains "tracked compiled artifact: vendor-tool" \
        "real host binary is named in the finding"
    if [[ "$GATE_OUT" == *"ELF binary"* || "$GATE_OUT" == *"Mach-O binary"* || "$GATE_OUT" == *"PE32/MS-DOS executable"* ]]; then
        _pass "real host binary is classified as a native executable format"
    else
        _fail "real host binary was not classified as ELF/Mach-O/PE"
        echo "$GATE_OUT" | sed 's/^/      /' >&2
    fi
}

# Boundary of the `[[ -s ]]` guard and of od's 4-byte read: files with fewer
# than four bytes cannot complete a signature and must not be blocked. A
# zero-byte and a one-byte file also prove the guard does not crash the loop.
test_short_files_below_signature_length_pass() {
    local repo
    repo="$(new_repo)"
    write_bytes "$repo" "fixtures/empty" ''
    write_bytes "$repo" "fixtures/one-byte" '\177'
    write_bytes "$repo" "fixtures/two-bytes" '\177E'
    write_bytes "$repo" "fixtures/three-bytes" '\177EL'
    write_bytes "$repo" "fixtures/four-bytes-text" 'text'
    track "$repo" fixtures

    run_gate "$repo"
    assert_rc 0 "files shorter than a full signature pass"
    assert_contains "binary-artifact check passed" "short-file repository reports success"
}

# The PE signature is complete at two bytes, so the gate fails closed on a
# truncated MZ file even though od read fewer than four bytes.
test_two_byte_mz_fails_closed() {
    local repo
    repo="$(new_repo)"
    write_bytes "$repo" "fixtures/truncated" 'MZ'
    track "$repo" fixtures/truncated

    run_gate "$repo"
    assert_rc 1 "two-byte MZ file fails closed"
    assert_contains "tracked compiled artifact: fixtures/truncated (PE32/MS-DOS executable)" \
        "two-byte MZ reports the PE description"
}

# The extension fallback catches artifacts whose magic bytes the parser does not
# model (static archives, COFF objects, import libraries).
test_extension_fallback_blocks() {
    local repo ext
    for ext in a o obj lib dll dylib so wasm exe; do
        repo="$(new_repo)"
        write_bytes "$repo" "out/artifact.$ext" 'this payload has no executable magic\n'
        track "$repo" "out/artifact.$ext"

        run_gate "$repo"
        assert_rc 1 ".$ext extension is blocked"
        assert_contains "tracked compiled artifact extension: out/artifact.$ext" \
            ".$ext reports the extension finding"
    done
}

# A file carrying both a blocked extension and executable magic must report both
# findings — the two detectors are independent, not short-circuited.
test_magic_and_extension_both_reported() {
    local repo
    repo="$(new_repo)"
    write_bytes "$repo" "out/module.wasm" '\0asm\1\0\0\0\1\7\1\140\0\1\177'
    track "$repo" out/module.wasm

    run_gate "$repo"
    assert_rc 1 "wasm file with wasm extension is blocked"
    assert_contains "tracked compiled artifact: out/module.wasm (WebAssembly binary module)" \
        "magic detector reports the wasm file"
    assert_contains "tracked compiled artifact extension: out/module.wasm" \
        "extension detector reports the wasm file"
}

# The gate scopes to tracked files: an untracked build output in the working
# tree is not a source-control problem and must not block a commit.
test_untracked_binary_ignored() {
    local repo
    repo="$(new_repo)"
    write_bytes "$repo" "README.md" '# Title\n'
    write_bytes "$repo" "bin/controller" '\177ELF\2\1\1\0\0\0\0\0\0\0\0\0\2\0\076\0'
    track "$repo" README.md

    run_gate "$repo"
    assert_rc 0 "untracked binary in the working tree is ignored"
    assert_not_contains "bin/controller" "untracked binary is not reported"
}

# git ls-files still lists a staged file that was removed from the working tree;
# the `[[ -f ]]` guard must skip it instead of erroring out under `set -e`.
test_tracked_but_missing_file_skipped() {
    local repo
    repo="$(new_repo)"
    write_bytes "$repo" "docs/gone.md" 'content\n'
    track "$repo" docs/gone.md
    rm -- "$repo/docs/gone.md"

    run_gate "$repo"
    assert_rc 0 "tracked file missing from the working tree is skipped"
    assert_contains "binary-artifact check passed" "missing-file repository reports success"
}

# NUL-delimited iteration: paths containing spaces must be inspected and
# reported whole, not split into fragments.
test_path_with_spaces_blocked() {
    local repo
    repo="$(new_repo)"
    write_bytes "$repo" "third party/probe tool" '\177ELF\2\1\1\0\0\0\0\0\0\0\0\0\2\0\076\0'
    track "$repo" "third party/probe tool"

    run_gate "$repo"
    assert_rc 1 "binary at a path containing spaces is blocked"
    assert_contains "tracked compiled artifact: third party/probe tool (ELF binary)" \
        "path containing spaces is reported intact"
}

# Two offenders must both be reported in a single run: the loop accumulates
# findings rather than exiting on the first one.
test_all_offenders_reported() {
    local repo
    repo="$(new_repo)"
    write_bytes "$repo" "bin/steward" '\177ELF\2\1\1\0\0\0\0\0\0\0\0\0\2\0\076\0'
    write_bytes "$repo" "bin/cfg.exe" 'MZ\x90\0\3\0\0\0\4\0\0\0\xff\xff\0\0PE\0\0'
    write_bytes "$repo" "README.md" '# Title\n'
    track "$repo" bin README.md

    run_gate "$repo"
    assert_rc 1 "repository with several artifacts is blocked"
    assert_contains "tracked compiled artifact: bin/steward (ELF binary)" \
        "first offender is reported"
    assert_contains "tracked compiled artifact: bin/cfg.exe (PE32/MS-DOS executable)" \
        "second offender is reported"
    assert_contains "compiled artifacts must be produced by the release pipeline" \
        "summary remediation message is emitted"
}

# A file the gate cannot read is a file the gate cannot clear. Regression test:
# od's failure used to be swallowed inside the command substitution, so an
# unreadable tracked binary passed the gate silently.
test_unreadable_file_fails_closed() {
    local repo
    repo="$(new_repo)"
    write_bytes "$repo" "bin/opaque" '\177ELF\2\1\1\0\0\0\0\0\0\0\0\0\2\0\076\0'
    track "$repo" bin/opaque
    deny_read "$repo/bin/opaque"

    # The fixture is only meaningful if access was actually revoked. root
    # bypasses mode bits outright, so verify rather than assume — asserting
    # against a still-readable file would silently re-test the ordinary
    # ELF-detection path under this test's name.
    if is_readable "$repo/bin/opaque"; then
        _pass "unreadable-file fail-closed check not applicable (read access could not be revoked for this user)"
        restore_read "$repo/bin/opaque"
        return
    fi

    run_gate "$repo"
    assert_rc 1 "unreadable tracked file fails closed"
    assert_contains "unreadable tracked file: bin/opaque" \
        "unreadable file is named in the finding"
    restore_read "$repo/bin/opaque"
}

# The rewrite exists so the gate keeps working where file(1) is absent. Running
# with a PATH that contains only bash, git and od proves the detector has no
# hidden dependency on file(1) and cannot be silently disabled by its absence.
test_runs_without_file_utility() {
    local repo shim
    repo="$(new_repo)"
    write_bytes "$repo" "bin/steward" '\177ELF\2\1\1\0\0\0\0\0\0\0\0\0\2\0\076\0'
    track "$repo" bin/steward

    shim="$SCRATCH/minimal-bin"
    mkdir -p "$shim"
    populate_minimal_bin "$shim" bash git od

    if [[ -x "$shim/file" ]]; then
        _fail "minimal PATH unexpectedly provides file(1)"
        return
    fi

    GATE_RC=0
    GATE_OUT="$( (cd "$repo" && env -i PATH="$shim" HOME="$SCRATCH" "$shim/bash" "$GATE") 2>&1 )" || GATE_RC=$?
    assert_rc 1 "gate blocks an ELF binary with file(1) absent from PATH"
    assert_contains "tracked compiled artifact: bin/steward (ELF binary)" \
        "detection works without file(1)"
    assert_not_contains "requires the 'file' utility" \
        "gate does not demand file(1)"
}

# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

echo "check-binary-artifacts.sh tests"
echo "==============================="

if [[ ! -x "$GATE" ]]; then
    echo "ERROR: $GATE is missing or not executable" >&2
    exit 1
fi

test_clean_repo_passes
test_magic_signatures_blocked
test_ambiguous_cafebabe_emits_single_finding
test_real_host_binary_blocked
test_short_files_below_signature_length_pass
test_two_byte_mz_fails_closed
test_extension_fallback_blocks
test_magic_and_extension_both_reported
test_untracked_binary_ignored
test_tracked_but_missing_file_skipped
test_path_with_spaces_blocked
test_all_offenders_reported
test_unreadable_file_fails_closed
test_runs_without_file_utility

echo ""
echo "Passed: $PASS_COUNT  Failed: $FAIL_COUNT"

if [[ "$FAIL_COUNT" -ne 0 ]]; then
    echo "check-binary-artifacts.sh tests: FAIL"
    exit 1
fi

echo "check-binary-artifacts.sh tests: PASS"
