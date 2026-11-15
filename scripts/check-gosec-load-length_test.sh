#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 Jordan Ritz
#
# Tests for scripts/check-gosec-load-length.sh and scripts/run-gosec.sh
# (Issue #6270).
#
# Covers: a throwaway Go module with enough non-test files to exceed a set
# GOSEC_LOAD_THRESHOLD is rejected (exit 1) with the package import path, its
# computed length, the threshold and the hard limit on stderr; the same module
# passes (exit 0) with the threshold raised; _test.go files are not counted;
# the computed length equals an independently computed sum(len(root/dir/file)+1);
# a root-package fixture and a symlinked module root are measured against the
# logical scan root; a bad threshold fails closed (exit 2); and the wiring —
# both gosec invocations in security-scan.yml and the Makefile security-gosec
# target call scripts/run-gosec.sh, which builds a private mktemp -d scan root
# (Issue #6276), verifies the link before cd, runs the guard by an absolute
# path before gosec and returns gosec's exit code; a stub gosec on PATH
# exercises the wrapper end to end.
#
# Each case runs in a throwaway module so nothing touches the real tree.
#
# Usage: bash scripts/check-gosec-load-length_test.sh

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GUARD="$REPO_ROOT/scripts/check-gosec-load-length.sh"
WRAPPER="$REPO_ROOT/scripts/run-gosec.sh"
WORKFLOW="$REPO_ROOT/.github/workflows/security-scan.yml"
MAKEFILE="$REPO_ROOT/Makefile"

HARD_LIMIT=16383
MODULE="example.com/fixture"
NFILES=20

PASS=0
FAIL=0

pass() {
    echo "  ✅ $1"
    PASS=$((PASS + 1))
}

fail() {
    echo "  ❌ $1"
    FAIL=$((FAIL + 1))
}

TMP_DIRS=()
cleanup() {
    local d
    for d in "${TMP_DIRS[@]:-}"; do
        [ -n "$d" ] && rm -rf "$d"
    done
}
trap cleanup EXIT

# make_module creates a throwaway module and echoes its path. It holds
# big/ with NFILES non-test files plus two _test.go files, small/ with one
# file, and a root package file.
make_module() {
    local dir i
    dir="$(mktemp -d)"
    TMP_DIRS+=("$dir")
    printf 'module %s\n\ngo 1.21\n' "$MODULE" >"$dir/go.mod"
    printf 'package fixture\n' >"$dir/root.go"
    mkdir -p "$dir/big" "$dir/small"
    for i in $(seq 1 "$NFILES"); do
        printf 'package big\n\nconst C%d = %d\n' "$i" "$i" >"$dir/big/file_number_$i.go"
    done
    printf 'package big\n' >"$dir/big/a_long_named_helper_test.go"
    printf 'package big\n' >"$dir/big/another_long_named_helper_test.go"
    printf 'package small\n' >"$dir/small/s.go"
    printf '%s' "$dir"
}

# expected_length <root> <reldir> <module dir> — independent sum(len+1) over
# the non-test .go files in <module dir>/<reldir>, as seen from <root>.
expected_length() {
    local root="$1" rel="$2" moddir="$3" total=0 f path
    for f in "$moddir/$rel"/*.go; do
        case "$f" in *_test.go) continue ;; esac
        if [ -n "$rel" ]; then
            path="$root/$rel/$(basename "$f")"
        else
            path="$root/$(basename "$f")"
        fi
        total=$((total + ${#path} + 1))
    done
    printf '%s' "$total"
}

# run_guard <dir> [VAR=value ...] — runs the guard in <dir>, setting RC/STDOUT/STDERR.
run_guard() {
    local dir="$1" out err
    shift
    out="$(mktemp)"
    err="$(mktemp)"
    ( cd "$dir" && env "$@" bash "$GUARD" ) >"$out" 2>"$err"
    RC=$?
    STDOUT="$(cat "$out")"
    STDERR="$(cat "$err")"
    rm -f "$out" "$err"
}

echo "🧪 scripts/check-gosec-load-length.sh and scripts/run-gosec.sh"
echo "================================================================"

mod="$(make_module)"
root="/scan/root/x"
want_big="$(expected_length "$root" big "$mod")"
want_small="$(expected_length "$root" small "$mod")"

# --- 1. Over the threshold: exit 1 and a message naming package/length/limit --
threshold=$((want_big - 1))
run_guard "$mod" "GOSEC_SCAN_ROOT=$root" "GOSEC_LOAD_THRESHOLD=$threshold"
if [ "$RC" -eq 1 ]; then
    pass "package over the threshold exits 1"
else
    fail "package over the threshold should exit 1 (rc=$RC, stderr: $STDERR)"
fi
case "$STDERR" in
    *"$MODULE/big"*) pass "stderr names the package import path" ;;
    *) fail "stderr should name $MODULE/big (got: $STDERR)" ;;
esac
case "$STDERR" in
    *"$want_big characters"*) pass "stderr states the computed length ($want_big)" ;;
    *) fail "stderr should state length $want_big (got: $STDERR)" ;;
esac
case "$STDERR" in
    *"threshold $threshold"*"$HARD_LIMIT"*) pass "stderr states the threshold and the hard limit $HARD_LIMIT" ;;
    *) fail "stderr should state threshold $threshold and limit $HARD_LIMIT (got: $STDERR)" ;;
esac
case "$STDERR" in
    *"Split the package"*) pass "stderr tells the reader to split the package" ;;
    *) fail "stderr should say to split the package (got: $STDERR)" ;;
esac
case "$STDERR" in
    *"$MODULE/small"*) fail "package within the threshold must not be reported (got: $STDERR)" ;;
    *) pass "only the over-threshold package is reported" ;;
esac

# --- 2. Threshold raised: exit 0 -------------------------------------------
run_guard "$mod" "GOSEC_SCAN_ROOT=$root" "GOSEC_LOAD_THRESHOLD=$want_big"
if [ "$RC" -eq 0 ]; then
    pass "threshold equal to the computed length exits 0"
else
    fail "threshold raised to $want_big should exit 0 (rc=$RC, stderr: $STDERR)"
fi

# --- 3. _test.go files are not counted -------------------------------------
# The fixture's big/ has two long-named _test.go files. If they were counted
# the length would exceed want_big and the run above would have failed; also
# assert directly that adding one more test file leaves the guard passing.
printf 'package big\n' >"$mod/big/yet_another_extremely_long_named_helper_test.go"
run_guard "$mod" "GOSEC_SCAN_ROOT=$root" "GOSEC_LOAD_THRESHOLD=$want_big"
if [ "$RC" -eq 0 ]; then
    pass "_test.go files are not counted"
else
    fail "adding a _test.go file must not change the length (rc=$RC, stderr: $STDERR)"
fi

# --- 4. Computed length equals the independent sum -------------------------
# With the threshold one below the length the reported value is exact.
run_guard "$mod" "GOSEC_SCAN_ROOT=$root" "GOSEC_LOAD_THRESHOLD=$((want_small - 1))"
case "$STDERR" in
    *"$MODULE/big is $want_big characters"*) pass "big/ length $want_big equals the independent sum(len(root/dir/file)+1)" ;;
    *) fail "big/ length should be $want_big (got: $STDERR)" ;;
esac
case "$STDERR" in
    *"$MODULE/small is $want_small characters"*) pass "small/ length $want_small equals the independent sum" ;;
    *) fail "small/ length should be $want_small (got: $STDERR)" ;;
esac

# --- 5. The root package is measured without a directory component ----------
want_root="$(expected_length "$root" "" "$mod")"
run_guard "$mod" "GOSEC_SCAN_ROOT=$root" "GOSEC_LOAD_THRESHOLD=$((want_root - 1))"
case "$STDERR" in
    *"package $MODULE is $want_root characters"*) pass "root package length $want_root measured without a directory component" ;;
    *) fail "root package length should be $want_root (got: $STDERR)" ;;
esac

# --- 6. Default scan root is the logical $PWD, not the resolved path --------
linkparent="$(mktemp -d)"
TMP_DIRS+=("$linkparent")
ln -s "$mod" "$linkparent/s"
want_link="$(expected_length "$linkparent/s" big "$mod")"
out="$(mktemp)"
err="$(mktemp)"
( cd "$linkparent/s" && GOSEC_LOAD_THRESHOLD=$((want_link - 1)) bash "$GUARD" ) >"$out" 2>"$err"
rc=$?
STDERR="$(cat "$err")"
rm -f "$out" "$err"
if [ "$rc" -eq 1 ]; then
    case "$STDERR" in
        *"$MODULE/big is $want_link characters"*) pass "default scan root is the logical \$PWD under a symlink ($want_link)" ;;
        *) fail "under a symlink the length should be $want_link (got: $STDERR)" ;;
    esac
else
    fail "symlinked module root should exit 1 at threshold $((want_link - 1)) (rc=$rc)"
fi

# --- 7. A bad threshold fails closed ---------------------------------------
run_guard "$mod" "GOSEC_SCAN_ROOT=$root" "GOSEC_LOAD_THRESHOLD=lots"
if [ "$RC" -eq 2 ]; then
    pass "non-numeric threshold fails closed (exit 2)"
else
    fail "non-numeric threshold should exit 2 (rc=$RC)"
fi

# --- 8. Outside a Go module the guard fails closed --------------------------
nomod="$(mktemp -d)"
TMP_DIRS+=("$nomod")
run_guard "$nomod" "GOSEC_SCAN_ROOT=$root"
if [ "$RC" -eq 2 ]; then
    pass "fails closed (exit 2) outside a Go module"
else
    fail "outside a Go module the guard must exit 2 (rc=$RC, stderr: $STDERR)"
fi

# --- 9. Wiring: every gosec invocation goes through the wrapper -------------
# A command-position gosec: first word of a line, or after && / ; / `then`.
bare_gosec='(^|&&|;|then)[[:space:]]*@?gosec[[:space:]]'

wf_wrapped="$(grep -c 'scripts/run-gosec\.sh .*-fmt sarif .*-no-fail\|scripts/run-gosec\.sh .*-severity medium' "$WORKFLOW")"
if [ "$wf_wrapped" -eq 3 ]; then
    # 3 = SARIF run with .gosec.json, SARIF run without it, and the gate run.
    pass "security-scan.yml: SARIF (both branches) and gate invocations call scripts/run-gosec.sh"
else
    fail "security-scan.yml should have 3 wrapped gosec invocations (found $wf_wrapped)"
fi
if grep -Eq "$bare_gosec" "$WORKFLOW"; then
    fail "security-scan.yml still has a bare gosec invocation: $(grep -En "$bare_gosec" "$WORKFLOW" | head -1)"
else
    pass "security-scan.yml has no bare gosec invocation"
fi
if grep -q 'scripts/run-gosec\.sh .*-severity medium -confidence medium \./\.\.\.' "$WORKFLOW" &&
    ! grep 'scripts/run-gosec\.sh .*-severity medium' "$WORKFLOW" | grep -q -- '-no-fail'; then
    pass "security-scan.yml gate run keeps -severity/-confidence and has no -no-fail"
else
    fail "security-scan.yml gate run must keep -severity medium -confidence medium and omit -no-fail"
fi

mk_target="$(awk '/^security-gosec:/{f=1; next} f && /^[A-Za-z_.-]+:/{f=0} f' "$MAKEFILE")"
if printf '%s\n' "$mk_target" | grep -q 'scripts/run-gosec\.sh -conf \.gosec\.json -severity medium -confidence medium \./\.\.\.'; then
    pass "Makefile security-gosec calls scripts/run-gosec.sh with the existing flags"
else
    fail "Makefile security-gosec must call scripts/run-gosec.sh -conf .gosec.json -severity medium -confidence medium ./..."
fi
if printf '%s\n' "$mk_target" | grep -Eq "$bare_gosec"; then
    fail "Makefile security-gosec still has a bare gosec invocation"
else
    pass "Makefile security-gosec has no bare gosec invocation"
fi

# The fixed shared path is built from pieces so this file does not name it.
fixed_root="/tmp"/"s"
if grep -v '^[[:space:]]*#' "$WRAPPER" | grep -Eq "${fixed_root}([^[:alnum:]_.-]|\$)"; then
    fail "run-gosec.sh must not reference the fixed shared scan root"
else
    pass "run-gosec.sh does not reference a fixed shared scan root"
fi
if grep -Eq '^SCAN_DIR="\$\(mktemp -d /tmp/gXXXXXX\)"$' "$WRAPPER"; then
    pass "run-gosec.sh creates its scan root with mktemp -d /tmp/gXXXXXX"
else
    fail "run-gosec.sh must create its scan root with mktemp -d /tmp/gXXXXXX"
fi
if grep -Eq '^SCAN_ROOT="\$SCAN_DIR/s"$' "$WRAPPER"; then
    pass "run-gosec.sh links the repository as a one-character name inside the private directory"
else
    fail "run-gosec.sh must set SCAN_ROOT=\"\$SCAN_DIR/s\""
fi
readlink_line="$(grep -n 'readlink "\$SCAN_ROOT"' "$WRAPPER" | head -1 | cut -d: -f1)"
cd_line="$(grep -n '^cd "\$SCAN_ROOT"$' "$WRAPPER" | head -1 | cut -d: -f1)"
if [ -n "$readlink_line" ] && [ -n "$cd_line" ] && [ "$readlink_line" -lt "$cd_line" ]; then
    pass "run-gosec.sh verifies the link target before cd"
else
    fail "run-gosec.sh must verify readlink (line '${readlink_line:-none}') before cd (line '${cd_line:-none}')"
fi
guard_line="$(grep -n 'check-gosec-load-length\.sh' "$WRAPPER" | grep -v '^[0-9]*:#' | head -1 | cut -d: -f1)"
gosec_line="$(grep -n '^gosec "\$@"' "$WRAPPER" | head -1 | cut -d: -f1)"
if grep -v '^[[:space:]]*#' "$WRAPPER" | grep -q '"\$REPO_ROOT/scripts/check-gosec-load-length\.sh"'; then
    pass "run-gosec.sh invokes the guard by an absolute path under the repository root"
else
    fail "run-gosec.sh must invoke \"\$REPO_ROOT/scripts/check-gosec-load-length.sh\""
fi
if [ -n "$guard_line" ] && [ -n "$gosec_line" ] && [ "$guard_line" -lt "$gosec_line" ]; then
    pass "run-gosec.sh runs the guard before gosec"
else
    fail "run-gosec.sh must run the guard (line '${guard_line:-none}') before gosec (line '${gosec_line:-none}')"
fi
if grep -q '^exec gosec' "$WRAPPER"; then
    fail "run-gosec.sh must not exec gosec (the EXIT trap would not run)"
else
    pass "run-gosec.sh does not exec gosec"
fi

# --- 10. Behaviour: wrapper with a stub gosec on PATH ------------------------
# The stub records, from inside the run, its logical $PWD, readlink "$PWD" and
# the parent of $PWD (the link is gone afterwards), then exits with $STUB_RC.
stubdir="$(mktemp -d)"
TMP_DIRS+=("$stubdir")
cat >"$stubdir/gosec" <<'STUB'
#!/bin/bash
{
    printf 'pwd=%s\n' "$PWD"
    printf 'target=%s\n' "$(readlink "$PWD")"
    printf 'parent=%s\n' "$(dirname "$PWD")"
    printf 'args=%s\n' "$*"
} >"$STUB_RECORD"
exit "${STUB_RC:-0}"
STUB
chmod +x "$stubdir/gosec"

# run_wrapper <stub rc> [VAR=value ...] — sets RC and STDERR; the record file is
# $stubdir/record (absent when the stub never ran).
run_wrapper() {
    local stub_rc="$1" err
    shift
    rm -f "$stubdir/record"
    err="$(mktemp)"
    env "PATH=$stubdir:$PATH" "STUB_RC=$stub_rc" "STUB_RECORD=$stubdir/record" "$@" \
        bash "$WRAPPER" -fmt text ./... >/dev/null 2>"$err"
    RC=$?
    STDERR="$(cat "$err")"
    rm -f "$err"
}

rec() { sed -n "s/^$1=//p" "$stubdir/record"; }

for want_rc in 0 1; do
    run_wrapper "$want_rc"
    if [ "$RC" -eq "$want_rc" ]; then
        pass "wrapper returns the stub gosec exit code $want_rc"
    else
        fail "wrapper should return $want_rc (rc=$RC, stderr: $STDERR)"
    fi
    if [ ! -f "$stubdir/record" ]; then
        fail "stub gosec was not invoked for exit code $want_rc"
        continue
    fi
    parent="$(rec parent)"
    if [ "$(rec target)" = "$REPO_ROOT" ]; then
        pass "gosec runs in a link whose target is the repository root"
    else
        fail "link target should be $REPO_ROOT (got: $(rec target))"
    fi
    case "$(rec pwd)" in
        "$parent"/s) pass "gosec sees the logical short path $(rec pwd) ($(printf '%s' "$(rec pwd)" | wc -c) characters)" ;;
        *) fail "logical PWD should be <parent>/s (pwd=$(rec pwd), parent=$parent)" ;;
    esac
    case "$parent" in
        /tmp/g??????) pass "private scan directory is /tmp/gXXXXXX" ;;
        *) fail "scan directory should match /tmp/gXXXXXX (got: $parent)" ;;
    esac
    if [ -n "$parent" ] && [ ! -e "$parent" ]; then
        pass "private scan directory is removed after the run (exit $want_rc)"
    else
        fail "private scan directory $parent still exists after the run"
        rm -f "$parent/s"
        rmdir "$parent" 2>/dev/null
    fi
done

# Two runs get distinct private directories.
run_wrapper 0
first_parent="$(rec parent)"
run_wrapper 0
if [ -n "$first_parent" ] && [ "$first_parent" != "$(rec parent)" ]; then
    pass "each run uses its own scan directory"
else
    fail "two runs reused the scan directory $first_parent"
fi

# A failing guard stops the run before gosec and exits 1.
run_wrapper 0 GOSEC_LOAD_THRESHOLD=1
if [ "$RC" -eq 1 ] && [ ! -f "$stubdir/record" ]; then
    pass "guard failure exits 1 and gosec is never invoked"
else
    fail "GOSEC_LOAD_THRESHOLD=1 should exit 1 without invoking gosec (rc=$RC, record exists: $([ -f "$stubdir/record" ] && echo yes || echo no))"
fi
leftover="$(find /tmp -maxdepth 1 -name 'g??????' -user "$(id -u)" -newer "$stubdir/gosec" 2>/dev/null | head -1)"
if [ -z "$leftover" ]; then
    pass "no scan directory is left behind after a guard failure"
else
    fail "scan directory left behind after a guard failure: $leftover"
fi

echo ""
echo "Passed: $PASS  Failed: $FAIL"
[ "$FAIL" -eq 0 ] || exit 1
echo "✅ check-gosec-load-length.sh tests passed"
