#!/usr/bin/env bash
# Tests for agent-dispatch.sh's credential mirror (T6).
#
# There is no existing test file for agent-dispatch.sh -- this is the first
# one, and it covers only the mirror.
#
# WHAT IS BEING PROTECTED. Containers used to bind-mount the host's live
# ~/.claude/.credentials.json as a FILE. The host rotates its token by writing
# a replacement and renaming it into place, and a file bind mount pins the
# ORIGINAL inode -- so a running container never saw the replacement and kept
# presenting a credential that had been revoked. Measured on one sweep:
# container up 17:45:43, host rewrote the credential 18:13:39, next request
# rejected 18:14:15 with "OAuth access token has been revoked".
#
# Four of the six mount sites were additionally read-WRITE, which let a
# container write the host's live credential.
#
# HERMETIC, and deliberately so. Nothing here runs docker, and nothing here
# reads or writes the real ~/.claude. Both the source and the mirror are
# redirected at temp directories via CFGMS_HOST_CREDS_FILE and
# CFGMS_CREDS_MIRROR_DIR. A test that touched the live credential could
# revoke the token this very session is authenticated with.
#
# NO SUBSHELLS AROUND TEST BLOCKS. An earlier draft of this file wrapped each
# block in `( ... ) || true`; a subshell gets its own copy of the counters, so
# the suite printed two failing assertions and then `Summary: 0/0 passed` and
# exited 0. A test file that cannot fail is worse than no test file, because
# it occupies the place where a real one would go.
#
# WHAT THIS CANNOT TEST, stated rather than implied: none of these observes a
# real OAuth rotation against a live container. Whether a RUNNING Claude Code
# re-reads the credential file at all, or only reads it at process start, is
# unresolved -- it cannot be settled from the minified CLI bundle, and the
# decisive test needs a real rotation, which must not be forced because
# forcing one revokes the host session's own token. If the CLI only reads at
# start, the mirror reduces the FREQUENCY of an in-flight auth failure rather
# than eliminating it. That residual risk is a documented caveat here, not a
# fabricated assertion.
#
# Follows the hermetic pattern of investigator-entrypoint_test.sh.
#
# Run: bash .devcontainer/agent-dispatch-credential-mirror_test.sh
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DISPATCH="$(cd "$SCRIPT_DIR/.." && pwd)/.claude/scripts/agent-dispatch.sh"

[[ -f "$DISPATCH" ]] || { echo "FAIL: expected file not found: $DISPATCH" >&2; exit 1; }

TESTS_RUN=0
TESTS_PASSED=0
FAILURES=()

_fail() {
    TESTS_RUN=$((TESTS_RUN + 1))
    FAILURES+=("$1")
    echo "    x $1" >&2
}
_pass() {
    TESTS_RUN=$((TESTS_RUN + 1))
    TESTS_PASSED=$((TESTS_PASSED + 1))
    echo "    ok $1"
}
assert_eq() {
    local actual="$1" expected="$2" msg="$3"
    if [[ "$actual" == "$expected" ]]; then _pass "$msg"
    else _fail "$msg -- want $(printf '%q' "$expected"), got $(printf '%q' "$actual")"; fi
}
assert_ne() {
    local a="$1" b="$2" msg="$3"
    if [[ "$a" != "$b" ]]; then _pass "$msg"
    else _fail "$msg -- expected values to differ, both were $(printf '%q' "$a")"; fi
}
assert_contains() {
    local haystack="$1" needle="$2" msg="$3"
    if [[ "$haystack" == *"$needle"* ]]; then _pass "$msg"
    else _fail "$msg -- expected to find $(printf '%q' "$needle")"; fi
}
assert_not_contains() {
    local haystack="$1" needle="$2" msg="$3"
    if [[ "$haystack" != *"$needle"* ]]; then _pass "$msg"
    else _fail "$msg -- did not expect to find $(printf '%q' "$needle")"; fi
}

WORK=""
setup_fixture() {
    teardown_fixture
    WORK="$(mktemp -d)"
    mkdir -p "${WORK}/host"
    printf '%s\n' '{"claudeAiOauth":{"accessToken":"TOKEN-ORIGINAL","expiresAt":9999999999000}}' \
        > "${WORK}/host/.credentials.json"
    export CFGMS_HOST_CREDS_FILE="${WORK}/host/.credentials.json"
    export CFGMS_CREDS_MIRROR_DIR="${WORK}/mirror"
    CREDS_MIRROR_DIR="${WORK}/mirror"
    CREDS_MIRROR_FILE="${CREDS_MIRROR_DIR}/.credentials.json"
    CREDS_MIRROR_HEARTBEAT="${CREDS_MIRROR_DIR}/.watcher-heartbeat"
}
teardown_fixture() {
    if [[ -n "${CREDS_MIRROR_WATCHER_PID:-}" ]]; then stop_creds_mirror_watcher || true; fi
    [[ -n "$WORK" ]] && rm -rf "$WORK"
    WORK=""
}
trap 'teardown_fixture' EXIT

# Source the FUNCTIONS only. agent-dispatch.sh guards its command dispatch
# with `[[ "${BASH_SOURCE[0]}" == "${0}" ]]`, so sourcing runs no arm -- this
# drives the real functions, not a copy of them.
# shellcheck disable=SC1090
source "$DISPATCH"

# agent-dispatch.sh sets `-e` at its top, and sourcing applies that to THIS
# shell. Several assertions below deliberately capture a non-zero command --
# the whole point of `test_dead_watcher_blocks_launch` is that the gate exits
# 10 -- so `-e` would abort the suite at the first refusal it is testing for
# and report a pass count for the assertions it never reached. Turn it back
# off explicitly, after sourcing, where the import happens.
set +e

echo "=== agent-dispatch.sh: credential mirror (T6) ==="

# ---------------------------------------------------------------------------
echo ""
echo "test_mirror_readonly_oneway"
# ---------------------------------------------------------------------------
setup_fixture
refresh_creds_mirror

# Read from the SOURCE rather than from a variable this test set itself: the
# claim is about what the script mounts, not about what a fixture can be
# persuaded to say.
mounts=$(grep -E '^\s*-v .*credentials\.json' "$DISPATCH" || true)
assert_not_contains "$mounts" '${HOME}/.claude/.credentials.json' \
    "no container mounts the host's LIVE credential file any more"

mirror_mounts=$(grep -c 'CREDS_MIRROR_FILE}:${CREDS_MIRROR_MOUNT}:ro' "$DISPATCH" || true)
assert_eq "$mirror_mounts" "6" "all six credential mount sites use the mirror, read-only"

rw=$(grep -E 'CREDS_MIRROR_FILE\}:\$\{CREDS_MIRROR_MOUNT\}"' "$DISPATCH" || true)
assert_eq "$rw" "" "no mirror mount is read-write"

guards=$(grep -c '^\s*ensure_creds_mirror_for_mount$' "$DISPATCH" || true)
assert_eq "$guards" "6" \
    "every mount site is guarded, so an absent mirror cannot be mounted as a DIRECTORY"

dir_mode=$(stat -c '%a' "$CREDS_MIRROR_DIR")
file_mode=$(stat -c '%a' "$CREDS_MIRROR_FILE")
assert_eq "$dir_mode" "700" "mirror directory is 0700"
assert_eq "$file_mode" "600" "mirror file is 0600"

entries=$(cd "$CREDS_MIRROR_DIR" && ls -A | sort | tr '\n' ' ')
assert_eq "$entries" ".credentials.json " \
    "the mirror holds the credential and nothing else -- none of the host's transcripts, memory or profile"

assert_contains "$(cat "$CREDS_MIRROR_FILE")" "TOKEN-ORIGINAL" \
    "the mirror carries the host's credential"

if assert_creds_mirror_uid 2>/dev/null; then
    _pass "host uid matches the container uid the mirror must be readable by"
else
    assert_ne "$(id -u)" "$CREDS_MIRROR_CONTAINER_UID" \
        "the uid assertion fires only when host and container uids genuinely differ"
fi

# ---------------------------------------------------------------------------
echo ""
echo "test_watcher_updates_on_inode_change"
# ---------------------------------------------------------------------------
setup_fixture
refresh_creds_mirror
mirror_inode_before=$(stat -c '%i' "$CREDS_MIRROR_FILE")
host_inode_before=$(stat -c '%i' "$CFGMS_HOST_CREDS_FILE")

# Rotate exactly as the host really does: write a replacement and RENAME it
# over the original. That is what produces a new inode, and it is the step
# that used to leave a running container pinned to the old one.
printf '%s\n' '{"claudeAiOauth":{"accessToken":"TOKEN-ROTATED","expiresAt":9999999999000}}' \
    > "${WORK}/host/.credentials.json.new"
mv "${WORK}/host/.credentials.json.new" "$CFGMS_HOST_CREDS_FILE"

host_inode_after=$(stat -c '%i' "$CFGMS_HOST_CREDS_FILE")
assert_ne "$host_inode_before" "$host_inode_after" \
    "precondition: a host rename really does change the inode"

refresh_creds_mirror
mirror_inode_after=$(stat -c '%i' "$CREDS_MIRROR_FILE")

assert_contains "$(cat "$CREDS_MIRROR_FILE")" "TOKEN-ROTATED" \
    "the rotated credential reaches the mirror"
# The whole fix in one assertion. A container's file mount pins the mirror's
# inode, so the mirror must be rewritten IN PLACE. Were this to change the
# inode, the mirror would faithfully reproduce the very bug it exists to fix
# -- and the content assertion above would still pass.
assert_eq "$mirror_inode_before" "$mirror_inode_after" \
    "the mirror keeps its inode across a rotation, so a running container's mount still resolves to it"

# Detection leads with the inode, not mtime: a same-second replacement can
# share an mtime and must still be detected.
id_before=$(creds_file_identity "$CFGMS_HOST_CREDS_FILE")
printf '%s\n' '{"claudeAiOauth":{"accessToken":"TOKEN-THIRD","expiresAt":9999999999000}}' \
    > "${WORK}/host/.credentials.json.new2"
touch -r "$CFGMS_HOST_CREDS_FILE" "${WORK}/host/.credentials.json.new2"
mv "${WORK}/host/.credentials.json.new2" "$CFGMS_HOST_CREDS_FILE"
id_after=$(creds_file_identity "$CFGMS_HOST_CREDS_FILE")
assert_ne "$id_before" "$id_after" \
    "a replacement carrying the SAME mtime is still detected, because identity leads with the inode"

refresh_creds_mirror
assert_contains "$(cat "$CREDS_MIRROR_FILE")" "TOKEN-THIRD" \
    "the same-mtime replacement also reaches the mirror"

# ---------------------------------------------------------------------------
echo ""
echo "test_dead_watcher_blocks_launch"
# ---------------------------------------------------------------------------
setup_fixture
refresh_creds_mirror

# A plain refresh must NOT write the heartbeat. If it did, the launch gate
# would refresh the heartbeat immediately before testing it and the staleness
# check could never fire -- dead code that reads as a safety net.
assert_eq "$(creds_mirror_age_seconds)" "never" \
    "a content refresh does not write the heartbeat: only a watcher proves a watcher is alive"

creds_mirror_heartbeat
if creds_mirror_is_fresh; then _pass "a just-beaten heartbeat is fresh"
else _fail "a just-beaten heartbeat should be fresh"; fi

# Age it past the threshold: the state that is otherwise indistinguishable
# from "no refresh happened", which is the original bug restored quietly.
touch -d "@$(( $(date +%s) - CREDS_MIRROR_MAX_AGE_SECONDS - 60 ))" "$CREDS_MIRROR_HEARTBEAT"
if creds_mirror_is_fresh; then _fail "a stale heartbeat should NOT read as fresh"
else _pass "a heartbeat older than the threshold reads as stale"; fi

# And the gate refuses the launch. CFGMS_TEST_CREDS_STATUS injects a healthy
# token, so the refusal can only come from mirror staleness -- otherwise this
# would pass for the wrong reason.
out=$(bash -c "
    export CFGMS_HOST_CREDS_FILE='$CFGMS_HOST_CREDS_FILE'
    export CFGMS_CREDS_MIRROR_DIR='$CREDS_MIRROR_DIR'
    export CFGMS_TEST_CREDS_STATUS='CREDS_OK:300'
    source '$DISPATCH'
    touch -d \"@\$(( \$(date +%s) - 10000 ))\" '$CREDS_MIRROR_HEARTBEAT'
    gate_credentials_for_launch
    echo GATE_ALLOWED
" 2>&1)
assert_contains "$out" "creds_mirror_stale" \
    "the launch gate refuses a stale mirror, naming staleness as the cause"
assert_not_contains "$out" "GATE_ALLOWED" \
    "the gate does not fall through to allow the launch"

# A first launch, with no watcher ever started, must NOT be refused -- it
# starts one instead. Collapsing this with the stale case would break every
# first dispatch.
out_first=$(bash -c "
    export CFGMS_HOST_CREDS_FILE='$CFGMS_HOST_CREDS_FILE'
    export CFGMS_CREDS_MIRROR_DIR='${WORK}/mirror-first'
    export CFGMS_TEST_CREDS_STATUS='CREDS_OK:300'
    source '$DISPATCH'
    gate_credentials_for_launch
    echo GATE_ALLOWED
" 2>&1)
assert_contains "$out_first" "GATE_ALLOWED" \
    "a first launch with no watcher yet starts one rather than being refused"

# A missing mirror must fail loudly: Docker creates an absent bind source as
# a DIRECTORY, which would mount a directory over the container's credential
# path and break auth for a reason that looks nothing like its cause.
out2=$(bash -c "
    export CFGMS_HOST_CREDS_FILE='${WORK}/host/does-not-exist.json'
    export CFGMS_CREDS_MIRROR_DIR='${WORK}/mirror-absent'
    source '$DISPATCH'
    ensure_creds_mirror_for_mount
    echo LAUNCH_PROCEEDED
" 2>&1)
assert_contains "$out2" "credential mirror unavailable" \
    "an absent host credential blocks the launch with a named reason"
assert_not_contains "$out2" "LAUNCH_PROCEEDED" \
    "the launch does not proceed to mount a source that does not exist"

teardown_fixture

echo ""
echo "=== Summary: $TESTS_PASSED/$TESTS_RUN passed ==="
if [[ ${#FAILURES[@]} -gt 0 ]]; then
    echo ""
    echo "FAILURES:"
    for f in "${FAILURES[@]}"; do echo "  - $f"; done
    exit 1
fi
exit 0
