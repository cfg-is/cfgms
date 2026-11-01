#!/usr/bin/env bash
#
# Fixture test for scripts/install-git-hooks.sh (Issue #4150).
#
# A hook run from a LINKED worktree inherits GIT_DIR=<main>/.git/worktrees/<name>
# and GIT_INDEX_FILE. The pre-push hook runs `make test`; with those still set,
# a test that runs `git init` in a scratch directory re-initialises the MAIN
# repository and sets core.bare=true, and tests that stage files write into the
# worktree's index. This installs the real hooks into a throwaway repository,
# stubs `make` with exactly that `git init`, and pushes from a linked worktree
# and from the main checkout.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALLER="${SCRIPT_DIR}/install-git-hooks.sh"

TMP="$(mktemp -d)"
trap 'rm -rf "${TMP}"' EXIT

ran=0; fail=0
ok()  { ran=$((ran + 1)); printf '  ok    %s\n' "$1"; }
bad() { ran=$((ran + 1)); fail=$((fail + 1)); printf '  FAIL  %s\n        %s\n' "$1" "$2"; }

# Never let the environment this test runs in leak into the fixture repos.
# shellcheck disable=SC2046
unset $(git rev-parse --local-env-vars) 2>/dev/null || true

git init -q --bare "${TMP}/remote.git"
git init -q "${TMP}/main"
cd "${TMP}/main"
git config user.email hooks-test@example.invalid
git config user.name hooks-test
git config commit.gpgsign false
git commit -q --allow-empty -m init
git remote add origin "${TMP}/remote.git"
mkdir -p scripts
cp "${INSTALLER}" scripts/install-git-hooks.sh
bash scripts/install-git-hooks.sh >/dev/null
# Tracked, so the hook's uncommitted-changes prompt never fires on the fixture.
git add scripts/install-git-hooks.sh
git commit -q --no-verify -m installer

# `make` stub: record the git variables it inherited, then do what a test
# suite does — create a scratch repository with `git init`.
mkdir -p "${TMP}/bin"
cat > "${TMP}/bin/make" <<'STUB'
#!/usr/bin/env bash
env | grep '^GIT_' | grep -v '^GIT_EXEC_PATH=' | sort > "${HOOKS_TEST_OUT}/make-env.$$"
scratch="$(mktemp -d)"
( cd "${scratch}" && git init -q )
rm -rf "${scratch}"
touch "${HOOKS_TEST_OUT}/make-ran.$$"
exit 0
STUB
chmod +x "${TMP}/bin/make"
export HOOKS_TEST_OUT="${TMP}/out"
mkdir -p "${HOOKS_TEST_OUT}"

echo ""
echo "install-git-hooks_test.sh — pre-push from a linked worktree"
echo "------------------------------------------------------------"

git worktree add -q "${TMP}/linked" -b feature/story-0-hooks-probe
cd "${TMP}/linked"
git commit -q --allow-empty -m probe

rc=0
PATH="${TMP}/bin:${PATH}" git push -q origin feature/story-0-hooks-probe >"${TMP}/push-linked.log" 2>&1 || rc=$?
if [[ ${rc} -eq 0 ]]; then ok "push from a linked worktree succeeds"
else bad "push from a linked worktree succeeds" "exit ${rc}: $(tail -5 "${TMP}/push-linked.log")"; fi

if compgen -G "${HOOKS_TEST_OUT}/make-ran.*" >/dev/null; then ok "pre-push ran make test from the linked worktree"
else bad "pre-push ran make test from the linked worktree" "the make stub never ran"; fi

bare="$(git -C "${TMP}/main" config --get core.bare || true)"
if [[ "${bare}" != "true" ]]; then ok "the main repository is not flipped to core.bare=true"
else bad "the main repository is not flipped to core.bare=true" "core.bare=${bare}"; fi

leaked="$(cat "${HOOKS_TEST_OUT}"/make-env.* 2>/dev/null | grep -E '^GIT_(DIR|INDEX_FILE|WORK_TREE)=' || true)"
if [[ -z "${leaked}" ]]; then ok "make test sees no GIT_DIR / GIT_INDEX_FILE / GIT_WORK_TREE"
else bad "make test sees no GIT_DIR / GIT_INDEX_FILE / GIT_WORK_TREE" "${leaked}"; fi

dirty="$(git -C "${TMP}/linked" status --porcelain 2>&1 || true)"
if [[ -z "${dirty}" ]]; then ok "the linked worktree's index is untouched"
else bad "the linked worktree's index is untouched" "$(head -3 <<<"${dirty}")"; fi

# The main-checkout push path must still validate.
rm -f "${HOOKS_TEST_OUT}"/make-ran.*
cd "${TMP}/main"
git checkout -q -b feature/story-0-hooks-main
git commit -q --allow-empty -m probe-main
rc=0
PATH="${TMP}/bin:${PATH}" git push -q origin feature/story-0-hooks-main >"${TMP}/push-main.log" 2>&1 || rc=$?
if [[ ${rc} -eq 0 ]] && compgen -G "${HOOKS_TEST_OUT}/make-ran.*" >/dev/null; then
  ok "a push from the main checkout still runs make test"
else
  bad "a push from the main checkout still runs make test" "exit ${rc}: $(tail -5 "${TMP}/push-main.log")"
fi

echo "------------------------------------------------------------"
printf 'ran %d, failed %d\n' "${ran}" "${fail}"
[[ ${fail} -eq 0 ]]
