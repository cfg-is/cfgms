#!/usr/bin/env bash
# check-cla-signed.sh <github-login>
# Exits 0 if the login appears in CONTRIBUTORS.md; exits 1 otherwise.
# Used as a CLA stopgap during human review of external-author PRs.
set -euo pipefail

login="${1:?Usage: check-cla-signed.sh <github-login>}"
repo_root="$(cd "$(dirname "$0")/.." && pwd)"
contributors="${repo_root}/CONTRIBUTORS.md"

if [[ ! -f "$contributors" ]]; then
  echo "ERROR: CONTRIBUTORS.md not found at ${contributors}" >&2
  exit 1
fi

if grep -qiF "@${login}" "$contributors" 2>/dev/null || \
   grep -qiF "github.com/${login}" "$contributors" 2>/dev/null || \
   grep -qiF "[${login}]" "$contributors" 2>/dev/null; then
  echo "CLA_SIGNED:${login}"
  exit 0
else
  echo "CLA_NOT_SIGNED:${login}"
  exit 1
fi
