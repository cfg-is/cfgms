#!/usr/bin/env bash
# load-security-review-credentials.sh — host-side OS-keychain lookup for the
# security-review harness's per-lane provider API keys (Issue #3903).
#
# Retrieval mechanism ONLY, lifted from scripts/load-credentials-from-keychain.sh
# -- deliberately not that script's shape. That script is designed to be
# `source`d, loads a cleartext .env.local, and `export`s secrets as
# environment variables (visible to every child process, and to `docker
# inspect` output when forwarded with `-e`). This script never sources an env
# file and never exports anything: it is a pure lookup. The caller
# (agent-dispatch.sh's launch-investigator) writes the result straight into a
# 0600 file inside a memory-backed credential directory instead of an env var
# — see docs/architecture/security-review-harness.md for the full boundary.
#
# Safe to `source` unconditionally: this file only defines functions when
# sourced. Direct execution (`./load-security-review-credentials.sh get
# <name>`) is the only path with side effects, and its only output is the
# secret itself on stdout — never logged, never echoed elsewhere.
set -u

SECURITY_REVIEW_KEYCHAIN_SERVICE="cfgms-security-review"

# security_review_get_credential <key_name>
# Prints the credential to stdout and returns 0, or prints nothing and
# returns 1 if it is not present in the OS keychain (or no keychain tool is
# available on this platform). Never logs the value anywhere.
security_review_get_credential() {
  local key_name="$1"
  case "$(uname -s)" in
    Linux)
      command -v secret-tool >/dev/null 2>&1 || return 1
      secret-tool lookup service "$SECURITY_REVIEW_KEYCHAIN_SERVICE" credential "$key_name" 2>/dev/null
      ;;
    Darwin)
      command -v security >/dev/null 2>&1 || return 1
      security find-generic-password -s "$SECURITY_REVIEW_KEYCHAIN_SERVICE" -a "$key_name" -w 2>/dev/null
      ;;
    *)
      return 1
      ;;
  esac
}

# Direct-execution CLI wrapper. Not used by launch-investigator (which sources
# this file and calls security_review_get_credential directly so the secret
# never crosses a process boundary as a CLI argument) — provided for manual
# credential provisioning/verification from the command line.
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  set -euo pipefail
  case "${1:-}" in
    get)
      [[ $# -eq 2 ]] || { echo "Usage: $0 get <key_name>" >&2; exit 1; }
      secret=$(security_review_get_credential "$2") || secret=""
      [[ -n "$secret" ]] || { echo "ERROR: no credential found in OS keychain for '${2}'" >&2; exit 1; }
      printf '%s' "$secret"
      ;;
    *)
      echo "Usage: $0 get <key_name>" >&2
      exit 1
      ;;
  esac
fi
