#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 Jordan Ritz
#
# npm-audit-gate.sh — `npm audit --audit-level=high` with a time-boxed,
# exact-ID exception list (web/npm-audit-exceptions.txt).
#
# The gate runs `npm audit --json` in the current directory (web/) and fails on
# every high or critical finding, exactly like `--audit-level=high`, except a
# finding whose every reachable advisory is an *active* exception. A dependent
# package's `via` entries that name another package (a string) are resolved
# transitively to advisory objects (cycle-safe); a single non-exempt advisory
# anywhere in the chain fails the gate.
#
# Exception file format (mirrors .nancy-ignore), one entry per line:
#   GHSA-xxxx-xxxx-xxxx package=<npm-package> until=YYYY-MM-DD   # comment
# The ID must be an exact GHSA literal (no wildcard or prefix). An entry is
# ACTIVE only while today (UTC) is strictly before `until=` AND no patched
# release of its package has been published, i.e. the newest version on the
# registry (`npm view <package> version`) is not newer than the newest version
# of that package resolved in package-lock.json. `fixAvailable` in npm's output
# is not used as a signal: it can propose a semver-major downgrade.
# The 15-day maximum per entry is a review convention, not enforced here.
#
# Fails closed: empty audit output, JSON without `.vulnerabilities`, an
# unreachable `npm view`, a package missing from the lockfile or a malformed
# exception entry all exit non-zero.
#
# Test seams (used by scripts/npm-audit-gate_test.sh):
#   NPM_AUDIT_GATE_NPM                 npm executable (default: npm)
#   NPM_AUDIT_GATE_TODAY               YYYY-MM-DD overriding today's UTC date
#   NPM_AUDIT_GATE_LATEST_<PKG>        newest published version of <PKG>
#                                      (upper-cased, non-alphanumerics -> _),
#                                      e.g. NPM_AUDIT_GATE_LATEST_PICOMATCH
#   NPM_AUDIT_GATE_EXCEPTIONS          exception file path
#   NPM_AUDIT_GATE_LOCKFILE            package-lock.json path
#
# Run: bash scripts/npm-audit-gate.sh   (from web/, or via `npm run audit`)
# Exit codes: 0 = no unexempted high/critical advisory; 1 = gate failure

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EXCEPTIONS_FILE="${NPM_AUDIT_GATE_EXCEPTIONS:-$SCRIPT_DIR/../web/npm-audit-exceptions.txt}"
LOCKFILE="${NPM_AUDIT_GATE_LOCKFILE:-package-lock.json}"
NPM_BIN="${NPM_AUDIT_GATE_NPM:-npm}"

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

fail() {
    echo -e "${RED}❌ npm-audit-gate: $1${NC}" >&2
    exit 1
}

command -v jq >/dev/null 2>&1 || fail "jq is required but not installed"

# is_real_date YYYY-MM-DD — format and calendar validity (GNU or BSD date).
is_real_date() {
    local d="$1"
    [[ "$d" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]] || return 1
    local round
    round="$(date -u -d "$d" +%F 2>/dev/null || date -u -j -f '%Y-%m-%d' "$d" +%F 2>/dev/null)" || return 1
    [ "$round" = "$d" ]
}

TODAY="${NPM_AUDIT_GATE_TODAY:-$(date -u +%F)}"
is_real_date "$TODAY" || fail "today's date '$TODAY' is not a valid YYYY-MM-DD date"

# newest_version v1 v2 ... — highest by version sort.
newest_version() {
    printf '%s\n' "$@" | sort -V | tail -n 1
}

# ---------------------------------------------------------------------------
# Parse and validate the exception file.
# ---------------------------------------------------------------------------
[ -f "$EXCEPTIONS_FILE" ] || fail "exception file not found: $EXCEPTIONS_FILE"

declare -A EXC_PKG=() EXC_UNTIL=()
set -f # entries are tokenised unquoted below; never glob-expand a wildcard id
line_num=0
while IFS= read -r raw_line || [ -n "$raw_line" ]; do
    line_num=$((line_num + 1))
    entry="${raw_line%%#*}"
    # shellcheck disable=SC2086 # intentional word splitting to tokenise
    set -- $entry
    [ $# -eq 0 ] && continue

    where="$EXCEPTIONS_FILE:$line_num"
    id="$1"
    shift
    [[ "$id" =~ ^GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}$ ]] ||
        fail "$where: '$id' is not an exact GHSA-xxxx-xxxx-xxxx id (no wildcard or prefix)"

    pkg="" until_val=""
    for tok in "$@"; do
        case "$tok" in
        package=*) pkg="${tok#package=}" ;;
        until=*) until_val="${tok#until=}" ;;
        *) fail "$where: unexpected token '$tok' (want: $id package=<name> until=YYYY-MM-DD)" ;;
        esac
    done
    [ -n "$pkg" ] || fail "$where: $id is missing package="
    [[ "$pkg" =~ ^(@[a-z0-9._-]+/)?[a-z0-9._-]+$ ]] || fail "$where: invalid package name '$pkg'"
    [ -n "$until_val" ] || fail "$where: $id is missing until=YYYY-MM-DD"
    is_real_date "$until_val" || fail "$where: until='$until_val' is not a valid YYYY-MM-DD date"
    [ -z "${EXC_UNTIL[$id]+x}" ] || fail "$where: duplicate entry for $id"

    EXC_PKG[$id]="$pkg"
    EXC_UNTIL[$id]="$until_val"
done <"$EXCEPTIONS_FILE"
set +f

# ---------------------------------------------------------------------------
# Decide, per entry, whether it is still active (expiry, then patched release).
# STATE[id] is one of: active | expired | patched
# ---------------------------------------------------------------------------
latest_published() {
    local pkg="$1" var out
    var="NPM_AUDIT_GATE_LATEST_$(echo "$pkg" | tr '[:lower:]' '[:upper:]' | sed 's/[^A-Z0-9]/_/g')"
    if [ -n "${!var:-}" ]; then
        echo "${!var}"
        return 0
    fi
    out="$("$NPM_BIN" view "$pkg" version 2>/dev/null)" || return 1
    out="$(echo "$out" | tail -n 1 | tr -d '[:space:]')"
    [ -n "$out" ] || return 1
    echo "$out"
}

locked_newest() {
    local pkg="$1" versions
    [ -f "$LOCKFILE" ] || return 1
    versions="$(jq -r --arg p "$pkg" '
        (.packages // {}) | to_entries[]
        | select(.key | test("(^|/)" + ($p | gsub("[.]"; "\\.")) + "$"))
        | .value.version // empty' "$LOCKFILE" 2>/dev/null)" || return 1
    [ -n "$versions" ] || return 1
    # shellcheck disable=SC2086
    newest_version $versions
}

declare -A STATE=()
state_json="{}"
for id in "${!EXC_UNTIL[@]}"; do
    pkg="${EXC_PKG[$id]}"
    if ! [[ "$TODAY" < "${EXC_UNTIL[$id]}" ]]; then
        STATE[$id]="expired"
    else
        locked="$(locked_newest "$pkg")" || fail "$id: no resolved '$pkg' version in $LOCKFILE — cannot check for a patched release"
        latest="$(latest_published "$pkg")" || fail "$id: cannot determine the newest published '$pkg' version (npm view failed) — failing closed"
        if [ "$latest" != "$locked" ] && [ "$(newest_version "$latest" "$locked")" = "$latest" ]; then
            STATE[$id]="patched"
            echo "ℹ️  $id: $pkg $latest is published but $locked is locked — exception no longer applies" >&2
        else
            STATE[$id]="active"
        fi
    fi
    state_json="$(jq -c --arg id "$id" --arg pkg "$pkg" --arg st "${STATE[$id]}" --arg until "${EXC_UNTIL[$id]}" \
        '. + {($id): {package: $pkg, state: $st, until: $until}}' <<<"$state_json")"
done

# ---------------------------------------------------------------------------
# Run the audit. npm exits non-zero whenever it finds vulnerabilities, so the
# exit status is ignored; the JSON is validated instead (fail closed).
# ---------------------------------------------------------------------------
audit_json="$("$NPM_BIN" audit --json 2>/dev/null || true)"
[ -n "$audit_json" ] || fail "npm audit produced no output (network or registry error?) — failing closed"
jq -e '(.vulnerabilities | type) == "object"' <<<"$audit_json" >/dev/null 2>&1 ||
    fail "npm audit output is not JSON with a .vulnerabilities object — failing closed"

# Every high/critical vulnerability must trace only to active exceptions.
# Prints one line per offending (package, advisory) pair.
failures="$(jq -r --argjson exc "$state_json" '
    .vulnerabilities as $v
    # Advisory objects reachable from package $name, following string `via`
    # entries; $seen guards against cycles. A string naming a package that is
    # absent from the report is unresolvable and yields a marker (fails closed).
    | def advs($name; $seen):
        if ($seen | index($name)) then []
        elif ($v[$name] == null) then [{unresolved: $name}]
        else [ $v[$name].via[]?
               | if type == "string" then advs(.; $seen + [$name])[] else . end ]
        end;
      def advid:
        if has("unresolved") then "unresolved:" + .unresolved
        else ((.url // "") | capture("(?<id>GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4})$").id? // ("non-ghsa:" + ((.url // .title // "unknown") | tostring)))
        end;
      def verdict:
        advid as $id
        | if has("unresolved") then "unresolvable dependency chain"
          elif ($exc[$id] == null) then "not exempt"
          elif ($exc[$id].package != (.name // "")) then "not exempt (advisory package \(.name // "?") does not match exception package \($exc[$id].package))"
          elif ($exc[$id].state == "expired") then "exception expired (until=\($exc[$id].until))"
          elif ($exc[$id].state == "patched") then "patched release published"
          else "ok" end;
      $v | to_entries[]
      | select(.value.severity == "high" or .value.severity == "critical")
      | .key as $pkg | .value.severity as $sev
      | (advs($pkg; []) | unique_by(advid)) as $list
      | if ($list | length) == 0 then "\($pkg) (\($sev)): no advisory found in via chain — not exempt"
        else $list[] | (verdict) as $r | select($r != "ok") | "\($pkg) (\($sev)): \(advid) — \($r)"
        end
' <<<"$audit_json")" || fail "could not evaluate npm audit output — failing closed"

if [ -n "$failures" ]; then
    echo -e "${RED}❌ npm-audit-gate: high/critical advisories are not covered by an active exception:${NC}" >&2
    echo "$failures" | sed 's/^/   /' >&2
    exit 1
fi

high_total="$(jq '[.vulnerabilities[] | select(.severity == "high" or .severity == "critical")] | length' <<<"$audit_json")"
echo -e "${GREEN}✅ npm-audit-gate: no unexempted high/critical advisories ($high_total high/critical package(s) covered by active exceptions, today=$TODAY)${NC}"
exit 0
