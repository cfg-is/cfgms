#!/usr/bin/env bash
# Regression test for per-segment model routing (Issue #3030).
#
# Model selection used to be hardcoded in three places (entrypoint.sh,
# review-entrypoint.sh, agent frontmatter) and could not be changed without a
# code edit. This covers the config-driven resolver: .claude/model-routing.yaml
# defaults + per-segment overrides, a hardcoded fallback on missing/malformed
# config, and CFGMS_MODEL_OVERRIDE taking precedence over the file. Also
# asserts the entrypoints and agent-dispatch.sh are actually wired to it.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
AGENT_CONTEXT="${REPO_ROOT}/.devcontainer/agent-context.sh"
ENTRYPOINT="${REPO_ROOT}/.devcontainer/entrypoint.sh"
REVIEW_ENTRYPOINT="${REPO_ROOT}/.devcontainer/scripts/review-entrypoint.sh"
DISPATCH="${REPO_ROOT}/.claude/scripts/agent-dispatch.sh"
ROUTING_FILE="${REPO_ROOT}/.claude/model-routing.yaml"

for f in "$AGENT_CONTEXT" "$ENTRYPOINT" "$REVIEW_ENTRYPOINT" "$DISPATCH" "$ROUTING_FILE"; do
  [[ -f "$f" ]] || { printf 'FAIL: expected file not found: %s\n' "$f" >&2; exit 1; }
done

fail=0; ran=0
ok()   { ran=$((ran + 1)); printf '  ok    %s\n' "$1"; }
bad()  { ran=$((ran + 1)); fail=$((fail + 1)); printf '  FAIL  %s\n        %s\n' "$1" "${2:-}"; }
check_eq() {
  local desc="$1" actual="$2" expected="$3"
  if [[ "$actual" == "$expected" ]]; then ok "$desc"
  else bad "$desc" "want: ${expected}  actual: ${actual}"; fi
}
check_contains() {
  local desc="$1" hay="$2" needle="$3"
  if [[ "$hay" == *"$needle"* ]]; then ok "$desc"
  else bad "$desc" "want substring: ${needle}"; fi
}
check_not_contains() {
  local desc="$1" hay="$2" needle="$3"
  if [[ "$hay" != *"$needle"* ]]; then ok "$desc"
  else bad "$desc" "want NO substring: ${needle}"; fi
}

echo "model_routing.test.sh"
echo "----------------------"

printf '\n== .claude/model-routing.yaml ==\n'
routing_src="$(cat "$ROUTING_FILE")"
check_contains "declares defaults model" "$routing_src" "model: claude-sonnet-4-6"
check_contains "declares defaults effort" "$routing_src" "effort: high"
for seg in dev-agent fix-agent pr-review acceptance-review; do
  check_contains "declares segment ${seg}" "$routing_src" "${seg}:"
done

printf '\n== ac_resolve_agent_model resolver ==\n'
# shellcheck source=/dev/null
source "$AGENT_CONTEXT"

SANDBOX="$(mktemp -d)"
trap 'rm -rf "$SANDBOX"' EXIT

cat > "${SANDBOX}/routing.yaml" <<'YAML'
defaults:
  model: claude-sonnet-4-6
  effort: high
segments:
  dev-agent:        { model: claude-sonnet-4-6 }
  fix-agent:        { model: claude-sonnet-4-6 }
  pr-review:        { model: claude-sonnet-4-6 }
  acceptance-review: { model: claude-sonnet-4-6 }
YAML

unset CFGMS_MODEL_OVERRIDE
resolved="$(CFGMS_MODEL_ROUTING_FILE="${SANDBOX}/routing.yaml" ac_resolve_agent_model "dev-agent")"
mapfile -t lines <<< "$resolved"
check_eq "known segment resolves configured model" "${lines[0]:-}" "claude-sonnet-4-6"
check_eq "known segment resolves configured effort" "${lines[1]:-}" "high"

# Segment override wins over defaults.
cat > "${SANDBOX}/override.yaml" <<'YAML'
defaults:
  model: claude-sonnet-4-6
  effort: high
segments:
  fix-agent:        { model: claude-opus-4-7 }
YAML
resolved="$(CFGMS_MODEL_ROUTING_FILE="${SANDBOX}/override.yaml" ac_resolve_agent_model "fix-agent")"
mapfile -t lines <<< "$resolved"
check_eq "segment-level model overrides defaults" "${lines[0]:-}" "claude-opus-4-7"

# Unknown segment falls back to file defaults, not the hardcoded fallback.
cat > "${SANDBOX}/unknown_seg.yaml" <<'YAML'
defaults:
  model: claude-sonnet-9-9
  effort: medium
segments:
  dev-agent:        { model: claude-sonnet-4-6 }
YAML
resolved="$(CFGMS_MODEL_ROUTING_FILE="${SANDBOX}/unknown_seg.yaml" ac_resolve_agent_model "never-defined-segment")"
mapfile -t lines <<< "$resolved"
check_eq "unknown segment falls back to file defaults (model)" "${lines[0]:-}" "claude-sonnet-9-9"
check_eq "unknown segment falls back to file defaults (effort)" "${lines[1]:-}" "medium"

# Missing config file: hardcoded fallback, current production values.
resolved="$(CFGMS_MODEL_ROUTING_FILE="${SANDBOX}/does-not-exist.yaml" ac_resolve_agent_model "dev-agent")"
mapfile -t lines <<< "$resolved"
check_eq "missing file falls back to hardcoded model" "${lines[0]:-}" "claude-sonnet-4-6"
check_eq "missing file falls back to hardcoded effort" "${lines[1]:-}" "high"

# Malformed config file: same hardcoded fallback, never a crash.
printf 'not: [valid, yaml, {{{\n***\n' > "${SANDBOX}/malformed.yaml"
set +e
resolved="$(CFGMS_MODEL_ROUTING_FILE="${SANDBOX}/malformed.yaml" ac_resolve_agent_model "dev-agent" 2>/dev/null)"
rc=$?
set -e
check_eq "malformed file does not abort resolution" "$rc" "0"
mapfile -t lines <<< "$resolved"
check_eq "malformed file falls back to hardcoded model" "${lines[0]:-}" "claude-sonnet-4-6"
check_eq "malformed file falls back to hardcoded effort" "${lines[1]:-}" "high"

# CFGMS_MODEL_OVERRIDE takes precedence over the file, even with a valid config.
resolved="$(CFGMS_MODEL_ROUTING_FILE="${SANDBOX}/routing.yaml" CFGMS_MODEL_OVERRIDE="claude-opus-override" ac_resolve_agent_model "dev-agent")"
mapfile -t lines <<< "$resolved"
check_eq "CFGMS_MODEL_OVERRIDE wins over configured model" "${lines[0]:-}" "claude-opus-override"
check_eq "CFGMS_MODEL_OVERRIDE does not affect effort" "${lines[1]:-}" "high"
unset CFGMS_MODEL_OVERRIDE

# CFGMS_MODEL_OVERRIDE also wins with a missing/malformed file (never blocked
# by config state).
resolved="$(CFGMS_MODEL_ROUTING_FILE="${SANDBOX}/does-not-exist.yaml" CFGMS_MODEL_OVERRIDE="claude-opus-override" ac_resolve_agent_model "dev-agent")"
mapfile -t lines <<< "$resolved"
check_eq "CFGMS_MODEL_OVERRIDE wins with missing file" "${lines[0]:-}" "claude-opus-override"
unset CFGMS_MODEL_OVERRIDE

printf '\n== entrypoint.sh wiring ==\n'
entrypoint_src="$(cat "$ENTRYPOINT")"
check_not_contains "no longer unconditionally hardcodes AGENT_MODEL" "$entrypoint_src" 'AGENT_MODEL="claude-sonnet-4-6"'
check_contains "resolves model via ac_resolve_agent_model" "$entrypoint_src" "ac_resolve_agent_model"
check_contains "routes fix-pr to the fix-agent segment" "$entrypoint_src" "fix-agent"
check_contains "routes dev issue/branch to the dev-agent segment" "$entrypoint_src" "dev-agent"
check_contains "result manifest records resolved model" "$entrypoint_src" '"model": "${AGENT_MODEL}"'
check_contains "result manifest records resolved effort" "$entrypoint_src" '"effort": "${AGENT_EFFORT}"'
if bash -n "$ENTRYPOINT" 2>/dev/null; then ok "entrypoint.sh parses"; else bad "entrypoint.sh parses" "bash -n failed"; fi

printf '\n== review-entrypoint.sh wiring ==\n'
review_src="$(cat "$REVIEW_ENTRYPOINT")"
check_contains "sources agent-context.sh" "$review_src" "agent-context.sh"
check_contains "resolves model via ac_resolve_agent_model" "$review_src" "ac_resolve_agent_model"
check_contains "routes to the acceptance-review segment" "$review_src" "acceptance-review"
check_not_contains "no longer hardcodes claude-sonnet-4-6 in the claude invocation" "$review_src" '--model claude-sonnet-4-6 -p'
check_contains "result manifest records resolved model" "$review_src" '"model": "${AGENT_MODEL}"'
check_contains "result manifest records resolved effort" "$review_src" '"effort": "${AGENT_EFFORT}"'
if bash -n "$REVIEW_ENTRYPOINT" 2>/dev/null; then ok "review-entrypoint.sh parses"; else bad "review-entrypoint.sh parses" "bash -n failed"; fi

printf '\n== agent-dispatch.sh forwards CFGMS_MODEL_OVERRIDE ==\n'
dispatch_src="$(cat "$DISPATCH")"
mapfile -t missing_override < <(awk '
  /docker run -d/                 { in_block = 1; block = ""; start = NR }
  in_block                        { block = block $0 "\n" }
  in_block && /cfg-agent:latest/  {
    in_block = 0
    if (block ~ /--entrypoint \/bin\/bash/) next
    if (block !~ /CFGMS_MODEL_OVERRIDE/) print start
  }
' "$DISPATCH")
if [[ "${#missing_override[@]}" -eq 0 ]]; then
  ok "every accounting dispatch path forwards CFGMS_MODEL_OVERRIDE"
else
  bad "every accounting dispatch path forwards CFGMS_MODEL_OVERRIDE" \
      "docker run at line(s) ${missing_override[*]} does not forward it"
fi

printf '\n%s\n' "-----------------------------------------"
if [[ "$fail" -eq 0 ]]; then
  printf 'PASS: %d checks\n' "$ran"; exit 0
else
  printf 'FAIL: %d of %d checks failed\n' "$fail" "$ran"; exit 1
fi
