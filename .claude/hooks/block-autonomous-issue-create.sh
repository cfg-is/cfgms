#!/usr/bin/env bash
# PreToolUse(Bash) gate — block autonomous (headless) agents from creating GitHub issues.
#
# Pipeline work originates from the private project board. Dev items become
# issues via `project-queue.sh materialize` (convert, NOT `gh issue create`) —
# at decomposition by default (ADR-015, via create-story), at dispatch for
# --defer drafts — so the materialize path never matches here. Community
# issues are human-directed and only created in interactive sessions.
#
# Fires only when CFGMS_AUTONOMOUS=true (set solely on headless dispatch launches).
# Interactive sessions (human present) are unaffected — a human may still direct
# issue creation. Exit 2 blocks the tool call and returns the reason to the agent.
set -euo pipefail

# Gate autonomous sessions only.
[[ "${CFGMS_AUTONOMOUS:-}" == "true" ]] || exit 0

cmd=$(python3 -c "import json,sys
try: print((json.load(sys.stdin).get('tool_input') or {}).get('command',''))
except Exception: print('')" 2>/dev/null || echo "")

# Any path that creates a public issue. `materialize-issue` converts a draft
# (no 'gh issue create' / no 'create-epic|create-community-issue'), so it passes.
if printf '%s' "$cmd" | grep -qE 'gh +issue +create|pipeline-helper\.sh +create-(epic|community-issue)'; then
  echo "BLOCKED: autonomous agents must not run raw issue creation." >&2
  echo "All pipeline work originates from the private project board; dev items become" >&2
  echo "locked, internal issues only via the CONVERT-based materialize path." >&2
  echo "Use: ./scripts/pipeline-helper.sh create-story <epic_num> <title> <body_file> [--defer]" >&2
  echo "(materializes a locked internal issue; --defer keeps it a private draft)." >&2
  echo "Community/epic issues are human-directed only." >&2
  exit 2
fi
exit 0
