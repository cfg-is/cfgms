## Summary

Bump `{{NAME}}` from `{{FROM}}` to `{{TO}}`.

## Why now

{{JUSTIFICATION}}

## Files In Scope ({{LOCATION_COUNT}} occurrences — lockstep required)

{{LOCATION_LIST}}

## Acceptance Criteria

1. Every location listed above is updated from `{{FROM}}` to `{{TO}}`. No file left at the old version.
2. **Verification — old version absent**: `python3 .claude/tooling/refresh-pins/verify_pin_clean.py --pattern "{{FROM_PATTERN}}" --scope "{{SCOPE_PATHS}}"` exits **0**. This classifies every grep hit as an executing reference (a live pin, an install command, a dependency declaration) or as prose (a comment, an echoed help string, changelog narrative) — see `SKILL.md` Phase 4 "Per-story mechanics" for the classification rules. A hit inside a comment or a printed message does not fail this check; a real pin left at the old version does.
3. **Verification — new version present**: `grep -rE "{{TO_PATTERN}}" {{SCOPE_PATHS}}` returns **{{LOCATION_COUNT}} matches**.
4. `make test-agent-complete` passes on the change (the dispatch harness validates the candidate with this target before it publishes the PR).
5. CI required checks all pass — all ten contexts required by the `develop` ruleset, not just `unit-tests`, `integration-tests`, `Build Gate` and `security-deployment-gate`. Verified by the acceptance reviewer from the PR's checks, against the full set read from the ruleset rather than a copy of it (the dev agent has no GitHub access and does not run this): `gh api repos/cfg-is/cfgms/rulesets/11647684 --jq '.rules[]|select(.type=="required_status_checks").parameters.required_status_checks[].context'`.
6. If this pin appears in any Docker image (FROM golang:..., FROM ...), the rebuilt image's Trivy scan reports the new version, not the old. The acceptance reviewer must verify by fetching the latest docker-security workflow run for this PR and grepping the Trivy SARIF for `"Installed Version"` lines.

## Cooldown decision

{{COOLDOWN_BLOCK}}

## Out of Scope

- Bumping unrelated pins in the same PR (one story per logical pin)
- Refactoring code that uses the bumped dependency (only the version string changes)
- Adding new tests for behavior that already has coverage

## Dependencies

None

## Implementation Notes

- This is a mechanical change. Edit every location in the list and run `make test-agent-complete` on it. The dispatch harness validates, commits, pushes and opens the PR; the dev agent does none of that.
- If the tests fail on the new version, that's a real regression — STOP, do not paper over it. Describe the failing test and its output in the agent's summary and leave the version change as it is. The run then fails validation and keeps its work as a draft PR; once two runs for the story have failed, the harness refuses the next run and sets the story Blocked for the founder. Do NOT add `t.Skip()` or otherwise mask the failure.
- For Docker `FROM` lines: the tag format is `<image>:<version>-<base>`. Preserve the `-alpine3.23` (or whatever) suffix exactly — only the version segment changes.
- For Go toolchain bumps specifically: `go.mod` uses `toolchain go1.X.Y` (no leading `v`); workflows use `GO_VERSION: '1.X.Y'` and `go-version: '1.X.Y'`; Dockerfiles use `FROM golang:1.X.Y-alpine...`. Same numeric value, three different surrounding syntaxes — all must move together.

## Required Tests

`make test-agent-complete` must pass. No new tests required for a version bump (unless it exposes a real regression that requires test updates).

## Notes

This story was created by the `refresh-pins` skill on {{DATE_UTC}}. See `.claude/skills/refresh-pins/SKILL.md` for the skill's flow and `.claude/skills/refresh-pins/references/cooldown-policy.md` for the cooldown policy this story applied.
