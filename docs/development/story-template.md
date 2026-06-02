## Parent epic: #<EPIC_NUMBER>

## Goal

<One paragraph describing what should be observable / true when this story is done. Outcome, not task list.>

## Dependencies

<One of three forms:>

<Form 1 — no deps:>
None

<Form 2 — existing issue deps:>
- #NNN — <reason> — must be merged into develop before this story starts
- #MMM — <reason> — <when external PR known: (PR: #PPP)>

<Form 3 — sibling deps with placeholders for two-pass create:>
- #SIBLING-S1 — <reason> — must be merged into develop before this story starts
- #SIBLING-S2 — <reason> — must be merged before this story starts

<IMPORTANT: PO cron preflight rejects prose without #NNN. Only `None` / `none.` / `n/a` / empty are accepted as empty markers.>

## Out of Scope

- <Explicit list of nearby code/files/behaviors the dev agent must NOT touch>
- <Use "None" only if genuinely nothing adjacent is at risk>

## Files In Scope

- `path/to/file.go` — <what to do with this file>
- `path/to/file_test.go` — <what tests to add>

<IMPORTANT: PO cron preflight requires at least one file path (backticked or bare) in this section.>

## Docs In Scope

- `docs/path/to/doc.md` — <what to update>

<Use "None — no product-shape change" with justification only if the story genuinely doesn't change observable shape. See ba.md "Documentation & Tests Currency" rule.>

## Reference Implementation

- <Pointer to existing pattern in the codebase to follow, with file:line>
- <Relevant architecture doc>

## Implementation Notes

<Specific technical guidance for the dev agent:>
- Central providers to use
- Interfaces to implement
- Edge cases to handle
- Security considerations

## Acceptance Criteria

- [ ] <Specific, testable criterion>
- [ ] [REQUIRED TEST] <Test that MUST exist for the story to be accepted>
- [ ] <Another criterion>
- [ ] Tests added/updated for all behavior changes (unit + integration where applicable)
- [ ] Docs updated — enumerate or write "N/A — no product-shape change" with justification
- [ ] `make test-complete` passes

<Mark every AC requiring a specific test with [REQUIRED TEST]. Acceptance review treats these as hard gates.>
