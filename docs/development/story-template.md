## Parent epic: #<EPIC_NUMBER>

## Goal

<One paragraph describing what should be observable / true when this story is done. Outcome, not task list.>

## Dependencies

<One of two forms:>

<Form 1 — no deps:>
None

<Form 2 — issue deps (siblings included — stories are created in dependency
order and each create-story call returns its real #NNN immediately, so sibling
references always use real numbers; placeholder tokens are retired):>
- #NNN — <reason> — must be merged into develop before this story starts
- #MMM — <reason> — <when external PR known: (PR: #PPP)>

<IMPORTANT: PO cron preflight rejects prose without #NNN. Only `None` / `none.` / `n/a` / empty are accepted as empty markers.>

<IMPORTANT: story bodies are world-readable at creation (ADR-015). No secrets, no customer/business specifics, no exploit-grade vulnerability detail — use create-story --defer for bodies that must stay private until dispatch.>

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

## Environment

<Optional. Omit for ordinary Linux-buildable work (the default). Set `windows`
(or `macos`) when the story needs that host's environment: (1) native OS behavior
a Linux container can't build/live-test, OR (2) full end-to-end deployment tests
and troubleshooting — the Windows host runs the Linux-controller + Linux/Windows-
minion matrix that a container can't. Routes the story off the Linux orchestrator
to a host serving that environment (see po.md §7).>

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
