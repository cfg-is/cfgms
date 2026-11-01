# Documentation Standards

Write documentation only when it serves a named reader task, a tool contract or
required evidence. Length, age and a historical label do not establish value.
Use the [documentation currency contract](../product-planning.md#documentation-currency)
for retention and the [documentation boundary](../documentation-boundaries.md)
for product versus private-deployment information.

## Purpose and ownership

- Name the reader/task in the opening. Give each contract one authoritative owner.
- Link to that owner instead of copying rules across READMEs, agent prompts and
  runbooks. Keep essential local prerequisites visible where a reader acts.
- Create a directory README only when it provides useful navigation or required
  tool input. A folder does not automatically need a document.
- Separate implemented behavior, approved future direction and dated evidence.
  Do not present proposed config or APIs as runnable examples.
- Use Git history for superseded text. Update, consolidate or delete inaccurate
  material and repair references rather than adding an archive by default.

## Content appropriate to the task

- **API/package contracts:** document behavior, inputs, outputs, side effects and
  important failure cases. Exported Go comments follow GoDoc conventions. Add
  examples when they resolve a real usage ambiguity; do not duplicate source
  signatures or narrate every implementation step.
- **Operator procedures:** state prerequisites and provide commands/configuration
  matching the current parser and trust model. Include recovery/failure guidance
  where needed. Point to the canonical config instead of maintaining another
  complete copy.
- **Architecture decisions:** preserve relevant rationale and accepted constraints.
  Make status, amendments and decision-time context clear. Current operating
  behavior belongs in its runtime contract, not a parallel implementation diary.
- **Agent instructions:** keep task entry points short and explicitly load the
  relevant contract. Preserve frontmatter, required headings and parser consumers
  when shortening. A link is not proof the agent has loaded its contents.
- **Evidence:** retain unique measurements or finding-to-remediation records when
  they have a current purpose. Temporary progress, sprint and publication-approval
  memos normally belong outside canonical product documentation.

## Format and examples

Use descriptive headings, concise prose and lists/tables where they improve
navigation. Add a table of contents only when useful. Diagrams/screenshots need a
specific explanatory purpose and must stay accurate. Version footers, change
histories, repeated overview sections and generic tool recommendations are not
required; Git already records file revisions. Dates matter for observations,
measurements and decision records, not as decorative boilerplate.

Canonical documentation describes CFGMS directly, following the naming/example
rules in [CLAUDE.md](../../../CLAUDE.md#documentation).

## Review before acceptance

For each added/changed document, establish its purpose and owner, check affected
claims against source or agreed intent, and resolve overlapping instructions.
Check links/anchors and non-Markdown loaders, tests and scripts before moving or
removing a file. Run relevant documentation checks; execute examples or tests
when needed and report unverified procedures explicitly. A clean link scan is
not proof of factual accuracy or useful scope.

Use the [doc-review skill](../../../.claude/skills/doc-review/SKILL.md) during story
completion. For epic discovery and acceptance evidence, use
[Product Planning](../product-planning.md).
