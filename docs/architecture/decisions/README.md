# Architecture Decision Records (ADRs)

This directory contains Architecture Decision Records (ADRs) for CFGMS - important architectural decisions made during the project's evolution.

## What is an ADR?

An Architecture Decision Record captures a significant architectural decision, its context, the decision made, and its consequences. ADRs help teams understand:

- Why certain architectural choices were made
- What alternatives were considered
- What trade-offs were accepted
- What consequences (positive and negative) were anticipated

## ADR Format

Each ADR follows this structure:

```markdown
# ADR NNN: Title

**Status**: Proposed | Accepted | Deprecated | Superseded

**Date**: YYYY-MM-DD

**Deciders**: Team members involved

## Context
What is the issue we're facing? What factors are in play?

## Decision
What are we going to do about it?

## Consequences
What becomes easier or harder by making this decision?
```

## ADR Lifecycle

- **Proposed**: Under discussion, not yet approved
- **Accepted**: Approved and being/has been implemented
- **Deprecated**: No longer relevant but kept for historical context
- **Superseded**: Replaced by another ADR (link to replacement)

## Index of ADRs

### Active Decisions

| ADR | Title | Date | Status |
|-----|-------|------|--------|
| [001](001-central-provider-compliance-enforcement.md) | Central Provider Compliance Enforcement | 2025-10-20 | Accepted |
| [003](003-storage-data-taxonomy.md) | Storage Data Taxonomy | 2026-04-13 | Proposed |

### Superseded/Deprecated

*None yet*

## Creating a New ADR

1. **Choose the next number**: Look at the index above and use the next sequential number
2. **Copy the template**: Use an existing ADR as a template
3. **Fill in the sections**: Focus on context, decision, and consequences
4. **Set status to "Proposed"**: Start as proposed until team approves
5. **Update this index**: Add your ADR to the table above
6. **Submit PR**: Get team review before merging

## When to Create an ADR

Create an ADR when making decisions about:

- **System Architecture**: Major structural changes (e.g., adding central providers)
- **Technology Choices**: Selecting frameworks, databases, protocols
- **Patterns & Practices**: Establishing coding patterns or development workflows
- **Trade-offs**: When accepting significant trade-offs that affect the system
- **Enforcement Mechanisms**: Changes to how we enforce architectural rules

**Don't create ADRs for**:

- Minor implementation details
- Routine bug fixes
- Refactoring that doesn't change architecture
- Decisions that are easily reversible

## Best Practices

1. **Keep it concise**: 1-3 pages is ideal
2. **Include context**: Explain the problem, not just the solution
3. **Document alternatives**: Show what else was considered
4. **Be honest about consequences**: Include both positive and negative outcomes
5. **Link related ADRs**: Reference superseded or related decisions
6. **Update when superseded**: If a decision is replaced, update the status and link to the new ADR

## Resources

- [ADR GitHub Organization](https://adr.github.io/) - ADR best practices and tools
- [Michael Nygard's ADR format](https://cognitect.com/blog/2011/11/15/documenting-architecture-decisions) - Original ADR proposal
- [Markdown Architectural Decision Records (MADR)](https://adr.github.io/madr/) - Alternative template format

## Integration with CFGMS Development

ADRs are referenced in:

- **CLAUDE.md**: Link to relevant ADRs for major architectural decisions
- **PR Reviews**: `/pr-review` may reference ADRs during Phase 3 (Architecture & Design)
- **Story Planning**: `/story-start` may suggest creating ADR for significant changes
- **Documentation**: Architecture docs in `docs/architecture/` may reference specific ADRs
