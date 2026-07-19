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
| [002](002-steward-bootstrap-for-controllers.md) | Steward Bootstrap for Controller Nodes | 2026-03-30 | Accepted |
| [003](003-storage-data-taxonomy.md) | Storage Data Taxonomy | 2026-04-13 | Proposed |
| [004](004-audit-chain-integrity.md) | Audit Chain Integrity via HMAC-Keyed Hash Chain | 2026-04-21 | Accepted |
| [005](005-logging-interface-for-transport-providers.md) | Logging Interface for Transport Providers | 2026-05-04 | Accepted |
| [006](006-module-packaging-and-distribution.md) | Module Packaging and Distribution | 2026-06-05 | Accepted |
| [007](007-controller-upgrade-and-state-externalization.md) | Controller Upgrade and State Externalization Strategy | 2026-06-15 | Accepted |
| [008](008-durable-execution-substrate.md) | Durable Execution Substrate for the Workflow Engine | 2026-06-15 | Accepted |
| [009](009-hyperv-vm-provisioning-from-install-media.md) | Hyper-V VM Provisioning from Install Media (ISO → Managed Endpoint) | 2026-06-18 | Accepted |
| [010](010-steward-side-provisioning-enrollment.md) | Steward-Side Provisioning Enrollment — Controller-Supplied Join Token, IP-Trust Admission, Media Cleanup | 2026-06-19 | Accepted |
| [011](011-registration-refresh.md) | Registration-Refresh for Stewards Offline Past mTLS Cert Expiry | 2026-06-20 | Accepted |
| [012](012-steward-event-telemetry-stream.md) | Steward Event/Telemetry Stream to Controller | 2026-06-23 | Accepted |
| [013](013-steward-controller-trust-and-distribution.md) | Steward Controller-Trust Anchoring and Binary Distribution | 2026-06-24 | Accepted |
| [014](014-cfg-sessions-and-credential-unlock.md) | cfg Admin Sessions and Credential Storage (Zero Standing Privilege) | 2026-06-28 | Accepted |
| [015](015-story-materialization-at-decomposition.md) | Story Materialization at Decomposition | 2026-07-03 | Accepted |
| [016](016-steward-module-foundation.md) | Steward Module Foundation — stdlib set, repository layout, DNA-fragment contract | 2026-07-04 | Proposed |
| [017](017-dna-composition-and-sync.md) | DNA Composition & Sync — fragment model, authority resolution, partial-sync validation (incl. Amendment 1: twin/DEX data-model commitments) | 2026-07-04 | Proposed |
| [018](018-web-session-semantics.md) | Web-Session Semantics (Browser Credential Login) | 2026-07-04 | Accepted |
| [019](019-third-party-module-inclusion-and-trust.md) | Third-Party Module Inclusion and Delegated Publisher Trust | 2026-07-04 | Proposed |
| [020](020-dna-required-field-declaration.md) | DNA Required-Field Declaration — per-configuration-type contract, module-manifest sourced | 2026-07-13 | Accepted |
| [021](021-identity-assurance-levels.md) | Identity Assurance Levels and Step-Up Authentication | 2026-07-16 | Accepted |

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
