# Security Decision Records (SDRs)

This directory contains Security Decision Records (SDRs) that document important security-related decisions made during the development of CFGMS.

## Index

### Communication Security
- [SDR-001: Removal of Dark Ports Requirement](001-remove-dark-ports.md)
- [SDR-002: Dual Protocol Communication Strategy](002-dual-protocol-communication.md)
- [SDR-003: Optional OpenZiti Integration](003-optional-openziti.md)

## SDR Template

Each SDR follows this structure:
```markdown
# SDR-XXX: Title

## Status
[Accepted/Proposed/Deprecated/Superseded]

## Context
[Background and situation]

## Decision
[The decision made]

## Consequences
### Positive
[List positive consequences]

### Negative
[List negative consequences]

### Mitigations
[List mitigations for negative consequences]

## Alternatives Considered
[List and explain alternatives]

## Implementation Notes
[Implementation details and considerations]
```

## Creating New SDRs

1. Create a new file named `XXX-title.md` where XXX is the next available number
2. Follow the template structure above
3. Update this index file
4. Add references in relevant documentation 