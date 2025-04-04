# SDR-003: Optional OpenZiti Integration

## Status
Accepted

## Context
OpenZiti provides zero-trust networking capabilities that could enhance the security of the system. We needed to decide whether to make it a required component or an optional enhancement.

## Decision
We have decided to make OpenZiti integration optional:
- Core system works with standard gRPC + mTLS
- OpenZiti available as an optional enhancement
- Configuration-driven enablement
- Seamless integration with existing security

## Consequences

### Positive
- System remains accessible for basic deployments
- Users can choose security level based on needs
- Easier initial adoption
- Flexible deployment options
- Can be added later as security needs grow

### Negative
- Need to maintain two connection methods
- More complex documentation
- Need to ensure consistent security
- Additional testing requirements

### Mitigations
- Clear documentation of both approaches
- Strong security defaults for standard mode
- Comprehensive testing of both modes
- Clear migration path between modes

## Alternatives Considered

### 1. Required OpenZiti
- Maximum security
- Consistent security model
- But higher barrier to entry
- Required additional infrastructure

### 2. No OpenZiti Support
- Simpler implementation
- But limited security options
- No zero-trust networking
- Less suitable for complex deployments

## Implementation Notes
- OpenZiti integration uses connection strategy pattern
- Standard mode uses direct gRPC + mTLS
- Both modes maintain strong security
- Configuration determines which mode to use
- Documentation covers both deployment options 