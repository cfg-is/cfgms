# SDR-002: Dual Protocol Communication Strategy

## Status
Accepted

## Context
The system needs to support both internal agent communication and external API access. We needed to choose appropriate protocols that balance security, performance, and usability.

## Decision
We have decided to implement a dual-protocol approach:
- gRPC with mTLS for internal agent communication
- HTTPS/REST with API keys for external API access

## Consequences

### Positive
- gRPC provides efficient internal communication
- REST API enables easy integration with external systems
- Clear separation between internal and external access
- Familiar protocols for different use cases
- Good balance of security and usability

### Negative
- Need to maintain two different protocols
- Different authentication mechanisms
- More complex security documentation
- Need to ensure consistent security across both protocols

### Mitigations
- Strong security defaults for both protocols
- Comprehensive security documentation
- Automated security testing for both protocols
- Clear separation of concerns in codebase

## Alternatives Considered

### 1. gRPC Only
- More consistent protocol
- Better performance
- But harder for external integration
- Required custom client libraries

### 2. REST Only
- Simpler protocol
- Better external compatibility
- But less efficient for internal communication
- Higher overhead for agent communication

## Implementation Notes
- gRPC implementation focuses on performance and security
- REST API implementation focuses on usability and standards
- Both protocols use strong authentication
- Both protocols implement rate limiting
- Both protocols have comprehensive logging
