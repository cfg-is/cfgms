# SDR-001: Removal of Dark Ports Requirement

## Status
Accepted

## Context
The original design specified that all open ports must be 'Dark' and protected by mutual TLS with Single Packet Authentication (SPA). This requirement was intended to make the server invisible to port scanners and other attack attempts.

## Decision
We have decided to remove the "Dark" ports requirement and instead rely on standard security practices:
- gRPC with mTLS for internal agent communication
- HTTPS with API keys for external REST API access
- Optional OpenZiti integration for enhanced security

## Consequences

### Positive
- Simplified deployment and configuration
- Better compatibility with standard tools and libraries
- Easier integration with existing security infrastructure
- More familiar security model for users
- Reduced operational complexity

### Negative
- Slightly increased attack surface (ports are discoverable)
- Less protection against port scanning
- May require additional security measures at network level

### Mitigations
- Strong authentication requirements
- Rate limiting on all endpoints
- Comprehensive logging and monitoring
- Optional OpenZiti integration for zero-trust networking
- Cloudflare or similar protection can be used in deployments

## Alternatives Considered

### 1. Keep Dark Ports with SPA
- Maintained maximum security
- But added significant complexity
- Made the system harder to use and integrate
- Required custom client libraries

### 2. Use Only OpenZiti
- Provided zero-trust networking
- But required additional infrastructure
- Made the system less accessible
- Added deployment complexity

## Implementation Notes
- All internal communication uses gRPC with mTLS
- External API uses standard HTTPS with API keys
- OpenZiti integration remains optional
- Security documentation updated to reflect new approach 