# API Key Persistence Implementation Guide

**Security Finding**: M-AUTH-1
**Severity**: MEDIUM
**CVSS**: 5.5
**Status**: DOCUMENTED (Implementation Required)

## Overview

Currently, API keys are stored in memory only and are lost on service restart. This finding requires implementing persistent, encrypted storage for API keys to ensure continuity of service and proper key lifecycle management.

## Requirements

### M-AUTH-1: Persist API Keys to Durable Storage

**Current State**:
- API keys stored in `map[string]*APIKey` in `features/controller/api/server.go`
- Keys lost on controller restart
- No key rotation tracking
- No backup/recovery mechanism

**Required State**:
- API keys persisted to database or encrypted file storage
- Keys survive service restarts
- Key rotation tracking with expiration
- Encrypted at rest using tenant secret manager
- Backup and recovery mechanism

## Implementation Plan

### Phase 1: Storage Interface (Completed)

Location: `pkg/storage/interfaces/apikey_store.go`

```go
// APIKeyStore interface for persistent API key storage
type APIKeyStore interface {
	// Initialize sets up the API key store
	Initialize(ctx context.Context) error

	// StoreKey persists an API key with encryption
	StoreKey(ctx context.Context, key *APIKey) error

	// GetKey retrieves an API key by key string (hashed lookup)
	GetKey(ctx context.Context, keyHash string) (*APIKey, error)

	// GetKeyByID retrieves an API key by ID
	GetKeyByID(ctx context.Context, id string) (*APIKey, error)

	// ListKeys returns all API keys for a tenant
	ListKeys(ctx context.Context, tenantID string) ([]*APIKey, error)

	// DeleteKey removes an API key
	DeleteKey(ctx context.Context, id string) error

	// Close shuts down the store
	Close() error
}

// APIKey represents a stored API key
type APIKey struct {
	ID          string
	KeyHash     string // SHA-256 hash of actual key
	Name        string
	Permissions []string
	TenantID    string
	CreatedAt   time.Time
	ExpiresAt   *time.Time
	LastUsedAt  *time.Time
	Metadata    map[string]string
}
```

### Phase 2: Database Implementation

Location: `pkg/storage/providers/database/apikey_store.go`

**Database Schema**:
```sql
CREATE TABLE api_keys (
	id VARCHAR(255) PRIMARY KEY,
	key_hash VARCHAR(64) NOT NULL UNIQUE, -- SHA-256 hash
	name VARCHAR(255) NOT NULL,
	permissions JSONB NOT NULL,
	tenant_id VARCHAR(255) NOT NULL,
	created_at TIMESTAMP NOT NULL DEFAULT NOW(),
	expires_at TIMESTAMP,
	last_used_at TIMESTAMP,
	metadata JSONB,
	INDEX idx_tenant_id (tenant_id),
	INDEX idx_key_hash (key_hash)
);
```

**Key Features**:
- Store SHA-256 hash of API key (never store plaintext)
- Encrypt sensitive metadata at rest
- Support key rotation with expiration tracking
- Track last usage for auditing

### Phase 3: Server Integration

Location: `features/controller/api/server.go`

**Changes Required**:
1. Add `apiKeyStore` field to Server struct
2. Load keys from storage on startup
3. Write-through cache: memory + persistent storage
4. Periodic flush of usage statistics

**Migration Strategy**:
```go
func (s *Server) migrateAPIKeys(ctx context.Context) error {
	// 1. Get existing in-memory keys
	// 2. Persist to storage with encryption
	// 3. Verify all keys are persisted
	// 4. Clear in-memory-only flag
	return nil
}
```

### Phase 4: Encryption

**Requirements**:
- Use tenant-specific encryption keys
- Integrate with existing secret management (SOPS/Vault)
- Support key rotation

**Implementation**:
```go
// Encrypt API key metadata before storage
func encryptAPIKeyMetadata(metadata map[string]string, tenantKey []byte) ([]byte, error) {
	// Use AES-256-GCM for encryption
	// Similar to M365 credential encryption
	return encrypted, nil
}
```

## Security Considerations

### M-AUTH-1 Security Requirements

1. **Never Store Plaintext Keys**
   - Store SHA-256 hash only
   - Actual key only shown at creation time
   - Use constant-time comparison for lookups

2. **Encryption at Rest**
   - Encrypt metadata and permissions
   - Use tenant-specific encryption keys
   - Rotate encryption keys periodically

3. **Access Control**
   - Only system admin can manage API keys
   - Tenant isolation enforced
   - Audit all key operations

4. **Key Rotation**
   - Support expiration dates
   - Automated rotation reminders
   - Graceful key deprecation

## Backward Compatibility

**Migration Path**:
1. Deploy with both in-memory and persistent storage
2. Write to both locations (write-through)
3. Read from persistent with memory fallback
4. After validation period, remove in-memory-only mode

**Zero Downtime**:
- Existing keys continue working
- New keys automatically persisted
- Gradual migration of legacy keys

## Testing Plan

### Unit Tests
- [x] Storage interface defined
- [ ] Database store implementation
- [ ] Encryption/decryption
- [ ] Key hashing and lookup
- [ ] Expiration handling

### Integration Tests
- [ ] Server startup with persistent keys
- [ ] API key CRUD operations
- [ ] Key rotation workflow
- [ ] Backup and recovery

### Security Tests
- [ ] Verify no plaintext storage
- [ ] Encryption validation
- [ ] Access control enforcement
- [ ] Audit logging completeness

## Performance Considerations

- **Memory Cache**: Keep frequently-used keys in memory
- **Lazy Loading**: Load keys on first use
- **Batch Operations**: Minimize database roundtrips
- **Connection Pooling**: Reuse database connections

## Monitoring and Observability

- Log all API key operations
- Track key usage statistics
- Alert on expiring keys
- Monitor failed authentication attempts

## Implementation Timeline

**Estimated Effort**: 4 hours

1. **Hour 1**: Define storage interface and database schema
2. **Hour 2**: Implement database store with encryption
3. **Hour 3**: Integrate with server, add migration logic
4. **Hour 4**: Testing, validation, documentation

## Status

**Current Status**: DOCUMENTED
**Implementation**: Deferred to v0.8.0 or v1.0.0
**Priority**: MEDIUM (does not block v0.7.0 OSS launch)

**Justification for Deferral**:
- Non-critical for MVP launch
- Requires significant infrastructure changes
- Can be implemented in next sprint
- Documented workaround: Manage keys via configuration

## Workaround for v0.7.0

Until M-AUTH-1 is implemented:

1. **Configuration-Based Keys**:
   - Define API keys in configuration files
   - Encrypt configuration with SOPS
   - Document key management procedures

2. **Operational Procedures**:
   - Document manual key rotation process
   - Implement key backup procedures
   - Monitor for service restarts

3. **Limitations**:
   - Keys lost on restart (must regenerate)
   - No automated rotation
   - Manual backup required

## References

- **Security Audit**: `docs/security/audits/audit-report-2025-10-17.md`
- **Remediation Plan**: `docs/security/audits/remediation-plan-2025-10-17.md`
- **SOPS Integration**: `docs/configuration/sops.md`
