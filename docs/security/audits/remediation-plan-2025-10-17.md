# Security Audit Remediation Plan

**Date:** October 17, 2025
**Story:** #225 - Security Code Review (External Audit)
**Audit Report:** audit-report-2025-10-17.md

## Remediation Scope

**Included in This Sprint:**
- All 5 High severity findings
- 5 selected Medium severity findings (quick wins + crypto improvements)

**Deferred to Follow-up Stories:**
- 4 Medium severity findings requiring significant infrastructure changes

---

## Prioritized Remediation List

### Phase 1: Quick Wins (45 minutes) - HIGH PRIORITY

#### 1. H-AUTH-1: Remove API Key from Logs
**Priority:** P0 - CRITICAL
**Effort:** 5 minutes
**Files:** `features/controller/api/handlers_apikeys.go:322`

**Acceptance Criteria:**
- [ ] Remove `"key", keyString` from log statement
- [ ] Log only `"id"` and `"created_at"` timestamp
- [ ] Verify API key generation still works
- [ ] Test that logs don't contain full API keys

**Implementation:**
```go
// BEFORE:
s.logger.Info("Generated default API key", "id", defaultKey.ID, "key", keyString)

// AFTER:
s.logger.Info("Generated default API key", "id", defaultKey.ID, "created_at", defaultKey.CreatedAt)
```

---

#### 2. H-AUTH-4: Reduce Token Prefix Logging
**Priority:** P0 - CRITICAL
**Effort:** 5 minutes
**Files:** `features/controller/api/handlers_registration.go:55`

**Acceptance Criteria:**
- [ ] Reduce token prefix from 15 chars to 6 chars
- [ ] Verify registration still works
- [ ] Test that reduced prefix still aids debugging

**Implementation:**
```go
// BEFORE:
s.logger.Info("Processing steward registration request", "token_prefix", req.Token[:min(len(req.Token), 15)])

// AFTER:
s.logger.Info("Processing steward registration request", "token_prefix", req.Token[:min(len(req.Token), 6)])
```

---

#### 3. M-INPUT-1: Fix Integer Overflow in Query Parameters
**Priority:** P1 - HIGH
**Effort:** 30 minutes
**Files:** `features/controller/api/validation_middleware.go:110-114`

**Acceptance Criteria:**
- [ ] Replace `strconv.Atoi()` with `strconv.ParseInt(value, 10, 64)`
- [ ] Add explicit range validation
- [ ] Test with boundary values (0, 1000, max int64)
- [ ] Verify validation still rejects invalid inputs

**Implementation:**
```go
// BEFORE:
if limit, err := strconv.Atoi(value); err == nil {
    validator.ValidateInteger(result, fieldName, int64(limit), "positive", "max:1000")
}

// AFTER:
limit, err := strconv.ParseInt(value, 10, 64)
if err != nil {
    result.AddError(fieldName, "must be a valid integer")
    continue
}
if limit < 0 || limit > 1000 {
    result.AddError(fieldName, "must be between 0 and 1000")
}
```

---

### Phase 2: CORS Security (30 minutes) - HIGH PRIORITY

#### 4. H-AUTH-3: Fix CORS Wildcard Configuration
**Priority:** P0 - CRITICAL
**Effort:** 30 minutes
**Files:** `features/controller/api/middleware.go:63`

**Acceptance Criteria:**
- [ ] Create configurable allowed origins list
- [ ] Validate origin header against whitelist
- [ ] Support localhost for development
- [ ] Test cross-origin requests are properly validated
- [ ] Add configuration documentation

**Implementation:**
```go
type CORSConfig struct {
    AllowedOrigins []string
}

func (s *Server) configureCORS() {
    s.corsConfig = &CORSConfig{
        AllowedOrigins: []string{
            "https://portal.example.com",
            "https://portal.example.com",
            "http://localhost:3000",  // Development
        },
    }

    // Load from environment/config
    if envOrigins := os.Getenv("CFGMS_ALLOWED_ORIGINS"); envOrigins != "" {
        s.corsConfig.AllowedOrigins = strings.Split(envOrigins, ",")
    }
}

func (s *Server) corsMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        origin := r.Header.Get("Origin")

        // Check if origin is in allowed list
        allowed := false
        for _, allowedOrigin := range s.corsConfig.AllowedOrigins {
            if origin == allowedOrigin {
                allowed = true
                break
            }
        }

        if allowed {
            w.Header().Set("Access-Control-Allow-Origin", origin)
        }

        next.ServeHTTP(w, r)
    })
}
```

---

### Phase 3: Cryptography Hardening (2.5 hours) - MEDIUM PRIORITY

#### 5. M-CRYPTO-1: Increase PBKDF2 Iteration Count
**Priority:** P1 - HIGH
**Effort:** 30 minutes
**Files:** `features/modules/m365/auth/file_credential_store.go:47`

**Acceptance Criteria:**
- [ ] Change iteration count from 10,000 to 310,000
- [ ] Update constant with OWASP reference comment
- [ ] Test credential encryption/decryption still works
- [ ] Document iteration count rationale

**Implementation:**
```go
const (
    // PBKDF2 iteration count per OWASP 2023 recommendations
    // https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#pbkdf2
    pbkdf2Iterations = 310000  // Increased from 10,000 (security audit finding M-CRYPTO-1)
)

// Update usage:
encryptionKey := pbkdf2.Key(
    []byte(passphrase),
    salt,
    pbkdf2Iterations,  // Use constant instead of hardcoded value
    32,
    sha256.New,
)
```

---

#### 6. M-CRYPTO-2: Implement Salt-Per-Credential Storage
**Priority:** P1 - HIGH
**Effort:** 2 hours (includes migration)
**Files:** `features/modules/m365/auth/file_credential_store.go`

**Acceptance Criteria:**
- [ ] Generate unique random salt (32 bytes) for each credential
- [ ] Store salt alongside encrypted data
- [ ] Update encryption to use per-credential salt
- [ ] Update decryption to use stored salt
- [ ] Implement migration from hardcoded salt to per-credential salt
- [ ] Test encryption/decryption with new salts
- [ ] Test migration preserves existing credentials
- [ ] Document salt storage format

**Implementation:**
```go
type StoredCredential struct {
    TenantID      string          `json:"tenant_id"`
    ProviderType  string          `json:"provider_type"`
    Salt          string          `json:"salt"`           // Base64-encoded 32-byte salt
    EncryptedData string          `json:"encrypted_data"` // Base64-encoded ciphertext
    CreatedAt     time.Time       `json:"created_at"`
    UpdatedAt     time.Time       `json:"updated_at"`
    Version       int             `json:"version"`        // Migration version
}

// V1: Hardcoded salt (legacy)
// V2: Per-credential salt (new)

func (fcs *FileCredentialStore) StoreClientSecret(provider string, data map[string]interface{}) error {
    // Generate unique salt for this credential
    salt := make([]byte, 32)
    if _, err := io.ReadFull(rand.Reader, salt); err != nil {
        return fmt.Errorf("failed to generate salt: %w", err)
    }

    // Derive key from passphrase + unique salt
    encryptionKey := pbkdf2.Key(
        []byte(fcs.passphrase),
        salt,
        pbkdf2Iterations,
        32,
        sha256.New,
    )

    // Encrypt
    dataJSON, _ := json.Marshal(data)
    encrypted, err := fcs.encryptData(dataJSON, encryptionKey)

    // Store with salt
    credential := StoredCredential{
        TenantID:      fcs.tenantID,
        ProviderType:  provider,
        Salt:          base64.StdEncoding.EncodeToString(salt),
        EncryptedData: encrypted,
        CreatedAt:     time.Now(),
        UpdatedAt:     time.Now(),
        Version:       2,  // New format
    }

    return fcs.saveCredential(credential)
}

func (fcs *FileCredentialStore) GetClientSecret(provider string) (map[string]interface{}, error) {
    credential, err := fcs.loadCredential(provider)

    var encryptionKey []byte

    // Handle migration from V1 to V2
    if credential.Version == 1 || credential.Salt == "" {
        // Legacy: hardcoded salt
        encryptionKey = pbkdf2.Key(
            []byte(fcs.passphrase),
            []byte("cfgms-saas-salt"),  // Old hardcoded salt
            10000,  // Old iteration count
            32,
            sha256.New,
        )
    } else {
        // New: per-credential salt
        salt, err := base64.StdEncoding.DecodeString(credential.Salt)
        if err != nil {
            return nil, fmt.Errorf("invalid salt: %w", err)
        }

        encryptionKey = pbkdf2.Key(
            []byte(fcs.passphrase),
            salt,
            pbkdf2Iterations,
            32,
            sha256.New,
        )
    }

    // Decrypt
    decrypted, err := fcs.decryptData(credential.EncryptedData, encryptionKey)

    // If V1, re-encrypt with V2 format
    if credential.Version == 1 {
        fcs.migrateCredentialToV2(credential, decrypted)
    }

    return decrypted, nil
}
```

---

### Phase 4: Multi-Tenancy Hardening (4 hours) - HIGH PRIORITY

#### 7. M-TENANT-2: Block Cross-Tenant Role Inheritance
**Priority:** P1 - HIGH
**Effort:** 2 hours
**Files:** `features/rbac/manager.go`

**Acceptance Criteria:**
- [ ] Add tenant boundary validation to `CreateRole` with parent
- [ ] Prevent role inheritance across tenant boundaries
- [ ] Return clear error when cross-tenant inheritance attempted
- [ ] Add integration test for cross-tenant inheritance blocking
- [ ] Update role creation documentation

**Implementation:**
```go
func (m *Manager) CreateRole(ctx context.Context, role *rbac.Role) error {
    // Validate parent role if specified
    if role.ParentRoleId != "" {
        parentRole, err := m.GetRole(ctx, role.ParentRoleId)
        if err != nil {
            return fmt.Errorf("parent role not found: %w", err)
        }

        // SECURITY: Prevent cross-tenant role inheritance
        if parentRole.TenantId != role.TenantId {
            return fmt.Errorf("cross-tenant role inheritance not allowed: parent tenant=%s, child tenant=%s (security finding M-TENANT-2)",
                parentRole.TenantId, role.TenantId)
        }
    }

    // Continue with role creation
    return m.store.SaveRole(ctx, role)
}
```

**Test:**
```go
func TestCrossTenantRoleInheritanceBlocked(t *testing.T) {
    // Create role in tenant A
    parentRole := &rbac.Role{
        Id:       "parent-role",
        TenantId: "tenant-a",
        Name:     "Parent Role",
    }

    // Attempt to create child role in tenant B inheriting from tenant A
    childRole := &rbac.Role{
        Id:           "child-role",
        TenantId:     "tenant-b",
        Name:         "Child Role",
        ParentRoleId: "parent-role",
    }

    err := manager.CreateRole(ctx, childRole)

    // Should fail with cross-tenant error
    assert.Error(t, err)
    assert.Contains(t, err.Error(), "cross-tenant role inheritance not allowed")
}
```

---

#### 8. H-TENANT-1: Add Tenant Context Validation to Storage
**Priority:** P0 - CRITICAL
**Effort:** 2 hours
**Files:** `pkg/storage/providers/database/config_store.go`, `rbac_store.go`, `audit_store.go`

**Acceptance Criteria:**
- [ ] Add tenant context validation helper function
- [ ] Validate tenant context in all StoreConfig operations
- [ ] Validate tenant context in all GetConfig operations
- [ ] Validate tenant context in RBAC storage operations
- [ ] Return `ErrCrossTenantAccessDenied` error
- [ ] Add integration tests for cross-tenant access attempts
- [ ] Update storage documentation

**Implementation:**
```go
// Common error
var ErrCrossTenantAccessDenied = errors.New("cross-tenant access denied")

// Helper function
func validateTenantContext(ctx context.Context, resourceTenantID string) error {
    callerTenantID, ok := ctx.Value(tenantIDContextKey).(string)
    if !ok || callerTenantID == "" {
        return errors.New("tenant context not found in request")
    }

    if callerTenantID != resourceTenantID {
        return fmt.Errorf("%w: caller=%s, resource=%s",
            ErrCrossTenantAccessDenied, callerTenantID, resourceTenantID)
    }

    return nil
}

// Apply to all storage operations
func (s *DatabaseConfigStore) StoreConfig(ctx context.Context, config *interfaces.ConfigEntry) error {
    // SECURITY: Validate caller's tenant matches config tenant (finding H-TENANT-1)
    if err := validateTenantContext(ctx, config.Key.TenantID); err != nil {
        return err
    }

    // Continue with storage...
}

func (s *DatabaseConfigStore) GetConfig(ctx context.Context, key interfaces.ConfigKey) (*interfaces.ConfigEntry, error) {
    // SECURITY: Validate caller's tenant matches requested tenant
    if err := validateTenantContext(ctx, key.TenantID); err != nil {
        return nil, err
    }

    // Continue with retrieval...
}
```

**Test:**
```go
func TestCrossTenantStorageAccessBlocked(t *testing.T) {
    // Context says user is from tenant-a
    ctx := context.WithValue(context.Background(), tenantIDContextKey, "tenant-a")

    // Try to store config for tenant-b
    config := &interfaces.ConfigEntry{
        Key: interfaces.ConfigKey{
            TenantID: "tenant-b",  // Different tenant!
        },
    }

    err := store.StoreConfig(ctx, config)

    // Should fail
    assert.ErrorIs(t, err, ErrCrossTenantAccessDenied)
}
```

---

### Phase 5: Documentation & Configuration (30 minutes)

#### 9. H-AUTH-2: Document Environment API Key Encryption Requirement
**Priority:** P1 - HIGH
**Effort:** 30 minutes
**Files:** `docs/security/`, `README.md`

**Acceptance Criteria:**
- [ ] Document that environment variables should NOT contain plaintext API keys
- [ ] Provide SOPS encryption example
- [ ] Update deployment documentation
- [ ] Add security warning to configuration guide
- [ ] Create example encrypted .env file

**Implementation:**
```markdown
## Security Warning: API Key Storage

⚠️ **NEVER store API keys in plaintext environment variables**

### ❌ Insecure (DO NOT DO THIS):
```bash
export CFGMS_API_KEY="cfgms_key_abc123xyz456..."
```

### ✅ Secure Options:

**Option 1: Use SOPS (Recommended)**
```bash
# Encrypt secrets file
sops --encrypt .env > .env.encrypted

# Controller loads from encrypted file
CFGMS_SECRETS_FILE=".env.encrypted" ./controller
```

**Option 2: Use HashiCorp Vault**
```bash
vault kv put secret/cfgms/api-key value="..."
```

**Option 3: Use Kubernetes Secrets (for K8s deployments)**
```yaml
apiVersion: v1
kind: Secret
metadata:
  name: cfgms-api-key
type: Opaque
stringData:
  api-key: "..."
```

See [Security Best Practices](./SECURITY.md) for details.
```

---

## Deferred to Follow-up Stories

### Story #233: Security Hardening - Infrastructure Changes (12 hours)

**Medium Priority Issues Requiring Significant Work:**

1. **M-INPUT-2: Add Regex Timeout Mechanism** (2 hours)
2. **M-AUTH-2: Add Admin Operation Audit** (3 hours)
3. **M-INPUT-3: SQL Identifier Whitelisting** (1 hour)
4. **M-AUTH-1: Persist API Keys to Storage** (4 hours)
5. **M-TENANT-1: Implement PostgreSQL Row-Level Security** (4 hours)

---

## Testing Strategy

### Unit Tests Required
- [ ] API key logging (verify no keys in output)
- [ ] Token prefix length validation
- [ ] Integer parsing boundary conditions
- [ ] CORS origin validation
- [ ] PBKDF2 iteration count
- [ ] Salt generation uniqueness
- [ ] Cross-tenant role inheritance blocking
- [ ] Cross-tenant storage access blocking

### Integration Tests Required
- [ ] End-to-end CORS validation
- [ ] Credential encryption/decryption with new salts
- [ ] Migration from V1 to V2 credential format
- [ ] Multi-tenant isolation validation

### Security Regression Tests
- [ ] Verify no API keys logged anywhere
- [ ] Verify CORS rejects unauthorized origins
- [ ] Verify tenant isolation across all layers

---

## Success Criteria

**Story #225 Completion:**
- [ ] All 5 High severity findings remediated
- [ ] 5 selected Medium findings remediated
- [ ] All tests pass (unit + integration)
- [ ] Security scan clean (gosec, staticcheck, trivy)
- [ ] Documentation updated
- [ ] Audit report updated with remediation summary

**Security Posture Improvement:**
- Before: 8 High, 8 Medium findings
- After: 0 High, 3 Medium findings (67% reduction)
- Overall Rating: B+ → A-

---

## Effort Summary

| Phase | Tasks | Effort | Priority |
|-------|-------|--------|----------|
| Phase 1 | Quick Wins (3 items) | 45 min | P0 |
| Phase 2 | CORS Security | 30 min | P0 |
| Phase 3 | Cryptography (2 items) | 2.5 hours | P1 |
| Phase 4 | Multi-tenancy (2 items) | 4 hours | P0-P1 |
| Phase 5 | Documentation | 30 min | P1 |
| **Total** | **9 items** | **~8 hours** | **Mixed** |

**Estimated Completion:** 1 working day

---

**Report Status:** DRAFT
**Next Action:** Begin remediation starting with Phase 1
