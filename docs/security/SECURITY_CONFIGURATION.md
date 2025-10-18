# Security Configuration Guide

This document provides essential security configuration guidance for CFGMS deployments.

## Table of Contents
- [API Key Management](#api-key-management)
- [CORS Configuration](#cors-configuration)
- [Cryptographic Settings](#cryptographic-settings)
- [Multi-Tenancy Security](#multi-tenancy-security)

## API Key Management

### Environment API Keys

**CRITICAL**: Environment variables containing API keys **MUST** be encrypted or stored in secure secret management systems.

#### Production Deployment Requirements

1. **Never store plaintext API keys in environment files**
   ```bash
   # ❌ INSECURE - DO NOT DO THIS
   export CFGMS_API_KEY="plaintext-key-here"

   # ✅ SECURE - Use encrypted storage
   export CFGMS_API_KEY=$(vault kv get -field=api_key secret/cfgms/production)
   ```

2. **Use Secret Management Systems**
   - **HashiCorp Vault**: Recommended for enterprise deployments
   - **AWS Secrets Manager**: For AWS cloud deployments
   - **Azure Key Vault**: For Azure cloud deployments
   - **SOPS**: For GitOps workflows (see [SOPS Integration](#sops-integration))

3. **Environment File Protection**
   ```bash
   # Set restrictive permissions on .env files
   chmod 600 .env

   # Add to .gitignore
   echo ".env" >> .gitignore
   echo ".env.*" >> .gitignore
   ```

#### SOPS Integration

CFGMS integrates with SOPS (Secrets OPerationS) for encrypted secret storage:

```bash
# Install SOPS
brew install sops  # macOS
# or download from https://github.com/mozilla/sops/releases

# Create encrypted .env file
sops .env.encrypted

# Use in production
export $(sops -d .env.encrypted | xargs)
./cfgms-controller
```

**Reference**: See `docs/configuration/sops.md` for detailed SOPS configuration.

#### API Key Rotation

Implement regular API key rotation (recommended: every 90 days):

```bash
# Generate new API key
./cfgcli api-keys create --name "production-key-2025-Q1" --ttl 90d

# Update secret management system
vault kv put secret/cfgms/production api_key="<new-key>"

# Revoke old key after validation
./cfgcli api-keys revoke <old-key-id>
```

#### Logging Security

**Security Finding H-AUTH-1**: API keys are never logged by CFGMS.

- Controller logs show only key IDs: `"key_id": "key-abc123"`
- Registration tokens show only 6-character prefix: `"token_prefix": "f7g8h9"`
- Full secrets never appear in logs, metrics, or error messages

## CORS Configuration

### Overview

**Security Finding H-AUTH-3**: CFGMS uses origin whitelisting instead of wildcard CORS.

The Controller API enforces strict Cross-Origin Resource Sharing (CORS) policies to prevent unauthorized cross-origin access.

### Configuration

#### Environment Variable

```bash
# Set allowed origins (comma-separated)
export CFGMS_ALLOWED_ORIGINS="https://app.example.com,https://dashboard.example.com"
```

#### Default Origins

If `CFGMS_ALLOWED_ORIGINS` is not set, these defaults apply (development only):

```
http://localhost:3000    # Development frontend
http://localhost:3001    # Alternative dev frontend
http://localhost:9080    # API itself (for testing)
```

**WARNING**: Default origins are **NOT suitable for production**. Always configure explicit origins.

### Production Best Practices

1. **Use HTTPS Only**
   ```bash
   # ✅ SECURE
   export CFGMS_ALLOWED_ORIGINS="https://app.example.com,https://admin.example.com"

   # ❌ INSECURE - HTTP in production
   export CFGMS_ALLOWED_ORIGINS="http://app.example.com"
   ```

2. **Specify Exact Origins**
   ```bash
   # ✅ SECURE - Exact match
   export CFGMS_ALLOWED_ORIGINS="https://app.example.com"

   # ❌ INSECURE - Wildcards not supported
   export CFGMS_ALLOWED_ORIGINS="https://*.example.com"
   ```

3. **Separate by Environment**
   ```bash
   # Development
   CFGMS_ALLOWED_ORIGINS="http://localhost:3000"

   # Staging
   CFGMS_ALLOWED_ORIGINS="https://staging.example.com"

   # Production
   CFGMS_ALLOWED_ORIGINS="https://app.example.com,https://admin.example.com"
   ```

### CORS Behavior

#### Allowed Origins
When a request includes an `Origin` header matching the allowed list:
- `Access-Control-Allow-Origin`: `<matching-origin>`
- `Access-Control-Allow-Methods`: `GET, POST, PUT, DELETE, OPTIONS`
- `Access-Control-Allow-Headers`: `Content-Type, Authorization, X-API-Key`
- `Access-Control-Expose-Headers`: `X-Total-Count`

#### Disallowed Origins
When a request includes an `Origin` header NOT in the allowed list:
- Preflight (OPTIONS) requests: `403 Forbidden`
- No CORS headers set
- Request is rejected

#### No Origin Header
Requests without an `Origin` header (e.g., server-to-server):
- Processed normally
- No CORS headers added
- No CORS restrictions applied

### Testing CORS Configuration

```bash
# Test allowed origin
curl -X OPTIONS https://controller.example.com/api/v1/health \
  -H "Origin: https://app.example.com" \
  -H "Access-Control-Request-Method: GET" \
  -v

# Should return: 200 OK with CORS headers

# Test disallowed origin
curl -X OPTIONS https://controller.example.com/api/v1/health \
  -H "Origin: https://evil.com" \
  -H "Access-Control-Request-Method: GET" \
  -v

# Should return: 403 Forbidden with no CORS headers
```

## Cryptographic Settings

### Password-Based Key Derivation (PBKDF2)

**Security Finding M-CRYPTO-1**: CFGMS uses OWASP 2023 recommended PBKDF2 iterations.

#### M365 Credential Encryption

M365 module credentials are encrypted using:
- **Algorithm**: PBKDF2-HMAC-SHA256
- **Iterations**: 310,000 (OWASP 2023 recommendation)
- **Key Size**: 256 bits
- **Encryption**: AES-256-GCM

**Security Finding M-CRYPTO-2**: Each credential file uses a unique 32-byte salt.

#### Credential File Format

```
[32-byte salt][AES-256-GCM encrypted data]
```

#### Migration from Legacy Format

CFGMS automatically migrates credentials encrypted with the legacy format:
- **Legacy**: 10,000 iterations, global salt
- **New**: 310,000 iterations, per-credential salt
- **Migration**: Transparent on first read, writes use new format

No manual intervention required - credentials are migrated on first use.

#### Key Derivation Configuration

The passphrase for credential encryption MUST be:
- Minimum 32 characters
- Stored in secret management system (not environment files)
- Rotated annually

```bash
# Set via environment variable (use secret management in production)
export M365_CREDENTIAL_PASSPHRASE=$(vault kv get -field=passphrase secret/cfgms/m365)
```

## Multi-Tenancy Security

### Tenant Isolation

**Security Finding M-TENANT-2**: CFGMS enforces strict tenant boundary validation.

#### RBAC Cross-Tenant Protection

Role inheritance is validated to prevent privilege escalation:

```go
// ✅ ALLOWED: Parent and child in same tenant
parentRole.TenantId = "tenant-123"
childRole.TenantId = "tenant-123"

// ❌ BLOCKED: Cross-tenant inheritance
parentRole.TenantId = "tenant-123"
childRole.TenantId = "tenant-456"
// Returns: "cross-tenant role inheritance not allowed"
```

#### Audit Logging

Cross-tenant access attempts are logged with CRITICAL severity:
```json
{
  "event_type": "rbac_security_violation",
  "severity": "CRITICAL",
  "error_code": "RBAC_CROSS_TENANT_INHERITANCE_BLOCKED",
  "security_finding": "M-TENANT-2",
  "child_tenant": "tenant-456",
  "parent_tenant": "tenant-123"
}
```

### Tenant Context Validation

**Security Finding H-TENANT-1**: Storage operations should validate tenant context.

**Status**: Recommended for implementation - defense-in-depth measure.

Pattern for future implementation:
```go
// Validate tenant context in storage operations
func validateTenantContext(ctx context.Context, resourceTenantID string) error {
    authTenantID := ctx.Value("tenant_id").(string)
    if authTenantID != resourceTenantID {
        return ErrCrossTenantAccessDenied
    }
    return nil
}
```

## Security Audit Compliance

This configuration guide addresses findings from the October 2025 security audit:

| Finding ID | Severity | Status | Section |
|------------|----------|--------|---------|
| H-AUTH-1 | HIGH | ✅ Remediated | [API Key Management](#api-key-management) |
| H-AUTH-2 | HIGH | ✅ Documented | This document |
| H-AUTH-3 | HIGH | ✅ Remediated | [CORS Configuration](#cors-configuration) |
| H-AUTH-4 | HIGH | ✅ Remediated | [API Key Management](#logging-security) |
| M-CRYPTO-1 | MEDIUM | ✅ Remediated | [Cryptographic Settings](#password-based-key-derivation-pbkdf2) |
| M-CRYPTO-2 | MEDIUM | ✅ Remediated | [Cryptographic Settings](#credential-file-format) |
| M-INPUT-1 | MEDIUM | ✅ Remediated | Input validation (code-level fix) |
| M-TENANT-2 | MEDIUM | ✅ Remediated | [Multi-Tenancy Security](#rbac-cross-tenant-protection) |
| H-TENANT-1 | HIGH | 📋 Recommended | [Multi-Tenancy Security](#tenant-context-validation) |

**Full Audit Report**: `docs/security/audits/security-audit-report-2025-10-17.md`
**Remediation Plan**: `docs/security/audits/remediation-plan-2025-10-17.md`

## Additional Resources

- **SOPS Integration**: `docs/configuration/sops.md`
- **Certificate Management**: `docs/security/certificate-management.md`
- **Mutual TLS Configuration**: `docs/security/mtls.md`
- **Audit Logging**: `docs/security/audit-logging.md`

## Security Contact

To report security vulnerabilities, see `SECURITY.md` in the repository root.

---

**Last Updated**: 2025-10-18
**Security Audit**: October 2025 (Story #225)
