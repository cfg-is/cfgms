# Certificate Architecture (Story #377)

## Overview

CFGMS supports two certificate deployment architectures:

- **Unified** (default): A single `CertificateTypeServer` certificate serves all purposes (HTTPS API, MQTT mTLS, QUIC mTLS, config signing). Backward compatible with all existing deployments.

- **Separated**: Three purpose-specific certificates with distinct lifecycles, key properties, and trust boundaries.

## Why Separated Architecture?

| Problem | Impact | Separated Solution |
|---------|--------|--------------------|
| TLS key compromise exposes config signing | Attacker can sign malicious configs | Signing key is separate, never used for TLS |
| 90-day TLS rotation disrupts 3-year signing trust | Stewards must re-trust on every rotation | Signing cert has independent 3-year lifecycle |
| Public APIs can't use Let's Encrypt without exposing internal CA | External cert requires exposing internal PKI | Public API cert loaded from external source |

## Certificate Types

### Unified Mode (default)

```
CertificateTypeServer (=1)
  Purpose:  Everything (HTTPS, MQTT, QUIC, signing)
  EKU:      ServerAuth
  Lifetime: 365 days
  Key:      2048-bit RSA
```

### Separated Mode

```
CertificateTypePublicAPI (=3)
  Source:   External files (certbot/LE) or Internal CA
  Purpose:  HTTPS REST API only
  EKU:      ServerAuth
  Lifetime: 90 days (external) or 365 days (internal)

CertificateTypeInternalServer (=4)
  Source:   Internal CA
  Purpose:  MQTT + QUIC mutual TLS
  EKU:      ServerAuth
  Lifetime: 365 days

CertificateTypeConfigSigning (=5)
  Source:   Internal CA
  Purpose:  Config/DNA signing ONLY
  EKU:      CodeSigning (NOT ServerAuth)
  KeyUsage: DigitalSignature only (no KeyEncipherment)
  Key:      4096-bit RSA
  Lifetime: 1095 days (3 years)
```

## Configuration

### Enabling Separated Mode

Set the environment variable:

```bash
CFGMS_CERT_ARCHITECTURE=separated
```

Or in `controller.cfg`:

```yaml
certificate:
  architecture: separated
```

### External Public API Certificate (Let's Encrypt / certbot)

```bash
CFGMS_CERT_ARCHITECTURE=separated
CFGMS_CERT_PUBLIC_API_SOURCE=external
CFGMS_CERT_PUBLIC_API_CERT_PATH=/etc/letsencrypt/live/api.example.com/fullchain.pem
CFGMS_CERT_PUBLIC_API_KEY_PATH=/etc/letsencrypt/live/api.example.com/privkey.pem
```

### Custom Signing Certificate Validity

```bash
CFGMS_CERT_SIGNING_VALIDITY_DAYS=730  # 2 years instead of default 3
```

## Migration Guide

### From Unified to Separated

1. Set `CFGMS_CERT_ARCHITECTURE=separated`
2. Restart the controller
3. On first boot, `EnsureSeparatedCertificates()` auto-generates:
   - Internal mTLS certificate from existing CA
   - Config signing certificate (4096-bit, 3-year) from existing CA
4. Existing stewards continue working via backward compatibility:
   - `ServerCert` in registration response is set to the signing cert
   - Older stewards use `ServerCert` for verification (works correctly)
   - Newer stewards prefer `SigningCert` field when present

### From Separated Back to Unified

1. Remove `CFGMS_CERT_ARCHITECTURE` or set to `unified`
2. Restart the controller
3. System reverts to using `CertificateTypeServer` for all purposes

## Steward Behavior

### Registration Response

In separated mode, the registration response includes:

```json
{
  "server_cert": "<signing cert PEM for backward compat>",
  "signing_cert": "<dedicated signing cert PEM>"
}
```

### Certificate Preference Order (config verification)

1. `signing_cert` from registration (if present)
2. `server_cert` from registration
3. `signing.crt` from disk
4. `server.crt` from disk
5. CA certificate (fallback)

## Type Enum Stability

Certificate type values are explicit integers (not iota) to prevent stored `metadata.json` corruption if types are reordered:

```go
CertificateTypeCA              = 0
CertificateTypeServer          = 1
CertificateTypeClient          = 2
CertificateTypePublicAPI       = 3
CertificateTypeInternalServer  = 4
CertificateTypeConfigSigning   = 5
```

## Future Work

- **Issue #401**: Let's Encrypt automation via certbot module (v0.9.3)
- **Certificate rotation**: Independent rotation schedules per cert type
- **OCSP stapling**: For externally-sourced public API certificates
