# cert_trust Module

## Overview

The `cert_trust` module manages the OS-level system trust store on managed endpoints. It installs, trusts, and removes CA certificates from the platform's native trust mechanism — making the OS trust (or stop trusting) a certificate authority for all applications that consult the system trust store.

This module is distinct from CFGMS's own mTLS certificate lifecycle (`pkg/cert`). It operates on the OS trust store (which CAs the system trusts globally), not on CFGMS's internal certificate chain.

No private key material is handled. Trust-store entries are public certificates only.

## Implementation References

- Schema: [`features/modules/stdlib/cert_trust/module.yaml`](../../features/modules/stdlib/cert_trust/module.yaml)
- Implementation: [`features/modules/stdlib/cert_trust/module.go`](../../features/modules/stdlib/cert_trust/module.go)

## Platform Support

| Platform | Get | Set (install) | Set (remove) | Mechanism |
|----------|-----|--------------|--------------|-----------|
| Linux (Debian-family) | ✓ | ✓ | ✓ | `/usr/local/share/ca-certificates/` + `update-ca-certificates` |
| Windows | ✓ | ✓ | ✓ | `certutil.exe -addstore/-delstore Root` |
| macOS | ✓ | ✓ | ✓ | `security add-trusted-cert / delete-certificate` (System keychain) |

**Linux note:** This module targets Debian-family distributions (Debian, Ubuntu, and derivatives). RPM-based distributions (RHEL, Fedora, CentOS) use a different trust store path and refresh command and are not supported in this version.

**Privilege requirement:** All platforms require administrator/root privileges to modify the system trust store.

## Configuration

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `fingerprint` | string | **Yes (as resource ID)** | SHA-256 fingerprint (64-char lowercase hex, no colons). Used as the resource ID passed by the framework. |
| `state` | string | **Yes** | `"present"` or `"absent"` |
| `cert_pem` | string | **Yes when `state: present`** | PEM-encoded CA certificate to install. Must contain a `CERTIFICATE` block. No private key. |
| `subject` | string | No (observed only) | Certificate subject DN — returned by `Get`, ignored by `Set`. |
| `issuer` | string | No (observed only) | Certificate issuer DN — returned by `Get`, ignored by `Set`. |
| `not_after` | string | No (observed only) | Certificate expiry in RFC3339 format — returned by `Get`, ignored by `Set`. |
| `trusted_for` | string | No (observed only) | Trust purpose — returned by `Get`, ignored by `Set`. |

## Resource ID

The resource ID for `cert_trust` is the **SHA-256 fingerprint** of the certificate, expressed as 64 lowercase hexadecimal characters with no colons or separators. Example:

```
a7f3c2d18e4b5690123456789abcdef0123456789abcdef0123456789abcdef01
```

The fingerprint is the stable identity of the certificate. If the certificate is replaced (different bytes, different fingerprint), it is a different resource.

## Get

`Get(fingerprint)` queries the OS trust store for a certificate with the given SHA-256 fingerprint.

- If the certificate is **present**, returns a `CertTrustConfig` with `state: present` and the observed `subject`, `issuer`, `not_after`, and `trusted_for` fields populated.
- If the certificate is **absent**, returns a `CertTrustConfig` with `state: absent` and all other fields empty. This is not an error — it matches how the file module returns `state: absent` for non-existent files.

## Examples

### Trust a CA certificate

```yaml
modules:
  acme_corp_root_ca:
    type: cert_trust
    config:
      fingerprint: a7f3c2d18e4b5690123456789abcdef0123456789abcdef0123456789abcdef01
      state: present
      cert_pem: |
        -----BEGIN CERTIFICATE-----
        MIIB...
        -----END CERTIFICATE-----
```

### Remove a previously trusted CA

```yaml
modules:
  old_vendor_ca:
    type: cert_trust
    config:
      fingerprint: b8e4d3e29f5c6701234567890bcdef01234567890bcdef01234567890bcdef012
      state: absent
```

## Security Considerations

Trust-store mutations are **security-sensitive operations** that control which certificate authorities the OS trusts system-wide. This module:

- Requires root/administrator privileges on all platforms.
- Logs all install and remove operations via `logging.SanitizeLogValue()` per the CFGMS threat model.
- Never handles private key material — only public CA certificates.
- Validates that the `cert_pem` fingerprint matches the resource ID before installing, preventing accidental installation of the wrong certificate under a given fingerprint identity.

Per the CFGMS threat model ("Steward Operating Model"), this module directly implements the "additional trusted publishers, publisher revocations" blast-radius controls. Treat any proposed change to the trust store with the same scrutiny as a change to code signing policy.
