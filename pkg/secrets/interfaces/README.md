# pkg/secrets/interfaces

This package defines the contracts for CFGMS secret storage. All secret backends —
SOPS, steward, and future vault-class providers — implement the interfaces here.

## Interface Surface

| Interface | File | Purpose |
|-----------|------|---------|
| `SecretStore` | `secret_store.go` | Core CRUD, versioning, rotation, metadata, lifecycle |
| `SecretProvider` | `provider.go` | Auto-registration pattern; creates `SecretStore` instances |
| `LeasedSecret` | `leased_secret.go` | Optional mixin for dynamic-secret leasing (vault-class only) |

## Mixin Pattern

`LeasedSecret` is an **optional mixin**. It is not part of `SecretStore` because most
providers are static-secret providers that do not support per-request dynamic credentials.
Callers check for the capability at runtime with a type assertion:

```go
// Always safe — falls back gracefully if provider is static-only.
if ls, ok := store.(interfaces.LeasedSecret); ok {
    secret, lease, err := ls.LeaseSecret(ctx, "db/creds", &interfaces.LeaseRequest{
        TTL:       time.Hour,
        Renewable: true,
    })
    // ... use secret, remember to revoke lease when done
    defer ls.RevokeLease(ctx, lease.ID)
}
```

Never call lease methods without the type-assertion guard. Static providers will simply
not satisfy the interface.

## When to Implement `LeasedSecret`

Implement `LeasedSecret` when the provider generates credentials **on-demand per request**
and the credential has a bounded lifetime that the provider tracks (a lease). Classic
examples:

- HashiCorp Vault / OpenBao database secrets engine — generates a unique DB user per lease
- AWS Secrets Manager dynamic credentials — scoped IAM credentials with automatic rotation
- Azure Key Vault managed identities — time-bounded access tokens

**Do not implement `LeasedSecret` for**:

- File-based providers (SOPS, flat-file) — secrets are stored, not generated
- OS-keychain providers (steward) — secrets are stored and retrieved, not leased
- Any provider where the same credential value is returned on every `GetSecret` call

## Provider Capability Matrix

| Provider | Package | Secret model | `LeasedSecret` |
|----------|---------|-------------|----------------|
| SOPS | `pkg/secrets/providers/sops` | Static — encrypted files in git | No |
| Steward | `pkg/secrets/providers/steward` | Static — OS-native encrypted blobs | No |
| OpenBao (future) | `pkg/secrets/providers/openbao` | Static + dynamic leased | Yes |
| AWS Secrets Manager (future) | `pkg/secrets/providers/awssm` | Static + dynamic leased | Yes |
| Azure Key Vault (future) | `pkg/secrets/providers/azkv` | Static + dynamic leased | Yes |

## `Policy` Field on `SecretMetadata`

`SecretMetadata.Policy map[string]any` carries provider-specific access-control and
lease-policy parameters as an opaque map. SOPS and steward providers always leave it
`nil`. Vault-class providers may populate it with fields such as `ttl`, `max_leases`,
or `bound_ips`.

**Security note**: Never log or expose `Policy` contents — they may contain sensitive
policy identifiers. Use `logging.SanitizeLogValue` for any secret key or lease ID that
appears in log lines.

## `ProviderCapabilities.SupportsLeasing`

`ProviderCapabilities.SupportsLeasing` (declared in `provider.go`) is the static
flag a provider sets in `GetCapabilities()` to advertise that it supports dynamic
leasing. `LeasedSecret` is the runtime-checkable counterpart: if a store value
satisfies `LeasedSecret`, the provider supports leasing for that store instance.
Both should be consistent, but callers must use the type assertion — not the flag —
when dispatching actual lease operations.
