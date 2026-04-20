# pkg/audit

Unified audit system for all CFGMS components. Provides tamper-evident, validated audit entries stored via pluggable storage backends.

## Sentinel Constants

System-internal events use these sentinel values so callers are not scattered with raw string literals:

| Constant | Value | Purpose |
|---|---|---|
| `SystemTenantID` | `"system"` | Tenant ID for controller-internal events |
| `SystemUserID` | `"system"` | User ID for system-originated events |

> **Note:** These are a known workaround for controller identity. See TODO(#751) for the planned replacement with real tenant/user identity.

## Constructor

`NewManager` returns `(*Manager, error)` — callers must handle the error:

```go
auditManager, err := audit.NewManager(store, "controller")
if err != nil {
    return nil, fmt.Errorf("failed to initialize audit manager: %w", err)
}
```

Errors are returned (not panicked) when `store` is nil or `source` is empty.

## Minimal SystemEvent Example

```go
event := audit.SystemEvent(audit.SystemTenantID, "controller_start", "Controller started on :8443")
if err := auditManager.RecordEvent(ctx, event); err != nil {
    logger.Warn("Failed to record startup audit event", "error", err)
}
```

`SystemEvent` sets `ResourceID` to `"controller"` so the entry passes `validateEntry`. No additional builder calls are required.

## Minimal SecurityEvent Example

```go
event := audit.SecurityEvent(tenantID, userID, "brute_force_detected", "5 failed logins in 60s", audit.AuditSeverityHigh)
if err := auditManager.RecordEvent(ctx, event); err != nil {
    logger.Warn("Failed to record security audit event", "error", err)
}
```

`SecurityEvent` uses `userID` as both the user and the `ResourceID`, satisfying validation.

## Sensitive Data Redaction

All audit entries have sensitive field values automatically redacted at `build()` time — before the entry reaches the store or the write queue. The redaction is performed in memory, so even in-memory audit inspection will not see raw secrets.

### Default Deny-List

Values whose **key name** (case-insensitive substring match) contains any of the following tokens are replaced with `[REDACTED]`:

| Token | Example keys matched |
|---|---|
| `password` | `password`, `user_password`, `OLD_PASSWORD` |
| `secret` | `secret`, `client_secret`, `some_secret` |
| `token` | `token`, `api_token`, `access_token` |
| `api_key` | `api_key`, `MY_API_KEY` |
| `apikey` | `apikey`, `apiKey` |
| `credential` | `credential`, `credentials` |
| `private_key` | `private_key`, `privateKey` |
| `access_key` | `access_key`, `AWS_ACCESS_KEY` |
| `auth` | `auth`, `authorization`, `x_auth_token` |

### Checking Whether a Key Will Be Redacted

```go
import "strings"

func willBeRedacted(key string) bool {
    lower := strings.ToLower(key)
    for _, deny := range audit.RedactedKeys {
        if strings.Contains(lower, deny) {
            return true
        }
    }
    return false
}
```

### Extending the Deny-List

`audit.RedactedKeys` is exported so callers can append domain-specific terms:

```go
audit.RedactedKeys = append(audit.RedactedKeys, "msp_license_key")
```

> **Warning:** Appending to `RedactedKeys` after `NewManager` is called is not goroutine-safe. Configure it once, before the first `RecordEvent` call.

### Scope of Redaction

| Field | Redacted? | Notes |
|---|---|---|
| `Details` | Yes | String values with sensitive key names |
| `Changes.Before` | Yes | String values with sensitive key names |
| `Changes.After` | Yes | String values with sensitive key names |
| `Changes.Fields` | No | Field names (not values) are never redacted |
| `ErrorMessage` | Yes | `key=value` pairs where key matches deny-list |
| Integer/bool values | No | Only string values are replaced |

## Compliance Reporting

Compliance report generation is handled by `features/reports/`, not by this package.
`pkg/audit` does not contain a `ComplianceReporter`; that symbol was removed in
Issue #766 because the implementation was dead code with XSS and CSV-injection
vulnerabilities. Use `features/reports/` for all compliance reporting needs.
