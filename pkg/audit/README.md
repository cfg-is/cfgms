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

## Shutdown Guarantee

`pkg/audit.Manager` maintains an internal bounded write queue (`defaultQueueCapacity = 1024` entries). Events are enqueued by `RecordEvent` and `RecordBatch` in the caller's goroutine, then drained to the store by a single background goroutine. This keeps the caller non-blocking even when the store is slow.

### Flush and Stop

```go
// Flush blocks until all queued entries have been written to the store.
// Use this when you need to read back entries immediately after recording them.
if err := auditManager.Flush(ctx); err != nil {
    logger.Warn("audit flush interrupted", "error", err)
}

// Stop flushes in-flight entries and then shuts down the drain goroutine.
// Call Stop in server.Stop() before closing the storage manager.
if err := auditManager.Stop(ctx); err != nil {
    logger.Warn("audit stop failed", "error", err)
}
```

`Stop` is idempotent — safe to call multiple times. The second call is a no-op.

### Queue-Full Behaviour

When the queue is full (1024 entries buffered), `RecordEvent` **drops the entry and logs a warning** rather than blocking the caller. Audit must never stall application code. If you observe drop warnings in production, increase the `defaultQueueCapacity` constant in `pkg/audit/manager.go`.

### Shutdown Sequence

The correct shutdown order in `server.Stop()` is:

1. Record the shutdown audit event (`RecordEvent`)
2. Stop other subsystems that may emit audit events
3. **Call `auditManager.Stop(ctx)`** — flushes all in-flight events
4. Close the storage manager

`auditManager.Stop` must run before the storage manager is closed so that draining
entries have a live store to write to.

## Compliance Reporting

Compliance report generation is handled by `features/reports/`, not by this package.
`pkg/audit` does not contain a `ComplianceReporter`; that symbol was removed in
Issue #766 because the implementation was dead code with XSS and CSV-injection
vulnerabilities. Use `features/reports/` for all compliance reporting needs.
