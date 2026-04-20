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

## Shutdown Guarantee

`Manager` has an internal bounded write queue (`defaultQueueCapacity = 1024`) and a background drain goroutine started by `NewManager`. All `RecordEvent` and `RecordBatch` calls enqueue entries for async storage rather than writing synchronously. Two methods guarantee emission completeness during shutdown:

### `Flush(ctx context.Context) error`

Waits until all entries enqueued **before** the call have been persisted. Returns `ctx.Err()` if the context expires before draining completes. Callers should use a generous timeout (e.g. 10 s) to allow the drain loop to finish writing.

```go
flushCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
defer cancel()
if err := auditManager.Flush(flushCtx); err != nil {
    logger.Warn("audit Flush timed out", "error", err)
}
```

### `Stop(ctx context.Context) error`

Calls `Flush` then shuts down the drain goroutine. **Must be called before the storage backend is closed** so in-flight entries are not lost. `Stop` is idempotent — safe to call multiple times.

```go
// In shutdown path, before closing the storage manager:
stopCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
defer cancel()
if err := auditManager.Stop(stopCtx); err != nil {
    logger.Warn("audit Stop error", "error", err)
}
```

### Queue-full behaviour

When the queue is at capacity, `RecordEvent` logs a warning via `slog.Default()` and returns `errQueueFull` — **it does not block the caller**. This is an intentional design choice: audit must never stall application code. The `defaultQueueCapacity = 1024` constant is defined in `manager.go` and easy to tune.

Storage errors (e.g. the underlying store returning an error) are logged by the drain goroutine but do not propagate back to the original caller, because the write is asynchronous.

## Compliance Reporting

Compliance report generation is handled by `features/reports/`, not by this package.
`pkg/audit` does not contain a `ComplianceReporter`; that symbol was removed in
Issue #766 because the implementation was dead code with XSS and CSV-injection
vulnerabilities. Use `features/reports/` for all compliance reporting needs.
