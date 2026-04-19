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

## Compliance Reporting

Compliance report generation is handled by `features/reports/`, not by this package.
`pkg/audit` does not contain a `ComplianceReporter`; that symbol was removed in
Issue #766 because the implementation was dead code with XSS and CSV-injection
vulnerabilities. Use `features/reports/` for all compliance reporting needs.
