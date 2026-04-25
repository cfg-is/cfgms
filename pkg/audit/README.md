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

## Shutdown Guarantee (Issue #764)

`Manager` owns an internal bounded write queue and a background drain goroutine.
Calls to `RecordEvent` / `RecordBatch` enqueue entries; the drain goroutine writes
them to the underlying `business.AuditStore`. Two methods are provided for
callers that need synchronous durability:

| Method | Semantics |
|---|---|
| `Flush(ctx) error` | Blocks until every entry enqueued **before** this call has been written to the store, or `ctx` is cancelled. Does not close the queue — subsequent `RecordEvent` calls continue to work. |
| `Stop(ctx) error` | `Flush` followed by a one-shot shutdown of the drain goroutine. Idempotent via `sync.Once` — repeated calls return `nil`. After `Stop`, `RecordEvent` returns an error. |

### Typical Shutdown Pattern

```go
// On graceful shutdown of the owning component:
ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
defer cancel()

// Record the final shutdown event, then drain + stop.
_ = auditManager.RecordEvent(ctx, audit.SystemEvent(audit.SystemTenantID, "stop", "shutting down"))
if err := auditManager.Stop(ctx); err != nil {
    logger.Warn("audit manager stop returned an error", "error", err)
}
```

`Stop` must be called **before** the underlying storage manager is closed so
pending entries can still reach disk.

### Queue Capacity and Drop Behaviour

The queue has a fixed capacity of `1024` entries (internal constant
`defaultQueueCapacity`). When the queue is full, `RecordEvent` **does not
block** — instead it drops the entry and emits a `slog.Warn` log containing the
entry ID, action, and resource type. Dropping is intentional: audit recording
must never stall caller goroutines, and a sustained queue-full condition
indicates a slow or stalled storage backend that should be investigated via the
warning logs.

`RecordEvent` returns an error for both the queue-full case and the
post-`Stop` case. Production callers MUST handle the error (typically by
logging a warning) rather than discarding it with `_ =`.

### Flush Ordering Semantics

`Flush` uses a channel-based rendezvous with the drain goroutine. Entries
enqueued **before** the `Flush` call is observed by the drain goroutine are
guaranteed to be written before `Flush` returns. Entries enqueued
**concurrently** (after `Flush` acquired the rendezvous slot) are NOT part of
this flush but will be part of a later `Flush` or `Stop`.

### Caller Obligations

- Every owner of a `Manager` must call `Stop` during graceful shutdown.
- Every production caller of `RecordEvent` must handle the returned error
  (log it; do not silently discard with `_ =`).
- Tests that query the store immediately after `RecordEvent` must call
  `Flush` first, because writes are now asynchronous.

## Tamper-Evidence

Every audit entry carries two chain integrity fields:

| Field | Type | Purpose |
|---|---|---|
| `SequenceNumber` | `uint64` | Monotonically increasing per-tenant counter, assigned by the drain goroutine before persisting |
| `PreviousChecksum` | `string` | HMAC-SHA256 checksum of the immediately preceding entry for the same tenant |

Together these fields form a **keyed hash chain**: to tamper with, delete, or reorder any entry without detection, an attacker would need to recompute every subsequent entry's checksum using the HMAC key — a key that is never stored alongside the audit log.

### HMAC Key

The signing key is sourced from `pkg/secrets` when a `SecretStore` is wired via `WithSecretsStore(store)`. The key name is `"audit/hmac-key"`. If the key does not exist it is generated and stored automatically.

When no secrets store is provided (the default in testing and OSS deployments without key management), a random 32-byte key is generated in-process at startup. Per-entry integrity is preserved within that process run; cross-restart verification requires a persistent key via `WithSecretsStore`.

```go
// Production: wire persistent HMAC key
auditManager, err := audit.NewManager(store, "controller",
    audit.WithSecretsStore(secretsStore))

// Development / testing: ephemeral in-process key (default)
auditManager, err := audit.NewManager(store, "controller")
```

### VerifyChain

`VerifyChain` is a pure in-memory function — it does not re-read from the store. Callers are responsible for providing a complete, sorted slice:

```go
entries, err := auditManager.QueryEntries(ctx, &business.AuditFilter{
    TenantID: tenantID,
    Order:    "asc",
})
// ...
breaks := auditManager.VerifyChain(entries)
for _, b := range breaks {
    log.Printf("chain break at seq=%d entry=%s: %s", b.SequenceNumber, b.EntryID, b.Reason)
}
```

`VerifyChain` reports three violation types:

| Reason prefix | Description |
|---|---|
| `checksum mismatch` | An entry's fields were modified after it was written |
| `previous_checksum mismatch` | An entry does not link to the entry that preceded it |
| `sequence gap` | One or more entries are missing between two consecutive entries in the slice |

Entries with `SequenceNumber == 0` are pre-chain legacy entries (written before Issue #767) and are silently skipped.

### Limitations

The HMAC chain provides **detection** of undetected single-row deletion or reordering by an outsider who lacks the HMAC key. It does **not** prevent a sufficiently privileged storage administrator who also possesses the HMAC key from recomputing all checksums after modification — in that case the attack would be undetectable at the chain level. This is an inherent limitation of keyed hash chains; a Merkle tree anchored to an external immutable record would be required for stronger guarantees.

## Compliance Reporting

Compliance report generation is handled by `features/reports/`, not by this package.
`pkg/audit` does not contain a `ComplianceReporter`; that symbol was removed in
Issue #766 because the implementation was dead code with XSS and CSV-injection
vulnerabilities. Use `features/reports/` for all compliance reporting needs.

## RBAC Permission Events

RBAC permission-check, grant, revoke, and delegate operations are recorded as
`AuditEventAuthorization` entries via `features/rbac.Manager`. Each entry has:

| `AuditEntry` field | Value |
|---|---|
| `EventType` | `AuditEventAuthorization` |
| `ResourceType` | `"permission"` |
| `ResourceID` | The permission ID being checked or granted |
| `UserID` | The subject (user/service) whose access is being evaluated |
| `Action` | `"check_permission"`, `"grant_permission"`, `"revoke_permission"`, or `"delegate_permission"` |
| `Result` | `AuditResultSuccess` (granted), `AuditResultDenied` (denied), `AuditResultError` (system error) |
| `IPAddress` | Source IP from the access request context, if provided |
| `UserAgent` | User agent from the access request context, if provided |
| `Details["reason"]` | Human-readable reason for the decision (check events) |
| `Details["granted_by"]` | Actor who performed the grant (grant events) |
| `Source` | `"rbac"` |

### Querying RBAC Permission Events

Use `rbac.Manager.QueryAuditEntries` (which delegates to `Manager.QueryEntries`) to
retrieve permission events from the durable store:

```go
filter := &business.AuditFilter{
    TenantID:      tenantID,
    UserIDs:       []string{subjectID},
    EventTypes:    []business.AuditEventType{business.AuditEventAuthorization},
    Actions:       []string{"check_permission"},
    ResourceTypes: []string{"permission"},
    TimeRange:     &business.TimeRange{Start: &startTime},
    Limit:         100,
}
entries, err := rbacManager.QueryAuditEntries(ctx, filter)
```

For security monitoring (excessive denials), use `Manager.GetFailedActions`:

```go
tr := &business.TimeRange{Start: &lookback}
failedActions, err := rbacManager.AuditManager().GetFailedActions(ctx, tr, 100)
```

## Secret Manager Events (Issue #864)

Secret store, retrieve, rotate, and delete operations in `features/tenant/security.TenantSecretManager`
are recorded via `pkg/audit.Manager`. Each entry has:

| `AuditEntry` field | Value |
|---|---|
| `EventType` | `AuditEventDataModification` (store/rotate/delete) or `AuditEventDataAccess` (retrieve) |
| `ResourceType` | `"secret"` |
| `ResourceID` | The secret ID |
| `UserID` | `SystemUserID` (`"system"`) — operations are initiated by the secret manager itself |
| `Action` | `"secret.store"`, `"secret.retrieve"`, `"secret.rotate"`, or `"secret.delete"` |
| `Result` | `AuditResultSuccess` on success; `AuditResultError` on failure |
| `ErrorCode` | `"SECRET_OP_FAILED"` when result is `AuditResultError` |
| `Severity` | `AuditSeverityHigh` — all secret operations are sensitive |
| `Source` | `"tenant_secret_manager"` |

### Migration from TenantSecretAuditEntry (Issue #864)

The former `TenantSecretAuditEntry` was constructed in `auditSecretOperation` and discarded
(`_ = entry`). All secret-operation audit events now flow through `pkg/audit.Manager` backed
by durable storage and survive process restarts.

| Old behaviour | Replacement |
|---|---|
| `auditSecretOperation` building a local struct and discarding it | `auditManager.RecordEvent` routes the event to the durable audit store |
| `TenantSecretAuditEntry` struct (still present for in-memory use) | Central `AuditEntry` in the durable store, queryable via `Manager.QueryEntries` |

### Migration from rbac.AuditLogger (Issue #768)

The former `rbac.AuditLogger` in-memory store and its associated types
(`rbac.AuditFilter`, `rbac.ComplianceReport`, `rbac.SecurityAlert`) were deleted in
Issue #768. All permission-check audit events now flow through `pkg/audit.Manager`
backed by durable storage and survive process restarts.

| Old API | Replacement |
|---|---|
| `rbac.NewAuditLogger()` | Built into `rbac.NewManagerWithStorage` — no separate construction needed |
| `auditLogger.LogPermissionCheck(...)` | Called automatically inside `rbac.Manager.CheckPermission` |
| `manager.GetAuditEntries(ctx, &rbac.AuditFilter{...})` | `manager.QueryAuditEntries(ctx, &business.AuditFilter{...})` |
| `manager.GetComplianceReport(ctx, filter)` | Query `QueryAuditEntries` and compute stats; or use `features/reports/` |
| `manager.GetSecurityAlerts(ctx, hours)` | `manager.QueryAuditEntries` with `Results: []business.AuditResult{business.AuditResultDenied}` |
| `manager.ExportAuditLog(ctx, filter, "csv")` | Use `features/reports/` (CSV injection-safe exporter) |
