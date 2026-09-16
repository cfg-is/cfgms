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
| `passwd` | `passwd`, `PASSWD`, `old_passwd` |
| `secret` | `secret`, `client_secret`, `some_secret` |
| `token` | `token`, `api_token`, `access_token` |
| `api_key` | `api_key`, `MY_API_KEY` |
| `apikey` | `apikey`, `apiKey` |
| `credential` | `credential`, `credentials` |
| `private_key` | `private_key`, `PRIVATE_KEY` |
| `privatekey` | `privateKey`, `myPrivateKey` (the no-underscore spelling `private_key` misses) |
| `access_key` | `access_key`, `AWS_ACCESS_KEY` |
| `auth` | `auth`, `auth_token`, `x-auth`, `Authorization`, `authentication`, `proxy-authorization` — a plain substring match, with a short exact-match exemption for attribution keys (Issue #4098) |

`auth`'s attribution exemption: a key containing `auth` is redacted **unless the
whole key** is one of the attribution names below, compared after lowercasing and
stripping non-alphanumeric characters (`Authorized-By`, `authorized_by` and
`authorizedBy` are therefore one entry):

`author`, `authors`, `authored_by`, `authorized_by`, `authorised_by`,
`author_name`, `author_email`, `authorized_by_id`

The exemption is exact-match and fail-closed: anything else containing `auth` is
redacted, including `Authorization` and `authentication` headers. Only the whole
key is exempt — `author_token` is still redacted, by the `token` term.

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

> **Note:** this snippet matches the real check for every token; it differs only
> in that the real check exempts the handful of exact attribution keys listed
> above from the `auth` term. It therefore over-predicts redaction for `author`
> and `authorized_by`, and never under-predicts it.

### Extending the Deny-List

`audit.RedactedKeys` is exported so callers can append domain-specific terms:

```go
audit.RedactedKeys = append(audit.RedactedKeys, "msp_license_key")
```

> **Warning:** Appending to `RedactedKeys` after `NewManager` is called is not goroutine-safe. Configure it once, before the first `RecordEvent` call.

### Scope of Redaction

Redaction is not string-only and not one level deep (Issue #4098). A sensitive
key redacts its value outright regardless of Go type; a non-sensitive key
holding a nested map or slice is descended into; and a string value under a
non-sensitive key is itself scanned for an embedded `key=value` secret using
the same pattern applied to `ErrorMessage`.

| Field | Redacted? | Notes |
|---|---|---|
| `Details` | Yes | Any value under a sensitive key, of any Go type; nested maps and slices are scanned recursively; string values under non-sensitive keys are scanned for embedded `key=value` secrets |
| `Changes.Before` | Yes | Same as `Details` |
| `Changes.After` | Yes | Same as `Details` |
| `Changes.Fields` | No | Field names (not values) are never redacted |
| `ErrorMessage` | Yes | `key=value`, `key: value`, and `"key":"value"` pairs where key matches deny-list; the full value is redacted even if it contains spaces |
| Non-string values under a sensitive key | Yes | Redacted regardless of Go type (int, bool, float, nested map, slice, ...) |

## Shutdown Guarantee (Issue #764)

`Manager` owns an internal bounded write queue and a background drain goroutine.
Calls to `RecordEvent` / `RecordBatch` enqueue entries; the drain goroutine writes
them to the underlying `business.AuditStore`. Two methods are provided for
callers that need synchronous durability:

| Method | Semantics |
|---|---|
| `Flush(ctx) error` | Blocks until every entry enqueued **before** this call has been written to the store, or `ctx` is cancelled. Does not close the queue — subsequent `RecordEvent` calls continue to work. On every non-cancelled return, reports a non-nil error naming the cumulative count of permanently lost entries (see below), or `nil` if none have been lost. |
| `Stop(ctx) error` | `Flush` followed by a one-shot shutdown of the drain goroutine. Idempotent via `sync.Once` — repeated calls are safe. After `Stop`, `RecordEvent` returns an error. Like `Flush`, every call — including calls after the first — reports the current cumulative lost-entry count. |

### Retry and Lost-Entry Reporting (Issue #4098)

A failed `AppendChainedEntry` call is retried with bounded backoff
(`maxAppendAttempts`, currently 3 attempts total) before the drain goroutine
gives up on that entry. Once retries are exhausted the entry is counted in an
internal cumulative counter and logged at `Error`. `RecordEvent` has already
returned successfully by that point — its asynchronous contract is unchanged —
so the loss cannot be reported back to the original caller directly. Instead,
`Flush` and `Stop` both return a non-nil error naming the total count on every
call, for the life of the `Manager`; the count is never cleared on read, so a
second `Stop` after a first reported loss still reports it. Callers that need
to know whether an audit event actually reached durable storage must check the
error returned by `Flush` or `Stop`, not just the error returned by
`RecordEvent`.

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

The `Checksum` field covers every field of the entry except `Checksum` itself
(Issue #4098). This is a hard break, not a migration: entries checksummed
before this change do not verify, and are not re-signed — `VerifyChain`
reports them as a `checksum mismatch` the same as any other tampered entry.

Each field is fed to the HMAC length-prefixed, as
`<decimal byte length> ":" <value>`, and `Tags` is written as a length-prefixed
element count followed by each tag framed the same way. The encoding is
therefore injective: no two distinct field assignments produce the same hash
input. This matters because several covered fields are attacker-influenced
(`UserAgent`, `Path`, `ResourceName`, `ErrorMessage`) and
`logging.SanitizeLogValue` strips only control characters. Joining the values
around a delimiter instead would let an attacker who plants that delimiter in
one field later shift the boundary between two adjacent fields — re-partitioning
the stored content while the recomputed HMAC still matched.

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

`VerifyChain` reports four violation types:

| Reason prefix | Description |
|---|---|
| `sequence number missing` | An entry has `SequenceNumber == 0` — see below |
| `checksum mismatch` | An entry's fields were modified after it was written |
| `previous_checksum mismatch` | An entry does not link to the entry that preceded it |
| `sequence gap` | One or more entries are missing between two consecutive entries in the slice |

Entries with `SequenceNumber == 0` are **rejected**, not skipped (Issue #4098):
`VerifyChain` reports a `ChainBreak` for them rather than passing them through
unverified. This was previously a silent skip on the theory that such entries
were pre-chain legacy data (written before Issue #767); the checksum-coverage
change in Issue #4098 (see below) is a hard break with no migration path, which
removes that legacy class entirely — there is nothing left to protect by
special-casing sequence zero.

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

## Tenant Security Audit Events (Issue #865)

The four core security log methods in `features/tenant/security.TenantSecurityAuditLogger`
forward events to `pkg/audit.Manager` for durable storage in addition to the in-memory window.
Two methods (`LogVulnerabilityStatusChange`, `LogRemediationAction`) remain in-memory only
and are not forwarded (deferred to a follow-up story).

| Method | `Action` | `ResourceType` | `ResourceID` | `Result` |
|---|---|---|---|---|
| `LogIsolationRuleChange` | `"tenant.isolation.rule_change"` | `"isolation_rule"` | tenant ID | `AuditResultSuccess` |
| `LogAccessAttempt` | `"tenant.access.attempt"` | `"tenant_access"` | `request.SubjectID` | `AuditResultSuccess` (granted) / `AuditResultDenied` (denied) |
| `LogPolicyViolation` | `"tenant.policy.violation"` | `"policy"` | policy ID | `AuditResultError` |
| `LogComplianceViolation` | `"tenant.compliance.violation"` | `"compliance_framework"` | framework name | `AuditResultError` |

Additional `Details` fields per method:

| Method | `Details` keys |
|---|---|
| `LogIsolationRuleChange` | `change_type`, `old_rule`, `new_rule` |
| `LogAccessAttempt` | `granted`, `reason` |
| `LogPolicyViolation` | `violation`, plus all keys from the caller-provided `context` map |
| `LogComplianceViolation` | `requirement`, `violation` |

`LogIsolationRuleChange` and `LogComplianceViolation` set `UserID` to `SystemUserID` (`"system"`);
`LogAccessAttempt` and `LogPolicyViolation` set `UserID` to the subject's ID.

Audit failures (`RecordEvent` returns error) are logged via `slog.Warn` but do not prevent
the in-memory append — the in-memory window remains observable even when durable storage is unavailable.

### In-Memory Cap

The in-memory entry window is capped at 1000 entries with FIFO eviction. All six `Log*` methods
share the `addEntry` path and count toward the cap, including the two deferred methods.
The cap applies only to the in-memory window; the durable store retains all forwarded entries.

### Querying Tenant Security Audit Events

```go
filter := &business.AuditFilter{
    TenantID:      tenantID,
    ResourceTypes: []string{"isolation_rule", "tenant_access", "policy", "compliance_framework"},
    TimeRange:     &business.TimeRange{Start: &startTime},
    Limit:         100,
}
entries, err := auditManager.QueryEntries(ctx, filter)
```
