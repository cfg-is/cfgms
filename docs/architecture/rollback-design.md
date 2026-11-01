# Configuration Rollback

## Status

Configuration rollback is implemented in `features/config/rollback`, exposed over REST under `/api/v1/rollback` (`features/controller/api/rollback_handler.go`) and on the CLI as `cfg config rollback`. Rollback points are versions in the `ConfigStore`; rollback operations and their audit trails are persisted as `ConfigStore` entries.

## Components

All of the following live in `features/config/rollback`:

- **`RollbackManager`** (`DefaultRollbackManager`, `manager.go`) — `ListRollbackPoints`, `PreviewRollback`, `ExecuteRollback`, `GetRollbackStatus`, `CancelRollback` and `ListRollbackHistory`. Reads version history from the `ConfigStore`.
- **`RollbackValidator`** (`DefaultRollbackValidator`, `validator.go`) — validates the target, the rollback type and the caller's permissions, detects breaking changes, checks module dependencies and module compatibility, checks system health, and produces a `RiskAssessment` (overall risk level, data-loss risk, estimated downtime, estimated affected users).
- **`RollbackNotifier`** (`notifier.go`) — `DefaultRollbackNotifier` logs started, progress, completed and failed events; `WebhookNotifier` posts them to a webhook URL with exponential backoff (1 s base delay, 10 s per-request timeout); `CompositeNotifier` fans out to several notifiers.
- **`RollbackStore`** — `StorageRollbackStore` (`storage_store.go`) persists each `RollbackOperation` as a YAML `ConfigStore` entry under tenant `system`, namespace `rollback-operations`, name = operation ID, with target type, target ID and status in the entry metadata. `InMemoryRollbackStore` (`store.go`) serves tests.

## Types

Defined in `types.go`:

| Kind | Values |
|------|--------|
| Rollback type | `full`, `partial` (named configurations), `module` (named modules), `emergency` |
| Target type | `device`, `group`, `client`, `msp`, `steward` |
| Operation status | `pending`, `validating`, `approval_required`, `in_progress`, `completed`, `failed`, `cancelled` |

Each `RollbackPoint` carries the version identifier (`commit_sha`), timestamp, author, message, the configurations it touches, a risk level and `can_rollback`.

## Workflow

`ExecuteRollback`:

1. Rejects the request with `ROLLBACK_IN_PROGRESS` (HTTP 409) if another rollback for the same target has not reached a terminal status.
2. Runs `PreviewRollback`, which diffs the target's current version against `rollback_to`, filters the changes by rollback type, and runs the validator.
3. Rejects the request when validation fails, unless `options.force` is set.
4. Requires an `approval_id` when the preview's risk assessment is high or critical, reports data-loss risk, or estimates more than 100 affected users. `emergency: true` bypasses the approval requirement. A missing `approval_id` returns `APPROVAL_REQUIRED`.
5. Persists the operation as `pending`, records a `rollback_initiated` audit entry, sends the started notification, and returns HTTP 202.

The operation then runs asynchronously through the stages `validating` (10 %), `executing` (20 %), `applying_changes` (40–80 %, one step per change), `merging` (85 %), `deploying` (90 %) and `completed` (100 %). Every stage appends an audit entry; a failure at any stage sets the status to `failed`, records the error, and sends the failed notification.

`CancelRollback` succeeds only while the operation is `pending`, `validating` or `approval_required`, and records who cancelled it and why.

## REST API

Every route requires the `config:rollback` permission.

| Method and path | Response |
|-----------------|----------|
| `GET /api/v1/rollback/points?target_type=…&target_id=…&limit=50` | `{"rollback_points": [...]}` |
| `POST /api/v1/rollback/preview` | `{"preview": {...}}` — changes, affected modules, validation results, estimated duration, `requires_approval`, risk assessment |
| `POST /api/v1/rollback/execute` | HTTP 202, `{"rollback": {...}}` — the operation with its `id`, `status` and `progress` |
| `GET /api/v1/rollback/{rollback_id}/status` | `{"rollback": {...}}` — the operation including `result` and `audit_trail` |
| `POST /api/v1/rollback/{rollback_id}/cancel` | `{"message": "Rollback cancelled successfully"}` |
| `GET /api/v1/rollback/history?target_type=…&target_id=…&limit=…` | `{"rollback_operations": [...]}` |

Request body for preview and execute:

```json
{
  "target_type": "steward",
  "target_id": "steward-abc123",
  "rollback_type": "full",
  "rollback_to": "<version>",
  "reason": "Reverting problematic firewall update",
  "emergency": false,
  "approval_id": "",
  "configurations": [],
  "modules": [],
  "options": { "force": false }
}
```

`reason` is required unless `emergency` is true.

## CLI

```bash
cfg config rollback <steward-id>                       # list rollback points
cfg config rollback <steward-id> --to <version> --dry-run   # preview
cfg config rollback <steward-id> --to <version>        # execute and poll status
```

The execute form polls `GET /api/v1/rollback/{id}/status` every 2 seconds until the operation reaches a terminal status. A 409 response means another rollback is already in progress for that steward.

## Storage integration

- Historical configurations come from the `ConfigStore`.
- Operations and audit entries are persisted through `StorageRollbackStore` into the `ConfigStore`, so they survive controller restarts and are visible to every controller node that shares the store.
- See [Storage Architecture](storage-architecture.md) for the storage model.
