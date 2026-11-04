# Upgrade Lifecycle Reference

Use this reference to distinguish upgrade status sources. For execution, start
with the [controller](controller-upgrade.md), [rolling cluster](rolling-cluster-upgrade.md)
or [fleet steward](../deployment/fleet-upgrades.md) procedure.

## Which status describes which operation?

| Operation | Status/evidence | Limits |
|---|---|---|
| Supported controller restart | CLI result, service logs, HTTPS `/api/v1/ready`, steward reconnect/query checks | Does not append to the cutover history file or create an experimental quarantine slot. |
| Steward upgrade dispatch | Returned `upgrade_id` and `GET /api/v1/stewards/upgrade/{upgrade_id}` | Durable dispatch/status records are distinct from launcher event ingestion. |
| Ringed fleet rollout | `rollout_id` and `GET /api/v1/rollout/{rollout_id}` | Stored progress does not establish automatic resumption after controller restart. |
| Steward launcher | Local launcher state and upgrade flag events | Local retention and failure counters are not controller cutover history. |
| Experimental controller port swap | Local `cutover.history.jsonl` and cutover state | Frozen experimental path; not the supported production procedure. |

## Local experimental cutover history

`cfg controller upgrade history` reads the local cutover JSONL file, not a
fleet-wide or cluster-wide history API. It does not report supported restart
upgrades. A missing/empty history file is not evidence that no restart occurred.

```bash
cfg controller upgrade history --limit 5
cfg controller upgrade history --json
```

Select a non-default file with `--history`. Defaults are
`/var/lib/cfgms/cutover.history.jsonl` on Linux and
`%ProgramData%\cfgms\cutover.history.jsonl` on Windows.

The experimental orchestrator emits staged, smoketest-passed/failed, committed,
rolled-back, quarantine-expired and aborted transitions. A smoketest checks
HTTPS `/api/v1/ready`, including durable storage. Records include `event_type`,
`timestamp`, binary paths and, where applicable, `reason` and `duration_ms`.
The event schema also defines validation/pruning event types; a defined type
alone does not prove a production producer or scheduled task is wired.

The controller cutover retention helper is not called by a production retention
scheduler. Do not schedule a nonexistent prune CLI or apply its quarantine
promises to the supported restart path. Follow the selected procedure's backup
and rollback instructions.

## Dispatching and rolling back steward upgrades from the console

Steward upgrades can also be dispatched from the **Installer** page of the web
console, under *Upgrade stewards*, instead of `POST /api/v1/stewards/upgrade`:

1. Enter a target selector, the version, the platform (`windows`, `darwin`,
   `linux`) and the architecture (`amd64`, `arm64`), then choose
   **Dispatch upgrade**. Dispatch needs a fresh passkey tap; cancelling the
   prompt sends nothing.
2. The page shows the returned `upgrade_id` and the steward count, and checks
   `GET /api/v1/stewards/upgrade/{upgrade_id}` every 3 seconds until the status
   is `committed`, `rolled_back` or `failed`.
3. To roll back, enter the version to restore and choose **Roll back**, then
   **Confirm** (the request is sent only on Confirm; **Cancel** abandons it).
   This calls `POST /api/v1/stewards/upgrade/{upgrade_id}/rollback` and needs no
   passkey tap.

## Starting and halting a fleet rollout from the console

A ringed fleet rollout can be driven from the **Installer** page, under *Fleet
rollout*, instead of calling `POST /api/v1/rollout` directly:

1. Enter the target version (and, optionally, a tenant path; blank uses your
   own tenant) and choose **Start rollout**. Start needs a fresh passkey tap;
   cancelling the prompt sends nothing.
2. The page shows the `rollout_id` and checks `GET /api/v1/rollout/{rollout_id}`
   every 3 seconds until the rollout is no longer `in-progress`. When the
   controller cannot query ring health the page says *metrics unavailable* with
   the reason, and shows no on-version, failed or pending numbers — they are
   unknown, not zero.
3. To stop it, choose **Halt**, then **Confirm** (the request is sent only on
   Confirm; **Cancel** abandons it). This calls
   `POST /api/v1/rollout/{rollout_id}/halt` and needs no passkey tap.

## Steward launcher state and retention

`cfgms-steward-launcher` supervises the steward and records startup failures in
its local `state.json`. Inspect an installed launcher's configured root:

```bash
cfgms-steward-launcher status --root /opt/cfgms
```

`ConsecutiveFailures` increments on startup-window failures or non-zero exits,
and resets after a clean startup. Repeated failures require local service/log
inspection; a counter alone does not identify the underlying defect.

After a clean startup, the launcher prunes old version directories. The active
version and versions younger than the quarantine window are retained. Older
versions are subject to both count and byte limits:

| Flag | Default |
|---|---|
| `--quarantine-window` | `1h` |
| `--max-versions` | `3` old versions |
| `--max-bytes` | `524288000` bytes (500 MiB) |

This is launcher-local pruning, not a controller scheduled sweep. Configure the
flags on the installed launcher service when overriding these defaults.

The launcher writes flag files that the steward publishes on reconnect as
`steward.upgrade.committed` or `steward.upgrade.rolled_back`. The controller's
current event handler does not persist these event types into upgrade history.
Do not equate their publication with a completed end-to-end event history view;
the durable upgrade dispatch/status API is a separate mechanism.
