# Upgrade Lifecycle Runbook

Operator reference for the CFGMS upgrade pipeline introduced by epic
#1917. Covers what each upgrade event means, retention semantics, and
how to use `cfg controller upgrade history` for forensics.

## Quick reference

```bash
# Stage + cut over to a new controller binary
cfg controller upgrade run --binary <path> --config /etc/cfgms/controller.cfg

# Show the last 10 upgrade events (newest first)
cfg controller upgrade history

# Roll back to the quarantined binary (must be within the quarantine window)
cfg controller upgrade rollback --config /etc/cfgms/controller.cfg

# Inspect retention state for a specific event in JSON
cfg controller upgrade history --json | jq '.[] | select(.event_type=="upgrade.pruned")'
```

## The event types

The orchestrator emits a structured event at each transition. Events are
appended (newest last) to `cutover.history.jsonl` next to the state
file (`/var/lib/cfgms/cutover.history.jsonl` on Linux,
`%ProgramData%\cfgms\cutover.history.jsonl` on Windows).

| event_type | When | Operator action |
|---|---|---|
| `upgrade.staged` | New binary validated and about to be spawned. | None — informational. |
| `upgrade.smoketest_passed` | Candidate serving `/api/v1/health` healthy. | None — proceed automatic. |
| `upgrade.smoketest_failed` | Candidate didn't pass health probe. | Read `reason` field; fix binary and re-run. Blue still serving. |
| `upgrade.committed` | Swap completed; new binary is canonical. | None — verify via `status`. |
| `upgrade.rolled_back` | Operator-invoked rollback restored previous binary. | None — verify via `status`. |
| `upgrade.quarantine_expired` | Quarantined backend stopped after the window. | None — informational. Past this point, rollback isn't a one-command operation. |
| `upgrade.pruned` | Retention pruner deleted an old binary. | None — informational. |
| `upgrade.validation_failed` | Validator rejected the binary (bad signature, wrong arch). | Fix the binary supply; nothing was spawned. |
| `upgrade.aborted` | Context cancellation reached the orchestrator. | Re-run when ready; orchestrator is back to idle. |

Each event carries:

- `timestamp` (UTC)
- `binary_path` — the binary the event concerns
- `canonical_binary` — what was canonical at the moment of the event
- `previous_binary` — what was canonical BEFORE the event (only for `committed` / `rolled_back`)
- `duration_ms` — how long the probe took (`smoketest_passed` / `smoketest_failed`)
- `reason` — human-readable explanation (failure events)

## Retention semantics

When a cutover commits successfully, the previous binary is kept on disk
for the configured quarantine window so `rollback` is a one-command
operation. After the window expires, the binary is eligible for pruning,
subject to two caps:

- `MaxVersions` (default 3): keep the N most-recent past-quarantine
  binaries. Anything older is pruned oldest-first.
- `MaxBytes` (default 500 MB): keep total past-quarantine binary size
  below this. Anything pushing over is pruned oldest-first.

The MORE RESTRICTIVE cap wins. A small `MaxBytes` with a large
`MaxVersions` still bounds disk usage; a generous `MaxBytes` with a
tight `MaxVersions` still bounds the number of archives an operator
needs to remember.

Active canonical AND any binary within the quarantine window are
NEVER pruned regardless of caps — the rollback escape hatch is
absolute within that window.

## Forensic playbook

### "What was the last thing pushed and did it succeed?"

```bash
cfg controller upgrade history --limit 5
```

The newest event tells you the current state of the orchestrator.
`upgrade.committed` ⇒ healthy upgrade; `upgrade.smoketest_failed` ⇒
attempt that aborted; `upgrade.rolled_back` ⇒ operator regretted a
recent commit.

### "Has anyone else upgraded today?"

```bash
cfg controller upgrade history --limit 100 --json | jq '[.[] | select(.timestamp > "2026-06-07T00:00:00Z")] | length'
```

### "Why did the last smoketest fail?"

```bash
cfg controller upgrade history --json | jq '.[] | select(.event_type=="upgrade.smoketest_failed") | {ts: .timestamp, reason: .reason, duration_ms: .duration_ms}'
```

### "I rolled back too late — how do I find the binary?"

After `upgrade.quarantine_expired` fires for a binary, it may still be
on disk if retention caps haven't been exceeded. Check the controller
binary archive directory (configured per-deployment) for files whose
`mod_time` matches the rolled-back binary's `binary_path` from the
`upgrade.committed` event.

If `upgrade.pruned` was emitted for that path, the binary is gone — pull
from your backup or rebuild from source.

## Steward-side upgrade lifecycle

The launcher (`cfgms-steward-launcher`) implements the same upgrade
lifecycle observability on the steward side as the controller has for
its own binary. After each supervised restart, the launcher:

1. **Writes a flag file** in `--cert-store-dir` that the steward process
   reads on reconnect and converts to a `steward.upgrade.committed` or
   `steward.upgrade.rolled_back` event reported to the controller.
2. **Prunes old version directories** under `<Root>/versions/` using the
   same retention algorithm as the controller.
3. **Tracks consecutive startup-window failures** in `state.json` so
   operators can see a persistent failure count via `cfgms-steward-launcher status`.

### Steward-side retention defaults

| Setting | Default | Flag |
|---|---|---|
| Quarantine window | 1 h | `--quarantine-window` |
| Max old versions | 3 | `--max-versions` |
| Max total bytes | 500 MB | `--max-bytes` |

These match the controller defaults. Override per-steward by passing the
corresponding flags when registering the launcher as an OS service.

Pruning runs after each **clean** startup (child stayed alive past its
`--startup-window` and exited with code 0). The active version directory is
never pruned regardless of policy.

### Reading the ConsecutiveFailures counter

```bash
cfgms-steward-launcher status --root /opt/cfgms
```

```
Root:                /opt/cfgms
Current:             v1.4.2
Previous:            v1.4.1
ConsecutiveFailures: 0
```

`ConsecutiveFailures` increments on every startup-window failure or non-zero
exit, and resets to 0 on the first clean startup. A non-zero value after the
launcher stabilises means operator intervention is needed: the rollback budget
may be exhausted, or all installed versions are broken.

## What's NOT yet automated (follow-up work)

- **Scheduled retention sweep**: the controller-side Prune helper exists but no
  periodic task wires it up. Operators should call it from cron /
  systemd-timer / Task Scheduler until a built-in scheduler lands.
- **Steward upgrade history view**: `EventStewardUpgradeCommitted` /
  `EventStewardUpgradeRolledBack` events reach the controller's
  `handleEventFromProvider` default case and are not yet stored in
  `UpgradeStore`. A future story must wire that subscription and expose
  a REST endpoint before per-steward upgrade history is surfaced in
  `cfg controller upgrade history`.

These are tracked as follow-up tasks.
