# Controller Upgrade Runbook

How to upgrade a CFGMS controller in production using the blue/green
cutover flow introduced by epic #1917 (Story C, #1920).

## When to use this

Use this runbook when you have a new `cfgms-controller` binary to deploy
to a running controller host AND you cannot tolerate more than ~10
seconds of API unavailability for connected stewards.

This is the controller side of the zero-downtime upgrade epic. The
steward-side counterpart is the launcher binary (Story A, #1918) which
operates on a different mechanism (atomic-swap-with-rollback for the
steward).

## What happens during a cutover

1. **Validate.** `cfg controller upgrade run --binary <path>` checks
   the new binary exists and is executable.
2. **Smoketest.** A candidate instance of the new binary is spawned on
   the candidate listen addresses (default `:8081` for API and `:4434`
   for transport). The orchestrator probes its `/healthz` endpoint
   until it responds (or the smoketest timeout, default 30s, elapses).
3. **Drain.** The current canonical binary receives a graceful shutdown
   signal (SIGTERM on Unix, Ctrl-Break on Windows) and is given up to
   `PortHandoffTimeout` (default 5s) to finish in-flight requests.
4. **Port handoff.** The orchestrator waits for the canonical TCP ports
   to actually free at the OS level (TIME_WAIT linger, especially on
   Windows loopback).
5. **Stop candidate.** The smoketest instance of the new binary
   releases its candidate ports.
6. **Spawn canonical.** A fresh instance of the new binary is started
   on the canonical ports.
7. **Readiness probe.** The new canonical is probed to confirm it
   accepts connections.
8. **Park previous.** The previous binary path is recorded as the
   quarantined rollback target. The quarantine window (default 1h)
   controls how long the rollback remains a one-command operation.

Total wall-clock time: typically 5-15 seconds. Stewards experience
~1-3 seconds of API unavailability during the port handoff, well
under the 10-second AC bound from the epic. The gRPC-over-QUIC
client reconnect logic handles the transient outage transparently.

## Commands

```bash
# Upgrade the canonical binary to v0.5.11
cfg controller upgrade run \
    --binary /opt/cfgms/cfgms-controller-v0.5.11 \
    --config /etc/cfgms/controller.cfg

# See which binary is canonical and which is in the quarantine slot
cfg controller upgrade status

# Roll back to the quarantined binary (if recent upgrade misbehaves)
cfg controller upgrade rollback \
    --config /etc/cfgms/controller.cfg
```

The CLI also accepts:

- `--canonical-api-addr` / `--canonical-transport-addr` — override the
  canonical listen addresses (defaults `:8080` / `:4433`).
- `--candidate-api-addr` / `--candidate-transport-addr` — override the
  candidate listen addresses (defaults `:8081` / `:4434`).
- `--quarantine-window` — how long the previous binary stays available
  for rollback. Default 1h.
- `--smoketest-timeout` — cap on the smoketest probe duration. Default 30s.
- `--state` — path to the cutover state file. Default:
  `/var/lib/cfgms/cutover.state.json` (Linux) or
  `%ProgramData%\cfgms\cutover.state.json` (Windows).

## Recovering from a failed cutover

| Failure | Symptom | Recovery |
|---------|---------|----------|
| Candidate fails smoketest | CLI surfaces `cutover: candidate smoketest failed: <reason>` and exits non-zero | The original canonical was never touched — it's still serving. Investigate the failure reason (logs in the candidate's stdout/stderr) and try again with a fixed binary. |
| Canonical port did not free | CLI surfaces `canonical API port :8080 did not free` and exits non-zero | The previous canonical didn't drain in time. The orchestrator force-stopped it; the operator may need to manually kill any zombie process holding the port. Then re-run. |
| New canonical fails readiness | CLI surfaces `cutover: post-swap readiness probe failed: <reason>` | The new binary is broken. The orchestrator stopped it. The CANONICAL PORTS ARE FREE; stewards have no controller to talk to. Immediately re-run with the previous binary path, or run `cfg controller upgrade rollback` if a quarantined slot exists. |
| `cfg controller upgrade rollback` fails | CLI surfaces a swap or spawn error | The state file still records the previously-canonical binary; re-run rollback after addressing the underlying error. |

## What's NOT in this version (deferred follow-ups)

- **Bundle signature verification.** The orchestrator's `Validator`
  interface is implemented as a no-op pending epic #1882. Operators
  must trust the binary path they supply.
- **Stewards-stay-connected integration test.** The full
  connected-steward-survives-upgrade test (#1920 [REQUIRED TEST])
  needs Docker infrastructure with a real controller + steward and
  belongs to follow-up work.
- **Quarantined-backend running on alternate ports.** This MVP's
  quarantine slot records only the path of the previous binary, not
  a live process. Rollback respawns the previous binary on canonical
  ports (another ~2s of unavailability). A future enhancement could
  keep the previous binary RUNNING on alternate ports for instant
  rollback, but it requires runtime port-rebind in the controller
  server.

## See also

- [Operating model — Concurrent Controller Execution](../architecture/operating-model.md)
- Epic [#1917](https://github.com/cfg-is/cfgms/issues/1917) — Zero-downtime upgrades
- Story [#1920](https://github.com/cfg-is/cfgms/issues/1920) — Cutover router + CLI
- Story [#1919](https://github.com/cfg-is/cfgms/issues/1919) — Multi-bind + storage concurrency substrate
