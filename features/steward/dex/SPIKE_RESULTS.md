# DEX Windows Acquisition Spike — Measured Results (#2540)

Measurement deliverable for the DEX ETW/WMI acquisition spike (#2516), running the
acquisition harness merged in #2517 (`features/steward/dex/`). #2517 shipped the
harness but **no numbers** (hosted CI runners lack ETW `StartTrace` privilege, so
`TestCollectorRunShort` auto-skips). This document records a **real, privileged
run** and answers the spike's question: *per-signal reachable? + sustained %CPU vs
the 1.0% budget.*

This is acquisition + measurement only (throwaway `SpikeReport`). No persistence,
no schema, no production DEX/cfg/control-plane surface — the DEX collection track
stays gated on the storage-shape ADR + ADR-017 Amendment 1.

## ⚠️ What these numbers do and do NOT prove

This spike proves the provider **enablement** path only. It does **not** prove we
can consume the event stream, and the overhead figure is **not** a collection cost:

- **The harness has no event consumer.** `runETWConsumer` is a no-op
  (`<-ctx.Done()` — it waits out the window). The `ProcessTrace` consumer that
  #2517 originally had was **removed** because the native ETW→Go callback on a
  locked OS thread corrupts the Go runtime (`acquireSudog` / `cgocallbackg` per-P
  state; atomic-only callback bodies do not prevent it). See the collector comment.
- **"Reachable: YES" means "we can enable the provider"** (`StartTrace` +
  `EnableTraceEx2` succeed under privilege) — **not** "we can read its events."
- **`total_events: 0` is by construction**, not a measurement of low activity —
  nothing consumes the buffers.
- **The ~0.00–0.05% CPU figure is the cost of *enabling* providers with the
  buffers undrained** — it is **NOT** the cost of consume + decode + attribute at
  volume. Do not read "PASS" as "DEX fits the 1% budget"; the real collection
  overhead is unmeasured.

Whether an in-steward Go agent can actually consume + decode + attribute the
stream (and at what real overhead) is the subject of the follow-up feasibility
spikes: **#2571** (Windows) and **#2572** (Linux). This document is the
enablement + reachability baseline they build on.

## Run context (proof of real run)

The spike was executed **in the steward's own service context** — the faithful
deployment context, not merely an elevated shell — via the signed inline-exec
admin channel (`cfg steward exec`) to the CFG-70-02 steward, which runs as
`LocalSystem` and therefore holds the ETW `StartTrace` privilege the collector
needs.

| Field | Value |
|-------|-------|
| Host | **CFG-70-02** |
| Executing identity | **NT AUTHORITY\SYSTEM** (steward `LocalSystem` service context) |
| Windows session | **0** (service session — **no interactive desktop**; see app_hang note) |
| OS | Microsoft Windows Server 2025 Datacenter Evaluation, build 26100 |
| Steward | `steward-1780659937223058807`, tenant `infra-hyperv`, v0.9.13 |
| Date | 2026-07-10 (America/New_York) |
| Entry point | `cfgms-steward dex-spike` (hidden diagnostic subcommand, #2540) |

**Why this is a real privileged run and not the skip path:** the same binary run
**non-elevated** on the same host reports every ETW provider as
`reachable: false → "StartTrace: Access is denied. (code 5)"`; run in the steward
SYSTEM context all four flip to `reachable: true`. That flip is only possible with
a genuine privileged `StartTraceW` — it cannot be produced without executing under
`StartTrace` privilege on the host. Both raw `SpikeReport` JSON blobs are embedded
below as the contrast proof.

## Signal reachability (steward SYSTEM context)

| Signal class | Mechanism / provider | Reachable? | Notes |
|--------------|----------------------|-----------|-------|
| `app_hang`   | ETW / `Microsoft-Windows-Win32k`            | **YES** | `StartTrace`+`EnableTraceEx2` succeed. See session-0 caveat below — UI/app-hang events do not *emit* in a service session. |
| `disk_io`    | ETW / `Microsoft-Windows-Kernel-Disk`       | **YES** | Provider enable succeeds. |
| `hard_fault` | ETW / `Microsoft-Windows-Kernel-PerfInfo`   | **YES** | Provider enable succeeds. |
| `network`    | ETW / `Microsoft-Windows-DNS-Client`        | **YES** | Provider enable succeeds. |
| `smart`      | WMI / `MSStorageDriver_FailurePredictData`  | **YES** (with caveat) | Provider class present; the Count probe query errors `Invalid query` — the WMI query shape needs adjustment before real collection. |
| `thermal`    | WMI / `MSAcpi_ThermalZoneTemperature`       | **YES** (with caveat) | Provider class present; Count probe errors `Not supported` — this host does not expose an ACPI thermal zone via WMI (a valid "not available on this hardware" result). |

All four ETW providers are reachable under the steward's privilege. The two WMI
providers resolve but their sample count query does not succeed as written
(`smart`: query-shape bug to fix; `thermal`: hardware does not expose the zone).

## CPU overhead vs the 1.0% budget

Sustained %CPU while the full provider set is enabled and the consumer/poller run,
measured against a 1.0% single-core budget. Multiple windows (all **within
budget**):

| Window | Context | CPU % | Verdict |
|--------|---------|-------|---------|
| **30 s** | steward SYSTEM (representative) | **0.00 %** | **PASS** |
| 30 s | steward SYSTEM (earlier run) | 0.052 % | PASS |
| 25 s | steward SYSTEM, with generated disk+DNS activity | 0.125 % | PASS |
| 5 s  | steward SYSTEM | 0.937 % | PASS (short window — fixed enable/teardown cost not yet amortized) |
| 10 s | non-elevated (ETW enable denied) | 0.312 % | PASS |

The representative 30-second steward-context windows measure **≈0.00–0.05% CPU** —
**far under the 1.0% budget** for *enabling* all six providers. The 5 s window is
higher only because the one-time `StartTrace`/`EnableTraceEx2`/teardown cost is
amortized over a shorter window; it still passes.

**This is enablement overhead, not collection overhead** (no consumer runs — see
the callout at the top). The cost of actually consuming + decoding + attributing
events at volume is unmeasured here and is the point of #2571/#2572.

## Events captured — 0 (genuine result, with follow-up)

`Total signal events captured: 0` on **every** run, including a run with a
concurrent disk-write + DNS-resolution activity generator overlapping the
collection window. This is a real finding, not a measurement error:

1. **Session 0 / no interactive desktop.** The steward runs as a `LocalSystem`
   service in session 0. The `Win32k`/DWM UI-responsiveness + app-hang signals are
   desktop-session signals; they do not emit in a service session regardless of
   privilege. In the steward's actual deployment context these UI signals are
   **not observable** — a load-bearing result for the DEX design: app-hang/UX
   telemetry cannot be sourced from the steward's own service session and would
   need a different acquisition path (per-session agent).
2. **There is no consumer — it was removed.** `runETWConsumer` is a no-op
   (`<-ctx.Done()`). The #2517 `ProcessTrace` consumer was removed because the
   native ETW→Go callback corrupts the Go runtime (`acquireSudog` / `cgocallbackg`;
   atomic-only callbacks do not fix it). So 0 events is **by construction**, on
   every run including one with deliberate disk+DNS activity — nothing drains the
   buffers. This is the load-bearing open question: **can an in-steward Go process
   consume a high-rate ETW stream at all, and at what real overhead?** That is
   exactly what #2571 (Windows) exists to answer; it was **out of scope for this
   measurement spike**, scoped to reachability + enablement overhead only.

## Bottom line

- **Reachability:** all four target ETW providers are reachable from the steward's
  SYSTEM context; the two WMI providers resolve but need query/hardware follow-up.
- **Overhead:** enabling the full provider set costs **≈0.00–0.05% CPU** over a
  30 s window — **comfortably within the 1.0% budget** (`WithinBudget = true`).
- **Consumption is UNPROVEN.** The harness has no consumer (removed — the
  in-process Go `ProcessTrace` callback corrupts the Go runtime). So we have **not**
  shown we can read the stream, and the overhead above is enablement-only.
  Resolving this — and measuring real overhead-at-volume — is the follow-up
  feasibility spike **#2571** (Windows) / **#2572** (Linux).
- **Two further de-risking findings:** (a) UI/app-hang signals do not emit in the
  steward's service session (session 0) — need a per-session path; (b) the two WMI
  providers resolve but their sample-count query needs fixing (`smart`) / the
  hardware does not expose the zone (`thermal`).

## Reproduction

Run in the steward's SYSTEM context (holds `StartTrace` privilege) on a Windows host:

```powershell
# via the signed admin inline-exec channel, targeting the host's steward:
cfg steward exec <steward-id> --shell pwsh --timeout 200s --command `
  "Start-Process 'C:\path\cfgms-steward.exe' -ArgumentList 'dex-spike','--overhead-window-sec','30' -RedirectStandardOutput out.txt; # then read out.txt"
```

The inline-exec job enforces its own runtime cap (~tens of seconds), so a 30 s
window is launched **detached** (`Start-Process`, redirected to a file) and the
file is read after the window completes, rather than waiting inline.

Or directly, from an elevated session on the host:

```powershell
cfgms-steward dex-spike --overhead-window-sec 30          # human summary
cfgms-steward dex-spike --overhead-window-sec 30 --json   # raw SpikeReport
```

Non-elevated the ETW providers report `StartTrace: Access is denied (code 5)` and
the run does **not** satisfy the spike (privilege-skip path).

## Raw `SpikeReport` output (embedded proof)

### Steward SYSTEM context — 30 s window (`--json`)

```json
{
  "reachability": [
    { "class": "app_hang",   "mechanism": "etw", "provider": "Microsoft-Windows-Win32k",       "reachable": true },
    { "class": "disk_io",    "mechanism": "etw", "provider": "Microsoft-Windows-Kernel-Disk",  "reachable": true },
    { "class": "hard_fault", "mechanism": "etw", "provider": "Microsoft-Windows-Kernel-PerfInfo", "reachable": true },
    { "class": "network",    "mechanism": "etw", "provider": "Microsoft-Windows-DNS-Client",   "reachable": true },
    { "class": "smart",      "mechanism": "wmi", "provider": "MSStorageDriver_FailurePredictData", "reachable": true, "error": "Count property: Exception occurred. (Invalid query )" },
    { "class": "thermal",    "mechanism": "wmi", "provider": "MSAcpi_ThermalZoneTemperature",  "reachable": true, "error": "Count property: Exception occurred. (Not supported )" }
  ],
  "overhead": { "duration_sec": 30.0014589, "cpu_percent": 0, "budget_percent": 1, "within_budget": true },
  "total_events": 0
}
```

### Non-elevated, same host/binary — 10 s window (`--json`) — contrast baseline

```json
{
  "reachability": [
    { "class": "app_hang",   "mechanism": "etw", "provider": "Microsoft-Windows-Win32k",       "reachable": false, "error": "StartTrace: StartTraceW: Access is denied. (code 5)" },
    { "class": "disk_io",    "mechanism": "etw", "provider": "Microsoft-Windows-Kernel-Disk",  "reachable": false, "error": "StartTrace: StartTraceW: Access is denied. (code 5)" },
    { "class": "hard_fault", "mechanism": "etw", "provider": "Microsoft-Windows-Kernel-PerfInfo", "reachable": false, "error": "StartTrace: StartTraceW: Access is denied. (code 5)" },
    { "class": "network",    "mechanism": "etw", "provider": "Microsoft-Windows-DNS-Client",   "reachable": false, "error": "StartTrace: StartTraceW: Access is denied. (code 5)" },
    { "class": "smart",      "mechanism": "wmi", "provider": "MSStorageDriver_FailurePredictData", "reachable": true, "error": "Count property: Exception occurred. (Invalid query )" },
    { "class": "thermal",    "mechanism": "wmi", "provider": "MSAcpi_ThermalZoneTemperature",  "reachable": true, "error": "Count property: Exception occurred. (Not supported )" }
  ],
  "overhead": { "duration_sec": 10.0003697, "cpu_percent": 0.31248844730210323, "budget_percent": 1, "within_budget": true },
  "total_events": 0
}
```
