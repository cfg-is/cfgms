# Steward Operating Model

How the steward behaves at runtime. This document governs steward implementation decisions — every steward feature and issue should be consistent with the model described here.

For the system-level operating model, see [operating-model.md](operating-model.md).
For cfg format details, see [steward-configuration.md](steward-configuration.md).

## One Sentence

The steward is a daemon that maintains a device in the state described by its cfg, reports on compliance, and optionally connects to a controller for cfg delivery, reporting, and remote operations.

## Lifecycle

### Startup

1. **Load cfg** — Find and parse the `hostname.cfg` file (local file, or last-known cfg from controller)
2. **Discover modules** — Scan module paths, load available modules, validate that all modules referenced in the cfg are available
3. **Initial convergence** — Evaluate every resource in the cfg immediately (apply or monitor, depending on mode)
4. **Start convergence schedule** — Begin the compliance re-check loop at the interval defined by `converge_interval` in the cfg (default: 30 minutes)
5. **Collect DNA** — Gather device identity and attributes (hardware, software, network, security)
6. **Connect to controller** (if configured) — Establish a gRPC-over-QUIC transport connection. Check for cfg updates

### Normal Operation

The steward runs three concurrent activities:

```
┌─────────────────────────────────────────────┐
│              Steward Daemon                  │
│                                              │
│  ┌──────────────────────┐                   │
│  │ Convergence Loop     │  cfg-driven       │
│  │ (scheduled + events) │  core activity    │
│  └──────────────────────┘                   │
│                                              │
│  ┌──────────────────────┐                   │
│  │ Self-Awareness       │  DNA, health,     │
│  │ (periodic collection)│  performance      │
│  └──────────────────────┘                   │
│                                              │
│  ┌──────────────────────┐                   │
│  │ Controller Channel   │  optional         │
│  │ (if connected)       │  overlay          │
│  └──────────────────────┘                   │
│                                              │
└─────────────────────────────────────────────┘
```

### Shutdown

1. Complete any in-progress resource operations
2. Flush queued reports (to controller if connected, otherwise ensure local logs are written)
3. Disconnect from controller cleanly (gRPC-over-QUIC transport close)
4. Exit

## Convergence Loop

This is the steward's core activity. It runs on startup, on schedule, and in response to events.

### Trigger Sources

| Trigger | Description |
|---------|-------------|
| **Startup** | Full convergence immediately on start (both standalone and controller-connected) |
| **Schedule** | Periodic re-check at the `converge_interval` defined in the cfg (default: 30 minutes) |
| **Cfg change** | New cfg received from controller, or local cfg file modified |
| **Event hook** | Module-defined monitor detects a relevant change (e.g., file modified, service stopped) |
| **Controller command** | Controller sends `sync_config` — immediate convergence trigger, an optimization not a dependency |

### Per-Resource Cycle

For each resource in the cfg, the execution engine runs:

```
Get → Compare → Set → Verify
```

1. **Get**: Call `module.Get()` to read current state from the system
2. **Compare**: Engine compares current state against desired state from the cfg (using `StateComparator`)
3. **Set**: If drifted and in `apply` mode, call `module.Set()` to converge
4. **Verify**: Call `module.Get()` again to confirm the change took effect

**In `apply` mode:**
- If current matches desired: no action, report compliant
- If drifted: Set → Verify → report remediated

**In `monitor` mode:**
- If current matches desired: report compliant
- If drifted: report drift (skip Set and Verify, no changes made)

### Error Handling

Controlled by the cfg's `error_handling` settings:

- **continue** (default): Log the error, skip the failed resource, process remaining resources
- **fail**: Stop execution on the first error

Failed resources are reported individually — a failure on one resource does not mask the status of others.

### Idempotency

Every convergence run must be safe to repeat. Modules implement Get/Set such that applying a cfg that is already converged results in zero changes. This is fundamental — the scheduled re-check depends on it.

## Modules

Modules are the code packages that manage resources. Each resource block in the cfg references a module by name and provides module-specific configuration.

### Module Contract

Every module implements the `Module` interface:

| Method | Purpose |
|--------|---------|
| **Get** | Read the current state of the resource from the system |
| **Set** | Apply changes to reach desired state |

Modules also implement `ConfigState` for their configuration, which provides:
- **Validate** — check that the resource configuration in the cfg is valid
- **AsMap** — return state as a map for field-by-field comparison
- **GetManagedFields** — declare which fields this module manages

Compare and Verify are performed by the execution engine (not the module) — it calls `Get`, uses the `StateComparator` to diff against desired state, calls `Set` if needed, then calls `Get` again to verify.

### Event Hooks

Modules can optionally implement the `Monitor` interface to watch for real-time changes to their managed resources. The monitor provides a `Changes()` channel that emits `ChangeEvent` values (created, modified, deleted, permissions changed).

For example:
- The `file` module watches for filesystem changes to managed files
- The `service` module monitors service state changes

When a change event fires, it triggers a convergence check for that specific resource rather than waiting for the next scheduled run. This provides near-real-time drift correction for critical resources.

## Self-Awareness

The steward continuously knows about itself. This information is collected independently of the convergence loop.

### DNA (Digital Native Attributes)

A snapshot of the device's identity and state:

| Category | Examples |
|----------|----------|
| **Hardware** | CPU, memory, disk, motherboard, serial numbers |
| **Software** | OS, installed packages, running services, startup programs |
| **Network** | Interfaces, IPs, MACs, routing |
| **Security** | Firewall status, encryption state, admin accounts |

DNA is collected on startup and periodically thereafter. It serves two purposes:
1. **Device identity** — the controller uses DNA to identify and classify devices
2. **Drift baseline** — DNA changes between collections indicate environmental drift

### DNA Sync Model

DNA is a deterministic, hashable dataset. The steward computes a hash of its current DNA and includes it in every heartbeat. This keeps the controller aware of DNA currency with near-zero bandwidth overhead.

- **Heartbeats** carry the DNA hash (control plane, every heartbeat interval)
- **Deltas** are published as changes are detected (control plane, as they occur)
- **Full sync** is only required on initial registration or when the controller detects a hash mismatch (data plane, on demand)

As long as both sides compute the same hash, the full DNA never needs to be retransmitted after the initial sync. If a delta is missed or hashes diverge, the controller requests a full sync over the data plane.

### Health

The steward monitors its own operational health:

| Signal | Healthy | Degraded | Unhealthy |
|--------|---------|----------|-----------|
| Config errors | 0 | Threshold exceeded | — |
| Certificate validity | Valid, > 7 days | < 7 days to expiry | Expired/invalid |
| Controller connection | Connected | — | Disconnected (if configured) |
| Task latency | Within bounds | Threshold exceeded | — |

Health status is included in heartbeats and available locally.

### Performance

The steward collects and retains time-series performance metrics for the host system:

- **System metrics**: CPU, memory, disk I/O, network I/O (collected on interval)
- **Process metrics**: per-process CPU/memory for watched processes
- **Local retention**: metrics are stored locally with a configurable retention period (e.g., 30 days) for historical analysis even when offline
- **Threshold alerting**: evaluated locally — the steward reports threshold breach events immediately, not raw metric streams
- **Controller reporting**: three modes of metric delivery:
  - **Periodic upload**: steward pushes collected metrics to the controller on a regular interval (e.g., hourly)
  - **On-demand**: controller requests current metrics or a historical range from the steward
  - **Real-time streaming**: controller initiates a live metrics stream for a single endpoint (e.g., admin troubleshooting a specific device)

This data provides the foundation for future Digital Experience (DEX) capabilities — user experience scoring, hardware lifecycle analysis, and productivity impact assessment. Building collection and local retention now means DEX becomes an analytics layer on top, not a rebuild.

## Reporting

The steward always reports. Where reports go depends on the deployment.

### Local (Always)

Every steward writes structured logs locally, regardless of deployment mode. This is the baseline — it works offline, standalone, and connected.

Log locations:
- Linux: `/var/log/cfgms/` or systemd journal
- Windows: Windows Event Log and `C:\ProgramData\CFGMS\logs\`
- macOS: System log and `/usr/local/var/log/cfgms/`

### Controller (When Connected)

When connected to a controller, the steward also reports upstream:

| Report | Timing | Content |
|--------|--------|---------|
| **Heartbeat** | Periodic (configurable interval) | Health status, uptime |
| **Convergence result** | After each convergence run | Per-resource compliance status, changes made, errors |
| **DNA hash** | With each heartbeat | Hash of current DNA (control plane) |
| **DNA delta** | As changes detected | Changed attributes only (control plane) |
| **DNA full sync** | On hash mismatch or initial registration | Complete DNA snapshot (data plane) |
| **Performance metrics** | Periodic (e.g., hourly), on-demand, or real-time stream | CPU, memory, disk, network, process metrics |
| **Events** | As they occur | Drift detected, module errors, threshold breaches |

### Offline Queueing

When the controller connection is lost:

1. Steward continues all normal operations (convergence, DNA, health)
2. Reports that would go to the controller are queued locally
3. When connection is restored, queued reports are delivered in order
4. Controller rebuilds its view of this steward from the resynced reports

## Controller Channel

The controller channel is an **additive overlay** on top of the convergence loop, not a replacement for it. A controller-connected steward behaves identically to a standalone steward for all convergence operations — the connection adds:

1. **Cfg delivery** — the controller pushes cfg updates over the gRPC data plane
2. **Near-real-time reporting** — convergence results, events, and heartbeats are forwarded upstream
3. **Out-of-band `sync_config` trigger** — the controller can request immediate convergence (optimization only; the loop continues on schedule regardless)

If the controller connection is lost, the steward continues converging on schedule against its last-received cfg and queues reports locally until reconnection.

The `--regtoken` flag establishes the controller channel — it does not change the steward's fundamental convergence behaviour.

## Controller-Connected Capabilities

These behaviors require an active controller connection and are not available in standalone mode.

### Cfg Delivery

The controller pushes cfg updates to the steward over the gRPC data plane service. Cfgs are signed by the controller's signing certificate — the steward verifies the signature before applying, ensuring cfgs cannot be tampered with in transit or injected by a rogue source. The steward stores the verified cfg locally and triggers a convergence run. If the connection is later lost, the steward continues using the last-received cfg.

### Ad-Hoc Script Execution

The controller can push a one-off script for immediate execution, outside the cfg. Use cases:
- Emergency remediation
- Diagnostics and data collection
- One-time operations that don't belong in desired state

Results are reported back to the controller. Ad-hoc scripts do not modify the cfg.

### Remote Terminal

The controller can establish an interactive terminal session through the steward for live troubleshooting. The steward provides a secure, authenticated shell session back to the administrator.

### Orchestrated Operations

The steward participates in multi-node operations coordinated by the controller (rolling updates, coordinated reboots, cluster-aware operations). The steward applies its own cfg — the controller determines sequencing and timing across devices. See the [controller operating model](controller-operating-model.md) for orchestration details.

## Registration

How a steward joins a controller.

1. Administrator creates a **registration token** on the controller (via REST API)
2. Steward is started with `--regtoken <token>`
3. Steward contacts controller, submits token
4. Controller validates token, provisions steward identity, issues mTLS certificates
5. Steward stores certificates locally and establishes a gRPC-over-QUIC transport connection
6. Steward checks for a cfg from the controller
7. Normal operation begins

After initial registration, the steward reconnects automatically on restart using its stored certificates. The registration token is only used once.

## Cfg Fields Governing Convergence

The convergence loop behaviour is controlled by fields in the cfg:

| Field | Default | Description |
|-------|---------|-------------|
| `steward.converge_interval` | `30m` | How often the steward re-converges against the cfg. Accepts any Go duration string: `"5m"`, `"30m"`, `"1h"`, etc. |

Industry reference intervals: CFEngine 5 min, DSC 15 min, Chef/Puppet 30 min.

## Deployment-Independent Behavior

The steward binary is the same in every deployment. The table below shows which behaviors are active in each mode:

| Behavior | Standalone | Controller-Connected |
|----------|------------|---------------------|
| Load and parse cfg | Local file | Pushed by controller, stored locally |
| Convergence loop (apply/monitor) | Yes | Yes |
| Scheduled re-check (`converge_interval`) | Yes | Yes (default 30m until cfg received) |
| Event hooks | Yes | Yes |
| DNA collection | Yes | Yes |
| Health monitoring | Yes | Yes |
| Performance monitoring | Yes | Yes |
| Local logging | Yes | Yes |
| Controller reporting | — | Yes (with offline queueing) |
| Heartbeats | — | Yes |
| Cfg delivery from controller | — | Yes |
| Ad-hoc script execution | — | Yes |
| Remote terminal | — | Yes |
| Multi-node orchestration | — | Yes |
