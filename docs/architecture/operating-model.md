# CFGMS Operating Model

How the system behaves at runtime. This document governs implementation decisions — every feature and issue should be consistent with the model described here.

For system structure (code organization, providers, modules), see [ARCHITECTURE.md](../../ARCHITECTURE.md).

## How CFGMS Works

CFGMS manages device state through configuration files. The core loop is:

1. A **cfg** describes the desired state of a device
2. A **steward** applies the cfg and keeps the device in that state
3. A **controller** (optional) distributes cfgs and collects reports

```
                    ┌────────────┐
                    │ Controller │  Distributes cfgs
                    │            │  Collects reports
                    └─────┬──────┘
                          │
                     cfg + reports
                          │
               ┌──────────┴──────────┐
               │                     │
          ┌────┴─────┐         ┌─────┴────┐
          │ Steward  │         │ Steward  │   Each steward maintains
          │          │         │          │   its device's state from
          │ cfg → ✓  │         │ cfg → ✓  │   its own cfg
          └──────────┘         └──────────┘
```

The controller is not required. A steward with a local cfg is a complete, functional deployment.

## The Cfg

A cfg is a YAML file (`hostname.cfg`) that declares the desired state of a device. It contains:

- **Resource configurations**: each block references a module and describes the desired state for that resource (e.g., a `file` module block declares a file's path, content, and permissions)
- **Schedule**: how often to re-check compliance
- **Mode**: whether to enforce desired state (`apply`) or only monitor and report drift (`monitor`)

The cfg is the single source of truth for a steward. Whether it came from a local file or was pushed by a controller, the steward treats it the same way.

## Component Roles

### Steward

The steward is a daemon that maintains a device in the state described by its cfg.

**Core behaviors:**

1. **Apply** — On startup and when the cfg changes, evaluate each resource's current state against desired state. In `apply` mode, converge the device (Get → Compare → Set → Verify). In `monitor` mode, detect and report drift without making changes
2. **Maintain** — Re-check compliance on the schedule defined in the cfg. In `apply` mode, correct any drift. In `monitor` mode, report drift. Respond to module-defined event hooks (e.g., file change triggers re-check of that resource)
3. **Know itself** — Collect DNA (hardware, software, network, security attributes). Monitor its own health and performance
4. **Report** — Always log locally. When connected to a controller, also report events, status, and DNA upstream. When disconnected, queue reports locally and resync on reconnect

These four behaviors are the same regardless of deployment mode. The only difference between standalone and controller-connected is **where the cfg comes from** and **where reports go**.

| | Standalone | Controller-Connected |
|---|---|---|
| Cfg source | Local file | Pushed by controller, stored locally |
| Apply/Maintain | Same | Same |
| DNA/Health | Same | Same |
| Reporting | Local logs | Local logs + controller (with offline queueing) |

When connected to a controller, the steward also supports:

5. **Execute ad-hoc scripts** — The controller can push one-off scripts for immediate execution outside the cfg (e.g., emergency remediation, diagnostics). Results are reported back to the controller
6. **Remote terminal** — The controller can establish an interactive terminal session to the device through the steward for live troubleshooting

These capabilities require an active controller connection and are not available in standalone mode. They do not replace or bypass the cfg — they are operational tools for administrators.

**What the steward is NOT:**
- Not idle when disconnected from the controller
- Not a different product depending on how it was deployed

### Controller

The controller is the central management server. It does not manage devices directly — it manages cfgs and communicates with stewards.

**Core behaviors:**

1. **Store cfgs** — Version-controlled configuration storage. Cfgs are authored here (via API, workflow, or direct edit) and distributed to stewards
2. **Distribute cfgs** — Push cfgs to stewards over the data plane. The controller decides which steward gets which cfg (based on tenant hierarchy, groups, targeting rules)
3. **Collect reports** — Receive status, events, DNA, health, and historical performance metrics from stewards. Aggregate for fleet-wide dashboards, compliance reporting, trend analysis, and troubleshooting. This data is the foundation for future Digital Experience (DEX) capabilities
4. **Run workflows** — Execute automation workflows for cloud/SaaS operations that don't require a steward (desired-state convergence for cloud resources, orchestration and data sync between third-party services, and imperative automation). See [controller operating model](controller-operating-model.md) for details
5. **Manage identity** — Certificate authority, steward registration, tenant management
6. **Orchestrate multi-node operations** — The controller is aware of application dependencies and infrastructure roles (e.g., Hyper-V clusters, SQL clusters, domain controllers, DNS/DHCP roles). Operations that span multiple devices — rolling updates, coordinated reboots, cluster-aware patching — are sequenced by the controller to maintain service availability. Individual stewards apply their cfgs; the controller decides the order and timing

**What the controller is NOT:**
- Not required for a steward to function
- Not the thing that "runs" modules on devices — stewards do that
- Not a remote shell or task execution engine

### Communication Model

```
Controller                              Steward
    │                                      │
    │──── cfg push (data plane) ──────────►│  "Here is your new cfg"
    │                                      │
    │◄─── status report (control plane) ───│  "Applied 5 resources, 0 drift"
    │◄─── heartbeat (control plane) ───────│  "I'm alive, healthy, DNA hash: abc123"
    │◄─── DNA delta (control plane) ──────│  "RAM changed from 16GB to 32GB"
    │◄─── DNA full sync (data plane) ─────│  "Here is my complete DNA" (on controller request eg hash mismatch etc)
    │◄─── performance metrics (data plane)─│  Periodic, on-demand, or real-time stream
    │                                      │
    │──── command (control plane) ────────►│  "Sync your cfg now" (optional)
    │                                      │
```

- **Control plane**: lightweight messages — heartbeats (including DNA hash), commands, status, events, DNA deltas
- **Data plane**: bulk transfers — cfgs, full DNA snapshots (on hash mismatch), performance metrics

Both planes use the unified **gRPC-over-QUIC** transport (port 4433, mTLS). All controller-steward communication flows over a single multiplexed QUIC connection with distinct gRPC services for control and data operations.

The controller can tell a steward to sync its cfg immediately (e.g., after an admin pushes a change). But the steward also re-checks on its own schedule. The command is an optimization, not a dependency.

### Outpost (Future)

Regional infrastructure component deployed at site level. Two roles:

1. **Proxy cache** — Caches binaries, packages, and cfg artifacts used by multiple stewards at the site, reducing WAN bandwidth and speeding up deployments
2. **Network operations** — Manages agentless endpoints that can't run a steward (switches, firewalls, APs, printers) via SSH, SNMP, and vendor APIs. Also performs network scans and topology discovery

Reports to controller. Not yet implemented.

## Failure Modes

### Steward loses controller connection

The steward continues operating normally:
- Keeps applying its last-known cfg on schedule
- Keeps detecting and correcting drift
- Keeps collecting DNA and monitoring health
- Queues reports locally

When connection is restored:
- Resyncs queued reports to controller
- Checks for cfg updates
- Resumes real-time reporting

### Controller restarts

Stewards are unaffected. They continue maintaining their cfgs independently. When the controller comes back:
- Stewards reconnect automatically (gRPC-over-QUIC transport reconnect with exponential backoff)
- Queued reports are delivered
- Controller rebuilds its view of fleet state from steward reports

### Steward restarts

On startup, the steward:
1. Loads its cfg (from local file or last-known from controller)
2. Applies immediately (full convergence)
3. Reconnects to controller if configured
4. Resumes normal schedule

## Deployment Modes

All deployment modes use the same steward binary. The mode only determines where the cfg comes from and whether a controller channel exists.

### Standalone

Steward reads a local `hostname.cfg`. No controller, no network dependency.
```
steward ← hostname.cfg (local file)
```

### Controller + Stewards

Controller distributes cfgs. Stewards register, receive cfgs, and report status.
```
controller ← admin authors cfgs
    │
    ├──► steward-1 ← cfg (pushed, stored locally)
    ├──► steward-2 ← cfg (pushed, stored locally)
    └──► steward-3 ← cfg (pushed, stored locally)
```

### Controller Only (Cloud Management)

Controller runs workflows against cloud APIs. No stewards needed.
```
controller ← admin authors workflows
    │
    └──► Cloud / SaaS APIs (M365, PSA, distributor, etc.)
```

This is the same controller — it just has no stewards registered. The workflow engine operates independently of steward management.
