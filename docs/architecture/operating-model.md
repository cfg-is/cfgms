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
- **Mode**: whether to enforce desired state (`apply`) or only monitor and report drift (`monitor`) [GAP: apply/monitor mode toggle not yet implemented in steward cfg or execution engine — see issue #1524]

The cfg is the single source of truth for a steward. Whether it came from a local file or was pushed by a controller, the steward treats it the same way.

## Core Primitives

CFGMS is built from a small set of powerful primitives. New features compose existing primitives rather than introducing parallel mechanisms.

- **Config management** — the cfg + steward convergence loop is the substrate for all device state management.
- **Workflow engine** — handles cloud/SaaS desired-state, orchestration, and event-driven automation. Registration approval, drift response policies, and third-party integrations all express through workflows.
- **Durable job queue (controller-side)** — fanout, retries, deferred operations, and HA failover replay all use the same queue. Survives controller restarts and leader failover.
- **DNA** — deterministic, hashable representation of managed-object state. Underlies sync, drift detection, and compliance reporting.
- **Central providers** (storage, logging, secrets, directory, transport) — pluggable interfaces. New backends extend an existing provider rather than introducing a parallel system.

If a feature can use an existing primitive, that's the path. Building a parallel mechanism requires justification.

## Save = Deploy

Any source that writes a cfg to the controller's ConfigStore (CLI, web UI, GitOps webhook, workflow output) triggers automatic distribution to matched stewards. There is no separate "push" action — save IS deploy. [GAP: storage-watch auto-trigger not yet wired; config saves currently require an explicit `POST /api/v1/config/push` call — see issue #1525]

```
 ┌───────────────┐   write   ┌─────────────┐  storage-watch  ┌──────────┐
 │ Author        │ ─────────▶│ ConfigStore │ ──────────────▶│  Fanout  │
 │ (CLI/UI/Hook) │           │ (durable)   │ debounce ~500ms │ (queue)  │
 └───────────────┘           └─────────────┘                 └─────┬────┘
                                                                   ▼
                                                            ┌──────────────┐
                                                            │  Stewards    │
                                                            │  (converge   │
                                                            │   on next hb)│
                                                            └──────────────┘
```

- **Single write path.** All sources write to ConfigStore via the same path.
- **Debounce.** Storage-watch waits ~500ms (configurable) before triggering fanout. Absorbs burst edits invisibly. [GAP: debounce not yet implemented — see issue #1525]
- **Durable queue.** Fanout uses the controller's durable job queue — the same primitive used for retries, deferred operations, and HA failover replay.
- **Idempotency carries load.** A steward already at the target DNA hash treats a sync command as a no-op.
- **Resource-bounded fanout.** Fanout is bounded by controller capacity (CPU, outbound bandwidth) to prevent thundering-herd saturation.

Stewards' own heartbeat-driven loops also notice config divergence via DNA hash mismatch — the fanout command is an optimization on top of that steady-state loop, not a dependency for correctness.

## Safety Primitives

Safety against bad configs comes from operator-controllable primitives:

- **Targeting precision** — a cfg explicitly lists which stewards / groups / tenant paths / DNA-attributes it applies to. A bad change is bounded by what it was authored to target.
- **Deployment rings (convention)** — steward tags (`ring=canary`, `ring=prod-early`, `ring=prod-broad`) let operators author phased rollouts as separate configs or staged target lists. v1 is convention; auto-progressive ring machinery is a future enhancement.
- **Deployment visibility** — `cfg config deployments <id>` shows applied / pending / failed / halted counts and per-steward status. [GAP: command not yet implemented — see issue #1526]
- **E-stop (planned)** — `cfg config halt <id>` cancels remaining queued sends for a config.
- **Rollback (planned CLI; underlying infrastructure exists)** — restore a previous cfg version via `features/controller/api/rollback_handler.go`.

## Component Roles

### Steward

The steward is a daemon that maintains a device in the state described by its cfg.

**Core behaviors:**

1. **Apply** — On startup and when the cfg changes, evaluate each resource's current state against desired state. In `apply` mode, converge the device (Get → Compare → Set → Verify). In `monitor` mode, detect and report drift without making changes [GAP: monitor mode not yet implemented — see issue #1524]
2. **Maintain** — Re-check compliance on the schedule defined in the cfg. In `apply` mode, correct any drift. In `monitor` mode, report drift. Respond to module-defined event hooks (e.g., file change triggers re-check of that resource)
3. **Know itself** — Collect DNA (hardware, software, network, security attributes). Monitor its own health and performance
4. **Report** — Always log locally. When connected to a controller, also report events, status, and DNA upstream. When disconnected, queue reports locally and resync on reconnect

**Apply mode vs Monitor mode (configurable per steward):** [GAP: apply/monitor mode toggle not yet implemented — see issue #1524]

- **`apply` mode** (default for managed devices): the steward actively converges the device to match its cfg. When drift is detected, the steward attempts local convergence and reports the outcome as a single combined message containing `{drift_detected, drift_setting, convergence_result, final_state}` — one message per drift event.
- **`monitor` mode**: the steward detects drift but does not act. Emits a non-compliance event upstream; operator action (or a separate `apply` workflow) decides whether to correct.

Mode is set in steward configuration. A single steward operates in one mode at a time across all its managed resources. Per-resource override is not in scope for v1.

Controller-side logging captures both the drift event and convergence result regardless of mode — flapping detection can be added later without wire-protocol changes.

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

### Trust Model

mTLS for all controller↔steward traffic, with three layers of identity.

**Controller identity is anchored at build time.**
The steward binary is built with the controller's URL compiled in (`-ldflags="-X main.ControllerURL=..."`). Scope: per controller (or controller cluster), not per tenant. One steward binary serves all tenants the controller manages.

**Steward identity is established at registration.**
Two credential flavors:

- **Short-lived / single-use registration tokens** — manual onboarding, small fleets, time-bounded provisioning. Generated on the controller, handed to the steward as a string. Consumed at registration; expiry enforces time bounds.
- **Long-lived tenant/group registration codes** — RMM/GPO mass deployment. Same string-on-the-wire pattern, baked into deployment scripts and reused by many devices. Encodes tenant/group target.

Both flow through the controller's registration approval workflow (`RegistrationApprovalHook`). The default hook auto-approves all valid registrations. To customize approval, deploy a workflow named `steward-registration-approval`; a workflow with `Variables: {policy: accept}` short-circuits to auto-approve. [GAP: built-in named workflow templates (`auto-approve`, `manual-review`) not yet shipped — see issue #1527] Custom workflows implement arbitrary policy via the workflow engine.

**Admin identity is a single-file mTLS bundle.**
On `--init`, the controller writes the bundle to a known path:
- Linux/macOS: `/etc/cfgms/admin.bundle.yaml`
- Windows: `%ProgramData%\cfgms\admin.bundle.yaml`

YAML containing cert + key + CA inline. The `cfg` CLI auto-discovers via: `--bundle <path>` → `CFGMS_ADMIN_BUNDLE` env → `~/.config/cfgms/admin.bundle.yaml` → system path. `cfgms-controller bootstrap-admin` issues named bundles per operator, regenerates the system bundle, lists issued bundles, and revokes by serial.

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

## UX Surfaces

Operators interact with CFGMS through layered UX surfaces.

**`cfg` CLI — first-class community UI.** The canonical interaction surface for the open-source distribution. Every documented operator action works through the CLI. The CLI wraps REST endpoints so operators don't need to script against REST for documented workflows.

**Web UI — commercial layer (planned before v1).** A separate UX layer in the commercial distribution. Targets operators who prefer graphical workflows or shared-team views. Some power-user flows may remain CLI-only.

**REST API — underlying contract.** The wire format the CLI and web UI both use. Stable, versioned, and documented at `docs/api/rest-api.md`. Available to operators and integrators for scripting and third-party tools.

**Workflow engine — automation surface.** For SaaS/cloud operations that don't require a steward (M365, identity providers, ticketing systems), the workflow engine is the primary expression mechanism. See [controller operating model](controller-operating-model.md#workflow-engine).

## Monitoring Export Credentials

OTLP exporter credentials (API keys / bearer tokens) are stored in `pkg/secrets`, not in config files. Configure the secret key name via `config["secret_key"]` and use `NewOTLPExporterWithSecrets` to wire the store at construction time.
