# Steward Operating Model

How the steward behaves at runtime. This document governs steward implementation decisions — every steward feature and issue should be consistent with the model described here.

For the system-level operating model, see [operating-model.md](operating-model.md).
For cfg format details, see [steward-configuration.md](steward-configuration.md).

## One Sentence

The steward is a daemon that maintains a device in the state described by its cfg, reports on compliance, and optionally connects to a controller for cfg delivery, reporting, and remote operations.

## Lifecycle

### Startup

1. **Load cfg** — Find and parse the `hostname.cfg` file (local file, or last-known cfg from controller)
2. **Discover modules** — Scan module paths and register available modules. Modules referenced in the cfg are loaded on-demand during convergence (not validated at startup)
3. **Initial convergence** — Evaluate every resource in the cfg immediately (apply or monitor, depending on `drift_mode` received from the controller)
4. **Start convergence schedule** — Begin the compliance re-check loop at the interval defined by `converge_interval` in the cfg (default: 30 minutes). DNA is collected as part of each convergence run (not a separate startup step)
5. **Connect to controller** (if configured) — Establish a gRPC-over-QUIC transport connection. Check for cfg updates

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
3. **Set**: If drifted and in `apply` mode, call `module.Set()` to converge. In `monitor` mode, emit `drift.detected.monitor` event upstream and skip Set/Verify.
4. **Verify**: Call `module.Get()` again to confirm the change took effect

**In `apply` mode:**
- If current matches desired: no action, report compliant
- If drifted: Set → Verify → report remediated

**In `monitor` mode:**
- If current matches desired: report compliant
- If drifted: emit `drift.detected.monitor` upstream event; skip Set and Verify; report `StatusNonCompliant`

### Error Handling

Controlled by the cfg's `error_handling` settings (three independent fields: `module_load_failure`, `resource_failure`, `configuration_error`):

- **continue**: Log the error, skip the failed resource, process remaining resources
- **warn** (default for `resource_failure`): Log a warning, skip the failed resource, continue with remaining resources
- **fail** (default for `configuration_error`): Stop execution on the first error

The default for `resource_failure` is `warn` (not `continue`). `module_load_failure` defaults to `continue`; `configuration_error` defaults to `fail`.

Failed resources are reported individually — a failure on one resource does not mask the status of others.

### Idempotency

Every convergence run must be safe to repeat. Modules implement Get/Set such that applying a cfg that is already converged results in zero changes. This is fundamental — the scheduled re-check depends on it.

### Drift Modes

The `drift_mode` field in the controller-delivered cfg selects how the steward responds to drift detected during convergence or scheduled re-checks:

- **`apply` mode** (default — matches current behavior when `drift_mode` is absent): the steward attempts local convergence and reports the outcome. The controller sees the drift and its resolution together.
- **`monitor` mode**: the steward detects drift but does not act. Emits a `drift.detected.monitor` event upstream with `ResourceResult.Status = StatusNonCompliant`; operator action (or a separate `apply` workflow) decides whether to correct.

`drift_mode` is set exclusively from the controller-delivered cfg — a separate field from `steward.mode` (which controls connectivity: `standalone` or `controller`). A single steward operates in one drift mode at a time across all its managed resources. Per-resource override is not in scope for v1.

**Security invariant**: `drift_mode` is sourced from the authenticated controller-delivered cfg only. The local-file loading path (`loadFromPath` in `features/steward/config/config.go`) clears the field after parsing so a tampered `hostname.cfg` cannot flip a controller-connected steward into monitor mode.

**Distinguishable event type**: in monitor mode the executor sets `StateDiff.EventType = "drift.detected.monitor"` before invoking the `DriftEventHandler`. This lets the controller distinguish monitor-mode stewards (which simply haven't drifted) from apply-mode stewards via fleet-wide telemetry. Handler ordering is preserved: `DriftEventHandler` always fires before any mode-specific branch.

Controller-side logging captures both the drift event and convergence result regardless of mode, enabling flapping detection (a future enhancement) without wire-protocol changes.

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

Modules **should, when possible, implement the `Monitor` interface** to watch for real-time changes to their managed resources. The monitor provides a `Changes()` channel that emits `ChangeEvent` values (created, modified, deleted, permissions changed). When a change event fires, it triggers a convergence check for that specific resource rather than waiting for the next scheduled run — near-real-time drift correction for critical resources.

Some resources don't have a feasible event-source (no OS-level watcher, no vendor API hook); those modules fall back to the scheduled re-check interval (`steward.converge_interval`). Event-driven Monitor support is preferred and should be added where the underlying platform permits it.

Current adoption (as of v0.9.x):

- **Implemented**: none
- **Polling-only (no Monitor yet)**: `activedirectory`, `file`, `directory`, `script`, `firewall`, `package`, `patch`

Adding `Monitor` support to additional modules is an ongoing enhancement, prioritized by user impact (security-sensitive resources benefit most from event-driven detection).

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
| **Heartbeat** | Periodic (20 s base ± up to 10 s uniform jitter per tick; effective interval always in [20 s, 30 s)) | Health status, uptime |
| **Convergence result** | After each convergence run | Per-resource compliance status, changes made, errors |
| **DNA hash** | With each heartbeat | Hash of current DNA (control plane) |
| **DNA delta** | As changes detected | Changed attributes only (control plane) |
| **DNA full sync** | On hash mismatch or initial registration | Complete DNA snapshot (data plane) |
| **Performance metrics** | Periodic (e.g., hourly), on-demand, or real-time stream | CPU, memory, disk, network, process metrics |
| **Events** | As they occur | Drift detected, module errors, threshold breaches |

### Heartbeat Timing

Stewards send heartbeats at a base interval of **20 seconds**, with **uniform per-tick jitter in [0, 10 s)**. The effective per-tick interval is always in **[20 s, 30 s)**.

**Why 20 s base with jitter (epic #1664):**

- **NGFW UDP idle timeout survival**: Most Next-Generation Firewalls and NAT devices expire UDP pinholes after 30 s of silence. With a maximum effective interval of 30 s (exclusive), and QUIC keepalives at 20 s, at least one keepalive or heartbeat always fires before the 30 s timeout — keeping the QUIC connection alive through NGFW/NAT devices without requiring shorter (more expensive) keepalives.
- **Herd prevention**: Jitter prevents 50 k stewards from synchronising their heartbeats, which would create CPU spikes on the controller. Uniform jitter distributes heartbeat load evenly across the 10 s window.
- **Controller offline threshold**: The controller marks a steward offline after **60 s of silence** (3 missed heartbeats at 20 s base). The 3-miss threshold provides tolerance for transient network blips while detecting genuinely lost stewards within 60–90 s.

The QUIC `KeepAlivePeriod` is set to **20 s** (aligned with the heartbeat base) so the QUIC layer and application layer cooperate — a QUIC PING fires at 20 s regardless of jitter, ensuring the UDP pinhole never reaches 30 s idle even when the heartbeat fires at its maximum interval.

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

## Entry Paths

The steward binary supports four entry paths:

| Invocation | Mode | Description |
|------------|------|-------------|
| `cfgms-steward --regtoken TOKEN` | Controller-connected (foreground) | Registers with the controller via HTTP REST API, receives mTLS certificates, then establishes a gRPC-over-QUIC transport connection. Registration is called on every invocation — there is no stored-certificate resume path. |
| `cfgms-steward --config path.cfg` | Standalone (foreground) | Loads cfg from the specified local file. No controller connection is established. All convergence, DNA, health, and local logging operate as normal. |
| `cfgms-steward install --regtoken TOKEN` | Controller-connected (service) | Installs the steward as a native OS service (systemd on Linux, SCM on Windows, launchd on macOS) and starts it. |
| `cfgms-steward` (no arguments) | Interactive | Prompts for a registration token, then presents a menu: [1] Install as service, [2] Run once in foreground, [3] Exit. |

When both `--regtoken` and `--config` are supplied, the `--regtoken` path takes precedence and `--config` is ignored.

## Logging

The steward writes structured logs using the file logging provider. This is the only supported logging provider for the steward binary — the timescale (database) provider is a controller-only feature.

Log level is controlled by the `CFGMS_LOG_LEVEL` environment variable (default `INFO`). Accepted values are `debug`, `info`, `warn`, and `error` (case-insensitive). Invalid or empty values fall back to `INFO`.

Log directory is controlled by `CFGMS_LOG_DIR` (default `/tmp/cfgms` with a warning; set this for production deployments).

## Controller-Connected Capabilities

These behaviors require an active controller connection and are not available in standalone mode.

### Cfg Delivery

The steward receives new cfgs via two paths, both arriving over the gRPC data plane service:

- **Controller-initiated sync** — after a save-IS-deploy ConfigStore write on the controller, the controller fans out a `CommandSyncConfig` to the steward, prompting it to fetch the new cfg immediately.
- **Heartbeat-driven discovery** — every heartbeat carries the steward's current cfg version. If the controller's view diverges (newer cfg available), the next heartbeat response triggers the same sync path.

Either path lands the same outcome: the steward fetches the new cfg, verifies the controller's signature, stores it locally, and triggers a convergence run. Cfgs are signed by the controller's signing certificate — the steward verifies the signature before applying, ensuring cfgs cannot be tampered with in transit or injected by a rogue source.

If the controller connection is later lost, the steward continues using the last-received cfg.

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

### Controller Anchor (Build Time)

The steward binary is built with the controller's URL compiled in at link time (`-ldflags="-X main.ControllerURL=..."`). A given steward binary will only ever talk to its compile-time controller. Scope: per controller (or controller cluster), not per tenant — one steward binary serves all tenants the controller manages.

A steward binary today connects to exactly one controller URL. Multi-controller deployments — where a steward might fail over between geographically distributed controllers (e.g., `east.cfg.ms`, `west.cfg.ms`) — are not yet supported. [GAP: multi-controller / subdomain-matching binary support — see issue #1517]

### Registration Credentials

Two credential flavors, both flow through the same registration API:

1. **Short-lived / single-use registration tokens** — generated on the controller via `cfg token create --expires=<duration> --single-use`. Suitable for manual onboarding, small fleets, or time-bounded provisioning windows. The token is consumed on use; expiry enforces time bounds.
2. **Long-lived tenant/group registration codes** — durable, non-single-use random opaque strings stored as a join field on the controller's tenant/group record. Suitable for RMM/GPO mass deployment where the same code is baked into a deployment script and reused by many devices. On registration the controller looks up the code in its records and assigns the steward to the matching tenant/group; the code itself carries no meaning, so renames of the tenant/group don't break previously issued codes.

The administrator chooses which flavor fits the deployment workflow. Both arrive at the steward as a plain string passed via `--regtoken <token>` (or `cfgms-steward install --regtoken <token>` for the OS-service install).

### Registration Flow

1. Administrator creates a registration token or code on the controller.
2. Steward is started with `--regtoken <token>`.
3. Steward contacts its compile-time controller URL (HTTPS), submits the token.
4. Controller validates the token (single-use: consume; long-lived code: look up the matching tenant/group record), applies the registration approval workflow (`auto-approve` or `manual-review`), and on approval issues mTLS certificates scoped to the steward's tenant/group identity.
5. Steward imports the issued cert into its local `cert.Manager` (stored under the platform cert dir) for use in TLS handshakes, records the node ID, and establishes a gRPC-over-QUIC transport connection.
6. Steward checks for a cfg from the controller.
7. Normal operation begins.

On every subsequent startup the steward re-registers via the same HTTP REST endpoint — HTTP registration is called on every invocation and there is no stored-certificate resume path that skips it. The cert stored by `cert.Manager` is used for TLS handshakes within the session but does not replace the HTTP registration call.

### Approval Workflow

Registration approval runs through the controller's workflow engine via the `RegistrationApprovalHook`. Built-in workflows:

- **`auto-approve`** (development default): accepts any valid token immediately.
- **`manual-review`** (production): pauses the registration workflow pending operator action via `cfg registration approve <id>` or `cfg registration deny <id>`.

Operators can also write custom workflows that implement arbitrary policy (e.g., auto-approve `tenant=lab` registrations, manual-review everything else).

### Bootstrap TLS Trust

The initial registration call is an HTTPS request to a controller whose TLS certificate is signed by a CA the steward has never seen. By default the steward validates against system root CAs. For MSPs that deploy controllers with a private CA (self-signed or internal PKI), set:

```
CFGMS_HTTP_CA_CERT_PATH=/path/to/controller-ca.crt
```

The steward loads the PEM-encoded CA certificate at startup and uses it exclusively to verify the controller's TLS certificate during registration. Once registration succeeds, all subsequent communication uses the mTLS certificates issued by the controller — the CA cert file is not needed again.

The controller writes its CA certificate to `<CFGMS_CERT_PATH>/ca/ca.crt` on first boot. In Docker or containerised deployments, mount the controller's cert volume read-only into each steward container and point `CFGMS_HTTP_CA_CERT_PATH` at the mounted path.

TLS verification is always enforced. There is no environment variable to disable it.

## Cfg Fields Governing Convergence

The convergence loop behaviour is controlled by fields in the cfg:

| Field | Default | Description |
|-------|---------|-------------|
| `steward.converge_interval` | `30m` | How often the steward re-converges against the cfg. Accepts any Go duration string: `"5m"`, `"30m"`, `"1h"`, etc. |
| `steward.drift_mode` | `apply` | How the steward handles detected drift. `apply`: correct drift with `Set()` + `Verify()`. `monitor`: emit `drift.detected.monitor` event, skip `Set()` and `Verify()`. **Controller-delivered only** — local file value is ignored. |

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
