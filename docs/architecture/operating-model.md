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
- **Deployment visibility** — `cfg config deployments <id>` shows applied / pending / failed / halted counts and per-steward status.
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
3. **Collect reports** — Receive status, events, DNA, health, and historical performance metrics from stewards. Aggregate for fleet-wide dashboards, compliance reporting, trend analysis, and troubleshooting. This data is the foundation for the **Digital Employee Experience (DEX)** track — a layered rollout (collection → baselines → root-cause → prediction → remediation), not a single future capability — and, with versioned DNA history, for the Digital Twin
4. **Run workflows** — Execute automation workflows for cloud/SaaS operations that don't require a steward (desired-state convergence for cloud resources, orchestration and data sync between third-party services, and imperative automation). The workflow engine runs **workflow-kind modules** (`executors: [workflow]`) — out-of-process gRPC binaries that the controller spawns to interact with cloud APIs on behalf of the workflow. See [controller operating model](controller-operating-model.md) for details
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

Both flow through the controller's registration approval workflow (`RegistrationApprovalHook`). The controller ships two built-in workflows selectable via `registration.workflow` in `controller.cfg`:

- **`auto-approve`** (default) — approves all valid registrations immediately. Uses `Variables: {policy: accept}` to short-circuit the engine without running steps. Safe for development and small trusted fleets.
- **`manual-review`** — quarantines each new steward pending operator action via `cfg registration approve`. Sets `registration_decision: quarantine` so the hook restricts the steward to baseline config only until promoted.

Custom workflows implement arbitrary policy via the workflow engine by deploying a workflow named `steward-registration-approval`.

**Admin identity is a single-file mTLS bundle.**
On `--init`, the controller writes the bundle to a known path:
- Linux/macOS: `/etc/cfgms/admin.bundle.yaml`
- Windows: `%ProgramData%\cfgms\admin.bundle.yaml`

YAML containing cert + key + CA inline. The `cfg` CLI auto-discovers via: `--bundle <path>` → `CFGMS_ADMIN_BUNDLE` env → `~/.config/cfgms/admin.bundle.yaml` → system path. `cfgms-controller bootstrap-admin` issues named bundles per operator, regenerates the system bundle, lists issued bundles, and revokes by serial.

### Outpost (Future)

Regional infrastructure component deployed at site level. Two roles:

1. **Proxy cache** — Caches binaries, packages, and cfg artifacts used by multiple stewards at the site, reducing WAN bandwidth and speeding up deployments
2. **Network operations** — Manages agentless endpoints that can't run a steward (switches, firewalls, APs, printers) via SSH, SNMP, and vendor APIs. Also performs network scans and topology discovery

The outpost runs **outpost-kind modules** (`executors: [outpost]`) to manage remote LAN devices. Outpost modules run on the outpost host and use the outpost as a proxy agent for devices that cannot run a steward. The outpost module runtime is the same gRPC-based runtime as the steward, scoped to the outpost process.

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

## Concurrent Controller Execution (Blue/Green Pattern)

CFGMS controllers are designed to support a **blue/green upgrade pattern**: two
controller binaries running on the same host (or two hosts sharing storage)
can coexist on the same data directory without corrupting state. This is the
substrate for the zero-downtime upgrade flow described in epic #1917.

### What's safe

- **Read concurrency.** Both controllers can serve API reads concurrently against
  shared storage. Storage backends are coordinated via filesystem-level
  primitives (POSIX rename / Windows MoveFileEx + retry for flatfile; WAL-mode
  shared-memory locking for SQLite).
- **Single-writer + reader peers.** During cutover, one controller is the
  primary writer for new state (registrations, heartbeats, config updates) and
  the peer serves reads. Identity continuity is exact: a steward registered
  against the writer is immediately visible on a read from the peer — no
  replication lag, no re-registration. See `pkg/storage/providers/sqlite/
  concurrent_writers_test.go::TestSQLite_IdentityContinuity_BlueWriteGreenRead`
  for the pinned guarantee.
- **Concurrent writes to disjoint keys.** Two writers updating different
  records concurrently complete safely. WAL coordinates SQLite writers; atomic
  rename + retry coordinates flatfile writers.

### What's not safe (yet)

- **Concurrent writes to the same key.** Two writers updating the same
  steward record / config / RBAC entry at the same moment race on
  last-writer-wins semantics. No corruption, but the merge is unordered. This
  is acceptable for blue/green cutover (the primary writer is well-defined at
  any given moment) but is **not** acceptable for multi-active HA — that
  needs a separate epic with proper write coordination.
- **Schema migrations during cutover.** A migration that changes column or
  field shapes must run during a maintenance window or after both sides have
  upgraded. Blue/green cutover assumes both binaries speak the same storage
  schema.

### Storage layer guarantees

| Backend  | Concurrency contract                                                                                                                                                                                                              |
|----------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| SQLite   | WAL mode + `busy_timeout=5000ms`. Multiple `*sql.DB` handles on the same file (in-process OR cross-process) write safely without lock failures. Tested at 1000 concurrent writes split across two handles with zero failures.    |
| Flatfile | Writes commit via atomic temp-file + rename. On Windows, rename retries `ERROR_SHARING_VIOLATION` from concurrent readers; reads retry the same error from concurrent writers. Tested with 1 writer + N reader subprocesses, 0 torn reads. |

### Operator interface

The blue controller runs on the canonical ports from `controller.cfg`. The
green controller binds on overrides supplied at startup:

```sh
cfgms-controller \
    --config /etc/cfgms/controller.cfg \
    --listen-api-addr :9081 \
    --listen-transport-addr :4434
```

Precedence: CLI flag > env var (`CFGMS_HTTP_LISTEN_ADDR`,
`CFGMS_TRANSPORT_LISTEN_ADDR`) > cfg file value > built-in default. Both
binaries read the same `data_dir`, same storage configuration, same identity
material — so the green binary is bit-for-bit indistinguishable from the
blue binary in terms of "what it serves." Only the listen addresses differ.

The cutover mechanism itself (story #1920) is implemented as
**port-ownership-swap** — not a byte-level reverse proxy. The
orchestrator (`features/controller/cutover`) drains the previous
canonical, waits for the canonical ports to free, then spawns a fresh
instance of the new binary on those ports. Stewards reconnect via the
gRPC-over-QUIC backoff already built into the client. Typical wall-
clock window: 1-3 seconds.

Operator commands:

```sh
cfg controller upgrade run --binary /opt/cfgms/cfgms-controller-vNEW \
    --config /etc/cfgms/controller.cfg
cfg controller upgrade status
cfg controller upgrade rollback --config /etc/cfgms/controller.cfg
```

State persistence: `/var/lib/cfgms/cutover.state.json` (Linux) or
`%ProgramData%\cfgms\cutover.state.json` (Windows) records the
canonical + quarantined binary paths so `status` and `rollback` work
across CLI invocations. The full operator runbook lives at
[docs/operations/controller-upgrade.md](../operations/controller-upgrade.md).

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

## Cluster Prerequisites

Controller startup in `ha.mode: cluster` performs an early prerequisite gate before reading or writing any state. If any prerequisite is unmet, the controller exits immediately with a clear error.

### Required backends

| Backend | What it provides | How to configure |
|---------|-----------------|------------------|
| Postgres storage provider | Shared business-store state across all controller nodes (RBAC, tenants, sessions, registrations); also backs `pkg/session.Store` (`DatabaseSessionTokenStore`) so `cfg`/web session tokens issued on one node are validated and revoked on any peer node (Issue #2775) | `storage.cluster.postgres_dsn` or `CFGMS_STORAGE_CLUSTER_POSTGRES_DSN` |
| S3-compatible blob store | Shared installer artifact repository so all nodes serve the same steward binaries | `CFGMS_S3_INSTALLER_BUCKET` (required); `CFGMS_S3_INSTALLER_REGION`, `CFGMS_S3_INSTALLER_ENDPOINT_URL` (optional) |

### Startup error messages

```
cluster mode requires a cluster-capable storage backend; provider "flatfile" does not support cluster coordination
cluster mode requires S3-compatible blob storage: set CFGMS_S3_INSTALLER_BUCKET
```

Both gates fire before any tenant, RBAC, or steward state is touched, so a misconfigured cluster fails fast rather than partially initialising.

### Non-cluster modes

Single-server and blue/green deployments skip the cluster gate entirely. They use the OSS composite backend (flatfile + SQLite) or a standalone Postgres provider, and store installer artifacts on the local filesystem under `BlobStorage.Root`.

## UX Surfaces

Operators interact with CFGMS through layered UX surfaces.

**`cfg` CLI — first-class community UI.** The canonical interaction surface for the open-source distribution. Every documented operator action works through the CLI. The CLI wraps REST endpoints so operators don't need to script against REST for documented workflows. `cfg steward logs` is available but returns 501 until a log-pull transport is wired.

**Web UI (planned before v1).** A separate UX layer for operators who prefer graphical workflows or shared-team views. Some power-user flows may remain CLI-only.

**REST API — underlying contract.** The wire format the CLI and web UI both use. Stable, versioned, and documented at `docs/api/rest-api.md`. Available to operators and integrators for scripting and third-party tools.

**Workflow engine — automation surface.** For SaaS/cloud operations that don't require a steward (M365, identity providers, ticketing systems), the workflow engine is the primary expression mechanism. See [controller operating model](controller-operating-model.md#workflow-engine).

## Controller Blob Store Namespaces

The controller blob store (`pkg/storage/interfaces/blob.BlobStore`) partitions binary artifacts by namespace within each tenant.

| Namespace | Purpose |
|-----------|---------|
| `installers` | Platform installer packages uploaded via `PUT /api/v1/installer/artifacts/{platform}/{arch}` |
| `steward-binaries` | Versioned steward binaries published via `POST /api/v1/installer/steward-binaries/{version}/{platform}/{arch}`. Each entry carries publisher-signature metadata and the publishing operator identity. |

Steward binary distribution uses the `steward-binaries` namespace exclusively. Blob keys take the form `{version}-{platform}-{arch}` (e.g. `v0.5.12-linux-amd64`). Binaries must carry a valid Ed25519 publisher signature verified against the CFGMS publisher identity before storage.

## Steward Upgrade Dispatch Flow (Epic #1930)

The controller can push a new steward binary to one or more stewards via a selector-based fan-out.
The flow enforces an approval gate before dispatch and records per-steward lifecycle state in a durable `UpgradeStore`.

### Dispatch steps

1. **Publish**: operator calls `POST /api/v1/installer/steward-binaries/{version}/{platform}/{arch}`.
   The controller verifies the Ed25519 publisher signature and stores the blob with `publisher`, `publisher_tenant`, and `signature` labels.
2. **Approve**: a separate operator (with `installer:approve:steward` permission) sets the `approved_by` label on the blob.
   The controller records the approver identity in `BlobMeta.Labels["approved_by"]`.
3. **Dispatch**: operator calls `POST /api/v1/stewards/upgrade` with a fleet selector (e.g. `id:steward-abc`), version, platform, and arch.
   The controller:
   a. Parses the selector and applies the caller's tenant scope.
   b. Resolves matching stewards via `FleetQuery.Search`; drops stewards from other tenants (403 if none remain).
   c. Verifies the blob's `approved_by` label is non-empty (403 if missing — "published but not approved").
   d. Recomputes SHA-256 from the stored blob bytes (does not trust `BlobMeta.Checksum`).
   e. Checks for non-terminal upgrade records per steward; returns 409 if any exist.
   f. Creates one `UpgradeRecord` per steward (status: `dispatched`) with publisher provenance fields (`Publisher`, `BundleSignature`, `SignatureDigest`) and a 32-byte `OperationNonce` for replay defense.
   g. Fans out `CommandPushStewardBinary` to each steward via the control plane (fire-and-forget goroutine).
   h. Returns `202 Accepted` with `upgrade_id` (the first steward's record ID) and `steward_count`.

### Approval state machine

```
published ──► approved ──► dispatchable
   │               │
   └── dispatch    └── dispatch blocked
       blocked         unblocked
```

| Blob label       | Meaning |
|-----------------|---------|
| (absent)         | Not yet published (blob does not exist) |
| `published_by`   | Binary has been published; awaiting approval |
| `approved_by`    | Binary is approved and dispatchable |

### UpgradeRecord lifecycle

```
dispatched ──► downloaded ──► swapped ──► committed
                                     └──► rolled_back
(any state) ──► failed
```

Terminal states (`committed`, `rolled_back`, `failed`) unblock re-dispatch to the same steward.

### Durable store requirement

The controller refuses dispatch with `503 Service Unavailable` if no durable `UpgradeStore` is
configured at server startup. There is no silent in-memory fallback — durable state is required
to survive controller restarts and HA failover replay.

### Rollback

`POST /api/v1/stewards/upgrade/{upgrade_id}/rollback` requires an explicit `version` field
(named target, not most-recent). The rollback is a dispatch-equivalent action: it looks up the
original steward, fetches the target-version blob (must be approved), creates a new `UpgradeRecord`,
and fans out `CommandPushStewardBinary`. Requires `installer:dispatch:steward` permission.

## Monitoring Export Credentials

OTLP exporter credentials (API keys / bearer tokens) are stored in `pkg/secrets`, not in config files. Configure the secret key name via `config["secret_key"]` and use `NewOTLPExporterWithSecrets` to wire the store at construction time.
