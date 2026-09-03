# Steward Operating Model

How the steward behaves at runtime. This document governs steward implementation decisions — every steward feature and issue should be consistent with the model described here.

For the system-level operating model, see [operating-model.md](operating-model.md).
For cfg format details, see [steward-configuration.md](steward-configuration.md).

## One Sentence

The steward is a daemon that maintains a device in the state described by its cfg, reports on compliance, and optionally connects to a controller for cfg delivery, reporting, and remote operations.

## Lifecycle

### Startup

The steward starts immediately when the OS service manager launches it and runs
regardless of what else on the host is ready. Subsystems attach as they become
available — the process never exits because a dependency is not yet up. (Issue #2034)

1. **Early logger** — A stderr logger is active from the first instruction, before any disk or network call. A file-based logger is initialised next; if that fails (e.g. log dir not yet writable at early boot) the process continues with the stderr fallback.
2. **Load cfg** — Find and parse the `hostname.cfg` file (local file, or last-known cfg from controller)
3. **Discover modules** — Scan module paths and register available modules. Modules referenced in the cfg are loaded on-demand during convergence (not validated at startup)
4. **Initial convergence** — Evaluate every resource in the cfg immediately (apply or monitor, depending on `drift_mode` received from the controller)
5. **Start convergence schedule** — Begin the compliance re-check loop at the interval defined by `converge_interval` in the cfg (default: 30 minutes). DNA is collected as part of each convergence run (not a separate startup step)
6. **Connect to controller** (if configured) — Attempt a gRPC-over-QUIC transport connection. If the network or controller is not yet reachable, the steward marks itself `degraded` and retries in the background with exponential backoff (5 s → 5 min). The process continues running during the retry period. No `depend=` / delayed-start service ordering is required or relied upon.

#### Health states during startup

| State | Meaning |
|-------|---------|
| `degraded` | Process is alive but one or more subsystems (controller, DNA/WMI) are not yet attached |
| `healthy` | All subsystems have attached and the convergence loop is running normally |

The `degraded` state is reported in the controller-facing heartbeat so operators
and the launcher's known-good gating can distinguish "started but waiting on
WMI/network" from "broken". A registered steward that sends no heartbeat for
≥ 90 s (≈ 3× the 20 s base heartbeat interval + jitter per epic #1664) is
treated as alertable by the controller.

**Fail-closed during degraded mode:** integrity checks are never relaxed while
degraded. Config-signature failures remain hard rejections (codes.DataLoss).
Module trust verification with `module_trust.mode: controller` refuses to load
modules when the controller is unreachable — it never falls back to `bypass`.
An unloadable or tampered cert store triggers re-registration or stop, not a
degraded-but-trusted continue.

#### Windows service-registration self-repair (#2465)

On Windows the launcher supervises the steward as a Service Control Manager
(SCM) service (`CFGMSSteward`). The SCM's install-time recovery actions restart
a *crashed* service, but they cannot help if the service **registration itself**
is deleted out from under the running launcher — the failure mode observed live
when an anti-virus product quarantined the launcher binary and removed its SCM
entry as "remediation", leaving the steward silently and permanently dead until
a manual reinstall.

To close that gap the launcher runs a dedicated self-repair ticker inside its
supervise loop, on its own cadence (≤ the fastest SCM recovery delay, 10 s) and
**independent of the supervised child's lifecycle** — a stable steward may run
for weeks between child restarts, so the check must not be gated on that. Each
tick verifies the `CFGMSSteward` registration still exists and, if it has been
deleted, re-creates it with the same binary path, automatic start type, and
recovery actions as the original install, reusing the currently-running
process's own arguments. The repair is logged loudly at warning level with a
greppable `event=service_registration_repaired` field (visible in
`C:\ProgramData\cfgms\logs`); a repair that itself fails is logged and the
supervise loop continues rather than crashing (the steward child is unaffected
by a missing SCM entry until the next reboot). This behavior is Windows-only —
the launcher's supervise loop no-ops the check on Linux/macOS.

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

### Tiered Convergence (ADR-024 Amendment 1)

Each convergence tick is classified as **Tier-1** or **Tier-2**. Both tiers enforce identical drift-detection and resource-enforcement semantics; they differ only in what happens after declared-resource work completes.

**Tier-1 (every cycle):** Declared-resource enforcement — `Get → Compare → Set → Verify` for every resource in the active cfg. Fast and lightweight; runs every convergence tick.

**Tier-2 (every Nth cycle):** All of Tier-1, plus a whole-domain observe sweep. `N` is the `steward.observe_sweep_n` knob in the steward config file. When the key is absent — including when the steward has no local config file at all — `N` defaults to 10, so the sweep runs on every 10th tick. Setting `N = 0` disables the sweep entirely. Setting `N = 1` runs the sweep on every tick. Negative values are rejected at config validation.

**Tier-2 observe sweep sequence:**

1. The steward reports its current baseline DNA to the controller as an `EventObserveSweepRequest`.
2. The controller resolves which observe modules apply to this device (matching `observe_when` predicates against the reported DNA) and responds with `CommandObserveModules` carrying the resolved `{name, kind}` specs.
3. For each spec, the steward loads the module via the existing signed/trust-verified pull path, invokes its `Get()` read-only, and collects the resulting fragments.
4. Observe-module fragments are merged into the existing DNA fragment set via `Assembler.Assemble`, then committed through `setCurrentDNAFragments` — **the same emission path used by declared-resource convergence** (ADR-024 Amendment 1 §2; no new channel). Module authority always preempts observe-only host-fact fragments for the same kind (ADR-016).

The observe sweep adds endpoint-side CPU proportional to the number and cost of matched observe modules, controllable by tuning `N`.

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

### Convergence Event Emitter (ADR-012)

For every resource check that reaches the drift-comparison step, the execution engine emits a correlated detection+outcome event pair over an out-of-band `LogStream` channel to the controller. The emitter runs on its own goroutine, independent of the module-execution goroutine; the convergence loop enqueues events via a non-blocking call and never waits for the send to complete. When the buffer is full, entries are dropped and counted. The emitter reconnects automatically with exponential back-off if the `LogStream` RPC fails.

**Detection event** — enqueued immediately before `module.Get()`, carrying a newly generated `correlation_id`, the `resource_id`, and the active `drift_mode`. A detection event with no matching outcome event signals that convergence hung inside a module (ADR-012 §2 crash-isolation).

**Outcome event** — enqueued after convergence completes, with the same `correlation_id` and an `action` field: `applied` (convergence succeeded), `drift_reported` (monitor mode), `error` (Set or Verify failed), or `did-not-finish(timeout)` (per-call deadline exceeded — see below).

**Per-call module timeout (ADR-012 §7)** — each individual `module.Get`, `module.Set`, and `verifyChanges` call runs under its own `context.WithTimeout` (default 120 s, configurable via `ExecutorConfig.ModuleCallTimeoutSec`; there is no "infinite" option). If a module call exceeds its deadline, the executor emits a `did-not-finish(timeout)` outcome event carrying `timeout_ms` (the configured ceiling) and `duration_ms` (actual elapsed), then returns `StatusTimeout` immediately — converting the former silent wedge into two queryable, correlated events. Errors that return before the deadline continue through the existing `handleResourceError` → `ConfigStatusReport` → `StatusError` path unchanged.

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

### Stdlib Modules

The six stdlib modules (`file`, `service`, `package`, `script`, `firewall`, `patch`) ship as out-of-process gRPC binaries bundled in the steward installer. They use the same module contract as third-party modules — publisher-signed bundles, verified by the runtime at load time, invoked via `CFGMS_MODULE_SOCKET`. There are no compiled-in modules; stdlib is governance (installer payload), not implementation.

Because they are part of the installer payload, the stdlib modules load at steward startup without any network access to the controller — a steward can converge against locally-cached cfg using the stdlib set even when the controller is unreachable. The `directory` resource is no longer a separate module: it is the `file` module's `type: directory` variant.

Installer bundling:
- **Linux** (tar.gz): binaries at `usr/local/lib/cfgms/modules/cfgms-module-<name>`, copied by `install.sh`
- **macOS** (.pkg): binaries at `/usr/local/lib/cfgms/modules/cfgms-module-<name>`, included in the pkg payload
- **Windows** (MSI): binaries at `C:\Program Files\CFGMS\modules\cfgms-module-<name>.exe`, included via WiX components

### Module Trust Modes

The steward verifies module bundle signatures according to the `module_trust.mode` field in `steward.cfg`:

| Mode | Verification | When to use |
|------|-------------|-------------|
| **`controller`** (default) | None — the steward accepts any bundle the controller has approved | Normal deployment; trust is delegated to the controller |
| **`strict`** | Steward independently verifies Ed25519 signatures against its local trust set: the CFGMS publisher identity baked in at build time, plus any publishers listed in `additional_publishers` | High-security environments where a compromised controller must not be able to push arbitrary code to stewards |
| **`bypass`** | None — no verification | Development and testing only |

In `strict` mode, the trusted publisher set is:
1. The `cfgms` publisher identity — a 32-byte Ed25519 public key compiled into the steward binary at build time via `-ldflags`. This identity cannot be changed via cfg push.
2. Additional publishers listed in `steward.cfg` under `module_trust.additional_publishers` (v1: by name only; key material lookup from a durable trust store is future work).

**Threat model invariant**: a compromised controller cannot push arbitrary modules to stewards running in `strict` mode — the steward rejects any bundle whose publisher key is not in its local trust set, regardless of controller approval.

### Module Runtime Lifecycle

Out-of-process module binaries are managed by the steward module runtime. Each module runs in a separate process connected over a local socket:

**Startup sequence (per module):**

1. `starting` — runtime fork/execs the module binary; passes the socket path via `CFGMS_MODULE_SOCKET` environment variable
2. `ready` — runtime polls the socket until the module process starts listening, then dials gRPC and calls `Handshake`
3. `running` — module is operating normally; the steward holds an active `StewardModuleClient` gRPC session

**Socket paths:**
- Unix: `${runtime_dir}/sockets/cfgms-module-<name>-<id>.sock` — sockets live in a steward-private directory created mode 0700; the mode is re-asserted on each start. Socket file permissions are the module-channel trust boundary: the gRPC channel carries no per-caller credentials, so access is controlled solely by the directory owner bit.
- Windows: `\\.\pipe\cfgms-module-<name>-<id>` — Windows enforces per-user pipe ACLs at the kernel level.

**Shutdown sequence:**

1. `stopping` — runtime sends the `Shutdown` RPC; module should exit cleanly
2. `stopped` — if the module has not exited within **10 seconds** after the `Shutdown` RPC, the runtime kills the process; socket file is removed

Trust verification (in `strict` mode) is performed **before** fork/exec. If the bundle fails trust verification, `Start()` returns `ErrPublisherNotTrusted` and no process is started.

### Four Execution Paths

Every byte of code that runs on a steward arrives through exactly one of these paths (see ADR-006 for full details):

| Path | Trust anchor | Notes |
|------|-------------|-------|
| **Modules** | Publisher-signed bundle | gRPC module invoked to enforce cfg |
| **Scripts** | Publisher-signed; cfg-content staged to disk with recorded hash | `<interpreter> -File <path>` against on-disk file |
| **Inline cfg CLI commands** | Admin mTLS-signed payload, end-to-end | Separate epic |
| **Remote shell** | Interactive admin session | Separate epic |

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

The convergence runtime now wires `Monitor` automatically: on cfg load it calls `Monitor(ctx, resourceID, desired)` for every module that implements the interface, fans in the `Changes()` channels, and on each `ChangeEvent` runs a targeted `ExecuteResource` for the changed `resourceID` (treating the event as a hint — actual state is re-read via `module.Get()` and desired state comes from the cfg, never from `event.Details`).

### Monitor Resilience

The Monitor consumer is hardened against event storms, slow modules, and concurrent shutdown:

| Property | Behaviour |
|----------|-----------|
| **Debounce** | Duplicate events for the same `resourceID` within a 1.5 s window are coalesced into a single `ExecuteResource` call. The first event starts a timer; subsequent events within the window are dropped. |
| **Bounded queue + shed-to-poll** | The fan-in channel has a fixed capacity of 64 events. When full, incoming events are dropped with a `Warn` log entry (`"Monitor event queue full, event shed to scheduled poll"`). The scheduled `convergenceLoop` continues at its normal interval and will correct any resources whose events were shed. |
| **DNA refresh on change** | After a targeted reconcile that calls `Set` (i.e. `ChangesApplied = true`), the steward re-collects the DNA snapshot immediately. The refreshed hash is available on the next heartbeat without waiting for the next scheduled convergence tick. |
| **Clean shutdown** | `Stop()` closes the shutdown channel (stopping all pending debounce timers), waits for fan-in and event-loop goroutines to exit via `WaitGroup`, then calls `Close()` on each active monitor before unloading modules. No `Set` call can run after `Close()`. |

Current adoption:

- **Implemented**: `hyperv` (VM state — power on/off and create/delete, via a single host-level Windows Event Log subscription over the Hyper-V VMMS/Worker channels; Windows only, polling backstop elsewhere)
- **Polling-only (no Monitor yet)**: `activedirectory`, `file`, `script`, `firewall`, `package`, `patch`

Adding `Monitor` support to additional modules is an ongoing enhancement, prioritized by user impact (security-sensitive resources benefit most from event-driven detection).

### Monitor Load Budget and Reaction Latency

Measured end-to-end on a live Hyper-V host (Windows Server 2025) against the `hyperv` VM-state Monitor, validating both a Windows and a Linux guest VM (Issue #2115). The budget is per active host subscription, not per watched VM — the `hyperv` Monitor uses a single host-level `EvtSubscribe` shared across all watched VMs.

| Metric | Budget / target | Measured |
|--------|-----------------|----------|
| Idle goroutines | ≤ 1 reader goroutine per active subscription | +1 (one Event-Log reader pump) |
| Idle heap allocation delta | < 2 MB | ~9 KB |
| CFGMS-owned subscription handles | ≤ 2 (the `EvtSubscribe` handle + the auto-reset signal event) | 2 |
| Total process OS-handle delta around `Monitor()` | observed, not a hard budget | ~16 (the extra ~14 are ALPC/RPC handles the Windows eventing service `wevtsvc` opens beneath `EvtSubscribe`; CFGMS neither owns nor can enumerate them) |
| Per-extra-VM OS-handle growth (single-subscription invariant) | ~0 | +6 for 3 additional watched VMs (benign service-side churn, **not** new subscriptions — a per-VM subscription regression would add ~16 each) |
| Idle CPU | < 0.1% | Not asserted in-process — the reader goroutine is idle-blocked in `WaitForSingleObject`; observed negligible. |
| **Reaction latency — event** | < 2 s (out-of-band change → `ChangeEvent` on `Changes()`) | < 20 ms (sub-poll-granularity) |
| **Reaction latency — correction** | < 5 s (reconcile applies `Start-VM` once the drift is visible) | ~0.9 s |
| Teardown | `Close()` joins the reader goroutine; no goroutine leak (`goleak`) | clean (0 leaked goroutines) |

**ps-host state-propagation caveat.** The Hyper-V Event Log signal fires within milliseconds of an out-of-band VM power-state change, but the persistent ps-host PowerShell session's `Get-VM` lags the true VM state by several seconds (≈5 s observed) after such a change — VMMS state propagation to that long-lived session. Because a single out-of-band change is debounced into **one** targeted reconcile, a reconcile whose `Get` runs before propagation reads the stale prior state and no-ops, dropping the correction until the next scheduled convergence tick. The production debounce (1.5 s) does not fully cover the observed lag. Operators relying on sub-tick event-driven correction of Hyper-V VM state should be aware that the *correction* (not the detection) can be delayed to the scheduled `converge_interval` when the propagation lag exceeds the debounce window; the scheduled poll is the guaranteed backstop. Tightening this (e.g. a fresh-CIM query in the ps-host `Cfgms-GetVM` verb, or a short reconcile retry when a change event finds no drift) is tracked as a follow-up.

## Self-Awareness

The steward continuously knows about itself. This information is collected independently of the convergence loop.

### DNA (Digital Native Attributes)

The device's stable, hashable state — a **set of addressable fragments**, not a flat snapshot (ADR-016 / ADR-017). Each fragment has an object-canonical **typed entity id** (`service:sshd`, `host:cpu`), a single resolved **authority** (a managing module, or the gatherer/osquery for observe-only host facts), and a **provenance envelope** (`source`, `observed_at`, `confidence`) carried outside its hash. For the per-attribute audit of the **legacy** flat-map collector this model retires, see [DNA Collection Audit](dna-collection.md).

Fragments are sourced by class:

| Class | Examples | Authority | Drift |
|-------|----------|-----------|-------|
| **Managed** | services, files, users, packages, firewall (from module `Get`) | managing module | enforced (`auto_correct` / `report_only`) |
| **Observe-only** | CPU model, total memory, BIOS, OS build | **interim**: existing per-platform gatherers (ADR-017 Amendment 3); **future**: osquery source swap | report-only |

> **Interim authority note (ADR-017 Amendment 3):** The `host:*` observe-only fragments
> (`host:cpu`, `host:memory`, `host:os`, `host:bios`) are currently sourced by the existing
> per-platform gatherers (`features/steward/dna/{hardware,network,security}_*.go`) via a
> partition step that reads the already-collected flat attribute map. The gatherers are reused
> unmodified. The `commonpb.DNA.attributes` proto field (the legacy flat surface) was retired in
> Issue #3331; all controller consumers now project attributes from `DNA.Fragments` via
> `service.FlattenDNAFragments`. The osquery integration will later **swap the source** of the
> same `host:*` fragment ids — a source change only, invisible to fragment consumers, deferred
> to a follow-on epic.

Ephemeral runtime values (utilisation, PIDs, per-process metrics, health) are **not DNA** (ADR-017 clause 4) — see [Performance](#performance) below. DNA serves two purposes:
1. **Device identity** — the typed entity ids the controller uses to identify and classify devices, and the shared join key for the topology graph and DEX
2. **Drift baseline** — managed fragments whose state diverges from desired trigger drift correction

#### Monitored module resource state — flat attributes and cluster fragments

The steward's monitor fan-in caches the newest `ChangeEvent` details per
resource (last-write-wins, no history). Two output paths are derived from the
same cache:

**Flat attribute path (non-cluster resources):**  `Executor.CollectModuleDNAAttributes`
merges flattened resource state with the hardware-fact attributes on the same
refresh tick — the same delta-compressed publish path, no separate channel.

Flattening and namespacing convention:

- every key is `<resourceID>.<field>` with the resource ID **verbatim** —
  including its colon, with no module-name prefix
- nested map keys join with `.` — `resource_owner.web-01`
- slice values join with `,`
- any other value stringifies (`true`, `3`)

**Fragment path (cluster:* resources, Issue #2908):**  `Executor.CollectModuleFragments`
produces one `cluster:<Name>` ADR-017 fragment per cached cluster:* resource.
Each fragment's `CanonicalBytes` encode the full `ClusterStatus.AsMap()` payload
(including `resource_owner`, `member_nodes`, `cno_owner_node`, `found`) using the
deterministic `CanonicalizeFragment` binary encoding. The controller cluster
registry (`features/controller/clusterregistry`) reads from `StewardData.DNAFragments`
and decodes the canonical bytes via `DecodeCanonicalFragment` to extract role
ownership.

> **Wire protocol note:** Fragment transmission steward→controller via
> `DNATransfer` / `reassembleDNA` is deferred to a follow-on story; the fragment
> wire shape is defined but not yet wired. The identity check
> (`firstChunk.GetStewardId() != peerID` in `dna_handler.go`) applies to the
> full DNA sync and continues to protect all DNA — including any future fragment
> payloads — from spoofing.

A resource that leaves monitoring (module close, steward shutdown) is evicted
from the cache, so its flat keys disappear from the next collected map and its
fragment disappears from the next `CollectModuleFragments` call — the delta
publish signals the removal. The snapshot is **eventually consistent** by
design: it rides the DNA refresh interval, and any safety-critical decision
(e.g. cluster ownership gating) always uses live module queries, never this
snapshot.

### DNA Sync Model

DNA is a deterministic, hashable dataset with a **two-level (Merkle-style) hash**: a per-fragment hash over each fragment's canonical bytes, and an **aggregate root** over the sorted `(fragment_id, fragment_hash)` manifest. The steward includes the aggregate root in every heartbeat, keeping the controller aware of DNA currency with near-zero bandwidth.

- **Heartbeats** carry the aggregate root (control plane, every heartbeat interval)
- **Partial sync**: on a root mismatch the controller diffs manifests and requests only the changed/added/removed fragments' bytes (data plane), then recomputes the root to prove its copy is fully in sync — no whole-DNA re-transfer
- **Full sync** is required only on initial registration

The controller stores DNA **versioned and append-only** (ADR-017 Amendment A1.3), not last-write-wins: each accepted delta produces a new fragment version, so per-entity state stays queryable over time. Because unchanged fragments dedupe by hash, history cost tracks change volume, not fleet-size × time.

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

This data is the collection foundation for **Digital Employee Experience (DEX)** — a layered track (collection → attribution → baselines → root-cause → prediction → experience-driven remediation), not a single future capability. Building collection and local retention now means DEX's later layers become an analytics + workflow-engine remediation loop on top, not a rebuild. DEX signals attach to the same typed entity ids as DNA (ADR-017 Amendment A1.4), so baselines and root-cause join against DNA and the topology graph rather than forming a separate data island.

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

### Fencing-Token Command Fence (ADR-029 Decision 6; substrate updated by ADR-031 Decision 5 / Issue #3760)

Every inbound `Command` carries a fencing token stamped by the controller that published it (`Command.Term`, #3390). The field name and wire type are unchanged since #3390 — a `uint64` — only its source has moved: originally the Raft term the controller cluster was at (ADR-029 Decision 5), it is now the S3 database lease's monotonic fencing token (ADR-031 Decision 5, Issue #3760), read via `ha.Manager.GetTerm()` either way. Only a cluster deployment (`ha.mode: cluster`) holds that lease and therefore stamps a non-zero token; single-server and blue-green deployments have no lease to draw one from and publish unstamped commands, which the ratchet's first column already covers. The steward tracks the highest value it has observed and enforces a three-state ratchet on the receive path, ahead of command dispatch — this mechanism did not change when the source did:

| Steward state | Unstamped command (`term` missing or 0) | Stamped command (`term > 0`) |
|---|---|---|
| Never seen a stamped command | **Accept** — genuine bootstrap, or mid-rollout behind a controller predating #3390 | **Accept**, record the value as the new high-water mark, set the ratchet |
| Ratchet set | **Reject — downgrade attempt**, not legacy traffic | Accept iff `term >= highest_seen`; reject and leave the high-water mark unchanged otherwise |

A rejected command is a refusal, not a transport error — it never reaches the command dispatch pipeline, and it does not disconnect the control channel or trigger a convergence-loop retry. Rejections are logged at `WARN` (every value derived from the rejected command passes through `logging.SanitizeLogValue()`, including the claimed fencing token).

#### Ratchet Persistence (#3437)

Both ratchet fields — the ratchet-set flag and the high-water fencing token — are persisted to `fence_ratchet.json` in the steward's cert store directory (`CertStoreDir`). The file is written atomically (write-to-tmp then rename) every time the ratchet advances. On startup, `NewTransportClient` loads the file; a missing or unreadable file is treated as "never seen a stamped command" (the same as first boot). This means a routine steward restart no longer resets the fence: a stale leader's old command cannot exploit a restart to look like "never seen a fencing token before" and be accepted inside the dual-authority window the epic exists to close.

#### Enrollment-Path Reset (#3437)

A legitimate controller-cluster rebuild restarts the fencing-token source from its low-water value (Raft terms restarted at 1; the database lease's token starts fresh at 1 for a newly created lease row). Without a reset mechanism, a steward holding a persisted high-water value above that would permanently reject the new cluster — total loss of fleet control. The reset is `registration.resetFenceRatchetOnEnrollment`, which calls `FenceRatchet.ClearRatchet()` and removes the persisted state so the fence starts fresh on the next startup.

**Where it fires.** The registration client (`features/steward/registration/client_http.go`) invokes the reset at its two enrollment-completion points, and nowhere else: `Register`'s HTTP 200 branch (immediate approval) and `PollStatus`'s `claimed` branch (approval by an operator). `cmd/steward/main.go`'s `registerAndConnect` supplies `HTTPConfig.CertStoreDir`, which is what gives the client a durable ratchet to clear; the certificate-refresh path (`refreshAndConnect`) leaves it unset, because re-issuing a certificate for the same cluster is not a cluster rebuild.

**What is verified before it fires.** The reset is conditional, not a rename of `ClearRatchet`. `verifyEnrollmentCertSet` requires the enrollment response to carry a complete certificate set (client certificate, client key, CA certificate); that the certificate and key are a usable pair; and that the leaf chains to the CA delivered in the same response, is inside its validity window, and carries the client-auth EKU. Any failure leaves the persisted fence exactly as it was and logs at `WARN` — fail-closed, since a cleared fence re-opens the dual-authority window. A pending (HTTP 202) registration and an already-claimed (HTTP 410) poll carry no certificate set and so are not enrollment completions.

**Physical isolation.** `resetFenceRatchetOnEnrollment` is unexported and lives in the steward-side enrollment client, and it is the only production caller of `ClearRatchet` in the codebase. `features/steward/client` (the command-receive package) therefore cannot name it — the Go compiler, not a convention, is the primary enforcement. The AST-walk test `TestNoRatchetClearCallerOutsideRegistration` (`features/steward/registration/architecture_test.go`) covers `ClearRatchet`, the reset function, and its exported spelling, so neither a direct call nor a re-exported wrapper can reintroduce a path from the command-receive package. An attacker who controls the command channel cannot trigger the reset.

**Safety contingency.** The enrollment exchange is TLS-authenticated in the server direction — the steward verifies the controller against its pinned or installed CA — and the steward presents a registration token; it is not mutual TLS, and the certificate-set verification above proves only that the material came from whichever CA that exchange presented. Closing the registration-gating gap is a forthcoming (private/deferred) story. Until it lands, the reset is safe against the failure modes this story exists for — a routine steward restart and a legitimate controller-cluster rebuild — but not unconditionally safe against a network adversary who can both spoof the registration endpoint and be trusted by the steward's configured trust store. See `features/steward/registration/client_http.go:resetFenceRatchetOnEnrollment` for the inline contingency notice.

Whether a given steward is capable of enforcing the fence at all is determinable from the controller via the existing `GET /api/v1/stewards` `StewardInfo.Version` field — no separate capability flag was introduced. A steward at a fence-capable version that has not yet seen a stamped command is in the accept-unstamped bootstrap state, not actively rejecting anything; that is expected for a freshly enrolled or freshly upgraded steward, not itself a sign of compromise.

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

Log directory is controlled by `CFGMS_LOG_DIR`. The three native installers set it automatically to the platform-conventional paths listed under *Log locations* above (Linux `/var/log/cfgms/` via the systemd unit's `Environment=` line, Windows `C:\ProgramData\CFGMS\logs\` via the service's registry `Environment` value, macOS `/usr/local/var/log/cfgms/` via the launchd plist's `EnvironmentVariables` dict) — an installed steward never falls back silently. A steward run bare (no installer — dev/manual/e2e) keeps the `/tmp/cfgms`-with-a-warning fallback.

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

#### Operator Payload Signature Verification (Issues #3694/#3696/#3697)

An inline ad-hoc command is verified in `preflightScriptSignature`
(`features/steward/commands/execute_script.go`) before the executor ever runs. The
signature covers `operatorpayload.CanonicalBytes` of the reconstructed envelope
(content, shell, resolved target list, nonce, expiry) — never content alone — and the
envelope must name this steward's own ID, must not be expired, and its nonce must not
have been seen before, regardless of which credential type signed it.

Two credential types are accepted, dispatched on which proof fields are present in the
command:

- **X.509 / CSR-issued payload-signing credential.** The operator signs with the
  zero-custody credential `cfg credential request-signing-cert` issues (Issue #3696);
  the certificate must chain to the steward's configured controller CA and carry the
  payload-signing marker (`cert.HasPayloadSigningMarker`) — an admin mTLS bundle no
  longer qualifies.
- **WebAuthn assertion (Issue #3697).** A browser-only operator with no mTLS bundle
  signs via the controller's `/api/v1/operator-payload/sign/begin`/`finish` ceremony
  (Issue #3695): the assertion's `clientDataJSON.challenge` must equal
  `operatorpayload.ChallengeHash(envelope)` — SHA-256 over a **domain-separated**
  preimage, never over bare `CanonicalBytes`, so an assertion collected during any other
  ceremony at the same relying party (a routine passkey login, say) cannot be replayed as
  an operator authorization — and the assertion signature must verify, as
  `authenticatorData || SHA-256(clientDataJSON)`, against the credential's public key.

  The steward applies the mandatory W3C WebAuthn §7.2 assertion checks in full rather
  than treating `authenticatorData` as opaque signature input: `clientDataJSON.type` must
  be `webauthn.get`, its `origin` must be one the relying-party binding names,
  `authenticatorData`'s `rpIdHash` must equal `SHA-256(rpID)`, and both the **User
  Present** and **User Verified** flags must be set. Requiring UV matches the
  controller's own `protocol.VerificationRequired` ceremony — the steward exists to check
  the controller independently, so it applies no weaker verification than the party it
  checks.

  The credential's public key has no certificate chain of its own, so it is resolved from
  the CA-signed revocation manifest (`GET /api/v1/certificates/revocation-manifest`,
  `features/controller/api/handlers_revocation_manifest.go`), extended with a
  Kind-discriminated `authorized_webauthn_credentials` roster alongside the existing
  revoked-serials list — never from an unsigned, live controller claim. The manifest's
  own signature is chain-verified against the steward's controller CA via its embedded
  `signer_certificate_pem` before any entry in it is trusted, and it also carries the
  relying-party binding (`webauthn_relying_party`) the origin and `rpIdHash` checks are
  made against, since a steward has no other trustworthy source for it.

  Roster membership is not authorization. Each entry states the authority its owning
  account actually holds, and the steward re-checks both predicates:

  - **Grant.** The entry must carry `operator-payload:sign` — the same permission the
    controller gates the signing ceremony on. The controller builds the roster from
    accounts holding that permission (root-scope administrators hold every permission),
    and excludes disabled accounts, whose credentials survive the disable by design
    (Issue #3126).
  - **Tenant.** The entry names its owning account's tenant path, or is marked root
    scope. A steward accepts a root-scope entry fleet-wide, and a tenant-scoped entry
    only when its own tenant path is that tenant or a descendant of it. Without this the
    roster's fleet-wide reach would let a credential registered in one tenant authorize
    execution in another.

  The manifest is also freshness-bound, because it travels inside the command and is
  otherwise a bearer artifact: it carries an `issued_at` instant, the steward refuses one
  older than 15 minutes or dated in its own future, and it keeps a high-water mark of the
  newest instant accepted so a captured older manifest — the copy that still lists a
  since-removed credential — cannot roll it back. Without that, de-registering a
  compromised passkey or disabling its account would never take effect on a steward,
  since `version` counts revoked certificate serials and does not move when the roster
  changes. The high-water mark is process-scoped; after a restart the age bound alone
  applies until the first manifest is accepted.

  Unlike the X.509 path, WebAuthn verification has no "no CA roots configured"
  relaxation: the public key has no other source, so it fails closed rather than silently
  skipping verification.

Residual-risk profile (Issue #3695's own note, restated here for the verifying side): a
WebAuthn private key is hardware-bound and never exists server-side at all, so the
"controller durably retains an extractable private key indefinitely" problem the
credential cutover (#3696) closes for the mTLS path is structurally impossible on the
WebAuthn path. What remains is the shallower risk that a compromised controller mints a
bogus WebAuthn registration — bounded by `webauthn:register`'s existing `AssuranceStrong`
gate — not the deeper risk of silently stealing a years-old credential.

### Remote Terminal

The controller can establish an interactive terminal session through the steward for live troubleshooting. The steward provides a secure, authenticated shell session back to the administrator.

### Live Telemetry Stream

The controller can subscribe to a live feed of the steward's process and service
telemetry via the `TelemetryStream` bidi RPC. While subscribed, the steward
periodically calls `Snapshot()` (from `features/steward/telemetry`) and streams
the result. No collection happens between subscriptions — see
[Live Telemetry Snapshots](#live-telemetry-snapshots-2763--2764--epic-2738)
above for the full specification.

### Orchestrated Operations

The steward participates in multi-node operations coordinated by the controller (rolling updates, coordinated reboots, cluster-aware operations). The steward applies its own cfg — the controller determines sequencing and timing across devices. See the [controller operating model](controller-operating-model.md) for orchestration details.

#### Cluster-Role Quorum (`dna.cluster_role`)

When multiple stewards form a redundancy cluster (Hyper-V cluster, SQL Availability Group, domain controller site, etc.), rolling updates must never take down all cluster members simultaneously. The controller enforces this via the `dna.cluster_role` DNA attribute and the `DnaRoleQuorumChecker`.

**Setting the attribute:**

Add `cluster_role` to the steward's DNA configuration:

```yaml
dna:
  cluster_role: hyperv-cluster
```

The value is a free-form string — pick a name that identifies the redundancy domain. All stewards that share a value form one group; stewards with no `cluster_role` are treated as independent.

**Example role values:**

| Value | Typical members |
|-------|----------------|
| `hyperv-cluster` | Hyper-V failover cluster nodes |
| `sql-ag-primary` | SQL Server Availability Group members |
| `dc-site-a` | Domain controllers in site A |

**Quorum guarantee:**

When a rolling batch job runs, the `DnaRoleQuorumChecker` partitions the fleet such that **no two stewards with the same non-empty `cluster_role` appear in the same batch wave**. A cluster with four Hyper-V nodes gets one node per wave regardless of the requested batch size — ensuring at least three nodes remain operational during any wave.

Stewards without a `cluster_role` are placed freely into available slots alongside role-bearing stewards, filling up to the requested batch size.

### Live Telemetry Snapshots (#2763 / #2764 / epic #2738)

For the Web UI live-operations ("task manager") view, the steward exposes an
on-demand, point-in-time snapshot of its **running processes** (per-process CPU%,
memory, disk I/O; network counters are reserved — see below) and **installed
services** (name, run state). This is `features/steward/telemetry` — distinct from
`features/steward/dex` (the DEX experience-signal ETW/PSI spike) and from the
convergence loop.

Key properties:

- **On-demand, subscription-scoped.** The collector is a callable snapshot
  function that does **no work unless invoked** — no background goroutine, no
  event stream. It runs only while a controller subscriber is attached; between
  calls it costs nothing.
- **Usermode, in-process, no shell-out.** Linux reads `/proc` (process table) and
  the systemd D-Bus `Manager.ListUnits` (services); Windows uses the
  `NtQuerySystemInformation` process table and the Service Control Manager
  (`svc/mgr`). No kernel driver, no eBPF, no ETW, and no `ps`/`tasklist`/
  `systemctl`/`wmic` — matching the steward execution-path posture.
- **Sub-1% sustained CPU budget.** Measured at a 1 Hz poll cadence: ~0.6% (Windows)
  / ~0.8% (Linux) of a single core. `NtQuerySystemInformation` is used on Windows
  in preference to the WMI perf-object query specifically because the latter
  measured ~20× over budget.
- **Read-only.** State observation only — no service start/stop/restart (that
  overlaps the `service` stdlib module's desired-state enforcement, a separate
  boundary).
- **Join-able entities.** Each process/service carries an ADR-017 object-canonical
  `fragment_id` (`process:<name>`, `service:<name>`) so a controller can join the
  telemetry to DNA + the topology graph. Nothing here writes DNA.

Per-process **network** byte accounting is structurally present in the wire format
but not populated by this usermode collector — it requires kernel-assisted tracing
(eBPF / the Windows Kernel-Network ETW provider), reserved for a future story.

#### TelemetryStream RPC (#2764)

The steward exposes live telemetry over the data-plane `TelemetryStream` bidi RPC
(`rpc TelemetryStream(stream TelemetrySnapshot) returns (stream TelemetryRequest)`).
The steward dials out and is the *sending* side — it emits `TelemetrySnapshot`
frames and receives `TelemetryRequest` control messages from the controller.

Subscription lifecycle (steward-side):

1. The steward opens the stream and enters an idle receive loop.
2. On an inbound `TelemetryRequest{subscribe: true, interval_ms: N}`, the steward
   starts a ticker at `max(N, 1000)` ms and calls `Snapshot()` on each tick,
   streaming the result to the controller.
3. On an inbound `TelemetryRequest{subscribe: false}` or stream teardown, the
   ticker is stopped. No further `Snapshot()` calls occur until the next
   subscribe=true.

The 1 s floor on `interval_ms` is enforced steward-side as defense in depth —
the actual untrusted-input boundary is the controller-facing web API (story #2765).
The stream reconnects with exponential back-off on failure (same pattern as
`EventEmitter`/`LogStream`).

## Registration

How a steward joins a controller.

### Controller Anchor (Build Time)

The steward binary is built with the controller's URL compiled in at link time (`-ldflags="-X main.ControllerURL=..."`). A given steward binary will only ever talk to its compile-time controller. Scope: per controller (or controller cluster), not per tenant — one steward binary serves all tenants the controller manages.

A steward binary today connects to exactly one controller URL. Multi-controller deployments — where a steward might fail over between geographically distributed controllers (e.g., `east.cfg.ms`, `west.cfg.ms`) — are not yet supported. [GAP: multi-controller / subdomain-matching binary support — still open, re-confirmed live 2026-08-20 by story #3096; see `docs/testing/controller-ha-real-cluster-runbook.md` §6]

> The citation on this gap previously pointed at issue #1517, which is closed and
> was **controller-trust anchoring** (ADR-013: install-time vs compile-time trust
> options), not multi-controller failover. That was a mis-citation, corrected here.

**What story #3096 established about the scope of this gap.** Measured against the
real 3-node cluster, a single controller URL is **not** a barrier to
surviving a *leader* failover. A steward attached to a surviving node keeps its
gRPC-over-QUIC ControlChannel open across a Raft re-election and misses no
heartbeats — the leader changing is invisible to it, because every node serves
steward traffic directly against the shared backend and no request is forwarded
to the leader. Measured: leader SIGKILLed, re-election 12.02s, steward's next
heartbeat landed 6s after the kill, zero reconnects
(`test/e2e/ha/steward_continuity_real_test.go`).

The gap therefore bites in exactly one case: when the steward's **own** node is
the one that fails. There is no second URL to fall back to, so that steward is
offline until its node returns. The existing options are an LB/VIP in front of
the cluster or per-steward node assignment; neither is built. Both are recorded,
with the evidence, in runbook §6.

### Registration Credentials

Two credential flavors, both flow through the same registration API:

1. **Perennial registration tokens** — generated on the controller via `cfg token create --expires=<duration>`. Suitable for manual onboarding, small fleets, or time-bounded provisioning windows. Tokens survive multiple registrations (never consumed on use); rotate with `cfg token rotate --tenant-id <id>` to atomically invalidate all prior tokens and issue a new one. Expiry enforces time bounds.
2. **Long-lived tenant/group registration codes** — durable random opaque strings stored as a join field on the controller's tenant/group record. Suitable for RMM/GPO mass deployment where the same code is baked into a deployment script and reused by many devices. On registration the controller looks up the code in its records and assigns the steward to the matching tenant/group; the code itself carries no meaning, so renames of the tenant/group don't break previously issued codes.

The administrator chooses which flavor fits the deployment workflow. Both arrive at the steward as a plain string passed via `--regtoken <token>` (or `cfgms-steward install --regtoken <token>` for the OS-service install).

### Registration Flow

1. Administrator creates a registration token or code on the controller.
2. Steward is started with `--regtoken <token>`.
3. Steward contacts its compile-time controller URL (HTTPS), submits the token.
4. The steward generates its mTLS keypair locally and submits the registration request with a `csr_pem` — a PEM-encoded certificate signing request over that keypair's public half; the private key never crosses the wire (Issue #3780). Controller validates the token (perennial token: check expiry and revocation; long-lived code: look up the matching tenant/group record), validates the CSR (rejects a request with no `csr_pem` or one carrying embedded private-key material), and applies the registration approval workflow:
   - **Approved** (HTTP 200): controller signs the submitted CSR into an mTLS certificate scoped to the steward's tenant/group identity and returns the full `RegistrationResponse` with `client_cert` and `ca_cert`. When the controller's cert manager is backed by an imported regional intermediate rather than a root CA, the response also carries `issuer_chain` — the PEM-concatenated chain from `client_cert`'s direct issuer up to (but not including) `ca_cert` (Issue #3778). Self-hosted, root-only controllers omit the field; `ca_cert` is always the ultimate trust root, never an intermediate.
   - **Quarantined** (HTTP 202): controller returns a `RegistrationPendingResponse` with a `pending_id` and `status: "pending"`. No certificates are issued. The steward enters a **Phase 2 poll loop** (see below).
   - **Rejected** (HTTP 403): registration is denied; steward exits.
5. **Phase 2 — Poll loop (quarantine path):** The steward polls `GET /api/v1/registration/status/{pending_id}` using `Authorization: Bearer <regToken>`. Poll interval = `baseInterval + rand(jitter)` (default 90 s base, 30 s jitter). Possible outcomes:
   - `{"status":"pending"}` (HTTP 200): operator has not yet acted — continue polling.
   - `{"status":"claimed", "client_cert":..., "issuer_chain":..., ...}` (HTTP 200): operator approved; the controller signs the same CSR submitted in step 4 and returns the resulting cert bundle exactly once, with the same `issuer_chain` behavior described above. The steward combines the returned `client_cert` with the private key it generated in step 4 to complete its credential set, and proceeds to step 6.
   - HTTP 410 Gone: steward already collected the cert (duplicate poll) — stop polling.
   - `{"status":"denied"}` or `{"status":"expired"}` (HTTP 200): registration was rejected — steward exits or re-registers.
   The cert is signed on first approved poll (sign-on-claim); the controller never generates or sees a private key for this credential.
   Registration-refresh responses (`RefreshCompleteResponse`) carry the same `client_cert`/`ca_cert`/`issuer_chain` shape for the same reason.
6. On approval: steward imports the issued cert into its local `cert.Manager` (stored under the platform cert dir) for use in TLS handshakes, records the node ID, and establishes a gRPC-over-QUIC transport connection.
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

**Chain-aware verification (Issue #3778).** The steward's trust pool for a freshly issued certificate set is built from leaf + `issuer_chain` + `ca_cert`, not leaf + `ca_cert` alone: `ca_cert` is verified as the root, and any delivered `issuer_chain` is supplied as intermediates so the leaf can bridge to it. This matters for SaaS cells backed by an imported regional intermediate (ADR-032), where the leaf's direct issuer is the intermediate rather than the pinned root. Self-hosted deployments carry no `issuer_chain` and this reduces to today's leaf + root verification unchanged.

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
| Module Monitor engine (fan-in, debounce, targeted reconcile) | Yes | Yes — started by `syncConfigNow` after each cfg fetch; stopped by `Disconnect` |
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
