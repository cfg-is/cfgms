# Controller Operating Model

How the controller behaves at runtime. This document governs controller implementation decisions — every controller feature and issue should be consistent with the model described here.

For the system-level operating model, see [operating-model.md](operating-model.md).
For the steward operating model, see [steward-operating-model.md](steward-operating-model.md).

## One Sentence

The controller is the central management server that stores and distributes cfgs, collects reports from stewards, orchestrates multi-node operations, runs cloud/SaaS workflows, and provides a REST API for administration.

## Lifecycle

### First Run (Initialization)

The controller distinguishes between first run and normal startup. First run requires explicit action — the controller never silently auto-generates infrastructure.

**Why**: If the controller auto-generated a CA and certs on every startup where it couldn't find existing ones, a misconfigured storage mount or wrong config path would silently create a new CA — breaking trust with every registered steward. This is a catastrophic failure disguised as a successful startup.

#### The `--init` command

Initialization is performed by running `controller --init --config /path/to/controller.cfg`. This is a one-shot command: it performs all initialization steps, prints the result (CA fingerprint, storage provider, timestamp), and exits. It does not start the server.

#### Init sequence

The `initialization.Run()` function performs the following steps in order:

1. **Pre-flight validation** — verifies that config is present, certificate management is enabled (`certificate.enable_cert_management: true`), and `certificate.ca_path` is set
2. **Idempotent guard** — reads the CA directory for an existing `.cfgms-initialized` marker. If the marker exists, init refuses to run and reports when and with what CA the controller was previously initialized. To re-initialize, the operator must remove the CA directory and run `--init` again
3. **Storage backend creation** — initializes the configured storage provider (git or database) via `interfaces.CreateAllStoresFromConfig()`
4. **CA directory and CA generation** — creates the CA directory (`os.MkdirAll` with `0700`), then creates a new Certificate Authority via `pkg/cert.Manager` with `LoadExistingCA: false`
5. **Internal mTLS certificate** — if separated certificate architecture is configured, generates the `cfgms-internal` certificate used for gRPC-over-QUIC inter-component communication
6. **Config signing certificate** — if separated architecture, generates the `cfgms-config-signer` certificate used to sign cfgs distributed to stewards (4096-bit RSA key)
7. **RBAC store initialization** — initializes default permissions, roles, and subjects via `rbac.NewManagerWithStorage()`
8. **Init marker written last** — the `.cfgms-initialized` marker is the final step. If any earlier step fails, no marker is written, and the installation is not considered initialized

Server certificates (for the transport listener) are **not** created during `--init`. Those are generated during normal startup by the transport subsystem, which knows the specific certificate names and file paths it requires.

#### The `.cfgms-initialized` marker

The marker is a JSON file named `.cfgms-initialized` placed in the CA directory. It records:

- `version` — marker format version (for future migration)
- `initialized_at` — UTC timestamp of initialization
- `controller_version` — version of the controller binary that ran `--init`
- `storage_provider` — storage backend used (e.g., `git`, `database`)
- `ca_fingerprint` — SHA-256 fingerprint of the generated CA certificate

The marker is written atomically using a temp file + rename pattern (`WriteInitMarker` writes to `.cfgms-initialized.tmp`, then renames). Placing the marker in the CA directory is intentional: if the CA mount is missing, both CA files and marker are absent, producing the correct failure mode on startup.

#### Rollback on failure

A `RollbackTracker` registers cleanup functions as initialization progresses. If any step fails, all registered cleanup functions execute in LIFO order (e.g., removing the CA directory that was just created). The tracker collects all rollback errors rather than stopping at the first failure.

#### Server startup init guard

On normal startup (without `--init`), the server checks for the marker before loading the certificate manager:

- **Marker present** — proceed with normal startup
- **No marker but CA files exist** — legacy installation from before the init guard was introduced. The server auto-creates a marker with `storage_provider: unknown-legacy` and the existing CA's fingerprint, then proceeds normally
- **No marker and no CA files** — refuse to start with `ErrNotInitialized`, directing the operator to run `controller --init --config <path>`

### Normal Startup

After initialization, the controller starts normally. If required infrastructure is missing (no CA, no storage, no config), **the controller refuses to start and reports what is wrong** — it does not attempt to regenerate or self-heal.

1. **Load configuration** — Parse controller config file. Fail with clear error if not found
2. **Initialize storage** — Connect to durable storage backend. Fail if unreachable — the controller cannot operate without persistent storage
3. **Verify security** — Load existing CA, server certs, and signing cert. Fail if missing or invalid — never regenerate silently
4. **Initialize RBAC** — Load permissions, roles, subjects from storage
5. **Start transport server** — Unified gRPC-over-QUIC server for all controller-steward communication (port 4433, mTLS). Serves both control plane (heartbeats, commands, status) and data plane (cfg delivery, DNA sync, bulk transfers) over multiplexed QUIC streams
7. **Start services** — Heartbeat monitoring, command publisher, registration handler, tenant manager
8. **Start HA** (if clustered) — Join Raft cluster, participate in leader election
9. **Start REST API** — HTTP server for administration (port 9080). Owned exclusively by `server.Server` (`httpServer` field); `controller.go` does not create a second instance
10. **Start workflow engine** — Begin processing scheduled and queued workflows

**Failure modes on startup:**
- Missing config file → error with expected paths
- Storage unreachable → error with connection details
- CA/certs missing → error explaining that `--init` is required
- CA/certs expired → error with expiry details and renewal instructions
- Storage schema mismatch → error with migration instructions
- Transport address conflict → error with port details and resolution steps

### Node Management

The controller is a self-sufficient application — it creates its own directories, certificates, and storage during `--init` and runs without external dependencies beyond the OS. For quick-start and development, no steward is needed.

For production fleets, a steward runs alongside the controller on each node. The steward manages node-level infrastructure via its convergence loop, while the controller focuses on fleet operations.

| Responsibility | Owner | Examples |
|----------------|-------|----------|
| OS packages | Steward | `git`, `sops`, system updates |
| System directories | Steward | `/etc/cfgms/`, `/var/lib/cfgms/`, `/var/log/cfgms/` |
| Firewall rules | Steward | Ports 8080/TCP, 4433/UDP |
| OS service management | Steward | systemd unit, service restart on failure |
| Controller config file | Steward | `/etc/cfgms/controller.cfg` |
| CA and certificates | Controller | Generated during `--init`, managed in-memory |
| RBAC and tenant data | Controller | Stored in durable storage backend |
| Fleet registry | Controller | Steward registrations and heartbeats persisted in `StewardStore` — survives controller restarts (Issue #663) |
| Storage backend | Controller | Git repo or PostgreSQL operations |
| Fleet orchestration | Controller | Config distribution, steward registration, workflows |

See [Single Controller Deployment](../../deployment/single-controller/walkthrough.md) for the deployment guide and [ADR-002](decisions/002-steward-bootstrap-for-controllers.md) for the architectural decision.

### Normal Operation

The controller runs several concurrent activities:

```
┌───────────────────────────────────────────────────────┐
│                  Controller                            │
│                                                        │
│  ┌────────────────────┐  ┌─────────────────────────┐  │
│  │ Fleet Management   │  │ Workflow Engine          │  │
│  │ (steward comms)    │  │ (cloud/SaaS automation) │  │
│  └────────────────────┘  └─────────────────────────┘  │
│                                                        │
│  ┌────────────────────┐  ┌─────────────────────────┐  │
│  │ REST API           │  │ Orchestration           │  │
│  │ (admin interface)  │  │ (multi-node operations) │  │
│  └────────────────────┘  └─────────────────────────┘  │
│                                                        │
│  ┌────────────────────┐  ┌─────────────────────────┐  │
│  │ Identity & Auth    │  │ Monitoring & Reporting  │  │
│  │ (certs, RBAC)      │  │ (fleet visibility)      │  │
│  └────────────────────┘  └─────────────────────────┘  │
│                                                        │
└───────────────────────────────────────────────────────┘
```

### Shutdown

1. Stop accepting new API requests
2. Complete in-progress orchestrated operations (or safely pause them)
3. Notify stewards of impending disconnect (stewards continue operating independently)
4. Flush pending writes to storage
5. Leave HA cluster cleanly (if clustered)
6. Close transport server (gRPC-over-QUIC)
7. Exit

## Cfg Management

The controller is the authoring and distribution point for steward cfgs. It does not apply cfgs itself — stewards do that.

### Cfg Lifecycle

```
Author → Validate → Store → Distribute → Monitor Compliance
```

1. **Author** — Cfgs are created or updated via REST API, workflow output, or direct storage edit
2. **Validate** — Controller validates cfg syntax, module references, and tenant scoping before accepting
3. **Store** — Cfg is persisted in durable, version-controlled storage. Every change is a new version with full audit trail
4. **Distribute** — Controller pushes the cfg to the target steward(s) over the QUIC data plane. Cfgs are signed with the controller's signing certificate so stewards can verify authenticity
5. **Monitor** — Controller receives convergence results from stewards and tracks per-device compliance status

### Cfg Targeting

The controller decides which steward gets which cfg based on:

- **Direct assignment** — a cfg explicitly targets a steward by ID
- **Group membership** — a cfg targets a group; all stewards in that group receive it
- **Tenant hierarchy** — cfgs inherit through the recursive tenant hierarchy (e.g., MSP → Client → Group → Device). Child tenants can override parent settings at any depth
- **Effective cfg** — the controller resolves inheritance and produces the effective cfg for each steward, merging all applicable layers

### Config Signing

Every cfg distributed to a steward is signed using the controller's dedicated signing certificate (or server cert in unified mode). The steward verifies this signature before applying, ensuring cfgs cannot be tampered with in transit or injected by a rogue source.

## Fleet Management

The controller maintains awareness of all registered stewards and their state.

### Fleet Registry Durability (Issue #663)

The fleet registry is backed by a `StewardStore` (see `pkg/storage/interfaces/steward_store.go`). Registrations, heartbeats, and status transitions are persisted to durable storage so the fleet view survives controller restarts without waiting for all stewards to re-register.

**Steward lifecycle states**: `registered` → `active` → `lost` / `deregistered`. Records are retained indefinitely for audit; a `lost` steward can re-register and will have its record updated in place.

**Implementation**: `features/steward/StewardHealthTracker` wraps a `StewardStore` for durable fields and keeps ephemeral per-process metrics (`HealthMetrics`: task latency counters, config error counts, recovery attempts) in-memory only. The in-memory metrics are not persisted and reset on restart — this is by design.

**After a restart**: On startup, the controller can call `ListStewards()` or `ListStewardsByStatus()` to enumerate the fleet without waiting for stewards to check in. The stored `last_seen` and `last_heartbeat_at` timestamps allow the controller to identify stewards that went silent before or during the restart.

### Steward Tracking

For each steward, the controller tracks:

| Data | Source | Update Frequency |
|------|--------|-----------------|
| Identity (ID, tenant, group) | Registration | Once |
| Connection status | Heartbeats | Configurable interval |
| Last heartbeat | gRPC heartbeat calls | Configurable interval |
| Health status | Heartbeat payload | With each heartbeat |
| Compliance status | Convergence result reports | After each convergence run |
| DNA hash | Heartbeat payload | With each heartbeat |
| DNA snapshot | Full sync (data plane) or deltas (control plane) | On hash mismatch, initial registration, or as changes occur |
| Performance metrics | Steward metric uploads | Periodic + on-demand |

### Heartbeat Monitoring

The controller monitors steward heartbeats to detect connectivity loss:

- Stewards send heartbeats at a configurable interval
- If a heartbeat is missed beyond a timeout threshold, the steward is marked disconnected
- Disconnected stewards continue operating independently — the controller simply loses visibility until the steward reconnects
- On reconnect, the steward resyncs queued reports and the controller rebuilds its view

### Commands

The controller can send commands to stewards over the gRPC control plane service:

| Command | Purpose |
|---------|---------|
| `sync_config` | Tell steward to fetch its latest cfg now (optimization — steward also checks on schedule) |
| `sync_dna` | Request fresh DNA collection and upload |
| `execute_script` | Run an ad-hoc script (outside the cfg) |

Commands are fire-and-forget with completion tracking — the controller publishes the command and monitors for completion/failure events.

## Orchestration

The controller coordinates operations that span multiple stewards. Individual stewards apply their own cfgs; the controller determines sequencing and timing.

### Orchestration Model

```
Admin triggers operation
        │
        ▼
Controller plans execution order
(considering dependencies, roles, cluster membership)
        │
        ▼
Batch 1: [steward-A, steward-B]  → wait for completion
Batch 2: [steward-C]             → wait for completion
Batch 3: [steward-D, steward-E]  → wait for completion
        │
        ▼
Operation complete (or rolled back on failure)
```

### Dependency Awareness

The controller understands infrastructure relationships:

- **Cluster membership** — which stewards belong to Hyper-V clusters, SQL clusters, etc.
- **Infrastructure roles** — domain controllers, DNS servers, DHCP servers
- **Quorum requirements** — how many nodes must remain online during updates
- **Service dependencies** — which services depend on which infrastructure roles

This knowledge informs operation sequencing:
- Never update all domain controllers simultaneously
- Respect Hyper-V cluster quorum during rolling updates
- Drain a node before rebooting, ensure it rejoins before proceeding
- Pause the rollout if a batch fails

### Coordinated Operations

| Operation | Orchestration Behavior |
|-----------|----------------------|
| **Rolling cfg update** | Push cfg to stewards in batches, verify convergence success before next batch |
| **Coordinated reboot** | Drain workloads, reboot in sequence respecting quorum, verify node health before proceeding |
| **Cluster-aware patching** | Patch one node at a time, live-migrate VMs, verify cluster health between nodes |
| **Emergency rollback** | If a batch fails, halt rollout and optionally push previous cfg version to affected stewards |

## Workflow Engine

The workflow engine serves three roles:

1. **Desired-state engine for cloud resources** — brings the same Get/Set convergence model to SaaS platforms that stewards bring to local devices
2. **Orchestration and data sync between services** — keeps third-party platforms in sync with CFGMS-managed endpoints and each other
3. **Integration platform** — connects services together via workflows, with extensible node types

Integrations are organized by type. Initial integrations focus on MSP operational needs, with additional categories added based on demand:

| Integration Type | Purpose | Examples |
|-----------------|---------|----------|
| **PSA / Ticketing** | Asset sync, ticket routing, client management | Service desk platforms |
| **Distribution / Licensing** | License provisioning, reconciliation, billing | Distributor marketplaces |
| **Cloud Identity** | User/group management, policy enforcement | M365, Azure AD, Google Workspace |
| **Endpoint Management** | Device configuration, compliance | CFGMS stewards (Windows, Linux, macOS) |
| **Documentation** (future) | Automated documentation updates | Knowledge base and IT documentation platforms |
| **Automation Bridge** (future) | Extend workflows via external automation | Third-party workflow/automation platforms |
| **AI Processing** (future) | Classification, anomaly detection, NLP | LLM and ML services |

### Design Principle: Same Mental Model

Configuring an M365 conditional access policy should feel like configuring a firewall rule on a steward. The admin writes a resource block in a cfg, declares desired state, and the system converges. The difference is where it executes — not how the admin thinks about it.

```yaml
# These should feel the same to an admin:

# Runs on steward (local device)
resources:
  - name: web-firewall
    module: firewall
    config:
      rules:
        - name: allow-https
          port: 443
          action: allow

# Runs on controller (cloud API)
resources:
  - name: mfa-policy
    module: conditional_access
    config:
      name: "Require MFA for all users"
      state: enabled
      conditions:
        users: all
      grant_controls:
        require_mfa: true
```

### How It Works

The workflow engine hosts **cloud modules** that implement the same Get/Set contract as steward modules, but execute against external APIs instead of local system state:

1. **Get** — Query the cloud API for current resource state (e.g., read current conditional access policies from Entra ID)
2. **Compare** — Engine compares current state against desired state from the cfg
3. **Set** — If drifted, call the cloud API to converge (e.g., create/update the policy)

This means cloud resources get the same convergence loop as local resources — scheduled re-checks detect drift (someone changed a policy in the portal), and the controller corrects it.

### Event Hooks for Cloud Resources

Cloud modules can register monitors using platform-native mechanisms:

- **Log ingestion** — consume audit logs from M365, Azure, AWS to detect changes in near-real-time
- **Webhook receivers** — receive change notifications from cloud platforms
- **Polling** — scheduled API checks for platforms without push notifications

When a change is detected, it triggers a convergence check for that resource — the same pattern as a steward's file monitor detecting a local change.

### Imperative Workflows

Not everything is desired state. The workflow engine also supports imperative operations:

- **User provisioning** — onboard a new employee across M365, create mailbox, assign licenses
- **Scheduled tasks** — recurring license reconciliation, report generation
- **Event-driven automation** — respond to alerts, webhooks, or steward events

These are authored as step sequences, not convergent cfgs. They execute once (or on schedule) and report results.

### Service Orchestration and Data Sync

MSPs operate across multiple platforms that need to stay in sync. The workflow engine acts as the glue:

```
PSA / Ticketing  ◄──►  CFGMS Controller  ◄──►  Distributor / Licensing
                              │
                       ┌──────┴──────┐
                       │             │
                 Cloud Tenants   Stewards
                 (cloud cfg)    (device cfg)
```

**Examples of sync workflows:**

- **New client onboarding** — create tenant in CFGMS, provision cloud tenant, create client in PSA, set up licensing — all from one trigger
- **Device sync** — steward DNA (hardware, software) syncs to PSA asset records automatically
- **License reconciliation** — compare distributor license counts against actual cloud usage, flag discrepancies
- **Alert routing** — steward threshold breach events create tickets in PSA

Each integration is a workflow node type. Nodes can be composed into multi-step workflows that span services. Data flows between nodes, transformed as needed.

### Extensibility

The workflow engine uses a node-based architecture where each integration is a pluggable node type:

- **Service nodes** — PSA, distributor, cloud identity, endpoint management
- **Logic nodes** — conditionals, loops, filters, transforms
- **AI nodes** (future) — LLM-powered data classification, anomaly detection, natural language processing
- **Automation bridge nodes** (future) — integration with external workflow/automation platforms
- **Documentation nodes** (future) — automated updates to IT documentation platforms

### Workflow Engine Capabilities

The workflow engine must support the following capabilities to fulfill its role as a serious automation platform:

- **Authoring** — visual node-based workflow builder with draft/publish lifecycle
- **Triggers** — webhook, schedule, event-driven, manual, and chained (workflow triggers workflow)
- **Execution** — per-node retry policies, error paths, partial rollback, real-time execution trace
- **Data flow** — field mapping between service schemas, filtering, and transformation between nodes
- **Credentials** — tenant-scoped secret injection, never exposed in workflow definitions or logs
- **Debugging** — failed workflow runs retain full execution detail (inputs, outputs, and API request/response at every node) so failures can be diagnosed from history without re-execution. Successful runs retain summary-level traces. Debug depth and retention are configurable per workflow. Step-through execution with breakpoints available during development. Resume or re-run from any failed node without restarting the entire workflow
- **Testing** — sandbox execution, replay failed runs, input/output inspection per node
- **Versioning** — workflow version history, rollback to previous versions

### Workflow vs Cfg Summary

| | Steward Cfg | Cloud Cfg (Workflow Engine) | Imperative Workflow |
|---|---|---|---|
| **Runs on** | Steward | Controller | Controller |
| **Manages** | Local device resources | Cloud/SaaS resources | Any external operation |
| **Model** | Desired state (Get/Set) | Desired state (Get/Set) | Imperative steps |
| **Convergence** | Yes (scheduled + hooks) | Yes (scheduled + log/webhook hooks) | No (run once or on schedule) |
| **Example** | Firewall rule | Conditional access policy | Onboard new employee |

## Identity and Authorization

### Steward Registration

The controller is the certificate authority and identity provider for stewards:

1. Admin creates a **registration token** via REST API (scoped to tenant/group, with expiry)
2. Steward presents token during registration
3. Controller validates token, generates steward ID, issues mTLS client certificate
4. Controller distributes CA cert, signing cert, and connection details
5. Steward is now a trusted member of the fleet

### RBAC

All API operations are governed by role-based access control:

- **Permissions** — fine-grained actions (e.g., `steward:list`, `steward:write-config`)
- **Roles** — groups of permissions (e.g., `admin`, `operator`, `viewer`)
- **Subjects** — users or API keys assigned to roles
- **Tenant scoping** — permissions are scoped to tenant path; an MSP admin sees all descendants, a client admin sees only their subtree
- **Zero-trust evaluation** — every request is evaluated against the policy engine

### API Authentication

- **API keys** — stored encrypted, used for programmatic access
- **Registration tokens** — scoped, expirable tokens for steward bootstrap only

## Multi-Tenancy

The controller enforces strict tenant isolation across all operations.

### Tenant Model

CFGMS uses a **recursive parent-child tenant model**. Every tenant has a unique identifier and an optional parent identifier. There are no fixed hierarchy levels — "MSP → Client → Group → Device" is a common convention, but the system supports arbitrary depth.

Tenants are identified by **path** (e.g., `root/msp-a/client-1/servers`). Path-based identification enables:

- **Prefix matching** — target all tenants under `root/msp-a/` with a single operation
- **Wildcard targeting** — `root/msp-a/*/production` matches all production groups across clients
- **Efficient resolution** — cfg inheritance walks the path from root to leaf

#### Example: Single MSP (Apache / OSS)

```
acme-msp (root)
 ├── client-a
 │   ├── production
 │   │   ├── device-1 (steward)
 │   │   └── device-2 (steward)
 │   └── development
 │       └── device-3 (steward)
 ├── client-b
 │   ├── servers
 │   │   └── device-4 (steward)
 │   └── workstations
 │       └── device-5 (steward)
 └── internal
     └── device-6 (steward)
```

One root tenant, unlimited depth. This is the Apache-licensed deployment model.

#### Example: SaaS Platform (Elastic / Commercial)

```
cfg-is (platform root)
 ├── msp-alpha (root)
 │   ├── client-1
 │   │   └── ...
 │   └── client-2
 │       └── ...
 ├── msp-beta (root)
 │   ├── client-1
 │   │   └── ...
 │   └── client-2
 │       └── ...
 └── msp-gamma (root)
     └── ...
```

Multiple independent root tenants under a platform tenant. MSPs cannot see each other's trees. This is the Elastic-licensed deployment model — it enables cfg.is to host hundreds of MSPs on shared infrastructure with per-MSP isolation, resource scheduling, and billing.

### Cfg Inheritance

Configuration resolves recursively from root to leaf:

1. Start with the root tenant's cfg
2. At each level, merge the child tenant's cfg over the parent's
3. Named resources replace entire blocks (declarative merging)
4. The leaf cfg (effective cfg for a steward) is the fully-resolved result

Every value in the effective cfg carries its **source path** and **version** for auditability — an admin can see exactly which tenant level provided each setting.

### Isolation Guarantees

- **Data isolation** — tenants cannot access other tenants' cfgs, DNA, or reports
- **Transport isolation** — each steward connects with its own mTLS client certificate; gRPC service handlers enforce per-steward identity on every call
- **Certificate isolation** — each steward gets its own client certificate
- **RBAC isolation** — permissions are scoped to tenant path; a client admin cannot manage another client's devices
- **Cfg inheritance** — flows down the hierarchy only; children inherit from parents, never sideways
- **Multi-root isolation** (commercial) — independent root tenants are fully isolated; no inheritance, no visibility, no shared state between roots

## Monitoring and Reporting

### Fleet Visibility

The controller aggregates data from all stewards to provide:

- **Compliance dashboard** — which devices are in desired state, which have drift
- **Health overview** — which stewards are connected, degraded, or offline
- **Performance trends** — historical CPU, memory, disk, network across the fleet (from steward metric uploads)
- **Audit trail** — who changed what cfg, when, and what happened as a result

### Reports

The controller generates reports from aggregated steward data:

- **Compliance reports** — per-tenant, per-group, or fleet-wide compliance status
- **Drift reports** — what changed, when, on which devices
- **Executive summaries** — high-level fleet health for management
- **Export formats** — JSON, CSV, HTML, PDF

### Alerting

The controller evaluates fleet-level conditions and raises alerts:

- Steward disconnection (heartbeat timeout)
- Widespread compliance failure (threshold of stewards reporting drift)
- Cfg distribution failure (steward rejected or failed to apply)
- Security events (unauthorized registration attempts, certificate issues)

## High Availability

### OSS (Single Server)

The controller runs as a single instance. If it goes down, stewards continue operating independently on their last-known cfgs. When the controller comes back, stewards reconnect and resync.

### Commercial (Cluster)

Multiple controller instances form a Raft consensus cluster:

- **Leader election** — one node is elected leader and handles writes
- **State replication** — cfg changes, registration events, and fleet state are replicated across nodes
- **Automatic failover** — if the leader goes down, a new leader is elected
- **Split-brain detection** — cluster detects and resolves network partitions
- **Session sync** — steward sessions are synchronized across nodes for seamless failover

Stewards connect to any cluster node. If their node goes down, they reconnect to another.

## REST API

The REST API is the admin interface to the controller. All operations are authenticated, authorized via RBAC, and audit-logged.

### API Categories

| Category | Purpose |
|----------|---------|
| **Health** | Controller status, component health |
| **Steward management** | List, inspect, configure stewards |
| **Cfg management** | Upload, validate, distribute cfgs |
| **Registration tokens** | Create, list, revoke tokens for steward bootstrap |
| **Certificates** | List, provision, revoke certificates |
| **RBAC** | Manage permissions, roles, subjects |
| **API keys** | Create, list, delete API keys |
| **Tenants** | Manage recursive tenant hierarchy (create, move, delete tenants at any depth) |
| **Monitoring** | Fleet metrics, health, logs, traces |
| **Compliance** | Compliance status, reports |
| **HA** | Cluster status, leader info, node list |
| **Workflows** | Create, trigger, monitor workflows |
| **Orchestration** | Initiate and monitor multi-node operations |
