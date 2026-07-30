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
3. **Storage backend creation** — initializes the storage backend. Default configuration deployments use the composite flatfile + SQLite backend via `interfaces.CreateOSSStorageManager()`; production-scale deployments may configure a database backend via `interfaces.CreateAllStoresFromConfig()`
4. **CA directory and CA generation** — creates the CA directory (`os.MkdirAll` with `0700`), then creates a new Certificate Authority via `pkg/cert.Manager` with `LoadExistingCA: false`
5. **Internal mTLS certificate** — if separated certificate architecture is configured, generates the `cfgms-internal` certificate used for gRPC-over-QUIC inter-component communication
6. **Config signing certificate** — if separated architecture, generates the `cfgms-config-signer` certificate used to sign cfgs distributed to stewards (4096-bit RSA key)
7. **RBAC store initialization** — initializes default permissions, roles, and subjects via `rbac.NewManagerWithStorage()`
8. **Init marker written last** — the `.cfgms-initialized` marker is the final step. If any earlier step fails, no marker is written, and the installation is not considered initialized
9. **Admin credential bundle** — issues the admin mTLS client certificate and writes the bundle to the platform-default path (`/etc/cfgms/admin.bundle.yaml` on Linux/macOS, `%ProgramData%\cfgms\admin.bundle.yaml` on Windows). If a bundle already exists at that path, issuance is skipped (idempotent). The bundle is the operator's credential for all subsequent REST API access

Server certificates (for the transport listener) are **not** created during `--init`. Those are generated during normal startup by the transport subsystem, which knows the specific certificate names and file paths it requires.

#### The `.cfgms-initialized` marker

The marker is a JSON file named `.cfgms-initialized` placed in the CA directory. It records:

- `version` — marker format version (for future migration)
- `initialized_at` — UTC timestamp of initialization
- `controller_version` — version of the controller binary that ran `--init`
- `storage_provider` — storage backend used (e.g., `flatfile`, `database`)
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
5. **Start transport server** — Unified gRPC-over-QUIC server for the control and data planes (port 4433, mTLS). Serves control plane (heartbeats, commands, status) and data plane (cfg delivery, DNA sync) over multiplexed QUIC streams. **Exception — installer/steward-binary distribution:** steward binary payloads (both the controller push and the steward self-fetch, Issue #2833) transfer over the **HTTPS REST listener** (port 9080, step 9), not the QUIC transport — matching how installers and package managers are fetched everywhere and keeping large-file transfer off the control/data-plane streams. The QUIC transport carries control/data-plane messages, not binary payloads. Deployment consequence: a managed steward needs reachability to **both** port 4433 (QUIC) and port 9080 (HTTPS) on the controller — the "single port for everything" goal holds for the control+data plane, not for binary distribution
7. **Start services** — Heartbeat monitoring, command publisher, registration handler, tenant manager
8. **Start HA** (if clustered) — Join Raft cluster, participate in leader election
9. **Start REST API and Web UI** — A single TLS HTTP server (port 9080) serves both the REST API and the embedded web UI from the same listener. Owned exclusively by `server.Server` (`httpServer` field); `controller.go` does not create a second instance. The web UI is embedded in the controller binary via `//go:embed all:dist` in the `web/` package — no separate server, no second port, no Node toolchain at runtime. A committed placeholder (`web/dist/index.html`) keeps `go build` self-contained; a real Vite build (`npm run build` inside `web/`) replaces it when producing a release binary. The SPA is served as a lowest-priority catch-all route: REST API (`/api/*`) and Raft (`/raft/*`) routes always take precedence. In `ClusterMode` the TLS listener is configured with `ClientAuth = tls.RequestClientCert`: HA peers that present a client certificate will have it recorded in `r.TLS.PeerCertificates` for application-layer CN verification, while non-cluster API clients (operators, curl, stewards, browsers) that do not present a client certificate are accepted without modification
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
| Steward tags | Controller | Operator-assigned tags persisted in `tagstore.Store` (SQLite-backed, `features/controller/tagstore`) — survives controller restarts and DNA refreshes (Issue #2542) |
| Storage backend | Controller | Flatfile + SQLite (default) or PostgreSQL (production scale) operations |
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

1. **Author** — Cfgs are created or updated via the `cfg` CLI (`cfg config upload`), the administration web UI, a GitOps webhook, or workflow output. All sources write through the same ConfigStore — there is no separate "fast path".
2. **Validate** — Controller validates cfg syntax, module references, and tenant scoping before accepting. Validation is part of the write path; an invalid cfg never lands in storage.
3. **Store** — Cfg is persisted in durable, version-controlled ConfigStore. Every change is a new version with full audit trail.
4. **Distribute** — A successful `ConfigStore` write inside `SetConfiguration()` triggers automatic distribution via a service-level callback (Issue #1521, Option A). The callback is registered at server startup (`server.go`) and invokes `push.Fanout()` scoped to the tenant from the write context. Distribution is fire-and-forget: `SetConfiguration()` returns without blocking on fanout completion. Cfgs are signed with the controller's signing certificate so stewards can verify authenticity. Note: debounce (burst-save absorption) and per-steward targeting evaluation are tracked as follow-on stories.
5. **Monitor** — Controller receives convergence results from stewards and tracks per-device compliance status. Operators view propagation via `cfg config deployments <id>`.

**Save = Deploy:** `SetConfiguration()` automatically triggers fan-out to all active stewards of the affected tenant via the registered `FanoutCallback`. `POST /api/v1/config/push` is retained as an explicit-override / force-push endpoint. See [system operating model — Save = Deploy](operating-model.md#save--deploy) for the cross-component view.

### Cfg Targeting

The controller decides which steward gets which cfg based on:

- **Direct assignment** — a cfg explicitly targets a steward by ID ✓ implemented (`config_service_v2.go`: per-steward config stored and retrieved by steward ID)
- **Group membership** — a cfg targets a group; all stewards in that group receive it ✓ implemented (tenant/group path used in inheritance resolution)
- **Tenant hierarchy** — cfgs inherit through the recursive tenant hierarchy (e.g., MSP → Client → Group → Device). Child tenants can override parent settings at any depth ✓ implemented (`InheritanceResolver.ResolveConfiguration()`)
- **Cluster membership** — a steward that belongs to one or more clusters (Hyper-V, SQL, etc.) receives an additional `cluster-policies/<clusterName>` config layer inserted after Group-level and before Device-level in the merge order ✓ implemented (`InheritanceResolver` cluster-policies cascade, Issue #2425)
- **Effective cfg** — the controller resolves inheritance and produces the effective cfg for each steward, merging all applicable layers ✓ implemented (`GetEffectiveConfiguration()`)
- **Tag-based targeting** — stewards can carry arbitrary tags (e.g., `ring=canary`, `role=web-server`, `region=us-east`); a cfg targets stewards by tag expression via role configs ✓ implemented (`roleConfigAdapter` in config_service_v2.go injects matching role fragments into `InheritanceResolver`, Issue #2546)
- **DNA-attribute matching** — a cfg can target stewards whose DNA attributes match a predicate (e.g., `os=linux`, `cpu_arch=arm64`) via role config selectors ✓ implemented (same role-policies cascade, Issue #2546)

**Deployment rings:** see the Deployment Rings section below for the v1 mechanism. Operator-tagged phased rollouts using separate cfgs are still supported alongside rings.

### Cluster-Policies and Role-Policies Cascade

Stewards receive additional configuration layers beyond the tenant hierarchy: cluster membership adds a `cluster-policies/<clusterName>` layer, and matching role configs add a `role-policies/<roleName>` layer. Both are applied by `InheritanceResolver.ResolveConfiguration()` after the tenant hierarchy and before device-level config.

**Merge priority order (lowest → highest):**

| Level | ConfigKey namespace | Source |
|-------|--------------------|-----------------------|
| MSP | `msp-policies/global` | Tenant hierarchy root |
| Client | `client-policies/<tenantID>` | Tenant hierarchy |
| Group | `group-policies/<tenantID>-groups` | Tenant hierarchy |
| **Cluster** | **`cluster-policies/<clusterName>`** | **Cluster membership (DNA attributes)** |
| **Role** | **`role-policies/<roleName>`** | **Selector match (DNA + controller tags)** |
| Device | `stewards/<stewardID>` | Device-level override |

A device-level resource always wins. A role resource overrides cluster-policies for the same resource name. A cluster resource overrides group-level defaults.

**Sourcing cluster membership:** the cluster registry is derived from steward DNA attributes published by the steward's `DNARefreshLoop` ticker (default 30 min). A steward that carries `cluster:<clusterName>.*` DNA attributes is recorded as a member of that cluster. Membership is **eventually consistent**: a steward joining or leaving a cluster can take up to one refresh interval before `ResolveConfiguration` reflects the change.

**Authoring cluster-policies configs:** use the existing config-push path (`cfg config upload`) to store a `ConfigKey{Namespace: "cluster-policies", Name: "<clusterName>"}` document for the cluster's tenant. The resolver looks up this document automatically for every member steward. For migrating a single resource from device scope to cluster scope, the `move_resource_to_cluster` workflow step is the production path: it reads both docs, writes the resource into `cluster-policies/<clusterName>` via the raw `ConfigStore` (no service-layer equivalent exists for that namespace), and then removes it from `stewards/<stewardID>` via `ConfigurationServiceV2.SetConfiguration` (the validated + fan-out path). The cluster-first write order is the recoverability contract — a crash between the two writes leaves the resource in both docs, and re-running the step detects this and completes the device-side removal without re-writing the cluster doc. Manual `cfg config upload` authoring of whole cluster-policies documents remains the path for bulk cluster-scope changes.

**Accountable-authority reconciliation (Issue #2704):** the controller exposes `GET /api/v1/clusters/{name}/reconciliation` as the **single accountable authority** that reconciles the declared clustered resources (sourced from `cluster-policies/<clusterName>`) against the actual cluster registry (derived from steward DNA). For each declared resource the endpoint produces one of four classifications:

| Status | Meaning |
|--------|---------|
| `present-with-live-owner` | Resource exists in the registry and its owner steward has a heartbeat within the last 60 s. Healthy. |
| `declared-but-missing` | Resource declared in `cluster-policies` but no steward has published a `resource_owner.<role>` DNA attribute for it (create-coverage gap). Non-owner stewards' compliant-by-delegation abstain is **not safe** for this resource. |
| `orphan-dead-owner` | Registry entry exists but the owner steward's last heartbeat exceeds 60 s (`DeadOwnerStaleThreshold`, matching the 3-missed-heartbeat offline timeout from epic #1664). Resource is orphaned. |
| `split-brain` | Two or more cluster members report different `resource_owner.<role>` values for the same role. All distinct claims are listed in `all_owner_claims`. |

Non-healthy statuses surface as `health.Alert` entries (critical for missing/split-brain, warning for dead-owner) and `health.ComponentHealth` entries in the response. Detection is on-demand (no background poll): the endpoint scans the current DNA snapshot and config store on each call.

**Workflow-driven `ha_role` writes (Issue #2667):** the `set_ha_role` workflow step is the first production writer of a resource's `ha_role` field via the workflow engine. It reads the target steward's device-scope config document (`stewards/<steward_id>`), locates the named `hyperv.vm` resource, and merges `{cluster_name, resource_group_name}` into its `ha_role` block. The write goes through `ConfigurationServiceV2.SetConfiguration` — the same validated + fan-out path as every other device-scope write — ensuring `ValidateConfiguration` runs and the registered `FanoutCallback` (Save = Deploy) fires an immediate push to the steward.

**No-op for non-clustered stewards:** when a steward has no cluster membership, the cluster-policies step is skipped entirely. The `EffectiveConfiguration` output is byte-identical to before this cascade level was introduced, verified by regression tests.

### Role-Policies Namespace (Issues #2543, #2546)

The `role-policies` ConfigStore namespace stores **role configs**: named objects that couple a selector expression with a `StewardConfig` fragment. During config resolution the resolver evaluates all role configs for the tenant, selects those whose selector matches the target steward's DNA + controller-stored tags, and merges the fragments into the effective config after cluster-policies and before device config. Authoring is handled by the `/api/v1/roles` REST endpoint and the `cfg role` CLI verb.

**Role config object shape:**

```json
{
  "name":      "github-runners",
  "tenant_id": "acme/ops",
  "selector":  "os:windows tag:github-runner",
  "fragment":  { ... StewardConfig fields ... },
  "created_at": "2026-07-13T00:00:00Z",
  "created_by": "ops-admin"
}
```

- `name` — unique within the tenant; alphanumerics, hyphens, underscores, and dots only.
- `selector` — standard fleet selector expression parsed by `pkg/fleet/selector.Parse`; stored verbatim. Validated at author time; an un-parseable selector is rejected with 400.
- `fragment` — a partial `StewardConfig`; no steward ID is required. Fields that are empty or zero-valued in the fragment are not merged (the field retains the value from the lower-priority layer).

**ConfigKey:**

```
ConfigKey{TenantID: "<tenant>", Namespace: "role-policies", Name: "<roleName>"}
```

**Authoring:** `POST /api/v1/roles` (requires `role:write`), `GET /api/v1/roles` / `GET /api/v1/roles/{name}` (requires `role:read`), `DELETE /api/v1/roles/{name}` (requires `role:write`). Cross-tenant authoring is rejected with 403. See `cfg role --help` for CLI usage.

**Resolution:** `InheritanceResolver.ResolveConfiguration()` applies matching role fragments between cluster-policies and device-level config (Issue #2546). The `roleConfigAdapter` in `config_service_v2.go` lists all `role-policies` entries for the tenant, parses each selector via `pkg/fleet/selector.Parse`, and returns the matching fragments sorted alphabetically by name. Multiple matching roles merge in that order; later names override earlier ones for the same resource. A role-provider error is non-fatal: resolution continues without role fragments and a WARN is emitted.

## Deployment Rings

Deployment rings are a fleet-wide governance mechanism that controls which steward binary version reaches which stewards, in what order. The controller declares an ordered, named ring set; each steward subscribes to a ring via its DNA attribute `deployment_ring`; and config delivery resolves the effective `desired_version` from the ring.

### Ring Configuration

Rings are declared in the controller config under `deployment_rings:`. Example with the four default rings:

```yaml
deployment_rings:
  fallback_ring: default          # ring used for stewards with no/invalid ring attribute
  rings:
    - name: pre-release           # name must match ^[a-z][a-z0-9-]{0,31}$
      desired_version: "v0.6.0"   # version targeted at this ring; empty = no override
    - name: early
      desired_version: "v0.5.21"
      soak: 24h                   # Story S3: minimum soak before promotion
      halt_threshold: 0.05        # Story S3: error-rate threshold that halts promotion
      concurrency_limit: 10       # Story S3: max simultaneous upgrades in this ring
    - name: default
      desired_version: "v0.5.20"
    - name: stable
      desired_version: "v0.5.19"
```

When `deployment_rings:` is absent from controller config, the default four-ring set is applied automatically: `pre-release → early → default → stable`, with `default` as the fallback ring.

**Validation at startup:** ring names must be non-empty, unique within the set, and match `^[a-z][a-z0-9-]{0,31}$`. The `fallback_ring` must name a declared ring. Invalid config causes a startup error.

### Steward Ring Subscription

A steward subscribes to a ring via the `deployment_ring` DNA attribute, set by the operator:

```
cfg dna set <steward-id> deployment_ring early
```

The controller validates the attribute value at config-delivery time (not at DNA-write time). The `deployment_ring` attribute is a plain string set by the operator — stewards do not self-assign rings.

### Ring-Resolved Config Delivery

When the controller delivers config to a steward (`GetConfiguration`):

1. The inheritance resolver walks the tenant hierarchy and produces the effective config, including any `desired_version` set at the tenant-config path.
2. The controller reads the steward's DNA `deployment_ring` attribute.
3. `ResolveRingVersion` (`pkg/config/inheritance.go`) looks up the ring in the declared ring set.
4. If the resolved ring has a non-empty `desired_version`, that value **overrides** the tenant-path `desired_version`. This makes rings the authoritative targeting vocabulary for version rollouts.
5. If `desired_version` is empty for the resolved ring, no override is applied and the tenant-path value is used unchanged.

### Fallback Behavior

When a steward's `deployment_ring` is absent or names a ring not in the declared set, the controller falls back to the `fallback_ring`. The fallback is logged as a structured WARN:

```
deployment_ring_fallback  steward_id=<id>  ring_value=<original or empty>  fallback_ring=default
```

This is the v1 anomaly surface; a metric/alert layer is a follow-on story. Operators should assign all fleet stewards to rings to suppress this warning.

### Ring-Set Change Audit

Every change to the ring set (add/remove/reorder/version change) is logged at INFO level via the structured audit logger with actor, before-state, and after-state:

```
ring_set_changed  actor=controller  before=[pre-release=v0.5.20,...] fallback=default  after=[...]
```

Ring-set mutation happens only via controller config file reload or restart. No live-mutation REST API exists in this version.

### Ordered Promotion Model

The ring order in `deployment_rings.rings` defines the promotion sequence: the operator advances a version from earlier rings (pre-release → early → default → stable) by setting `desired_version` on each ring. The rollout workflow that automates this advancement is described in the [Rollout Workflow](#rollout-workflow) section below.

### Rollout Workflow

`POST /api/v1/rollout` starts a ring-advance rollout that moves a target steward binary version through the ordered ring set. Each ring transition is governed by a configurable soak period and a health gate; if the health gate fails the rollout halts and the operator must resolve the issue before restarting.

#### Ring-Advance Loop

The rollout goroutine processes rings in declaration order:

1. **Set desired_version** — the ring's `desired_version` is updated in-memory to the target version, making it visible to ring health queries for this controller process.
2. **Soak** — if `ring.soak` is non-zero, the goroutine waits the soak duration before sampling health. Zero soak skips the wait.
3. **Query ring health** — the fleet is queried for all stewards with `deployment_ring = <ring>`. Each steward is classified as:
   - **on-version**: `RunningVersion == desired_version`
   - **failed**: has a terminal-failure upgrade record (`status: failed` or `rolled_back`) for this version
   - **pending**: all others (no record yet, or an in-progress upgrade)
4. **Halt or advance**: if `failed / (on_version + failed) > halt_threshold` the rollout transitions to `halted`. Otherwise the ring is marked completed and the loop advances to the next ring.

#### Failure Policy

**Per-endpoint requeue**: a steward that does not reach the target version is not dropped. Its ID is appended to `RolloutRecord.DeferredStewards` after the health gate runs. The steward's `deployment_ring` attribute is never mutated by the rollout; it remains in its ring and will be retried on the next rollout pass.

**Per-ring halt**: if `failed_count / (on_version_count + failed_count) > halt_threshold` (per-ring `RingSpec` field, default 0.05) the rollout halts: no further ring promotions occur, no new dispatches are issued, and a structured error is logged. The operator resolves the failures and re-issues the rollout.

Pending stewards are excluded from the halt-threshold denominator — they are still in-flight and are counted separately.

#### Operator Halt

`POST /api/v1/rollout/{rollout_id}/halt` signals the rollout goroutine to stop advancing. The goroutine checks the halt signal at soak time and at each ring boundary. The rollout record transitions to `halted` status immediately on the API call; the goroutine exits at the next checkpoint.

#### Rollout Status

`GET /api/v1/rollout/{rollout_id}` returns:

| Field | Description |
|-------|-------------|
| `current_ring` | Ring currently being processed; empty when completed |
| `status` | `in-progress`, `halted`, or `completed` |
| `on_version_pct` | Percentage of current-ring stewards on the target version |
| `failed_count` | Stewards with terminal upgrade failures in the current ring |
| `pending_count` | Stewards still in progress in the current ring |
| `rings_completed` | Number of rings that passed the health gate |
| `rings_total` | Total rings in the rollout plan |

Health metrics are computed live against the current ring for in-progress rollouts; terminal states report the final observed values.

#### v1 In-Memory Durability Risk

The rollout goroutine runs in memory on the in-memory workflow engine. **A controller restart during a rollout loses the orchestration state (current ring, progress counter).** The operator must re-issue the rollout after restart.

Ring `desired_version` mutations applied by the goroutine are in-memory only in v1; they survive for the lifetime of the controller process but are not persisted to the git-backed config. The `RolloutRecord` stored in `RolloutStore` is durable (git-backed or database-backed depending on the configured provider) and tracks which rings were completed before the restart.

**Mitigation**: the operator re-issues `POST /api/v1/rollout` after restart. Rings already at the target version will pass their health gate quickly (soak re-runs from scratch); rings not yet reached are processed as if starting fresh. No data is lost; at most a soak period is duplicated.

This risk is tracked in [ADR-008](decisions/008-durable-workflow-execution.md) and will be addressed when durable workflow execution (DBOS or equivalent) is adopted. Do not engineer around this limitation in v1 stories.

### Config Signing

Every cfg distributed to a steward is signed using the controller's dedicated signing certificate (or server cert in unified mode). The steward verifies this signature before applying, ensuring cfgs cannot be tampered with in transit or injected by a rogue source.

## Fleet Management

The controller maintains awareness of all registered stewards and their state.

### Fleet Registry Durability (Issue #663)

The fleet registry is backed by a `StewardStore` (see `pkg/storage/interfaces/steward_store.go`). Registrations, heartbeats, and status transitions are persisted to durable storage so the fleet view survives controller restarts without waiting for all stewards to re-register.

**Steward lifecycle states**: `registered` → `active` → `lost` / `deregistered`. Records are retained indefinitely for audit; a `lost` steward can re-register and will have its record updated in place.

**Implementation**: `features/controller/fleet/fleet.HealthTracker` wraps a `StewardStore` for durable fields and keeps ephemeral per-process metrics (`HealthMetrics`: task latency counters, config error counts) in-memory only. The in-memory metrics are not persisted and reset on restart — this is by design.

**After a restart**: On startup, the controller can call `ListStewards()` or `ListStewardsByStatus()` to enumerate the fleet without waiting for stewards to check in. The stored `last_seen` and `last_heartbeat_at` timestamps allow the controller to identify stewards that went silent before or during the restart.

### Controller-Side Tag Store (Issue #2542)

The tag store (`features/controller/tagstore`) provides a durable store of operator-assigned tags keyed by steward ID.

**Why a separate store — not DNA attributes:**
The controller replaces a steward's DNA wholesale on every `DNARefreshLoop` cycle (`SyncDNA` in `controller_service.go`). Any tag written into `DNA.Attributes` would be clobbered on the next refresh. The tag store is the clobber-proof source of truth for controller-owned metadata.

**Invariant:** Admin sets tags here; DNA refresh never touches this store. Tags survive controller restarts and DNA refreshes.

**Tag format:** `^[a-z0-9][a-z0-9-]{0,63}$` — lowercase alphanumeric start, hyphen-and-alphanumeric body, 1–64 characters. Enforced at write time. Keeps tags selector-safe without escaping.

**Implementation:** SQLite-backed (`modernc.org/sqlite`, pure-Go, CGO-free). Wired into `ControllerService` via `SetTagStore()`; accessed by later stories via `controllerService.TagStore()`.

**API:**
- `Set(ctx, stewardID, []string) error` — replace the full tag list (validates format, rejects duplicates)
- `Get(ctx, stewardID) ([]string, error)` — returns empty slice when no tags exist (not an error)
- `Delete(ctx, stewardID) error` — remove the entry (idempotent)
- `GetAll(ctx) (map[string][]string, error)` — all entries
- `TagsFor(stewardID) []string` — convenience accessor with no error return; logs failures

### Session Token Store (Issue #2774)

The session token store (`pkg/session` + `pkg/storage/providers/sqlite`) provides a durable backing store for `pkg/session.Manager`. At bootstrap the controller calls `initializeSessionStore` (`features/controller/server/server.go`) which selects the backing store based on `storage.sqlite_path`:

- **SQLite configured** — `SQLiteSessionTokenStore` is opened at `cfg.Storage.SQLitePath` (a dedicated handle, separate from the shared business-store handle). Both the CLI session manager (ADR-014 defaults: idle 15m / absolute 8h / grace 30s) and the web session manager (idle 60m / absolute 12h / grace 30s) share this store. Sessions survive controller restarts and, with the multi-node store backend (separate story), cluster failovers.
- **SQLite absent** — `session.NewMemStore()` is used. Sessions are operational but are lost when the controller process stops.

Either way, `httpServer.SetDurableSessionStore(sessionStore)` is called on every startup path so `sessionManager` and `webSessionManager` are never nil, and `POST /api/v1/sessions` / `POST /api/v1/web/login` never return 503 SESSION_UNAVAILABLE.

The security invariant is unchanged by the backing store: `session.Manager` always passes `session.HashToken(token)` to `Store.Set`/`Get` — the raw token value is never stored or logged.

### Steward Tracking

For each steward, the controller tracks:

| Data | Source | Update Frequency |
|------|--------|-----------------|
| Identity (ID, tenant, group) | Registration | Once |
| Connection status | Heartbeats | Configurable interval |
| Last heartbeat | gRPC heartbeat calls | Configurable interval |
| Health status | Heartbeat payload | With each heartbeat |
| Compliance status | Convergence result reports | After each convergence run |
| DNA aggregate root | Heartbeat payload | With each heartbeat |
| DNA fragments | Full sync (initial) or partial-sync deltas (data plane); stored **versioned/append-only** | On root mismatch, initial registration, or as changes occur |
| Steward version | Heartbeat `Version` field + `steward.version` DNA attribute | With each heartbeat and DNA delta |
| Performance metrics | Steward metric uploads | Periodic + on-demand |

### Heartbeat Monitoring

The controller monitors steward heartbeats to detect connectivity loss:

- Stewards send heartbeats at a **20 s base interval with ±10 s uniform per-tick jitter** (effective interval always in [20 s, 30 s) — see the [steward operating model heartbeat timing](steward-operating-model.md#heartbeat-timing) for rationale)
- The controller marks a steward **offline after 60 s of silence** (`StewardOfflineTimeout`, epic #1664) — this is 3 missed heartbeats at the 20 s base, providing tolerance for transient network blips
- Disconnected stewards continue operating independently — the controller simply loses visibility until the steward reconnects
- On reconnect, the steward resyncs queued reports and the controller rebuilds its view

**Two distinct timeout thresholds — do not confuse them:**

| Field | Default | Purpose |
|-------|---------|---------|
| `StewardOfflineTimeout` | 60 s | Marks a steward offline after extended silence (epic #1664). Used by `checkStaleHeartbeats`. |
| `HeartbeatTimeout` | 15 s | HA-failover detection threshold (Story #198, <15 s). Scoped exclusively to controller-HA scenarios. |

These fields must remain distinct. `HeartbeatTimeout` is intentionally short for fast HA-failover detection and must not be used for steward-liveness decisions.

### IP-Trust Establishment

The controller promotes a steward's source IP to **trusted status** only after it has been continuously healthy for at least the configured threshold (default: **30 minutes**). This is implemented by `IPTrustEvaluator` (`features/controller/registration/ip_trust_evaluator.go`, Issue #1694).

**Mechanism:**

1. Each heartbeat from a healthy steward triggers `RecordLiveness(tenantID, stewardID, ip, healthy=true)` via the `TrustEvaluator` wired into the heartbeat service.
2. The evaluator maintains an in-memory per-(tenantID, ip) timer recording the first time a healthy liveness event was seen.
3. When `now − firstSeen ≥ threshold`, the evaluator calls `store.AddTrustedRange(tenantID, ip+"/32", false)` and clears the timer.
4. When the steward goes offline (`healthy=false`), the timer is reset. The IP must sustain liveness from scratch before trust is granted.

**Sandbox-detonation resistance:** Analysis environments (VMs, containers) that auto-detonate after 3–15 minutes cannot sustain the 30-minute liveness window. Their IP is never promoted to trusted status.

**Failure-safe restarts:** The in-memory timer is intentionally non-durable. After a controller restart the 30-minute clock resets, but existing trust entries in the `IPTrustStore` survive. This is fail-safe — the timer reset only delays trust establishment; it never revokes already-trusted IPs.

**Configuration:** `registration.ip_trust_threshold` (YAML duration, default `30m`). The threshold is configurable per deployment; the default of 30 minutes is chosen to be well above sandbox lifetime (3–15 min) while remaining practical for legitimate registrations.

| Parameter | Default | Purpose |
|-----------|---------|---------|
| `registration.ip_trust_threshold` | 30 min | Continuous liveness required before IP is trusted (Issue #1694) |
| `registration.ip_trust_dark_window` | 30 days | Inactivity period before a trusted IP range is auto-revoked (Issue #1697) |
| `registration.pending_review_timeout` | 5 days | Maximum time a pending registration may await operator action (Issue #1697) |

### IP-Trust Dark-Window Expiry (Issue #1697)

A trusted IP range is automatically revoked after 30 consecutive days with no registrations and no healthy stewards from that range (the **dark window**). The sweep is performed hourly by `IPTrustExpiryJob` (`features/controller/registration/ip_trust_expiry.go`).

**Exemption:** Pre-seeded entries (`PreSeeded: true`) are never auto-revoked. Operator-owned ranges added via `cfg registration ip-trust add --pre-seeded` can only be revoked explicitly with `cfg registration ip-trust revoke`.

**Activity tracking:** `RecordHealthySteward` (called on every healthy steward heartbeat) updates the `last_activity` timestamp on the matching CIDR entry. A registration attempt from an already-known IP also counts as activity. An entry whose `last_activity` is older than the dark window is revoked on the next sweep.

**Idempotency:** Revoking an already-revoked entry is a no-op.

### Pending-Registration Expiry (Issue #1697)

Pending registration entries that have not been acted on within 5 days are automatically marked `expired` by `PendingExpiryJob` (`features/controller/registration/pending_expiry.go`). The sweep runs hourly and delegates to `PendingRegistrationStore.ExpireStale`.

Expired entries are visible via `cfg registration pending` (status `expired`). They cannot be approved or denied after expiry; the steward must re-register to obtain a fresh pending entry.

### Commands

The controller can send commands to stewards over the gRPC control plane service:

| Command | Purpose |
|---------|---------|
| `sync_config` | Tell steward to fetch its latest cfg now (optimization — steward also checks on schedule). Save=deploy will automatically issue this command for affected stewards once the storage-watch trigger is wired (see issue #1521). |
| `sync_dna` | Request fresh DNA collection and upload |
| `reconnect` | Instruct the steward to reconnect to the controller (used during HA failover) |
| `execute_script` | Run an ad-hoc script (outside the cfg) — [GAP: not implemented as a control-plane command — see issue #1523. Script execution is available via the REST API (`POST /api/v1/stewards/{id}/scripts`).] |

Commands are fire-and-forget with completion tracking — the controller publishes the command and monitors for completion/failure events.

### Steward Auto-Upgrade via `desired_version` (Issue #2260)

Operators pin the steward version fleet-wide or per-tenant via the `steward.upgrade` cfg block:

```yaml
steward:
  upgrade:
    desired_version: "v1.4.2"
    allow_downgrade: false   # default; set true to permit rollback
```

**Inheritance:** `desired_version` and `allow_downgrade` flow through the normal cfg-inheritance tree (root → tenant → group → device). A child setting overrides the parent. Absence at a level means the parent value is inherited unchanged.

**How a steward converges to `desired_version`:**

1. The controller pushes a new steward binary to the endpoint via the `push_steward_binary` data-plane command. The steward downloads, verifies, and stages the binary under `{Root}/versions/{version}/{binaryName}`, then invokes the launcher's `swap` sub-command. On success, the staged version and path are recorded internally (`lastStagedVersion` / `lastStagedBinaryPath`).
2. On every cfg-convergence cycle (`TriggerConvergence`), the steward reads `desired_version` from its last received cfg. If it differs from the running version, the steward re-invokes the launcher swap against the already-staged binary without downloading again.
3. **Self-fetch when nothing is staged (Issue #2833).** If the desired binary is not already staged, the steward pulls it from the controller itself — no push required. It requests `GET /api/v1/public/steward-binaries/{version}/{platform}/{arch}?tenant=...` over mTLS against the controller's HTTPS base (`CFGMS_CONTROLLER_HTTPS_URL`), then verifies, stages, and swaps through the same pipeline as the pushed path. This makes declaring a `desired_version` sufficient on its own to converge a steward.
   - **Tenant resolution:** the steward requests its own tenant namespace first, then falls back to `default` — so a fleet-wide binary published under `default` reaches every steward, while a tenant may override for just its own devices. The steward only ever requests tenants it is registered under.
   - **Independent publisher verification:** the steward verifies the Ed25519 publisher signature against the **build-time-baked** `CFGMSPublisherIdentity`, over the version-bound `contentHash|version|platform|arch` composite (Issue #2834). The version/platform/arch fed to the check come only from the steward's own requested `desired_version` and detected `runtime.GOOS`/`GOARCH`, and the content hash is recomputed locally — never taken from a controller-supplied header. The `X-CFGMS-Publisher` response header is a hint only and can never select a verification key. This means a compromised controller cannot make a steward run an unsigned, altered, or rolled-back binary.
   - **Host-pinned + https-only:** the constructed URL's host is pinned to the controller transport host and the scheme must be https, so no cross-host fetch is possible.
   - **Degrade safe:** any failure (unset HTTPS base, network, sha/signature/version-binding mismatch, both tenants 404) leaves the steward on its current version to retry next cycle; it never swaps an unverified binary.
4. If `allow_downgrade` is `false` (the default) and `desired_version` is older than the running version, the swap is blocked. Set `allow_downgrade: true` to permit explicit rollbacks.

**Downgrade guard:**
- Blocked unless `allow_downgrade` is `true` in either the running cfg or the controller-synced config cache (`upgradeAllowDowngrade`).
- This prevents accidental downgrades from misconfigured cfg pushes.

**Version tracking in DNA and heartbeats:**
- `steward.version` is injected into every DNA delta before publish. The controller stores it as a DNA attribute and exposes it in the fleet list API (`GET /api/v1/stewards`).
- Every heartbeat now carries a `Version` field, which `RecordHeartbeat` uses to keep the in-memory fleet registry current.

**Fleet visibility:** the steward API list response includes `version` (from `steward.version` DNA attribute) alongside `id`, `status`, and `last_seen`. Operators can filter and audit version skew across the fleet without a separate inventory tool.

## Orchestration

The controller coordinates operations that span multiple stewards. Individual stewards apply their own cfgs; the controller determines sequencing and timing.

### Batch Job Dispatch (Issue #2296)

Rolling-batch jobs are the primary orchestration primitive. A batch job:

1. Resolves a fleet selector to a list of steward IDs.
2. Partitions the list into waves of `batch_size` stewards.
3. Dispatches a `ConfigSyncBatch` command to each wave via the `RollingBatchExecutor`.
4. Tracks per-step status in `BatchJobStore` (pending → running → completed/failed).

**REST API:**

| Method | Path | Permission | Description |
|--------|------|------------|-------------|
| `POST` | `/api/v1/jobs` | `jobs:write` | Submit a rolling-batch job; returns 202 Accepted with job ID |
| `GET`  | `/api/v1/jobs/{id}` | `jobs:write` | Poll job status and step table |

**CLI:**

```
cfg job submit --selector <expr> [--batch-size <n>]   # default batch-size 10
cfg job status <job-id>
```

The executor runs asynchronously — the HTTP response returns immediately with the job ID. Callers poll `GET /api/v1/jobs/{id}` for progress.

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

The workflow engine hosts **workflow modules** that implement the same Get/Set contract as steward modules, but execute against external APIs instead of local system state. The M365 family (auth, conditional-access, intune-policy, entra-group, entra-admin-unit, entra-user, entra-application) lives at `features/workflow/modules/m365/` and is the first set of these.

1. **Get** — Query the external API for current resource state (e.g., read current conditional access policies from Entra ID)
2. **Compare** — Engine compares current state against desired state from the cfg
3. **Set** — If drifted, call the external API to converge (e.g., create/update the policy)

This means externally-managed resources get the same convergence loop as local resources — scheduled re-checks detect drift (someone changed a policy in the portal), and the controller corrects it.

### Event Hooks for Workflow-Managed Resources

Workflow modules can register monitors using platform-native mechanisms:

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
- **Operability** — operators can inspect and control running executions via the `cfg` CLI: `cfg workflow list` (definitions), `cfg workflow status <exec-id> --workflow <name>` (per-execution state and current step), `cfg workflow cancel <exec-id> --workflow <name>` (cancel a running execution). See [commands reference](../development/commands-reference.md#workflow-management).

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

The controller is the certificate authority and identity provider for stewards. Two credential flavors support different deployment workflows:

**Perennial registration tokens**
- Generated via REST API or `cfg token create --expires=<duration>`
- Scoped to tenant/group, with optional expiry
- Survive multiple registrations (never consumed on use); rotate with `cfg token rotate` to atomically invalidate all prior tokens and issue a fresh one
- Suitable for: manual onboarding, small fleets, time-bounded provisioning

**Long-lived tenant/group registration codes**
- Durable random opaque strings stored as a join field on the tenant/group record
- On registration, the controller looks up the code and assigns the steward to the matching tenant/group
- Suitable for: RMM/GPO mass deployment where the same code is baked into deployment scripts and used by many devices
- Renaming a tenant/group does not break previously issued codes (the code is independent of the human-readable name)

**Registration flow:**

1. Admin creates a token or code on the controller (scoped to tenant/group, with optional expiry for tokens).
2. Steward presents the token/code during registration via the compile-time controller URL.
3. Controller validates the credential — perennial token: check expiry and revocation; long-lived code: look up matching record.
4. Controller runs the registration approval workflow via `RegistrationApprovalHook`. The active workflow is selected by `registration.workflow` in `controller.cfg`:
   - **`ip-trust`** (default): approves the registration when the steward's source IP is trusted for its tenant; quarantines otherwise. The first steward from any new tenant always quarantines because no IP is trusted yet. The hook is code-wired (`IPTrustApprovalHook`), not seeded as a workflow. It fails closed — a nil or erroring trust store quarantines rather than admits.
   - **`manual-review`** (production): quarantines the steward pending operator action. Sets `registration_decision: quarantine` so the steward is restricted to baseline config until promoted. Operators use `cfg registration pending` to list quarantined stewards, `cfg registration approve <id>` to promote, and `cfg registration deny <id> [--reason ...]` to reject.
   - **`auto-approve`** (deprecated): approves every valid registration unconditionally. Dev/test environments only — a startup warning is logged. Replaces the legacy `DefaultApprovalHook`.
   - Custom workflows can implement arbitrary policy (e.g., approve `tenant=lab` registrations, reject everything else)
5. On approval (`approve`): controller generates the steward ID and issues an mTLS client certificate scoped to the steward's tenant/group identity (HTTP 200 with full cert bundle).
   On quarantine (`quarantine`): controller returns HTTP 202 with a `pending_id` and no certificates. The pending entry is written to the durable `PendingRegistrationStore` (SQLite by default, PostgreSQL at production scale). The steward polls `GET /api/v1/registration/status/{pending_id}` with its registration token as a Bearer credential until the operator acts. Operators use `cfg registration approve <pending-id>` or `cfg registration deny <pending-id>`.
   On rejection (`reject`): HTTP 403 is returned; registration is denied.
6. **Generate-on-claim (quarantine path):** When the operator approves an entry and the steward polls again, the controller generates the mTLS certificate in memory for that single response, marks the entry as `claimed`, and returns the full cert bundle in HTTP 200. A subsequent poll on an already-claimed entry returns HTTP 410 Gone — the cert is never re-issued. Private keys are never stored in the database.
7. Controller distributes the CA cert, signing cert, and connection details.
8. Steward is now a trusted member of the fleet and stores its cert for subsequent startups.

**Registration status endpoint (Issue #1696):**

`GET /api/v1/registration/status/{pending_id}` — authenticated with `Authorization: Bearer <regToken>`.

| Response | Meaning |
|----------|---------|
| HTTP 200 `{"status":"pending"}` | Operator has not yet acted |
| HTTP 200 `{"status":"claimed", "client_cert":..., ...}` | Approved and cert issued — steward should connect now |
| HTTP 410 Gone | Already claimed (duplicate poll) — stop polling |
| HTTP 200 `{"status":"denied"}` | Operator denied — steward should exit or re-register |
| HTTP 200 `{"status":"expired"}` | Entry expired before operator acted — steward should re-register |
| HTTP 403 | Token tenant ≠ entry tenant (tenant isolation) |
| HTTP 401 | Invalid or missing Bearer token |

**Configuring the registration workflow (`controller.cfg`):**

```yaml
registration:
  workflow: ip-trust       # or: manual-review, auto-approve (default: ip-trust)
  # trusted_proxies lists CIDR ranges of reverse proxies trusted to set
  # X-Forwarded-For. Empty (default) means X-Forwarded-For is never trusted.
  trusted_proxies:
    - "10.0.0.0/8"
```

| Value | Behavior |
|---|---|
| `ip-trust` (default) | Approves the registration when the source IP is trusted for the tenant; quarantines otherwise. Code-wired (`IPTrustApprovalHook`) — no workflow is seeded. Fails closed on a missing or erroring trust store. |
| `manual-review` | Quarantines every new steward pending operator action. Seeds a built-in workflow with `Variables: {registration_decision: quarantine}`. Use `cfg registration pending` / `approve` / `deny` to manage the queue. |
| `auto-approve` (deprecated) | Approves all valid registrations immediately. Dev/test environments only — a startup deprecation warning is logged. |

If `registration.workflow` is omitted, the controller defaults to `ip-trust`. The `CFGMS_REGISTRATION_WORKFLOW` environment variable overrides the config-file value (used by test environments to opt into `auto-approve`).

**X-Forwarded-For spoofing protection:** The controller derives the steward's source IP for the IP-trust decision from the TCP peer address (`r.RemoteAddr`). It honors an `X-Forwarded-For` header **only** when the TCP peer falls within a `trusted_proxies` CIDR range. With `trusted_proxies` empty (the default), `X-Forwarded-For` is always ignored, so an attacker on an untrusted network position cannot bypass IP-trust by injecting a forged header. When the controller runs behind a load balancer, set `trusted_proxies` to the load balancer's address range so the real client IP is used.

**Managing pending registrations with `cfg registration`:**

When using `manual-review`, quarantined stewards accumulate in the controller's durable pending queue until approved or denied. Use the `cfg registration` CLI commands to manage them:

```bash
# List all quarantined stewards awaiting approval (shows SOURCE_IP and RDNS columns)
cfg registration pending

# Approve a steward (promotes from quarantined → registered)
cfg registration approve <steward-id>

# Deny a steward (removes from queue; steward must re-register to retry)
cfg registration deny <steward-id> --reason "Unauthorized deployment"

# Approve all pending registrations in one call
cfg registration approve-all

# Approve only pending entries whose source IP is in a given CIDR range
cfg registration approve-by-cidr 10.0.0.0/8

# Add a pre-seeded trusted CIDR range for a tenant (ip-trust workflow)
cfg registration ip-trust add 10.0.0.0/8 --tenant-id acme-corp

# Revoke a trusted CIDR range for a tenant
cfg registration ip-trust revoke 10.0.0.0/8 --tenant-id acme-corp
```

| Command | HTTP call | Effect |
|---|---|---|
| `cfg registration pending` | `GET /api/v1/registration/pending` | Lists all quarantined stewards with SOURCE_IP and RDNS |
| `cfg registration approve <id>` | `POST /api/v1/registration/{id}/approve` | Promotes steward status to `registered` |
| `cfg registration deny <id>` | `POST /api/v1/registration/{id}/deny` | Removes steward from pending queue |
| `cfg registration approve-all` | `POST /api/v1/registration/approve-all` | Approves all pending registrations in the caller's tenant scope; prints count approved |
| _(web registration console only)_ | `GET /api/v1/registration/approve-by-cidr/preview?cidr=<cidr>` | Read-only dry run: returns the count, pending IDs, and source IPs that `approve-by-cidr` would approve. Mutates nothing |
| `cfg registration approve-by-cidr <cidr>` | `POST /api/v1/registration/approve-by-cidr` | Approves pending entries in the caller's tenant scope whose source IP falls in the CIDR. Requires a user-presence step-up (below) |
| `cfg registration ip-trust add <cidr>` | `POST /api/v1/registration/ip-trust` | Adds a pre-seeded trusted CIDR for `--tenant-id` |
| `cfg registration ip-trust revoke <cidr>` | `DELETE /api/v1/registration/ip-trust/{tenant_id}/{cidr}` | Revokes a trusted CIDR for `--tenant-id` |

Required API key permissions: `registration:list-pending` for `pending` and for the approve-by-CIDR preview; `registration:approve` for individual approval and `approve-all`; `registration:approve-by-cidr` for `approve-by-cidr`; `registration:deny` for denial; `registration:manage-ip-trust` for ip-trust subcommands.

**Tenant scoping of bulk approval.** `approve-all` and `approve-by-cidr` — and the preview — resolve their target set through `ListPending(ctx, callerTenantID)`, so a caller whose principal carries a tenant (API key or non-root web account) can only approve pending entries belonging to that tenant. A caller with no tenant on its principal (mTLS admin bundle, root-scoped web account) retains fleet-wide reach. Entries outside the caller's scope are never listed, previewed, or mutated.

**Presence step-up on `approve-by-cidr`.** `registration:approve-by-cidr` carries `RequireUserPresence: true` (ADR-021 Decision 4): `AssuranceStrong` alone is not enough, and the request must also carry a fresh, single-use `X-Presence-Token` obtained from `POST /api/v1/webauthn/presence/begin` → `/finish`. Without one the call returns `401` with `WWW-Authenticate: CFGMS-StepUp realm="cfgms", required="strong", presence="required"`. Rationale: one call admits every pending steward in an IP range, and RFC1918 ranges collide across tenants, so the match set is a trust-boundary decision. The preview endpoint is deliberately *not* presence-gated — an operator inspects the exact match set first, then spends one gesture on the mutation. The web console blocks the mutating call until the preview has been shown and confirmed.

The `pending` output includes a `SOURCE_IP` column showing the steward's source IP at registration time, and an `RDNS` column populated by a best-effort reverse DNS lookup at display time (shows `-` on failure or timeout).

The `approve-by-cidr` command performs IP containment filtering on the controller using `net.ParseCIDR` + `ipNet.Contains` — the CIDR is not delegated to the database. All approved entries are updated atomically per-entry; partial approval (some entries approved, others skipped) is the expected outcome.

The pending queue is backed by the durable `PendingRegistrationStore` (SQLite by default, PostgreSQL at production scale) and survives controller restarts.

### RBAC

All API operations are governed by role-based access control:

- **Permissions** — fine-grained actions (e.g., `steward:list`, `steward:write-config`)
- **Roles** — groups of permissions (e.g., `admin`, `operator`, `viewer`)
- **Subjects** — users or API keys assigned to roles
- **Tenant scoping** — permissions are scoped to tenant path; an MSP admin sees all descendants, a client admin sees only their subtree
- **Zero-trust evaluation** — every request is evaluated against the policy engine

#### Cache Invalidation

The RBAC and zero-trust policy subsystems maintain a two-tier authorization cache (L1 in-memory, L2 warm store). When a role is revoked or a zero-trust policy is deactivated or retired, all cache layers are invalidated **synchronously** before the write returns. Stale cached grants cannot outlive the policy change that revoked them.

If a cache invalidation call fails transiently (e.g., transient error), the operation is still recorded in the audit log with `cache_invalidation_failed=true`. In that scenario, the worst-case stale window is bounded by cache TTLs: **up to 5 minutes** for L1 + **up to 10 minutes** for L2 (L2 TTL is typically 2× L1). Under normal operation (invalidation succeeds) the stale window is zero.

### API Authentication

Three authentication mechanisms, used for different purposes.

**Admin mTLS bundle (primary operator path)**
- Single-file YAML containing admin cert + key + CA inline
- Generated on `--init` and written to a platform-default path:
  - Linux/macOS: `/etc/cfgms/admin.bundle.yaml`
  - Windows: `%ProgramData%\cfgms\admin.bundle.yaml`
- The `cfg` CLI auto-discovers via: `--bundle <path>` flag → `CFGMS_ADMIN_BUNDLE` env → `~/.config/cfgms/admin.bundle.yaml` → system path
- `cfgms-controller bootstrap-admin` manages bundles:
  - Issue named bundles per operator (`bootstrap-admin --name <op> --output <path>`)
  - Regenerate the system bundle (`bootstrap-admin --regenerate`)
  - List issued bundles (`bootstrap-admin --list`)
  - Revoke by serial (`bootstrap-admin --revoke <serial>`)

**API keys (programmatic access)**
- Stored encrypted, used for service-to-service integration and scripted automation
- Scoped to specific permissions via RBAC

**Registration tokens (steward bootstrap only)**
- Scoped, expirable tokens for the steward registration flow described in [Steward Registration](#steward-registration)
- Not usable for general API authentication after bootstrap

### Admin Session Model

The zero-standing-privilege session model (ADR-014) eliminates long-lived admin credentials: a human admin authenticates once with a short-lived mTLS certificate, receives a rolling bearer token, and the token automatically expires if unused.

For the operator-facing CLI workflow (first connect, reconnect, session status, disconnect), see the [cfg Operator Guide](../../deployment/cfg-operator-guide.md). This section documents the server-side mechanics.

**Session lifecycle:**

1. `POST /api/v1/sessions` — admin mTLS only; returns `{session_id, token, issued_at, idle_ttl, absolute_expiry}` (HTTP 201). The token is a 43-char base64url string (32 random bytes from `crypto/rand`, 256 bits of entropy). The `cfg connect` command drives this call.
2. Every authenticated request carrying `Authorization: Bearer <session-token>` resets the idle TTL and returns a refreshed token in the `X-Session-Token` response header. The client replaces its stored token with the refreshed value on each response. The `cfg` CLI handles token rotation transparently — each subcommand that makes an API call automatically updates the stored token.
3. `DELETE /api/v1/sessions/{id}` — revokes immediately; callable with a valid session token or an admin mTLS cert. The `cfg disconnect` command drives this call.

**Token lifecycle parameters (ADR-014 ratified defaults):**

| Parameter | Default | Description |
|---|---|---|
| Idle TTL | 15 minutes | Session expires if no request is made within this window |
| Absolute cap | 8 hours | Hard ceiling from original connect, regardless of activity |
| Grace window | 30 seconds | Prior token remains valid this long after a renewal (tolerates racing requests from a stateless CLI) |

**Rolling-token model:** On each successful request, the controller generates a fresh token (current token → new token, old token moves to grace slot). Concurrent requests carrying the prior token during the grace window are accepted without triggering a second rotation. After the grace window, the prior token is rejected (HTTP 401).

**Security properties:**
- The controller stores only SHA-256(token) — raw token values are never persisted or logged.
- Token values are sanitized from all log output via `logging.SanitizeLogValue()`.
- Session-token principals carry `IsAdmin=true` with the same tenant scope as the originating mTLS cert (typically empty for admin certs, meaning no tenant restriction).
- Session tokens are length-distinguishable from API keys: session tokens are 43 chars (base64url without padding), API keys are 44 chars (base64url with padding). The middleware uses this length difference to route auth correctly.
- Session durability follows `storage.sqlite_path`: when SQLite is configured, sessions survive a controller restart and the `cfg` CLI can reconnect without re-authenticating; when SQLite is absent, an in-memory store is used and sessions are lost on restart. The store selection happens at bootstrap (`initializeSessionStore`, story #2774) using the same config signal as the upgrade-store and tag-store fallback paths.
- The `cfg` CLI stores the session token in the OS-native secret store (Windows Credential Manager, macOS Keychain, Linux Secret Service or kernel keyring) — never in a file on disk. The encrypted admin bundle stored alongside it is machine-bound and cannot be reused from another machine.

## Multi-Tenancy

The controller enforces strict tenant isolation across all operations.

### Principal Fields: Assurance vs. GlobalScope

Every authenticated `Principal` carries two independent fields that govern different access decisions:

- **`Assurance`** — the identity assurance level (ADR-021). Governs which operations the principal may perform: `AssuranceMachine` (API key, relay-script), `AssuranceBasic` (cfg-Bearer session, web session), `AssuranceStrong` (mTLS cert). Auth-strength-gated routes (certificate provisioning, RBAC management, etc.) check this field.

- **`GlobalScope`** — whether the principal has cross-tenant visibility (`true`) or is confined to its own tenant subtree (`false`). Today all human-authenticated principals (mTLS cert, cfg-Bearer session, web session) have `GlobalScope=true`; all machine principals (API key, relay-script) have `GlobalScope=false`.

These signals are **orthogonal**: a future tenant-scoped web account type would have `Assurance=AssuranceBasic` but `GlobalScope=false` and would be tenant-confined despite its assurance level. A strongly-authenticated but tenant-scoped service account would have `Assurance=AssuranceStrong` but `GlobalScope=false` — it could perform strongly-authenticated operations but only within its own tenant. Do not collapse these two signals back into one; see ADR-021 Context §"It is load-bearing on an unwritten assumption" for the failure mode this separation forecloses.

### Tenant Model

CFGMS uses a **recursive parent-child tenant model**. Every tenant has a unique identifier and an optional parent identifier. There are no fixed hierarchy levels — "MSP → Client → Group → Device" is a common convention, but the system supports arbitrary depth.

Tenants are identified by **path** (e.g., `root/msp-a/client-1/servers`). Path-based identification enables:

- **Prefix matching** — target all tenants under `root/msp-a/` with a single operation
- **Wildcard targeting** — `root/msp-a/*/production` matches all production groups across clients
- **Efficient resolution** — cfg inheritance walks the path from root to leaf

#### Example: Single MSP

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

One root tenant, unlimited depth.

#### Example: SaaS Platform

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

Multiple independent root tenants under a platform tenant. MSPs cannot see each other's trees. This topology enables cfg.is to host hundreds of MSPs on shared infrastructure with per-MSP isolation, resource scheduling, and billing.

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
- **Multi-root isolation** — independent root tenants are fully isolated; no inheritance, no visibility, no shared state between roots

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

### Single Server

The controller runs as a single instance. If it goes down, stewards continue operating independently on their last-known cfgs. When the controller comes back, stewards reconnect and resync.

### Clustered

Multiple controller instances form a **Raft consensus cluster**. Raft is the sole authority for cluster membership and leader election — there is no static or geographic node discovery layer, and no ad-hoc election logic outside Raft:

- **Cluster membership** — determined exclusively by Raft consensus; peers are bootstrapped from the `discovery.config.nodes` list and thereafter managed by Raft configuration changes
- **Leader election** — Raft consensus elects one node as leader to handle writes; `CheckQuorum:true` causes the leader to step down automatically when it loses quorum, without any explicit demotion call
- **State replication** — cfg changes, registration events, and fleet state are replicated across nodes via the Raft log
- **Automatic failover** — if the leader goes down, Raft elects a new leader automatically
- **Split-brain detection** — the cluster detects and resolves network partitions; quorum-based resolution delegates leader step-down to Raft (`CheckQuorum`) rather than calling explicit demote operations

Stewards connect to any cluster node. If their node goes down, they reconnect to another.

#### Raft Peer Authentication

The `POST /raft/message` endpoint uses **mTLS peer certificate CN verification** as its sole authentication mechanism. The TLS listener in `ClusterMode` is configured with `ClientAuth = tls.VerifyClientCertIfGiven` (set in `setupManagedTLS`), so HA peers that present a client certificate have it chain-verified and recorded in `r.TLS.PeerCertificates` for application-layer inspection. Clients without a certificate still complete the TLS handshake and fall through to API-key auth on other endpoints; `HandleMessage` explicitly rejects them with HTTP 403.

`HandleMessage` extracts `r.TLS.PeerCertificates[0].Subject.CommonName` and rejects (HTTP 403) any request where:

- `r.TLS` is nil (plain HTTP, not mTLS)
- No peer certificate was presented
- The peer certificate CN does not match any entry in the node's `allowedCNs` list

The `allowedCNs` list is built at startup from the `discovery.config.nodes` peer entries (each node's `id` field) plus the local node's own `id`. This means **peer certificates must carry a CN that matches the `node.id` value declared in the cluster node configuration**.

**Peer certificate provisioning** is automatic. During `ClusterMode` startup, `ha.NewManager` requires a non-nil `*cert.Manager` and calls `certManager.GenerateClientCertificate` with `CommonName = cfg.Node.ID` to mint a dedicated peer identity cert. This cert is loaded into the outbound `raftTransport` HTTP client as `tls.Config.Certificates`, so every `POST /raft/message` the transport makes automatically presents it. Passing a nil `*cert.Manager` to `NewManager` in `ClusterMode` returns an error immediately. `SingleServerMode` and `BlueGreenMode` do not require a cert manager (no peer transport is created).

The `GET /api/v1/raft/status` endpoint is protected by RBAC (`ha:read-status` permission) via the standard API authentication middleware — it is not a peer endpoint and must not be accessed without a valid API key.

> **Do not use the `X-Raft-From` header for authentication** — it is set by the sender and is untrusted. Only the TLS peer certificate is authoritative.

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
| **Orchestration** | Initiate and monitor multi-node operations [GAP: not implemented — see Orchestration section above] |
| **Modules** | List cached modules, approve queued bundles |
| **Live telemetry** | `GET /api/v1/telemetry/ws/{steward_id}` — WebSocket endpoint that fans steward telemetry snapshots (process/service) to browser subscribers in real time. Requires `steward:telemetry` permission. The controller subscribes upstream to the steward (via `TelemetryRequest{subscribe=true}`) on the first browser connection and unsubscribes on the last browser disconnect, preserving the "collect only while watched" property. |

### Steward List Pagination

`GET /api/v1/stewards` returns the full steward list by default and supports optional server-side pagination (Issue #2489) so browser clients can page through large fleets without downloading the full list:

- **Query parameters:** `limit` (integer, 1–500) and `offset` (integer, ≥ 0). `limit` without `offset` implies `offset=0`; `offset` without `limit` is rejected with HTTP 400 (ambiguous page size). Out-of-range or non-integer values are rejected with HTTP 400 and a specific error code.
- **Ordering:** when paginating, results are sorted by steward ID before slicing so pages are stable across requests. This ordering exists solely for pagination determinism — user-facing sort is a client-side concern.
- **Paginated envelope:** when `limit`/`offset` are present, the response `data` payload is an object instead of the plain array:

```json
{
  "stewards": [ ... ],
  "total": 48123,
  "limit": 100,
  "offset": 200
}
```

`total` is the post-filter, pre-slice steward count, so clients can compute page counts. Pagination composes with the existing filter parameters (`os`, `platform`, `arch`, `status`, `hostname`, `tag`) and applies on both the filtered and unfiltered code paths.

- **Backward compatibility:** requests without `limit`/`offset` return the existing payload shape unchanged — a plain JSON array of stewards — so `cfg` and existing API clients are unaffected.

---

## Module Cache and Approval Workflow

The controller fetches module bundles from configured git sources, verifies publisher signatures, assigns an approval decision, and stages approved bundles in a content-addressed on-disk cache.

### Cache Filesystem Layout

Bundles are stored at:

```
<data_dir>/module-cache/<publisher>/<name>/<version>/<content_hash>/
    manifest.yaml      — module metadata (ModuleMetadata)
    binaries.yaml      — os-arch → relative binary path index
    signatures.yaml    — publisher signatures
    content_hash.txt   — original content hash (pre-path-sanitization)
    approval.yaml      — current approval state
```

The `<content_hash>` directory name is a path-safe transformation of the bundle's SHA-256 content hash. Standard base64 characters (`/`, `+`, `=`) are replaced with filesystem-safe equivalents; the original hash is preserved in `content_hash.txt` and returned by all cache operations.

**Idempotency:** `Put()` with the same content hash is a no-op. `Put()` with a different hash at the same `(publisher, name, version)` returns `ErrContentAddressConflict`.

### Git Source Resolver

`GitSourceResolver` maps `module_sources:` config blocks to git clone URLs:

```yaml
module_sources:
  cfgms:
    type: git
    base: https://modules.example.com/cfgms
```

For a reference like `cfgms/hyperv@0.2.1`, the clone URL is `<base>/<name>` (e.g. `https://modules.example.com/cfgms/hyperv`). Clones use `--depth 1` for minimal network and disk usage. Publisher, name, and version components are validated to reject path traversal sequences before use.

### Approval State Machine

Each bundle in the cache has one of three approval states:

```
                    ┌─────────────────┐
  Trusted publisher │                 │
  + valid signature │  auto-approve   │──────────────┐
                    └─────────────────┘              │
                                                     ▼
  [bundle arrives]──►  evaluate()  ──► pending ──► approved
                                          │
                    Unknown publisher     │  (admin Approve())
                                          │
                    ┌─────────────────┐   │
  Signature fails   │                 │   │
  (tampered bundle) │     reject      │◄──┘ (only from pending)
                    └─────────────────┘
                          ▼
                       rejected
```

**`ApprovalWorkflow.Evaluate(bundle, store)` rules:**

| Condition | Decision |
|-----------|----------|
| Publisher in trust store AND signature passes `VerifyBundleSignature` | `AutoApprove` |
| Publisher NOT in trust store | `QueueForReview` |
| Publisher in trust store but signature fails | `Reject` |

**Default trust list:** `["cfgms"]` (seeded from `pkg/modules/trust.CFGMSPublisherIdentity()`).

### `cfg module` CLI

```
cfg module list [--tenant <tenant-path>] [--status pending|approved|rejected]
cfg module approve <publisher>/<name>@<version>
```

`cfg module list` calls `GET /api/v1/modules` with optional `?tenant=...&status=...` query parameters and renders a tabular summary of publisher, name, version, approval status, and (truncated) content hash.

`cfg module approve` calls `POST /api/v1/modules/<publisher>/<name>/<version>/approve`, which invokes `ApprovalWorkflow.Approve()` server-side. Only bundles in `pending` state can be approved; an error is returned for bundles that are already approved or rejected.

Admin mTLS authentication (via admin bundle file) is required for both commands, following the same auth pattern as `cfg registration approve`.
