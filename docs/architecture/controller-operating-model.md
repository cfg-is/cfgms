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
8. **Start HA** (if clustered) — Begin contending for the cluster leadership lease (`pkg/lease`, ADR-031 Decision 5) against the shared database, and begin self-registering this node in the shared controller-node registry (Issue #3763) so peers can resolve it for cluster-to-cluster delivery. `GET /api/v1/ha/nodes` and `GET /api/v1/ha/leader` converge once the node's own registration and lease-acquisition loops complete their first cycle — both are independent background loops with no cross-node log to replay.
9. **Start REST API and Web UI** — A single TLS HTTP server (port 9080) serves both the REST API and the embedded web UI from the same listener. Owned exclusively by `server.Server` (`httpServer` field); `controller.go` does not create a second instance. The web UI is embedded in the controller binary via `//go:embed all:dist` in the `web/` package — no separate server, no second port, no Node toolchain at runtime. A committed placeholder (`web/dist/index.html`) keeps `go build` self-contained; a real Vite build (`npm run build` inside `web/`) writes to `web/dist/app/`, which the controller prefers over the placeholder when producing a release binary. The placeholder carries the `CFGMS_DIST_PLACEHOLDER` sentinel: a binary built without a frontend build refuses to route `/` and logs the reason, rather than serving an empty shell as if it were the application. The SPA is served as a lowest-priority catch-all route: REST API (`/api/*`) routes always take precedence. In `ClusterMode` the TLS listener is configured with `ClientAuth = tls.RequestClientCert`: HA peers that present a client certificate will have it recorded in `r.TLS.PeerCertificates` for application-layer CN verification, while non-cluster API clients (operators, curl, stewards, browsers) that do not present a client certificate are accepted without modification
10. **Start workflow engine** — Begin processing scheduled and queued workflows

**Failure modes on startup:**
- Missing config file → error with expected paths
- Storage unreachable → error with connection details
- CA/certs missing → error explaining that `--init` is required
- CA/certs expired → error with expiry details and renewal instructions
- Storage schema mismatch → error with migration instructions
- Transport address conflict → error with port details and resolution steps

### Degraded-Mode Visibility

A deployment may run with declared-optional storage capabilities absent. Optionality is a legitimate design choice — a subsystem can declare a store as optional (`interfaces.RequirementOptional`) when it degrades gracefully without it, rather than failing composition. Silence about such gaps is not: every declared-optional store that composes absent is surfaced, not left for an operator to discover at request time.

As of this writing, every subsystem-declared store requirement in the controller (including push-resumption's `PushStore`, guaranteed across all deployment shapes since Issue #3402) is `RequirementRequired`, so no capability is currently absent-by-design. The mechanism below is exercised by future subsystems (registration, workflow-trigger — epic #3406) that may declare optional dependencies; the example fields are illustrative.

**At startup**, every absent optional capability is logged once at `WARN` level with four fields:

| Field | Example |
|-------|---------|
| `capability` | `ExampleStore` |
| `subsystem` | `example` |
| `provider` | `flatfile` |
| `consequence` | `Example feature is degraded — <functional impact> (provider: flatfile)` |

An operator who watches the startup log can see exactly which features are degraded and why, without querying an endpoint.

**At runtime**, the same information is available through `GET /api/v1/ha/status` (requires the `ha:read-status` permission). The response includes an `absent_capabilities` array: empty when all declared optional capabilities are present, or one entry per absent capability otherwise. Each entry carries the same four fields logged at startup.

```json
{
  "node_id": "ctrl-01",
  "is_leader": true,
  "mode": "single_server",
  "health": "healthy",
  "absent_capabilities": [
    {
      "capability": "ExampleStore",
      "subsystem": "example",
      "consequence": "Example feature is degraded — <functional impact> (provider: flatfile)",
      "provider": "flatfile"
    }
  ]
}
```

**Fixable vs. by-design absence**: every entry names the running `provider`. If the consequence is unacceptable, the operator can switch to a provider that supplies the capability. If the absence is intentional for this deployment shape, the entry is informational only — it does not affect the `health` field or block any operation.

**Computation**: the capability set is evaluated once at composition time (`features/controller/server/server.go:New`), not per request. The result is stored in the API server and served verbatim.

**Access control**: `absent_capabilities` is part of the administrative status surface. Unauthenticated callers and callers without `ha:read-status` receive `401` before the handler runs; the capability detail is never included in error responses.

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

**FC-cascade config invariant (Issue #3107):** every `hyperv.vm` resource that carries an `ha_role` block — making it a clustered failover-cluster VM role — and every `hyperv.cluster` resource MUST reside in `cluster-policies/<clusterName>`, never in device scope (`stewards/<stewardID>`). This is not a soft convention: `GetClusterDeclaredResources` (the sole source for `Reconcile`'s declared set) reads **only** from `cluster-policies/<clusterName>`. A clustered resource that remains in device scope is **silently absent** from `Reconcile`'s input — it is never classified as `declared-but-missing`, `orphan-dead-owner`, or `split-brain`; the reconciliation machinery simply cannot see it. This means device-scope clustered declarations are not flagged as errors — they are silently unreconciled.

The `promote-hv-role` workflow (epics #2657/#2807, stories #2667–#2671) is the canonical and exclusive creation path for clustered `hyperv.vm` resources since those epics shipped. Every promotion terminates with the `move_resource_to_cluster` step, which atomically relocates the resource from `stewards/<stewardID>` to `cluster-policies/<clusterName>` with a cluster-first write order (the cluster doc is written before the device doc is updated, so a mid-flight crash leaves the resource in both docs rather than neither; re-running the step completes the device-side removal without re-writing the cluster doc). There are no backlog scattered declarations to migrate: the fleet has been greenfield on this invariant since the epics shipped. Operators authoring clustered resources directly (outside the workflow) must use `cfg config upload` targeting `cluster-policies/<clusterName>` from the start — never the device-scope `stewards/<id>` path.

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

Deployment rings are a fleet-wide governance mechanism that controls which steward binary version reaches which stewards, in what order. The controller declares an ordered, named ring set; ring membership is declared in controller config only (no write path exists for stewards or operators to self-assign rings); and config delivery applies the ring's `desired_version` to stewards per their controller-config membership.

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

A steward's ring membership is declared in controller configuration only. There is no steward-facing or CLI write path for ring assignment — no `cfg dna set ... deployment_ring` command exists or is planned. Ring assignment is controller-config-only: set `deployment_ring` for a steward by authoring the appropriate controller config document and reloading or restarting the controller.

### Ring-Resolved Config Delivery

When the controller delivers config to a steward (`GetConfiguration`), the effective `desired_version` comes from the tenant-path inheritance resolver only. Issue #3316 removed the config-delivery-time override that had read a steward's `deployment_ring` DNA attribute and applied the matching ring's `desired_version` on top of the resolver's result — that attribute has no write path, so the override always took the no-op fallback branch. This did not remove DNA-attribute-based ring reads elsewhere: the rollout health gate (`queryRingHealthCounts`, `failedStewardIDs` in `features/controller/api/handlers_rollout.go`) and the workflow engine's ring-health node (`features/workflow/nodes/ring_health_node.go`) still query the fleet by `deployment_ring` DNA attribute; see [Rollout Workflow](#rollout-workflow) below.

### Fallback Behavior

`fallback_ring` names the ring used when a steward's `deployment_ring` is absent or names a ring not in the declared set. Prior to Issue #3316, config delivery resolved this per steward on every `GetConfiguration` call and logged a structured WARN when the fallback was taken; that resolution path has been removed; no code now computes or logs an individual steward's fallback outcome. `fallback_ring` remains a declared config field (defaulted by `DefaultFallbackRing` in `features/controller/config/config.go`), but since no steward has a `deployment_ring` DNA attribute set (no write path exists), rollout health queries for any ring currently match zero stewards.

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

**Enrollment at claim, not at check-in (Issue #3403)**: A steward's durable `StewardRecord` is written at cert-issuance time (the "claim" step), not lazily at the first gRPC check-in. Both registration paths write the record at the same point:
- **Direct approval** (`handleRegister` with `AlwaysApproveHook`): `handleRegister` itself calls `StewardStore.RegisterSteward` with `StewardStatusRegistered` inline, before returning the cert bundle (pre-existing write, Issue #2095, unchanged by this story).
- **Quarantine → approve → claim** (manual-review flow): the steward polls `/api/v1/registration/status/{id}` once the operator has approved the pending entry; `buildClaimResponse` calls `StewardStore.RegisterSteward` at that poll, before the cert is returned.

Both paths enforce the same tenant-scoped `device_id` uniqueness rule before writing. `handleRegister` rejects a registration whose `device_id` is already held by another steward in the tenant (HTTP 409), and `buildClaimResponse` re-runs that check immediately before its own write: the register-time check cannot catch a collision between two enrollments that are both still pending, because neither has a `StewardRecord` yet. A colliding claim is refused with 409 and mints no certificate. Cross-tenant collisions remain allowed — each tenant namespace is independent. The rule keeps `GetStewardByDeviceID` unambiguous; it is the single lookup behind the registration-refresh revocation gate, so a second record sharing a `device_id` would let a revoked steward pass that gate against its sibling's identity key.

In both cases, `status = registered` at enrollment and `status = active` after the first gRPC check-in. A steward that is enrolled (cert issued) but has never connected is present in `StewardStore` and therefore visible in the fleet registry after a controller restart via `LoadFromStorage` — it cannot silently disappear due to a backend migration or node replacement that clears in-memory state.

An **unapproved** steward (pending entry in `PendingRegistrationStore`, operator has not yet acted) has no `StewardRecord` and is invisible to `LoadFromStorage`. It cannot receive config pushes or participate in convergence until its cert is claimed.

**Implementation**: `features/controller/fleet/fleet.HealthTracker` wraps a `StewardStore` for durable fields and keeps ephemeral per-process metrics (`HealthMetrics`: task latency counters, config error counts) in-memory only. The in-memory metrics are not persisted and reset on restart — this is by design.

**After a restart**: `LoadFromStorage` warms the in-memory registry from two sources: DNA storage (connected stewards that have sent at least one check-in) and `StewardStore` (all enrolled stewards including those that have never connected). This union guarantees that a steward enrolled on one controller node is immediately visible after a failover or backend migration, without waiting for it to reconnect.

### Durable Device-Tenant Mapping (Issue #3324)

Tenant resolution for a steward is backed by a dedicated `device_tenant` table (SQLite migration v2 / PostgreSQL schema), not by DNA. This is deliberate: the flat `DNARecord`/`dna_history` store is steward-writable data (`SyncDNA` replaces a steward's DNA wholesale on every refresh cycle), and deriving tenant from it would let a compromised steward influence its own tenant scoping — the invariant Issue #2008 forbids. `device_tenant` is written only by the controller at registration time (`RegisterSteward`, `AcceptRegistration`) and on an authenticated admin move (`UpdateStewardTenant`); the connect-hook reconnect path always passes an empty tenant so the durable value wins.

`lookupDurableTenant` (`features/controller/service/controller_service.go`) reads exclusively from `device_tenant` via `GetDeviceTenant` — `ok=false` means "tenant unknown," and callers must decline to fabricate a tenant-scoped registry entry rather than fall back to DNA.

**Controller-startup registry recovery** (`LoadFromStorage`) warms the in-memory steward registry from two sources:

1. **DNA storage**: tenant from `ListDeviceTenants()` (primary); `GetLatestByDeviceID`'s `record.DNA` for the DNA payload only, never for tenant. The single fallback to `record.TenantID` covers the narrow window between a `dna_history` write and a controller restart where the corresponding `device_tenant` write did not complete — migration v2 backfills `device_tenant` from `dna_history` on upgrade, so this fallback is a transient gap, not a steady-state path.

2. **StewardStore** (Issue #3403): `ListStewards()` is called after the DNA enumeration. Any steward present in `StewardStore` but absent from DNA storage (enrolled but never connected) is added to the in-memory registry using the tenant and status from its `StewardRecord`. This source is the fix for a validation lab incident where 3 HV-host stewards enrolled on 2026-08-01, never reconnected, and became invisible after the 2026-08-05 Postgres cutover that wiped DNA storage.

A device with no resolvable tenant from either source is skipped rather than warm-loaded with a fabricated tenant, per the Issue #2008 no-fabrication contract.

### Controller-Side Tag Store (Issue #2542)

The tag store (`features/controller/tagstore`) provides a durable store of operator-assigned tags keyed by steward ID.

**Why a separate store — not DNA attributes:**
The controller replaces a steward's DNA wholesale on every `DNARefreshLoop` cycle (`SyncDNA` in `controller_service.go`). Any tag written into the DNA record would be clobbered on the next refresh. The tag store is the clobber-proof source of truth for controller-owned metadata. (`DNA.Attributes` — the legacy flat map that was the prior candidate for in-band tag storage — was retired in Issue #3331; DNA now carries only `DNA.Fragments`.)

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

Either way, `httpServer.SetDurableSessionStore(sessionStore)` is called on every startup path so `sessionManager` and `webSessionManager` are never nil, and `POST /api/v1/sessions` / `POST /api/v1/web/passkey/login/begin` / `POST /api/v1/web/passkey/login/finish` never return 503 SESSION_UNAVAILABLE.

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

### Per-Tenant Ingest Admission Control (Issue #3759, ADR-031 Decision 6)

Steward ingest is admission-controlled per tenant by
`features/controller/transport.TenantQueue` — a per-tenant concurrency
semaphore, `MaxConcurrentPerTenant` (32) in-flight slots per tenant, non-blocking
`Acquire`/`Release`. Four entry points are gated on a cell: **connect**
(`Register`), **heartbeat** (`ControlChannel`'s Heartbeat message), **DNA sync**
(`SyncDNA`), and **bulk transfer** (`BulkTransfer`).

Two `TenantQueue` instances are constructed in
`features/controller/server.New` (`features/controller/server/ingest_admission.go`),
split by how much the controller trusts the bucket key each path uses:

| Instance | Paths | Bucket key |
|----------|-------|------------|
| `connectHeartbeat` | connect, heartbeat | server-verified (see below) |
| `dnaBulk` | DNA sync, bulk transfer | DNA: first chunk's `tenant_id` (wire data). Bulk: mTLS peer CN |

- **Connect** (`pkg/controlplane/providers/grpc.transportServer.Register`):
  `Acquire`/`Release` bracket the RPC from just after the registration-token
  tenant-binding check to the return. A saturated tenant gets
  `codes.ResourceExhausted`; other tenants are unaffected.
- **Heartbeat** (`transportServer.ControlChannel`, the `Heartbeat` case):
  `Acquire`/`Release` bracket only that one heartbeat's dispatch — never
  deferred to stream teardown. A saturated tenant has that heartbeat silently
  dropped (logged, stream stays open); the slot is free again before the next
  message on the loop.
- **DNA sync / bulk transfer** (`features/controller/transport.DNAHandler` /
  `BulkHandler`): unchanged by #3759 — `Acquire` on the first chunk, `Release`
  deferred for the RPC's duration. This is the pre-existing mechanism the connect
  and heartbeat paths above compose with, by reusing the same type, the same
  limit and the same acquire/release discipline.

Because `pkg/controlplane` is a central provider and must never import a
`features/` package (Central Provider System, CLAUDE.md), the gRPC provider
declares its own narrow `TenantAdmission` interface (`Acquire`/`Release`) rather
than importing `TenantQueue` directly; `*TenantQueue` satisfies it structurally
with no changes. `grpc.WithTenantAdmission(queue)` injects the gate — nil (the
default) disables admission control entirely, matching pre-#3759 behavior.

**Why two instances and not one.** A shared queue makes the bucket key an
authorization-relevant input: whoever can name a bucket can pin all 32 of that
bucket's slots. The DNA handler takes its key from the first chunk's
`tenant_id`, which is unverified wire data, and holds the slot for the life of
the RPC. Were connect and heartbeat to share that instance, a steward with a
valid certificate — CLAUDE.md's threat model assumes stewards run on hosts that
may be compromised — could open 32 concurrent `SyncDNA` streams naming a
**victim** tenant, trickle chunks to hold the slots, and thereby have the
victim's `Register` calls rejected and its heartbeats dropped fleet-wide, making
the victim's whole fleet look stale. The same sharing would also let unbounded,
unvalidated tenant strings into a `sync.Map` whose entries are never evicted.
Keeping the wire-keyed paths on their own instance bounds that flood to the DNA
and bulk paths, exactly as it was before connect and heartbeat were gated. The
split is by key trust level, not by path count: a further path may join
`connectHeartbeat` only once its key is derived server-side the same way.

**The connect/heartbeat bucket key is always server-verified, never the wire's
`tenant_id`.** `creds.tenant_id` and `heartbeat.tenant_id` are never inputs to
it. `Provider.admissionBucket` resolves the key in this order:

1. the tenant the caller has proven server-side — the tenant the registration
   token is bound to, from the `RegistrationTokenStore` lookup (connect only,
   which is why the binding check runs *before* `Acquire`);
2. the tenant the controller's own fleet record reports for the mTLS-verified
   certificate CN, via `StewardTenantResolver`
   (`grpc.NewStewardStoreTenantResolver` over `business.StewardStore`, wired in
   `server.New`). The ControlChannel resolves this **once at connect** and
   reuses it for every heartbeat on the stream, so the per-heartbeat path does no
   store lookups;
3. otherwise the mTLS-verified CN itself, in the reserved `steward-cn:`
   namespace — a still-bounded key (one per certificate this controller's CA
   issued) used when the steward has no fleet record yet or the resolver is
   unavailable. Admission is a fairness control, not an authorization decision,
   so a resolver outage degrades to per-steward buckets rather than refusing
   traffic.

A candidate key is additionally rejected by `validAdmissionTenantID` unless it is
1–128 bytes of `[A-Za-z0-9._/-]`; a rejected value falls back to the `steward-cn:`
bucket. `TenantQueue` entries are created lazily and never evicted, so its
documented bound ("number of active tenants") holds only while the key space is
server-controlled and bounded — that is what this validation, the server-verified
sourcing, and the instance split preserve for the connect/heartbeat gate.

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
| `registration.enrollment_link_ttl` | 72 hours | Validity window for a single-use passkey enrollment magic link (Issue #2966) |

### IP-Trust Dark-Window Expiry (Issue #1697)

A trusted IP range is automatically revoked after 30 consecutive days with no registrations and no healthy stewards from that range (the **dark window**). The sweep is performed hourly by `IPTrustExpiryJob` (`features/controller/registration/ip_trust_expiry.go`). In a multi-node cluster, only the node holding the `controller-ip-trust-expiry` lease runs a given sweep cycle — see [Background-Loop Singleton Scheduling](#background-loop-singleton-scheduling-issue-3762-adr-031-decision-4).

**Exemption:** Pre-seeded entries (`PreSeeded: true`) are never auto-revoked. Operator-owned ranges added via `cfg registration ip-trust add --pre-seeded` can only be revoked explicitly with `cfg registration ip-trust revoke`.

**Activity tracking:** `RecordHealthySteward` (called on every healthy steward heartbeat) updates the `last_activity` timestamp on the matching CIDR entry. A registration attempt from an already-known IP also counts as activity. An entry whose `last_activity` is older than the dark window is revoked on the next sweep.

**Idempotency:** Revoking an already-revoked entry is a no-op.

### Pending-Registration Expiry (Issue #1697)

Pending registration entries that have not been acted on within 5 days are automatically marked `expired` by `PendingExpiryJob` (`features/controller/registration/pending_expiry.go`). The sweep runs hourly and delegates to `PendingRegistrationStore.ExpireStale`. In a multi-node cluster, only the node holding the `controller-pending-registration-expiry` lease runs a given sweep cycle — see [Background-Loop Singleton Scheduling](#background-loop-singleton-scheduling-issue-3762-adr-031-decision-4). The manual-review workflow's own pending-expiry sweep (`ManualReviewApprovalHook`) is a separate loop with its own lease; see that section.

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

#### Cluster Command Delivery — Routing Table + Internal RPC + Outbox (ADR-031 Decision 3, Issue #3764)

A cluster deployment is any-node: the controller node that decides to dispatch a
command to a steward is not necessarily the node holding that steward's live
control-plane connection. Two primitives compose to make dispatch safe regardless
of which node that is:

- **Shared steward-routing table** (`pkg/storage/interfaces/business.RoutingStore`,
  `business.RoutingStaleAfter` = 90s). Every node records, on each steward connect,
  which node currently holds that steward's connection
  (`RecordConnection(ctx, stewardID, nodeID)`), refreshed by the same connect event
  that populates the node-local registry — there is no polling loop. A record older
  than the staleness window is not trusted and is treated as absent.
- **Internal controller-to-controller delivery RPC**
  (`pkg/controlplane/internaldelivery`, `cfgms.clusterdelivery.DeliveryService`) —
  the one inter-node RPC this deployment shape has. mTLS-secured on a
  dedicated internal listener (`InternalDeliveryListenAddr`), sharing the same
  mTLS trust material as the internal admin listener but its own port —
  gRPC needs to own its listener's connections directly, so it cannot share
  the internal HTTP listener. Node A calls `DeliverCommand` on node B to ask B to
  deliver locally; B returns a normal `DeliverCommandResponse` with
  `not_connected = true` if the steward is not connected there at that instant —
  never a gRPC error — since "not here right now" is an expected outcome the
  caller falls back on, not a failure.

`pkg/controlplane/internaldelivery.ClusterAwareSender` wraps the node-local
`ControlPlaneProvider` (the grpc/memory `SendCommand`/`FanOutCommand`
implementations) with this composition: try local delivery first; on a
"not connected here" result (`controlplane/interfaces.ErrStewardNotConnected`),
look up the routing table, and if a peer node claims the steward, forward via the
internal delivery RPC. Any miss along that chain — no routing entry, the routing
table naming this node itself, an unreachable peer, or the peer's own
`not_connected` response — surfaces the *original* local error to the caller,
unchanged. The
dispatcher (`features/controller/dispatcher`) and command publisher
(`features/controller/commands.Publisher`) are both constructed against this
wrapped sender in cluster mode, so every existing dispatch call site becomes
cluster-safe without a call-site change.

This RPC is a fast path, not a substitute for the durable outbox (Issue #3757,
ADR-031 Decision 2): the outbox row is the guarantee underneath it. A command
that fails every fast-path attempt (no routing entry, peer unreachable, peer
itself lost the connection since its last routing-table refresh) stays `pending`
in `CommandStore` and is drained the moment the steward next connects to any
node — `features/controller/service.PendingDeliveryDrainHook`, wired as an
on-connect hook, calls `CommandStore.ListPendingDeliveries` keyed by the
mTLS-authenticated connecting steward's own identity (never a caller-supplied
ID) and republishes each pending row through the normal publish path.

**Retired by this mechanism:** the `GetAllStewardsCluster`/`GetAllStewards` split
(`features/controller/service.ControllerService`) — the former had to stay
node-local because dispatching to a steward it didn't know about locally simply
failed, while the fleet-wide method was explicitly documented "NOT for
dispatch". `ControllerService.ListFleetStewards` is now the single fleet source
for every consumer, including dispatch: it reads durable storage directly on
every call (no polling cache, no populate-lag window) and dispatch safety no
longer depends on which source produced the steward ID at all — it is a property
of `ClusterAwareSender`, not of the listing method.

#### Outbound Command Contract — Fencing Term (#3390, ADR-029 Decision 5)

The `Command` proto message carries a `term` field (field 8, `uint64`). Commands
published through `commands.Publisher` — `PublishCommand`,
`PublishCommandWithCallback`, and `PublishCommandWithSigner`
(`features/controller/commands/publisher.go`) — are stamped at publish time with the
current fencing term, read from the `TermSource` wired at construction
(`*ha.Manager`, whose `GetTerm()` is lease-backed — the shared database lease,
ADR-031 Decision 5 — rather than a Raft term). This is
the **controller-side half** of the command fencing scheme defined in ADR-029:

- **Wire-compatible additive field.** A steward that does not yet understand field
  8 silently ignores it — unknown proto3 fields are preserved and forwarded, not
  rejected. Older stewards continue to operate unchanged.
- **Zero means not stamped, not "no fencing".** A `term` of zero means the command
  was published either by a controller predating fencing, or by one of the emitters
  listed under "Unstamped command paths" below. The steward-side enforcement —
  rejecting commands whose term is lower than the highest seen — is added in story
  #3436. Until that story ships, the field is informational only.
- **The term is not covered by the command signature.** `CommandSigningBytes`
  (`pkg/controlplane/types/messages.go`) deliberately omits `Term` from
  `commandSigningPayload`, so a `SignedCommand` carries an authenticated body with a
  transport-trusted (mTLS-authenticated, not signature-authenticated) term. Including
  it would break signature verification on every steward predating #3436 the moment a
  controller stamped a non-zero term. The consequence #3436/#3437 must design around:
  anything able to modify a command between signer and steward — a future Outpost
  proxy cache, an mTLS-terminating hop, a non-leader controller node — can rewrite
  the term without invalidating the signature. It can raise the term to defeat the
  fence, or set it to `MaxUint64` to poison the steward's high-water mark and wedge
  its command channel — permanently, once #3437 persists that mark across restarts.
  Making the term tamper-evident requires a negotiated signing-payload version, which
  does not exist yet.
- **Fence coverage is per-steward-determinable.** An operator can determine which
  stewards are capable of enforcing the fence without any new mechanism. The
  existing `GET /api/v1/stewards` endpoint (`handleListStewards`,
  `features/controller/api/handlers_stewards.go`) returns a `StewardInfo` per
  connected steward that includes the `version` field sourced from each steward's
  `steward.version` DNA attribute. A steward running the release that includes
  story #3436's enforcement is **capable** of enforcing the fence; full durability
  across restarts requires story #3437 as well. No capability flag or new field is
  introduced — binary version is the sufficient discriminant.

**Unstamped command paths (known gap for #3436).** Three controller-side emitters
build a `SignedCommand` directly instead of going through `commands.Publisher`, and
therefore send `term = 0`:

| Emitter | Command type | Location |
|---------|--------------|----------|
| Script dispatcher | `execute_script` | `features/controller/dispatcher/dispatcher.go:567` |
| Relay handler | `relay_response` | `features/controller/api/relay_handler.go:210` |
| HA manager, on leadership acquisition | `reconnect` | `pkg/ha/manager.go:556` |

These are unfenced today, and `execute_script` is the highest-privilege command in
the system: a deposed-but-still-running leader's dispatcher would land scripts on
endpoints that #3436's fence could not reject on term grounds. The inverse also
matters — under #3436's fail-closed downgrade rule (a steward that has observed a
non-zero term rejects a subsequent unstamped command), these three paths would start
being *rejected* by fence-enforcing stewards, breaking ad-hoc script execution and
relay responses. #3436 must resolve both directions: either these emitters take a
`TermSource` and stamp the term, or the enforcement rule exempts them explicitly.
Stamping them is out of scope for #3390, which is confined to the schema, the
publisher, and its wiring.

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
5. On approval (`approve`): controller generates the steward ID and signs the steward-submitted CSR into an mTLS client certificate scoped to the steward's tenant/group identity (HTTP 200 with full cert bundle). The steward generated its own keypair locally before registering and submitted only the public half as a CSR (`csr_pem`) — the controller never generates or sees a private key for this credential (Issue #3780). The controller also persists this tenant assignment to the durable `device_tenant` mapping — see [Durable Device-Tenant Mapping](#durable-device-tenant-mapping-issue-3324).
   On quarantine (`quarantine`): controller returns HTTP 202 with a `pending_id` and no certificates. The pending entry — including the submitted `csr_pem`, signed later at claim time — is written to the durable `PendingRegistrationStore` (SQLite by default, PostgreSQL at production scale). The steward polls `GET /api/v1/registration/status/{pending_id}` with its registration token as a Bearer credential until the operator acts. Operators use `cfg registration approve <pending-id>` or `cfg registration deny <pending-id>`.
   On rejection (`reject`): HTTP 403 is returned; registration is denied.
6. **Sign-on-claim (quarantine path):** When the operator approves an entry and the steward polls again, the controller signs the steward-submitted CSR in memory for that single response, marks the entry as `claimed`, and returns the full cert bundle in HTTP 200. A subsequent poll on an already-claimed entry returns HTTP 410 Gone — the cert is never re-issued. The controller never generates or sees a private key for this credential.
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

**X-Forwarded-For spoofing protection:** The controller derives the steward's source IP for the IP-trust decision and anonymous-download budgets from the TCP peer address (`r.RemoteAddr`). It honors `X-Forwarded-For` **only** when the TCP peer falls within a `trusted_proxies` CIDR range, then walks all header fields and comma-separated hops from right to left to select the first untrusted address. A malformed chain falls back to the TCP peer. With `trusted_proxies` empty (the default), `X-Forwarded-For` is always ignored. Configure every trusted hop and require the edge to append its observed upstream address or replace client-supplied headers; forwarding an unmodified client header defeats any origin-address scheme.

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

**Tenant scoping of bulk approval.** `approve-all` and `approve-by-cidr` — and the preview — resolve their target set through `ListPending(ctx, callerTenantID)`, so a caller whose principal carries a tenant (API key or non-root account) can only approve pending entries belonging to that tenant. A caller with no tenant on its principal (mTLS admin bundle, root-scoped account) retains fleet-wide reach. Entries outside the caller's scope are never listed, previewed, or mutated.

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

### mTLS Admin Certificate Principal Resolution

When an admin-marked mTLS certificate passes chain verification and revocation check, the controller resolves the authenticating principal from the certificate's bound account (if one exists) rather than hardcoding root scope unconditionally.

**Account-bound path:** If the certificate's serial appears in a `CertBindings` entry on a non-disabled account, the principal derives its `ID`, `TenantID`, `GlobalScope`, and `Permissions` from that account. `Principal.ID` is always the account's ID — never the certificate CommonName — so the audit trail and RBAC subject identity are the same value on every surface. `RootScoped` is read exclusively from the certificate's explicit extension (`cert.HasRootScopeMarker`), never derived from the account (ADR-025 A2.1/A2.2). A certificate carrying the root-scope marker but bound to a tenant-scoped account produces `RootScoped == true` with a non-empty `TenantID`; the marker is therefore inert, because `authorizeTenantAccess` only consults it when `TenantID == ""`.

**Fail-closed paths:** A certificate bound to a disabled account is rejected (HTTP 401) without falling through to any fallback. A store error during account lookup is also rejected — an outage must not become a privilege escalation.

**Bootstrap fallback (ADR-025 Amendment 3):** An admin-marked certificate with no bound account is treated as unscoped root indefinitely. This is a deliberate, permanent design decision: closing the fallback once a first account exists would mean a lost or corrupted account store leaves a freshly issued certificate also unbound and therefore rejected, so holding the CA would no longer suffice to regain access to the deployment. Every request that takes this path emits the `admin.bootstrap_fallback_used` audit event with `auth_path: "bootstrap-fallback"`. The `accounts_in_cache` field in the event makes the anomalous combination — bootstrap path used while accounts exist — separately detectable in monitoring. Revocation remains authoritative: a revoked certificate is rejected before the account lookup, so a stolen unbound certificate cannot bypass revocation by lacking a binding.

**Bound certificates cannot re-enter the fallback.** Because the fallback is unscoped root, any transition from *bound* to *unbound* while the certificate is still valid would widen that certificate's scope — deleting a tenant-scoped administrator would promote their certificate to root over every tenant. Three API paths can reach that transition, and each is closed rather than cascaded. This list is the complete set: every write path that rebuilds an account record must appear here, because `persistAccount` rebuilds the account metadata from the record it is handed and writes `cert_bindings` only when the slice is non-empty, so a write path that drops the field silently unbinds every certificate on the account.

- `POST /api/v1/accounts/{username}/certs/revoke/{serial}` revokes the certificate through `pkg/cert` *before* dropping the binding, and refuses the request with `503 CERT_MANAGER_UNAVAILABLE` when no certificate manager is configured — an unbind that cannot revoke is refused, not completed as a partial success.
- `DELETE /api/v1/accounts/{username}` refuses with `409 CERT_BINDINGS_PRESENT` while the account still has bindings. Deprovisioning is revoke-then-delete; the certificate is invalid before the account record that scoped it disappears.
- `POST /api/v1/accounts` on an existing username (reset/upsert) **carries the bindings forward** onto the rebuilt record. It is not refused the way a delete is: a reset is the takeover-containment operation — re-provision to zero authenticators, terminate live sessions — so refusing it while bindings exist would block containment on precisely the most privileged accounts. A reset keeps the account record and its ID, so the record that scopes each binding survives the write; carrying the slice forward closes the transition without weakening containment. A reset that also moves the account's scope moves its bindings with it, and the destination scope is bounded by the caller's own subtree (`isWithinTenantScope`), so no reset can widen a certificate beyond the authority of the admin issuing it.

`PUT /api/v1/accounts/{username}` and the WebAuthn, passkey-login and elevation write paths copy the whole account record before persisting, so they carry bindings forward structurally and are not separate transitions.

**The identity pin.** An operator authenticating with a certificate bound to `account-foo` is identified as `account-foo` on every request — direct mTLS and Bearer-token CLI sessions alike. `handleSessionCreate` mints the CLI session under the cert principal, so the session's `PrincipalID` is that same account ID, and the Bearer path re-reads the account record by it. The certificate's CommonName is never the acting identity on any surface, and no caller-supplied string can be substituted for the account ID.

**What authorizes a request is the account record, not a role assignment.** `requirePermission` → `hasPermission` consults `Principal.Permissions` only, and `Permissions` is populated exclusively from the authenticated account's `Permissions` field (all three branches: mTLS cert, Bearer session, web cookie). Root-scope accounts carry `ImplicitAdmin` instead and hold every permission. **RBAC subject-role assignments (`POST /api/v1/rbac/subjects/{id}/roles`) are stored and readable, but no request path resolves them into effective permissions** — every `rbacService` call site in `features/controller/api` is CRUD or read, and `handleAssignSubjectRole` writes to the RBAC store without touching the account record.

Two operational consequences follow, and both cut against the operator's expectation:

- **Granting a role does not grant API or web access.** The permission must be present on the account record (`account.Permissions`) for any surface to honour it.
- **Revoking a role assignment does not revoke access.** This is the direction that matters for containment: a grant already written to `account.Permissions` keeps authorizing after the role assignment is removed. Removing a permission from the account record — or disabling the account, which is rejected at authentication on every surface — is what actually revokes it.

Unifying the two — resolving subject-role assignments into effective permissions on the request path, so the RBAC surface becomes the authoritative grant source for both web and CLI/API — is production work not yet done. *Deferred: tracked in #3178 — wire subject-role → effective-permission resolution into the API authorization path.* Until it lands, treat the RBAC subject-role surface as role modelling, and `account.Permissions` as the enforced grant set.

When a role *is* assigned, the subject ID must be the account ID returned by `GET /api/v1/accounts/{username}` — never the certificate's CN field. `handleAssignSubjectRole` validates no foreign key against the account type, so a CN string is accepted as a subject ID and records a grant against an identity the auth chain never produces.

See `features/controller/api/middleware.go` (`extractAdminPrincipal`, `authenticationMiddleware`, `requirePermission`, `hasPermission`, `emitBootstrapFallbackAudit`) for the implementation. `features/controller/api/account_rbac_integration_test.go` asserts both properties above end-to-end (Issue #3583): the identity pin, and that a role carrying `config:list` assigned to the account's own subject ID leaves a `config:list`-gated request denied.

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

These signals are **orthogonal**: a future tenant-scoped account type would have `Assurance=AssuranceBasic` but `GlobalScope=false` and would be tenant-confined despite its assurance level. A strongly-authenticated but tenant-scoped service account would have `Assurance=AssuranceStrong` but `GlobalScope=false` — it could perform strongly-authenticated operations but only within its own tenant. Do not collapse these two signals back into one; see ADR-021 Context §"It is load-bearing on an unwritten assumption" for the failure mode this separation forecloses.

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
Cell 1                    Cell 2                    Cell 3
─────────────             ─────────────             ─────────────
msp-alpha (root)          msp-beta (root)           msp-gamma (root)
 ├── client-1              ├── client-1              └── ...
 │   └── ...                │   └── ...
 └── client-2               └── client-2
     └── ...                    └── ...
```

Each cell is a complete, independent CFGMS deployment (its own controller cluster, database, blob store, and vault, per ADR-032) with exactly one root tenant; MSPs are children of that root. Cells share no runtime state — there is no shared parent tenant, no cross-cell inheritance, and no cross-cell visibility. This topology enables cfg.is to host hundreds of MSPs across cells with per-MSP isolation, resource scheduling, and billing. Cross-cell concerns (a tenant→cell directory, admin routing, a cross-cell operations view) are deferred until a second cell is justified.

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
- **Cell isolation** — cells share no runtime state; each cell has exactly one root tenant

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

Multiple controller instances form a cluster with no leader-election protocol
of its own. Cluster membership and leadership authority are both derived from
the **shared PostgreSQL backend** every node already reads and writes — there
is no replicated log, no peer-to-peer consensus transport, and no election
timer (Issue #3763, ADR-031 Decision 5, superseding the Raft-based design of
ADR-028):

- **Cluster membership** — every `ClusterMode` node periodically registers its
  own ID and advertised address in the shared controller-node registry
  (`pkg/storage/interfaces/business.NodeRegistryStore`,
  `business.NodeRegistryStaleAfter` = 90s). `GetClusterNodes()` reads the
  registry directly; a node that stops registering (crash, graceful shutdown)
  drops out once its record goes stale — there is no separate deregistration
  call and no persisted membership log to recover on restart. A restarting
  node simply resumes registering itself on the next cycle.
- **Leadership** — one cluster-wide lease (`pkg/lease`, row name
  `controller-cluster-leadership`) is the sole authority. Every node contends
  for it independently via `TryAcquire`; `HasLeadership()` reads a
  monotonic-clock-bounded local cache of the last successful acquire/renew
  (`pkg/lease.SafetyMargin`, derived from `cfg.Cluster.ElectionTimeout` via
  the same 0.8× ratio ADR-029 Decision 1 established for the Raft-era lease).
  A node that can no longer renew — because it lost network access to the
  database, or crashed — has its cached authority lapse on its own clock,
  with no live database read required to detect the loss.
- **State replication** — there is nothing to replicate: every node reads and
  writes the shared PostgreSQL backend directly for cfg data, registration
  records, audit, RBAC, the leadership lease, and cluster membership alike.
- **Automatic failover** — if the leader goes down (or loses database
  reachability), its cached authority lapses within one `SafetyMargin`
  window and any contending node may then acquire the now-expired lease row.
  There is no explicit election: whichever node's next `TryAcquire` lands
  first wins.
- **Split-brain prevention** — two nodes cannot simultaneously hold the same
  lease row for longer than the derived `SafetyMargin` bound: the lease row
  itself is exclusive at the database layer (`AcquireOrRenew`'s
  compare-and-set), and each node's belief that it still holds authority is
  bounded by its own monotonic clock, not by a live check. This is the same
  property ADR-029's Raft-era lease existed to provide; ADR-031 Decision 5
  keeps the property while removing the Raft layer it used to sit on top of.

Stewards connect to any cluster node. If their node goes down, they reconnect to another.

Cross-node steward dispatch — reaching a steward whose control-plane
connection is held by a *different* node than the one that decided to send it
a command — is a separate mechanism from either of the above: see "Cluster
Command Delivery — Routing Table + Internal RPC + Outbox" below.

#### Write Admission (ADR-031 Decision 1)

Every cluster node accepts every read and write; there is no per-request
leadership gate. Before this decision, ~50 inline `HasLeadership()` checks
enforced a leader-only write convention across `features/controller/api`
(inconsistently — a parallel `ungatedHandlerBaseline` ratchet tracked dozens of
handlers that were never gated at all). The shared PostgreSQL database (ADR-007)
was already the only durable store these writes reached, so the gate blocked no
actual race there — it only enforced routing. ADR-031 removes the gates and makes
multi-writer safety explicit at the database layer instead: uniqueness
constraints and compare-and-set on version columns per write path (see "Write
Admission for Mutating Admin API Actions" under the REST API section below for
the inventory).

`HasLeadership()` (lease-backed, ADR-029 Decision 4) still exists and still
governs the one thing that remains a true cluster singleton: background
sweep/expiry/scheduler loops, claimed via `pkg/lease.SingletonJob` (see
Background-Loop Singleton Scheduling below) rather than a request-path gate. It
also remains available for status/diagnostic reporting (`GET /api/v1/ha/status`
et al.). Batch-job command dispatch continues to use lease-token-derived fencing
(sourced from the database lease's monotonic token rather than `GetTerm()`,
per ADR-031 Decision 3) rather than an HTTP-layer gate.

#### Background-Loop Singleton Scheduling (Issue #3762, ADR-031 Decision 4)

Before this story, every background sweep/expiry/scheduler loop ran on **every**
cluster node unconditionally — a multi-node deployment did each sweep once per
node per cycle rather than once per cluster. `HasLeadership()` gated exactly one
of these, and only incidentally: `resumePendingPushes`, a one-shot startup replay
(`features/controller/server/server.go`), not a periodic loop.

Cluster-singleton loops now claim a `pkg/lease` lease before running each cycle,
using the reusable `pkg/lease.SingletonJob` wrapper
(`RunIfLeader(ctx, fn)`) so no call site hand-rolls its own acquire/renew/release
sequence. `ha.Manager.NewBackgroundLoopLease(name, logger)` constructs one,
backed by a lease population distinct from the cluster-leadership lease
(`backgroundLoopLeaseTTL` = 90s, `backgroundLoopRenewInterval` = 20s, independent
of `cfg.Cluster.ElectionTimeout`). It is nil-receiver-safe: a nil `*ha.Manager`
(OSS single-node) and any non-`ClusterMode` deployment yield a `SingletonJob`
that runs every cycle unconditionally — identical to pre-#3762 behavior, so only
genuine multi-node clusters are affected.

**How `RunIfLeader` works:** on each tick, the loop calls
`leaseJob.RunIfLeader(ctx, cycleFn)`. It attempts `TryAcquire` for this cycle;
if another node holds the lease, `cycleFn` is skipped entirely (`RunIfLeader`
returns `false`). If acquired, a background goroutine renews the lease every
`RenewInterval` for as long as `cycleFn` runs — so a cycle slower than the lease
TTL does not lose the lease mid-execution and trigger a duplicate run elsewhere.
The lease is not explicitly released when the cycle finishes; it is left to
expire at TTL, which is simpler than a release round-trip and equally correct,
since no other node can acquire it before then regardless.

**Converted loops and their lease names:**

| Loop | Lease name | Category |
|------|-----------|----------|
| IP-trust dark-window expiry (`IPTrustExpiryJob`) | `controller-ip-trust-expiry` | True singleton — one global sweep across all tenants |
| Pending-registration expiry (`PendingExpiryJob`) | `controller-pending-registration-expiry` | True singleton |
| Manual-review pending expiry (`ManualReviewApprovalHook`) | `controller-manual-review-pending-expiry` | True singleton — a second, independent sweep of the same `PendingRegistrationStore.ExpireStale`, pre-existing and out of scope to merge with the above (this story does not redesign loop business logic) |
| Credential-request / enrolment-token expiry sweep | `controller-credential-request-expiry` | True singleton — one tick covers both the enrolment-token and orphaned-collected-certificate sweeps |
| CLI-login request expiry sweep | `controller-cli-login-request-expiry` | True singleton |
| DNA storage maintenance (`dnaStorage.Manager.runMaintenance`: flush, optimize, retention) | `controller-dna-storage-maintenance` | True singleton — the longest-running cycle of the set (see the renewal-under-load test below) |
| Workflow trigger cron scheduler (`CronScheduler.checkAndExecuteDueTriggers`) | `controller-workflow-trigger-scheduler` | True singleton — a due trigger must fire once per cluster, not once per node |
| Git-sync per-scope polling (`pkg/gitsync.Syncer`) | `controller-gitsync-scope-<tenant_path>/<namespace>` | True singleton, **one lease per scope** — scopes are independent (many may legitimately poll concurrently across a cluster), so this is many small singletons rather than one global sweep or a claimable work queue. Webhook-triggered syncs (`pkg/gitsync/webhook.go`) are **not** gated: a webhook must run on whichever node received the HTTP request, never wherever a different scope's polling lease happens to be held. |

**No loop in the current, live set is queue-shaped** (a table of discrete,
independently claimable work items) in the `SELECT ... FOR UPDATE SKIP LOCKED`
sense. The one candidate that resembles queue-shaped work —
`features/controller/dispatcher.Dispatcher`, which dispatches queued script
executions per device — is excluded: its `ExecutionQueue` is an in-memory,
node-local structure (`features/modules/stdlib/script/execution_queue.go`), not
shared cluster state, so each node correctly dispatches only what was queued to
it directly. Converting it to database work-claiming would require making that
queue durable and shared first, which is a storage-layer change this story does
not make.

Several other loops matching a `time.NewTicker` search were found unwired to any
production binary (RBAC JIT access-manager cleanup, the SIEM engine's four
tickers, directory DNA drift/monitoring, `pkg/configrouting.SyncService`, and
`features/config/git.DefaultGitManager`, superseded by `pkg/gitsync`) — dead
code, not currently running, so they are out of this story's live-loop count and
were left untouched.

**Tests:** `pkg/lease/singleton_test.go` and
`pkg/ha/background_loop_lease_test.go` prove the `SingletonJob`/
`NewBackgroundLoopLease` primitives directly (two-node mutual exclusion, and a
cycle far longer than the lease TTL renewing without a duplicate run). Each
converted loop above carries its own two-node test proving the same property
through its actual production wiring (e.g.
`TestIPTrustExpiryJob_TwoNodes_OnlyOneRunsPerCycle`,
`TestSyncer_PerScopeLease_TwoNodes_OnlyOneRunsPerCycle`); the DNA storage
maintenance loop additionally carries
`TestManager_MaintenanceLease_SlowCycleRenewsAcrossTTL_NoDuplicateRun`, the
renewal-under-load test for the longest-running cycle.

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

### Write Admission for Mutating Admin API Actions (ADR-031 Decision 1)

Every state-mutating handler (POST/PUT/DELETE/PATCH) in `features/controller/api` accepts requests on any cluster node — there is no per-handler `HasLeadership()` gate on the request path. Before ADR-031, epic #3411 had gated roughly fifty of these handlers on `HasLeadership()` (the lease-backed authority primitive, ADR-029 Decision 4) while a parallel `ungatedHandlerBaseline` ratchet tracked dozens more that were never gated at all — the leader-only model was a convention, not a completed invariant. ADR-031 Decision 1 removes the convention rather than finishing it: the shared PostgreSQL database (ADR-007) was already the only durable store these writes reached, from any node, so the gate blocked no actual race there.

#### Multi-writer safety is now explicit per write path

Removing the gate transferred the safety obligation it used to provide implicitly to each write path individually. Reviewed and made safe as part of this decision and its dependencies:

- **Credential and CLI-login lifecycle transitions** (WebAuthn credential revocation, enrolment-token spend-then-lodge, both approved→collected transitions, credential issue-and-rebind, credential-request approval) persist via `SecretStore.CompareAndSwapSecret`, keyed on the version read alongside the record — a concurrent conflicting write observes `409 Conflict` rather than silently losing an update (Issue #3775).
- **Audit-chain sequencing** (ADR-004) — per-tenant sequence numbers and `previous_checksum` linkage are assigned by database-side serialization rather than a single in-process drain goroutine, which N cluster nodes running independently could no longer make safe (Issue #3754).
- **Registration-refresh nonces** (ADR-011) — the single-use nonce lives in a durable, cross-node consumable `NonceStore` rather than an in-process cache, so a challenge and its completion can land on different nodes safely (Issue #3755).

#### Config push and background loops

`POST /api/v1/config/push` (`handleConfigPush`), the save=deploy fanout callback (`RegisterFanoutCallback` in `server.go`), and the startup replay of interrupted pushes (`resumePendingPushes`) are, likewise, no longer leadership-gated. Any node now accepts a push, resolves the selector, queries the fleet, writes desired state to the entity graph, and fans out to stewards via `commandPublisher` directly. Delivery durability — one outbox row per targeted steward, committed atomically with the push record so a controller crash mid-fan-out cannot silently drop a steward — is ADR-031 Decision 2, a separate concern from this admission change.

`HasLeadership()` remains the correct primitive for the one thing that is still a genuine cluster singleton: background sweep/expiry/scheduler loops, which claim a `pkg/lease.SingletonJob` lease per cycle rather than gating a request (see Background-Loop Singleton Scheduling above). It also remains available for status/diagnostic reporting. `IsLeader()`/`IsRaftLeader()` — the raw Raft replication-protocol primitives the architecture rule (Story #3391) used to police outside `pkg/ha` — were deleted along with Raft itself (Issue #3763); `TestNoRawLeaderPrimitiveOutsidePkgHA` (`pkg/ha/architecture_test.go`) remains in place as a name-based guard against either being reintroduced.

#### Retired: the baseline ratchet

`features/controller/api/architecture_test.go`'s `TestNoUngatedMutatingHandler` and its `ungatedHandlerBaseline` map — the mechanism that used to enforce the gate and track handlers still owing one — are deleted along with the gates themselves (Issue #3761). Per ADR-031 Decision 1, epic #3411's remaining scope (gating the handlers the baseline still listed) inverts rather than completing: there is no gate left to add those handlers to. `check-architecture` no longer runs this test; `TestNoRawLeaderPrimitiveOutsidePkgHA` (Story #3391, `pkg/ha/architecture_test.go`) is unaffected and continues to run as part of the same Makefile target.

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

## Observe-Resolution: DNA-driven Module Activation

`ResolveObserveModules` (`features/controller/modules/resolution/observe.go`) computes the set of modules a steward should observe based on its baseline DNA attributes and the registered module manifests.

### How it works

Each module manifest may carry an `observe_when` list of predicates. `ResolveObserveModules` takes a DNA attribute map and a slice of manifests, and returns the names of modules that match:

- A manifest with no `observe_when` (nil or empty) is **never** included. Absence means "never auto-pull for DNA" (ADR-024 §2).
- Predicates within a single manifest use **OR semantics**: any one matching predicate activates that module.
- `equals` requires an exact string match of the DNA attribute value.
- `contains` requires `strings.Contains` on the DNA attribute value.

### Relation to `ResolveCfgRequiredModules`

These are two distinct resolution functions serving different triggers:

| Function | File | Trigger | Input | Purpose |
|---|---|---|---|---|
| `ResolveCfgRequiredModules` | `resolution.go` | Cfg deployment | `required_modules:` list from cfg | Verify/fetch/approve modules before a cfg can deploy |
| `ResolveObserveModules` | `observe.go` | Baseline DNA available | DNA attribute map + manifests | Determine which modules to auto-pull for read-only DNA observation |

Do not conflate the two. `required_modules:` is a deployment-time cfg contract; `observe_when` is a baseline-fact-driven auto-pull signal. They use separate code paths intentionally.

### Purity guarantee

`ResolveObserveModules` is a pure function — no I/O, no RPC, no side effects. Wiring the result into a steward-facing command is done by the server's `handleObserveSweepRequest` handler (see below).

### Tier-2 observe RPC (Issue #3104, ADR-024 Amendment 1)

The observe-resolution path is triggered by the steward's Tier-2 convergence cycle:

1. **Steward → Controller:** On every Nth convergence tick (N = the steward's `steward.observe_sweep_n` config key, default 10), the steward publishes `EventObserveSweepRequest` carrying its current baseline DNA attribute map in `Details["baseline_dna"]`.
2. **Controller:** `handleObserveSweepRequest` in `features/controller/server/` receives the event, calls `ResolveObserveModules(baselineDNA, manifests)`, and — if any modules matched — sends `CommandObserveModules` back to the originating steward. The command's `params["modules"]` field carries a JSON array of `{name, kind}` specs.
3. **Steward:** `handleObserveModules` receives the command, loads each module via the signed/trust-verified pull path, runs `Get()` read-only, and merges the resulting fragments into the existing DNA fragment set via `setCurrentDNAFragments`.

If no modules match (empty resolution result), no command is sent — the steward's DNA update is skipped for that Tier-2 cycle. If the manifest provider is unavailable, the handler returns without sending a command (non-fatal).
