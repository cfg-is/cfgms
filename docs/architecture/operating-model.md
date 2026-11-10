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
- **Mode**: whether to enforce desired state (`apply`) or only monitor and report drift (`monitor`) — the `drift_mode` cfg field (`stewardtypes.DriftMode`, consumed by the steward execution engine)

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

Any source that writes a cfg to the controller's ConfigStore (CLI, web UI, GitOps webhook, workflow output) triggers automatic distribution to matched stewards. There is no separate "push" action — save IS deploy. The trigger is the fanout callback invoked from `ConfigurationServiceV2.SetConfiguration` after the ConfigStore write; `POST /api/v1/config/push` remains available for an explicit re-push.

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
- **Write triggers fanout.** A successful ConfigStore write inside `ConfigurationServiceV2.SetConfiguration` invokes the registered fanout callback (`RegisterFanoutCallback`) synchronously. Burst edits each trigger fanout, and idempotency (below) absorbs the repeats.
- **Durable queue.** Fanout uses the controller's durable job queue — the same primitive used for retries, deferred operations, and HA failover replay.
- **Idempotency carries load.** A steward already at the target DNA hash treats a sync command as a no-op.
- **Resource-bounded fanout.** Fanout is bounded by controller capacity (CPU, outbound bandwidth) to prevent thundering-herd saturation.

Stewards' own heartbeat-driven loops also notice config divergence via DNA hash mismatch — the fanout command is an optimization on top of that steady-state loop, not a dependency for correctness.

## Safety Primitives

Safety against bad configs comes from operator-controllable primitives:

- **Targeting precision** — a cfg explicitly lists which stewards / groups / tenant paths / DNA-attributes it applies to. A bad change is bounded by what it was authored to target.
- **Deployment rings (convention)** — steward tags (`ring=canary`, `ring=prod-early`, `ring=prod-broad`) let operators author phased rollouts as separate configs or staged target lists.
- **Deployment visibility** — `cfg config deployments <id>` shows applied / pending / failed / halted counts and per-steward status.
- **Rollback** — `cfg config rollback <steward-id>` restores a previous cfg version via `features/controller/api/rollback_handler.go`.

## Component Roles

### Steward

The steward is a daemon that maintains a device in the state described by its cfg.

**Core behaviors:**

1. **Apply** — On startup and when the cfg changes, evaluate each resource's current state against desired state. In `apply` mode, converge the device (Get → Compare → Set → Verify). In `monitor` mode, detect and report drift without making changes
2. **Maintain** — Re-check compliance on the schedule defined in the cfg. In `apply` mode, correct any drift. In `monitor` mode, report drift. Respond to module-defined event hooks (e.g., file change triggers re-check of that resource)
3. **Know itself** — Collect DNA (hardware, software, network, security attributes). Monitor its own health and performance
4. **Report** — Always log locally. When connected to a controller, also report events, status, and DNA upstream. When disconnected, queue reports locally and resync on reconnect

**Apply mode vs Monitor mode (configurable per steward via `drift_mode`):**

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

**Operator signature is mandatory for inline ad-hoc commands (Issue #3694).** Every inline command (`cfg steward run-command`, `cfg steward exec`) is signed by the operator before submission, and both the controller and the receiving steward verify that signature — neither side accepts an unsigned inline command, regardless of `require_signed_adhoc` configuration. The signature covers a canonical envelope (`pkg/operatorpayload`), not the command content alone: content, shell, the resolved list of authorized target steward IDs, a single-use nonce, and a bounded expiry are all bound into the signed bytes. This closes two gaps the content-only signature left open — a legitimately-signed command re-addressed to a different target set in transit, and replay of a captured signature — without requiring the steward to parse fleet selectors: it only checks whether its own ID is a member of the signed target list. The steward enforces expiry and nonce-replay independently of the outer `SignedCommand`'s own replay window, so a captured operator-signed envelope re-wrapped in a fresh outer command is still rejected.

The client signs with the operator's controller-issued admin-bundle credential, the same mTLS key used for API auth. The controller does not hold that key. `OperatorCredentialVerifier` in `features/steward/commands/execute_script.go` is the verification seam.

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

- **Perennial registration tokens** — manual onboarding, small fleets, time-bounded provisioning. Generated on the controller, handed to the steward as a string. Never consumed at registration: one token enrolls many devices and is spent only by rotation or revocation, with expiry enforcing time bounds. The controller records a per-device claim at the issuance boundary, so a device cannot be issued two certificates on one token.
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

**Revoked admin certs are exported as a signed manifest.** `pkg/cert.Manager.ListRevoked()` is controller-local: on its own, no steward can check operator-cert revocation independently of a live, trusted controller assertion. `GET /api/v1/certificates/revocation-manifest` exports that state as `{Kind: "operator-cert-revocation", Version, RevokedSerials}`, serialized with sorted serials for byte-stable signing, then signed with the controller's current `PurposeSigning` certificate via `signature.NewSigner` — the same signer construction config/DNA signing uses (`features/controller/service/signing_rotation.go`). The `Kind` field is what keeps a revocation manifest from ever being mistaken for a signed config/DNA payload sharing that same signing cert. `Version` is the count of revoked serials, which only grows since `Revoke` has no inverse. Publishing only: steward-side fetch, verification, and enforcement against it are a later story.

**The manifest is fleet-wide, so the endpoint is unscoped-callers-only.** It is gated at the read-only `certificate:list` permission (no elevated assurance — this is a read of state that `certificate:revoke` already produced), and the handler additionally requires an unscoped principal: a caller carrying a tenant scope receives `403`. Revocation status is *not* public — a tenant-scoped operator cannot otherwise enumerate other tenants' serials, and the revocation store holds steward-cert serials as well as operator-cert ones (`certificates/{serial}/revoke` writes into it). Filtering the manifest per tenant is not the alternative: a steward verifying the signature must see every revoked serial, and `Version` is the fleet-wide revoked count, so a subset would be a validly signed manifest that silently omits revocations. Tenant-scoped visibility of certificate data stays on `GET /api/v1/certificates` and `GET /api/v1/certificates/{serial}`, which filter by the caller's tenant subtree.

**Two residual-risk profiles for payload signing.** CFGMS has two independent paths for an
operator to produce a signature the steward will trust: the CSR-issued mTLS signing credential
(`POST /api/v1/signing-credential/request`, Issue #3693/#3692) and the WebAuthn operator-payload
signature (`POST /api/v1/operator-payload/sign/begin|finish`, Issue #3695, ADR-021 Amendment 2
cross-reference). Both require `AssuranceStrong`, but the credential each rests on has a
different failure mode if the controller is compromised. The mTLS path issues a certificate over
a CSR the operator generates — the private key never crosses the wire — but the *resulting
certificate* is an ordinary bearer credential the controller subsequently sees and could, if
compromised, mint again for an attacker without the legitimate operator noticing: the deeper risk
is a controller that silently steals or extends trust in a credential that already exists and is
expected to keep working unattended for its validity period. The WebAuthn path has no credential
of that shape at all — a WebAuthn private key is generated and held **only** inside the
authenticator hardware and never exists server-side, at rest or in transit, so "the controller
durably retains an extractable private key indefinitely" is not a risk this path can have; a
compromised controller can at most mint a bogus WebAuthn *registration* for an attacker-controlled
public key (bounded by `webauthn:register`'s existing `AssuranceStrong` gate, and visible to the
legitimate operator as an unrecognized credential the next time they list their passkeys), which
is a shallower failure than silently retaining a credential capable of unattended reuse.

**Blast-radius bound and audit trail are the compensating controls for the accepted
UI-trust gap (Issue #3698).** Neither residual-risk profile above defends against a
compromised controller showing an operator one payload while collecting a signature over
another — that gap is an accepted non-goal of the operator-signed-payload epic, not
something either credential path closes. Two server-side controls carry that accepted
risk instead, and both are enforced, not advisory:

- **A per-tenant maximum-target-count**, resolved root-to-leaf via the identical
  override-walk pattern the assurance-policy per-tenant overrides already use
  (`resolveAssuranceRequirement`/`resolveAssuranceRequirementForPath`,
  `features/controller/api/handlers_assurance_policy.go`): a parent tenant's bound is
  the default, and a child tenant can narrow it by setting its own
  (`business.BlastRadiusPolicyStore`, `resolveMaxTargetsForTenant`,
  `features/controller/api/handlers_runs.go`). It is a flat count, deliberately never a
  percentage of fleet size — a percentage grows exactly as the fleet gets more
  dangerous, so 10% of a 40,000-host fleet is still 4,000 hosts — and deliberately not a
  single global number either, since a bound sized for a 20-host tenant is wrong for a
  20,000-host tenant. This is the permanent, deliberately chosen enforced primitive for
  the epic, not a placeholder for a future percentage-based or more elaborate policy
  engine. The bound is checked after target resolution and before dispatch, for both the
  mTLS path (`POST /api/v1/runs/command`) and the WebAuthn path
  (`POST /api/v1/operator-payload/sign/begin`), and a request whose resolved target list
  exceeds it is hard rejected at admission — never a warning the operator can click
  through.
- **Every operator payload dispatch is audited**, accepted or rejected, via
  `audit.NewEventBuilder` (`emitOperatorPayloadDispatchAudit`,
  `features/controller/api/handlers_runs.go`), recording the payload's SHA-256 digest and
  byte length (never its literal text — an operator payload is arbitrary script text and
  routinely carries credentials inline, so storing it verbatim would violate the rule
  against writing secrets to disk; a digest still lets an investigator holding a candidate
  payload prove or disprove that it is the one dispatched), the
  resolved target list using each steward's cfg-declared resource id (never a live
  hostname), the signing credential's identifier (the X.509 certificate serial or the
  WebAuthn credential id), and the caller identity. A rejected-for-exceeding-the-bound
  attempt is itself audited as a bound violation, not silently dropped — an operator
  attempting to exceed the bound is a signal worth keeping in the trail, not a benign
  no-op.

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

## Backend Concurrency

Backend tests cover bounded concurrent-reader/writer behavior, including SQLite
identity visibility and atomic flat-file operations. Those guarantees belong to
the particular store operation and fixture; they do not establish safe overlapping
production controllers sharing a single-node data directory.

The supported [single-controller upgrade](../operations/controller-upgrade.md)
is restart-based under ADR-007. Production multi-controller service uses the
shared-store [cluster contract](decisions/031-controller-cluster-service-model.md)
and explicit routing. Flat-file config storage remains a single-writer deployment
choice. Use the [storage owner](storage-architecture.md) and source-adjacent
concurrency tests for the exact data-type/backend behavior; do not infer a
zero-downtime port-swap procedure from a passing storage-library test.

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

**`cfg` CLI.** An operator interface wrapping REST endpoints. Documented commands must match implemented behavior; full CLI parity is deferred under the [product vision](../product/vision.md).
**Web UI.** The primary operator experience for the API-first SaaS launch. Existing CLI-only flows are implementation coverage to reconcile, not a requirement that web operators install the CLI. See the [product vision](../product/vision.md) for priorities.

**REST API — underlying contract.** The wire format the CLI and web UI both use. Stable, versioned, and documented at `docs/api/rest-api.md`. Available to operators and integrators for scripting and third-party tools.

**Workflow engine — automation surface.** For SaaS/cloud operations that don't require a steward (M365, identity providers, ticketing systems), the workflow engine is the primary expression mechanism. See [controller operating model](controller-operating-model.md#workflow-engine).

**Partner-delegated M365 tenant access.** An MSP reaches a customer's M365 tenant through a Granular Delegated Admin Privileges (GDAP) relationship rather than the customer's own app credentials. M365 workflow modules obtain a token through `auth.Provider.GetAccessToken(ctx, cfgmsTenantID)`; when the `OAuth2Config` stored for that CFGMS tenant is marked partner-delegated, the token is minted against the customer M365 tenant named in that same stored config, using the partner's client credentials, after the partner's GDAP relationship with that customer is validated against the required roles. One CFGMS tenant maps to one customer M365 tenant, and the customer tenant is never a caller-supplied argument, so a CFGMS tenant cannot obtain a token for a customer reachable only through another CFGMS tenant's relationship. Modules are unchanged. The minted token's `tid` claim is checked against the intended customer tenant.

## Controller Blob Store Namespaces

The controller blob store (`pkg/storage/interfaces/blob.BlobStore`) partitions binary artifacts by namespace within each tenant.

| Namespace | Purpose |
|-----------|---------|
| `installers` | Platform installer packages uploaded via `PUT /api/v1/installer/artifacts/{platform}/{arch}` |
| `installer-floor` | Rollback floor records, one per tenant, platform, arch and accepted installer version (name `<platform>-<arch>@<version>`, body the installer content hash). The newest record is the floor an upload must exceed; records survive artifact delete. |
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

The `UpgradeStore` is created by the configured storage provider, like the other business stores,
through the optional `UpgradeStoreCreator` extension. In a controller cluster it is the shared
database provider's store, so every node reads the same upgrade records and an upgrade dispatched on
one node can be read and rolled back (by `upgrade_id`) from any other. On a single node it is the
SQLite provider's store in the configured SQLite file.

The controller refuses upgrade requests with `503 Service Unavailable` (`UPGRADE_STORE_UNAVAILABLE`)
when the provider supplies no store. There is no silent in-memory fallback — durable state is required
to survive controller restarts and HA failover replay.

Upgrade records that an earlier release kept in a node's own SQLite file are not migrated. A
controller on the shared database provider does not read them; at startup it logs once, at info
level, when the configured SQLite file exists and may hold such legacy records.

### Rollback

`POST /api/v1/stewards/upgrade/{upgrade_id}/rollback` requires an explicit `version` field
(named target, not most-recent). The rollback is a dispatch-equivalent action: it looks up the
original steward, fetches the target-version blob (must be approved), creates a new `UpgradeRecord`,
and fans out `CommandPushStewardBinary`. Requires `installer:dispatch:steward` permission.

## Monitoring Export Credentials

OTLP exporter credentials (API keys / bearer tokens) are stored in `pkg/secrets`, not in config files. Configure the secret key name via `config["secret_key"]` and use `NewOTLPExporterWithSecrets` to wire the store at construction time.
