# ADR-031: Controller Cluster Service Model — Any-Node Service, Durable Delivery, Minimal Leadership

**Status:** Accepted

**Date:** 2026-09-01

**Deciders:** Founder, Architecture

**Related:** Epic [#3751](https://github.com/cfg-is/cfgms/issues/3751) (this ADR is its design gate). ADR-007 (controller upgrade and state externalization — established the shared
PostgreSQL / blob / vault backend this ADR builds on). ADR-028 (Raft log persistence).
ADR-029 (lease-backed leadership authority). ADR-013 (steward–controller trust and
distribution). Issue #3741 (dispatch resolves through a not-for-dispatch fleet source).
Companion: ADR-032 (SaaS deployment topology and trust hierarchy — drafted alongside).

---

## Context

### What a multi-node controller cluster does today

A cluster of N controller nodes provides redundancy but not capacity, and pushes
cluster topology knowledge onto every client:

- **Writes are leader-only with no forwarding.** ~50 mutating REST handlers gate on
  `HasLeadership()` and return `503 service unavailable` from every non-leader node.
  The gate is an inline block copied per handler, not middleware. A client behind a
  load balancer receives 503s from N−1 of N nodes. A further 74 mutating handlers
  are not gated at all (the `ungatedHandlerBaseline` ratchet), so the leader-only
  model is not even consistently enforced.
- **Command delivery is node-local and unobservable.** The steward connection
  registry is a per-process map (`pkg/transport/registry`). Delivery primitives
  (`SendCommand`, `FanOutCommand`) look up only the local map. Config upload
  returns `status: stored` and then fans out on a detached goroutine iterating the
  node-local steward list: a steward connected to a peer node is silently never
  notified. The fan-out result is logged and discarded. There is no
  controller-to-controller RPC of any kind; the only inter-node wire is the Raft
  message transport.
- **Reads are node-local for tenant-scoped principals.** `GET /api/v1/stewards`
  serves the durable store only for unscoped admin callers; tenant-scoped callers
  get the local node's in-memory view. Per-steward DNA reads and config reads
  fail for stewards attached to peer nodes.
- **Every node runs every background loop.** Heartbeat sweeps, expiry jobs, trigger
  scheduling, health collection — eleven loops run on all N nodes against the shared
  database. Exactly one code path is leader-gated. Adding a node adds N× duplicate
  polling.
- **Each node opens ~300–500 database connections.** Every storage sub-store opens
  its own pool (default 25 connections × 12+ stores). Connection consumption scales
  with node count, not endpoint count, and exhausts the shared database first.
- **Raft replicates almost nothing.** The replicated state machine carries controller
  cluster membership (`node_update`) and a steward-session map (`session_update`)
  whose production wiring was never connected. Config, tokens, registrations,
  heartbeats, and DNA never touch the log. Business state already lives in the
  shared PostgreSQL backend (ADR-007).

### The structural observation

The leader-only write model is inherited from systems whose replicated log IS the
database. CFGMS's database is PostgreSQL, shared by all nodes (ADR-007). Raft is not
serializing business writes today and never was. The write gate therefore protects
nothing on the request path — transactional writes to the shared database are already
safe from any node. What genuinely needs single-writer semantics is a small set of
singleton background jobs, and what genuinely needs new machinery is cross-node
command delivery.

## Decisions

### Decision 1 — Any node serves any request

The leadership gate is removed from the API request path. Every cluster node accepts
every read and write; the shared PostgreSQL database is the serialization point.
Ordinary load balancing (one DNS name fronting N nodes) becomes the complete client
routing story, per ADR-013.

- The ~50 inline `HasLeadership()` request gates are deleted.
- The `ungatedHandlerBaseline` ratchet and its architecture rule are retired with
  them (their premise — mutating handlers must be leadership-gated — inverts).
  ADR-029's fencing analysis is preserved by Decision 3: side effects that must be
  cluster-singleton move behind the singleton executor rather than behind a
  request-path gate.
- Multi-writer safety obligations transfer to the database layer: writes that were
  implicitly serialized by the single-leader assumption must be reviewed for
  transactional soundness under concurrent writers (uniqueness constraints,
  compare-and-set on version columns). This review is a story in the epic, not
  assumed away. Two known casualties are named now:
  - **Audit chain sequencing (ADR-004).** Per-tenant sequence numbers are assigned
    in a single in-process drain goroutine, "no concurrent writer can interleave."
    N nodes each run that goroutine against one database, so per-tenant monotonic
    sequencing and `previous_checksum` linkage need database-side serialization.
    (With 74 handlers already ungated, cluster deployments likely violate this
    today; Decision 1 makes the fix mandatory rather than latent.)
  - **Registration-refresh nonce cache (ADR-011).** The single-use nonce lives in
    an in-process cache; under any-node service, challenge and completion can land
    on different nodes. ADR-011's own deferred alternative (nonce in the shared
    durable store) becomes mandatory.
- The architecture checker `TestNoUngatedMutatingHandler` (Story #3547) and its
  CLAUDE.md section enforce the exact invariant this decision deletes. They are
  retired deliberately as part of this decision — removed with the gates, never
  fought or baselined around. The raw-leader-primitive rule (Story #3391) survives:
  raw protocol flags remain forbidden wherever a singleton claim is meant.

### Decision 2 — Command delivery is a durable outbox with observable state

Delivery to stewards becomes a fact in the database, not a goroutine's best effort.

- A command/notification row commits **in the same transaction** as the state change
  that requires it (config write + "notify steward X" are atomic).
- Delivery lifecycle is recorded: `pending → delivered → acknowledged` (terminal
  failures recorded distinctly). The API exposes it; `cfg` and the web UI can watch
  a write until it lands on endpoints.
- Stewards attached to no node (offline) drain their pending rows on reconnect.
  Delivery to an offline endpoint is deferred, never lost.
- `status: stored` responses that imply more than storage are replaced by responses
  that reference the trackable delivery record.

### Decision 3 — A shared routing table and a direct delivery RPC

- Each node records which stewards hold control-plane connections to it, in shared
  state visible to all nodes (steward → node, with liveness).
- A new internal controller-to-controller gRPC service — the first — lets node A
  request immediate delivery to a steward connected to node B. mTLS on the existing
  internal listener, same certificate infrastructure as the Raft transport.
- The fast path is the direct RPC; the outbox row is the guarantee underneath it.
  If the RPC fails or the routing entry is stale, the row stays `pending` and is
  drained on the steward's next connection event.
- Fleet-wide fan-out composes the same two primitives: rows for all targets, each
  node delivers to its own connections. The `GetAllStewardsCluster` /
  `GetAllStewards` split ("dispatch-safe" by doc comment) is retired in favor of
  delivery that is cluster-safe by construction (#3741's stated end state).

### Decision 4 — Leadership shrinks to singleton scheduling only

- The background loops that must run once per cluster (sweeps, expiry, schedulers)
  run behind a singleton claim instead of on every node.
- Queue-shaped work uses database work-claiming (`SELECT … FOR UPDATE SKIP LOCKED`)
  so all nodes share the work; only genuinely singleton work uses the
  cluster-singleton lease.
- `HasLeadership()` survives only as the singleton-claim primitive, never as a
  request-path authorization check.

### Decision 5 — Consensus is replaced by a database lease (ratified 2026-09-01)

Two options were argued:

**(a) Keep Raft for leader election only.** ADR-028/ADR-029 machinery is built and
tested; the lease semantics are proven. Cost: an entire consensus subsystem — log
persistence, snapshotting, membership changes, a dedicated mTLS transport, and its
failure modes — retained to elect a scheduler. The session-replication half of its
state machine was never wired in production; the membership half duplicates what the
shared database can attest. Split-brain analysis must be maintained for a component
whose protected resource (the log) carries no business data.

**(b) Replace Raft with a lease table in the shared database.** Singleton claims
become fenced, quorum-equivalent leases implemented as transactional rows
(fencing-token column; ADR-029's fencing discipline carries over directly). The
cluster's availability already depends on the database — a cluster whose database is
down cannot serve writes regardless of who leads — so no new single point of failure
is introduced. Removes: the Raft subsystem, its transport, its log storage, ADR-028's
persistence machinery, and the dead session-replication path. Single-node
deployments lose a subsystem they never needed.

**Decided: (b). Raft is removed.** ADR-029's *authority* model (fenced,
lease-backed, no raw protocol flags) is retained in full; only its *implementation
substrate* changes from Raft to database leases. The fencing token becomes the
lease's monotonic token; the steward-side three-state ratchet (ADR-029 Decision 6,
shipped) carries over with the new token source and its enrollment-reset path
intact. ADR-028 is superseded in whole.

### Decision 6 — Node scale-out defects are in scope

- One shared database connection pool per node, sized deliberately, replacing 12+
  independent per-store pools.
- The three dead-wiring defects (cluster inventory refresh never started; HA
  manager's registry and control-plane provider never wired) are fixed or the dead
  code is removed as part of whichever decision above obsoletes it — not left
  ambiguous.
- Per-tenant admission control on the steward ingest path (connect, heartbeat, DNA)
  so one tenant cannot exhaust a shared cell. Limits are configurable per tenant;
  enforcement composes with the existing per-tenant DNA semaphore.

## Consequences

- Adding a node adds capacity: API service scales with N, connection load is pooled,
  background work is claimed once, delivery reaches any endpoint from any node.
- Clients need zero topology knowledge (ADR-013's model becomes true in practice).
- Writes gain multi-writer review obligations (Decision 1) — a real, bounded cost.
- Delivery gains durability and observability; the silent-no-op class is eliminated
  structurally.
- The consensus subsystem is deleted: raft transport, log persistence, snapshot
  machinery, membership protocol, and the never-wired session replication path.
  Operational surface shrinks materially for both SaaS and self-hosted
  deployments.
- The steward-facing protocol is unchanged: registration, transport address
  issuance, certificates, heartbeat, and DNA sync are untouched by this ADR.

## Out of scope / deferred

- SaaS deployment topology, CA hierarchy, tenant ID namespacing: **ADR-032**.
- Cross-region MSP experience: home-cell model with read-only cross-cell
  federation under a single-writer invariant — deferred; recorded as a one-line
  direction in ADR-032, not designed here.
- Heartbeat-path in-process contention (global mutexes, stale-sweep scan): separate
  performance epic, gated on benchmarks; not a cluster concern.
- Steward-side key generation (CSR enrollment): security defect tracked separately;
  interacts with ADR-032's chain distribution but is independent of this ADR.

## Supersedes / amends

Contradiction sweep completed 2026-09-01 against every ADR and canonical
architecture doc. Exact clauses:

**ADR-029 (Superseded in part / Amended)** — the most impacted.
- Decision 3's table ("`HasLeadership()` … every side-effecting path") and the
  Consequences' follower-503 trade ("callers see 503 and retry … accepted
  deliberately") are superseded by Decision 1 here.
- The lease *authority model* (fenced, no raw protocol flags) survives in full and
  governs Decision 4's singleton claims.
- Decisions 3–6's fencing-token source (Raft `GetTerm()`) is superseded: the
  fencing token becomes the database lease's monotonic token; the steward
  ratchet's three-state model carries over with the new token source.
- Epic #3411 (extend authority gating to remaining endpoints) inverts: its
  remaining scope is retired with the gates.

**ADR-028 (Superseded)** — in whole; the Raft log it persists no longer exists.

**ADR-004 (Amended)** — single-drain-goroutine sequencing claim replaced by
database-side per-tenant serialization (Decision 1, named casualty above).

**ADR-011 (Amended)** — in-memory nonce cache replaced by durable shared store
(Decision 1); refresh cert issuance affected separately by the CSR change
(ADR-032's remit).

**ADR-008 (Related, not conflicting)** — records that the documented "durable job
queue" never existed and commits durable execution state to the database. The
outbox (Decision 2) is a distinct, simpler mechanism than `pkg/orchestration`
workflows: same substrate, no workflow engine in the delivery path. Stated here so
the two are never conflated.

**ADR-003 / storage-architecture.md (doc update, no ADR change)** — the
CommandStore lifecycle ("startup sweep flips `executing` → `failed` on
controller_restart") inverts under Decision 2: a restart must not fail queued
deliveries; pending rows survive and drain.

**controller-operating-model.md (rewrite of clustering sections)** — "Authority
Gating" sections (§ around :1241 and :1300), the follower-503 examples, the
"fire-and-forget with completion tracking" command contract, and the Raft-term
outbound-command fence section are all superseded by Decisions 1–4.
steward-operating-model.md's "Raft-Term Command Fence" section is rewritten for
the lease token (mechanism unchanged, source renamed).
The already-true line — steward traffic "serves … directly against the shared
backend and no request is forwarded to the leader" — is the measured precedent
Decision 1 generalizes to the admin API.

**operating-model.md (Amended)** — the "Concurrent Controller Execution" section's
ceiling ("multi-active HA … needs a separate epic with proper write coordination")
is resolved by this ADR: the coordination is the shared database.

**Deferred to ADR-032** — amendments to ADR-007 (:97 "shared key vault for the
CA"), ADR-013 (chain model, §4 rotation channel), ADR-030 (cluster-CA wording),
ADR-025 (tenant-ID grammar under realm qualifiers), ADR-021 (Amendment 5's
"one non-CSR credential" claim), steward-operating-model.md's registration wire
contract (`client_key` in the response), and docs/operations/cluster-ca.md.

**pkg/cert (Amended, Issue #3852)** — Decision 1 assumes the serialization the
shared database provides; `pkg/cert`'s revocation list and config-signing
rotation cursor were node-local JSON files, so that premise did not hold for
`handleRevokeCertificate`, `handleRevokeCertBinding`, `handleRotateCert`, the
containment revoke paths, and `handleRotateSigningCert` — the three findings
Issue #3761's fix agent escalated as storage-shape problems a gating fix could
not resolve. `pkg/cert/interfaces.RevocationStore` / `SigningCursorStore` close
that gap: a file-backed implementation preserves single-node behavior
unchanged, and a Postgres-backed implementation
(`pkg/storage/providers/database`) is selected via `pkg/ha.Config.IsClusterMode()`
when the controller runs clustered, making revocation and signing-cursor state
satisfy Decision 1's premise like every other store this ADR covers. This was
the prerequisite the founder chose (option B, 2026-09-02) to unblock #3761;
the `HasLeadership()` gates named above are still in place and remain #3761's
job to remove.

The decisions/README.md index gains ADR-031's row; status columns for ADR-028/029
update per above when this ADR is Accepted.
