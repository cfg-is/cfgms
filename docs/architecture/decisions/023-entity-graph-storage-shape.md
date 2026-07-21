# ADR-023: Entity Graph storage shape — relational observation-log store

**Status:** Draft (2026-07-21)
**Date:** 2026-07-21
**Issue:** (to be assigned at decomposition)
**Epic:** (entity-graph foundation epic — to be filed; storage stories ride it)

---

## Context

[ADR-022](022-entity-graph-model-and-access-contract.md) defined the Entity Graph's logical model
and access contract and deliberately deferred the physical storage choice, handing this ADR seven
firm constraints (ADR-022 §10): an append-only, content-hash-deduped, two-timestamp observation
log; as-of/diff/timeline as first-class queries with collapse-group resolution; depth-bounded
(≤3) traversal; mandatory tenant-subtree filtering; a durable cursor-replayable change feed;
claim-scope set-difference at ingest; and a 50k+-steward envelope with interactive reads.

The contract was **shaped to keep this decision narrow**: no graph query language, no unbounded
traversal, no analytics on the hot path. The question this ADR answers is therefore not "which
graph database" but "what storage architecture serves the contracted operations inside CFGMS's
deployment reality."

That deployment reality: the controller is a self-hosted single binary run on-prem by MSPs as
well as operated as SaaS; storage is already a pluggable provider family with an embedded
`sqlite` provider (pure-Go driver, `modernc.org/sqlite`) and a server-based `database` provider
(`pkg/storage/providers/`); and the hard part of this workload is already proven in-tree — the
fleet DNA store (`features/controller/fleet/storage/`) does content-hash-deduped, versioned,
tenant-indexed history with retention pruning on exactly those two backends.

Founder decisions ratified 2026-07-21, taken as inputs:

1. **One store** — the entity-graph observation log subsumes DNA fragment history (no parallel
   versioned-fragment stores).
2. **Retention**: 90-day default history depth; configurable — downward for volume-constrained
   environments, upward (7+ years) for MSP/client compliance mandates.
3. **Partitioning**: delegated to this ADR's recommendation.
4. **Watch fan-out**: the contract states the requirement; each provider implements it in the way
   best suited to its backend.

---

## Decision

### 1. Relational observation-log architecture — no graph-native database

The Entity Graph is stored **relationally**. The source of truth is a single **append-only
observation log**: one row per observation, stamped with a **monotonic global sequence id**,
carrying `(subject, source, observed_at, recorded_at, kind, confidence, claim_scope_key)` and a
content-hash reference into a deduplicated payload table (the `DNARecord` dedup pattern,
generalized). Nothing updates or deletes log rows except retention GC (§7).

No dedicated graph database is introduced. The contract's operations all reduce to indexed
relational queries (§4); a graph-native store would add an external server dependency to a
single-binary self-hosted product, a licensing surface, and an operational system per deployment
— to buy traversal capability ADR-022 §9 deliberately excludes from the contract.

### 2. One store: the log subsumes DNA fragment history

Per the founder ratification: when the DNA-composition epic rebuilds DNA as fragments
(ADR-017), **fragment versions are observations in this log** — a fragment state change is an
observation of `kind: state` on the fragment's eid, content-hash-deduped like everything else.
Historical fragment state lives **once**, here. ADR-017 A1.3's versioned-fragment-history
requirement is satisfied by this store.

The DNA sync/validation hot path needs the current manifest and aggregate root per steward
without a history scan. That need is met **inside** this design, not beside it: the manifest/root
is a **transactional projection** (§3), maintained in the same transaction as the log append.
Hash validation (ADR-017 clause 7) reads a current-state lookup — never a history query — and
there is **no dual-write seam**: the log append is the single commit point; a crash can never
leave the validated root disagreeing with log-derived state. The DNA sync ingest handler is
accordingly an **internal writer** of the observation contract, joining the writers ADR-022 §9
enumerates.

This clause also resolves the question ADR-022 explicitly deferred to this ADR (whether the
graph's history "lineages over" the `DNARecord` store or replaces it) in favor of
**subsumption**, founder-ratified 2026-07-21: the existing flat-snapshot `DNARecord` store
evolves into this design with the DNA-composition epic rather than persisting as a parallel
history store.

### 3. Projections are derived, transactional, and rebuildable

Read-optimized **projection tables** — current entity state, current edge set, drift state,
per-`(source, claim_scope_key)` prior-assertion sets — are maintained in the same transaction as
log append. Every projection is **rebuildable by replaying the log**; replay is the recovery and
projection-schema-migration path, which is what makes the log the *only* source of truth rather
than the first among several.

**Replay determinism under a versioned taxonomy:** resolution rules (authority precedence,
ADR-022 §4) are registry-versioned and overridable, so replay applies the **current** rules by
design. An as-of-T read therefore answers "our best current interpretation of what was true at
T," not "the projection as it rendered at T under then-current precedence" — the observations
are immutable history; their interpretation is allowed to improve.

### 4. Query mapping

- **Neighborhood (depth ≤3)** — bounded recursive expansion over the indexed edge projection
  (`(from_eid, edge_type)`, `(to_eid, edge_type)`), with the tenant-subtree predicate applied at
  **every hop**, not post-filtered.
- **As-of-T / diff / timeline (single subject)** — `(subject, observed_at)`-indexed scans over
  the log; diff is two as-of projections; timeline is a range scan over subjects.
- **Collapse-group temporal reads** (ADR-022 §10 constraint 2 — the hard temporal case, and the
  one that sets the temporal index design): resolving a read with the `same-as` collapse option
  is a three-step query, not a flat scan — (1) resolve the `same-as` group membership **as of
  query time** from the edge history (those edges are themselves versioned observations);
  (2) apply the **tenant cut to the group before any merge** (ADR-022 §3 rule 1, a security
  invariant); (3) per-attribute precedence merge with `observed_at` tie-break over each
  surviving member's as-of state. This is what makes a machine's 30-day history survive a
  reimage (ADR-022 §5).
- **QueryEntities / ListDrifted** — indexed filters over projections.
- **Tenant filtering — authorization keys on *current* ownership.** Every log row and projection
  row carries the owning-tenant **path** stamped at ingest (prefix-indexed), but that frozen
  path is provenance, **not** the authorization key: visibility of a subject — including its
  full history — is governed by the subject's **current** owning tenant from the current-state
  projection. A moved entity's entire history is visible to its current owner and none of it to
  its former owner; filtering each historical row by its frozen ingest-time path would do the
  opposite (hide an entity's own pre-move history from its rightful owner while leaking it to
  the previous one). The subtree filter remains a predicate present in every query plan
  (ADR-022 §7's no-unfiltered-read rule, made structural).
- **Claim-scope ingest** — an enumeration diffs against the indexed prior-assertion set for that
  `(source, claim_scope_key)` as a batch upsert; O(scope-size) per enumeration, the accepted cost
  ADR-022 §10.6 flags.

### 5. Watch: the log sequence is the cursor — and commit-ordering is real machinery

A `Watch` cursor **is** a log sequence id; replay is an indexed range scan from the cursor;
semantics are **at-least-once, resumable, in sequence order**. Cursor semantics are cheap;
**correct ordering under concurrency is not** (this is the "new machinery" ADR-022 §10.5 warns
about), and it is a per-provider obligation:

- **`sqlite`** — WAL mode is single-writer, so commit order equals sequence order for free. The
  sequence column must be `INTEGER PRIMARY KEY AUTOINCREMENT` (the in-tree DNA store's schema is
  the required pattern) — never a bare rowid, which SQLite may reuse after retention GC deletes
  rows, corrupting cursors.
- **`database`** — a sequence assigned at INSERT does **not** commit in sequence order under
  concurrent transactions. A reader polling `seq > cursor` can observe seq 100 committed while
  seq 98 is still in-flight, advance its cursor, and silently never deliver 98 — at-most-once,
  the opposite of the promise. The provider MUST close this gap: assign the reader-visible
  sequence at commit time, or expose readers a **stable high-watermark** that never passes the
  lowest in-flight transaction.
- The contract test suite (§6) includes a **concurrent out-of-order-commit** case; a provider
  that loses an event under it does not ship.

How a provider *pushes* (backend-native notification primitives where the backend has them,
short-polling the sequence otherwise) is provider-internal, per the founder ratification.
Browser delivery rides the existing WebSocket fan-out in front of this feed (ADR-022 §9); the
feed itself is what makes a disconnected consumer able to catch up rather than miss events.

### 6. Two providers, per house style — and an honest envelope

The `pkg/entitygraph` contract (ADR-022 §10) gets two storage implementations, mirroring
ADR-003's pattern:

- **`sqlite`** — embedded, pure-Go, zero external dependencies; the OSS single-binary default.
  Its write path is WAL-mode single-writer, so its ceiling is observation write throughput
  (fleet size × change rate), not read load.
- **`database`** — server-based SQL; the tier that carries the contract's 50k+-steward envelope
  (SaaS and large self-hosted fleets).

The crossover point between the two is **a load-tested boundary established in story work, not a
number fixed here** — it is documented user-facing guidance derived from measurement, never a
discovered failure mode. `interfaces/contract_test.go` runs the full contract — Watch
cursor-replay including the concurrent out-of-order-commit case (§5), collapse-group temporal
reads (§4), tenant-filter enforcement on current ownership, retention invariants (§7), and
projection rebuild-by-replay — against **both** providers.

### 7. Retention: 90-day default, per-tenant-subtree override, history-only

- **Default history depth: 90 days.**
- **Configurable per tenant subtree**: an MSP or an individual client tenant can extend
  (unbounded — 7+ year compliance mandates) or reduce it; the **most specific tenant's policy
  wins** for records in its subtree, so one client's compliance hold never inflates sibling
  tenants' storage. Policy resolution — like visibility (§4) — keys on the subject's **current**
  owning tenant, so a moved entity's whole timeline is governed by one policy, not split across
  its former and current owners.
- **Retention prunes superseded history only — with one defined exception.** For **live**
  subjects, the latest version, the current-state projections, and open drift records are never
  GC'd: retention bounds *history depth* and can never make the graph forget what currently
  exists. For **retracted** subjects, whose latest observation is the absence record itself, a
  separate **tombstone horizon** (its own configurable knob, distinct from history depth)
  applies: the absence-as-latest is retained until the horizon passes, after which the subject
  is fully forgotten — log rows and projections removed. This is deliberately the *one* way the
  graph forgets a subject, and it is what prevents every entity ever retracted from accumulating
  as an immortal tombstone.
- GC is a background sweep honoring the effective (current-owner) policy per subject. The
  existing DNA store's pruning machinery (`sqlite_backend.go` retention sweep) is the in-tree
  template for **dedup-safe pruning only** — its time-cutoff path has no keep-latest guard, so
  the never-prune-current invariant is **new machinery this design adds**, not behavior
  inherited from the template.
- Storage growth remains change-proportional (content-hash dedup); long compliance retention
  therefore costs proportional to how much *changed* in seven years, not fleet-size × time.
- *Flagged, not decided here:* a compliance **export/archival format** (hand an auditor the
  history without keeping it hot) is a likely future story under the retention epic.

### 8. Partitioning posture: logical now, physical when demanded

Now: the tenant-path prefix index (§4) makes tenant the natural data-locality key, and the
sequence-ordered log keeps writes append-local. **No physical partitioning or sharding is built
yet.** When a real deployment's scale demands it, partitioning is a `database`-provider-internal
concern (partition by tenant-path and/or `recorded_at` epoch on the log), invisible through the
contract. Nothing in the schema or contract obstructs it — tenant path and time are stamped on
every row — so deferring costs nothing and avoids speculative machinery.

---

## Out of Scope

- **DDL / concrete schema** — epic-story work; this ADR fixes the architecture (log +
  projections + indexes), not column lists.
- **Backup/DR and cross-region replication** — deployment/operations concern of the chosen
  backend, not the shape.
- **Compliance export/archival format** — flagged in §7, its own story when a real mandate
  arrives.
- **The steward/module wire protocol for observations** — ADR-022 epic scope.
- **Telemetry/DEX signal storage** — remains outside the graph store entirely (ADR-022 §9
  boundary); its store is the DEX epic's concern.

---

## Consequences

### Positive

1. **Zero new infrastructure.** Both providers already exist as house patterns; the single-binary
   on-prem story and the AGPL posture are untouched; nothing new to operate, license, back up, or
   secure.
2. **One history store** for graph and DNA fragments — the "no parallel islands" principle
   applied to storage itself; ADR-017 A1.3 is satisfied here rather than twice.
3. **Watch, history, and audit provenance are one structure** — the sequence-ordered log serves
   all three; no separate changefeed subsystem to keep consistent.
4. **Rebuildable projections** make recovery and projection-schema evolution log-replays instead
   of migrations of truth.
5. **Compliance retention is a per-tenant knob**, not an architecture change — 90d and 7yr
   tenants coexist in one deployment paying only for their own change volume.

### Negative

1. **Recursive neighborhood queries need real care** — index discipline and per-hop tenant
   predicates are correctness-and-performance load-bearing; the contract tests must include
   adversarial depth/fan-out cases.
2. **Write amplification** — every ingest writes log + projections transactionally; the
   claim-scope diff adds O(scope) on enumerations. Acceptable at change-proportional volume;
   the sqlite envelope (§6) is where it bites first and must be honestly documented.
3. **Per-tenant retention GC is genuine machinery** — effective-policy resolution over the
   tenant tree (keyed on current ownership), sweep scheduling, the never-prune-current
   invariant (new, not in the in-tree template), and the tombstone horizon all need dedicated
   tests.
4. **The `database` provider owes a commit-ordered sequence** (or stable high-watermark) for
   Watch (§5) — a known outbox-class subtlety that must be engineered and contract-tested, not
   assumed.
5. **The DNA-composition epic inherits a coupling**: its fragment-history storage story now
   targets this store (§2) instead of extending `DNARecord` in place — sequencing between the two
   epics must respect that.

### Neutral

- A graph-native or otherwise specialized provider remains possible later **behind the same
  contract** (pluggability is the escape hatch); the consumer that genuinely needs unbounded
  traversal pays for that justification when it exists.
- The `memory` storage provider is not offered for the graph (house rule: no memory-only storage
  for durable features); tests use the real `sqlite` provider.

---

## Alternatives Considered

### Dedicated graph database

Buys pattern-matching and unbounded traversal the contract deliberately excludes; costs an
external server dependency in a self-hosted single-binary product, a licensing surface, poor
in-process embedding for Go, and a second operational system per deployment. Choosing storage
for the model's shape-word ("graph") rather than its contracted operations — **rejected**.

### Separate stores: fragment history beside graph history

Two versioned-truth stores for overlapping state (a fragment version is entity state), with
permanent reconciliation risk and double storage. Founder-ratified against — **rejected**.

### Document store

Weak fit for the two things this workload does most: multi-way indexed edge joins
(neighborhood) and time-ordered range scans (as-of/timeline/Watch). Adds a new backend family to
operate without removing any relational need — **rejected**.

### Log/stream platform as the observation log

An external event-streaming system gives an append-only sequenced log — and brings heavyweight
infrastructure wholly disproportionate to a self-hosted controller, while still needing a
relational projection layer for every read. The relational log gets the same semantics inside
the existing providers — **rejected**.

### Git+SOPS (the config-store default)

Already ruled out in the roadmap: an observation log at fleet change-volume is the opposite
write pattern of a version-controlled config store; no indexed temporal or edge queries —
**rejected**.

---

## References

- [ADR-022](022-entity-graph-model-and-access-contract.md) — the model and access contract; §10
  is the constraint set this ADR satisfies
- [ADR-017](017-dna-composition-and-sync.md) — Amendment 1 A1.3 (versioned fragment history —
  satisfied by §2's single store); clause 7 (sync hot path kept separate from history)
- [ADR-003](003-storage-data-taxonomy.md) — the per-data-type provider pattern §6 mirrors
- `features/controller/fleet/storage/` — in-tree proof of the deduped/versioned/tenant-indexed
  history pattern on both target backends, including retention pruning (`sqlite_backend.go`)
- `pkg/storage/providers/{sqlite,database}/` — the two provider implementations the graph store
  mirrors
- `go.mod` — `modernc.org/sqlite` (pure-Go embedded driver; preserves the single-binary
  controller)
