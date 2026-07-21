# ADR-022: Entity Graph — logical model and access contract

**Status:** Draft (2026-07-21, rev 2 — post adversarial BA + Tech Lead review)
**Date:** 2026-07-21
**Issue:** (to be assigned at decomposition)
**Epic:** (entity-graph / troubleshooting-cockpit backend epic — to be filed)

---

## Context

CFGMS is pulling the **troubleshooting cockpit** forward as its flagship surface: the screen that
answers, about any piece of a fleet, *what is wrong here, what else does it affect, what changed,
and how do I fix it* — and keeps answering as an investigation widens from one machine to several.
The web foundation the cockpit renders in already ships; the cockpit reference mockup exists
(`docs/design/mockups/troubleshooting-cockpit.html`). What does not exist is the thing underneath:
a coherent model of the entities CFGMS knows about and the relationships between them, and a
defined way to query and serve that model.

### What exists today

- **Per-object state and identity.** ADR-016/ADR-017 define DNA as a set of addressable fragments
  with an object-canonical `fragment_id` (`type:name`), single-authority resolution, a provenance
  envelope, and controller-side versioned history (ADR-017 Amendment 1). Note: this is the
  *defined* model — the fragment redesign is **not yet built**; `commonpb.DNA` is still a flat
  `map<string,string>` (`api/proto/common/common.proto:12`). What the controller persists today is
  versioned, content-hash-deduped, tenant-indexed history of the *flat* per-device DNA
  (`features/controller/fleet/storage/storage.go` — `DNARecord`).
- **Drift** is detected on the steward and is ephemeral — logged locally, not shipped
  (`features/steward/steward.go:401`; data-plane drift reporting is an explicit TODO). The
  controller's only central drift signal is an aggregate-hash mismatch on heartbeat that triggers
  a resync (`features/controller/heartbeat/service.go:284`). Two distinct steward-side shapes
  exist: convergence `StateDiff` (desired-vs-actual for managed resources,
  `features/steward/steward.go:428`) and `DriftEvent`/`AttributeChange` (observed
  snapshot-vs-snapshot change for the unmanaged remainder, `pkg/dna/drift/drift.go`). Neither is
  persisted centrally; neither is entity-addressed.
- **Relationships exist only in pockets, shaped by whoever discovered them.** The Hyper-V module
  holds cluster→node→VM topology as fields on Windows-only structs
  (`features/modules/hyperv/cluster.go:161` — `MemberNodes`, `RoleOwners`); the directory layer
  holds membership as per-object adjacency lists (`pkg/directory/dna/interfaces.go:182` —
  `DirectoryRelationships`); tenancy is a `ParentID` pointer plus materialized path
  (`pkg/storage/interfaces/business/tenant_store.go`); M365 GDAP holds partner↔customer edges.
  There is **no shared edge type, no channel in the module contract to emit a discovered
  relationship** (they ride as opaque keys inside `ConfigState.AsMap()`), and **no store that holds
  cross-entity relationships**. The one cross-entity primitive in the module contract is
  `ManagedElsewhere() (bool, authority)` (`features/modules/module.go:75`).

### Direction

The founder has fixed the design posture: **shape the model to what the product needs — the
cockpit now, the digital-twin and DEX capabilities behind it — and bend the collectors to the
model.** Refactoring existing collectors to report relationship data correctly is expected,
in-scope work. The model must never inherit the accidental shapes of today's collectors.

Four constraints are locked as inputs:

1. **Nothing is out of scope in the model.** Every kind of relationship is first-class. What is
   incremental is discovery capability, not the model — a relationship CFGMS cannot yet observe is
   not-yet-populated, never excluded by design.
2. **The cockpit is a pure view over current knowledge** — sparse today, denser as discovery
   grows; it must not assume completeness.
3. **Relationship knowledge is sourced from discovery**, with multiple sources contributing the
   same kinds of relationships over time at differing trust and freshness.
4. **An investigation spans many endpoints.** A case accretes entities as work widens; it is
   one-to-many with the things it touches.

ADR-017 Amendment 1 guaranteed the **identity + history substrate** (typed entity id, provenance
envelope, versioned fragment history, DEX-signals-address-entities) and flagged a companion ADR
for the graph itself. This is that companion — the **logical model and access contract**. The
physical storage shape (which store, partitioning, sync mechanics) is deliberately a separate
follow-up ADR; §10 hands it firm constraints.

---

## Decision

CFGMS gains one product-wide model — the **Entity Graph** — served by a new pluggable central
provider. The graph is the accumulation point for everything CFGMS knows about a deployment:
typed entities, typed relationships between them, their state, where each piece of knowledge came
from, and how all of it changes over time. The graph holds **stable knowledge**: entities, edges,
state, drift, history. It does not hold telemetry — but telemetry addresses graph entities, so
experience data joins the graph instead of forming an island (§9, boundary).

### 1. Entities are typed; identity is `authority-scope [/ local_id]`

The graph's node identity extends ADR-017 A1.2's typed entity id (`type:name`) from steward-local
to fleet-global by composition:

```
eid = authority_segment [ "/" local_id ]
```

- **`authority_segment`** is one `type:name` segment naming a **naming authority** — a real thing
  that mints unique, stable local names: `host:<device-id>` (a steward-managed machine),
  `cluster:<cluster-guid>` (a failover cluster), `directory:<instance-id>`,
  `m365:<tenant-guid>`, `cfgms:<deployment-id>` (deployment-global objects such as tenants).
- **A bare authority segment is itself a legal eid and names the asset as a whole.**
  `host:a1b2c3` *is* the machine; `cluster:hv-east-guid` *is* the cluster. This is the node the
  cockpit's asset context, neighborhood, and drift reads target.
- **`local_id`**, when present, is exactly the ADR-017 `fragment_id` (`service:sshd`,
  `file:/etc/hosts`, `host:os`) — unchanged, so within a steward's context the join key is
  (steward identity from the mTLS peer → authority segment) + `fragment_id`.
- **Parsing and enforcement:** authority names use a restricted charset (no `/`); an eid parses
  unambiguously at the **first** `/`; `local_id` may contain anything
  (`host:a1b2/file:/etc/hosts` is valid). A single **eid constructor** in the provider is the
  only mint path — it validates the authority charset, the registered types, and rejects
  malformed ids at ingest. Collector code never string-concatenates eids.
- **Structural containment is derived, not observed.** For any eid with a local part,
  `contains(authority, authority/local)` is implied by the grammar; the provider materializes
  these edges automatically. No collector emits "host contains its own fragments."
- **Shared, multi-observer entities get their own authority.** A cluster observed by every member
  node is **one** eid (`cluster:<guid>`), not N per-node eids: entities that exist independently
  of any single observer are named under their own stable identity (cluster GUID, directory
  instance id), and per-node observations converge on that one eid via source resolution (§4).
  `ManagedElsewhere` maps to this: the owning node's module observes authoritatively; non-owners
  corroborate or abstain.
- The **entity-type taxonomy** (ADR-017 A1.2) is extended to a versioned registry that also
  enumerates authority types and, per entity type, which authority class names it. It covers
  kinds no module manages (`application:*`, `device:*`, `user:*`, `group:*`, `tenant:*`,
  `vm:*`, `vswitch:*`, …) — such entities exist as observed or telemetry-only nodes with no
  managed fragment.

**Naming scope is not tenancy and not topology.** The authority segment exists solely to make
names unique and stable; owning tenant is a resolved attribute plus an edge (§7), and physical
placement is an edge. Moving an entity between tenants or hosts never rewrites history. When a
thing genuinely changes naming authority — a reimaged or re-enrolled machine minting a new
device-id (today's DNA-ID-mismatch path, `features/steward/steward.go:375`) — the new authority
is a new eid joined to the old by correlation (§3), and the temporal reads accept a
collapse-group option (§9) so "what changed on this machine over 30 days" survives a reimage.

**Relationship to ADR-017 (proposed Amendment 2).** This clause deliberately changes two
Amendment 1 statements and must be recorded as ADR-017 Amendment 2 when this ADR is accepted:
A1.2's "no separate node-identity scheme" and A1.4's "signals are addressed to a `fragment_id`"
become: **fleet-global addressing is the `eid`; a bare `fragment_id` is host-local shorthand**,
valid only where the authority is implied by the transport context (a steward's own DNA sync).
Emitters of fleet-scoped data (DEX signals, edges) carry the full eid. The join-for-free property
is preserved in substance — one shared identity across DNA, graph, and DEX — but the fleet-scoped
form is two-part, and pretending otherwise would leave A1.2/A1.4 unbuildable across 50k hosts.

### 2. Relationships are first-class, typed, directed edges

An edge is a record in its own right — never a field buried inside one endpoint's state:

```
edge  = (edge_type, from_eid, to_eid)          — identity
      + attributes                              — typed, optional (e.g. port, role, affinity)
      + per-source observation set (§4)         — who asserts this edge, since when, how surely
```

- **`edge_type`** comes from a versioned, enumerated **edge taxonomy** owned alongside the entity
  taxonomy. Seed set: `contains`, `runs-on`, `member-of`, `depends-on`, `serves`, `connects-to`,
  `manages`, `managed-by`, `assigned-to`, `delegated-access`, `reports-to`, `same-as` (§3).
- **Discovery is never blocked on taxonomy governance.** A collector that observes a relationship
  kind not yet enumerated reports it as `related:<discriminator>` (a reserved open subtype with a
  free-text discriminator). Instances land immediately, render generically, and a registry
  promotion (taxonomy version bump) later reclassifies them to a first-class type. This keeps
  constraint 1 true in both directions: no relationship excluded by design, and no ad-hoc
  proliferation of unreviewed first-class types.
- Edges are sparse and populated by discovery. An edge type with no observer yet simply has no
  instances — it is never "unsupported."
- Both endpoints are `eid`s. An edge may reference an entity the graph has not otherwise seen: a
  **placeholder node** materializes under that same eid, carrying only the edge-observer's
  provenance. Later observations of the eid enrich the same node — placeholders are early
  knowledge, not a parallel record needing reconciliation.

### 3. Multiple sources name the same real thing: correlation, never destructive merge

Different sources will see one real-world thing under different identities (the Hyper-V module
sees a VM by cluster-role name; that VM's own steward sees itself as `host:<device-id>`; the
directory sees a computer object). The model keeps each source's entity **distinct** and joins
them:

- Entities carry **identity claims** as attributes (hostname, MACs, machine SID, directory
  objectGUID, serial, cloud object id) with normal provenance.
- A controller-side **correlator** emits `same-as` edges between entities whose claims match,
  with confidence reflecting the strength of the match. `same-as` is an ordinary edge — observed,
  provenanced, retractable when it proves wrong.
- The read contract can **collapse** a `same-as` group into one logical entity view on request
  (§9); the stored graph never merges records. The collapse rule is deterministic:
  1. **Tenant cut first (required, security):** members outside the caller's tenant subtree are
     removed *before* any merging; their attributes never appear in the collapsed view.
  2. Per attribute, the value from the highest-precedence source class (§4) wins; ties break by
     latest `observed_at`.
  3. Conflicting values are not discarded — the collapsed view carries per-attribute provenance
     and the losing values remain retrievable per member.
- Wrong correlations are corrected by retracting the `same-as` edge — no un-merge problem, no
  lost provenance.

### 4. Every write is an observation; current state is a projection

The single write primitive — for entities, attributes, and edges alike — is the **observation**:

```
observation = (source, observed_at, subject, kind, payload, confidence)
  subject    : eid | edge identity
  kind       : state | presence | absence
  confidence : high | medium | low     (producer-declared, ordinal)
```

- **`source`, `observed_at`, `confidence`** are ADR-017 A1.1's provenance envelope, reused;
  `recorded_at` (controller ingest time) is stamped on receipt. As in A1.1, provenance is
  metadata *about* knowledge, never part of any DNA hash.
- **Freshness is a separate dimension, not a confidence rewrite.** Staleness is computed
  (now − `observed_at`, against the source's declared observation cadence) and returned alongside
  confidence on every read. Stale knowledge is flagged, never silently dropped — an unplugged
  switch does not vanish, it goes stale. Consumers render both dimensions; the model does not
  collapse them into one number.
- Sources report in two modes:
  - **Delta** — assert or retract a single subject (`presence`/`absence`/`state`).
  - **Claim-scoped enumeration** — the source declares a **claim scope** and enumerates its
    complete contents; anything previously asserted *by that source, inside that scope* and
    missing from the enumeration is implicitly retracted. A claim scope is a first-class
    descriptor:
    ```
    claim_scope = (source, pattern, as_of)
      pattern : edge pattern    (edge_type, anchor eid, direction)
              | entity pattern  (entity_type, authority prefix)
    ```
    A source's declared scopes must not overlap for the same pattern key; an enumeration replaces
    that source's prior assertion set for exactly that scope. This is what lets snapshot-style
    collectors (cluster enumeration, directory sync) converge without tombstone bookkeeping, and
    it bounds each source's blast radius to its own claims — one collector can never silently
    erase another's knowledge.
  - **Source closure (administrative retraction).** A source that disappears permanently never
    sends a final enumeration, so its claims would otherwise persist forever. Lifecycle events
    close them administratively: steward deregistration emits `absence` across the departed
    authority's subtree; module uninstall closes that module's claim scopes on its host. Closure
    is an observation like any other (source: the controller lifecycle manager) — visible in
    history, not a silent purge.
- **Resolution** generalizes ADR-017 clause 2. Per subject, at most one source class is
  **authoritative**; the default total order is:
  **enforcing module > managing integration (directory/cloud provider) > observer
  (osquery/monitor) > operator assertion > correlator inference** —
  overridable per entity type in the taxonomy registry; ties within a class break by registry
  order, then latest `observed_at`. The same order applies to **edges** (where two sources most
  often meet on one subject, since edge identity carries no authority segment). The authoritative
  observation is the subject's *managed truth*; non-authoritative observations are retained,
  queryable, and surfaced — disagreement between sources is signal the cockpit can show, not
  noise to discard.
- **Projection ordering:** current state projects by `observed_at` (ties: `recorded_at`), so a
  late-arriving stale observation can never regress a fresher current state; it lands in history
  where it belongs.

### 5. History is append-only and queryable over time

Extending ADR-017 A1.3 from fragments to the whole graph: the observation log is **append-only**;
supersession creates versions, never overwrites. Two timestamps make history trustworthy:
`observed_at` (when true in the world, per the source) and `recorded_at` (when the controller
learned it). Content-hash dedup keeps unchanged re-observations cheap — storage growth tracks
change volume, not fleet-size × time; retention depth is policy.

Three temporal reads are contract-level (§9): state **as-of T**, **diff** between two times, and
a **change timeline** over a set of subjects — each accepting the `same-as` collapse-group option
(§3), so history survives identity changes like re-enrollment. The cockpit's change-timeline
card, the twin's "what was true at T," and DEX baselining are all these three operations.

*Dependency note:* per-eid state and history presuppose the ADR-017 fragment model and
fragment-addressed versioned history, which are **defined but not yet built** (see Dependencies).
The existing `DNARecord` store versions the flat per-device map and is the substrate that epic
rebuilds fragment-addressed.

### 6. Desired state, drift, and apply outcomes attach to entities

Managed entities have a desired state and an actual state, and the graph records both plus what
happened between them:

- **Desired state is ingested from ConfigStore as observations** with source
  `config:<revision>` — so every desired-state change carries its originating revision, the
  timeline shows config pushes natively, and the drift hero card can label its desired column
  ("intent r2291"). `GetDesiredState(eid)` is a first-class read (§9).
- **Drift-diff** — the per-attribute desired-vs-actual delta — is sourced from the convergence
  loop's `StateDiff` (which knows desired state), re-keyed onto eids and shipped centrally by the
  steward (closing the current log-only TODO). The persisted record carries the **full compared
  field set** (matching fields included — the hero card renders checkmarks too), the desired-side
  revision, and lifecycle `detected → acknowledged → resolved/ignored`. The existing
  `DriftEvent`/`AttributeChange` shapes serve the *unmanaged observed-change* stream (no desired
  state exists for those) and feed the timeline; both streams are re-keyed onto eid — this is
  real rework of both paths, not a relabeling.
- **Apply outcomes** — per entity, per config revision: applied / partial / failed, with
  per-section error detail — are shipped by the steward as eid-addressed records. This is what
  lets the hero card say "last_apply r2291 partial (section 'memory': lock timeout)."
- Drift lifecycle transitions (acknowledge/ignore/resolve) are **workflow annotations, not
  world-facts**: they are written through a dedicated narrow operation (§9), stamped with actor
  and time, and never masquerade as observations of reality.
- The aggregate-hash heartbeat remains the cheap liveness/sync signal; the graph holds the
  *explanation*.

### 7. Tenancy: an attribute for authorization, an edge for topology

- Every entity carries a resolved **owning tenant** attribute (derived at ingest: steward
  registration tenant; directory/cloud instance→tenant mapping), indexed for filtering.
- **Every read operation takes a mandatory caller-tenant-subtree filter.** The provider enforces
  it; there is no unfiltered read. This is the required behavior for the REST layer too:
  collection/`{id}` routes are not middleware-tenant-scoped, so every handler MUST apply the
  in-handler subtree check and return 404 (not 403) on cross-tenant access. (Existing handlers
  are the pattern, not the proof — at least one has a known latent gap; the graph API treats the
  filter as a hard requirement, not an inherited habit.)
- Traversal (§9) never crosses the caller's tenant subtree: edges to out-of-subtree entities are
  cut from results, not exposed as stubs. `same-as` collapse applies the same cut before merging
  (§3).
- The tenant tree itself is mirrored into the graph (`tenant:*` entities, `contains` edges,
  sourced from the authoritative `TenantStore`) so tenancy is traversable like any other
  structure — but authorization always uses the denormalized owner attribute, never a graph
  traversal.

### 8. Cases overlay the graph; the graph never references cases

A **case** is a human construct — an investigation workspace — layered over discovered reality:

```
case = (case_id, tenant, ticket, status, pins[], content[])
ticket  = fields{ title, client, contact, priority, category, … }
          — each field carries its own source (email | caller-id | psa | operator | inferred)
            and filled/missing state; per-field provenance is load-bearing in the UI
pin     = (ref, annotation, author, pinned_at)
  ref   : eid | edge identity | observation/version | drift record
          | (subject, time-range)          — a range is always anchored to a subject
content = typed entries: finding | transcript-entry | note
          — the prepared-investigation narrative (email intake) and live-call transcript
            are case content, not graph references
```

- Cases live in a standard storage business store (`case_store`), **not** in the graph. The
  dependency is one-way: cases hold typed references into the graph; no graph record knows about
  cases. Discovered reality stays clean of workflow state.
- A case is one-to-many with entities by construction, and accretes pins as an investigation
  widens. Every pin must satisfy the case tenant's visibility at pin time; pins to knowledge that
  later goes stale or is retracted remain valid — they resolve through history (§5), so a case
  file still shows what was known when it was pinned.
- **The case's tenant is its visibility ceiling** — intended behavior: an incident on MSP-shared
  infrastructure that spans sibling clients is opened at the MSP tenant, whose subtree covers
  both. A client-scoped case cannot pin outside its subtree, by design.
- Case *workflow* (intake automation, chat, specialist bots, PSA/CRM lookups, remediation
  approval) is cockpit-epic scope; this clause fixes the storage shape and the case↔graph
  relation only.

### 9. The access contract

Two contracts, deliberately asymmetric: many readers, one disciplined write path.

**Read operations** (cockpit, twin, DEX, future consumers — all reads accept `as_of`, all carry
the mandatory tenant filter, and entity-targeted reads accept a `same-as` collapse-group option):

| Operation | Answers |
|---|---|
| `GetEntity(eid, opts)` | current state + provenance + freshness (+ collapsed `same-as` view) |
| `GetDesiredState(eid)` | desired state + originating config revision |
| `QueryEntities(filter, page)` | entities by type / attribute predicates / text, paged |
| `GetEdges(filter)` | edges by endpoint / type / source |
| `GetNeighborhood(eid, edge_types, direction, depth)` | connected subgraph; depth default 2, contract max 3 |
| `GetHistory(subject, range)` / `Diff(subject, t1, t2)` | versions over time; delta between two times |
| `GetTimeline(subjects[], range)` | merged state-change + drift + apply-outcome event stream |
| `GetDriftState(eid)` / `ListDrifted(filter)` | persisted drift-diff (full compared field set); fleet drift survey |
| `Watch(filter, cursor)` | durable, cursor-replayable change feed of entity/edge/drift events |
| `ResolveIdentity(claims)` | best-known `eid`(s) for device/object identity claims ("caller says PC-0231") — *not* a PSA/CRM contact lookup |

Traversal is **depth-bounded neighborhood expansion, not a general graph query language** — a
deliberate contract restriction (with the explicit depth cap) so both relational and
property-graph backends can implement it without contortion; every cockpit/twin/DEX need
identified so far composes from these operations.

**Boundary: telemetry and DEX signals.** Per ADR-017 clause 4 / A1.4, live performance and
experience data (latency, resource use, app-hangs) is telemetry — it is **not stored in and not
served by** the entity graph. The contract's guarantee is the **join**: telemetry and DEX signals
are addressed by `eid` (Amendment 2 form), so any signal store can be joined to graph topology by
identity. A cockpit view like "2 of 3 dependents degraded ×4 latency" is composed at the API/UI
layer from `GetNeighborhood` (topology) + an eid-keyed signal read served by the
telemetry/DEX pipeline — whose read surface is that epic's contract, not this one's.

**Write contract** (collectors only): `ReportObservations(batch)` — a batch of §4 observations
under one source identity, with optional claim-scope declarations — plus one narrow workflow
write, `UpdateDriftLifecycle(record, transition, actor)` (§6). The correlator (§3), the
ConfigStore desired-state ingest (§6), and lifecycle closure (§4) are internal writers using the
same observation primitive. Consumers never write knowledge; a technician "adding" a manual
`depends-on` edge is a source (`operator:<user>`) reporting an observation — fully provenanced,
fully retractable, no privileged side door.

**Serving:** REST subrouters (`/api/v1/entities`, `/api/v1/cases`) follow the existing pattern —
`requirePermission` wrapping plus the mandatory in-handler tenant-subtree filter (§7). For live
updates, the durable cursored `Watch` feed is **new machinery** (nothing in `pkg/storage` or the
transport layer provides it — §10 constraint 5); the existing telemetry-WebSocket pattern
(`features/controller/transport/telemetry_handler.go`) is reused only as the browser fan-out
transport in front of it.

### 10. Provider shape, and the constraints handed to the storage-shape ADR

The Entity Graph is a **new pluggable central provider** (`pkg/entitygraph`): contract in
`interfaces/` (operations of §9 + provider registry), implementations under `providers/`,
`interfaces/contract_test.go` run against every implementation, business logic imports interfaces
only. It clears the central-provider gates: consumed by >1 feature (cockpit, asset page, twin,
DEX); it composes *above* `pkg/storage/interfaces` rather than overlapping it (storage stores;
the graph models, resolves, and queries). Write-through caching via `pkg/cache.Cache` per house
style. The `case_store` is a standard storage business-store contract, not part of the provider.

**Disposition of `pkg/directory`'s overlapping surface.** The directory provider remains the
*integration* layer (connection, sync, auth against directory backends) and becomes a **collector**
writing observations. Its own relationship/history/drift query surfaces
(`DirectoryRelationships`, directory history, directory drift detection) are **subsumed by the
entity graph and retired as consumers migrate** — two stores of relationship truth is exactly the
pocket-fragmentation this ADR exists to end. Dependency direction is one-way: directory-sync
feature code depends on the entitygraph write contract; `pkg/entitygraph` never imports
`pkg/directory`.

The follow-up **storage-shape ADR** chooses the physical backend. It inherits these firm
constraints from the model — surfaced here so they are inputs, not discoveries:

1. Append-only observation log with content-hash dedup and two-timestamp (bitemporal-lite)
   versioning (§4–§5).
2. As-of-T projection, two-point diff, and merged timeline as first-class queries, including
   collapse-group resolution (§5, §3).
3. Depth-bounded (≤3) neighborhood traversal over typed directed edges — no requirement for
   arbitrary traversal (§9).
4. Mandatory tenant-subtree filtering on every read path (§7).
5. A **durable, cursor-replayable change feed** serving `Watch` — new machinery; no existing
   storage or transport primitive provides it (§9).
6. Claim-scoped enumeration resolved at ingest by set-difference against the source's prior claim
   set (§4). *Known tension:* this ingest work is O(scope size) per enumeration, not
   change-proportional — storage *growth* tracks change volume (constraint 7) but enumeration
   *ingest cost* does not; the backend design must absorb full-scope re-enumerations (directory
   sync, cluster snapshot) at fleet scale.
7. Scale envelope: 50k+ stewards × per-host fragment counts, with storage growth proportional to
   change volume (§5); graph reads are interactive (cockpit) — the hot path is
   neighborhood + current-state projection, not analytics.

---

## Dependencies

This ADR's model is buildable only on top of work that is defined but **not yet implemented**:

1. **ADR-017 fragment model + fragment-addressed versioned history** (the DNA-composition /
   baseline-DNA epic). Today `commonpb.DNA` is still the flat map and `DNARecord` versions whole
   flat snapshots — per-eid state, history, and drift all presuppose fragments. That epic is a
   hard predecessor of the entity-graph epic — and **it is not yet filed**. The predecessor
   chain per the roadmap is: module foundation (epic #2460, closed) → **OSquery integration
   epic (unfiled)** → **DNA-composition / baseline-DNA epic (unfiled)** → this. (ADR-017's
   mention of epic #2418 is a citation of the rework obligation recorded in that Hyper-V
   epic's *ADR Alignment* item 1, not the DNA epic's number.)
2. **ADR-016 module `owns:`/fragment emission** — the identity declarations collectors report
   under.
3. **Collector refactors** (Consequences, Negative 1) — the graph is only as populated as its
   sources; the cockpit MVP slice needs at minimum the steward drift/apply shipping and the
   Hyper-V edge mapping.

---

## Cockpit MVP — sufficiency check

The mockup's evidence cards and case chrome, mapped honestly: **Served** = this contract;
**Composed** = this contract joined with another subsystem's surface; **Out of model** = another
epic's deliverable the cockpit consumes directly.

| Mockup element | How it's answered | Backend work it implies |
|---|---|---|
| Drift-diff hero — desired vs actual on `sql-primary`, ✓-matching fields, "intent r2291", "last_apply r2291 partial (lock timeout)" | **Served**: `GetDriftState` + `GetDesiredState` (revision-labeled) + apply-outcome records (§6) | steward ships StateDiff-based drift + apply outcomes, re-keyed to eid |
| Blast radius — dependency graph topology, "3 dependents" | **Served**: `GetNeighborhood(eid, {depends-on, serves, runs-on}, depth 2)` | edge ingestion from collectors + operator-asserted edges |
| Blast radius — "×4 latency" / degraded-health coloring | **Composed**: topology from `GetNeighborhood` joined by eid with a telemetry/DEX signal read (§9 boundary) | eid-addressed signal pipeline + its read surface (DEX epic) |
| Change timeline — drift, config-push r2291 | **Served**: `GetTimeline` (config pushes are desired-state observations, §6) | desired-state ingest from ConfigStore |
| Change timeline — "Ticket #4821 opened", remediation staged | **Composed**: cockpit merges case_store / workflow events with the graph timeline client-side | case/workflow event surfaces (cockpit epic) |
| Ticket quick-reference — per-field source badges, missing-field state | **Served** (storage shape): `case_store` ticket fields with per-field provenance (§8) | case_store + intake fill (workflow out of model) |
| Contact/Category fill from caller-ID / PSA | **Out of model**: PSA/CRM integration (cockpit epic). `ResolveIdentity` covers only device-claims → eid | PSA integration |
| Investigation findings / live-call chat | **Served** (storage shape): case `content[]` streams (§8); authoring workflow out of model | cockpit epic |
| Case bar, pins, accretion across endpoints | **Served**: `case_store` CRUD + pins (§8) | case_store |
| Live updates during a call | **Served**: `Watch` cursor feed + WebSocket fan-out (§9) | new durable change feed |

Sparse population is acceptable by constraint 2. With the dependency chain (§ Dependencies) and
the MVP collector refactors landed, every **Served** row renders from real data on a
Hyper-V-managed fleet; **Composed/Out-of-model** rows degrade gracefully (topology without
health coloring; timeline without ticket events) rather than blocking the screen.

---

## Out of Scope

- **Physical storage** — engine choice, partitioning, replication, sync mechanics (the follow-up
  storage-shape ADR; §10 fixes its inputs).
- **Telemetry/DEX signal storage and read surface** — the graph guarantees eid-addressability
  (the join), not signal serving (§9 boundary; DEX epic).
- **Wire encodings** — proto shapes for observation batches and the module edge-emission channel
  are epic-level implementation of §4/§9.
- **The full taxonomy contents** — this ADR fixes the registry mechanism, seed sets, the
  `related:<discriminator>` escape, and governance; enumerating every entity/edge type is story
  work as collectors are refactored.
- **Case workflow** — intake automation, chat, specialist bots, PSA/CRM integration, remediation
  approval (cockpit epics). §8 fixes the case storage shape only.
- **Correlator matching rules** — §3 fixes the mechanism (claims → `same-as` → collapse-on-read
  with tenant cut); rule quality iterates as story work.

---

## Consequences

### Positive

1. **One accumulation point.** Discovered knowledge compounds product-wide instead of dying in
   collector-local structs; every new module/integration enriches the same graph the cockpit,
   twin, and DEX read.
2. **The cockpit MVP is buildable** against a contract whose sufficiency is itemized honestly —
   served vs composed vs out-of-model — so decomposition can scope each row without mid-epic
   surprises.
3. **Twin/DEX land as views and joins, not rebuilds** — identity, provenance, history, and edges
   are the Tier-1/Tier-2 roadmap commitments honored in one place; the telemetry boundary keeps
   ADR-017 clause 4 intact while making DEX joinable.
4. **Multi-source truth is safe by construction**: single-authority resolution with a defined
   precedence order, retained dissent, claim-scoped retraction with lifecycle closure,
   correlation-not-merge with a tenant-cut collapse rule — no collector can corrupt another's
   knowledge, wrong joins are reversible, and collapse cannot leak across tenants.
5. **The storage conversation inherits firm inputs** (§10), including its known cost tension,
   instead of re-deriving the model.

### Negative

1. **Collector refactors are real work** (accepted by direction): the module contract gains an
   observation/edge-emission channel; Hyper-V maps `ClusterStatus`/`RoleOwners`/`SwitchName`/
   `HARole`/`ManagedElsewhere` onto typed edges under cluster-scoped authority; the directory
   layer maps `DirectoryRelationships`/`GroupMembership`/`OUHierarchy` onto edges; the steward
   ships StateDiff-based drift, apply outcomes, and observed-change events re-keyed to eid; GDAP
   maps to `delegated-access`. Each is mechanical against §4 but touches shipped code.
2. **New controller machinery**: ingest + resolution + correlator + projection + durable change
   feed — the provider is a genuinely new subsystem, not a wrapper.
3. **Hard-gated on the DNA-composition epic** (Dependencies) — the entity graph cannot ship
   per-eid state or history until fragments exist; sequencing is explicit, not discovered.
4. **Taxonomy governance is a standing obligation**: entity/edge types are versioned registry
   changes, with the discipline that implies (softened by the `related:*` escape).
5. **`pkg/directory`'s query surfaces are retired** as consumers migrate — deliberate
   consolidation, but a migration with consumers to move.
6. **Two id-shaped concepts coexist** until collector refactors complete: legacy name-references
   inside config state (e.g. `SwitchName`) and graph edges. The refactor epics retire the former
   as the source of record; config remains the desired-state input, the graph the knowledge
   record.

### Neutral

- The existing fleet DNA history store (`DNARecord`) remains the fragment-state substrate once
  the DNA-composition epic rebuilds it fragment-addressed; the graph's history projection
  lineages over it rather than duplicating it. How literally that reuse happens is a storage-ADR
  concern.
- Audit records keep their own store and rules; audit `resource_id` values should converge on
  `eid` format opportunistically, not as a migration.
- ADR-017 gains Amendment 2 (§1) at acceptance of this ADR — a recorded supersession, not a
  silent drift.

---

## Alternatives Considered

### Extend the DNA fragment store into the graph

DNA is a per-host, hashed, sync-validated artifact with strict determinism invariants (ADR-017
clauses 5–7). Edges span hosts and sources, are multi-source and confidence-weighted, and must
never enter the hash. Forcing them into DNA either breaks sync determinism or smuggles knowledge
around the hash — **rejected**; the graph joins *on* DNA identity instead of living inside DNA.

### Fold telemetry/DEX signals into the graph

Would give the cockpit one read surface — and destroy the stable-knowledge/ephemeral-stream
separation ADR-017 clause 4 exists for (hash stability, storage volume, retention semantics).
The eid join delivers the composed view without merging the stores — **rejected**.

### Keep relationships as attributes inside each resource's state (status quo)

This is today's shape: edges buried as opaque keys in `ConfigState` maps, invisible outside the
owning collector, single-source, not cross-host addressable, not queryable. It is precisely the
"model built for the collectors" the direction forbids — **rejected**.

### Adopt the directory layer's `Relationship` schema as the product model

`pkg/directory`'s `Relationship{Type,TargetType,Cardinality}` is a schema *descriptor* for
directory object classes, not instance data, and is directory-scoped. It becomes one taxonomy
input — **rejected as the model**.

### Destructive merge of correlated entities

Merging records when identity claims match loses provenance, and un-merging after a wrong match
is unrecoverable in an append-only store. `same-as` + collapse-on-read gets the same read
ergonomics with reversibility — **rejected**.

### Cases as entities inside the graph

Modeling investigations as graph nodes lets workflow state contaminate discovered reality,
entangles case ACLs with graph traversal, and makes "what does CFGMS know" depend on "what are
humans doing." One-way references keep both models honest — **rejected**.

### A general graph query language in the contract

Exposing arbitrary traversal/pattern queries would bind the contract to backends that can execute
them, pre-deciding the storage conversation this ADR explicitly defers. Every identified consumer
need composes from typed lookups, filtered queries, depth-bounded neighborhoods, temporal reads,
and a change feed — **rejected** (revisit only with a concrete consumer need that cannot compose).

### Design the model after choosing storage

Inverts the dependency: the store would shape the model, which is the same trap as
collector-shaped modeling. The model here is implementable by more than one backend family by
construction (§9 restriction, §10 constraints) — **rejected**.

---

## References

- [ADR-016](016-steward-module-foundation.md) — module `Get` → canonical fragment; `owns:`
  identity declarations
- [ADR-017](017-dna-composition-and-sync.md) + Amendment 1 — fragment model, authority resolver,
  typed entity id, provenance envelope, versioned history; names this ADR as its companion.
  §1 here proposes **Amendment 2** (eid supersedes bare `fragment_id` for fleet-global
  addressing) to be recorded on acceptance
- [ADR-003](003-storage-data-taxonomy.md) — storage data taxonomy the `case_store` and provider
  compose with
- [ADR-021](021-identity-assurance-levels.md) — step-up model the cockpit's REST surface rides
- `docs/product/roadmap.md` — Digital Twin & DEX tiered rollout (Tier-2 graph, temporal query,
  unified entity query API); Captured Backlog
- `docs/design/mockups/troubleshooting-cockpit.html` + `docs/design/web-ui-design-system.md`
  — the consuming surface (case model, evidence canvas)
- `features/modules/hyperv/cluster.go`, `pkg/directory/dna/interfaces.go`,
  `pkg/storage/interfaces/business/tenant_store.go` — today's relationship pockets (refactor
  targets)
- `pkg/dna/drift/drift.go`, `features/steward/steward.go` (StateDiff `:428`, DNA-ID mismatch
  `:375`), `features/controller/heartbeat/service.go` — drift today (steward-local, ephemeral)
- `features/controller/fleet/storage/` — versioned per-device DNA history (existing substrate;
  flat-map-addressed until the DNA-composition epic)
- `features/controller/transport/telemetry_handler.go` — WebSocket fan-out transport reused in
  front of the new `Watch` feed
