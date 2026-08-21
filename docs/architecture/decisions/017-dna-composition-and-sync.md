# ADR-017: DNA Composition & Sync — fragment model, authority resolution, and partial-sync validation

**Status:** Accepted (2026-07-08)
**Date:** 2026-07-04
**Amended:** 2026-07-07 — [Amendment 1](#amendment-1-2026-07-07--twindex-data-model-commitments): twin/DEX Tier-1 data-model commitments (provenance envelope, typed entity id, versioned history retention, shared entity identity for DEX); 2026-07-21 — [Amendment 2](#amendment-2-2026-07-21--fleet-global-addressing-is-the-eid-adr-022): fleet-global addressing is the `eid` (ADR-022); 2026-07-23 — [Amendment 3](#amendment-3-2026-07-23--existing-gatherers-are-the-interim-observe-only-host-fact-authority): existing gatherers as interim observe-only host-fact authority; 2026-08-15 — [Amendment 4](#amendment-4-2026-08-15--dnatransferattributes-retired-from-the-full-sync-wire-protocol): `DNATransfer.Attributes` retired from the full-sync wire protocol
**Issue:** #2901
**Epic:** #2852 — DNA composition — fragment model, authority resolver, partial sync, fragment history in the Entity Graph (ADR-017)

---

## Context

DNA is CFGMS's deterministic, hashable representation of a host's state. Its purpose is mutual validation: the steward assembles DNA, the controller holds a copy, and after a **partial** update both sides must be able to confirm the controller's copy is **fully in sync** with the steward's actual state — cheaply, without re-transferring everything.

### Current implementation

Today DNA is a **flat `map[string]string`** assembled by a monolithic `Collector` (`features/steward/dna/dna.go`) whose platform-specific gatherers (`hardware_*.go`, `network_*.go`, `security_*.go`, `software_*.go`) fill categories of attributes. A single `ComputeHash(attributes)` hashes the entire map; heartbeats carry that fingerprint. `commonpb.DNA` is the wire type.

This model has three structural limits:

1. **No per-object addressing.** A single whole-map hash means any change rehashes everything. The controller cannot validate or request an individual object; partial sync cannot prove that applying a delta brought its copy fully into sync at object granularity.
2. **Bespoke gathering that duplicates modules and osquery.** The monolithic collector re-reads state that managed modules already compute in `Get`, and re-implements per-platform host-fact collection that osquery does natively — the "build our own osquery" duplication.
3. **No notion of source or authority.** An attribute has no owner, so there is no way to say "this object is managed (enforce drift)" vs "this is an observed fact (report only)."

### What ADR-016 provides

ADR-016 requires every module's `Get` to emit a **canonical DNA fragment** per managed object, and requires modules to **declare the object identities they own**. This ADR defines how those fragments — plus curated osquery facts — **compose** into DNA, how **authority** resolves between them, and how **sync + partial validation** work.

### Pre-production posture

CFGMS has no production deployments. The `commonpb.DNA` wire type is redefined cleanly (flat map → fragment set); no migration shims or dual-format support are built (per the project's pre-release breaking-change policy).

---

## Decision

### 1. DNA is a set of addressable fragments

DNA is redefined from a flat attribute map to a **set of fragments**. Each fragment is:

```
fragment = (fragment_id, authority, canonical_bytes, fragment_hash)
```

- **`fragment_id`** — the **object-canonical identity**, stable regardless of which source produced it: `service:sshd`, `file:/etc/hosts`, `user:svc-cfgms`, `host:cpu`, `host:memory`, `host:os`. A service is `service:sshd` whether osquery observed it or the `service` module manages it.
- **`authority`** — the source that produced this fragment on this host right now: a module identity, or `osquery`.
- **`canonical_bytes`** — the fragment's state under the canonical serialization (clause 5).
- **`fragment_hash`** — SHA-256 of `canonical_bytes`.

### 2. Two sources, single authority per fragment — the resolver

A fragment's `authority` is resolved at assembly time, per object, **atomically** (whole fragment, never per-field — ADR-016 clause 5):

```
for each object the host exposes:
    if an ACTIVE module declares ownership of this fragment_id → module is authority (module.Get)
    else if fragment_id is in the curated osquery stable-fact allowlist → osquery is authority
    else → no fragment
```

**Module authority preempts osquery.** Installing a module that owns `service:sshd` makes it the authority; osquery stops contributing `service:sshd` **to DNA** (osquery may still be queried ad-hoc). Uninstalling reverts authority to osquery if the fact is in the allowlist, else the fragment disappears. Because `fragment_id` is object-canonical, the handoff is a source swap on the same id — the fragment's content and hash legitimately change (observed view → managed view), and that change is a real, desirable "this is now managed" transition the controller should see.

The resolver runs in the steward's DNA assembler and consults the **active-module registry** for the ownership declarations ADR-016 requires.

### 2a. Managed objects source their fragment from the module — not a second reader

For a managed object, the fragment **is** the module's `Get` output. The steward does not also read that object through a separate path and reconcile. Single source of truth = the enforcer. This is what keeps the fragment deterministic and avoids the two-readers-disagree failure that breaks hash validation.

### 3. Fragment class: managed vs observe-only — gates drift

Every fragment carries its class, derived from `authority`:

| Class | Authority | Drift behavior |
|---|---|---|
| **managed** | a module | Drift modes apply (`auto_correct` / `report_only`) — the object has a desired state to enforce |
| **observe-only** | osquery | No drift correction — you cannot "correct" total RAM or CPU model; report only |

The class is not bookkeeping: the convergence loop uses it to decide which fragments are enforceable. Only managed fragments enter drift correction.

### 4. Stable state only — telemetry is excluded

DNA fragments contain **only stable, desired-comparable state**. Ephemeral runtime values — live PIDs, current CPU/memory utilisation, uptime, per-process resource use — are **not DNA**. They belong to the monitor-stream / telemetry pipe (a separate, unhashed channel; the asset-page live views), which is out of scope here.

Consequently osquery contributes to DNA **only** through a curated **stable-fact allowlist** (e.g. `host:cpu` model, `host:memory` total, `host:bios`, `host:os` build) — never its dynamic tables (`processes`, live counters). Its dynamic tables serve ad-hoc queries and telemetry, both outside DNA. This is the rule that keeps the aggregate hash stable instead of flapping every second.

### 5. Canonical serialization

Both module and osquery fragments serialise under one canonical scheme: **fixed field ordering, normalised value encoding, no host-local or run-local noise** (timestamps, ordering artifacts). The requirement is: identical observed state ⇒ identical `canonical_bytes` ⇒ identical `fragment_hash` on the steward and independently on the controller. Without this, the two sides cannot agree on a hash and sync validation is impossible.

### 6. Two-level hash — per-fragment + aggregate root

DNA has a **two-level (Merkle-style) hash**:

- **Per-fragment hash** — `fragment_hash` over each fragment's `canonical_bytes`.
- **Aggregate root** — a hash over the **manifest**: the set of `(fragment_id, fragment_hash)` pairs, sorted by `fragment_id`.

The aggregate root is what heartbeats carry (replacing today's whole-map fingerprint). It changes iff any fragment's content, or the set of fragments, changes.

### 7. Partial-sync protocol

```
1. Steward heartbeat carries the aggregate root (and, on request or by policy, the manifest:
   the list of (fragment_id, fragment_hash)).
2. Controller compares the root to its stored copy.
   - match → in sync, done.
   - mismatch → controller diffs manifests to find changed/added/removed fragment_ids,
     requests only those fragments' canonical_bytes over the data plane.
3. Controller applies the delta, recomputes the aggregate root over its updated manifest,
   and confirms it equals the steward's root.
```

Step 3 is the **partial-sync validation** the model exists for: because both sides compute the root identically from identical fragments (clause 5), a matching recomputed root proves the controller's copy is now **fully in sync** with the steward — validated by the delta alone, no full re-transfer. "Completeness" here means *the controller's view equals the steward's view*, which is exactly what a partial sync must guarantee.

### 8. The curated osquery fact list is deferred, but its contract is fixed here

The specific osquery queries that populate `host:*` fragments are **not** enumerated in this ADR — they are defined after the stdlib set is confirmed (ADR-016 clause 1), because the managed surface determines the unmanaged remainder. What is fixed here is the **contract**: osquery facts enter DNA only via a curated **stable-fact allowlist**, each mapped to an object-canonical `host:*` `fragment_id`, each **observe-only**, never from dynamic tables.

---

## Out of Scope

- **The enumerated osquery query list** — a story deliverable gated on ADR-016 clause 1.
- **Monitor-stream / telemetry design** — the live process/service/resource views (asset page); a separate unhashed pipe.
- **Drift-correction mechanics** — the existing drift subsystem (`features/steward/dna/drift`); this ADR only gates it by the managed/observe-only class.
- **Module `Get` fragment wire shape** — ADR-016 owns the requirement; the proto/serialization detail is an implementation concern of that epic.

---

## Consequences

### Positive

1. **Cheap, provable partial sync**: object-level deltas plus an aggregate root that validates the controller's copy is fully in sync — no whole-DNA re-transfer.
2. **Single-authority determinism**: every fragment has exactly one source; the object-canonical id + atomic resolution make the hash reproducible on both sides.
3. **No duplicated gathering**: managed state comes from module `Get`, host facts from osquery; the bespoke per-platform collector is retired rather than extended (kills the "build our own osquery" risk).
4. **Managed/observed separation**: drift correction is cleanly gated to enforceable fragments.
5. **DNA richness scales with stdlib**: each stdlib module added (ADR-016) contributes managed fragments, shrinking the osquery-fact remainder.

### Negative

1. **Breaking proto redesign**: `commonpb.DNA` changes from flat map to fragment set — acceptable pre-production, done as a clean break with no shims. Everything reading/writing DNA (heartbeat, controller store, delta transfer) changes with it.
2. **Collector decomposition**: the monolithic `Collector`'s gatherers must be reclassified — managed categories migrate into module `Get` (`user`, `hostname`, etc. per ADR-016), unmanaged host facts migrate to the osquery allowlist. Real refactoring, not a rename.
3. **New steward + controller machinery**: the assembler, the authority resolver, fragment-addressable controller-side DNA storage, and the delta protocol are new.
4. **Depends on osquery + stdlib**: the `host:*` fragment layer needs the osquery integration (#2), and authority resolution needs the module ownership declarations (#3 / ADR-016). This epic sits downstream of both.

### Neutral

- The existing `hardware/network/security/software` gatherers are reclassified (→ module `Get` or osquery fact), not deleted — the logic mostly relocates.
- Read-only DNA fragments that ADR-016 noted (users/hostname under `features/steward/dna/`) become the seed for the corresponding modules' `Get`.

---

## Alternatives Considered

### Keep the flat map + single hash, add map-diff partial sync

Diff the two attribute maps to compute a delta.

**Rejected:** no per-object authority, no managed/observed distinction, a single change still rehashes the whole map, and the source duplication (modules + bespoke collector both reading state) persists. Map-diffing transfers less but proves nothing about object-level completeness.

### Field-level (sub-fragment) authority

Let a module own some fields of an object and osquery the rest.

**Rejected (ADR-016 clause 5):** two sources on one fragment can disagree by a field, making its hash non-deterministic and breaking sync validation. Authority is atomic per object.

### osquery as the sole DNA source, including managed objects

Read everything — even managed objects — from osquery.

**Rejected:** osquery cannot enforce, so the module is already the source of truth for what it manages; sourcing the same object from osquery too creates the two-readers-disagree hazard and demotes the enforcer's own view. Modules own managed fragments; osquery owns the unmanaged remainder.

### Keep a bespoke per-platform fact collector instead of osquery

**Rejected:** reinvents osquery per platform (the clone risk that motivated sequencing osquery before baseline DNA), with a perpetual per-OS maintenance burden and no ad-hoc query surface.

---

## References

- [ADR-016](016-steward-module-foundation.md) — Steward Module Foundation (provides `Get`→fragment + `owns:` declarations)
- [ADR-020](020-dna-required-field-declaration.md) — DNA Required-Field Declaration: defines the per-configuration-type required-field contract that rides this ADR's fragment model and authority resolver. Extends the `owns:` clause (ADR-016 clause 5) with a `required_fields` list; the resolver clause 2 defines here is the runtime that applies the union of required fields at DNA write time.
- [ADR-006](006-module-packaging-and-distribution.md) — Module Packaging and Distribution
- `features/steward/dna/dna.go` — current `Collector`, `ComputeHash` (redefined by this ADR)
- `features/steward/dna/drift` — drift subsystem gated by the managed/observe-only class
- `docs/product/roadmap.md` — Captured Backlog (OSquery, controller baseline DNA) + [Digital Twin & DEX — Tiered Rollout](../../product/roadmap.md#digital-twin--digital-employee-experience-dex--tiered-rollout) (the Tier-1 commitments this amendment lands)

**Flat-DNA-surface consumers to re-home on the fragment model.** Two shipped
consumers read/write today's flat attribute map directly and must be migrated
onto fragments when the DNA-composition epic is decomposed (that epic is not
yet filed; the rework obligation is recorded as *ADR Alignment* item 1 in epic
#2418 — the cluster.cfg cascade epic those consumers shipped under): the
steward-side ChangeEvent→DNA attribute bridge
(#2423/#2435 — module Monitor engine events surfaced as DNA attributes) and the
controller-side cluster-registry parser (#2424 — cluster membership parsed from
steward DNA attributes). Both are attribute-key contracts on the flat surface;
re-homing them is in scope for that epic, not this ADR.

---

## Amendment 1 (2026-07-07) — Twin/DEX data-model commitments

**Status:** Accepted (2026-07-08, rider on this ADR)

**Context.** A product-planning session (roadmap.md v4.1, *Digital Twin & DEX — Tiered Rollout*) established that the Digital Twin and Digital Employee Experience (DEX) capabilities ship as layers threaded across the timeline, built on the **same DNA foundation this ADR defines**. Four data-model commitments are cheap to honor in this epic and expensive to retrofit later; the baseline-DNA / DNA-composition epic **must** land them. Each is deliberately designed to preserve the base ADR's invariants — hash determinism (clause 5) and telemetry exclusion (clause 4) — by adding *around* the fragment, never *inside* the hash.

### A1.1 — Fragment provenance & freshness travel in an envelope, never in the hash

Every fragment gains a **provenance envelope** carried alongside `canonical_bytes` but **excluded from `canonical_bytes`, `fragment_hash`, the manifest, and the aggregate root**:

```
fragment_envelope = (source, observed_at, confidence)
```

- **`source`** — the concrete producer instance (which module version, or that osquery ran the read). Distinct from `authority` (clause 2), which is the *role* that won resolution; `source` is the *provenance* of this specific read.
- **`observed_at`** — when the steward last confirmed this fragment's state.
- **`confidence`** — producer-declared reliability of the read. A module that partially fails to read an object marks the fragment low-confidence rather than emitting a wrong-but-confident value.

**Invariant preserved.** Clause 5 forbids run-local noise (timestamps) inside `canonical_bytes` precisely so identical state hashes identically. The envelope honors this: it is metadata *about* the fragment, not fragment content. Two stewards with identical `sshd` state still produce identical `service:sshd` fragment hashes even though their `observed_at` differ — so partial-sync validation (clause 7) is unaffected, while "how fresh / how sure is this?" becomes answerable.

### A1.2 — `fragment_id` is a first-class **typed entity id**; the type taxonomy is stable

Clause 1 already defines `fragment_id` as `type:name` (`service:sshd`, `file:/etc/hosts`, `host:cpu`). This amendment elevates the **`type` prefix to a first-class, enumerated entity type** — a stable, versioned taxonomy owned by this epic (seeded by the stdlib object kinds plus the `host:*` fact kinds), not an incidental naming convention.

This id is the **single shared identity** across three consumers, so they join for free:

- **DNA** — the fragment (this ADR).
- **Topology graph** (twin Tier 2) — graph **nodes are typed entities**; edges (`runs-on`, `depends-on`, `serves`, …) connect `fragment_id`s. No separate node-identity scheme.
- **DEX telemetry** (Tier 2/3) — experience signals are addressed **to** a `fragment_id` (A1.4).

A per-consumer id scheme would be the expensive retrofit this clause prevents. The taxonomy must therefore also cover entity kinds that DEX/topology need but no stdlib module *manages* (e.g. `application:*`, `device:*`) — such entities may exist as osquery-observed or telemetry-only nodes with **no managed fragment**.

### A1.3 — The controller **retains versioned fragment history** (restores DNA "memory")

The base ADR describes the controller holding *a* copy and updating it in place via partial sync (clause 7). This amendment requires the controller-side DNA store to be **append-only / versioned**, not last-write-wins:

- Each accepted partial-sync delta produces a new **version** of the affected fragments, stamped with the aggregate-root version and ingest time; superseded fragment states are **retained, not overwritten**.
- Per-entity state becomes **queryable over time**: "what was `service:sshd` on 2026-06-01", "diff `host:os` over the last 30 days", "when did this fragment last change".
- History is **cheap by construction**: `fragment_hash` dedups unchanged fragments (an object unchanged across N syncs stores one state row plus version pointers), so storage tracks *change volume*, not fleet-size × time. Retention depth is a configurable policy.

**Why here, not later.** Current-state-only is a lossy write. Once the controller overwrites, the history is gone — no Tier-2 temporal query, no Tier-3 DEX baseline/trend, no config-change→effect correlation can be reconstructed after the fact. This closes the "DNA lost its memory" gap. It changes **controller storage only** — not the wire protocol, the hash, or the steward.

### A1.4 — DEX signals & graph edges address typed entities; telemetry stays non-DNA

Clause 4's exclusion stands: DEX experience signals (app-hang, I/O wait, boot/login duration, per-process resource use) are **telemetry, not DNA**. They flow on the separate unhashed monitor-stream pipe and never enter fragments, the manifest, or the hash.

The single commitment this rider adds: that telemetry is **addressed to the same typed `fragment_id`s** (A1.2). A DEX signal for QuickBooks references its `application:*` entity; a per-process metric references its owning entity. This keeps clause 4 intact while making DEX baselines and root-cause a **join** against DNA + the topology graph rather than a parallel, unjoinable data island.

### Consequences of the amendment

- **Invariants held.** Hash determinism (A1.1 keeps metadata out of the hash), single-authority atomicity (unchanged), telemetry exclusion (A1.4 keeps signals out of DNA). The rider adds around the fragment, not inside it — partial-sync validation is untouched.
- **Wire additions are additive.** The provenance envelope (A1.1) is additive metadata on the `commonpb.DNA` type; manifest and aggregate root are unchanged.
- **Controller storage is the real new work** (A1.3): fragment-addressable storage becomes version-addressable. This is the load-bearing change and must be scoped explicitly in the DNA-composition epic.
- **A companion storage-shape ADR is likely needed** for the Tier-2 topology graph (property-graph store) and the temporal query surface — flagged in roadmap.md, to be drafted separately. This rider guarantees only the **identity + history substrate** those build on. *(Both companions have since landed: [ADR-022](022-entity-graph-model-and-access-contract.md) — model and access contract — and [ADR-023](023-entity-graph-storage-shape.md) — storage shape, which also satisfies this amendment's A1.3 versioned-history requirement via its single observation-log store.)*

---

## Amendment 2 (2026-07-21) — Fleet-global addressing is the `eid` (ADR-022)

**Status:** Accepted (2026-07-21, recorded on acceptance of [ADR-022](022-entity-graph-model-and-access-contract.md))

[ADR-022](022-entity-graph-model-and-access-contract.md) §1 defines the fleet-global entity
identity as `eid = authority_segment [ "/" fragment_id ]` (a bare authority segment names the
asset as a whole). This supersedes, **in part**, two Amendment 1 statements:

- **A1.2** "no separate node-identity scheme": the single shared identity survives, but its
  fleet-global form is the two-part `eid`. `fragment_id` alone is not unique across a fleet;
  it remains valid **host-local shorthand** only where the authority is implied by transport
  context (a steward's own DNA sync, where the mTLS peer identity supplies the authority
  segment).
- **A1.4** "signals are addressed to a `fragment_id`": emitters of fleet-scoped data — DEX
  signals, topology-graph edges — carry the full `eid`.

Nothing else changes: the fragment model, hash determinism, authority resolution, partial-sync
validation, provenance envelope, and versioned history are untouched. The join-for-free property
A1.2 exists for is preserved in substance — DNA, graph nodes, and DEX signals still join on one
shared identity; ADR-022 §1 is authoritative for the grammar, the authority-type registry, and
the eid-constructor enforcement point.

## Amendment 3 (2026-07-23) — Existing gatherers are the interim observe-only host-fact authority

**Status:** Accepted (2026-07-23, rider on this ADR)

**Context.** Clause 2/clause 8 name osquery as the authority for unmanaged
`host:*` observe-only facts, and epic #2852 originally scoped retiring the
monolithic flat collector with those facts "going dark" until osquery lands. A
product review established this would cause a functional regression — the existing
per-platform gatherers (`features/steward/dna/{hardware,network,security}_*.go`)
already collect these facts and drive live consumers (role-selector
config-targeting #2546, the compliance Reports Engine, host-attribute views) — for
no benefit, since the collectors already work.

**Decision.** Until the osquery integration lands, the **existing gatherers are
the interim authority** for the curated `host:*` observe-only fragment allowlist
(clause 8). A partition step shapes a curated, stable, non-ephemeral,
non-module-owned subset of the already-gathered attribute map into `host:*`
fragments (canonical serialization + hash, clauses 5–6); the gatherers are
**reused unmodified** and the DNA proto `Collect` returns now carries **only the
`host:*` fragments**: the legacy flat `commonpb.DNA.attributes` field is no longer
written (Issue #3332). The gathered attribute map itself still exists behind
`Collector.RawAttributes`, because two consumers are not fragment-aware yet — the
`sync_dna` attribute payload the controller's required-field integrity check reads
(`hostname`, `os`), and the unmanaged-drift detector (`pkg/dna/drift`), which
compares flat maps and would report "no drift" unconditionally if fed empty ones.
Re-homing those two onto fragments, and deleting the flat map, belong to the
clean-break epic. The osquery epic later **swaps the source** of the same
`host:*` fragment ids from gatherers to osquery — a source change, observe-only
either way, invisible to fragment consumers.

**Invariants preserved.** This builds no *new* bespoke collector (the "build our
own osquery" trap clause 2/Alternatives warns of) — it retains existing working
collection until its declared replacement exists, as Consequences→Negative #4
already implied. Managed objects remain module-`Get`-sourced (clause 2a); the
module-ownership exclusion filter keeps gatherer output from ever competing with a
module-owned kind (clause 5 atomicity). The flat collector's full retirement and
the `commonpb.DNA.attributes` removal are deferred to a follow-on clean-break epic
that also re-homes the Reports Engine off the flat `DNARecord` store.

## Amendment 4 (2026-08-15) — `DNATransfer.Attributes` retired from the full-sync wire protocol

**Status:** Accepted (2026-08-15, Issue #3322)

**Context.** Amendment 3 noted two consumers that were not yet fragment-aware:
(1) the `sync_dna` attribute payload (`DNATransfer.Attributes`) that Amendment 3
described as feeding the controller's required-field integrity check, and (2) the
unmanaged-drift detector. Issue #3319 re-homed the required-field integrity check
onto `DNA.Fragments`, removing dependency (1). The `DNATransfer.Attributes` blob
was the only remaining use of the flat map on the full-sync wire path.

**Decision.** `DNATransfer.Attributes` is no longer populated by the steward on
the full-sync path (`features/steward/client/client_transport.go`) and is no
longer read by the controller's `reassembleDNA`
(`features/controller/transport/dna_handler.go`). Both ends are now
Fragments-only. The struct field itself (`pkg/dataplane/types/transfers.go`) is
retained until story #15 removes it, once the field is confirmed unused on both
ends.

The delta-sync path was already Fragments-only (it has never populated
`Attributes`) and is unaffected.

**`commonpb.DNA.attributes` is not retired by this amendment — the wire field is.**
The `common.DNA` that `reassembleDNA` returns is not merely a decode of the wire:
`ControllerService.SyncDNA` assigns it wholesale (`steward.DNA = dna`), making it
the controller's canonical steward record. Leaving its flat map unset would
therefore *erase* attributes fleet-wide on each steward's first full sync, and
these consumers have not yet been re-homed onto `DNA.Fragments`:

| Consumer | Effect of a blank map |
|---|---|
| fleet inventory, attribute filter, module list (`features/controller/api/handlers_stewards.go`) | hostname/OS/arch blank; attribute filters match nothing |
| DNA fingerprint, attribute projection, attribute index (`features/controller/fleet/storage/`) | OS/platform-scoped patch and vulnerability targeting resolves to zero hosts |
| re-registration change detection (`features/controller/service/controller_service.go`) | `AttributeCount` compares permanently 0 against a non-zero incoming count |

Each failure is fail-closed rather than fail-open, but silent and fleet-wide.

So `reassembleDNA` **derives** `DNA.Attributes`/`DNA.AttributeCount` from the
received fragments via `sdna.FlattenFragments` — the same projection the
required-field integrity check uses (`features/controller/service/dna_integrity.go`).
The wire stays Fragments-only, the fragments stay authoritative, and no wire-supplied
attribute can enter the record: a transfer that still carries an `Attributes` blob
has it ignored entirely (`TestReassembleDNA_IgnoresWireAttributes`). The projection
merges fragments in ascending `fragment_id` order so the DNA fingerprint the
controller hashes from it is stable across identical snapshots. The projection and
the two `commonpb.DNA` fields are removed together once the consumers above read
fragments directly (epic #2911).

**Steward-identity security gate.** The `firstChunk.GetStewardId() != peerID`
check in `HandleGRPC` gates all DNA ingest regardless of wire format; it precedes
`reassembleDNA` and is unaffected by the Fragments-only rewrite. No identity or
tenant check on the full-sync path was removed.

**Note.** Non-cluster module DNA (file, service, package resources) reaches the
controller through `CollectModuleFragments`, which emits fragments for every
monitored resourceID — not only `cluster:*` — since Issue #3333. The full-sync
projection above therefore covers the same resource set the flat attribute map
did.

**Amendment 4 (Issue #3330): fragment-based control-plane delta.** `PublishDNAUpdate`'s
lightweight change notification was re-homed from a flat `map[string]string` diff
(attribute delta) to a fragment-based delta. The skip-when-unchanged gate now compares
`[]*commonpb.Fragment` by `(FragmentId, FragmentHash)` pairs rather than flat key-value
equality. When any fragment is added, removed, or has a changed hash, the steward sends
**all current fragments** (not only changed ones) serialised as a protojson JSON array
string in `Details["dna"]`; `handleDNAEvent` on the controller decodes them via
`extractFragmentsFromDetails` and derives `DNA.Attributes` from `FlattenDNAFragments`
for legacy consumers. The integrity check (`checkDNAIntegrityWithTable`) is satisfied
because the full current set — which always includes `host:os` (carrying `hostname` and
`os`) — is transmitted on every delta publish.
