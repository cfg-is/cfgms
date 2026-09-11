# ADR-033: Audit Sink Architecture and Adversary Bound

**Status:** Accepted

**Date:** 2026-09-11

**Deciders:** Founder, Architecture

**Related:** Epic [#4033](https://github.com/cfg-is/cfgms/issues/4033) (audit sink
architecture — this ADR is Story 1 of 5). ADR-004 (audit chain integrity — carries a
pointer amendment to this ADR; see [Amends](#amends)). Issue #3727 (identified the
bound this ADR closes and deferred the shape choice). ADR-031 Decision 1 (database-side
sequence serialization that `AppendChainedEntry` now performs; this ADR's shipper
design depends on that serialization already existing).

---

## Context

ADR-004's Adversary Bound (Issue #3727) proved that the audit chain's HMAC key is
loaded from the controller's own secrets store and stays resident in the controller
process. A controller compromised at the host level — the threat model CLAUDE.md
names explicitly — already holds the key, and `TestVerifyChain_KeyHolderCanForgeConsistentChain`
(`pkg/audit/manager_test.go`) proves mechanically that such an actor can rewrite
history into a chain `VerifyChain` reports as fully consistent. Issue #3727 named two
credible shapes for closing this bound and deferred the choice. This ADR records that
choice.

### The two candidate shapes

1. **A signing oracle outside the controller's reach** (e.g. an external
   signer/HSM/KMS the controller calls to sign each entry but cannot read the key
   from).
2. **An append-only sink outside the controller's trust boundary** that the
   controller can append to but not rewrite.

---

## Decision (founder, 2026-09-10)

**Shape (2), an append-only sink outside the controller's trust boundary, is chosen
as the recommended default for production — but not as the only option, and never as
a hard requirement for a basic deployment.**

Neither shape stops a compromised controller writing false NEW entries; nothing can
— while it runs, the controller is the source of truth for events it generates. The
achievable goal is preventing rewriting of the **past**.

### Required shape

1. **The audit sink is pluggable**, following the central-provider pattern that
   already exists — see [Provider placement](#provider-placement) below. This is not
   a new provider; it extends `pkg/storage`.
2. **Local durable sink is the default.** A basic deployment comes up with zero extra
   infrastructure and still gets audit logging. That default carries today's ADR-004
   bound — documented honestly, not hidden. See
   [Per-sink adversary bound](#per-sink-adversary-bound).
3. **WORM / object-lock sink is the recommended production option**, selected by
   configuration.
4. **Never fail open.** No deployment shape may run with audit logging silently
   disabled or dropped. This is enforced through the existing requirements mechanism
   — see [Never-fail-open mechanism](#never-fail-open-mechanism) below — and is
   revert-proof by construction: downgrading the severity or removing the check is
   itself the regression a required test guards against (Story 3 of Epic #4033).
5. **Sink-unavailable behaviour: durable local buffer, then flush.** When the
   configured WORM sink is unreachable, entries are written to local durable storage
   and shipped to WORM once it returns. The controller keeps serving throughout.
   **Accepted residual risk:** buffered-but-not-yet-flushed entries carry the local
   sink's bound (see below) until they flush — a compromised controller can rewrite
   them in that window. This is deliberate, not an oversight; see
   [Rejected alternative](#rejected-alternative-fail-closed-on-sink-unavailability).
6. Startup logs which sink is active and states plainly when the weaker ADR-004 bound
   applies to that deployment.

### Provider placement

The audit sink is **already pluggable** — this ADR extends an existing contract
rather than creating a new central provider:

- `business.AuditStore` (`pkg/storage/interfaces/business/audit_store.go`) is the
  interface, including `AppendChainedEntry`.
- `StorageProvider.CreateAuditStore(config)` (`pkg/storage/interfaces/provider.go`)
  is the factory every provider implements.
- Implementations already live under `pkg/storage/providers/`.

`pkg/audit.Manager` is a **consumer** of that contract, not an owner of storage: it
holds the HMAC key and passes a checksum function into
`store.AppendChainedEntry(...)`. A second, parallel sink abstraction inside
`pkg/audit` would be exactly the overlapping-provider case CLAUDE.md forbids —
`make check-architecture` is the gate that enforces this.

**Structural constraint that shapes the WORM design.** `AppendChainedEntry`'s
contract makes it the sole authority for sequence assignment: the chain-head read,
the `SequenceNumber` / `PreviousChecksum` assignment, and the durable write happen
inside one serializing atomic operation, and implementations must not accept a
caller-assigned sequence (ADR-004 amendment, ADR-031 Decision 1, Issue #3754). An
object-lock / WORM target has no equivalent serializing head read. Therefore the WORM
sink **cannot be a drop-in `AuditStore` replacement** — it is a **forward-only
shipper of already-sequenced entries**, with the local durable store retaining
sequence authority. The local durable store is not merely a fallback for the WORM
sink; it is the sequencer, and buffer-then-flush (point 5 above) is the shape this
existing contract already implies.

The WORM shipper writes forward using
`pkg/storage/interfaces/blob.BlobStore.PutBlobIfAbsent` — see
[Per-sink adversary bound](#per-sink-adversary-bound) for exactly what that primitive
does and does not guarantee.

### Never-fail-open mechanism

`StoreNameAudit` is already declared in `pkg/storage/interfaces/requirements.go`,
alongside the `RequirementRequired` / `RequirementOptional` severity model: a missing
**required** store blocks composition and names the subsystem, store, and provider in
the startup error (`ValidateStorageRequirements`, Epic #3406). Point 4 above is built
on that existing mechanism — declaring the audit store `RequirementRequired` — rather
than a new one. Story 3 of Epic #4033 wires this declaration and proves it with a
test that fails if the severity is downgraded or the check removed.

---

## Per-sink adversary bound

**Local durable sink (default).** Identical bound to today's ADR-004: a
host-compromised controller holds the HMAC key (loaded from its own secrets store)
and can rewrite any entry's content, recomputing `SequenceNumber`,
`PreviousChecksum`, and `Checksum` for every entry from that point forward, producing
a chain `VerifyChain` reports as fully consistent. Stated plainly, not softened: this
sink alone does not close the bound ADR-004 documented. It is a compensating control
against storage-layer tampering by an actor who lacks secrets-store access, not
against controller compromise.

**WORM / object-lock sink.** This is the sink where overselling the bound is easiest
and most damaging, so the guarantee is split into two facts that must not be blended
into one claim:

- **What the code alone guarantees.** The shipper writes forward using
  `PutBlobIfAbsent` (`pkg/storage/interfaces/blob.BlobStore`), an atomic
  "create-if-absent" primitive: two concurrent writers targeting the same key cannot
  both succeed, and the controller's own shipper code path cannot silently
  double-write or clobber an already-shipped key. This is a write-once guarantee
  against the controller's **own code path** — nothing more.
- **What the operator must additionally configure, outside the code, to get the
  guarantee the sink name implies.** `PutBlobIfAbsent` does not stop a
  credential-holding attacker from calling delete or overwrite directly against the
  underlying object store — that primitive was never designed to resist an adversary
  who holds the storage credentials, only to close a TOCTOU race between concurrent
  legitimate writers. A host-compromised controller holds exactly those credentials.
  The strong bound — a host-compromised controller cannot rewrite **flushed**
  (already-shipped) history — holds only when the operator has, outside this code:
  (a) enabled object-lock (e.g. S3 Object Lock in governance or compliance mode) on
  the target bucket, and (b) scoped the controller's own IAM credentials to exclude
  permissions sufficient to defeat the lock (e.g. `s3:PutObjectRetention`,
  `s3:BypassGovernanceRetention`, and delete permissions on locked objects).

  An ADR — or a deployment — that treats "WORM sink selected" as sufficient by itself
  is describing a bound the code does not provide. The strong bound is a property of
  the code **and** the bucket configuration **and** the IAM policy together; any one
  of the three missing collapses it to the local sink's bound without anyone having
  changed the "recommended production option" label.

  Entries not yet flushed (still in the local durable buffer from point 5 above)
  carry the local sink's bound, unconditionally, until they flush — this is the
  accepted residual risk from Decision point 5, not a gap in the WORM analysis.

---

## Non-Goals

- **Designing shape (1).** This ADR does not flesh out a signing-oracle design. It is
  recorded as a non-goal for this epic, not attempted, and not designed here.
- **A bare (non-stateful) signing oracle is explicitly not a fix, if shape (1) is
  ever revisited.** An attacker who cannot read the signing key can still hand a
  stateless signer a rewritten history entry-by-entry and collect fresh signatures
  for it, because a stateless signer has no memory of what it already signed. Shape
  (1) only closes anything if the signer is **stateful** — it must persist the last
  sequence number it signed and refuse to re-sign a sequence number it has already
  signed. This is recorded explicitly so that nobody implements a plain oracle later
  and believes the bound is closed by doing so. This is a non-goal note, not a
  design: the persistence mechanism, failure modes, and recovery behavior of a
  stateful signer are unspecified here and out of scope for this epic.
- Changing what is audited, or the audit event vocabulary.
- Removing the existing HMAC hash-chain. It remains effective against its documented
  adversary — an actor with storage access but no secrets-store access — and stays as
  a first line of detection regardless of which sink is in use.
- Adding a third-party log-shipping dependency without justification.

---

## Rejected alternative: fail closed on sink unavailability

**Rejected.** The alternative to buffer-then-flush (Decision point 5) is refusing to
serve writes while the configured WORM sink is unreachable. For a system targeting
50k+ managed endpoints, a sink outage stopping fleet management is a larger
real-world operational loss than a short, bounded, rewritable window in the audit
trail — under this system's threat model of a **compromised host**, not a
**hostile operator**. A hostile-operator threat model would weigh this trade
differently, since a hostile operator can time an outage; that is not the model this
ADR is written against (see CLAUDE.md's Threat Model). A future audit-regime
requirement could revisit this trade-off; if it does, revisit this section rather
than reading buffer-then-flush as a permanent architectural commitment.

---

## Consequences

### Positive

- A basic/self-hosted deployment gets audit logging with zero extra infrastructure,
  and the bound it operates under is stated at startup rather than left implicit.
- Production deployments get a materially stronger bound on already-flushed history
  by configuring existing, well-understood object-storage primitives (object-lock,
  IAM scoping) rather than a new, bespoke cryptographic subsystem.
- The existing `AppendChainedEntry` sequencing contract (ADR-004 amendment, ADR-031
  Decision 1) is reused as-is; the WORM shipper is additive and does not change how
  sequence numbers are assigned.
- Never-fail-open is enforced by the same requirements mechanism other required
  stores already use, rather than a bespoke check.

### Negative

- The WORM sink's strong bound depends on operator configuration outside CFGMS's
  code (bucket-level object-lock, IAM scoping). A misconfigured deployment silently
  runs at the local sink's bound while believing it has the stronger one — this ADR's
  explicit two-fact framing exists to keep that gap visible to whoever reads it, but
  it cannot force correct operator configuration.
- Buffered-but-unflushed entries during a WORM outage carry the weaker local bound
  until they flush — an accepted, bounded residual risk, not eliminated.
- A bare signing oracle remains an available-looking but non-functional shape;
  documenting it as a non-fix does not prevent a future implementer from building it
  incorrectly if this ADR is not read.

---

## Amends

**ADR-004 (Amended)** — its "Interim disposition" paragraph under
`## Adversary Bound (Issue #3727)` is amended by a new pointer block (in the same
style as its existing two amendment blocks) to point at this ADR: the follow-up work
closing the bound is no longer tracked only as a private project draft — it is this
ADR plus Stories 2–5 of Epic #4033. ADR-004's Decision, Threat Model, and Adversary
Bound prose otherwise remain intact; this ADR does not re-litigate them.

The decisions/README.md index gains this ADR's row.
