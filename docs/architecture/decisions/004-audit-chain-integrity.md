# ADR-004: Audit Chain Integrity via HMAC-Keyed Hash Chain

**Status:** Accepted  
**Date:** 2026-04-21  
**Issue:** #767

> **Amended 2026-08-28 (Issue #3727) — Adversary Bound.** This ADR's Threat Model
> table always noted that a key holder who recomputes checksums defeats the chain
> (see the original row below), but did not name who that key holder is by
> construction. It is the controller itself: `WithSecretsStore` loads the HMAC key
> from the controller's own secrets store, so a controller compromised at the host
> level holds the key. See [Adversary Bound](#adversary-bound-issue-3727) for the
> precise statement and its proof. Any architecture decision that names this chain
> as a compensating control for a compromised-controller scenario is describing a
> control that does not apply there — see ADR-021's qualification.

---

## Context

CFGMS stores immutable audit entries across three storage backends (flatfile, SQLite, PostgreSQL). The storage backends enforce append-only semantics at the application layer, but a sufficiently privileged operator with direct database access can delete or reorder rows without leaving traces at the application level.

The goal of this ADR is to make **undetected** deletion or reordering of audit entries detectable by any reader who holds the HMAC key — raising the bar above "trust the storage administrator" and providing forensic evidence of tampering.

### Requirements

1. Tampering with an entry's fields must produce a detectable checksum mismatch.
2. Deleting an entry must produce a detectable sequence gap.
3. Reordering entries must produce a detectable `previous_checksum` mismatch.
4. The mechanism must not require a trusted third party (e.g. a blockchain node).
5. The signing key must be sourced from `pkg/secrets`, not hardcoded.

---

## Decision

Use a **per-tenant HMAC-keyed hash chain** with the following design:

- Each `AuditEntry` carries `SequenceNumber uint64` (monotonically increasing per tenant) and `PreviousChecksum string` (the HMAC-SHA256 checksum of the immediately preceding entry for the same tenant).
- The `Checksum` field on each entry is computed as `HMAC-SHA256(key, ID|TenantID|Timestamp|EventType|Action|UserID|ResourceType|ResourceID|Result|SequenceNumber|PreviousChecksum)`.
- Sequence numbers are assigned inside the single drain goroutine in `pkg/audit/Manager` — no concurrent writer can interleave, so ordering is guaranteed without a database-side sequence.
- The HMAC key is loaded from `pkg/secrets` (key name `"audit/hmac-key"`) via the optional `WithSecretsStore` functional option on `NewManager`. If no secrets store is wired, a random 32-byte in-process key is used and a warning is logged.
- `VerifyChain(entries []*AuditEntry) []ChainBreak` is a pure in-memory function that walks a caller-provided, sorted slice and reports gaps, hash mismatches, and `PreviousChecksum` mismatches.

### Why HMAC-keyed hash chain instead of alternatives?

**Merkle tree:** Provides stronger proofs (you can prove inclusion of a single entry without revealing the whole log) but requires a trusted root anchor stored externally. It also adds significant implementation complexity and is not necessary for CFGMS's current threat model (detecting insider tampering, not proving non-inclusion to external auditors).

**Blockchain / distributed ledger:** Eliminates the need for a trusted key holder but introduces external dependencies, cost, latency, and operational complexity that are unjustified for a single-tenant or MSP-managed system where a single trusted administrator is the threat model.

**Plain sequence numbers without HMAC:** Detects deletion and reordering but not field-level tampering. Adding HMAC costs nothing at runtime and closes this gap.

**HMAC-keyed hash chain (chosen):** Simple, no external dependencies, detects all three threat scenarios (deletion, reordering, field tampering) for any reader who holds the key, integrates with the existing `pkg/secrets` key management infrastructure.

---

## Threat Model

| Threat | Detected? | Notes |
|---|---|---|
| Attacker without HMAC key modifies a row | Yes | Checksum mismatch |
| Attacker without HMAC key deletes a row | Yes | Sequence gap |
| Attacker without HMAC key reorders rows | Yes | PreviousChecksum mismatch |
| Attacker WITH HMAC key recomputes all checksums after modification | No | Inherent limitation of keyed hash chains. By construction this includes **the controller itself when host-compromised** — see [Adversary Bound](#adversary-bound-issue-3727) |
| Attacker modifies pre-chain (SequenceNumber==0) legacy entries | Partial | Per-entry checksum mismatch only; no chain linkage for legacy entries |

The chain does **not** protect against a sufficiently privileged administrator who possesses the HMAC key recomputing all subsequent checksums. Closing this gap would require an external immutable anchor (e.g. a Merkle root published to an external system), which is out of scope for this story.

---

## Adversary Bound (Issue #3727)

This chain detects exactly one class of adversary, and the distinction between
"detects" and "does not detect" is not symmetric with "external" vs. "insider" — it
is **whether the actor holds the HMAC key**, and the key's storage location
determines who that is.

**Detected: an actor with write/delete access to the audit storage backend who does
not hold the chain's HMAC key.** A database administrator, a support engineer with
direct SQL/filesystem access, or anyone else who can edit or delete rows in the
flatfile, SQLite, or PostgreSQL backend but cannot reach `pkg/secrets` falls here.
Deleting a row produces a sequence gap; reordering breaks `PreviousChecksum`;
editing a field breaks `Checksum`. `VerifyChain` reports all three as `ChainBreak`s.
This is the adversary the chain was designed for (`## Requirements` above), and the
chain closes that gap completely for entries written after Issue #767.

**Not detected: an actor who holds the HMAC key.** By construction, that actor
includes **the controller process itself**, whenever `WithSecretsStore` is wired —
which is the production configuration, not an edge case. The key is loaded from the
controller's own secrets store (`audit/hmac-key`) and stays resident in the
`Manager`'s memory for the life of the process. A controller compromised at the host
level (the adversary CLAUDE.md's Threat Model section names explicitly — "Admin
accounts may be phished or taken over for short periods") therefore already holds
the key. Such an actor can rewrite any entry's content and recompute
`SequenceNumber`, `PreviousChecksum`, and `Checksum` for every entry from that point
forward, in order — producing a chain `VerifyChain` reports as fully consistent. A
verifier sees a valid chain and nothing anomalous. This is not a bug in
`VerifyChain`; it is the inherent bound of a keyed hash chain whose key is
reachable by the party being defended against.

`pkg/audit/manager_test.go`'s `TestVerifyChain_KeyHolderCanForgeConsistentChain`
proves this mechanically: it takes real recorded entries, rewrites their content,
recomputes the chain fields using the same manager (i.e. the same key) that
recorded them, and shows `VerifyChain` reports zero breaks despite every entry's
content differing from what was originally recorded.
`TestVerifyChain_DetectsTampering`, `TestVerifyChain_DetectsPreviousChecksumMismatch`,
and `TestVerifyChain_DetectsDeletion` prove the complementary half of the bound: the
same package's protection against an actor who does *not* hold the key remains
intact.

**What this means for callers of this ADR.** "The audit trail" is not a single
guarantee usable everywhere the phrase appears. It is strong evidence against
storage-layer tampering by someone outside the controller's own trust boundary, and
it is **no evidence at all** against the controller's own host being compromised —
the exact scenario several other architecture decisions gesture at when they invoke
"audit" as a backstop. Each such decision must say which adversary it means. ADR-021
(`docs/architecture/decisions/021-identity-assurance-levels.md`) is qualified
accordingly as part of this issue.

**Interim disposition.** Closing this bound requires either (a) a signing key the
controller cannot read after startup (external signer/HSM/KMS), or (b) an
append-only sink outside the controller's trust boundary that the controller can
append to but not rewrite. Both are larger than a documentation change and are
deliberately not attempted here — see Issue #3727's Implementation Notes. The
follow-up work is tracked as a private project draft
(`PVTI_lADOCrV4cc4BX5ezzg4Z7eM`, materializes to a public issue at dispatch) titled
"audit: move audit-chain signing key outside controller's post-startup reach." Until
that work lands, the chain above should be read with this bound in mind: it is a
compensating control against storage tampering, not against controller compromise.

---

## Consequences

### Positive

- All three tampering vectors (modify, delete, reorder) are detectable for entries written after this change.
- The HMAC key integrates with the existing `pkg/secrets` provider — no new key management infrastructure required.
- `VerifyChain` is a pure function with no I/O, making it suitable for use in compliance exports and auditor tooling.
- Backward compatible: entries with `SequenceNumber == 0` (pre-#767) are skipped by `VerifyChain` without false positives.

### Negative

- The HMAC key is ephemeral if no secrets store is wired (logs a `Warn`). Operators who do not configure a secrets store lose cross-restart chain continuity.
- `GetLastAuditEntry` is called once per drain-loop iteration, adding one read per write. For flatfile (OSS), this is O(N) over the tenant's audit files; acceptable for the OSS use case, not suitable for high-throughput production deployments without an indexed store.
- The `Checksum` field now stores an HMAC-SHA256 value rather than a plain SHA256 value. Existing tooling that verifies checksums independently (outside the `VerifyIntegrity` or `VerifyChain` methods) will need updating.
