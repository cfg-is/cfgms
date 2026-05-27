# ADR-004: Audit Chain Integrity via HMAC-Keyed Hash Chain

**Status:** Accepted  
**Date:** 2026-04-21  
**Issue:** #767

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
| Attacker WITH HMAC key recomputes all checksums after modification | No | Inherent limitation of keyed hash chains |
| Attacker modifies pre-chain (SequenceNumber==0) legacy entries | Partial | Per-entry checksum mismatch only; no chain linkage for legacy entries |

The chain does **not** protect against a sufficiently privileged administrator who possesses the HMAC key recomputing all subsequent checksums. Closing this gap would require an external immutable anchor (e.g. a Merkle root published to an external system), which is out of scope for this story.

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
