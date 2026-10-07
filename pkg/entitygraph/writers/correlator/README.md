# correlator

MAC-identity correlator — entity-graph internal writer (ADR-022 §3, Issue #3369).

## Matching Rule (v0)

**Primary join key:** Normalized MAC address (uppercase colon-delimited).

Two entities from **different authority segments** that share at least one
normalized MAC address receive a `same-as` edge with `ConfidenceHigh`.

**VM GUID (corroborating-only):** VM GUID agreement alone — without MAC
agreement — never produces a `same-as` edge. GUID is reserved for a future
confidence-scoring layer, not part of the v0 join rule.

## MAC Normalization

MAC addresses from different producers use different formats:

| Producer | Example |
|---|---|
| Steward (Go `net` package) | `00:15:5d:ea:a3:35` (colon, lowercase) |
| Steward (Windows) | `00-15-5d-ea-a3-35` (hyphen, lowercase) |
| Hyper-V PowerShell | `0015DEAD1234` (no delimiter, mixed case) |

All three are normalized to uppercase colon-delimited form before comparison.

## Join-Key Hygiene and Fan-Out Bounds

A MAC only identifies a machine while it is globally unique, and collectors emit
addresses that are not. The steward DNA network collector reports
`iface.HardwareAddr` for every non-loopback adapter, so a Windows host
contributes the all-zero address of its WAN Miniport and tunnel pseudo-adapters
and the fixed Microsoft KM-TEST loopback address alongside its real NIC. Those
values repeat on every host in the fleet, and `dnasync` mints a distinct
authority segment per steward — so an unfiltered join on them would pair every
host with every other host across tenants.

Three bounds apply:

1. **Non-identifying addresses are rejected at normalization.** `normalizeMAC`
   returns empty for the all-zero address, any address with the multicast/group
   bit set (`hw[0]&1 == 1`, which also covers broadcast `ff:ff:ff:ff:ff:ff`), and
   known fixed virtual-adapter addresses (`02:00:4C:4F:4F:50`). The
   locally-administered bit is **not** rejected — hypervisors assign
   locally-administered addresses to real VM adapters.
2. **Group-size cap.** A MAC shared by more than `maxJoinGroupSize` (16) entities
   is skipped entirely. A unique MAC is seen by a small, bounded set of
   authorities; a MAC on dozens of entities is duplicated or spoofed, and pairing
   it would assert `ConfidenceHigh` identity between unrelated machines. The cap
   also bounds the `O(k²)` pairwise loop to 120 pairs per group, so no single MAC
   — including one injected by a compromised steward minting synthetic entities —
   can amplify into a fleet-scale edge burst.
3. **Bounded write batches.** Observations are flushed to the provider in batches
   of at most `maxObservationBatch` (1000) rather than accumulated for the whole
   sweep. A provider ingests one batch in one transaction, so an unbounded batch
   is both an unbounded allocation and an unbounded write-lock hold. Flushing
   mid-sweep can leave earlier edges written if a later batch fails; that is safe
   because same-as observations are content-hash deduped and the sweep is
   idempotent.

## Query Strategy

`QueryEntities`'s `EntityFilter.Attributes` field is declared in the provider
interface but not implemented by the SQLite provider — the query only filters
by `Kind` and `TenantFilter`. `network_adapters` is a list of maps (not a
flat scalar attribute), so attribute-value index matching is not feasible for
this field even with a future provider implementation. A **full entity scan +
in-process attribute match** is used for v0: O(fleet size) per sweep, as
flagged in ADR-022 §9. A future story may introduce a MAC-address index to
reduce per-sweep cost.

## Confidence Policy

`ConfidenceHigh` for all MAC matches. MAC addresses are tenant-cut-secure
primary keys: a steward cannot forge another steward's mTLS-verified authority
segment, so a MAC match across authority segments is a strong identity claim.
No medium/low tier is defined in v0.

That justification only holds while the emitted edge subject names the exact
entities that matched. Observation edge subjects use the format
`edge_type|from_eid|to_eid` and the provider parses them back by splitting on
`|`, while `types.ParseEID` rejects only `/` in an authority name — so a
collector-supplied authority name containing `|` would let one entity's subject
resolve to a different, real entity. The correlator therefore **skips any pair
whose EID string contains `|`**, keeping the subject round-trip injective and
the forged EID confined to its own authority segment.

## Tenant Boundary Behavior

The correlator operates **controller-wide with no tenant filter**. It asserts
`same-as` edges between entities from different tenant subtrees that share a
MAC address (e.g. a duplicate or spoofed adapter across tenants).

The read-time tenant cut in `GetEntity` (with `CollapseGroup=true` and
`TenantFilter` set) gates visibility for end users — a caller scoped to one
tenant cannot see the merged entity if they cannot see both members.

Asserting the edge at the correlator level enables **cross-tenant duplicate
detection** (e.g. two tenants claiming the same physical machine), which is
the intended behavior per ADR-022 §3's collapse rule.

## Invocation

This package is a **standalone-invokable writer pending controller-startup
wiring (#3253)**. Story #3253 ("wire the entity graph provider and its writers
into controller startup") will integrate periodic invocation.

```go
w, err := correlator.New(provider)
if err != nil {
    // handle
}
if err := w.Correlate(ctx); err != nil {
    // handle
}
```
