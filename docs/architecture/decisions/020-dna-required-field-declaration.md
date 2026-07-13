# ADR-020: DNA Required-Field Declaration — per-configuration-type contract, module-manifest sourced

**Status:** Accepted (2026-07-13)
**Date:** 2026-07-13
**Issue:** #2618
**Epic:** [#2460](https://github.com/cfg-is/cfgms/issues/2460)

---

## Context

### What prompted this ADR

Story #2617 landed a controller-side DNA write-integrity guard: before accepting a DNA snapshot, the controller checks that every field named in a per-configuration-type table is present and non-empty. The seed entry is:

```go
var dnaRequiredFields = map[configType][]string{
    configTypeFullOSDevice: {"hostname", "os"},
}
```

That table is currently hand-coded. As CFGMS grows to manage additional entity kinds — network/IoT devices, directory objects, cloud-tenant resources — adding a new guard entry per kind would require a code change each time. The `#2618` comment in `dna_integrity.go` marks this as the intended extension point.

This ADR closes the design gap: it defines where required-ness is declared, how a DNA snapshot's configuration type is resolved at write time, and the union rule that governs what "required" means across a multi-module entity. The result is a declaration contract, not a code change — future entity kinds add manifest entries, not guard rewrites.

### Relationship to existing ADRs

**ADR-016 clause 5** (`owns:` precedent) established that every module declares in `module.yaml` the object-identity namespace it authoritatively owns. Six `module.yaml` files currently carry `owns:` entries (`stdlib/{file,package,script,firewall,service,patch}` — verified against develop HEAD; the rollout epic #2460 is still in progress). Required-ness is the same kind of module-authority concern as ownership: it says "when I own an object of this kind, these fields must be populated for the DNA snapshot to be valid." Co-locating both in the manifest keeps one declaration site instead of two.

**ADR-017** defines the DNA composition model (fragment set, authority resolver, two-level hash, partial-sync protocol). This ADR rides the model ADR-017 defines — it does not re-litigate fragment mechanics or Merkle hashing. The resolver ADR-017 owns is the runtime that applies the union of required fields across an entity's applicable fragments at assembly and validation time; this ADR defines only the declaration contract that makes that resolution possible.

### Pre-existing implementation posture

The write-integrity guard from #2617 already satisfies the first concrete required-field contract (`full-os-device → {hostname, os}`). This ADR formalises that guard's implicit contract as the first table entry under the module-declared scheme — no behavior change for existing stewards.

---

## Decision

### 1. Declaration site: `module.yaml`, `required_fields` within each `owns:` entry

Required fields are declared in `module.yaml` as an optional `required_fields` list nested within each `owns:` entry. Nesting it inside `owns:` groups authority and required-ness at one declaration site and makes it syntactically impossible to declare required fields for a kind the module does not own.

```yaml
# module.yaml — ownership + required-field declaration example
owns:
  - kind: service
    required_fields:
      - name   # object identity key
      - state  # managed field that must be present for a valid DNA snapshot
```

**Semantics of `required_fields`:**

- Each entry names a field key that the module's `Get` must populate in the DNA fragment for every object of that kind it manages.
- A field listed here that is absent or empty in a DNA snapshot is a write-integrity violation for any configuration type that includes this module.
- Omitting `required_fields` from an `owns:` entry is valid: the module declares ownership but imposes no additional required-field constraint (the schema for that kind is currently unconstrained, pending a later story that adds specific entries).
- Omitting `owns:` entirely remains valid for modules that carry no DNA authority (backward-compatible with all existing `module.yaml` files that predate ADR-016's `owns:` rollout).

The `required_fields` declaration is the *contract surface* only. The manifest is not parsed at DNA assembly time by the steward today; the controller reads the applicable required sets from manifests it has cached for the active modules reporting on a given entity. Implementation of the manifest-driven loader is a follow-on story; until it lands, the hand-coded table in `dna_integrity.go` (seeded by #2617) is the operative source of truth — it must be kept consistent with the manifests.

### 2. Configuration-type resolution at write time: two-path approach

A DNA snapshot's configuration type determines which set of required fields applies. Resolution follows two distinct paths depending on whether the entity has a steward presence:

#### Path A — Steward-hosted entities: inferred from active modules

For entities managed by a steward (all current steward-kind modules — the full-OS device case), the configuration type is **inferred** from the module set active on that steward. No additional wire field is required:

- A steward carrying the stdlib set (`file`, `service`, `package`, `script`, `firewall`, `patch`, and, once built, `user`, `cert_trust`, `time`, `hostname`) is classified as `full-os-device` automatically.
- A steward carrying only a strict subset of those modules (e.g., a constrained device running only `service` and `package`) resolves to the same `full-os-device` type — the type is determined by the *class* of entity (a general-purpose host), not by module completeness.
- Extended modules (`acme`, `activedirectory`, `hyperv`, etc.) contribute additional `owns:` kinds and their `required_fields` to the union, but do not change the base configuration type.

This path imposes no new wire contract on the steward→controller communication path for existing steward-kind entities.

#### Path B — Non-steward entities: explicit declaration per object

For entities with no steward presence — network/IoT devices, directory objects, cloud-tenant resources — the module reporting on their behalf (an outpost or workflow module) **declares the configuration type explicitly** per reported object. The reporting module includes a `config_type` field alongside the DNA fragment payload:

```
fragment_payload = (fragment_id, config_type, authority, canonical_bytes, fragment_hash)
```

The `config_type` value must match a type registered in the controller's configuration-type registry (initially empty; entries are added as new outpost/workflow module support lands). An unrecognised `config_type` is treated conservatively: the required-field check is skipped (unknown contracts cannot be violated — the same default as the #2617 guard for unknown types).

**Why the split:** Steward-hosted entities have their module set visible to the controller via the registration and active-module-list; inferring the config type avoids a redundant declaration for every DNA snapshot. Non-steward entities arrive via a single reporting module that has no peer module context on the controller side — the module must therefore declare the type it is asserting authority over.

### 3. Union-of-fragments rule: required fields accumulate across applicable modules

For a given entity at write time, the controller collects the `required_fields` for every `owns:` entry whose `kind` matches any fragment present in that entity's DNA snapshot and whose module is active for that entity. The **union** of all collected field sets is the required-field contract for that DNA snapshot.

Example for a `full-os-device` steward with the `service` and `hostname` modules active:

| Module | `owns:` kind | `required_fields` |
|---|---|---|
| `service` | `service` | `[name, state]` |
| `hostname` | `hostname` | `[fqdn]` |

Required union: `{name, state, fqdn}` — all must be present and non-empty in the DNA snapshot for the write to be accepted.

**The #2617 seed entry fits here without modification.** The guard's `full-os-device → {hostname, os}` entry is the first concrete population of this union — sourced today from the hand-coded table, eventually driven from manifests. Its behavior is unchanged by this ADR: existing stewards continue to satisfy the check identically.

**Unknown kinds and nil DNA:** consistent with #2617's guard:
- A `nil` DNA snapshot always fails the integrity check.
- A `kind` present in the DNA snapshot but not listed in any active module's `owns:` has no required-field constraint (no declared authority → no declared required set for that kind).
- A `config_type` (Path B) with no registered entry passes the required-field check by default.

**The authority resolver (ADR-017) is the runtime owner.** ADR-017's resolver determines which modules are active and which `owns:` entries apply. This ADR requires that the declaration exist in the manifest so that the resolver can consume it; the resolver mechanics are ADR-017's.

---

## Out of Scope

- Any code change — this is an ADR-only story. No `module.yaml` schema change, no controller-side validation code, no test code.
- The immediate device-type seed + black-hole fix (#2617) — unaffected. It ships the first declared type under this contract.
- The full ADR-017 fragment/Merkle redesign — this ADR cross-references it and rides its model.
- The manifest-driven loader implementation — a follow-on story that reads `required_fields` from cached module manifests at DNA validation time, replacing the hand-coded table in `dna_integrity.go`.

---

## Consequences

### Positive

1. **No guard rewrite per new entity kind.** Adding a workflow module for directory objects requires only an `owns:` + `required_fields` entry in its `module.yaml`; the controller-side guard iterates the union at runtime once the manifest-driven loader lands.
2. **Single declaration site per module.** Authority (`owns:`) and required-ness (`required_fields`) are co-located in the manifest. A developer reading a `module.yaml` sees the complete DNA contract for that module without consulting controller code.
3. **Backward-compatible schema.** `required_fields` is optional within `owns:` and `owns:` is optional in the manifest — no existing `module.yaml` file breaks. Modules adopt the new clause incrementally.
4. **Conservative unknown-type default.** Unrecognised configuration types pass the check. New module support can land without a flag-day registry update; the guard tightens as manifests accumulate declared types.

### Negative

1. **Transient dual source of truth.** Until the manifest-driven loader story lands, the hand-coded table in `dna_integrity.go` and the `module.yaml` `required_fields` entries must be kept consistent manually. A divergence is a latent bug (the guard enforces the table; the manifest declares intent).
2. **Path B requires new wire field.** Outpost and workflow modules reporting non-steward entities must include `config_type` in their fragment payload. This is a new wire contract field for those module kinds (steward-kind modules are unaffected — Path A infers the type).
3. **Manifest caching dependency.** The manifest-driven loader requires the controller to have a current cached copy of each active module's manifest. Module updates that change `required_fields` must be followed by a manifest re-fetch before the new required set is enforced.

### Neutral

- The `required_fields` YAML key name is a convention; renaming before the manifest-driven loader ships is mechanical.
- ADR-016 clause 6's completeness gate already verifies that every stdlib module carries `module.yaml` with an `owns:` entry. Once `required_fields` is expected for stdlib modules, the gate extends to check that field as well — that extension is a follow-on story.

---

## Alternatives Considered

### Declare required fields in controller code, not the manifest

Maintain the hand-coded table in `dna_integrity.go` as the authoritative source, adding entries per new entity kind.

**Rejected:** requires a controller code change and redeploy for every new entity kind, regardless of whether the module itself has shipped. The manifest-declared approach lets module authors own the complete DNA contract for their module, consistent with the ADR-016 principle that module-authority concerns live in the manifest.

### Declare required fields in a separate registry file (e.g. `config/dna_required_fields.yaml`)

A central YAML registry, not per-module.

**Rejected:** splits the declaration from the module that declares authority. A developer adding a new module must update two files in two locations; the registry file has no natural owner and drifts. Per-module manifest declaration is self-contained and enforces the connection between ownership and required-ness.

### Per-field sub-authority (a module owns only some fields of an object)

Allow partial required-field declarations that do not correspond to whole-object `owns:` entries.

**Rejected (consistent with ADR-016 clause 5 and ADR-017 clause 2):** authority is atomic per object. Sub-property co-authorship of one object — including partial required-field constraints from two modules — reintroduces the two-sources-one-fragment non-determinism that breaks hash validation and makes required-field checking ambiguous (which module's required set governs?). Required fields must be declared by the module that owns the object kind.

### Infer required fields from the fragment schema (no manifest entry)

Derive required fields from which fields a module's `Get` always populates, via static analysis or reflection.

**Rejected:** the required-field contract is a *stability guarantee*, not an observation. Static analysis cannot distinguish "this field is always populated today" from "this field is always populated as a design invariant." Explicit declaration in the manifest is the contract; the implementation must honor it.

---

## References

- [ADR-016](016-steward-module-foundation.md) — Steward Module Foundation: `owns:` precedent (clause 5) and DNA-fragment contract (clause 4) that this ADR extends. Six `module.yaml` files currently carry `owns:` entries (`stdlib/{file,package,script,firewall,service,patch}`).
- [ADR-017](017-dna-composition-and-sync.md) — DNA Composition & Sync: fragment model, authority resolver, and partial-sync protocol that this ADR's required-field union rule rides on. Clause 2 defines the resolver this ADR's declaration feeds into; clause 5 defines the canonical serialization that required-field validation depends on.
- [ADR-019](019-third-party-module-inclusion-and-trust.md) — Third-Party Module Inclusion and Trust: governs the trust chain for module manifests; the `required_fields` declaration is trustworthy only as far as the publisher verification chain from ADR-019 extends.
- `features/controller/service/dna_integrity.go` — write-integrity guard seeded by #2617; the hand-coded table this ADR's manifest-declared contract will eventually replace.
- `docs/architecture/modules/README.md` — module manifest schema documentation; see the `owns:` and `required_fields` section.
- Issue #2617 — DNA write-integrity guard (the immediate implementation; seeds the first required-field entry).
- Epic #2460 — Steward module foundation (the rollout epic under which this ADR and its follow-on land).
