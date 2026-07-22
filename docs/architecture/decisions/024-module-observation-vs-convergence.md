# ADR-024: Module Observation vs Convergence — the `observe_when` predicate and the controller-mediated observation loop

**Status:** Accepted (2026-07-22)

## Context

### What prompted this ADR

A steward on a Hyper-V cluster node (a non-CNO member) did not report its cluster membership in DNA, even though the Windows cluster service on that node answers `Get-Cluster` fine. The root cause: cluster membership was wired as **resource-reconcile state** — the `cluster:<name>` DNA fragment is the `hyperv.cluster` resource's `ConfigState`, produced only when that resource is *declared and reconciled*. `hyperv.cluster` is declared only in one node's device config (the CNO owner), so the other members never reconcile it and never publish `cluster:*` DNA — despite being locally authoritative for their own membership.

This is a specific instance of a general coupling defect: **DNA observation was gated on convergence**. A steward reports rich state only for what it is told to *manage*, not for everything it can *see*. That is backwards. It also blocked the `promote-hv-role` workflow (`cfg workflow promote-hv-role`), whose cluster derivation reads the selected steward's `cluster:*` DNA and therefore only works for the one node that publishes it.

The generalisation, articulated during design: *stewards should be authoritative for what they can see*. A steward should report the union of what it can observe, and worry about convergence only for declared resources. Taken to its conclusion: installing a steward on a box should let it detect what the box **is** (installed roles/features) and emit rich DNA for each capability, with nothing declared — convergence being a separate, opt-in layer.

### Relationship to existing ADRs

- **ADR-006** (module packaging/distribution): modules are publisher-signed, trust-verified, pulled on demand. This ADR reuses that pull path for *observation*, not only convergence.
- **ADR-016** (steward module foundation, `owns:`): a module declares the object kinds it authoritatively manages. `observe_when` is a sibling manifest declaration on the same contract.
- **ADR-020** (`required_fields`): another module-manifest contract addition, sourced from `module.yaml`. `observe_when` follows the same pattern.
- **ADR-022 / ADR-023** (entity graph): capability observation is what populates the graph — each self-reported capability becomes nodes/edges, self-reported by the authoritative node.

### Pre-existing implementation posture

Baseline host facts (`hyperv_role_installed`, `virtualization_role=host`) are already emitted unconditionally by the hyperv module, independent of any declared resource — proving the "observe without a declaration" path already exists. The defect is that domain observation (cluster, VM inventory) was not folded into that baseline and was instead gated behind resource reconciliation.

## Decision

### 1. Observation and convergence are distinct jobs with distinct scoping

- **Observation (DNA):** a module reports everything it can observe across its whole `<module>.*` domain — best-effort, silently continuing on anything absent or not applicable. Not gated on any resource being declared.
- **Convergence:** a module enforces only the resource instances actually declared in config.

A module's DNA is the **union of what it can observe**; its convergence is the **subset it is told to enforce**.

### 2. `observe_when`: an optional, module-level activation predicate

`module.yaml` gains an optional `observe_when` field — a **dumb fact-match** against baseline DNA (fact key + `equals`/`contains` value), **not** a general-purpose expression language:

```yaml
# module.yaml — observation activation
observe_when:
  - fact: windows_feature
    contains: hyperv
```

- **Present** → the steward may pull this module (signed, trust-verified) and run it in **read-only observe mode** whenever the predicate matches the box's baseline DNA, with nothing declared.
- **Absent (blank)** → the steward **never auto-pulls this module for DNA.** Absence is the whole story; there is no separate "none" value.

`observe_when` is **module-level, not per-resource-type.** A module bundle handles all of its `<module>.*` resource types internally (e.g. the single `hyperv` module handles both `hyperv.vm` and `hyperv.cluster` — they are resource *types*, not separately-pullable modules). When activated, the module observes its **entire domain** in one pass.

### 3. A module contributes to DNA iff its domain is bounded and inventory-worthy — the same decision as `observe_when`

DNA is **observed inventory plus fleet-queryable facts that config does not already determine** — what the box *is/has*: roles, VMs, cluster membership, services present, packages installed, local users. **Config is desired state; drift is desired-vs-observed.**

Therefore the **content of managed resources does not belong in DNA.** A managed file's content is config-known; its deviation is drift. Duplicating it into DNA is redundant and creates a second source of truth. So:

- A module whose domain is **bounded and inventory-worthy** (service, package, user, hyperv, cert_trust, time, hostname, and future IIS/AD/DNS/DHCP) carries an `observe_when`; its whole-domain `Get` output *is* its DNA, with drift computed on the managed subset.
- A module whose domain is **unbounded or content-bearing** (`file`/directory, and any future registry-value / database-row module) carries **no** `observe_when`; its declared resources are tracked as **config + drift only**, never enumerated into DNA.

This makes "does this module auto-observe?" and "does its state belong in DNA?" the *same* question, answered by the presence of `observe_when`.

Graph granularity is left open: the entity graph (ADR-022/023) may later represent managed objects as lightweight **identity** nodes ("this box manages file X") without their content. That is a graph-granularity decision, separate from and not contradicted by "no managed content in DNA."

### 4. Observe mode is provably read-only

Observation is **enumerate + `Get`**, and `Get` is already contractually read-only (the Get/Set split; the `conformance.AssertDeterministicGet` / `AssertNoEphemeralFields` helpers). An `observe_when`-eligible module's observe path may run **only** enumeration + `Get`, never `Set`, and its `behavioral_envelope` for that path must declare **no `writes_paths` and no mutations**. This is verified by a conformance check (`AssertObserveReadOnly`) and auditable from the manifest. Auto-observe eligibility *requires* passing it. Pulling and running code for inventory still runs code; the read-only guarantee keeps it within the threat model (predictable, signed, declared-path admin tooling).

### 5. Resolution is controller-mediated — "just a DNA lookup"

Control is inverted: the steward reports what it sees; the controller (which holds every module manifest) decides what to pull.

1. The steward runs its **always-on baseline observers** (os, hardware, and — critically — `windows_features`/roles, the seeder) and reports `dna:{...}`.
2. The **controller** matches that DNA against every module's `observe_when` and replies with the module set to pull.
3. The steward pulls those modules (signed, trust-verified), runs a read-only `Get` across **each module's whole domain**, and reports the enriched DNA.

This is mostly a **single resolution pass**, not a deep loop: because a module covers its entire domain at once, there is no intra-`hyperv.*` sub-pull. Genuine second-order iteration occurs only when one module surfaces a *different* top-level capability that maps to a *different* module (rare), and is bounded.

The steward needs **no** capability→module map; the controller owns it, aggregated from the manifests.

## Out of Scope

- The concrete `windows_features`/roles baseline collector implementation (a story under the epic).
- Building the feature modules themselves (IIS/AD/DNS/DHCP). `hyperv` is the pathfinder.
- The dependency-graph node/edge schema (ADR-022/023) beyond noting that self-reported capabilities feed it.
- Linux/macOS capability-detection equivalents (same contract, later).

## Consequences

### Positive

- A steward becomes **self-describing**: install it and it reports rich DNA for everything the box does, with zero declaration.
- The observe-vs-converge coupling defect is fixed at the root; non-CNO cluster members self-report membership; `promote-hv-role` derivation works for any member.
- One optional manifest field answers both "auto-observe?" and "belongs in DNA?".
- DNA stays lean — inventory and non-config-derivable facts, not a duplicate of config.

### Negative

- Pulling and running observe modules is code execution for inventory; mitigated by the read-only guarantee, signing, and the manifest-declared envelope.
- Adds a manifest field and a controller-side resolution path that every module author must consider.

### Neutral

- Most existing modules will carry an `observe_when`; `file` (and content-bearing modules) will not; `script` (the signed-file execution primitive, no observation domain) will not.
- The resolution loop is a mirror of the convergence loop — a second reconciliation, for observation.

## Alternatives Considered

### A static posture enum (`auto` / `declared-only` / `none`)

Rejected. `none` was a smell — a static classification standing in for a dynamic activation rule. An optional predicate is cleaner: absence subsumes both `none` and the DNA-side of `declared-only`, and it doubles as the DNA-membership decision.

### Put managed-resource content in DNA

Rejected. It duplicates config, creates a second source of truth, and bloats DNA on boxes managing many files/keys. Managed state is config + drift.

### A steward-side capability→module map

Rejected. It forces every steward to embed the catalogue and keep it current. The controller already holds all manifests; the match belongs there.

### Per-resource-type observe declarations

Rejected. Modules are pulled as whole bundles (verified: one `module.yaml` per module; `hyperv.vm`/`hyperv.cluster` are types within `hyperv`). Activation and observation are naturally module-level.

## References

- ADR-006 — Module packaging and distribution
- ADR-016 — Steward module foundation (`owns:`)
- ADR-020 — DNA required-field declaration
- ADR-022 / ADR-023 — Entity graph model and storage
- `docs/architecture/modules/README.md` — module manifest contract
