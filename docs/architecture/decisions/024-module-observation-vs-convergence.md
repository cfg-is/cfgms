# ADR-024: Module Observation vs Convergence — the `observe_when` predicate and the controller-mediated observation loop

**Status:** Accepted (2026-07-22)

## Context

### What prompted this ADR

A steward on a Hyper-V cluster node (a non-CNO member) did not report its cluster membership in DNA, even though the Windows cluster service on that node answers `Get-Cluster` fine. The root cause: cluster membership was wired as **resource-reconcile state** — the `cluster:<name>` DNA fragment is the `hyperv.cluster` resource's `ConfigState`, produced only when that resource is *declared and reconciled*. `hyperv.cluster` is declared only in one node's device config (the CNO owner), so the other members never reconcile it and never publish `cluster:*` DNA — despite being locally authoritative for their own membership.

This is a specific instance of a general coupling defect: **DNA observation was gated on convergence**. A steward reports rich state only for what it is told to *manage*, not for everything it can *see*. That is backwards. It also blocked the `promote-hv-role` workflow (`cfg workflow promote-hv-role`), whose cluster derivation reads the selected steward's `cluster:*` DNA and therefore only works for the one node that publishes it.

**Story #2891 is the shipped fix for the hyperv-specific case** — no new ADR is
needed; this is implementation of the accepted decision above. It decouples
`cluster:<name>` DNA from `hyperv.cluster` resource declaration (all cluster
members now emit membership DNA via `Get-Cluster` self-discovery), adds
whole-domain VM and vSwitch inventory to the unconditional observe path, and
extends `psGetVM` with VM GUID and MAC addresses as entity-graph join keys.

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

---

## Amendment 1 (2026-07-24): One store — observation extends the existing fragment emission, not a parallel channel

**Status:** Accepted · **Deciders:** Founder, Architecture · **Amends:** Decisions 1 and 5

This amendment corrects a framing error that surfaced while sequencing the entity-graph
population work (epics #2890/#2853). The original text reads as if observation is a *new
collection layer that feeds a graph* — a second sink alongside DNA. It is not. The founder's
correction (2026-07-23): **DNA and the entity graph are ONE store, and a module reports its
observation by extending the emission it already makes — never by adding a parallel channel.**

### 1. DNA and the entity graph are one store

There is a single unified store; DNA is its **lean current-state projection**, not a separate
database. This is already the settled position of the entity-graph ADRs and is restated here so
observation is built on it:

- **ADR-023 §2** — one store; the fragment log subsumes DNA fragment history (the
  "graph-inside-DNA" alternative was rejected).
- **ADR-022** — one shared identity (`eid` / `fragment_id`) spans DNA, graph, and DEX.
- **ADR-017 A1.2** — `fragment_id` *is* the entity node id; edges connect `fragment_id`s.
- **ADR-023 clause 7** — the DNA **sync hot path stays separate** for performance; that is a
  transport optimization, not a second store.

Consequence: observation does not "populate a graph." A module emits **fragments (and edges,
identity, drift)** into the one store; the graph and DNA are two views of it.

### 2. One observation over the existing ADR-016 emission — extend it, do not duplicate it

A module's `Get` emits **one observation** — fragments + edges + identity + drift — over the
**existing ADR-016 fragment emission, extended**. There is **no** separate observation/edge
channel. The founder's constraint: *"doubling the steward→controller path is bad."*

This supersedes any wording (notably in epic #2853) that says "add an observation channel" or
"add an edge-emission channel." The corrected instruction is **"extend the existing fragment
emission."** `psGetVM`-style comprehensive collectors emit once; consumers (DNA inventory,
entity nodes/edges, identity correlation) read from that single emission rather than re-opening
the collector.

### 3. Re-observe cadence is the steward convergence cycle, tiered by default

Observation reuses the loop that already `Get`s managed resources — the steward **convergence
cycle** (~5 min lab, ~15 min production, ~30–60 min workstations). It is **tiered by default**,
and the tier boundary is **cost × value, not managed-vs-unmanaged**:

- **Tier 1 — declared-resource drift, every cycle.** Cheap, high-value state (including
  cheap+high-value observation such as cluster membership) refreshes each cycle.
- **Tier 2 — whole-domain extended discovery, every Nth cycle.** The expensive full-domain
  sweep runs on a slower beat; N is the endpoint-CPU knob.

Event push (e.g. the Hyper-V `monitor_windows.go` accelerator) is an **optional per-module
accelerator, not the baseline.** Sync stays light regardless — partial sync ships deltas only,
orthogonal to the CPU tiering above.

### Effect on decomposition

This amendment is the precondition for decomposing the observe-DNA framework stories (the
`#2948` remediation of epic #2890). Stories MUST reflect one store, extend-the-existing-emission,
and the tiered convergence-cycle cadence — not a parallel observation channel or a separate
collection layer.

## Amendment 2 (2026-08-25): `always_pull` — an explicit activation basis for modules with no conditional trigger

**Status:** Accepted · **Deciders:** Founder, Architecture · **Amends:** Decisions 2 and 5

This amendment adds a second activation basis alongside `observe_when`. It was forced by the
osquery integration (epic #2855), whose curated `host:*` fact collection must run on **every**
steward. The original text has no way to express that.

### What the original text says, and why it blocks

Decision 2 states: "**Absent (blank)** → the steward **never auto-pulls this module for DNA.**
Absence is the whole story; there is no separate `none` value." The implementation matches
exactly — `ResolveObserveModules` skips any manifest with nil or empty `ObserveWhen`, and
`moduleManifestAdapter.ListObservableManifests` filters to manifests with `len(ObserveWhen) > 0`
one level above it.

`observe_when` is a **dumb fact-match against baseline DNA**. It answers "does this box have the
thing?" — `windows_feature contains hyperv`. Osquery's activation condition is not a fact about
the box. There is no DNA fact meaning "this machine exists," and inventing one to satisfy the
matcher would be a fiction in the fact namespace.

So the original text offers two options for osquery, and both are wrong:

- **Absent `observe_when`** → never pulled. Osquery never reaches any steward.
- **A synthetic always-true predicate** → discussed below; rejected.

### Decision

`module.yaml` gains an optional boolean sibling to `observe_when`:

```yaml
# module.yaml — unconditional observation activation
always_pull: true
```

- **`always_pull: true`** → the module is selected for **every** steward, with no fact matching.
  It flows through the *same* Tier-2 resolution, dispatch and cadence machinery as
  `observe_when` modules (Amendment 1 §3 tiering, `steward.observe_sweep_n`). No new scheduler,
  no parallel pull path.
- **Absent or `false`** → **unchanged.** Absence still means never auto-pull. Only an explicit
  `always_pull: true` opts in, which matches the explicit-opt-in posture Decision 2 already
  established.
- **`always_pull` and `observe_when` are independent fields.** `always_pull: true` short-circuits
  ahead of predicate evaluation; `ObservePredicate` semantics, and `validateObserveWhen`, are
  untouched.

### Why this is not the static posture enum that Alternatives Considered rejected

This is the substantive objection to the shape, raised during decomposition, and it deserves an
answer in the record rather than in a story comment.

Alternatives Considered rejects a static posture enum (`auto` / `declared-only` / `none`) on the
grounds that "`none` was a smell — a static classification standing in for a dynamic activation
rule," because "absence subsumes both `none` and the DNA-side of `declared-only`."

**The rejection is about redundancy, not about static values.** `none` was rejected because
*absence already expressed it* — a second way to say the same thing. `always_pull` is the
opposite case: absence expresses "never," and **nothing in the current model expresses "always."**
It is not a static classification standing in for a dynamic activation rule; it is an explicit
declaration that no dynamic rule applies. The principle Alternatives Considered defends —
do not add a value that absence already encodes — is upheld here, not violated.

### Why not an `always: true` predicate inside `observe_when`

Considered and rejected. Keeping one field is superficially tidier, but `ObservePredicate`'s
contract is that `Fact` is required and exactly one of `Equals`/`Contains` is set — enforced by
`validateObserveWhen`, and stated in the type's own doc comment ("a single dumb fact-match
predicate"). An always-true entry satisfies none of that, so it would require special-casing in
validation and in `matchesAnyPredicate`, and it would make the type's documented invariant false
for every future reader. It puts a value that matches nothing inside a matcher.

A sibling field keeps the predicate type honest and confines the change to one short-circuit.

### Implementation note — the filter one level up

`moduleManifestAdapter.ListObservableManifests` filters to `len(Manifest.ObserveWhen) > 0`
**before** `ResolveObserveModules` ever sees a manifest. An `always_pull` manifest with empty
`observe_when` is dropped there unless that filter is widened too. A change made only in
`ResolveObserveModules` compiles, passes its own unit tests, and silently no-ops in production.

That filter sits **below** the `ApprovalStatusApproved` check in the same loop, and it must stay
there. Routing `always_pull` through this path is what preserves continuous approval-revocation
sensitivity: `ListObservableManifests` re-filters on approval status on *every* Tier-2 pass, and
per ADR-006 stewards keep no local approval queue, so this is the only recurring revocation check
in the system — `ResolveCfgRequiredModules` fires only at config-upload time. Any implementation
that short-circuits `always_pull` *above* the approval filter would unconditionally pull
unapproved bundles to every steward. That is a worse outcome than the problem this amendment
solves.

**The safety property is structural, and it depends on how the fix is written.** The approval
`continue` and the `ObserveWhen` test are two statements in one loop iteration, sharing one gate.
Widening the existing inner conditional — `len(b.Manifest.ObserveWhen) > 0 || b.Manifest.AlwaysPull`
— makes it impossible for `always_pull` to be evaluated before the approval check. Adding a
separate "always include `always_pull` manifests" pass elsewhere reintroduces exactly the bypass,
and an acceptance criterion worded loosely as *"`always_pull` manifests are always included"*
invites that mistake.

**A positive test does not catch this.** "An approved `always_pull` manifest appears in the
result" passes under both the correct fix and the bypass-shaped one. The required test is the
**negative** case: a cached but **not** approved manifest with `always_pull: true` must **not**
appear in `ListObservableManifests`'s output.

### Effect on decomposition

Epic #2855's activation story implements this amendment. Stories cite it; they do not edit it.
ADRs are drafted inline, never dispatched to a dev agent.
