# ADR-016: Steward Module Foundation — stdlib set, repository layout, and DNA-fragment contract

**Status:** Proposed
**Date:** 2026-07-04
**Issue:** (to be assigned at decomposition)
**Epic:** (module-foundation epic — to be filed)

---

## Context

ADR-006 established the module *packaging and distribution* model: out-of-process signed bundles, controller-cached and pulled by hosts, with stdlib defined as "the installer payload using the same module contract." It did **not** pin down three things that are now on the critical path:

1. **Which modules constitute the standard library**, and how we keep that set complete and compliant over time.
2. **How the module source tree is organised** so that the stdlib (installer payload) is physically separable from non-stdlib modules (pulled on demand).
3. **What a module's `Get` must emit for DNA**, and **how a module declares the objects it authoritatively owns** — the two clauses the forthcoming DNA composition ADR (ADR-017) depends on.

### Current state

All modules live flat in `features/modules/`, mixing stdlib and non-stdlib:

```
features/modules/
  file/  service/  package/  script/  firewall/  patch/          ← stdlib
  acme/  activedirectory/  hyperv/  github_runner/  network_activedirectory/  ← non-stdlib
```

There is no build-level or directory-level boundary between "ships in the installer" and "pulled on demand." A survey done for this ADR found:

- All six stdlib modules build (`cmd/main.go` present in each).
- **`patch` has no `module.yaml`** — the only stdlib module missing a manifest, so it is not a fully-declared bundle under ADR-006. It also carries a `stub_patch_manager.go` whose real-vs-placeholder status is unverified.

"Builds" is therefore not the same as "is a compliant, fully-declared, installer-shipped bundle." We need an enforceable definition of stdlib completeness, not a one-time cleanup.

### Why the DNA clauses belong here

The DNA model assembles a deterministic, hashable object from per-object fragments so steward and controller can validate full sync after a partial update. The intended sourcing is: **managed resources contribute their DNA fragment from the managing module's `Get`; unmanaged-but-stable host facts come from osquery.** For that to work, the module contract must require `Get` to emit a canonical fragment, and each module must declare which object identities it owns so the steward's DNA assembler can resolve authority. The resolver, the osquery fact list, and the hash/sync mechanics are ADR-017's; the two *contract clauses* are foundational to the module and belong here.

---

## Decision

### 1. The canonical standard library

**Inclusion test.** A module is stdlib iff it is part of the **declared baseline for nearly every managed machine** — it would be configured on essentially all endpoints to bring them to, and hold them in, a managed/compliant state — *or* it is a core **execution primitive** (one of the four execution paths). It must also be **CFGMS-published** (signed by the build keys compiled into the steward per ADR-006) and **ship in the installer payload**. The test is *usage across the fleet*, not capability: a module used on only a subset of machines — however powerful — is `extended`, not stdlib. "Declared baseline" includes **declare-once identity** (e.g. hostname), not only continuously-corrected state.

The standard library is exactly these **ten** modules:

| Module | Baseline role | Status |
|---|---|---|
| `file` | Files and directories (content, ownership, permissions/ACLs) | exists |
| `service` | OS services (systemd, Windows Service, launchd) | exists |
| `package` | OS package installation/removal | exists |
| `script` | Staged, signed script execution — **execution primitive** (path 2) | exists |
| `firewall` | Host firewall rules | exists |
| `patch` | OS patch/update compliance | exists (no `module.yaml`, stub unverified) |
| `user` | Local users & groups, membership, password/lock state, disable defaults | **net-new** |
| `cert_trust` | System trust store — install/trust CA & certs; keeps the CFGMS mTLS chain healthy fleet-wide | **net-new** |
| `time` | Timezone + NTP/time-sync (skew breaks Kerberos, cert validation, log correlation) | **net-new** |
| `hostname` | System/computer name & workgroup (domain join → `extended/activedirectory`) | **net-new** |

`script` is stdlib as an execution primitive rather than by the usage test. Four modules (`user`, `cert_trust`, `time`, `hostname`) have **no management code today** — only read-only DNA-collection fragments exist for users/hostname under `features/steward/dna/`, which fold into the new modules' `Get`. Building these is real cross-platform implementation work, not relocation.

This set is **closed**: adding an eleventh stdlib module is an ADR-level decision, not an incidental addition.

**Deliberately excluded from stdlib** (→ `extended/`, because each is used on only a subset of the fleet): `registry` and `scheduled_task` (not touched on typical endpoints), `network` (major OSes default to DHCP, so static config is a minority of machines), and `mount` / `sysctl` / `env` (server- or scenario-specific). Their exclusion is a usage-frequency call, not a judgment on importance; any may be built as an `extended` module when needed.

### 2. Repository and build layout

Modules are separated in the source tree by distribution class:

```
features/modules/
  stdlib/     <name>/   ← the six above; installer payload
  extended/   <name>/   ← CFGMS-authored, non-stdlib; built as standalone bundles, NOT in the installer
  adapter/              ← shared module runtime/contract code (unchanged)
```

- `stdlib/` is the **only** set compiled into / shipped with the installer.
- `extended/` modules (today: `acme`, `activedirectory`, `hyperv`, `github_runner`, `network_activedirectory`) are built as standalone signed bundles, published to the controller cache, and pulled on demand exactly as ADR-006 describes. They are **absent from a fresh steward** until a cfg references them.

The `stdlib` / `extended` names are chosen to pair with the "standard library" concept and to name the distinguishing axis (installer-payload vs on-demand). `extended` is used rather than `contrib` because these modules are CFGMS-authored, not third-party contributions. Relocation is mechanical but touches import paths; each module's move is a discrete story, and an actively-developed module (e.g. `hyperv`) may migrate as part of its own epic to avoid mid-flight churn.

Extracting `extended/` modules into separate repositories is **out of scope**; they remain in-repo under `extended/` for now.

### 3. Installer payload boundary

The installer payload manifest lists exactly the `stdlib/` bundles. The build fails if the payload manifest and the `stdlib/` directory disagree. This makes the "stdlib = installer payload" statement from ADR-006 mechanically true rather than conventional.

### 4. Module `Get` emits a canonical DNA fragment

Every module's `Get` returns, for each object it manages, a **canonical, deterministically-serialisable DNA fragment**:

- Addressed by a stable **object identity** (see clause 5).
- **Canonical serialisation** — fixed field ordering, normalised value encoding — so the same observed state always produces the same bytes and therefore the same hash on both steward and controller.
- **Stable desired-comparable fields only** — no ephemeral/runtime fields (live PIDs, current CPU/memory, timestamps). Ephemeral telemetry is not DNA and is out of scope for this contract.

The fragment is the module's authoritative DNA contribution for its objects. Its shape and the aggregation are defined in ADR-017; this ADR requires only that `Get` produce it.

### 5. Modules declare the object identities they own — atomic, object-level

Every module declares in `module.yaml` the **object-identity namespace** it authoritatively owns, e.g.:

```yaml
# module.yaml — DNA ownership declaration
owns:
  - kind: service          # authority over service:* objects this module manages
```

Authority is **atomic at the object level**: when an active module owns an object, it owns that object's **entire** DNA fragment — every property of it. A single object's properties are **never** split across two sources. At DNA assembly the steward excludes any object claimed by an active module from osquery's DNA contribution; on module uninstall, authority reverts (to osquery if the object's facts are in the curated allowlist, else the fragment disappears). The resolver that performs this is ADR-017's; this ADR requires the **declaration** that makes it possible.

Sub-property co-authorship of one object (module owns some fields, osquery others) is explicitly rejected — it re-introduces the two-sources-one-fragment non-determinism that breaks partial-sync hash validation.

### 6. Stdlib completeness is an enforced gate

A CI/build check (Makefile target) asserts, for every module under `stdlib/`, that it:

1. is present in the `stdlib/` directory **and** the installer payload manifest (clause 3),
2. builds a bundle with a valid `module.yaml` (executors, behavioral envelope, signing metadata),
3. exposes a `Get` that emits a canonical DNA fragment (clause 4),
4. declares its owned object identities (clause 5),
5. contains no unresolved stub in its enforcement path (no `stub_*` / `panic("TODO")` / `ErrNotImplemented` in the `Set`/`Get` code path).

This converts "make sure they are all built" from a one-time audit into a standing invariant. The immediate consequence: `patch` must gain a `module.yaml`, and its `stub_patch_manager` must be verified real (or completed) before the gate passes.

---

## Out of Scope

Deferred to ADR-017 (DNA composition & sync) or later work:

- The **DNA assembly + hash + partial-sync** mechanics and the **authority resolver** runtime.
- The **curated osquery DNA-fact query list** — deliberately deferred until the stdlib set is confirmed, because the managed surface determines what osquery should cover.
- **Observe-only vs managed fragment tagging** and its interaction with drift modes (`auto_correct` / `report_only`).
- **Ephemeral telemetry / monitor streams** (live process and resource views) — a separate, unhashed pipe, not DNA.
- **Separate-repo extraction** of `extended/` modules.

---

## Consequences

### Positive

1. **Enforceable stdlib**: completeness and compliance are a CI invariant, not a hope. The `patch` manifest gap would have shipped silently under the old flat layout.
2. **Clean distribution boundary**: the source tree mirrors the installer-payload-vs-on-demand split, so "what ships in the installer" is unambiguous.
3. **DNA on a firm contract**: modules produce deterministic fragments and declare ownership, giving ADR-017 a stable foundation and keeping authority single-sourced per object.
4. **Non-stdlib room to grow**: `extended/` can accumulate CFGMS modules without diluting the stdlib or the installer.

### Negative

1. **Relocation churn**: moving ~5 modules to `extended/` and 6 to `stdlib/` touches import paths across the tree; must be sequenced to avoid colliding with active module work (notably `hyperv`).
2. **Net-new stdlib build**: `user`, `cert_trust`, `time`, and `hostname` do not exist yet and must be built cross-platform before the completeness gate passes — a real implementation effort, not just relocation. Plus `patch` needs a `module.yaml` and its stub resolved. This makes the module-foundation work a build epic, not an audit; it likely splits into (a) reorg + contract + gate + `patch`, and (b) the four new modules.
3. **Contract surface on every module**: the `Get`→fragment and `owns:` clauses add required surface to every module, stdlib and extended alike.

### Neutral

- The `stdlib` / `extended` names are a convention; renaming later is a mechanical move.
- `adapter/` (shared runtime) is unaffected by the split.

---

## Alternatives Considered

### Keep the flat layout, distinguish by a manifest tag

Mark each `module.yaml` with `tier: stdlib|extended` and leave the directory flat.

**Rejected:** the installer-payload boundary stays a convention enforced only by reading manifests; nothing physically prevents a non-stdlib module from being swept into the payload. A directory boundary is checkable by the build with no manifest parsing.

### Sub-property (field-level) DNA authority

Let a module own some fields of an object while osquery contributes the rest.

**Rejected:** two sources contributing one object's fragment can disagree by a field and make the fragment hash non-deterministic, breaking exactly the partial-sync completeness validation DNA exists to provide. Object-level atomic authority keeps every fragment single-sourced.

### Define the osquery fact list now, in parallel with stdlib

**Rejected (deferred):** the set of facts osquery should feed into DNA is the complement of the managed surface. Defining it before the stdlib set is confirmed risks osquery and modules both claiming the same objects. The list is authored in ADR-017 once clause 1 here is settled.

---

## References

- [ADR-006](006-module-packaging-and-distribution.md) — Module Packaging and Distribution (this ADR extends it)
- ADR-017 — DNA Composition & Sync (forthcoming; depends on clauses 4 and 5)
- `CLAUDE.md` — Modules section, four execution paths, banned patterns
- `docs/product/roadmap.md` — Captured Backlog (module foundation, OSquery, controller baseline DNA)
