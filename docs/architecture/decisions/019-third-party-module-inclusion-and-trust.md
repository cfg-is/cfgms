# ADR-019: Third-Party Module Inclusion and Delegated Publisher Trust

**Status:** Proposed
**Date:** 2026-07-04
**Issue:** (to be assigned at decomposition)
**Epic:** (module-trust epic — to be filed)

---

## Context

ADR-006 established the module trust primitives — signed out-of-process bundles, CFGMS publisher keys **baked into the steward binary at build time**, a controller approval workflow, and end-to-end signing. It left two things unresolved that matter for a multi-tenant SaaS deployment:

1. **How a tenant includes and trusts a third-party module** — one written by an internal team or a vendor CFGMS has never heard of, for a trusted line-of-business app.
2. **The runtime/SaaS reality.** ADR-006's boundary — "no runtime key store; adding a publisher requires a steward rebuild" — is incompatible with SaaS: the operator compiles stewards centrally and ships one binary to all clients, and cannot recompile per tenant to bake in each tenant's LOB vendor keys.

### Current state (audit, 2026-07-04)

An audit of the tree found the bundle/trust machinery is largely **unbuilt on the steward** — this ADR designs a target model, not a patch to a working system:

- **Steward endpoint modules are statically compiled into the binary** (`features/steward/factory/factory.go:171`, `:144`). No bundle, no signature, no trust check on the steward path.
- `required_modules:` resolution (`features/controller/modules/resolution/`), the steward bundle runtime + trust enforcer (`features/steward/modules/runtime`, `.../trust`), and `module_trust.additional_publishers` (`trust.go:80` `TODO: v2`) are **built-but-orphaned or stub** — zero production callers.
- The git-repo module lineage (`features/config/git/module_repository.go`, `BasicSecurityScanner`) is **legacy-dead** — no production callers; its scanner is never registered.
- The **only live bundle path** is controller-side **workflow** (controller-kind) modules (M365/Entra): cache → approval → fork/exec.
- Trust/approval/cache are **global** — no per-tenant scoping.

The verify primitives themselves (`pkg/modules/trust/verify.go`, the approval rules) are real and correct; they are simply only reachable from the controller workflow path today.

### The conflation this ADR resolves

"How modules work" hides three independent axes. DSC blurs the first two:

- **Distribution** — where a module comes from and how it reaches the host.
- **Trust / admission** — whether we will run it.
- **Declaration** — whether a config must name what it uses.

CFGMS has a central controller, so it can decouple these in a way per-project package managers (go.mod, npm) cannot: make the **controller the admission authority**, so admins configure trust **once**, and everyday configs consume without ceremony.

---

## Decision

### 1. Signed-only, universally

Every module — stdlib, CFGMS-extended, and third-party — is a **signed bundle**. There is **no unsigned or source-trust tier.** The legacy git-source + scanner lineage (Lineage B) is retired, not revived. "Unsigned code on an endpoint" is outside the threat model; a git repo of module *source* is not a distribution mechanism.

### 2. Two planes: admission (controller) and usage (config)

| Plane | Who / when | What it does |
|---|---|---|
| **Admission** | Privileged admin, rarely, **per tenant**, audited | Declares what may enter *this tenant's* fleet (trusted publishers, feeds, pins). The controller approval workflow + cache is the single chokepoint. |
| **Usage** | Everyday config authoring, zero-ceremony | A cfg references a module by coordinate; it does **not** re-declare or re-establish trust. If the controller has admitted it, the steward pulls and runs it. |

This is the PowerShell "use an installed module without importing it" model: the controller's admitted set *is* the host's available modules. A config that references an un-admitted module fails resolution (as `resolution.go` already does).

### 3. Trust spectrum — all signature-based, pinning is the default

All rungs verify a publisher signature; they differ only in how much the admin pins:

| Rung | Meaning | Posture |
|---|---|---|
| **CFGMS root** | Publisher key baked into the steward binary | Always trusted; immutable; cannot be added/removed via config |
| **Publisher + version pinned** | Trust publisher K for module M at a pinned version/content-hash | **Default** for third-party |
| **Publisher-wide auto-admit** | Trust publisher P wholesale — anything signed by P auto-admits, no per-module pin | Opt-in loosening, for a fully-trusted publisher (e.g. the tenant's own internal team) |
| **Version/content pin** | Lock a specific version + `content_hash` for reproducibility | Orthogonal knob, composes with any rung |

The **publisher-wide auto-admit** rung is what satisfies "internal teams don't want to pin every module" **without** unsigned code: they trust their own signing identity once, and everything it signs flows in. Default remains pinned; wholesale trust is a deliberate opt-in per publisher.

### 4. "Trusted repo/feed" = a signed-bundle distribution source

A "trusted repository" is a **distribution source of signed bundles** (a feed, or a git repo that publishes signed bundle releases), pinnable by version/tag/commit. Trust still rides the **signature**, not the source location. Staging a bundle from such a source into the controller cache is the same operation as any other bundle admission.

### 5. Per-tenant admission and trust scoping

Admission, approval, trust config, and cache identity are **per tenant**. Because a steward belongs to exactly one tenant, its admitted set and trusted publishers are naturally its tenant's — one tenant trusting a vendor never leaks to another. This requires threading `tenantID` into the approval cache key, trust store, and resolution (all global today — a gap this ADR mandates closing).

### 6. Runtime-configured additional publishers (amends ADR-006)

The CFGMS root key stays **baked in and immutable**. *Additional* publishers are configured at runtime, **per tenant**, via `module_trust.additional_publishers` — and its name→key resolution (`trust.go:80`) is implemented. This **amends ADR-006's "no runtime key injection"**: that boundary protected the *root anchor*, which is preserved; delegating *additional* third-party trust to the tenant is deliberate, because the tenant owns that risk inside its own boundary.

Because this reopens the config-push escalation ADR-006 closed, additional-publisher and pin changes are a **high-friction, admin-mTLS-gated, prominently-audited** operation — not a routine `cfg push` — consistent with the "rarely-touched settings that bound blast radius" in the threat model.

### 7. Per-publisher / per-module trust mode

`module_trust.mode` (`strict` / `controller` / `bypass`) becomes configurable **per-publisher or per-module**, as ADR-006 intended (the code implements only a single global enum today). A tenant can, e.g., require `strict` independent verification for a high-value LOB publisher while accepting `controller` attestation for others.

### 8. Usage-plane resolution

A `resources[].module` reference resolves to an admitted coordinate for the tenant. `required_modules:` is repositioned as an **optional reproducibility / version-pin manifest**, not a trust gate. The controller resolves a bare module name to the tenant's admitted bundle; ambiguity (multiple publishers/versions) is resolved by an explicit pin or a tenant default. The built-in-short-name namespace and the publisher-qualified-coordinate namespace **converge** on the admitted-coordinate model.

### 9. Dev-test with signing

- **Pure local iteration:** ADR-006 `bypass` trust mode (development flag only; a production steward that receives `bypass` logs a warning and falls back to `controller`). No signing required to iterate locally.
- **Signed internal testing:** an internal/dev CFGMS publisher cert (a distinct dev signing identity) trusted by **non-production** stewards, so teams exercise the real signed path without the production key. Production stewards never trust the dev identity and never accept `bypass`.

---

## Out of Scope / Prerequisites

- **Steward bundle-load runtime.** This ADR presumes the steward can fork/exec signed bundles. Today it cannot (compiled-in built-ins). **Wiring the bundle runtime and converting built-ins/stdlib to bundles is a prerequisite owned by the module-foundation epic (ADR-016)** — whose scope the audit enlarges accordingly. This ADR designs the trust/inclusion model that rides on top.
- **Real-time revocation propagation** (ADR-006 deferred) — matters more for third-party.
- **External/OCI registry resolver** (ADR-006 deferred) — richer "trusted feed" sourcing beyond controller staging.
- **The concrete name→bundle resolution/disambiguation algorithm** — an implementation detail of the module-foundation work.

---

## Consequences

### Positive

1. **SaaS-viable third-party trust**: tenants add their own publishers via config, with no per-tenant steward rebuild.
2. **Low friction**: admins configure trust once, centrally, per tenant; everyday configs carry no trust ceremony; publisher-wide auto-admit removes per-module pinning for trusted internal teams.
3. **Threat model intact**: signed-only; the CFGMS root stays baked-in and immutable; trust changes are audited/high-friction; blast radius is per-tenant.
4. **Reuses working primitives**: the signature/approval code already exists and is correct — this wires and generalises it rather than inventing new crypto.
5. **One coherent model**: retiring the git-source lineage removes a second, contradictory front door.

### Negative

1. **Depends on unbuilt foundation**: nothing here runs until the steward bundle-load path exists (module-foundation/ADR-016). This ADR is target-state.
2. **Reopens a closed surface**: runtime additional-publisher trust reintroduces config-push escalation risk, mitigated (not eliminated) by mTLS-gating, audit, and per-tenant scoping.
3. **Per-tenant scoping is new work**: threading `tenantID` through cache/approval/trust touches several global singletons.
4. **`additional_publishers` must be built**: the name→key resolution stub becomes load-bearing.

### Neutral

- `required_modules:` shifts meaning (trust gate → optional reproducibility pin) — a re-scope of an existing, currently-dormant field.
- Retiring Lineage B removes dead code; confirm no open epic depends on the planned MSP module-repo (`RepositoryType{MSPModules,ClientModules}`) before deletion.

---

## Alternatives Considered

### An unsigned / source-trust tier (revive Lineage B)

Let internal teams reference unsigned module source from a trusted git repo, no signature.

**Rejected (founder decision):** puts unsigned, unpredictable code on endpoints, contradicting the threat model's "signed binaries, no obfuscation." CFGMS modules are binaries, so source would also need a build-or-scan pipeline that does not exist. The low-friction goal is met instead by publisher-wide auto-admit of *signed* modules.

### Per-config declaration like go.mod / npm

Require every config to declare and pin its modules in a manifest.

**Rejected:** that ceremony exists in language package managers *because they have no central authority*. CFGMS has the controller as admission authority, so trust is declared once centrally, not per config. Version pinning remains available as an optional reproducibility knob.

### Keep ADR-006 as-is (baked-in keys only)

**Rejected:** requires a steward rebuild + rollout per new publisher — infeasible for SaaS where one binary ships to all tenants and each tenant has different LOB vendors.

### Controller re-signs, or a single global trust set

**Rejected:** breaks end-to-end signing (ADR-006) and per-tenant isolation. The controller attests and caches; it does not re-sign, and trust is scoped per tenant.

---

## References

- [ADR-006](006-module-packaging-and-distribution.md) — Module Packaging and Distribution (**this ADR amends** the publisher-identity and trust-mode sections)
- [ADR-016](016-steward-module-foundation.md) — Steward Module Foundation (**prerequisite** — provides the bundle runtime + stdlib-as-bundles this ADR presumes)
- [ADR-017](017-dna-composition-and-sync.md) — DNA Composition & Sync
- `CLAUDE.md` — Modules section, threat model (rarely-touched trust settings), four execution paths
- Module inclusion/trust audit (2026-07-04) — current-state findings cited in Context
