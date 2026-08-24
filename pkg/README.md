# Central Providers (`pkg/`)

This directory contains **Central Providers** - shared packages that provide cross-cutting functionality used by multiple features.

## Golden Rules

1. **If functionality is needed by >1 feature, it MUST use or become a central provider**

2. **All central providers SHOULD be pluggable by default** (with `interfaces/` subdirectory)
   - Default assumption: Create pluggable provider with interfaces
   - Exception: True utilities or proven single-implementation cases
   - **When in doubt: Make it pluggable** - removing abstraction is harder than adding it

### Why Pluggable by Default?

- **Real-world examples**: Even "single implementation" providers often need alternatives:
  - `cert`: Internal CA, Let's Encrypt, HashiCorp Vault, external PKI
  - `cache`: Memory, Redis, Memcached, Hazelcast
  - `telemetry`: OpenTelemetry, Datadog, New Relic, Prometheus
- **CFGMS characteristics favor pluggable**:
  - Multi-tenant SaaS (different backends per tenant)
  - Commercial/Open Source split (easy feature gating)
  - 50k+ Stewards at scale (swappable backends)
  - Cloud vs On-Prem deployments

- **Bug prevention**: The dual-CA bug would have been impossible with pluggable cert provider
- **Testing**: Test implementations are trivial, no mocking needed
- **Future-proofing**: Cheap to add now, expensive to retrofit later

## Identifying Central Providers

### Pattern Recognition

```
pkg/{name}/interfaces/  → Pluggable provider (multiple implementations)
pkg/{name}/             → Direct provider (single implementation)
```

**Pluggable Providers** (have `interfaces/` subdirectory):
- Support multiple backends (git, database, timescale, etc.)
- Use auto-registration pattern (Salt-style)
- Business logic imports `pkg/{name}/interfaces` ONLY
- Examples: `storage`, `logging`, `secrets`, `directory`, `controlplane`, `dataplane`

**Direct Providers** (no `interfaces/` subdirectory):
- Single implementation
- Direct import by business logic
- Examples: `cert`, `telemetry`, `cache`, `ctxkeys`

**Not Central Providers**:
- `config`, `testing`, `testutil`, `version` - utility packages

## Before Adding to `pkg/`

Ask these questions in order:

1. **Is this cross-cutting?** (Used by >1 feature?)
   - ❌ No → Keep in feature code
   - ✅ Yes → Continue

2. **Does it overlap with existing provider?**
   - ✅ Yes → Extend existing provider
   - ❌ No → Continue

3. **Is this a true utility?** (Pure functions, no state, version info, test helpers)
   - ✅ Yes → Create direct utility package
   - ❌ No → Continue

4. **DEFAULT: Create pluggable provider with `interfaces/`**
   - ✅ Start with pluggable architecture
   - ⚠️ Only create direct provider if you can justify ALL of these:
     - Will NEVER have multiple implementations (be skeptical of "never")
     - Is pure utility with no state or backend
     - Abstraction cost is demonstrably too high (rare)

5. **Update CLAUDE.md** - Add to Central Provider System list

### Valid Exceptions to Pluggable Pattern

**Only create direct providers for:**
- **True Utilities**: `version`, `testutil`, `config` - Pure functions, no state
- **Proven Single Implementation**: Strong evidence no alternative will ever be needed
- **Performance Critical**: Demonstrated abstraction overhead is unacceptable (rare)

**Current direct providers to consider migrating**:
- `cert` → Could support: Internal CA, Let's Encrypt, Vault, external PKI
- `cache` → Could support: Memory, Redis, Memcached
- `telemetry` → Could support: OpenTelemetry, Datadog, New Relic

Migration not required immediately, but when adding second implementation or during major refactoring.

## Architecture Enforcement

**Automated checks prevent violations:**
- `make check-architecture` - Scans staged files pre-commit
- `/story-commit` - Blocks commits with violations
- `/pr-review` - Validates compliance in Phase 2

See `CLAUDE.md` Central Provider System section for the complete list of providers and rules.

## Storage Capability Declaration (Issue #3407)

Subsystems that depend on a non-universal store **declare** that dependency
statically, adjacent to the code that uses the store. The composition site
**collects** those declarations and **validates** them against the constructed
`StorageManager` at startup — failing closed before any request is served.

### Why this exists

Before this mechanism, a provider returning `ErrNotSupported` for a store silently
produced a nil in the `StorageManager`. The nil propagated through four layers of
wiring before a 503 surfaced at request time, giving operators no information about
which feature broke or why (#3400).

### How to declare a requirement

In your subsystem package, create a package-level variable:

```go
// In features/controller/registration/requirements.go
var StoreRequirements = []interfaces.StoreRequirement{
    {
        Subsystem: "registration",
        Store:     interfaces.StoreNamePendingRegistration,
        Severity:  interfaces.RequirementRequired,
    },
}
```

`Subsystem` is used verbatim in startup error messages — choose a name that
identifies the feature to an operator reading logs.

Use `RequirementRequired` when the subsystem cannot function without the store.
Use `RequirementOptional` when the subsystem degrades gracefully on absence.

### How collection works

`features/controller/server/server.go:collectActiveStorageRequirements` collects
requirements from every enabled subsystem and calls
`interfaces.ValidateStorageRequirements(storageManager, reqs)` immediately after
the `StorageManager` is constructed. Collection is gated on whether the subsystem
is enabled, so a deployment that does not run a subsystem is never blocked by its
requirements.

### What a startup failure looks like

```
storage composition failed — missing required stores:
subsystem "registration" requires PendingRegistrationStore but provider "database" does not supply it
```

Each line names the subsystem, the store, and the provider — enough context to
identify which feature broke and which provider must be fixed or replaced.

### Invariants

- **Declaration is adjacent to use**: the requirement lives in the same package as
  the code that reads the store, not in a central table that drifts.
- **Disabled subsystems impose no requirement**: a deployment without workflow
  support is never forced to supply a trigger store.
- **Existing nil-checks remain**: downstream nil-checks in subsystem code are
  defence-in-depth and must not be removed — the mechanism makes them unreachable
  under correct deployments, not redundant.
- **Validation runs at startup, not at request time**: the check happens once,
  immediately after construction, before any subsystem is initialised.
