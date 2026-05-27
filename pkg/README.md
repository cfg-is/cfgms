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
