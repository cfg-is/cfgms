# Central Providers (`pkg/`)

This directory contains **Central Providers** - shared packages that provide cross-cutting functionality used by multiple features.

## Golden Rule

**If functionality is needed by >1 feature, it MUST use or become a central provider.**

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
- Examples: `storage`, `logging`, `secrets`, `directory`, `mqtt`

**Direct Providers** (no `interfaces/` subdirectory):
- Single implementation
- Direct import by business logic
- Examples: `cert`, `telemetry`, `cache`, `session`

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

3. **Will it have multiple implementations?**
   - ✅ Yes → Create pluggable provider with `interfaces/`
   - ❌ No → Create direct provider

4. **Update CLAUDE.md** - Add to Central Provider System list

## Architecture Enforcement

**Automated checks prevent violations:**
- `make check-architecture` - Scans staged files pre-commit
- `/story-commit` - Blocks commits with violations
- `/pr-review` - Validates compliance in Phase 2

See `CLAUDE.md` Central Provider System section for the complete list of providers and rules.
