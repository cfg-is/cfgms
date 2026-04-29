# ADR 003: Storage Data Taxonomy

**Status**: Proposed

**Date**: 2026-04-13

**Deciders**: Development Team

**Related**: ADR-001 (Central Provider Compliance Enforcement), `docs/product/feature-boundaries.md`, `docs/architecture/storage-architecture.md`

## Context

### Scope

This ADR covers **controller-side storage only**. Steward persistence (local config file, OS keychain for certificates/secrets, in-memory state between convergence runs) is a simpler, separate concern and is deliberately out of scope.

### Current State

CFGMS currently models storage as "one provider implements many stores." A single global provider — `git` or `database` — is selected at deploy time and implements every store interface (`ConfigStore`, `AuditStore`, `RBACStore`, `RuntimeStore`, `RegistrationStore`, `ClientTenantStore`, `TenantStore`, M365 variants).

Two assumptions are baked into that shape:

1. One backend suits every data category.
2. Git is a viable general-purpose storage backend.

Both assumptions have broken down as scale and SaaS requirements have tightened.

### Scale Pressure

CLAUDE.md states the target of **50k+ Stewards** per controller deployment. At that scale, several data categories have requirements that differ sharply:

- **Business data** (tenants, stewards, commands, RBAC): high-write, transactional, queryable, must survive restart
- **Config data**: human-editable, versioned, often edited through external workflows (GitOps)
- **Secrets**: encrypted at rest, rotation auditable, often backed by a key vault
- **Timeseries** (metrics, logs): high-volume append-only, retention-driven, purged by age
- **Blobs** (installer binaries, reports, large artifacts): large-object, cheap storage, CDN-fronted in SaaS

A single global backend cannot serve all five well.

### Licensing Boundary

`docs/product/feature-boundaries.md:27` lists the OSS track as "Git, SQLite, PostgreSQL" and the commercial track as the same plus HA-optimized PostgreSQL. SQLite is advertised but not implemented. Git is listed as a storage backend but is a poor fit for anything other than small, human-edited config files.

### Concrete Deficiencies

Verified during exploration; each becomes a sub-issue under the epic tracked by this ADR:

1. **No SQLite provider.** `pkg/storage/providers/` contains only `database/` (PostgreSQL) and `git/`.
2. **No flat-file provider.** Needed to replace the git provider as the OSS file-based option.
3. **Git provider's `RuntimeStore` is memory-backed.** `pkg/storage/providers/git/plugin.go:152-166` returns `cache.NewRuntimeCache(...)` with a comment admitting "runtime sessions are ephemeral." Persistent-session semantics silently lost on git deployments.
4. **No `StewardStore`.** Steward fleet state (last-seen, heartbeat, status) is in-memory only in `features/steward/health.go`. Controller restart loses the fleet view.
5. **No persistent command dispatch.** `features/steward/commands/handler.go` tracks executing commands in-memory. No crash-survivable audit trail.
6. **Secrets run parallel to storage.** SOPS and steward crypto live outside the storage abstraction; no unified rotation/audit interface.
7. **No `BlobStore` interface.** Large artifacts embed in configs or write to disk ad hoc.
8. **No git-sync component.** No mechanism to pull from a tenant's external git origin (GitHub/GitLab) into a durable backend.

## Decision

### 1. Five-Type Storage Taxonomy

Storage is partitioned by data type, not by a single global backend. Each type has its own interfaces and its own backend selection. Deployments compose one provider per type.

| Type | OSS default | Commercial/SaaS default |
|------|-------------|-------------------------|
| Business data | SQLite | PostgreSQL |
| Config storage | Flat file | PostgreSQL |
| Config *git sync* (optional, per-scope) | Flat file ⇄ external git origin | PostgreSQL ⇄ external git origin |
| Secrets | SOPS files | Key vault (AWS Secrets Manager / HashiCorp Vault / Azure Key Vault) |
| Timeseries | Local log files | ClickHouse / Timescale / Influx |
| Blobs | Local filesystem | S3-compatible object storage |

**The OSS column shows the zero-config default, not a limit.** Any backend listed in the Commercial column is available to OSS deployments. The licensing boundary is tenant-tree shape (single-root vs multi-root), not backend choice — see `docs/product/feature-boundaries.md`. An OSS single-root deployment is free to run PostgreSQL for business data, a key vault for secrets, and S3 for blobs if the operator wants that.

### 2. Interface Mapping

`pkg/storage/interfaces/` is reorganized into subdirectories per type:

| Type | Interfaces |
|------|------------|
| `business/` | `TenantStore`, `ClientTenantStore`, `StewardStore` (new), `CommandStore` (new), `AuditStore`, `RBACStore`, `SessionStore` (new — extracted from `RuntimeStore`), `RegistrationTokenStore` |
| `config/` | `ConfigStore` |
| `secrets/` | `SecretStore` (new) — unifies SOPS and vault providers |
| `timeseries/` | `MetricsStore` (new), `LogStore` (new) |
| `blob/` | `BlobStore` (new) |

Providers implement one or more type interfaces (not all). A deployment's storage config names one provider per type.

**`ClientTenantStore` absorbs provider-specific variants.** The current `M365ClientTenantStore` is folded into `ClientTenantStore`; provider-specific data (M365 consent state, AD domain binding, Intune enrollment) is carried as extension fields on the unified entity. Cross-entity identity is an explicit design goal: a single endpoint must be correlatable across steward / Intune / AD, and a single user must be correlatable across AD / Intune / active sessions. Sub-stories touching `ClientTenantStore` must preserve this correlation capability. The concrete correlation model (identity keys, resolution rules) is out of scope for this ADR and will be its own follow-up.

**`RuntimeStore` is retired, not reorganized.** The current `RuntimeStore` interface mixes durable session state with ephemeral resolved-config memoization. Under this ADR:
- Durable session state moves to `business/SessionStore`.
- Ephemeral/derived state (resolved configs, inheritance memoization, anything rebuildable on restart) moves to `pkg/cache` with no storage interface at all.
- `RuntimeStore` ceases to exist.

General rule for the epic: **anything named `*Store` is durable; anything ephemeral is named `*Cache` and lives under `pkg/cache/`.**

### 3. Git Is a Sync Source, Not a Storage Backend

The existing `pkg/storage/providers/git/` is **deprecated and removed**. Git re-enters the architecture as an optional *sync source* for admin-designated config scopes.

**Replacement for OSS file-based storage**: a new **flat-file** provider. The admin is responsible for backups of the flat-file tree (filesystem snapshots, rsync, restic, etc.). CFGMS does not manage versioning or history at the storage layer.

**Git-sync model** (single component, shared across OSS and commercial):

- Admin binds a config scope (tenant path + namespace, e.g., `root/msp-a/client-1/firewall`) to an external git origin: URL, branch, credentials reference.
- Git-sync pulls from the origin on webhook (push event) with a polling fallback.
- Imported configs write through to the chosen config backend — flat-file (OSS) or PostgreSQL (commercial).
- Scopes without a git binding live natively in the backend.
- Read path is always the backend; git is the editing surface for bound scopes, not a query target.
- **v1 is one-way, read-only** (git → backend). The controller never writes back to the git origin. For bound scopes, all edits happen at the git origin (PRs, commits, merges via the tenant's normal GitOps workflow) and flow down via sync. Bidirectional sync (backend → git commits for UI-initiated edits) is explicitly out of scope for v1 and will be a future ADR if demand emerges.

This gives tenants their existing GitHub/GitLab PR workflow without CFGMS hosting git. One code path serves both OSS and commercial deployments.

### 4. Implementation Sequence

Tracked under the epic referenced in [Code Changes Required](#code-changes-required). Ordered to unblock SaaS first:

1. Flat-file provider (replaces git provider for OSS)
2. `StewardStore` + persistent fleet registry
3. ~~Deprecate and remove `pkg/storage/providers/git/`~~ **Done** (Issue #664)
4. SQLite provider for OSS business data
5. Persist command dispatch (audit-integrated)
6. Git-sync component
7. `BlobStore` interface + filesystem/S3 providers
8. `SecretStore` unification (SOPS + vaults)
9. Reorganize `pkg/storage/interfaces/` into type subdirectories

### 5. Out of Scope

- Queue and cache subsystems. Durable-adjacent, but not storage. Separate ADRs later.
- Steward-side persistence. Handled by local config files and OS keychain; not pluggable.

## Consequences

### Positive

1. **OSS↔commercial symmetry**: one git-sync path, two backend targets. No forked codebase.
2. **Admin-owned backups**: removing the git provider eliminates a surprising abstraction (git commits per write) and hands backup responsibility to the operator, who can use standard filesystem tools.
3. **Tenant workflow preserved**: MSPs continue editing config on their own GitHub/GitLab; git-sync imports the result.
4. **Clean swap boundaries**: a new timeseries backend doesn't force rewriting config or business stores.
5. **SaaS-ready**: SQLite/flat-file for OSS, PostgreSQL/S3/vault for SaaS — each type picks its own scaling story.
6. **Eliminates the `RuntimeStore` memory-cache lie**: the broken git implementation goes away. Durable pieces move to `SessionStore`; ephemeral pieces move to `pkg/cache`. No more interface pretending to be storage while returning a cache.
7. **Purges controller concerns from steward paths**: drift event storage, M365 admin-consent `ClientTenantStore`, and similar controller-side interfaces currently living under `features/steward/*` and `features/modules/m365/auth/*` relocate to the canonical `pkg/storage/interfaces/` tree. One authoritative location per interface.

### Negative

1. **Larger interface surface.** Five type directories, new interfaces (`StewardStore`, `CommandStore`, `SecretStore`, `MetricsStore`, `LogStore`, `BlobStore`).
2. **Flat-file provider is net-new work.** No free ride from the removed git provider — the flat-file provider has to earn its reliability.
3. **Admins lose automatic versioning.** The git provider auto-committed on every write; flat-file does not. Admins must configure their own backup/versioning. This is documented in the flat-file provider's README and release notes.
4. **Migration path for git-storage deployments.** Any existing production git-storage deployment needs a one-time export into flat-file or PostgreSQL. The deprecation story (sub-issue B) owns this migration tool.
5. **Git-sync is a new operational surface.** Webhook endpoints, credential storage, reconciliation loops. New failure modes to design for.

### Mitigations

- **Backup guidance**: flat-file provider ships with a documented `cfg backup` CLI helper that wraps standard tools (tar, restic). Listed in the provider's README.
- **Migration tool**: sub-issue B delivers `cfg storage migrate --from git --to flatfile|postgres` before the git provider is removed.
- **Git-sync reliability**: idempotent imports, per-scope error isolation, exponential backoff on origin failure. Covered in the git-sync sub-issue's acceptance criteria.

## Alternatives Considered

### Alternative 1: Keep Git as a Storage Provider, Add Git-Sync on Top

**Approach**: Leave `pkg/storage/providers/git/` in place. Add a separate git-sync component that runs alongside Postgres deployments.

**Rejected because**:
- Two code paths doing substantially similar work (commit on write vs. pull from origin)
- OSS and SaaS diverge architecturally — a bug found in one path doesn't necessarily fix the other
- Git provider's `RuntimeStore` memory-cache issue remains
- Admin still shoulders git-provider failure modes (merge conflicts on high-write paths) with no benefit

### Alternative 2: Require Postgres for All OSS Deployments

**Approach**: Drop file-based storage entirely; Postgres is the only supported backend.

**Rejected because**:
- Raises the OSS barrier to entry significantly — a single-binary MSP demo now requires a database
- Contradicts `feature-boundaries.md` which advertises flat-file-class options for OSS
- Over-serves the small-deployment end of the market

### Alternative 3: Per-Store Provider Selection Without the Taxonomy

**Approach**: Keep the flat list of stores (`ConfigStore`, `AuditStore`, etc.). Let each store pick a provider independently but don't group into types.

**Rejected because**:
- Doesn't give providers a natural shape — a "secrets provider" would still need to implement unrelated store interfaces
- Doesn't match how backend technology choices actually cluster (business → SQL; timeseries → columnar; blobs → object storage)
- Leaves the door open to new stores being added ad hoc without a home

### Chosen Approach: Five-Type Taxonomy + Flat-File + Git-Sync

Cleanest shape for the backend-technology clusters we actually need, preserves the tenant GitOps workflow, and lets a single git-sync code path serve both OSS and SaaS.

## Code Changes Required

This ADR ratifies the direction. Implementation is tracked by the epic **Storage Architecture: Five-Type Data Taxonomy (ADR-003)** with the following sub-stories (priorities reflect SaaS-unblock ordering):

| # | Title | Priority | Depends on | Status |
|---|-------|----------|------------|--------|
| A | Flat-file storage provider (OSS file-based backend) | P0 | — | **Merged** (Issue #661) |
| C | SQLite storage provider for OSS business data | P0 | — | **Merged** (Issues #662, #663, #665) |
| D | `StewardStore` interface + persistent fleet registry | P0 | A, C | **Merged** (Issue #663) |
| E | Persist command dispatch state (audit-integrated) | P1 | C | **Merged** (Issue #665) |
| J | Composite storage manager + OSS factory (`NewStorageManagerFromStores`, `CreateOSSStorageManager`) | P0 | A, C, D, E | **Merged** (Issue #692) |
| B | Deprecate and remove `pkg/storage/providers/git/` | P1 | A, J | In progress (Issue #664) |
| F | Git-sync component (shared OSS/commercial) | P1 | A | Not started |
| G | `BlobStore` interface + filesystem and S3-compatible providers | P2 | — | **Merged** (Issue #667) |
| H | `SecretStore` interface unifying SOPS and key vaults | P2 | — | Not started |
| I | Reorganize `pkg/storage/interfaces/` into type-based taxonomy | P2 | A, B, C, D, E, F, G, H | Not started |

**Dependency order** (must be respected by the Planning Team when decomposing this epic):

```
A, C  →  D, E, F  →  B  →  G, H  →  I
```

- A (flat-file) and C (SQLite) have no dependencies and can proceed in parallel.
- D (StewardStore) needs at least one backend (A or C) to persist into; the story must be built against both.
- B (remove git provider) can only land after A exists as its OSS replacement.
- F (git-sync) requires A (flat-file write-through target).
- I (interfaces reorganization) lands last so it doesn't cause churn during the earlier stories.

Each sub-story has its own testable acceptance criteria. This ADR is the shared source of truth for the taxonomy and the git-sync model.

## Documentation Currency

Any sub-story under this epic that changes the shape of the product — adds or removes a backend, changes the OSS/commercial boundary, renames a public interface, changes config schema, or moves an interface between packages — **must update the following in the same PR**:

- `docs/product/feature-boundaries.md` — if backend lists or licensing boundary wording changes
- `docs/architecture/storage-architecture.md` — operator walk-through of the taxonomy
- `pkg/storage/interfaces/README.md` — if interface inventory changes
- Any deployment, testing, or troubleshooting doc that names the changed interface or backend

Acceptance criteria for those stories **must include** a "Docs updated" checkbox that enumerates the files touched. Tests covering product-shape changes (test fixtures, integration tests, contract tests) must also be updated in the same PR. Stories that skip this are not "done" regardless of code state.

## Controller Interface Location

No controller-side storage, logging, or persistence interface may live under `features/steward/*` when this epic closes. Known offenders the sweep must relocate (non-exhaustive — sub-story I is responsible for the full audit):

- `features/modules/m365/auth/admin_consent_flow.go` — duplicate `ClientTenantStore` interface (redundant with the canonical `pkg/storage/interfaces/ClientTenantStore`; must be unified)

Rule of thumb: **if a steward does not use the interface, it does not belong under `features/steward/`.** Sub-story I includes an exhaustive audit and relocation pass, and the story's acceptance criteria must include `grep` evidence that no controller-only interfaces remain under `features/steward/*`.

## References

- `docs/architecture/decisions/001-central-provider-compliance-enforcement.md` — format template and the "pluggable by default" principle this ADR builds on
- `docs/product/feature-boundaries.md` — OSS/commercial line and storage backend advertisement
- `docs/architecture/ha-commercial-split.md` — build-tag pattern for OSS vs commercial code paths
- `docs/architecture/storage-architecture.md` — operator-facing walk-through of this decision (renamed from `hybrid-storage-solution.md`)
- `pkg/storage/providers/git/plugin.go:152-166` — evidence for git-provider deprecation (`RuntimeStore` memory-cache admission)
- `features/steward/health.go` — in-memory fleet state (motivates `StewardStore`)
- `features/steward/commands/handler.go` — in-memory command dispatch (motivates `CommandStore`)
- `pkg/storage/interfaces/` — current interface layout being reorganized
- CLAUDE.md — 50k+ steward scale target, pluggable-by-default rule
