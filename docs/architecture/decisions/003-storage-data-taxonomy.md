# ADR 002: Storage Data Taxonomy

**Status**: Proposed

**Date**: 2026-04-13

**Deciders**: Development Team

**Related**: ADR-001 (Central Provider Compliance Enforcement), `docs/product/feature-boundaries.md`, `docs/architecture/hybrid-storage-solution.md`

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

| Type | OSS backend | Commercial/SaaS backend |
|------|-------------|-------------------------|
| Business data | SQLite | PostgreSQL |
| Config storage | Flat file (authoritative) or PostgreSQL | PostgreSQL (authoritative) |
| Config *git sync* (optional, per-scope) | Flat file ⇄ external git origin | PostgreSQL ⇄ external git origin |
| Secrets | SOPS files | Key vault (AWS Secrets Manager / HashiCorp Vault / Azure Key Vault) |
| Timeseries | Local log files | ClickHouse / Timescale / Influx |
| Blobs | Local filesystem | S3-compatible object storage |

### 2. Interface Mapping

`pkg/storage/interfaces/` is reorganized into subdirectories per type:

| Type | Interfaces |
|------|------------|
| `business/` | `TenantStore`, `ClientTenantStore`, `StewardStore` (new), `CommandStore` (new), `AuditStore`, `RBACStore`, `SessionStore`, `RegistrationTokenStore` |
| `config/` | `ConfigStore`, `RuntimeStore` |
| `secrets/` | `SecretStore` (new) — unifies SOPS and vault providers |
| `timeseries/` | `MetricsStore` (new), `LogStore` (new) |
| `blob/` | `BlobStore` (new) |

Providers implement one or more type interfaces (not all). A deployment's storage config names one provider per type.

### 3. Git Is a Sync Source, Not a Storage Backend

The existing `pkg/storage/providers/git/` is **deprecated and removed**. Git re-enters the architecture as an optional *sync source* for admin-designated config scopes.

**Replacement for OSS file-based storage**: a new **flat-file** provider. The admin is responsible for backups of the flat-file tree (filesystem snapshots, rsync, restic, etc.). CFGMS does not manage versioning or history at the storage layer.

**Git-sync model** (single component, shared across OSS and commercial):

- Admin binds a config scope (tenant path + namespace, e.g., `root/msp-a/client-1/firewall`) to an external git origin: URL, branch, credentials reference.
- Git-sync pulls from the origin on webhook (push event) with a polling fallback.
- Imported configs write through to the chosen config backend — flat-file (OSS) or PostgreSQL (commercial).
- Scopes without a git binding live natively in the backend.
- Read path is always the backend; git is the editing surface for bound scopes, not a query target.
- v1 is read-only (git → backend). Bidirectional sync (backend → git commits for UI-initiated edits) is a future extension.

This gives tenants their existing GitHub/GitLab PR workflow without CFGMS hosting git. One code path serves both OSS and commercial deployments.

### 4. Implementation Sequence

Tracked under the epic referenced in [Code Changes Required](#code-changes-required). Ordered to unblock SaaS first:

1. Flat-file provider (replaces git provider for OSS)
2. `StewardStore` + persistent fleet registry
3. Deprecate and remove `pkg/storage/providers/git/`
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
6. **Eliminates the `RuntimeStore` memory-cache lie**: the broken git implementation goes away; flat-file or PostgreSQL backs runtime state durably.

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

| # | Title | Priority |
|---|-------|----------|
| A | Flat-file storage provider (OSS file-based backend) | P0 |
| B | Deprecate and remove `pkg/storage/providers/git/` | P1 |
| C | SQLite storage provider for OSS business data | P1 |
| D | `StewardStore` interface + persistent fleet registry | P0 |
| E | Persist command dispatch state (audit-integrated) | P1 |
| F | Git-sync component (shared OSS/commercial) | P1 |
| G | `BlobStore` interface + filesystem and S3-compatible providers | P2 |
| H | `SecretStore` interface unifying SOPS and key vaults | P2 |
| I | Reorganize `pkg/storage/interfaces/` into type-based taxonomy | P2 |

Each sub-story has its own testable acceptance criteria. This ADR is the shared source of truth for the taxonomy and the git-sync model.

## References

- `docs/architecture/decisions/001-central-provider-compliance-enforcement.md` — format template and the "pluggable by default" principle this ADR builds on
- `docs/product/feature-boundaries.md` — OSS/commercial line and storage backend advertisement
- `docs/architecture/ha-commercial-split.md` — build-tag pattern for OSS vs commercial code paths
- `docs/architecture/hybrid-storage-solution.md` — prior two-bucket framing (superseded by this ADR)
- `pkg/storage/providers/git/plugin.go:152-166` — evidence for git-provider deprecation (`RuntimeStore` memory-cache admission)
- `features/steward/health.go` — in-memory fleet state (motivates `StewardStore`)
- `features/steward/commands/handler.go` — in-memory command dispatch (motivates `CommandStore`)
- `pkg/storage/interfaces/` — current interface layout being reorganized
- CLAUDE.md — 50k+ steward scale target, pluggable-by-default rule
