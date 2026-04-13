# Storage Architecture

> **Source of truth**: [ADR-002: Storage Data Taxonomy](decisions/002-storage-data-taxonomy.md).
> This document is the operator-facing walk-through of the decision recorded in ADR-002.

## Summary

CFGMS controller storage is partitioned into five data types. Each type has its own interfaces and its own backend selection. Deployments compose one provider per type rather than choosing a single global backend.

Git is not a storage backend. For OSS, file-based storage is served by a flat-file provider; the admin is responsible for backups. Git re-enters the architecture as an *optional sync source* for admin-designated config scopes, implemented by a single git-sync component that works against both flat-file (OSS) and PostgreSQL (commercial) backends.

> **Scope note**: This document covers controller-side storage. Steward persistence (local config file, OS keychain, in-memory state between convergence runs) is a separate, simpler concern.

## The Five Data Types

| Type | OSS backend | Commercial/SaaS backend |
|------|-------------|-------------------------|
| Business data | SQLite | PostgreSQL |
| Config storage | Flat file (authoritative) or PostgreSQL | PostgreSQL (authoritative) |
| Config *git sync* (optional, per-scope) | Flat file ⇄ external git origin | PostgreSQL ⇄ external git origin |
| Secrets | SOPS files | Key vault (AWS Secrets Manager / HashiCorp Vault / Azure Key Vault) |
| Timeseries | Local log files | ClickHouse / Timescale / Influx |
| Blobs | Local filesystem | S3-compatible object storage |

### What belongs where

- **Business data**: tenants, stewards, commands, RBAC, sessions, audit logs, registration tokens, client-tenant records. Transactional, queryable, must survive restart.
- **Config storage**: human-editable configs (templates, policy, firewall rules). May be edited in the backend directly or imported from an external git origin via git-sync.
- **Secrets**: credentials, API keys, certificates. Always encrypted at rest.
- **Timeseries**: metrics and logs. Append-only, retention-driven, purged by age.
- **Blobs**: installer binaries, script bodies, report exports. Large, cheap, immutable.

## Git Is a Sync Source, Not a Backend

The previous architecture treated Git as a first-class storage backend (one commit per write, history-as-audit). That has been retired. Git now enters the architecture only as an *external source* that the admin binds to specific config scopes.

### The model

1. The admin designates one or more **scopes** (tenant path + namespace, e.g., `root/msp-a/client-1/firewall`) as git-synced.
2. Each scope binds to an external git origin: URL, branch, credentials reference.
3. The git-sync component pulls from each bound origin on webhook (push event) with a polling fallback.
4. Imported configs write through to the controller's config backend — flat-file for OSS, PostgreSQL for commercial.
5. Unbound scopes live natively in the backend.
6. The read path is always the backend. Git is the *editing surface* for bound scopes, not a query target.

v1 is read-only (git → backend). Bidirectional sync (UI-initiated edits flowing back to git commits) is a future extension.

### Why one component, two backends

The same git-sync code path serves both OSS and commercial deployments. The only variable is the backend adapter it writes through to. This avoids the fork that would result from git-as-backend-for-OSS and git-sync-for-SaaS existing side-by-side.

## MSP GitOps Example

An MSP hosting configs on GitHub with PR-based change management continues to work exactly as today:

1. MSP keeps config repo on `github.com:msp-corp/cfgms-configs`.
2. Admin binds scope `root/msp-corp` to that origin, branch `main`.
3. Config author opens a PR on GitHub.
4. Reviewer approves and merges.
5. GitHub sends webhook → CFGMS git-sync imports the merged tree.
6. Scopes not under `root/msp-corp` (e.g., fleet-wide policy set by the platform admin) stay in the backend, unaffected.

OSS deployments: the imported configs land in flat-file storage. Admin runs their own backup.
Commercial deployments: the imported configs land in PostgreSQL. HA, replication, PITR come from the database.

## Flat-File Provider (OSS)

The flat-file provider is the replacement for the deprecated git provider. It stores configs and runtime data as files under a configured root directory.

**Admin responsibilities**:
- Backups. CFGMS does not version at the storage layer. Use filesystem snapshots, rsync, restic, or an equivalent.
- Filesystem durability. SSD + regular snapshots is sufficient for single-controller OSS.
- Access control. Directory is readable/writable only by the controller process.

**What the flat-file provider does not do**:
- Automatic version history. (Use git-sync if you want PR-based change management.)
- Replication. (Use PostgreSQL if you need HA.)
- Arbitration. (Single-writer; not safe for multiple controllers to share the same root.)

## Interface Layout

Target layout (tracked under the ADR-002 epic):

```
pkg/storage/interfaces/
  business/       # TenantStore, ClientTenantStore, StewardStore, CommandStore,
                  # AuditStore, RBACStore, SessionStore, RegistrationTokenStore
  config/         # ConfigStore, RuntimeStore
  secrets/        # SecretStore
  timeseries/     # MetricsStore, LogStore
  blob/           # BlobStore
```

Current layout is flat (`audit_store.go`, `config_store.go`, `rbac_store.go`, …). Reorganization is tracked by a sub-story under the ADR-002 epic; see [`pkg/storage/interfaces/README.md`](../../pkg/storage/interfaces/README.md) for the current → target mapping.

## Configuration Example

```yaml
# cfgms.yaml — five-type storage composition (commercial/SaaS example)
controller:
  storage:
    business:
      provider: postgres
      config:
        host: cfgms-postgres.internal
        database: cfgms
        max_open_connections: 100

    config:
      provider: postgres
      config:
        host: cfgms-postgres.internal
        database: cfgms

    secrets:
      provider: vault
      config:
        address: https://vault.internal
        mount: cfgms

    timeseries:
      provider: clickhouse
      config:
        host: clickhouse.internal

    blobs:
      provider: s3
      config:
        bucket: cfgms-blobs
        region: us-east-1

  # Optional: scopes that should be imported from external git
  git_sync:
    - scope: root/msp-corp
      origin: git@github.com:msp-corp/cfgms-configs.git
      branch: main
      credentials_ref: secrets/git/msp-corp
```

```yaml
# cfgms.yaml — OSS single-controller example
controller:
  storage:
    business:
      provider: sqlite
      config:
        path: /var/lib/cfgms/business.db

    config:
      provider: flatfile
      config:
        root: /var/lib/cfgms/configs

    secrets:
      provider: sops
      config:
        root: /var/lib/cfgms/secrets

    timeseries:
      provider: filelog
      config:
        root: /var/lib/cfgms/timeseries

    blobs:
      provider: filesystem
      config:
        root: /var/lib/cfgms/blobs
```

## Implementation Status

Per ADR-002, the providers and interfaces above are **not all implemented today**. The ADR ratifies the direction; implementation is tracked by the **Storage Architecture: Five-Type Data Taxonomy (ADR-002)** epic and its sub-stories. See the ADR's [Code Changes Required](decisions/002-storage-data-taxonomy.md#code-changes-required) section for the authoritative sub-story list and priorities.

## References

- [ADR-002: Storage Data Taxonomy](decisions/002-storage-data-taxonomy.md) — authoritative design document
- [`docs/product/feature-boundaries.md`](../product/feature-boundaries.md) — OSS/commercial licensing boundary
- [`pkg/storage/interfaces/README.md`](../../pkg/storage/interfaces/README.md) — current interface layout and reorganization plan
- [ADR-001: Central Provider Compliance Enforcement](decisions/001-central-provider-compliance-enforcement.md) — pluggable-by-default principle
