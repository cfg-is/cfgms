# Backend Migration — Operator Guide

This guide covers the generic `cfg migrate` and `cfg storage migrate` verb shape used
to move data between CFGMS provider backends. Per-provider operator guides are linked
in the [Provider-Specific Guides](#provider-specific-guides) section below.

**`cfg storage migrate` and `cfg migrate --provider storage` are two different
tools with different capabilities — they are not interchangeable.**
`cfg storage migrate` (`cmd/cfg/cmd/storage.go`) is the older, narrower
command; it hard-rejects `--to database`/`--to postgres` with "postgres
migration is not supported". `cfg migrate --provider storage ...` (this
guide's examples below) is the current, supported tool for migrating onto
Postgres, and the one all examples in this guide use for that case. Confirmed
live in #3127: an operator following this guide's `cfg storage migrate`
examples as written against a Postgres target hits that rejection.

## Offline-Cutover Requirement

**Stop the controller before migrating any provider it is actively using.**

The migration tools assume exclusive write access to both the source and target backends.
Running a migration while the controller is live can produce split-brain state: the
controller continues writing to the source while the migrator reads a moving target,
yielding an inconsistent snapshot in the destination.

Recommended cutover sequence:

1. Stop the controller (`systemctl stop cfgms-controller` or equivalent).
2. Verify no other process holds the source backend open (check file locks, DB connections).
3. Run the migration with `--dry-run` first to confirm expected record counts.
4. Run the live migration.
5. Update the controller's backend configuration to point at the new target.
6. Start the controller and verify it reads the migrated data correctly.
7. Archive (do not immediately delete) the source backend for a roll-back window.

## Downtime Envelope

| Phase                          | Typical Duration |
|-------------------------------|-----------------|
| `--dry-run` validation         | Seconds to minutes (read-only, no writes) |
| Live migration (storage)       | Minutes to hours depending on record count |
| Live migration (secrets)       | Seconds to minutes (secrets are small) |
| Live migration (blobs)         | Minutes to hours depending on total blob size |
| Controller restart and verify  | 30–120 seconds |

Migration is idempotent: re-running against the same target is safe and produces
the same record counts with no duplicates.

## Generic Verb Shape

All CFGMS provider migration commands share this flag convention:

```
cfg migrate --provider <provider> --from <source-backend> --to <target-backend> [--dry-run]
cfg storage migrate --from <source-backend> --to <target-backend> [--dry-run]
```

| Flag         | Required | Description |
|-------------|----------|-------------|
| `--from`    | Yes      | Source backend name (provider-specific) |
| `--to`      | Yes      | Target backend name (provider-specific) |
| `--dry-run` | No       | Read source records and report counts without writing to target |

### `--dry-run`

`--dry-run` performs a read-only preview:

- Reads all records from the source backend.
- Counts records per store kind.
- Writes nothing to the target backend.
- Prints the same per-store count report as a live run.

Use it to confirm record counts before scheduling a maintenance window, and to
rehearse the migration against a copy of production data.

```bash
# Preview what would be migrated (cfg storage migrate cannot target database — see above)
cfg migrate --provider storage --from oss --to database --dry-run

# Execute the live migration
cfg migrate --provider storage --from oss --to database
```

A `--dry-run` count that differs from the live run count indicates the source
backend changed between the two invocations — always migrate with the controller stopped.

### Environment variables

`cfg migrate --provider storage` and `cfg migrate --provider blob` read their
backend configuration from environment variables — there are no `--config`
or per-backend flags:

| Variable | Provider | Backend | Description |
|----------|----------|---------|--------------|
| `CFGMS_STORAGE_FLATFILE_ROOT` | storage | `oss` | Flatfile root directory |
| `CFGMS_STORAGE_SQLITE_PATH` | storage | `oss` | SQLite database file path |
| `CFGMS_STORAGE_CLUSTER_POSTGRES_DSN` | storage | `database` | Postgres connection string (`host=... port=... dbname=... user=... password=... sslmode=...`) |
| `CFGMS_STORAGE_CLUSTER_SESSION_HMAC_KEY` | storage | `database` | HMAC key backing the session store's bearer-token hashing; required, must be a securely-generated random value |
| `CFGMS_BLOB_TENANT_IDS` | blob | both | Comma-separated tenant IDs to migrate (required) |
| `CFGMS_BLOB_FILESYSTEM_ROOT` | blob | `filesystem` | Root directory for the filesystem backend |
| `CFGMS_BLOB_S3_BUCKET` | blob | `s3` | S3 bucket name (required for `s3`) |
| `CFGMS_BLOB_S3_REGION` | blob | `s3` | AWS region (optional; default `us-east-1`) |
| `CFGMS_BLOB_S3_ENDPOINT_URL` | blob | `s3` | S3 endpoint URL for MinIO/local dev (optional) |

Pull `CFGMS_STORAGE_CLUSTER_POSTGRES_DSN`'s password and any S3 access/secret
keys from the OS keychain at invocation time — never hardcode them in a shell
history or script.

### Reporting

After a successful run (live or dry-run) the command prints a per-store summary:

```
Migration complete:
  config:                        1 204 records
  tenant:                          42 records
  registration_token:               8 records
  ...
  Total:                         1 254 records
```

Non-fatal per-store errors appear as `WARNING:` lines in the summary and do not
abort the remaining stores. A non-zero exit code is returned only for fatal errors
that prevent the migration from starting (missing configuration, unreachable backend).

## Provider-Specific Guides

Per-provider operator guides document backend names, required environment variables,
and provider-specific cutover notes. The following guides are planned as part of the
backend migration epic (#2256); links will resolve once the corresponding stories merge.

| Provider | Command | Guide |
|---------|---------|-------|
| Storage (controller data) | `cfg storage migrate` or `cfg migrate --provider storage` | [`docs/architecture/storage-architecture.md#storage-migration`](../architecture/storage-architecture.md) (S2) |
| Secrets (CA key + secrets) | `cfg migrate --provider secrets` | `docs/operations/secrets-ca-migration.md` (S3 — file does not exist yet; created by story #2323) |
| Blobs (installer artifacts) | `cfg migrate --provider blob` | `docs/operations/blob-migration.md` (S4 — file does not exist yet; created by story #2324) |

> **Note on forward references:** The `secrets-ca-migration.md` and `blob-migration.md`
> links above are intentional forward references to documents that will be created by
> their respective stories (S3 and S4). A missing file at those paths is expected while
> only S1 has merged — it is not a broken link bug.

## Related

- [`docs/architecture/storage-architecture.md`](../architecture/storage-architecture.md) — storage provider overview and migration-from-git guide
- [Roadmap](../product/roadmap.md) — epic #2256 tracking all migration stories
