# Controller HA — real-cluster validation runbook

Live-validation runbook for epic **#3090** (Controller HA validation on a real
multi-node cluster): migrating the Tier-1 `cfg-lab` controller off its
single-node storage backend onto shared PostgreSQL + S3-compatible blob
storage, joining a genuine 3-node `CFGMS_HA_MODE=cluster` deployment across
separate real hosts, and validating leader election, failover, and
split-brain resolution on real hardware rather than Docker containers.

## Overview

This runbook consolidates the live-validation output from eight stories (§2–§9) that together
satisfy epic #3090. Each section was appended by the story that ran the validation.

| Section | Story | Validated |
|---|---|---|
| §2 | #3127 | Storage migration — live Tier-1 controller from OSS flatfile to shared PostgreSQL |
| §3 | #3130 | Cluster join — two new nodes form a 3-node `ha.mode: cluster` Raft cluster |
| §4 | #3094 | Leader election and automatic failover (process-kill and host-kill scenarios) |
| §5 | #3095 | Network partition and split-brain resolution |
| §6 | #3096 | Steward fleet continuity through controller leader failover |
| §7 | #3405 | Fleet enrollment against the running cluster |
| §8 | #3462 | Sealed-credential migration (ADR-030, `LoadCredentialEncrypted=`) |
| §9 | #3436 | Steward-side Raft-term command fence (live wire-path verification) |

### Consolidated Results

All figures below were measured on the `cfg-lab` real-host cluster (`ctrl-node-1` /
`ctrl-node-2` / `ctrl-node-3`) using production defaults
(`ElectionTimeout: 10s`, `HeartbeatInterval: 2s` — `FastElectionConfig` was deliberately
not used, as it exists only to keep CPU-contended unit tests fast and would have
invalidated the comparison).

> **Target threshold labelling:** The Docker-suite assertions in the right-hand column are
> assertions in `test/integration/ha/` that have **never been executed to completion in
> CI** — no GitHub Actions workflow runs `go test ./test/integration/ha/...` against the
> 3-controller scenario, and `docker-compose.test.yml` never sets `CFGMS_HA_CA_CERT_PATH`
> (#3092's Out of Scope). This epic's real-host figures are the first time these thresholds
> have been proven against any live cluster with real mTLS-authenticated peers. They are
> cited as **unexecuted-in-CI target thresholds**, not previously-measured baselines.
> Cite the source assertions directly — `leader_election_test.go:224-225`,
> `failover_test.go:131-135`, `steward_ha_test.go:233-234` — rather than the
> `test/integration/ha/README.md` summary table, which restates but does not replace them.

| Metric | Real-cluster result | Docker-suite target | Docker assertion (unexecuted in CI) |
|---|---|---|---|
| Election / re-election time — process-kill (SIGKILL) | **14.02s** (§4, 2026-08-15) | < 15s | `TestLeaderElectionTiming` — `leader_election_test.go:224-225`: `assert.Less(t, electionTime, 15*time.Second, ...)` |
| Failover re-election time — host-kill (hard power-off) | **16.02s** (§4, 2026-08-15) | < 40s | `TestFailoverTiming` — `failover_test.go:131-135`: `assert.Less(t, failoverDuration, 40*time.Second, ...)` |
| Partition minority step-down (leader isolated as minority) | Within 30s bound; stayed down for 45s observation window (§5, 2026-08-15 / re-run 2026-08-25) | N/A — no `assert.Less` for this metric in Docker suite | `network_partition_test.go` uses `require.Eventually` bounds only |
| Partition heal — reconvergence to single leader | **2.01s** original run; **2.007s** re-run after #3389 (§5) | N/A — no `assert.Less` for this metric in Docker suite | `network_partition_test.go` uses `require.Eventually` bounds only |
| Steward continuity through leader failover | **0 reconnects, 0 missed heartbeats**; next heartbeat +6s, re-election 12.02s (§6, 2026-08-20) | < 15s (reconnect to *restarted* controller — a different scenario; see note below) | `steward_ha_test.go:233-234`: `assert.Less(t, failoverDuration, 15*time.Second, ...)`; outer poll bound at line 227: `require.Eventually(..., 90*time.Second, 2*time.Second, ...)` |

> **Steward continuity note:** The < 15s Docker assertion (`steward_ha_test.go:233-234`) tests
> steward reconnect to a controller that has restarted and rejoined its own cluster — not
> leader failover. The real-cluster finding (§6) is structural: stewards attach to a
> specific controller node, not specifically to the leader. Leader changes are invisible to
> a steward whose own node remains up. The reconnect scenario (steward's own node goes down)
> is explicitly out of scope per epic Non-Goals; an LB/VIP with a liveness health gate
> on `GET /api/v1/health` is the operational lever for that case. See §6 and §7 for the
> enrollment-path caveat (enrollment must gate on leadership, not just liveness, after #3473).

### Known Gaps / Follow-Up

Documented during epic #3090; status at epic close:

| Finding | Story | Status at epic close |
|---|---|---|
| `TestRealClusterPartition_NoDualLeader` initially failed — partition window allowed two nodes to simultaneously report `is_leader:true` (Raft `CheckQuorum` step-down timing overlaps followers' election timers; `CheckQuorum` guarantees write-safety, not status-flag agreement) | #3095 | **Resolved** — lease-backed `HasLeadership()` separated from `IsRaftLeader()` by epic #3386; test re-run PASS on 2026-08-25/26 (§5) |
| Steward single-controller-URL gap: when a steward's own node goes down, it retries that node indefinitely — no automatic failover to a cluster peer exists in the steward | #3096 | **Open** — per epic Non-Goals; documented in `steward-operating-model.md` |
| RLS unscoped-read bug: `current_setting('app.current_tenant', true)` returns `NULL` (not `''`) when unset, silently filtering all rows for unscoped DB callers | #3096 | **Filed as #3478** — `coalesce(...)` fix pending |
| Fleet view was node-local: `GET /api/v1/stewards` returned in-process map only, not cluster-wide store | #3096 | **Fixed by #3480** |
| Refused steward reconnects at ~1 Hz forever (backoff not persisted across reconnect-loop re-entries) | #3096 | **Fixed by #3481** |
| Raft ConfState not restored on restart — nodes came back with empty voter set; no election possible | #3096 | **Fixed by #3479** |
| Registration/token endpoints leader-gated via `HasLeadership()` (#3473): enrollment LB must health-gate on leadership (`GET /api/v1/raft/status` → `is_leader`), not just liveness | §7 (post-#3473) | **Documented in §7** — supersedes the plain-liveness-gate conclusion from §6 for enrollment paths |

---

## 1. Environment

Live bed: the **cfg-lab** 3-node Hyper-V failover cluster (`cluster.example.internal`),
same physical bed as the module-convergence work — see
[`hyperv-cluster-cascade-runbook.md`](hyperv-cluster-cascade-runbook.md) §1
for the underlying hypervisor topology (`HV-HOST-01` / `HV-HOST-02` /
`HV-HOST-03`, CSV01, `HVSwitch_1G`).

`ctrl-node-1` (the Tier-1 controller): `10.0.0.10`, REST API on
`:9080` (port `443` closed). `data-svc-vm` (shared Postgres/MinIO,
soon OpenBao — see §"Shared data-services VM" below): `10.0.0.12`.

### Lab rebuild note (2026-07-31/08-01)

While provisioning this story's VM, the lab's exec-dispatch subsystem and
`HV-HOST-01`'s steward wedged in a way that required a full lab reset —
all non-DC Hyper-V VMs torn down (CSV01 storage cleaned), the Tier-1
controller (`ctrl-node-1`) rebuilt from scratch on `HV-HOST-01`, and all
three HV-host stewards re-enrolled. The domain controllers (`cfg-dc1-02`,
`cfg-dc2-02`) were left untouched throughout.

`ctrl-node-1` is therefore **no longer** the persistent controller from the
original v0.9.7 Tier-1 bringup referenced elsewhere in epic #3090's planning
— it is a fresh instance (CA regenerated, tenant tree reseeded, fleet
re-enrolled). Anything in this epic that assumed continuity with the
original controller's history/state should be re-verified.

Seven genuine defects were found during the rebuild and filed as follow-up
stories under this epic (none fixed here — #3124 is infra-provisioning only):
- #3168 — `hyperv.vm` cloud-init VM occasionally boots without seeing the
  CIDATA seed disk on first boot (self-heals on a power-cycle, but not
  automatically on the module's own timeline).
- #3169 — the `hyperv.vm` module's `Set-VMFirmware -EnableSecureBoot On
  -SecureBootTemplate MicrosoftUEFICertificateAuthority` call reproducibly
  fails (`'MicrosoftUEFICertificateAuthority' matches none of the secure
  boot templates`) when run as part of the module's actual create sequence,
  even though the identical call succeeds in isolation. Both `ctrl-node-1`
  and `data-svc-vm` were provisioned manually instead (raw cloud image
  → fixed VHD → dynamic VHDX via `C:\temp\raw2vhd`, CIDATA seed built with
  the same mechanics as the module, `-EnableSecureBoot Off`) rather than via
  `cfg config upload` — see `C:\temp\ctrl-vm-create.ps1` /
  `C:\temp\datasvc-vm-create.ps1` on `HV-HOST-01` for the exact recipe.
- #3170 — `tier1-bootstrap.sh`'s config template is missing
  `transport.external_address` (controller now refuses to start without it).
- #3171 — `certificate.ca_path`/`cert_path` is silently ignored in favor of a
  relative default — `--init` must be run with CWD `/var/lib/cfgms` (matching
  the systemd unit's `WorkingDirectory`) or the CA never lands where the
  server expects to load it from.
- #3172 — the generated admin bundle embeds a hardcoded `controller_url` port
  (`:8080`) instead of the configured `listen_addr` port.
- #3173 — `cfg registration approve` / `approve-all` return success but the
  `registration pending` list still shows the entries afterward — cosmetic
  (the underlying steward really does flip to `active`), but worth fixing.
- #3174 — `cfg`'s `--tls-insecure` / `CFGMS_TLS_INSECURE` has no effect for
  admin-bundle (mTLS) authenticated commands (`steward`, `tenant`), only
  worked around here via an SSH tunnel to `localhost` (in the cert's SAN)
  instead of connecting by LAN IP.

### Shared data-services VM (`data-svc-vm`) — story #3124

A dedicated Debian VM hosts the PostgreSQL + MinIO backend shared by all
cluster controller nodes:

| Property | Value |
|----------|-------|
| VM name | `data-svc-vm` |
| Hypervisor host | `HV-HOST-01` |
| Tenant | `infra-hyperv` |
| Provisioning | Manual (see the rebuild note above) — `C:\temp\datasvc-vm-create.ps1` builds the VM, then `scripts/lab-datasvc-bootstrap.sh` (run once over SSH) installs PostgreSQL + MinIO |
| IP address | `10.0.0.12` (lab LAN, `10.0.0.0/24`, DHCP) |

**PostgreSQL:**

| Property | Value |
|----------|-------|
| Port | `5432` |
| Database | `cfgms` |
| Role | `cfgms` (dedicated, non-superuser, `LOGIN` only) |
| Listen | all interfaces; `pg_hba.conf` restricts inbound to `10.0.0.0/24` and is TLS-only — `hostssl … scram-sha-256` plus `hostnossl … reject`, so a `sslmode=disable` client is refused rather than served in cleartext |
| TLS CA cert | `/etc/postgresql/tls/ca.pem` on the VM (generated by `scripts/lab-datasvc-bootstrap.sh` Step 2.5; path printed at end of bootstrap run). Copy to each controller node as `/etc/cfgms/datasvc-ca.pem` |
| Connection string shape | `postgres://cfgms:<password>@10.0.0.12:5432/cfgms?sslmode=verify-full&sslrootcert=/etc/cfgms/datasvc-ca.pem` — use the raw `dsn` string config form (not the keyword-builder) to carry `sslrootcert` through unchanged; see story #3127 and `pkg/storage/providers/database/plugin.go` |

**MinIO (S3-compatible blob storage):**

| Property | Value |
|----------|-------|
| API port | `9000` |
| Console port | `9001` |
| Bucket | `cfgms-installer-blobs` |
| `endpoint_url` | `http://10.0.0.12:9000` |

**Credentials:** the PostgreSQL role password and MinIO root access/secret
key are generated once by `scripts/lab-datasvc-bootstrap.sh` on first run and
printed to stdout a single time. Store them in the operator workstation's
OS-native keychain — never in a file on disk, and never committed to this
repository. See the script's step 7 output for the exact storage commands per
platform. Operator-specific details (host names, keychain target names,
recovery order) are deployment state, not project documentation, and belong
in the operator's own notes rather than here.

### Privileges

Provisioning the VM and running the in-guest bootstrap requires the same
`cfg steward exec` (SYSTEM) / cluster-admin path documented in
[`hyperv-cluster-cascade-runbook.md`](hyperv-cluster-cascade-runbook.md) §1 —
a non-admin shell cannot create the VM or reach the Hyper-V APIs.

---

## 2. Storage migration (story #3127)

Migrates the live Tier-1 controller (`ctrl-node-1`) from its `oss`
(flatfile+SQLite) backend onto the `data-svc-vm` PostgreSQL backend
(story #3124) via `cfg migrate --provider storage --from oss --to database`
— **not** `cfg storage migrate`, which hard-rejects `--to postgres` (see the
epic Goal). Executed 2026-08-05.

### Bugs found and fixed while proving this path live

This was the first time the `database`/cluster storage path (used by both
`cfg migrate --provider storage` and real `ha.mode: cluster` controller
startup) had ever been exercised against a real Postgres instance — none of
its integration tests are wired into any Makefile target or CI job. Four
genuine bugs surfaced and were fixed directly (not routed around), per the
epic's guidance:

1. **`CreateClusterStorageManager` never threaded `session_hmac_key`**
   (`pkg/storage/interfaces/provider.go`) — the session store's HMAC key was
   silently dropped from the config map it built, so session-store creation
   always failed. This affects every real (non-test) caller: the migrator,
   and `server.go`/`initialization.go` cluster-mode controller startup.
   Fixed by adding a `sessionHMACKey` parameter, a
   `storage.cluster.session_hmac_key` / `CFGMS_STORAGE_CLUSTER_SESSION_HMAC_KEY`
   config path, and threading it through all four real call sites.
2. **Tenant and RBAC role import had no parent-first ordering**
   (`pkg/migrate/storage/migrate.go`) — `ListTenants`/`ListRoles` make no
   ordering guarantee, so importing a child before its parent violated the
   `cfgms_tenants_parent_id_fkey` / `rbac_roles_parent_role_id_fkey` foreign
   keys. Fixed with a generic `sortParentFirst` topological sort applied to
   both.
3. **`DatabaseTenantStore.CreateTenant` never translated a Postgres unique
   violation into `business.ErrTenantAlreadyExists`**
   (`pkg/storage/providers/database/tenant_store.go`) — so the migrator's
   already-idempotent retry logic (`errors.Is(err, ErrTenantAlreadyExists)`
   → `UpdateTenant`) never triggered, and a second migration run against a
   partially-populated target failed outright. Fixed to detect Postgres
   error code `23505` the same way the sqlite provider already does.
4. **`DatabaseRBACStore.StoreRole` inserted an empty `parent_role_id` as a
   literal empty string instead of `NULL`**
   (`pkg/storage/providers/database/rbac_roles.go`) — `parent_role_id` has a
   self-referential foreign key, so *every* role without a parent (i.e. every
   top-level role) violated it. Fixed with the same `nullStringOrEmpty`
   helper the tenant store already uses.
5. **`DatabaseAuditStore.scanAuditEntry` failed to scan a `NULL` `ip_address`**
   (`pkg/storage/providers/database/audit_store.go`) — `net.IP` has no
   `sql.Scanner`, so `database/sql`'s built-in NULL handling doesn't cover
   it; any audit entry without a client IP (internal/system-generated
   entries) broke `GetAuditEntry`/`ListAuditEntries` outright. This silently
   defeated the migrator's idempotent existence-check-before-insert, causing
   a duplicate-key error on any retry. Fixed by scanning into
   `sql.NullString` instead.

All five are covered by `go build`/`go vet`/`go test -short` (already in
`make test`) plus a live re-run of the affected integration suites
(`go test -tags integration ./pkg/storage/interfaces/... ./pkg/migrate/storage/... ./pkg/storage/providers/database/...`)
against a local `docker compose --profile database` Postgres — run per
package, not concurrently, since the shared, non-isolated `cfgms_test`
database races on schema setup across packages when run together (a
pre-existing test-infra gap, not caused by or fixed in this story).

### Pre-migration state

- Storage: `flatfile_root: /var/lib/cfgms/storage`, `sqlite_path:
  /var/lib/cfgms/cfgms.db` (the `oss` composite backend).
- Blobs: `/var/lib/cfgms/data/installers` contained **0 files** — there was
  no existing installer-blob data to migrate. `cfg migrate --provider blob`
  was not run; the `blobs:` config was left untouched.

### `--dry-run` record counts

Captured immediately after stopping the controller (2026-08-05T02:52:27Z),
against the live data:

```
Dry-run: planning migration oss → database (provider: storage)
Migration plan (no writes performed):
  rbac_role:                     12 records
  refresh_policy:                 3 records
  rbac_permission:               32 records
  registration_token:             2 records
  tenant:                         3 records
  audit:                         25 records
  Total:                         77 records
```

(An identical dry-run taken ~15 minutes earlier while the controller was
still live reported `audit: 24` / `Total: 76` — the `systemctl stop` itself
wrote one audit entry, accounting for the difference. No other drift between
the two runs.)

**`trigger` and `push` records were skipped — known, accepted OSS-only gap.**
Neither kind appears in the report above, and neither appears in the live
migration output below. Two things combine here:

- This controller genuinely held **0 `trigger` and 0 `push` records**. The
  migrator exports both kinds unconditionally from the `oss` source (which
  *does* implement `TriggerStore` and `PushStore`), and the report prints a
  line only for kinds with at least one record, so a `0`-count kind produces
  no line at all rather than an explicit `0`.
- Even had the counts been nonzero, those records would have been **silently
  dropped on import**: per the per-store-kind coverage table in
  [storage-architecture.md](../architecture/storage-architecture.md#stores-covered-by-the-storage-migrator),
  `trigger` and `push` are OSS-only — the PostgreSQL backend exposes no
  `TriggerStore`/`PushStore`, so the importer skips those records without
  error and the end-of-run integrity check compares only kinds that *both*
  backends support.

An operator migrating a controller that *does* hold trigger or push data
should expect exactly that silent skip and plan to re-create those records on
the Postgres side — it is a known gap in the database backend, not a
migration bug.

### Live migration

`cfg migrate --provider storage --from oss --to database` (no `--dry-run`)
completed with counts matching the dry-run exactly:

```
Migration complete:
  tenant:                         3 records
  rbac_permission:               32 records
  rbac_role:                     12 records
  refresh_policy:                 3 records
  audit:                         25 records
  registration_token:             2 records
  Total:                         77 records
```

### Controller cutover

`storage:` in `/etc/cfgms/controller.cfg` changed from the `oss` block to:

```yaml
storage:
  provider: database
  config:
    dsn: "postgres://cfgms:${CFGMS_STORAGE_DB_PASSWORD}@10.0.0.12:5432/cfgms?sslmode=verify-full&sslrootcert=/etc/cfgms/datasvc-ca.pem"
    session_hmac_key: "${CFGMS_SESSION_HMAC_KEY}"
```

The raw `dsn` string form is required here, not the
`host`/`port`/`database`/`username`/`password`/`sslmode` keyword set: the
keyword builder (`getDSN` in `pkg/storage/providers/database/plugin.go`) emits
only those six keywords and has no way to carry `sslrootcert`, so
`sslmode=verify-full` would have no CA to verify against. Copy
`/etc/postgresql/tls/ca.pem` from `data-svc-vm` to
`/etc/cfgms/datasvc-ca.pem` on each controller node (root-owned, mode 644 — it
is a public certificate) before restarting the controller.

> **History:** the config first applied at the story #3127 migration
> (2026-08-05) used the keyword form with `sslmode: "disable"`, because
> server-side TLS did not yet exist on `data-svc-vm`. Story #3179
> provisions that TLS and the `pg_hba.conf` on the data-services VM now carries
> a `hostnossl … reject` rule for `10.0.0.0/24`, so a `sslmode=disable`
> controller is refused at connect time rather than silently downgraded — the
> block above is the only configuration that connects.

`ha.mode` was **not** set — per this story's Out of Scope, the Tier-1
controller stays single-node; this is the plain single-provider `database`
path (`storage.provider: database`), not `storage.cluster.*`/cluster mode
(that's story #3130).

The two secrets are never written to `controller.cfg` or any committed
file — the config's generic `${VAR}` expansion (already supported by the
config loader) resolves them at load time. The session HMAC key must stay
stable for the life of the deployment, since it backs bearer-token hashing.

Secret material for a controller is supplied via SOPS-encrypted secrets and
systemd `LoadCredential=`, which exposes the value on tmpfs under
`/run/credentials` rather than on disk — see
`docs/deployment/single-controller/walkthrough.md`. `pkg/secrets/providers/sops`
accepts `LoadCredential`-backed files at mode `0440` as of #3130. Deployment
shortcuts that place secret material in a cleartext file on disk are
prohibited by CLAUDE.md's zero-tolerance rule ("No cleartext secrets on disk.
Even in development.") and must not be carried into any further cutover.

Post-cutover verification (steward round-trip, since no fleet is yet
enrolled to this HA-validation controller instance): a throwaway steward was
installed (`cfg token create` → `cfgms-steward install --regtoken ...
--controller-ca ... --fingerprint ...`), quarantined, approved
(`cfg registration approve`), reached `active` status with a live
heartbeat, received a `cfg config upload`'d test config (`file` module, a
scratch path under `/tmp`), and converged it correctly — proving the full
register → heartbeat → config-push → converge path against the new backend.
The steward was then decommissioned and its token revoked, leaving the
fleet table clean.

**Known pre-existing issue hit during verification, not fixed here:** the
generated admin bundle's embedded `controller_url` uses the hardcoded port
`:8080` instead of the configured `9080` (`#3172`, already filed) — worked
around with `CFGMS_API_URL=https://localhost:9080` for every `cfg` CLI
invocation against this controller.

### Downtime

| Leg | Stopped | Started | Downtime |
|-----|---------|---------|----------|
| Initial cutover (oss → database) | 2026-08-05T02:52:27Z | 2026-08-05T03:17:05Z | ~25 min — includes live debugging and rebuild/redeploy of the five bugs above; not representative of a routine cutover |
| Rollback drill (database → oss) | 2026-08-05T03:40:07Z | 2026-08-05T03:40:08Z | ~1s — a config/unit-file swap only, no data migration |
| Re-cutover (oss → database, final) | 2026-08-05T03:40:58Z | 2026-08-05T03:41:43Z | ~45s — representative of a routine cutover once the storage backend already holds migrated data |

### Rollback drill (tested, not just documented)

Executed once against the archive to prove the procedure actually works:

1. `systemctl stop cfgms-controller`.
2. Restored `/etc/cfgms/controller.cfg` and the systemd unit from the
   pre-migration backups taken before the cutover
   (`controller.cfg.pre-3127.bak`, `cfgms-controller.service.pre-3127.bak`,
   both left in place on `ctrl-node-1` alongside the live config).
3. `systemctl daemon-reload && systemctl start cfgms-controller`.
4. Confirmed `GET /api/v1/health` returned `"status":"healthy"` and the
   startup log showed `backend=flatfile` — the controller was serving the
   original, untouched flatfile+SQLite data.
5. Re-applied the database cutover (step above) to leave the controller
   running on Postgres for the health-soak period below.

The pre-migration flatfile+SQLite data was never deleted or moved — it
remains at its original paths (`/var/lib/cfgms/storage`,
`/var/lib/cfgms/cfgms.db`) — and is additionally archived (copied, not
moved) to `/var/lib/cfgms/archive-pre-3127-migration/` on `ctrl-node-1`.
Per the epic, this archive and the rollback path are **not** retired by this
story; only an explicit founder sign-off retires them.

### Health soak

The controller was left running on the Postgres backend after the rollback
drill (from 2026-08-05T03:41:43Z). Observed clean for 17+ minutes at story
close: `GET /api/v1/health` returns `"status":"healthy"` throughout, `systemctl
status` shows continuous `active (running)` with no restarts, and
`journalctl` shows zero `error`/`panic`/`fatal` lines since the re-cutover
(the only log noise is the pre-existing periodic TLS handshake errors from
stray clients on the LAN, unrelated to this story). The controller is left
running and observed on an ongoing basis past story close — the archived
pre-migration data and the tested rollback procedure both remain in place
and untouched; retiring them is a separate, explicit founder decision.

## 3. Cluster join (story #3130)

Joins two new controller nodes (`ctrl-node-2`, `ctrl-node-3`) to the
#3127-migrated Tier-1 controller (`ctrl-node-1`), cutting all three over to
a 3-node `ha.mode: cluster` deployment with a shared OpenBao-sourced CA (see
[`cluster-ca.md`](../operations/cluster-ca.md)) and shared Postgres/MinIO
backend (see [`cluster-storage-config.md`](../operations/cluster-storage-config.md)).
Executed 2026-08-11.

### VM provisioning

Both new nodes: Debian 13, Generation 2, 4 vCPU / 4GB RAM, provisioned via the
raw2vhd/CIDATA cloud-init recipe (`C:\temp\ctrl-vm-create.ps1`, adapted
per-host — not yet formalized into the repo). `ctrl-node-2` on
`10.0.0.11` (host HV-HOST-02), `ctrl-node-3` on `10.0.0.13`
(host HV-HOST-03). The provisioning template was fixed during this story to
install `hyperv-daemons` (`hv-kvp-daemon` — required for Hyper-V/
`Get-VMNetworkAdapter` to see the guest's IP at all) and to send the guest's
**FQDN**, not short hostname, via DHCP so DNS dynamic-update registers it (see
"DNS registration" below).

### DNS registration (client + server-side)

Neither new VM's hostname registered in `cluster.example.internal` DNS despite valid DHCP
leases. Root-caused via PSRemoting to both DCs (`cfg-dc1-02`, `cfg-dc2-02`) as
two independent gaps:

1. **DHCP server-side**: the DHCP service (`cfg-dc2-02`, itself a domain
   controller) had no `Set-DhcpServerDnsCredential` configured. Per Microsoft
   guidance, a DC-hosted DHCP server cannot register DNS on behalf of
   non-domain clients against a Secure-only zone using its own machine
   account — it needs an explicit low-privilege service-account credential,
   which was never provisioned. Relaxed `cluster.example.internal` and its reverse zone
   (`234.168.192.in-addr.arpa`) from `Secure` to `NonsecureAndSecure` dynamic
   updates (acceptable for this lab; not recommended in a production AD).
2. **Client-side**: systemd-networkd's DHCPv4 client only sends option 81
   (Client FQDN — what Windows DHCP's `OnClientRequest` registration mode
   requires) when the configured hostname contains a dot. netplan's
   `dhcp4-overrides`/`dhcp6-overrides` `hostname:` was set to the short
   hostname; changed to the FQDN (`ctrl-node-2.cluster.example.internal`) on both nodes.

Both fixes verified live via the DHCP server's audit log (`DNS Update
Request` → `DNS Update Successful` event pairs) and a direct `Get-DnsServerResourceRecord`
query on `cfg-dc1-02`.

### Bugs found and fixed while proving this path live

Six genuine bugs surfaced getting the two new nodes to a stable 3-node quorum
— none of this path had been exercised end-to-end before:

1. **`ha-cluster-node-bootstrap.sh` never wired `CFGMS_SECRETS_KEY_FILE`** —
   `--init` failed with "plaintext secret storage is prohibited". Added
   generation + `LoadCredential=`/`InaccessiblePaths=` wiring mirroring
   `tier1-bootstrap.sh`.
2. **`pkg/secrets/providers/openbao`'s `Available()` only reads the
   `OPENBAO_ADDR` env var**, never the resolved `certificate.cluster_ca.vault_address`
   — a correctly configured vault address alone still fails the registry's
   availability gate. Same root cause as a workaround already applied during
   #3127/#3130's CA migration into vault. Worked around operationally
   (`OPENBAO_ADDR` set alongside the config value in both scripts' `--init`
   env and systemd unit); the provider-level fix is a separate, flagged gap.
3. **`certificate.cert_path` does not correspond to any config struct
   field** — `CertificateConfig` has no `CertPath`, so the nested YAML key
   both bootstrap scripts rendered was silently dropped. The only field the
   code read at the time was the legacy top-level `cert_path`
   (`features/controller/config/config.go`), which defaults to the relative
   `"certs/"` and only resolved correctly because systemd's
   `WorkingDirectory=/var/lib/cfgms` happened to match — `--init` (run via
   `runuser`, no such cwd guarantee) failed with `mkdir certs/: permission
   denied`. Worked around by rendering a top-level `cert_path` key in both
   scripts. **Superseded during this same story's rebase onto `develop`**:
   issue #3171 (filed in the "Lab rebuild note" above) was independently
   fixed properly upstream in the meantime (PR #3257, `2f41f545`) —
   `certPath` is now derived structurally as `filepath.Dir(ca_path)` in both
   `initialization.go` and `server.go`, with its own test coverage
   (`TestRun_HonorsAbsoluteCAPath`, `TestRun_HonorsTrailingSlashCAPath`).
   This makes the top-level `cert_path` key dead config — removed from both
   bootstrap scripts (and the now-obsolete
   `TestRun_TopLevelCertPathMustBeAbsolute` regression test removed) once the
   rebase surfaced the conflict; `ca_path` alone is sufficient. This bug was
   **already latent in `ctrl-node-1`'s live config** (present since #3127)
   and would have hit the Tier-1 controller on its next restart regardless
   of #3130.
4. **`pkg/secrets/providers/sops` rejected `LoadCredential`-backed key
   files** — systemd's `LoadCredential=` always exposes files at mode `0440`
   (owner+group read, ACL-scoped to the unit by systemd itself, not by the
   raw group-owner bits), which the SOPS provider's permission check flatly
   rejected as "must not grant group or other access". This would have
   crash-looped **Tier-1 itself** on its next restart, since its systemd unit
   already carried the identical `LoadCredential` wiring from a prior
   session but had not restarted since. Fixed in code
   (`pkg/secrets/providers/sops/store.go`) with an exception scoped precisely
   to `/run/credentials/` paths.
5. **`internal_listen_addr: "0.0.0.0:9443"` rejected by design** —
   `config.ValidatePrivateListenerAddress` requires a fixed loopback/private
   IP, not the wildcard (binding all interfaces would risk exposing Raft
   traffic on any public-facing NIC). Fixed the bootstrap script to bind the
   node's actual private IP instead of `0.0.0.0`.
6. **`secrets.key` must be identical across all 3 cluster nodes, not
   independently generated per node** — it encrypts secrets (e.g. the audit
   HMAC key) persisted as shared rows in the cluster Postgres backend;
   whichever node writes first encrypts under its own key, and every other
   node fails to decrypt with `secret ciphertext authentication failed`.
   `ha-cluster-node-bootstrap.sh` originally self-generated a fresh random
   key per node via `openssl rand`; fixed to require a `CFGMS_SECRETS_KEY_B64`
   env var supplying the same value to every node (mirroring
   `CFGMS_SESSION_HMAC_KEY`'s existing pattern).

Two further operational fixes, not code bugs: `chmod +x` on this system did
not reliably grant group/other execute on a binary copied under an active
`umask 077` left set from generating `secrets.key` earlier in the script (the
`umask` was never scoped/reset) — fixed by scoping `umask 077` to a subshell
in both scripts and using explicit `chmod 0755`. And a bare `[[ cond ]] &&
echo` as the last command inside a `{ ...; } > file` group, when that group
is itself wrapped in a `(...)` subshell, interacts with `set -e` differently
than the unwrapped form — converted to explicit `if` statements to remove the
ambiguity regardless of wrapping.

A seventh, genuine `pkg/ha` defect surfaced verifying `GET /api/v1/ha/cluster`
(required by this story's acceptance criteria) against the live 3-node
cluster: it returned `{"nodes":null}` despite a healthy, agreed-upon Raft
quorum on `/api/v1/raft/status`. Root-caused via temporary diagnostic logging
to `features/controller/server/server.go`'s `Start()`: it creates
`ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second);
defer cancel()` solely to bound the synchronous `haManager.Start(ctx)` call —
every *other* long-running component in that function correctly starts with
`context.Background()` instead. `ha.Manager.Start(ctx)` stored that same
short-lived `ctx` as `m.ctx`, the context bounding **every** long-lived
background component (node-info replication, health checker, failover,
split-brain detection) — so `defer cancel()` firing on `Start()`'s return
killed them all within ~1ms, long before cluster-mode leader election (10s+
under real timings) could ever complete. Fixed in `pkg/ha/manager.go`: `m.ctx`
is now derived from `context.Background()`, decoupled from the caller-supplied
parameter, matching the lifecycle every sibling `.Start(context.Background())`
call in `server.go` already uses. Covered by a new regression test,
`TestManager_Start_SurvivesCallerContextCancelledAfterReturn`, which
reproduces the exact caller pattern (cancelling the passed context immediately
after `Start()` returns, not at test teardown) — verified to fail against the
pre-fix code and pass against the fix.

All fixes are covered by regression tests: `features/controller/initialization/initialization_test.go`,
`pkg/secrets/providers/sops/provider_test.go`, `pkg/ha/manager_test.go`, and
both bootstrap scripts' `_test.sh` suites (7/6 passing respectively).

### Node bootstrap

Both new nodes bootstrapped via `ha-cluster-node-bootstrap.sh --hostname=<fqdn>
--node-id=<private-ip> --cluster-nodes=10.0.0.10:9443,10.0.0.11:9443,10.0.0.13:9443
--postgres-host=10.0.0.12 --s3-endpoint=http://10.0.0.12:9000
--vault-address=http://10.0.0.12:8200 --vault-key-path=root/cluster-ca`.
`--node-id` uses the node's private IP (not FQDN) for consistency with the
existing established addressing scheme, even though DNS now works — changing
the whole cluster's addressing scheme was out of scope for this pass. Both
nodes loaded the CA fingerprint `fdac9d4ba886e876a3cfe6626cb4d7fc308310a7e8a325277cfaed40a318dc87`
from the shared vault, matching each other exactly.

### Tier-1 cutover

`ctrl-node-1`'s pre-cutover single-node config, systemd unit, and binary
were backed up to `/root/pre-cluster-cutover-backup/` before any change. Its
`controller.cfg` gained (on top of the existing `storage.provider: database`
block, kept for continuity): a top-level `cert_path` and
`internal_listen_addr: "10.0.0.10:9443"`, `ha: { mode: cluster }`,
`certificate.cluster_ca` (same vault address/key path as the two new nodes),
and a `storage.cluster` block (`postgres_dsn`, `session_hmac_key`, `s3`)
alongside the existing `storage.config`. Its systemd unit (an older,
pre-hardening definition — `User=root`, no sandboxing directives, unlike the
two new nodes' `User=cfgms` hardened units) was **not** migrated to the
hardened template in this pass — that's a separable security-hardening
change, deliberately not bundled with the cluster cutover to keep this
already-complex, live-production change minimally scoped. It only gained the
cluster-specific `Environment=` lines (`CFGMS_NODE_ID`,
`CFGMS_HA_EXTERNAL_ADDRESS`, `CFGMS_HA_CLUSTER_NODES`,
`CFGMS_HA_CA_CERT_PATH`, `OPENBAO_ADDR`, `CFGMS_SECRETS_KEY_FILE`,
`CFGMS_S3_INSTALLER_BUCKET`) plus the same `secrets.key` value as the two new
nodes (ctrl-01 had none — its binary predates the `CFGMS_SECRETS_KEY_FILE`
requirement).

All 3 nodes were stopped and started **together** for every coordinated
restart in this story — Raft state is entirely in-memory
(`raft.MemoryStorage`, never persisted to disk), so a node restarted alone
while its peers are already running re-bootstraps as a lone self-elected
leader and diverges from a peer that later tries to join late (reproduced
live: `panic: tocommit(4) is out of range [lastIndex(3)]` in
`go.etcd.io/raft/v3`, from `ctrl-node-3` joining after `ctrl-node-2`
had run solo for 13+ minutes during debugging). A coordinated cold start of
all 3 avoids this entirely.

### Downtime

| Leg | Stopped | Healthy | Downtime |
|-----|---------|---------|----------|
| Initial 3-way cutover (includes live debugging of bugs #2–#6 above) | 2026-08-11T12:30:09Z | 2026-08-11T12:31:33Z | ~84s |
| Rollback drill (cluster → single-node, ctrl-01 only) | 2026-08-11T12:36:32Z | 2026-08-11T12:36:38Z | ~6s |
| Re-cutover (single-node → cluster, final) | 2026-08-11T12:37:59Z | 2026-08-11T12:38:05Z | ~6s |

The two new nodes (`ctrl-node-2`/`3`) were never in the production request
path (no fleet was pointed at them), so their bootstrap iterations carried no
production downtime; only the `ctrl-node-1` legs above affected the live
fleet.

### Rollback drill (tested, not just documented)

Executed once against the live `ctrl-node-1`, mirroring #3127's drill
pattern:

1. Stopped all 3 nodes together.
2. Restored `ctrl-node-1`'s pre-cutover `controller.cfg`, systemd unit, and
   binary from `/root/pre-cluster-cutover-backup/` (taken before any
   cutover change).
3. `systemctl daemon-reload && systemctl start cfgms-controller` on
   `ctrl-node-1` alone.
4. Confirmed `GET /api/v1/health` returned `"status":"healthy"` running as a
   plain single-node controller (no `ha:`/`cluster_ca` in its active config).
5. Re-applied the cluster cutover (rebuilt binary, cluster config, cluster
   systemd unit, shared `secrets.key`) and restarted all 3 nodes together to
   leave the cluster running for the health soak below.

The pre-cutover backup at `/root/pre-cluster-cutover-backup/` on
`ctrl-node-1` is left in place, not retired by this story.

### Quorum verification

`GET /api/v1/raft/status` (admin mTLS) on all 3 nodes after the final
re-cutover, agreeing on `term: 2` and the same elected leader:

```
ctrl-node-1  {"node_id":11522188196814600707,"is_leader":false,"leader":11522193694372741762,"term":2}
ctrl-node-2 {"node_id":11522193694372741762,"is_leader":true, "leader":11522193694372741762,"term":2}
ctrl-node-3 {"node_id":11522191495349485340,"is_leader":false,"leader":11522193694372741762,"term":2}
```

`GET /api/v1/ha/cluster`, after the `pkg/ha` context-lifecycle fix above and a
fresh coordinated restart, returns all 3 nodes' `NodeInfo` (id, address,
capabilities, `started_at`) from every node's admin API — the acceptance
criterion this endpoint exists to satisfy.

An eighth bug was found and fixed chasing why its `leader` field (and the
separate `GET /api/v1/ha/leader` endpoint) still returned empty/`no_leader`
despite `/api/v1/raft/status` correctly agreeing on a real elected leader
across all 3 nodes: `RaftCommand.Data` was typed `interface{}`, so
`applyCommand`'s `json.Unmarshal` decoded the nested `node_update` payload as
`map[string]interface{}` — and `encoding/json` always decodes JSON numbers in
an `interface{}` position as `float64` (53 bits of integer precision). The
64-bit FNV node-ID hashes this package uses (~10^18 magnitude) silently lost
precision through that round-trip, so the key `applyNodeUpdate` actually
stored in `clusterState.Nodes` no longer matched `clusterState.Leader` (set
directly from the raft library's `uint64` `SoftState.Lead`, never touched by
this bug) — `GetLeaderInfo()`'s map lookup always missed. **This is more than
a cosmetic API gap**: a pre-fix reproduction of the regression test showed it
also triggers `Automatic failover triggered [reason=no_leader_elected]` — the
failover manager relies on the same `GetLeader()` path, so in a live cluster
this could have caused spurious failover, not just an empty API field. Fixed
by typing `RaftCommand.Data` as `json.RawMessage`, which defers decoding
until the typed unmarshal and never passes through `float64`. Verified live:
after redeploying the fixed binary and a fresh coordinated restart, all 3
nodes' `GET /api/v1/ha/cluster` and `GET /api/v1/ha/leader` correctly report
the elected leader.

### Health soak

All 3 nodes confirmed `NRestarts=0` and `active (running)` 20+ seconds after
the final coordinated start, with zero crash-loop events. `journalctl` on all
3 shows the expected periodic `Error collecting metrics: System collection
failed: failed to get CPU metrics: no CPU samples returned` (a pre-existing,
Hyper-V-guest-specific metrics gap, unrelated to this story and not
investigated further) and no `panic`/`fatal` lines since the final cutover.

**Steward fleet impact**: `steward_records` in the shared Postgres backend
was already empty (0 rows) before this story's cutover began — confirmed via
`audit_entries` timestamps, whose only non-`controller_start`/`controller_stop`
rows (`steward.exec.dispatched`, `registration_quarantined`) are all dated
2026-08-01, ten days before this cutover, with nothing in between. This
predates #3130 entirely and is most likely a gap in #3127's storage
migration (steward records not carried into the new Postgres schema) —
flagged as a separate follow-up, not investigated or fixed in this story.
This story's cutover caused **no additional fleet impact**: there was no live
steward fleet pointed at `ctrl-node-1` to affect.

## 4. Leader election and failover validation (story #3094)

Live-validated 2026-08-15 against the real 3-node cluster #3130 established
(`ctrl-node-1`, `ctrl-node-2`, `ctrl-node-3`) via a new automated
suite, `test/e2e/ha/leader_election_real_test.go` (`//go:build e2e`, gated by
`CFGMS_E2E_HA_CLUSTER_NODES`) — three tests, each run against the live
cluster, not a one-off manual observation.

### Method

- **Leader agreement**: mTLS `GET /api/v1/raft/status` (admin bundle client
  cert) against all 3 nodes' REST APIs (`:9080`), polled until all 3 agree on
  the same nonzero leader.
- **Process-kill failover**: SSH (`debian@<node>.cluster.example.internal`,
  `~/.ssh/cfgms_cluster_ed25519`) to the current leader, `systemctl kill
  --kill-who=main -s SIGKILL cfgms-controller.service` — an abrupt kill, not
  a graceful `systemctl stop`, so the OS/network stack resets in-flight TCP
  connections immediately (Implementation Notes' distinction from a host
  kill). The remaining 2 nodes are then polled for agreement on a new,
  different leader.
- **Host-kill failover**: `Stop-VM -TurnOff -Force` (hard power-off, not a
  guest shutdown) against the leader's VM, via remote Hyper-V PowerShell
  (`-ComputerName HV-HOST-02`/`HV-HOST-03` from `HV-HOST-01`, the same
  `lab\cfg`-domain-identity pattern the hyperv e2e suites use). Same
  agreement-polling as the process-kill case.
- **Recovery**: both failover tests bring the cluster back to a healthy
  3-node quorum before returning. Because `pkg/ha`'s Raft state is entirely
  `raft.MemoryStorage` (never persisted — see §3's "Raft state is entirely
  in-memory" note and its reproduced `panic: tocommit(4) is out of range
  [lastIndex(3)]`), a solo-restarted node re-bootstraps as a fresh
  self-elected single-node cluster and can diverge from its peers. Recovery
  therefore never restarts the downed node alone: it stops the two still-
  running peers first, brings the downed node back (process start, or
  `Start-VM` + wait-reachable + process start for the host-kill case), then
  starts all 3 together — the same stop-all/start-all discipline as §3's
  rollback drill.

### Measured results (real cfg-lab hardware, 2026-08-15)

| Scenario | Leader killed | New leader | Measured re-election time | Docker target threshold (§ below) |
|---|---|---|---|---|
| Process killed (SIGKILL) | `ctrl-node-2` | `ctrl-node-1` | **14.02s** | `TestLeaderElectionTiming`: < 15s (`test/integration/ha/leader_election_test.go:224-225`) |
| Host killed (`Stop-VM -TurnOff`) | `ctrl-node-2` | `ctrl-node-1` | **16.02s** | `TestFailoverTiming`: < 40s (`test/integration/ha/failover_test.go:131-135`, AC2 — NODE_TIMEOUT 15s + DISCOVERY_INTERVAL 10s + ELECTION_TIMEOUT 5s + buffer) |

**These are target thresholds, not a previously-proven baseline the real
numbers beat.** No GitHub Actions workflow runs `go test
./test/integration/ha/...` — only `cross-platform-build.yml` touches the `ha`
compose profile, and only for a single-container `controller-standalone`
image smoke test, never the 3-controller leader-election scenario — and
`docker-compose.test.yml` never sets `CFGMS_HA_CA_CERT_PATH` (see #3092's
Out of Scope). So the assertions above have likely never executed to
completion against real cross-container mTLS; this story's real-host figures
are the first time these thresholds have actually been proven against any
live cluster, real or Docker. That said, both real-host measurements land
comfortably inside their respective thresholds using **production defaults**
(`pkg/ha.DefaultConfig`: `ElectionTimeout: 10s`, `HeartbeatInterval: 2s` —
this suite deliberately avoids `FastElectionConfig`, which exists only to
keep CPU-contended unit tests fast and would have invalidated the
comparison).

Both runs left the cluster fully restored: `GET /api/v1/raft/status` agreed
across all 3 nodes at `term: 2` afterward, matching §3's own final
post-cutover state — consistent with a coordinated full-cluster restart
being, in effect, a fresh Raft bootstrap each time (state is memory-only, so
term does not carry over across a stop-all/start-all cycle). `GET
/api/v1/health` reported `"status":"healthy"` on all 3 nodes after both
tests. `GET /api/v1/stewards` reported 0 enrolled stewards before and after
each test (the live steward fleet has been empty since the §2 migration —
see §3's "Steward fleet impact" note; monitored per this story's Constraints,
nothing was present to disrupt).

### Technique note: `systemctl set-property` cannot disable `Restart=` at runtime

Not a `pkg/ha` production defect — a test-infrastructure gotcha worth
recording so a future operator doesn't rediscover it live. The unit carries
`Restart=on-failure` / `RestartSec=5`
(`scripts/ha-cluster-node-bootstrap.sh`); an unattended kill would let
systemd auto-respawn the node ~5s into the measurement window, landing it
back in a running quorum solo — the exact divergence risk described above,
except self-inflicted by the test rather than a real outage. The obvious
fix, `sudo systemctl set-property --runtime cfgms-controller.service
Restart=no` before the kill, fails live: `Failed to set unit properties on
cfgms-controller.service: Cannot set property Restart, or unknown property`
(systemd 257, Debian 13) — `Restart=` governs process lifecycle rather than
resource control and isn't in the D-Bus runtime-settable property set.
Verified this is not a version issue; it is simply not a settable property.
Working technique: send the kill and a `systemctl stop` back-to-back over one
SSH connection. `systemctl stop` cancels any pending auto-restart job
regardless of the unit's current state, and one round-trip comfortably beats
the 5s `RestartSec` window.

### Reproduction

```bash
export CFGMS_E2E_HA_CLUSTER_NODES="https://10.0.0.10:9080,https://10.0.0.11:9080,https://10.0.0.13:9080"
export CFGMS_E2E_HA_ADMIN_BUNDLE="C:/Users/cfg/admin.bundle.yaml"   # or ~/.cfgms/admin.bundle.yaml on Linux
go test -tags e2e -run TestRealCluster -v ./test/e2e/ha/...
```

`CFGMS_E2E_HA_SSH_KEY` (default `<home>/.ssh/cfgms_cluster_ed25519`) and
`CFGMS_E2E_HA_SSH_USER` (default `debian`) override the SSH identity used to
reach the node VMs. The host-kill test's `Stop-VM`/`Start-VM` calls target
the leader's Hyper-V host by name (`HV-HOST-01`/`HV-HOST-02`/`HV-HOST-03`, a
fixed cfg-lab topology table in the test file); running against a leader
hosted on `HV-HOST-01` requires a locally-elevated session on that host — this
session's local PowerShell was deliberately non-admin, confirmed live
(`Get-VM` on `HV-HOST-01` itself: "You do not have the required permission");
remote `-ComputerName HV-HOST-02`/`HV-HOST-03` calls worked from the same
non-elevated session without issue, since Hyper-V's remote-management check
is against the target host's group membership, not the caller's local
elevation. Both real runs above happened to land on `ctrl-node-2`
(`HV-HOST-02`), so this gap did not block either measurement.

## 5. Network partition / split-brain validation (story #3095)

Live-validated 2026-08-15 against the real 3-node cluster #3130 established,
via a new automated suite, `test/e2e/ha/network_partition_real_test.go`
(`//go:build e2e`, gated by `CFGMS_E2E_HA_CLUSTER_NODES`) — three tests, each
run against the live cluster.

### Method

A genuine `iptables` rule on **one** cfg-lab host (the current leader, chosen
so the test exercises a real `CheckQuorum` step-down rather than a
never-was-leader no-op) blocks the internal Raft consensus port (`:9443`,
both `--dport` and `--sport`, both `INPUT` and `OUTPUT`) via a dedicated
chain (`CFGMS_E2E_PARTITION`). The admin REST port (`:9080`) is deliberately
left open, so the suite's own mTLS polling (`GET /api/v1/raft/status`) keeps
observing **both** sides of the partition throughout — this is what makes the
dual-leader check meaningful. One node's rule is sufficient to create a
genuine 2-vs-1 split: the isolated node's own `INPUT`/`OUTPUT` chains block
consensus traffic in both directions, so the majority side's outbound
packets simply arrive and get dropped on receipt.

`t.Cleanup` removes the rule unconditionally (chain flush + delete), verified
live to run correctly even when a test assertion fails — the lab cluster was
confirmed fully healed and `iptables -L` empty after every run below,
including the failing one.

### Results

| Test | Result | Measured |
|---|---|---|
| `TestRealClusterPartition_MinorityStepsDown` | **PASS** | Isolated leader stepped down (`is_leader` → `false`) within the 30s bound and stayed down for the full 45s observation window; majority-side steward-fleet health (`GET /api/v1/stewards`) polled throughout, remained reachable (0 stewards enrolled — see §3/§4, unchanged since the storage migration; nothing present to disrupt). |
| `TestRealClusterPartition_NoDualLeader` | **FAIL (reproducible, not a flake)** | Both sides observed reporting `is_leader:true` simultaneously — run 1: 4 consecutive 500ms poll rounds (~2.0s); run 2 (re-run to confirm reproducibility, not a one-off): 11 consecutive rounds (~5.5s). See root cause below. |
| `TestRealClusterPartition_HealsToSingleLeader` | **PASS** | All 3 nodes reconverged on a single agreed leader in **2.01s** after the firewall rule was removed. |

### Root cause of the `NoDualLeader` failure — genuine finding, not a bug in this repo's Raft wiring

Traced through code, not guessed. `pkg/ha.RaftConsensus.IsLeader()`
(`raft_consensus.go:715-719`) reads a locally-cached `clusterState.Leader`
field, updated only from the Raft library's own `SoftState` transitions
(`updateLeadership`, `raft_consensus.go:661-696`) — this is correct: when the
isolated leader's own `CheckQuorum` step-down fires, its `SoftState.Lead`
becomes `raft.None` and `RaftState` becomes `StateFollower`, and
`updateLeadership` correctly sets `clusterState.Leader = 0`, making
`IsLeader()` false immediately once that Ready-cycle is processed. The
per-node tick loop (`raft_consensus.go:330-338`) is a plain, correctly-
implemented `time.Ticker`-driven loop — no processing-delay defect found
there either.

The actual mechanism is **two independent, unsynchronized timers inside
`go.etcd.io/raft/v3 v3.6.0`, each landing anywhere in `[ElectionTimeout,
2×ElectionTimeout]` = `[10s, 20s]` after the partition, with no ordering
between them.** Read out of the library source rather than inferred, because
the two timers are late for *different* reasons:

- **Isolated leader's step-down** — `tickHeartbeat` (`raft.go:862-877`) raises
  `MsgCheckQuorum` on a **fixed**, un-randomized period of exactly
  `electionTimeout` ticks. It is the *evidence* that is stale, not the timer:
  `stepLeader`'s `MsgCheckQuorum` case (`raft.go:1273-1285`) steps down only
  when `!trk.QuorumActive()`, and it clears every peer's `RecentActive` flag
  as it goes, so each check judges the interval since the *previous* check. A
  partition beginning just after check N is therefore still seen as "quorum
  active" at check N+1 and only causes step-down at check N+2 — landing the
  step-down anywhere in `(ElectionTimeout, 2×ElectionTimeout]`.
- **Majority's new election** — `pastElectionTimeout` (`raft.go:2045-2051`)
  uses `randomizedElectionTimeout = electionTimeout + rand(electionTimeout)`,
  i.e. uniformly in `[ElectionTimeout, 2×ElectionTimeout)`. This is the
  genuinely randomized one (anti-election-storm). `PreVote: true` adds a
  pre-vote round on top, which can only push the election later, never
  earlier.

Because the two windows overlap, the majority can complete its election
*before* the isolated node's own `CheckQuorum` observes the loss, producing an
interval in which both report `is_leader:true`. The upper bound on that
interval is the width of the overlap, ~`ElectionTimeout` (10s here);
reproduced twice at 2.0s and 5.5s, both inside that bound — the signature of
two unordered timers, not of a fixed defect.

With `ElectionTimeout: 10s` / `HeartbeatInterval: 2s` (`pkg/ha/config.go:28-29`)
this yields `ElectionTick=5`, `HeartbeatTick=1`, tick period 2s. Shrinking
`ElectionTimeout` narrows the worst-case overlap proportionally but never
closes it, and costs failover sensitivity to transient blips — which is
precisely why the fix below is a design decision rather than a config tweak.

**`pkg/ha/split_brain.go` was checked for a faster, independent detection
path that might already exist but not be wired to the status-reporting
API** — it does not. `performQuorumValidation` (`split_brain.go:339-371`) and
`applyQuorumBasedResolution` (`split_brain.go:421-438`) both detect quorum
loss independently of Raft, but their own code comments state the design
explicitly: *"Raft `CheckQuorum:true` handles leader step-down... no explicit
demotion is needed here"* / *"Raft will step down the leader via
CheckQuorum"* — both functions only **log** on quorum loss and deliberately
take no action, by design. This confirms the dual-leader window is not a
wiring gap (an existing faster mechanism failing to reach `IsLeader()`) but
the intended, documented behavior of relying solely on Raft's own
`CheckQuorum`.

**What Raft's `CheckQuorum` actually guarantees here is write-safety, not
status-flag agreement**: the isolated node cannot get any new log entry
committed without acknowledgment from a quorum of peers, so no conflicting
writes can occur during the overlap window even though both nodes'
`is_leader` fields briefly agree. Closing the STATUS-reporting gap to match
the AC's literal "at no point do two nodes simultaneously report themselves
as leader" would require an additional mechanism beyond vanilla `CheckQuorum`
— most naturally a leader-lease pattern (the leader treats itself as
not-currently-leader for status/read purposes unless it has received
actual quorum acknowledgment within roughly one heartbeat interval,
distinct from the raft library's own `SoftState`). This is a genuine new
architectural decision (lease window sizing is a real tradeoff against
false-demotion on transient network blips shorter than a real partition,
and touches `IsLeader()`/`GetLeaderInfo()`'s core semantics) — per this
epic's own Out-of-Scope carve-out ("fix it inline... unless the fix would
require new architecture, in which case flag it to the PO instead of
building it"), this is flagged for the PO/epic planning rather than built
here.

### Decision required before #3095 could be marked satisfied — RESOLVED by epic #3386

`TestRealClusterPartition_NoDualLeader` is a `[REQUIRED TEST]` of #3095 and,
at the time of the run above, **failed on the exact AC it was written to
prove**. The analysis above explains *why* it failed; it did not make the AC
satisfied on its own. This was an open decision for the PO / team lead, not
something the implementation or the acceptance check could settle — three
options were on the table (adjust the AC to the bound `CheckQuorum` actually
guarantees; split the leader-lease work into a follow-up story and close
#3095 on its other three ACs; or block #3095 until the lease mechanism
landed).

**The PO's ruling (comment on issue #3095, 2026-08-16) rejected weakening the
AC:** tracing the consumers of the pre-fix `IsLeader()` flag
(`features/controller/api/handlers_push.go:57`, `server.go:408`,
`features/controller/server/server.go:2018` at the time) showed the overlap
was not a reporting artifact — `handleConfigPush` resolves the selector,
queries the fleet, writes desired state to the entity graph, and fans out to
stewards via `commandPublisher`, with no Raft commit anywhere in that path.
During the overlap window two nodes would both admit config pushes and
deliver them to real endpoints. *"This story's AC is correct and unchanged,
and its test is not to be weakened, softened, or skipped. The system does not
yet satisfy it."* Resolution moved to epic **#3386** (Controller leadership
authority): lease-backed `HasLeadership()` separated from `IsRaftLeader()`
(#3388), the status surfaces switched to report it (#3435), and story
**#3389** named as the one that would make this test pass, unmodified.

**Resolved run (2026-08-25/26, story #3389).** A controller binary built from
#3389's branch (re-homing the three side-effecting call sites named above
onto `HasLeadership()`) was rolling-deployed to all three real cluster nodes
(`ctrl-node-1`, `ctrl-node-2`, `ctrl-node-3` — one node at a time,
quorum preserved throughout the deployment itself), then all three of this
story's tests were re-run **unmodified**:

| Test | Result | Measured |
|---|---|---|
| `TestRealClusterPartition_NoDualLeader` | **PASS** (previously failed reproducibly at 2.0s/5.5s) | 90 paired poll rounds across 45s (500ms interval), **0 dual-leader instants**. Partitioned node: `ctrl-node-1` (the leader at the time, isolated as the minority side). |
| `TestRealClusterPartition_MinorityStepsDown` | **PASS** (no regression) | Isolated leader (`ctrl-node-3` this run) stepped down and stayed down for the full 45s observation window. |
| `TestRealClusterPartition_HealsToSingleLeader` | **PASS** (no regression) | Reconverged to a single agreed leader in **2.0073369s** (bound 90s) — consistent with this section's original 2.01s measurement. |

Full quorum and cleanup verified after each run: `iptables -L
CFGMS_E2E_PARTITION` absent on all three hosts, `GET /api/v1/health` returns
`healthy` on all three, and `GET /api/v1/raft/status` agrees on a single
leader across all three nodes. The rolling deployment itself is additional
live evidence for the fix: each of the three sequential `systemctl stop` /
binary swap / `systemctl start` cycles is a real, brief leadership loss on
whichever node was stopped, and the cluster reconverged within seconds each
time with no operator intervention — the final restart (of the
then-current leader, `ctrl-node-1`) produced an uneventful term bump
(11→12) and instant re-election, the same `CheckQuorum` / election-timeout
machinery this section's tests exercise deliberately.

**Status: RESOLVED.** #3389 is epic #3386's story that made this AC pass; the
epic's Definition of Done for this half of the leadership-authority work is
satisfied. Fencing terms on *outbound* commands (#3390, merged) and the
steward-side term fence (#3436, merged) are the sibling halves of the epic
covering the command-dispatch path rather than the status/admission path this
section validates.

### Manual partition recovery (Constraints requirement)

If the automated `t.Cleanup` ever fails to remove the rule, the exact manual
command (also logged by the suite at the start of every partition test):

```bash
ssh -i <key> debian@<isolated-node-fqdn> \
  'sudo iptables -D INPUT -j CFGMS_E2E_PARTITION; sudo iptables -D OUTPUT -j CFGMS_E2E_PARTITION; \
   sudo iptables -F CFGMS_E2E_PARTITION; sudo iptables -X CFGMS_E2E_PARTITION'
```

## 6. Steward fleet continuity through failover (story #3096)

Live-validated 2026-08-20 against the same real 3-node cluster (`ctrl-node-1`,
`ctrl-node-2`, `ctrl-node-3`), via a new suite
`test/e2e/ha/steward_continuity_real_test.go` (`//go:build e2e`, same gating and
helpers as §4's `leader_election_real_test.go`).

### Headline

**Steward continuity through a controller leader failover works, and works
cleanly.** A steward attached to a *surviving* node does not notice a leader
change at all.

| Measurement | Value |
|---|---|
| Leader killed | `ctrl-node-2` (SIGKILL to the main process) |
| New leader | `ctrl-node-3` |
| Re-election time | **12.02s** |
| Steward's next heartbeat after the kill | **+6s** |
| Heartbeats missed | **0** (cadence ~25s held straight through) |
| Steward reconnects / ControlChannel errors during failover | **0** |
| Steward status throughout | `active` |

The reason is structural, and it is the answer to this story's central
investigation question: **there is no leader-forwarding step in the steward
path.** Every node serves steward traffic itself, straight against the shared
Postgres backend. Confirmed live by registering a steward through
`ctrl-node-1` while it was a *follower* — HTTP 200, certificate issued, row
written. So the leader is not in a steward's request path, and a leader change
is invisible to a steward whose own node stays up.

This also means the blue/green precedent in
[`operating-model.md`](../architecture/operating-model.md) (§"Stewards reconnect
via the gRPC-over-QUIC backoff already built into the client", 1–3s) does **not**
need to transfer: for leader failover, the steward's connection is never broken,
so no client-side backoff is exercised at all.

**The converse is the real gap.** A steward has exactly one controller URL, so
when *its own* node dies it does not fail over anywhere — it retries that one
node until it returns. That is the `steward-operating-model.md` multi-controller
gap (re-confirmed and re-scoped there), not a defect this story fixes; it is
explicitly out of scope per the epic's Non-Goals. If a deployment needs it today,
the only existing lever is an LB/VIP in front of the cluster — and note that
because *any* node serves steward traffic, such an LB does **not** need to
health-gate on `is_leader`; a plain liveness gate on `GET /api/v1/health`
suffices. That is a meaningfully cheaper answer than the leader-only LB the story
brief hypothesised, and it falls out of the no-forwarding finding above.

> **Superseded for the registration path (2026-08-22).** #3473 subsequently gated
> the registration and token endpoints on `HasLeadership()`, so a follower now
> answers `503` to an enrolment attempt. An LB used for *enrolment* **must**
> health-gate on leadership after all. The conclusion above still holds for the
> ControlChannel path this section actually measured — steady-state steward
> traffic is still served by any node. See §7.

### Reproduction

```bash
export CFGMS_E2E_HA_CLUSTER_NODES="https://10.0.0.10:9080,https://10.0.0.11:9080,https://10.0.0.13:9080"
export CFGMS_E2E_HA_ADMIN_BUNDLE="C:/Users/cfg/admin.bundle.yaml"
go test -tags e2e -run TestRealClusterStewardContinuity -v ./test/e2e/ha/...
```

`CFGMS_E2E_HA_STEWARD_ID` pins which steward to observe; unset means "first
`active` one". The suite **skips** rather than passing vacuously when no active
steward exists, because enrolling one is currently blocked by F2/F3 below.

### Enrolling a steward against the cluster (the procedure that works today)

This is the reconnect/enrolment procedure this story was asked to prove. It
works, but only with F1's fix in place and only until the next controller
restart (F3).

1. Add a trusted CIDR for the tenant so the default `ip-trust` approval hook
   returns `approve` instead of `quarantine`:
   ```bash
   POST /api/v1/registration/ip-trust {"tenant_id":"<tenant>","cidr":"<lan>/24","pre_seeded":true}
   ```
2. Mint a registration token (`POST /api/v1/registration/tokens`), then run the
   steward with the controller CA pinned:
   ```bash
   CFGMS_HTTP_CA_CERT_PATH=/path/to/controller-ca.crt \
     cfgms-steward --regtoken <token> --controller-url https://<any-node>:9080
   ```
   Any node works — leader or follower.
3. Reverse with `DELETE /api/v1/registration/ip-trust/<tenant>/<cidr>` (verified
   reversible: the entry soft-revokes, `revoked: true`, and enrolment stops
   being possible again). All scaffolding used for this story was reverted this
   way; the lab was left with 0 steward records, a healthy 3-node quorum, and
   `NRestarts=0` on all three nodes.

### Findings

Six defects were found live. Two were small enough to fix inside this story
(F1, F5); the rest are recorded here with file/line pointers, per the epic's
"document, don't fix" Non-Goal, and have since been filed as follow-up stories:

| Finding | Status |
|---|---|
| F1 — ip-trust API dead wiring | **fixed in this story** |
| F2 — no PendingRegistrationStore on Postgres | **already fixed** by #3401 (merged 2026-08-20, after this story's live run) |
| F3 — RLS unscoped read returns nothing | filed as **#3478** |
| F4 — fleet view is node-local | **fixed** by #3480 |
| F5 — missing record reported as service outage | **fixed in this story** |
| F6 — refused steward reconnects at ~1 Hz forever | **fixed by #3481** (PR #3497) |
| Cluster-restart hazard — Raft ConfState not restored | **fixed** by #3479 |

#### F1 (FIXED HERE) — the IP-trust operator API was dead wiring on every deployment

`api.Server.SetIPTrustStore` (`features/controller/api/server.go`) had **no
production caller**, so `s.ipTrustStore` was always nil and all three
`/api/v1/registration/ip-trust` endpoints returned `503 ip-trust store
unavailable` on every deployment shape — even though the Postgres provider
implements `CreateIPTrustStore` and `StorageManager.GetIPTrustStore()` returned a
live store that was handed to the approval hook a few lines later
(`features/controller/server/server.go`). Every handler unit test calls
`SetIPTrustStore` itself, which is why only startup wiring was broken and nothing
caught it. Same bug class as Issue #2548's tag/role store wiring.

This mattered here because the default `ip-trust` hook quarantines any untrusted
source IP, and an operator had **no way** to mark one trusted — so with F2 below,
enrolment against a cluster was impossible by any route.

Fixed by `wireRegistrationAPIStores`
(`features/controller/server/registration_api_store_wiring.go`), with a
regression test that does not need a Postgres-backed manager. Verified live: the
endpoint went from `503` to serving reads and writes, and enrolment then
succeeded.

#### F2 (documented) — the Postgres backend has no PendingRegistrationStore, so the quarantine path cannot work in a cluster

`DatabaseProvider.CreatePendingRegistrationStore`
(`pkg/storage/providers/database/plugin.go`) returns `business.ErrNotSupported`.
`CreateClusterStorageManager` (`pkg/storage/interfaces/provider.go`) tolerates
that and leaves the store nil, so `SetPendingStore` is skipped and every
quarantine registration fails at `handlers_registration.go` with
`503 Registration admission service unavailable` — reproduced on all three nodes.
Every `/api/v1/registration/*` admin endpoint 503s for the same reason.

Because Postgres is the only backend a multi-node cluster can share, the
quarantine/approval workflow was **unavailable in cluster mode by construction**,
and only the ip-trust auto-approve path (F1) could enrol anything.

**Since fixed by #3401** (PR #3463, merged 2026-08-20 — a few hours after this
story's live run, which was therefore measured against a controller that still
had the gap). The observations above describe the pre-#3401 behaviour and are
retained because they are what forced the ip-trust enrolment route this story
documents; re-verify against a current build before treating the 503s as live.

#### F3 (documented — highest impact) — RLS hides steward records from the controller's own DB role

**This is the root cause of the "steward fleet has been empty since the §2
migration" mystery recorded in §3 and §4.** The rows were never missing; they are
invisible.

`pkg/storage/providers/database/migrations/004_add_sessions_stewards_commands.sql`
states its intent in its own header comment — *"permissive when app.current_tenant
is not set (empty string)"* — and implements it as:

```sql
CREATE POLICY rls_read ON steward_records FOR SELECT USING (
    current_setting('app.current_tenant', true) = ''
    OR tenant_id = current_setting('app.current_tenant', true)
);
```

`current_setting(..., true)` returns **NULL**, not `''`, when the setting was
never applied in the session. `NULL = ''` is NULL, `tenant_id = NULL` is NULL,
`NULL OR NULL` is NULL — so the row is filtered out and the intended "unscoped
caller sees everything" branch **never fires**. Proven directly against the live
database:

| Session state | `select count(*) from steward_records` as role `cfgms` |
|---|---|
| `app.current_tenant` unset | **0** |
| `set app.current_tenant = ''` | 2 |
| `set app.current_tenant = 'infra-hyperv'` | 2 |
| (as superuser, RLS bypassed) | 2 |

and `select current_setting('app.current_tenant', true) is null` → `true`.

Consequences observed live: writes succeed (registration sets the tenant), then
any read without tenant context sees nothing. After a controller restart the
ControlChannel approval check — which has no tenant context — cannot find *any*
steward, so **every** steward is denied admission and the fleet cannot recover.
The same policy shape is applied to `sessions`, `steward_records`,
`command_records` and `command_transitions`.

Filed as **#3478**. *Recommended fix: wrap the unscoped branch in `coalesce(...)`,
e.g.* `coalesce(current_setting('app.current_tenant', true), '') = ''`*, in a new
migration across all four tables.* Deliberately **not** fixed inside this story:
it is a tenant-isolation control, and changing RLS semantics warrants its own
story and security review rather than riding along in a failover-continuity PR.

#### F4 (documented) — the fleet view is node-local, not cluster-wide

`GET /api/v1/stewards` (unfiltered) is served from
`ControllerService.GetAllStewards()`
(`features/controller/service/controller_service.go`), an in-process map — not
the shared store. Measured: a steward actively heartbeating through
`ctrl-node-1` was reported by that node and **not** by the other two, including
the leader, while its row sat in shared Postgres the whole time. The e2e suite
records this per-node split as a log line rather than an assertion, so it does not
block on a known gap.

So while a steward's *connection* survives failover cleanly, the new leader has
no knowledge of it.

**FIXED by #3480**, which composes the two sources rather than swapping one for
the other: the durable `StewardStore` is authoritative for existence, identity
and last-known status cluster-wide, while the node-local registry stays
authoritative for live connection state on the serving node. A steward attached
to a peer therefore appears with its durable facts and no fabricated liveness.
Tenant scoping was added to the unfiltered list path at the same time — it was
previously safe to omit only because the in-process map was node-local, and
reading the shared store without it would have handed a tenant-scoped caller the
whole cluster's fleet. Note this fix only returns rows once #3478 is applied:
before that, an unscoped store read is filtered to nothing by RLS.

#### F5 (FIXED HERE) — a missing steward record was reported as an approval-service outage

`stewardStoreApprovalChecker.IsApproved`
(`pkg/controlplane/providers/grpc/approval.go`) wrapped every store error,
including `business.ErrStewardNotFound`, so ControlChannel answered
`codes.Unavailable "steward approval service unavailable"` for a steward that
simply has no record. `Unavailable` reads as transient, so the steward retried
forever, and the controller logged the miss at ERROR on every attempt — **78 MB
of controller log and 63 MB of steward log in a single day** across three such
stewards on this cluster.

A steward with no record is definitively *not approved* — a determinate answer,
not a dependency failure. Now returns `(false, nil)`, which is equally
fail-closed (admission still refused) but surfaces as `PermissionDenied`.
Verified live: the message changed to `PermissionDenied: steward reconnect not
approved`.

**This does not stop the retry loop**, which is a separate defect, below.

#### F6 (fixed by #3481) — rejected stewards reconnect at ~1 Hz forever; backoff never grows

`Provider.reconnectLoop` (`pkg/controlplane/providers/grpc/provider.go`)
constructs a **fresh** backoff on every entry, and `dialAndOpenStream()` succeeds
for a stream the server rejects — the rejection only surfaces on the first
`Recv()`. So the client logs "reconnected", resets/rebuilds its backoff, is
rejected, and re-enters the loop at the initial interval. Observed live at
`attempt 1, backoff 1s` indefinitely. This is what turned F5's misclassification
into a log flood, and it will do the same for any persistently-rejected steward
regardless of status code.

Filed as **#3481**, not fixed here at the time: it changes reconnect timing in
the shared control-plane client, which is the very thing this story measures.

**Fixed in #3481** (PR #3497). The backoff now lives on the `Provider` and
persists across `reconnectLoop` invocations instead of being rebuilt per call,
and the reset moved from stream-open to the first successful `Recv` — a stream
that opens and is refused before delivering anything no longer counts as a
success. A persistently-refused steward now escalates to the configured ceiling
and keeps retrying there, while an ordinary transport-drop reconnect (which does
receive messages before breaking) still reconnects promptly.

### Cluster-restart hazard found while running this story (F1 of §4's concern, new)

Restarting the cluster no longer works unattended, and this bit twice during this
story. Since Issue #3284 the Raft log is persisted to `<data>/raft-log/raft.db`,
and `NewRaftConsensus` (`pkg/ha/raft_consensus.go`) takes `raft.RestartNode`
whenever that file has data. But nothing restores the **ConfState**, and
`config.Applied` is set to the recovered applied index, so the original
`ConfChange` entries are never re-delivered either. Every node comes back with an
empty voter set and no election ever happens:

```
newRaft 9fe7091e2a553a03 [peers: [], term: 3, commit: 8, applied: 8, ...]
newRaft 9fe70c1e2a553f1c [peers: [], term: 2, commit: 7, applied: 7, ...]
```

`GET /api/v1/raft/status` then reports `"leader":0` forever, with terms diverging
between nodes. Reproduced deterministically across two full stop/start cycles of
all three nodes. Note the WAL paths differ per node
(`/var/lib/cfgms/data/raft-log/` on `ctrl-node-1`, `/var/lib/cfgms/raft-log/`
on the other two), and `raft.db.wiped-3095` files on all three show story #3095
hit this too.

**Recovery** (also now built into `haRestoreQuorum` so the e2e suites leave the
lab healthy):

```bash
# on all three nodes
sudo systemctl stop cfgms-controller.service
sudo find /var/lib/cfgms -name raft.db -delete
# then start all three together
sudo systemctl start cfgms-controller.service
```

Quorum re-forms in seconds via the `StartNode` bootstrap path.

**FIXED by #3479.** The Raft `ConfState` is now persisted whenever a ConfChange
is applied, and restored on restart by seeding storage with a synthetic snapshot
carrying it — placed at the recovered applied index, with entries above that
index re-appended so committed-but-unapplied work is not lost. A store written
*before* the fix has a full log and no `ConfState`; those heal in place from the
configured peer list, so **no manual `raft.db` deletion is required when
upgrading past this fix**. The recovery procedure above is retained only for
nodes still running a pre-#3479 binary.

`haRestoreQuorum` in `test/e2e/ha/leader_election_real_test.go` no longer wipes
the WAL: that workaround destroyed the very log #3284 added, and would now mask
a regression in the restore path rather than working around a known defect.
This supersedes the "Raft state is entirely in-memory" note in §3/§4 — that was
true before #3284 and is why those stories' stop-all/start-all drills worked.

## 7. Fleet enrollment against the cluster (story #3405)

Executed 2026-08-22 against the 3-node cluster. This is the section to follow to
rebuild the cfg-lab fleet from scratch.

### Outcome

All three Hyper-V hosts (`HV-HOST-01`, `HV-HOST-02`, `HV-HOST-03`) are enrolled
against the cluster and were proven end to end:

| Check | Result |
|---|---|
| Enrolled and present in `GET /api/v1/stewards` | 3 stewards, tenant `infra-hyperv` |
| Visible from **all three** nodes, consistent identity/tenant/status | yes |
| Converging — proven by a real config delivery, not presence | `successful:1 failed:0`, marker file written on the endpoint |
| Survives a controller restart, **including a steward that never reconnected** | 3/3 still fully described on all nodes |
| Survives a leader failover, no steward lost or duplicated | `count=3 unique=3` on both survivors, term 2 → 3 |

This is the first fleet this epic has had. Every "live steward fleet is
undisrupted" criterion in epic #3090 previously measured against **0 stewards**
and passed vacuously.

### Prerequisite: the controller binary must be current

Deploy a build containing #3401, #3403, #3478 and #3480 to **all three** nodes
before enrolling. This is not optional housekeeping:

`pkg/storage/providers/database/steward_store.go:61` calls
`CreateStewardRecordsTable` on every store construction, and that function does
`DROP POLICY IF EXISTS rls_read` + `CREATE POLICY`. **A controller startup
rewrites the RLS policies from whatever is compiled into the running binary.** A
node still on a pre-#3478 build therefore silently reverts migration 010 the next
time it restarts, and the fleet becomes unreadable again with no error anywhere.
Verify after deploying:

```sql
SELECT CASE WHEN qual LIKE '%COALESCE%' THEN 'FIXED' ELSE 'BROKEN' END
FROM pg_policies WHERE tablename='steward_records' AND cmd='SELECT';
```

### Registration is leader-only — this is the trap

Since **#3473** the registration and token endpoints are gated on
`HasLeadership()`. A follower answers `503 service unavailable`, and the steward
surfaces it as:

```
HTTP registration failed: registration failed with status 503: service unavailable
```

which reads as an outage rather than "you are talking to a follower". Measured
on the live cluster: follower `.103` → 503, leader `.106` → 202. **Point the
steward's `--controller-url` at the current leader for enrolment.**

The gRPC ControlChannel is *not* leader-gated, so steady-state steward traffic
is genuinely any-node; only the enrolment REST call must reach the leader.

> **This corrects §6.** That section concluded an LB fronting the cluster "does
> not need an `is_leader` health gate — a plain liveness gate suffices." That was
> measured before #3473 and is no longer true for registration: an LB used for
> enrolment **must** health-gate on leadership (`GET /api/v1/raft/status` →
> `is_leader`). §6's conclusion still holds for the ControlChannel path it was
> actually measuring.

Find the leader before enrolling:

```bash
for ip in 103 104 106; do curl -s --cert admin.crt --key admin.key --cacert ca.crt \
  https://192.168.234.$ip:9080/api/v1/raft/status; done   # pick is_leader:true
```

### Procedure (per host)

1. **Mint a token against the leader.** The default lifetime is 15 minutes,
   which is too short for a multi-host rollout — set `expires_in`:
   ```
   POST https://<leader>:9080/api/v1/registration/tokens
   {"tenant_id":"infra-hyperv","controller_url":"10.0.0.10:4433","expires_in":"24h"}
   ```
2. **Stop the steward and clear its identity** so it re-registers rather than
   presenting a certificate the cluster has no record of:
   ```powershell
   Stop-Service CFGMSSteward -Force
   $certs = "$env:ProgramData\cfgms\steward\certs"
   Copy-Item -Recurse $certs "$certs.pre-enrol"; Remove-Item -Recurse -Force -LiteralPath $certs
   ```
3. **Repoint the service at the leader.** `sc.exe config binPath=` is unreliable
   through PowerShell remoting — the quoting is mangled and the change silently
   does not apply (observed live). Set the registry value instead, and read it
   back:
   ```powershell
   $key = 'HKLM:\SYSTEM\CurrentControlSet\Services\CFGMSSteward'
   $exe = '"C:\Program Files\CFGMS\cfgms-steward.exe"'
   Set-ItemProperty $key ImagePath "$exe --regtoken <TOKEN> --controller-url https://<leader>:9080"
   (Get-ItemProperty $key).ImagePath      # verify — do not assume
   ```
4. **Start the service**, then approve the quarantined registration. Approval
   takes the **`pending_id`**, not the steward ID:
   ```
   GET  https://<leader>:9080/api/v1/registration/pending
   POST https://<leader>:9080/api/v1/registration/<pending_id>/approve
   ```

`HV-HOST-01` hosts the non-admin operator session, so steps 2–4 there need an
elevated shell run by the maintainer; `HV-HOST-02` and `HV-HOST-03` are reachable
via `Invoke-Command` with an elevated token from the same account.

### Verification

```
GET /api/v1/stewards        # on EACH of .103 / .104 / .106 — all three must agree
```
A steward visible on only one node means the cluster-wide fleet read (#3480) is
not in the running build. Then prove convergence with a real delivery rather than
trusting presence:

```
PUT /api/v1/stewards/<steward_id>/config
```
with a `file` resource, restart the steward, and confirm the file exists on the
endpoint and the log reports `Configuration execution completed … successful:1
failed:0`. Note the `file` module **requires** `allowed_base_path` (an absolute
path constraining all operations); omitting it fails the resource with
`AllowedBasePath is required`, while the config still deploys — so the delivery
looks successful and the resource does not apply.

### Recovery — steward does not appear

- **`503 service unavailable` on register** — the URL points at a follower. Not
  an outage. Repoint at the leader.
- **`401 Invalid or expired registration token`** — tokens default to 15 minutes.
- **Steward loops `PermissionDenied: steward reconnect not approved`** — it holds
  a certificate for which the cluster has no record. Clear its identity
  (step 2) and re-enrol. Until #3481 lands this retries at ~1 Hz indefinitely and
  will flood both logs.
- **`Access is denied` writing the CA cert** — the Windows **ReadOnly** attribute
  on pre-existing files under `C:\ProgramData\cfgms`; clear `IsReadOnly` first.
  ACL grants do not fix it.

### Findings recorded, not fixed here

Per this story's Out of Scope, defects belong to sibling stories:

- **A stopped steward still reports `status: active`.** C3-02's steward was down
  across the whole controller restart and remained `active` in the fleet list on
  all three nodes. Correct for AC4 ("still fully described"), but liveness is not
  being aged — an operator cannot distinguish a live steward from a stopped one
  by status alone.
- **DNA `hostname`/`os` are empty in the fleet list** for all three stewards
  despite the steward publishing DNA successfully. Registration seeds
  identity hints (#2640); they are not surfacing in `GET /api/v1/stewards`.
- **Every controller restart still needs a manual `raft.db` wipe** to re-form
  quorum, because #3479's ConfState fix is not yet on `develop`. Both restarts in
  this story used the §6 recovery procedure. Once #3479 lands, drop the wipe.

---

## 8. Sealed-credential migration (story #3462)

Removing `EnvironmentFile=` secret delivery from the cluster nodes, per
[ADR-030](../architecture/decisions/030-controller-secret-material-at-rest.md).
Exercised on the live 3-node cluster on 2026-08-22, not only on a fresh install.

### What changed on each node

Before, `ctrl-node-2` and `ctrl-node-3` carried
`EnvironmentFile=/etc/cfgms/ha-secrets.env` — three secrets in cleartext on disk
and in the service environment, where `/proc/<pid>/environ` exposes them to root
and every child process inherits them. `ctrl-node-1` was worse: it kept the
same shape in `/etc/cfgms/storage-secrets.env` *and* read the root key straight
from the cleartext `/etc/cfgms/secrets.key` with no credential wiring at all.

After, all three carry four `LoadCredentialEncrypted=` lines and no
`EnvironmentFile=`, and no cleartext secret file remains anywhere under
`/etc/cfgms`.

### Node binding: `key_mode: host`, not `tpm2`

None of the three lab VMs presents a usable TPM2 — `systemd-analyze has-tpm2`
reports `partial` (rc 19: no firmware, driver or `libtss2-*` libraries) and there
is no `/dev/tpm*`. The bootstrap therefore **refuses** to provision them by
default rather than silently sealing to the disk-resident host key, and the
migration was run with the explicit `--allow-host-key` opt-in. Each node records
`key_mode: host` in `/etc/cfgms/.bootstrap-record`.

That is a real, recorded weakening for this lab: the unsealing key
(`/var/lib/systemd/credential.secret`) sits on the same virtual disk as the
blobs, so a stolen VHDX of a node yields that node's plaintext secrets. It does
not yield *another* node's — the blobs are still per-machine — but the cluster's
at-rest guarantee is its weakest node's, which is why the mode is written down
per node instead of inferred. Enabling vTPM on these VMs and re-running the
bootstrap (after deleting the `.cred` files) would move them to `key_mode: tpm2`.

### Procedure

The credential-sealing and unit rewrite are non-disruptive: the running service
keeps its already-loaded environment, and the new unit takes effect at the next
start. Only the final restart is an outage.

```bash
# 1. On each of ctrl-node-2 / ctrl-node-3, with the cluster still serving:
#    source the node's own existing values, then re-run the updated bootstrap.
sudo bash -c '
  set -a; . /etc/cfgms/ha-secrets.env; set +a
  export CFGMS_SECRETS_KEY_B64="$(base64 -w0 < /etc/cfgms/secrets.key)"
  CFGMS_BOOTSTRAP_ALLOW_HOST_KEY=1 bash ha-cluster-node-bootstrap.sh \
    --hostname=<fqdn> --node-id=<node-id> \
    --cluster-nodes=<same list as the running unit> \
    --postgres-host=... --s3-endpoint=... \
    --vault-address=... --vault-key-path=root/cluster-ca --skip-smoke
'

# 2. ctrl-node-1's unit was hand-written during the §3 cutover, not generated
#    by either script. Change only its secret-delivery lines: seal the three
#    values from storage-secrets.env plus the root key, replace
#    EnvironmentFile= with the four LoadCredentialEncrypted= lines and their
#    *_FILE Environment= lines, then remove the two cleartext files.

# 3. Deploy a controller build that understands the *_FILE variables (below),
#    then restart all three together.
```

**The controller binary must be updated in the same window.** Only
`CFGMS_SECRETS_KEY_FILE` existed before; `CFGMS_STORAGE_DB_PASSWORD_FILE`,
`CFGMS_SESSION_HMAC_KEY_FILE` and `OPENBAO_TOKEN_FILE` are #3462 additions. A
pre-#3462 binary started against a migrated unit fails config validation with
`missing required environment variables: [CFGMS_STORAGE_DB_PASSWORD ...]`.

### Restart hazard (pre-existing, #3479)

The coordinated stop/start hit the known ConfState-recovery defect documented in
§6 above: all three nodes came back with `"leader":0` and an empty voter set.
This is **not** related to credential delivery — it reproduces on any
stop-all/start-all since #3284. Its documented recovery (stop all three, `find
/var/lib/cfgms -name raft.db -delete`, start all three) restored quorum in
seconds.

### Evidence (2026-08-22)

Quorum, identical to the pre-migration baseline (term 2, leader
`11522188196814600707` = `ctrl-node-1`):

```
ctrl-node-1  {"node_id":11522188196814600707,"is_leader":true, "leader":11522188196814600707,"term":2,"nodes":3}
ctrl-node-2 {"node_id":11522193694372741762,"is_leader":false,"leader":11522188196814600707,"term":2,"nodes":3}
ctrl-node-3 {"node_id":11522191495349485340,"is_leader":false,"leader":11522188196814600707,"term":2,"nodes":3}
```

`GET /api/v1/health` reported `"status":"healthy"` on all three.

No secret in the service environment on any node — `/proc/<MainPID>/environ`
carries only paths:

```
CFGMS_SECRETS_KEY_FILE=/run/credentials/cfgms-controller.service/cfgms-secrets-key
CFGMS_STORAGE_DB_PASSWORD_FILE=/run/credentials/cfgms-controller.service/cfgms-db-password
CFGMS_SESSION_HMAC_KEY_FILE=/run/credentials/cfgms-controller.service/cfgms-session-hmac-key
OPENBAO_TOKEN_FILE=/run/credentials/cfgms-controller.service/cfgms-openbao-token
```

Credentials present and correctly scoped (`0440` with a per-invocation ACL where
the unit drops to `User=cfgms`; `0400` on `ctrl-node-1`, which still runs as
root):

```
-r--r-----+ 1 root root 32 cfgms-db-password
-r--r-----+ 1 root root 26 cfgms-openbao-token
-r--r-----+ 1 root root 32 cfgms-secrets-key
-r--r-----+ 1 root root 64 cfgms-session-hmac-key
```

`/etc/cfgms` holds no `secrets.key`, `ha-secrets.env` or `storage-secrets.env` on
any node.

Fail-loudly, verified on `ctrl-node-3` with a transient unit rather than the
cluster service: a sealed blob with one byte flipped makes systemd refuse to
start the unit with `status=243/CREDENTIALS`, and nothing generates a
replacement key.

### Two defects this live run caught

**Binary key truncated through a shell variable.** `provision_secrets_key`
originally decoded `CFGMS_SECRETS_KEY_B64` into a shell variable. A real 32-byte
random key contains NUL bytes, and bash command substitution discards them — the
first live migration attempt reported the cluster's actual key as *31 bytes* and
refused to proceed. Had the length check not been there, it would have compared
unequal against the node's existing key and, without the mismatch guard, sealed a
truncated root of trust. The key is now only ever a byte stream; `test7d` in
`ha-cluster-node-bootstrap_test.sh` pins it with a NUL-containing fixture.

**The pre-flight port check made the in-place upgrade impossible.** The script
refused to run whenever port 9080 was in use, which on a live node is always —
so the "idempotent, re-run safe" script could not actually be re-run without
taking the node down first, forcing a cluster-wide outage before any preparation
could happen. It now distinguishes its own running `cfgms-controller` from a
foreign listener.

---

## 9. Steward-side Raft-term command fence (story #3436)

Live-fleet proof for the in-memory comparison logic in
`features/steward/client/client_transport.go` (`checkTermFence` /
`receiveCommand`) — see
[`steward-operating-model.md`](../architecture/steward-operating-model.md#raft-term-command-fence-adr-029-decision-6)
for the design. This story implements comparison only; persistence across a
steward restart and the authenticated reset path are #3437.

### Method

A steward binary built from the story branch (`v0.0.0-story3436-fencetest`,
`go build ./cmd/steward`, no ldflags beyond `pkg/version.Version`) was run as a
**standalone validation instance** on `HV-HOST-01` — deliberately *not* the
shared `CFGMSSteward` production service on that host, to avoid touching a
live fleet member other stories depend on. Isolation required overriding two
environment variables the steward reads independently
(`ProgramData` for certs/secrets, `CFGMS_LOG_DIR` for logs — the latter is set
host-wide on `HV-HOST-01` to the real `C:\ProgramData\CFGMS\logs`, and a first
attempt without overriding it wrote two orphaned log files into that
production directory before the mistake was caught; no production files were
modified, and the two stray files were deleted). `CFGMS_HTTP_CA_CERT_PATH` was
pointed at the real cluster CA read-only.

The instance registered fresh (`cfg token create --tenant-id=infra-hyperv`,
approved via `cfg registration approve`) against the live 3-node
`ctrl-node-1` / `ctrl-node-2` / `ctrl-node-3` HA controller cluster
described in §1 — the same cluster whose Raft term this story's fence
enforces against. Registration and token-creation POSTs only succeeded
against `10.0.0.13` (the leader at the time); the other two nodes
returned `503` for both, consistent with these being unforwarded
leader-only writes rather than a fleet problem.

To observe the fence's decision on real inbound traffic without changing the
committed logic, two temporary `logger.Info` lines (prefixed
`TEMP-3436-VALIDATION-ONLY`) were added to `checkTermFence`, built, run
against the live cluster, and then reverted before commit — `git diff` against
the committed state was checked to confirm zero trace remained (`grep -c
TEMP-3436` = 0) and the fencing unit tests were re-run to confirm no
regression from the edit/revert cycle.

### Result

The steward (`steward-1787621085452586756`, a disposable validation record —
left enrolled, consistent with this fleet's existing orphaned-record entries
noted elsewhere in this doc; no decommission command exists) completed a real
mTLS + gRPC-over-QUIC connection to `ctrl-node-3` and received a genuine
inbound `push_signing_cert` command from the live controller as part of its
on-connect handshake. `checkTermFence` observed it with `claimed_term: 0`
against an unset ratchet and accepted it via the bootstrap-accept branch —
the same branch the story's bootstrap REQUIRED TEST exercises, now proven
against a real command dispatched by the real controller over the real wire
path, not a synthetic one. This confirms end to end: the receive path is
correctly wired ahead of `commands.Handler.HandleCommand` in the live
`SubscribeCommands` closure, `sc.Command.Term` deserializes correctly off the
real gRPC transport, and the fence does not interfere with normal command
delivery against a live controller.

**Not proven live: the rejection branches.** A genuine term decrease cannot be
produced by a healthy controller in this cluster — Raft terms are monotonic
(`becomeCandidate` only increments), so no legitimate live command can ever
carry a term below one this steward has already seen. Forcing a real
decrease would require deliberately corrupting the shared 3-node HA
controller cluster's Raft state (e.g. the documented `raft.db`-delete
recovery in §8, which resets the cluster other in-flight stories depend on)
— judged disproportionate to this story's validation. The rejection and
downgrade-omission branches are exhaustively covered by
`TestCheckTermFence_AcceptsAtOrAboveHighest_RejectsBelow` and
`TestCheckTermFence_DowngradeAfterRatchetSet_RejectsMissingOrZeroTerm` in
`client_transport_fencing_test.go` (deterministic, run in CI on every PR), and
by inspection share the exact `checkTermFence` code path just proven live for
the accept case — there is no separate rejection path that live traffic could
exercise differently. A live demonstration of an actual downgrade attempt
requires either #3437's `clusterID`-paired reset scenario (a legitimate
rebuild presenting a lower term for a *different* cluster) or dedicated
adversarial tooling that forges a signed command outside the controller —
out of scope here.

Attempting to trigger additional live command types via `cfg steward exec` /
`cfg steward run-command` against the validation steward reproduced the
`status: running (0/0 completed)` symptom already on file for this fleet
(target-selector match failure, not a term-fencing issue) — not investigated
further as out of scope for this story.
