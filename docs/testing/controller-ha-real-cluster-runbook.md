# Controller HA — real-cluster validation runbook

Live-validation runbook for epic **#3090** (Controller HA validation on a real
multi-node cluster): migrating the Tier-1 `cfg-lab` controller off its
single-node storage backend onto shared PostgreSQL + S3-compatible blob
storage, joining a genuine 3-node `CFGMS_HA_MODE=cluster` deployment across
separate real hosts, and validating leader election, failover, and
split-brain resolution on real hardware rather than Docker containers.

---

## 1. Environment

Live bed: the **cfg-lab** 3-node Hyper-V failover cluster (`lab.cfg.is`),
same physical bed as the module-convergence work — see
[`hyperv-cluster-cascade-runbook.md`](hyperv-cluster-cascade-runbook.md) §1
for the underlying hypervisor topology (`CFG-70-02` / `CFG-AB-02` /
`CFG-C3-02`, CSV01, `HVSwitch_1G`).

### Lab rebuild note (2026-07-31/08-01)

While provisioning this story's VM, the lab's exec-dispatch subsystem and
`CFG-70-02`'s steward wedged in a way that required a full lab reset —
all non-DC Hyper-V VMs torn down (CSV01 storage cleaned), the Tier-1
controller (`cfgms-ctrl-01`) rebuilt from scratch on `CFG-70-02`, and all
three HV-host stewards re-enrolled. The domain controllers (`cfg-dc1-02`,
`cfg-dc2-02`) were left untouched throughout.

`cfgms-ctrl-01` is therefore **no longer** the persistent controller from the
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
  even though the identical call succeeds in isolation. Both `cfgms-ctrl-01`
  and `cfgms-lab-datasvc` were provisioned manually instead (raw cloud image
  → fixed VHD → dynamic VHDX via `C:\temp\raw2vhd`, CIDATA seed built with
  the same mechanics as the module, `-EnableSecureBoot Off`) rather than via
  `cfg config upload` — see `C:\temp\ctrl-vm-create.ps1` /
  `C:\temp\datasvc-vm-create.ps1` on `CFG-70-02` for the exact recipe.
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

### Shared data-services VM (`cfgms-lab-datasvc`) — story #3124

A dedicated Debian VM hosts the PostgreSQL + MinIO backend shared by all
cluster controller nodes:

| Property | Value |
|----------|-------|
| VM name | `cfgms-lab-datasvc` |
| Hypervisor host | `CFG-70-02` |
| Tenant | `infra-hyperv` |
| Provisioning | Manual (see the rebuild note above) — `C:\temp\datasvc-vm-create.ps1` builds the VM, then `scripts/lab-datasvc-bootstrap.sh` (run once over SSH) installs PostgreSQL + MinIO |
| IP address | `192.168.234.105` (lab LAN, `192.168.234.0/24`, DHCP) |

**PostgreSQL:**

| Property | Value |
|----------|-------|
| Port | `5432` |
| Database | `cfgms` |
| Role | `cfgms` (dedicated, non-superuser, `LOGIN` only) |
| Listen | all interfaces; `pg_hba.conf` restricts inbound to `192.168.234.0/24` via `scram-sha-256` |
| Connection string shape | `postgres://cfgms:<password>@192.168.234.105:5432/cfgms?sslmode=require` |

**MinIO (S3-compatible blob storage):**

| Property | Value |
|----------|-------|
| API port | `9000` |
| Console port | `9001` |
| Bucket | `cfgms-installer-blobs` |
| `endpoint_url` | `http://192.168.234.105:9000` |

**Credentials:** the PostgreSQL role password and MinIO root access/secret
key are generated once by `scripts/lab-datasvc-bootstrap.sh` on first run and
printed to stdout a single time. They are stored in the operator
workstation's OS-native keychain (Windows Credential Manager on `CFG-70-02`,
target names `cfgms-lab-datasvc-postgres` / `cfgms-lab-datasvc-minio`) — never
committed to a file in this repository. See the script's step 7 output for
the exact storage commands on Linux/macOS.

### Privileges

Provisioning the VM and running the in-guest bootstrap requires the same
`cfg steward exec` (SYSTEM) / cluster-admin path documented in
[`hyperv-cluster-cascade-runbook.md`](hyperv-cluster-cascade-runbook.md) §1 —
a non-admin shell cannot create the VM or reach the Hyper-V APIs.

---

## 2. Storage migration (story #3127)

*To be filled in when #3127 lands — migrates the live Tier-1 controller from
its current flatfile/SQLite backend onto the `cfgms-lab-datasvc` PostgreSQL +
MinIO backend via `cfg storage migrate`.*

## 3. Cluster join (story #3130)

*To be filled in when #3130 lands — joins two additional controller nodes to
the migrated Tier-1 controller, forming a 3-node `CFGMS_HA_MODE=cluster`
deployment.*

## 4. Leader election and failover validation (story #3094)

*To be filled in when #3094 lands.*

## 5. Network partition / split-brain validation (story #3095)

*To be filled in when #3095 lands.*

## 6. Steward fleet continuity through failover (story #3096)

*To be filled in when #3096 lands.*
