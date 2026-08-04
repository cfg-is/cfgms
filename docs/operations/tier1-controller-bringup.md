# Tier 1 Controller Bring-Up

**M1 deliverable.** This runbook is the source of truth for `scripts/tier1-bootstrap.sh`.
Every Tier 1 rebuild from here on is: provision VM, copy script, run script.

Storage backend: flatfile + SQLite. No git, no SOPS, no external database.

---

## 1. Overview

`tier1-bootstrap.sh` orchestrates every step of a fresh Tier 1 controller deployment:
OS baseline, binary install, certificate initialization, systemd service, tenant tree
seeding, and smoke test. It is idempotent — re-running it on a fully-bootstrapped host
exits 0 with no destructive action.

The few steps that flank the script are covered in §4 (run bootstrap), §5 (distribute
admin bundle), and §2 (prerequisites). Everything else is automated.

---

## 2. Prerequisites

**VM specification** (Hyper-V Gen 2):

| Resource  | Minimum          | Notes                          |
|-----------|------------------|--------------------------------|
| OS        | Debian 12         | Bookworm. Other Debian-family distros not tested. |
| vCPU      | 2                 |                                |
| RAM       | 4 GB              |                                |
| Disk      | 40 GB             | `/var/lib/cfgms` grows with fleet size. |
| Secure Boot | Enabled (Gen 2) | Controller binary is unsigned; disable Secure Boot if it blocks execution. |

**Network:**

- SSH access from operator workstation to the VM
- VM outbound HTTPS (port 443) to `github.com` — binary download during bootstrap
- Ports 9080/TCP (REST API) and 4433/UDP (gRPC-over-QUIC) reachable from stewards and the `cfg` CLI

**Files to copy to the VM before running bootstrap:**

```bash
scp scripts/tier1-bootstrap.sh scripts/tier1-smoke-test.sh \
    <operator>@ctrl.cfgms.lab:/tmp/
```

Both scripts must be in the same directory at runtime (the smoke test script is
invoked by the bootstrap script via relative path).

---

## 3. Hostname vs IP and SAN

The TLS certificate generated during initialization embeds the hostname you supply
via `--hostname` in the Subject Alternative Name (SAN). Clients — stewards and the
`cfg` CLI — verify the SAN against what they dial. If they dial an IP address instead
of a hostname, the IP must match an entry in the cert's `ip_addresses` list.

**Default behavior:** the bootstrap script sets `common_name` and `dns_names` to the
`--hostname` value and always includes `127.0.0.1` in `ip_addresses`.

**Operator responsibility for routing:** Stewards and the `cfg` CLI must be able to
reach the controller at the hostname you provide. DNS or `/etc/hosts` entries are the
operator's responsibility — the bootstrap script does not configure network routing.

If the controller is reachable at additional hostnames or IPs (load balancer VIPs,
secondary interfaces), edit `/etc/cfgms/controller.cfg` before running `--init`, or
re-initialize with a `--config` override that includes the additional SANs.

---

## 4. Run Bootstrap

**Single command — run as root on the controller VM:**

```bash
sudo bash /tmp/tier1-bootstrap.sh --hostname=ctrl.cfgms.lab
```

Optional flags:

| Flag                    | Default                 | Purpose                                |
|-------------------------|-------------------------|----------------------------------------|
| `--hostname HOST`       | _(required)_            | Cert SAN + controller config hostname  |
| `--version TAG`         | latest tagged release   | Pin to a specific release tag          |
| `--binary-path PATH`    | _(download)_            | Air-gapped: provide binary locally     |
| `--config PATH`         | _(generated)_           | Provide a custom controller.cfg        |
| `--skip-tenant-seed`    | _(off)_                 | Skip tenant tree seeding               |
| `--skip-smoke`          | _(off)_                 | Skip smoke test                        |

Expected output (abbreviated):

```
[bootstrap] Step 1: Pre-flight checks
[bootstrap] Pre-flight checks passed.
[bootstrap] Step 2: OS baseline (idempotent)
[bootstrap] Directory layout ready.
[bootstrap] Step 3: Binary fetch
[bootstrap] Installing cfgms-controller version v1.x.y
[bootstrap] Binary installed to /usr/local/bin/cfgms-controller
[bootstrap] Step 4: Config
[bootstrap] Config rendered to /etc/cfgms/controller.cfg
[bootstrap] Step 5: Controller init
Controller initialization complete:
  CA Fingerprint:    SHA256:xxxx...
  Storage Provider:  flatfile
  Initialized At:    2026-06-02T00:00:00Z
[bootstrap] Step 6: Systemd service
[bootstrap] cfgms-controller service started.
[bootstrap] Step 7: Tenant seed
[bootstrap]   Tenant team-root: created.
[bootstrap]   Tenant agent-test: created.
[bootstrap]   Tenant infra-hyperv: created.
[bootstrap] Tenant seeding complete.
[bootstrap] Step 8: Smoke test
[PASS] health: GET /api/v1/health
[PASS] tenant-exists: team-root
[PASS] tenant-exists: agent-test
[PASS] tenant-exists: infra-hyperv

Result: 4 passed, 0 failed

==========================================
 Tier 1 Controller Bootstrap Complete
==========================================

Admin bundle:  /etc/cfgms/admin.bundle.yaml
...
```

If any step fails, the script exits non-zero and the error message identifies the
failing step. Correct the issue and re-run — the script is idempotent and will skip
already-completed steps.

---

## 5. Distribute Admin Bundle

The admin bundle (`/etc/cfgms/admin.bundle.yaml`) grants full admin access to the
controller REST API. Treat it like a root SSH key: never leave it on disk longer than
necessary to copy it to the keychain.

**Step 1 — Copy bundle to workstation (operator machine):**

```bash
scp ctrl.cfgms.lab:/etc/cfgms/admin.bundle.yaml /tmp/admin.bundle.yaml
```

**Step 2 — Store in OS keychain:**

Linux:
```bash
secret-tool store --label="CFGMS Admin Bundle" service cfgms bundle admin \
  < /tmp/admin.bundle.yaml
```

macOS:
```bash
security add-generic-password -s cfgms -a admin \
  -w "$(cat /tmp/admin.bundle.yaml)"
```

**Step 3 — Remove the plaintext copy:**

```bash
rm /tmp/admin.bundle.yaml
```

**Step 4 — Load the bundle in future shell sessions:**

```bash
source scripts/cfgms-bundle-load
```

`cfgms-bundle-load` retrieves the bundle from the keychain, writes it to a temp file,
exports `CFGMS_ADMIN_BUNDLE`, and registers a `trap` to delete the temp file when the
shell exits. After sourcing it, `cfg` and `tier1-smoke-test.sh` pick up `CFGMS_ADMIN_BUNDLE`
automatically.

---

## 6. Manual Upgrade

Verify the candidate's release signature, provenance, and checksum before it
reaches the controller. Read the release notes for state-format compatibility;
if the new release performs an irreversible state migration, a binary-only
rollback is not safe and the cold backup from §8 is required.

Stage the candidate without overwriting either the running binary or the
previous rollback copy:

```bash
sudo install -o root -g root -m 0755 \
  /path/to/new/cfgms-controller \
  /usr/local/bin/cfgms-controller.candidate

sudo systemctl stop cfgms-controller
sudo cp --preserve=mode,ownership,timestamps \
  /usr/local/bin/cfgms-controller \
  /usr/local/bin/cfgms-controller.previous
sudo mv /usr/local/bin/cfgms-controller.candidate \
  /usr/local/bin/cfgms-controller
sudo systemctl start cfgms-controller
```

Run the smoke test after upgrade to confirm the new version operates correctly:

```bash
source scripts/cfgms-bundle-load
bash scripts/tier1-smoke-test.sh
```

If startup or the smoke test fails, capture the journal and roll back immediately:

```bash
sudo journalctl -u cfgms-controller --no-pager -n 200
sudo systemctl stop cfgms-controller
sudo cp --preserve=mode,ownership,timestamps \
  /usr/local/bin/cfgms-controller.previous \
  /usr/local/bin/cfgms-controller.rollback
sudo mv /usr/local/bin/cfgms-controller.rollback \
  /usr/local/bin/cfgms-controller
sudo systemctl start cfgms-controller

source scripts/cfgms-bundle-load
bash scripts/tier1-smoke-test.sh
```

Retain `cfgms-controller.previous` until the upgraded controller has completed
the environment's soak period. For an incompatible state migration, restore the
pre-upgrade archive as described in §8 before starting the previous binary.

Do not re-run `tier1-bootstrap.sh` for upgrades — the `--init` step is idempotent
but binary placement goes through the download path. Use `--binary-path` if you
need to re-run the full bootstrap with a specific binary.

---

## 7. Operator Routing Responsibility

The bootstrap script provisions the controller and its TLS configuration but does not
manage network routing. The operator is responsible for:

- **Steward → controller**: UDP port 4433 must be open from steward network segments
  to the controller IP. Configure firewall rules, security groups, or VLAN policies
  as appropriate for the environment.
- **cfg CLI → controller**: TCP port 9080 must be reachable from operator workstations.
  For lab environments, direct reachability is typical. For production, consider a
  jump host or VPN.
- **DNS / hosts**: If stewards dial the controller by hostname, that hostname must
  resolve to the controller's IP from steward network segments.

The `--hostname` value supplied to bootstrap is embedded in the TLS SAN. If stewards
dial a different address (IP or alternate hostname), either re-bootstrap with the
correct `--hostname` or add the address to the config's `dns_names`/`ip_addresses`
before `--init`.

---

## 8. Recovery

Tier 1 has no online backup command. A complete recoverable copy consists of:

- `/var/lib/cfgms/` — SQLite, flat-file data, CA, server certificate, and audit data
- `/etc/cfgms/controller.cfg` — deployment configuration
- `/etc/cfgms/secrets.key` — the external encryption key

The key must be backed up at the same consistency point but escrowed separately
from the state archive under equivalent or stronger access control. Loss of it
makes encrypted data unrecoverable; disclosure compromises every secret
protected by it.

### Cold backup

Stop the controller so SQLite and flat-file state are captured at one consistency
point. Create the archive on an encrypted filesystem, copy the archive and checksum
to encrypted off-host storage, and then remove the staging copy.

```bash
sudo systemctl stop cfgms-controller

sudo sh -eu <<'EOF'
umask 077
install -d -m 0700 /backup/cfgms
backup_base="/backup/cfgms/controller-$(date -u +%Y%m%dT%H%M%SZ)"
state_file="${backup_base}.state.tar.gz"
key_file="${backup_base}.secrets.key"
tar --create --gzip --acls --xattrs --numeric-owner \
  --file "${state_file}.tmp" \
  --directory / \
  var/lib/cfgms \
  etc/cfgms/controller.cfg
install -m 0600 /etc/cfgms/secrets.key "${key_file}.tmp"
mv "${state_file}.tmp" "${state_file}"
mv "${key_file}.tmp" "${key_file}"
sha256sum "${state_file}" "${key_file}" > "${backup_base}.sha256"
printf 'Created coordinated backup set %s\n' "${backup_base}"
EOF

sudo systemctl start cfgms-controller
source scripts/cfgms-bundle-load
bash scripts/tier1-smoke-test.sh
```

Test restoration on an isolated host at the same release before relying on a
backup. Never extract an untrusted archive.

### Cold restore

Provision the `cfgms` service account and systemd unit first, but leave the
controller stopped. Verify the checksum and inspect the member list before
extracting:

```bash
sudo systemctl stop cfgms-controller
cd /backup/cfgms
sha256sum --check controller-YYYYMMDDTHHMMSSZ.sha256
tar --list --gzip --file controller-YYYYMMDDTHHMMSSZ.state.tar.gz

sudo tar --extract --gzip --acls --xattrs --numeric-owner \
  --file controller-YYYYMMDDTHHMMSSZ.state.tar.gz \
  --directory /
sudo install -o cfgms -g cfgms -m 0600 \
  controller-YYYYMMDDTHHMMSSZ.secrets.key \
  /etc/cfgms/secrets.key
sudo chown -R cfgms:cfgms /var/lib/cfgms
sudo chown cfgms:cfgms /etc/cfgms/controller.cfg
sudo chmod 0750 /var/lib/cfgms /etc/cfgms
sudo chmod 0640 /etc/cfgms/controller.cfg
sudo chmod 0600 /etc/cfgms/secrets.key

sudo systemctl start cfgms-controller
source scripts/cfgms-bundle-load
bash scripts/tier1-smoke-test.sh
```

After restore, verify audit-chain integrity, tenant inventory, steward
reconnections, certificate validity, and a signed configuration operation in
addition to the smoke test.

### Rebuild without a backup

If no usable backup exists:

1. Provision a new Debian 12 VM (§2)
2. Copy `tier1-bootstrap.sh` and `tier1-smoke-test.sh` to the new VM
3. Run bootstrap: `sudo bash /tmp/tier1-bootstrap.sh --hostname=<hostname>`
4. Distribute the new admin bundle (§5)
5. Re-register stewards — existing steward registrations are not portable across
   controller reinitializations (new CA means all mTLS credentials are invalid)

---

## 9. Per-Step Deviation Guide

If the bootstrap script cannot run (e.g., no outbound internet, restricted shell),
each step can be performed manually:

**Step 1 — Pre-flight**
The script checks for root, Debian OS, and port 9080 availability. Run manually:
`id` (must be 0), `grep -i debian /etc/os-release`, `ss -tlnp | grep ':9080'`.

**Step 2 — OS baseline**
The script runs `apt-get update && apt-get install -y git curl`, creates the `cfgms`
system user, and creates directories with correct ownership. Manually:
```bash
apt-get install -y git curl
useradd --system --no-create-home --shell /usr/sbin/nologin cfgms
mkdir -p /etc/cfgms /var/lib/cfgms/storage /var/lib/cfgms/certs/ca /var/log/cfgms
chown -R cfgms:cfgms /var/lib/cfgms /var/log/cfgms
chmod 750 /var/lib/cfgms /var/log/cfgms /etc/cfgms
```

**Step 3 — Binary fetch**
The script downloads the latest tagged release tarball from GitHub and extracts
`cfgms-controller` and `cfg` to `/usr/local/bin/`. Manually for air-gapped:
build from source (`make build-controller build-cli`) and copy to `/usr/local/bin/`.
Never use the develop tip for Tier 1 — always use a tagged release.

**Step 4 — Config**
The script renders `/etc/cfgms/controller.cfg` from the canonical template
(`docs/deployment/controller.cfg`) with `--hostname` substituted into
`common_name` and `dns_names`. Manually: copy the template and edit those fields.
Storage backend must be `flatfile_root` + `sqlite_path` (no git, no SOPS).

**Step 5 — Init**
The script runs `cfgms-controller --init --config /etc/cfgms/controller.cfg`.
This is idempotent: if `/etc/cfgms/.admin-bundle-issued` exists, init is skipped.
The init command creates the CA, server certificates, storage backend, and admin
bundle. Save the CA fingerprint printed at this step — stewards need it at
registration time.

**Step 6 — Systemd**
The script writes the unit file to `/etc/systemd/system/cfgms-controller.service`
and runs `systemctl daemon-reload && systemctl enable --now cfgms-controller`.
Manually: copy the unit from `docs/deployment/single-controller/cfgms-controller.service`
and run the same systemctl commands.

**Step 7 — Tenant seed**
The script runs `cfg tenant create` three times (idempotent):
```bash
cfg tenant create --tenant-id=team-root
cfg tenant create --tenant-id=agent-test --parent=team-root
cfg tenant create --tenant-id=infra-hyperv --parent=team-root
```
The `cfg` binary uses `CFGMS_ADMIN_BUNDLE` for authentication. Run these after
the controller is running and the admin bundle is available.

**Step 8 — Smoke test**
The script runs `scripts/tier1-smoke-test.sh`. Manually run it the same way:
```bash
CFGMS_ADMIN_BUNDLE=/etc/cfgms/admin.bundle.yaml bash scripts/tier1-smoke-test.sh
```
Expected: 4 checks pass (health + 3 tenant-exists). See §10.

---

## 10. Smoke Test

The smoke test (`scripts/tier1-smoke-test.sh`) validates the bootstrapped controller:

| Check | What it verifies |
|-------|-----------------|
| `health: GET /api/v1/health` | REST API accepts mTLS connections and returns HTTP 200 |
| `tenant-exists: team-root` | Root tenant seeded successfully |
| `tenant-exists: agent-test` | Child tenant seeded under team-root |
| `tenant-exists: infra-hyperv` | Child tenant seeded under team-root |

Expected output:
```
[PASS] health: GET /api/v1/health
[PASS] tenant-exists: team-root
[PASS] tenant-exists: agent-test
[PASS] tenant-exists: infra-hyperv

Result: 4 passed, 0 failed
```

To run it manually after bootstrap:

```bash
CFGMS_ADMIN_BUNDLE=/etc/cfgms/admin.bundle.yaml bash scripts/tier1-smoke-test.sh
```

Or from an operator workstation after sourcing the bundle:

```bash
source scripts/cfgms-bundle-load
bash scripts/tier1-smoke-test.sh --controller-url=https://ctrl.cfgms.lab:9080
```

If the smoke test fails, check the controller logs:
```bash
sudo journalctl -u cfgms-controller --no-pager -n 50
```
