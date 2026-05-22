# Fleet Deployment Walkthrough

Deploy a CFGMS controller, register two remote stewards, push a fleet config, and
observe convergence and drift correction — end to end on fresh Linux VMs.

**Time**: ~60 minutes (first-time setup)

**What you'll have when done**:
- A running controller accepting connections from remote stewards
- Two remote stewards registered, receiving configs, and converging
- A fleet config uploaded and applied on both endpoints
- Drift observable via controller logs and metrics

> **This walkthrough is the spec** that the docker fleet test (Epic #1501) validates
> on every PR. Commands marked `[GAP: ...]` represent planned functionality that is
> not yet implemented; REST API fallbacks are provided to demonstrate the underlying
> capability today.

## How this differs from the single-controller walkthrough

The [single-controller walkthrough](../single-controller/walkthrough.md) covers
controller bring-up and the local controller-steward. This walkthrough extends that by:

- Configuring the controller for remote steward access (transport on `0.0.0.0:4433`,
  public hostname/IP in the TLS certificate)
- Building steward binaries with the controller URL compiled in (required for remote
  registration)
- Issuing registration tokens and deploying stewards on separate VMs
- Pushing a fleet config and observing convergence across the fleet

Phases 1–2 below are a thin wrapper that delegates most steps to the single-controller
walkthrough. Start there if you haven't deployed a controller yet.

## Architecture

```
┌──────────────────────────────────┐
│        Operator Workstation      │
│  cfg CLI + admin.bundle.yaml     │
└──────────────┬───────────────────┘
               │ HTTPS :9080 (REST API, mTLS)
               ▼
┌──────────────────────────────────┐
│         Controller VM            │
│                                  │
│  REST API (HTTPS)    :9080/TCP   │
│  gRPC-over-QUIC (mTLS) :4433/UDP│
│  Auto-generated CA + certs       │
│  Flatfile+SQLite storage         │
└───────────┬──────────────────────┘
            │ gRPC-over-QUIC :4433 (mTLS)
            ├─────────────────────┐
            ▼                     ▼
┌─────────────────┐   ┌─────────────────┐
│  Steward VM 1   │   │  Steward VM 2   │
│  cfgms-steward  │   │  cfgms-steward  │
│  (systemd)      │   │  (systemd)      │
└─────────────────┘   └─────────────────┘
```

## Prerequisites

**Three Linux VMs** (Debian/Ubuntu recommended):
- `controller` — runs the CFGMS controller
- `steward-1` — first managed endpoint
- `steward-2` — second managed endpoint

**Network requirements**:
- Port `9080/TCP` open on the controller (REST API, for operator CLI and steward registration)
- Port `4433/UDP` open on the controller (gRPC-over-QUIC transport, for connected stewards)
- Both steward VMs can reach the controller on both ports
- Operator workstation can reach the controller on `9080/TCP`

**Build machine** (can be the controller VM):
- Go v1.25+
- Git installed

---

## Phase 1 — Controller Deployment

The controller setup is identical to the single-controller walkthrough, with two
important differences for fleet mode:

1. **Transport must listen on `0.0.0.0:4433`** (the default) — not `127.0.0.1:4433`
2. **The controller's public hostname or IP must be in the TLS certificate** so stewards
   can verify it during gRPC transport connection

Follow all steps in the [single-controller walkthrough](../single-controller/walkthrough.md)
up to and including **Step 4: Validate End-to-End**. When configuring `/etc/cfgms/controller.cfg`,
verify these fields:

| Field | Fleet requirement |
|-------|-------------------|
| `certificate.server.common_name` | Controller's public hostname or IP (e.g. `ctrl.mylab.local`) |
| `certificate.server.dns_names` | All hostnames stewards use to reach the controller |
| `certificate.server.ip_addresses` | All IPs stewards use to reach the controller |
| `transport.listen_addr` | `"0.0.0.0:4433"` (all interfaces, not just localhost) |

> **Storage note**: If `controller.cfg` still has `storage.provider: "git"`, replace the
> `storage:` block before running `--init` — the git provider has been removed. Use:
> ```yaml
> storage:
>   flatfile_root: "/var/lib/cfgms/storage"
>   sqlite_path: "/var/lib/cfgms/cfgms.db"
> ```
> See [#1547](https://github.com/cfg-is/cfgms/issues/1547) to track the canonical config update.

Once the single-controller walkthrough's Step 4 checklist passes, continue here.

---

## Phase 2 — Admin Bundle Access

`cfgms-controller --init` writes an admin credential bundle to
`/etc/cfgms/admin.bundle.yaml` on the controller. This file contains everything
the `cfg` CLI needs to authenticate to the controller REST API via mTLS.

Copy the bundle from the controller to your workstation:

```bash
# On your workstation — adjust the path/user to match your controller
scp controller-vm:/etc/cfgms/admin.bundle.yaml ~/.config/cfgms/admin.bundle.yaml
chmod 600 ~/.config/cfgms/admin.bundle.yaml
```

The `cfg` CLI walks the following lookup chain for the bundle:

| Priority | Location |
|----------|----------|
| 1 | `cfg --bundle <path>` flag |
| 2 | `CFGMS_ADMIN_BUNDLE` environment variable |
| 3 | `~/.config/cfgms/admin.bundle.yaml` (Linux/macOS) |
| 4 | `/etc/cfgms/admin.bundle.yaml` (Linux) |

> **Security**: This file grants full admin access to the controller. Treat it like a
> root SSH key — restrict permissions to `0600` and never commit it to version control.

### Verify admin bundle access

```bash
cfg controller status --url=https://<CONTROLLER_IP>:9080
```

Replace `<CONTROLLER_IP>` with your controller's IP or hostname. The `--url` flag points
to the REST API (port 9080, HTTPS) — not the QUIC transport port.

Expected output:

```
✓ Controller Health Status: HEALTHY
Uptime: X minutes
Checked: 2026-05-19 00:00:00 UTC

=== Component Health ===
✓ Transport (healthy)
✓ Storage (healthy)
✓ Application (healthy)
```

If you see a certificate error, the bundle's CA cert does not match the controller's TLS
certificate. Verify the bundle was generated by `--init` on this controller. See
[Troubleshooting](#troubleshooting) for more.

---

## Phase 3 — Issue Registration Tokens

A registration token is a short-lived credential that allows a steward to auto-register
with the controller. The token embeds the controller's gRPC transport address so the
steward knows where to connect after registration.

> **Two-port architecture**: The `--controller-url` in `cfg token create` is the
> **gRPC/QUIC transport address** (port `4433/UDP`) — the address stewards use for
> ongoing communication. This is distinct from the REST API (port `9080/TCP`) used
> by the `cfg` operator CLI. Do not mix them up.

Create a token for the group. Tokens are perennial — they survive multiple registrations until explicitly rotated or revoked:

```bash
# Token for the production group (7-day expiry window)
cfg token create \
  --tenant-id=default \
  --controller-url=<CONTROLLER_IP>:4433 \
  --group=production \
  --expires=7d
```

To invalidate the current token and issue a fresh one (e.g., after a deployment completes or a credential rotation policy requires it):

```bash
cfg token rotate --tenant-id=default --group=production
```

Replace `<CONTROLLER_IP>` with the IP or hostname steward VMs use to reach the controller.

**Token create output** (example):

```
Registration Token: abcdefghijklmnopqrstuvwxyz123456

Token Details:
  Tenant ID:      default
  Controller URL: 192.0.2.10:4433
  Group:          production
  Expires:        2026-05-26T00:00:00Z

Deployment Examples:

Linux/macOS:
  ./cfgms-steward-install --regtoken="abcdefghijklmnopqrstuvwxyz123456"

Direct execution:
  cfgms-steward --regtoken=abcdefghijklmnopqrstuvwxyz123456
```

Save the token string — you'll use it in Phase 4.

List all active tokens at any time:

```bash
cfg token list --tenant-id=default
```

---

## Phase 4 — Build and Register Remote Stewards

### Windows endpoints — MSI installer

Windows endpoints can be enrolled silently using the `cfgms-steward-windows-amd64.msi`
(or `arm64`) installer produced by CI. Download the MSI from the release artifacts and
deploy it from your RMM (NinjaOne, Datto, ConnectWise, etc.):

```powershell
# Silent install — public CA (controller uses a publicly-trusted cert):
msiexec /qn /i cfgms-steward-windows-amd64.msi `
  REGTOKEN="<registration-token>" `
  CA_FINGERPRINT="<sha256-hex>"

# Silent install — private CA (place ca.crt alongside the MSI before running):
# ca.crt is auto-detected from the same directory as the .msi file.
msiexec /qn /i cfgms-steward-windows-amd64.msi `
  REGTOKEN="<registration-token>" `
  CA_FINGERPRINT="<sha256-hex>"
```

The installer places `cfgms-steward.exe` in `C:\Program Files\CFGMS\` and registers the
`CFGMSSteward` Windows service configured for automatic start with restart-on-failure recovery.

> **CA fingerprint**: the controller prints the CA fingerprint during `--init`. Retrieve it
> at any time: `cfg controller info --url=https://<IP>:9080 | grep fingerprint`

> **Full Windows MSI deployment guide**: a complete walkthrough — including how to build
> a controller-URL-baked MSI for your fleet, download the install package from the controller,
> and distribute via RMM — will be added in Story 8 of Epic #1661.

### 4a — Build a steward binary for your controller

The steward binary has the controller URL **compiled in at build time**. A given binary
only ever talks to the controller it was built for — this is a deliberate trust assertion
(see `cmd/steward/main.go`).

On your build machine:

```bash
git clone https://github.com/cfg-is/cfgms.git
cd cfgms
make build-steward STEWARD_CONTROLLER_URL=https://<CONTROLLER_IP>:9080
```

This produces `bin/cfgms-steward` with the controller URL embedded. The `STEWARD_CONTROLLER_URL`
must use the HTTPS scheme and port 9080 (the REST API address stewards use for the initial
HTTP registration call, before switching to gRPC-over-QUIC on port 4433).

> **For remote stewards with a self-signed controller CA**: The steward verifies the
> controller's TLS certificate during registration. If the controller uses its
> auto-generated CA (the default), stewards need the CA certificate to trust it.
> Set `CFGMS_HTTP_CA_CERT_PATH` on each steward VM before running the binary:
> ```bash
> # Copy the CA cert from the controller (at /var/lib/cfgms/certs/ca/ca.crt)
> scp controller-vm:/var/lib/cfgms/certs/ca/ca.crt /tmp/controller-ca.crt
> export CFGMS_HTTP_CA_CERT_PATH=/etc/cfgms/controller-ca.crt
> ```
> Place the CA cert at a stable path (e.g. `/etc/cfgms/controller-ca.crt`) so the
> systemd service can find it via its `Environment=` directive.

### 4b — Deploy and register steward-1

Copy the binary and register as a systemd service in one step:

```bash
# On steward-1 VM
sudo cp cfgms-steward /usr/local/bin/cfgms-steward
sudo chmod +x /usr/local/bin/cfgms-steward

# If using the controller's self-signed CA:
sudo mkdir -p /etc/cfgms
sudo cp /tmp/controller-ca.crt /etc/cfgms/controller-ca.crt
sudo chmod 644 /etc/cfgms/controller-ca.crt

# Register and install as systemd service
# (requires the CFGMS_HTTP_CA_CERT_PATH env to be set in the service unit
#  if using the controller's self-signed CA — see note below)
sudo CFGMS_HTTP_CA_CERT_PATH=/etc/cfgms/controller-ca.crt \
  cfgms-steward install --regtoken <TOKEN_FOR_STEWARD_1>
```

> **Systemd environment**: `cfgms-steward install` writes a systemd unit file. If the
> controller uses a self-signed CA, add the CA path to the unit's `Environment=` directive
> after install:
> ```bash
> sudo systemctl edit cfgms-steward --force
> # Add:
> # [Service]
> # Environment=CFGMS_HTTP_CA_CERT_PATH=/etc/cfgms/controller-ca.crt
> sudo systemctl daemon-reload
> sudo systemctl restart cfgms-steward
> ```

Alternatively, for a quick foreground first-run before committing to systemd:

```bash
sudo CFGMS_HTTP_CA_CERT_PATH=/etc/cfgms/controller-ca.crt \
  cfgms-steward --regtoken <TOKEN_FOR_STEWARD_1>
```

This blocks until you `Ctrl-C`. Use it to see registration logs before installing as a service.

### 4c — Deploy and register steward-2

Repeat the same steps on `steward-2` using `<TOKEN_FOR_STEWARD_2>`.

### 4d — Verify steward service

On each steward VM:

```bash
cfgms-steward status
sudo systemctl status cfgms-steward
sudo journalctl -u cfgms-steward -n 20 --no-pager
```

Look for these log messages on successful registration and connection:

```
Registration successful via HTTP   steward_id=<ID>  tenant_id=default  group=production
Connected to controller via gRPC transport
Configuration executor initialized  tenant_id=default
```

---

## Phase 5 — Verify Fleet

### List registered stewards

```bash
cfg steward list
```

Expected output (two stewards registered, both `connected`):

```
ID              STATUS     VERSION  LAST SEEN             HOSTNAME
--              ------     -------  ---------             --------
steward-abc123  connected  1.0.0    2026-05-19 00:00:30   steward-1
steward-def456  connected  1.0.0    2026-05-19 00:00:31   steward-2
```

Note the `ID` values for each steward — you'll need them in Phase 6.

### Inspect a specific steward

```bash
cfg steward status <STEWARD_ID>
```

Expected output:

```
ID:               steward-abc123
Status:           connected
Connection:       connected
Last Seen:        2026-05-19 00:00:30
Version:          1.0.0
Hostname:         steward-1
OS:               linux
Architecture:     amd64
```

Use `--json` to get the full machine-readable response:

```bash
cfg steward status <STEWARD_ID> --json
```

> **Alternative — REST API via curl**
> If you prefer direct API access or need to script around the controller, the REST
> endpoints are also available. First extract your admin bundle's certs:
>
> ```bash
> python3 - <<'EOF'
> import os, yaml
> b = yaml.safe_load(open(os.path.expanduser('~/.config/cfgms/admin.bundle.yaml')))
> open('/tmp/admin.crt','w').write(b['cert_pem'])
> open('/tmp/admin.key','w').write(b['key_pem'])
> open('/tmp/admin-ca.crt','w').write(b['ca_pem'])
> EOF
> chmod 600 /tmp/admin.key
> ```
>
> List all stewards:
> ```bash
> curl --cacert /tmp/admin-ca.crt --cert /tmp/admin.crt --key /tmp/admin.key \
>   https://<CONTROLLER_IP>:9080/api/v1/stewards
> ```
>
> Get a specific steward:
> ```bash
> curl --cacert /tmp/admin-ca.crt --cert /tmp/admin.crt --key /tmp/admin.key \
>   https://<CONTROLLER_IP>:9080/api/v1/stewards/<STEWARD_ID>
> ```

### Controller-side visibility

The controller's transport metrics show connected steward count:

```bash
cfg controller metrics --url=https://<CONTROLLER_IP>:9080
```

Look for `Connected Stewards: 2` in the Transport section.

---

## Phase 6 — Upload a Fleet Config

An example fleet config is in [`example-fleet-config.yaml`](example-fleet-config.yaml).
It demonstrates a simple file and directory deployment. Edit it to match your environment
before uploading.

Upload the config to each registered steward using the steward IDs from Phase 5:

```bash
# Upload to steward-1
cfg config upload example-fleet-config.yaml --steward <STEWARD_1_ID>

# Upload to steward-2
cfg config upload example-fleet-config.yaml --steward <STEWARD_2_ID>
```

Expected output:

```
Configuration stored for steward <STEWARD_1_ID> (status: stored)
```

> **Alternative (curl)**: If you prefer the REST API directly, you can upload using
> `PUT /api/v1/stewards/{id}/config` with `Content-Type: application/yaml`:
>
> ```bash
> curl \
>   --cacert /tmp/admin-ca.crt \
>   --cert /tmp/admin.crt \
>   --key /tmp/admin.key \
>   -X PUT \
>   -H "Content-Type: application/yaml" \
>   -d @example-fleet-config.yaml \
>   https://<CONTROLLER_IP>:9080/api/v1/stewards/<STEWARD_1_ID>/config
> ```

### Trigger distribution

After uploading, push the config to active stewards immediately:

```bash
curl \
  --cacert /tmp/admin-ca.crt \
  --cert /tmp/admin.crt \
  --key /tmp/admin.key \
  -X POST \
  -H "Content-Type: application/json" \
  -d '{"config_id": "fleet-config-v1", "version": "1", "tenant_id": "default"}' \
  https://<CONTROLLER_IP>:9080/api/v1/config/push
```

All three fields — `config_id`, `version`, and `tenant_id` — are required; the handler
returns `400 Bad Request` if any is absent. Use any descriptive string for `config_id`
and `version` (they appear in audit logs and push records).

Expected response (`202 Accepted`):

```json
{
  "push_id": "push-1716076800000000000",
  "status": "accepted",
  "queued_at": "2026-05-19T00:00:00Z"
}
```

> **[GAP: save=deploy auto-distribution not yet wired to ConfigStore — see issue #1525]**
> In the target architecture, saving a config to the controller automatically triggers
> distribution to matched stewards. Today, an explicit `POST /api/v1/config/push` is
> required after each config upload.

---

## Phase 7 — Verify Convergence

Steward convergence is heartbeat-driven. After receiving the config push, each steward
runs through its convergence loop: `Get → Compare → Set → Verify` for each resource.
The default `converge_interval` is `30m`; an explicit push triggers immediate convergence.

### On each steward VM

Watch the steward logs for convergence activity:

```bash
sudo journalctl -u cfgms-steward -f
```

Look for:

```
Convergence loop starting   operation=convergence_loop
Module converged            module=directory  resource=app-config-dir  status=ok
Module converged            module=file       resource=app-main-config  status=ok
Convergence loop complete   resources_converged=3  resources_skipped=0  resources_failed=0
```

Verify resources were actually applied on the steward VM:

```bash
# Directories created with correct ownership
ls -la /etc/myapp /var/lib/myapp /var/log/myapp

# Config file written with correct content
cat /etc/myapp/config.yaml
```

### Controller-side confirmation

> **[GAP: `cfg config deployments <id>` not yet implemented — see issue #1526]**
> This command will show applied/pending/failed counts and per-steward status.
> Until #1526 lands, observe convergence via steward logs (above) and the REST API.

Poll steward status to confirm `last_seen` advances with each heartbeat:

```bash
cfg steward status <STEWARD_1_ID>
```

A `last_seen` timestamp that advances every 30 minutes (the default convergence interval)
confirms the steward is connected and converging.

---

## Phase 8 — Drift Observation

Drift occurs when a resource on an endpoint moves out of the desired state — a file is
modified, a directory is removed, a package is uninstalled. CFGMS detects and corrects
this automatically on the next convergence cycle.

### Inducing drift

On `steward-1`, manually modify a resource that the fleet config manages:

```bash
# Modify the managed file out-of-band
sudo bash -c 'echo "# MANUAL EDIT — will be corrected by CFGMS" >> /etc/myapp/config.yaml'

# Or remove a managed directory
sudo rm -rf /etc/myapp
```

### Apply mode — automatic correction

All stewards run in `apply` mode by default. On the next convergence cycle (within
`converge_interval`, default `30m`) the steward detects the drift and corrects it:

```bash
sudo journalctl -u cfgms-steward -f
```

Look for:

```
Drift detected   module=file  resource=app-main-config  expected_hash=abc  actual_hash=xyz
Applying correction  module=file  resource=app-main-config
Module converged  module=file  resource=app-main-config  status=corrected
```

Verify the file was restored:

```bash
cat /etc/myapp/config.yaml
# Should show the desired state from the fleet config, not the manual edit
```

> **[GAP: apply/monitor mode toggle not yet implemented — see issue #1524]**
> The desired-state design includes a `drift_mode` field that switches a steward between
> `apply` (converge changes) and `monitor` (report drift without correcting it). Today
> the steward always applies changes when drift is detected regardless of any mode
> setting. The current `steward.mode` field in the cfg controls connectivity mode
> (`standalone` vs `controller`), not drift behavior.
>
> **[GAP: modules.Monitor() not implemented by any steward module — see issue #1590]**
> The `Monitor` interface in `features/modules/module.go` defines real-time
> change-detection for modules that support it. As of the #1511 audit, no steward module
> implements this interface. All modules use the polling-based convergence loop
> (`Get → Compare → Set`). Real-time drift notification via `Monitor()` is aspirational.

---

## Day-2 Operations

### Token rotation

Rotate registration tokens periodically (or immediately if a token is compromised):

```bash
# Revoke the old token (preserves audit trail)
cfg token revoke <OLD_TOKEN>

# Issue a new token
cfg token create \
  --tenant-id=default \
  --controller-url=<CONTROLLER_IP>:4433 \
  --group=production \
  --expires=7d
```

Existing stewards that already registered are not affected by token revocation — they
hold mTLS certificates issued at registration time. Revocation prevents new registrations
with that token.

### Steward decommission

On the endpoint being decommissioned:

```bash
# Stop and remove the service; --purge also removes the binary
sudo cfgms-steward uninstall --purge
```

The steward's registration record remains in the controller. There is no `DELETE /api/v1/stewards/{id}` endpoint today — steward record deletion is not yet implemented.

### Certificate renewal

Steward mTLS certificates are renewed automatically when they approach expiry — the
controller issues a new cert on the next heartbeat before the old one expires. No manual
intervention is needed for routine renewal.

Admin operator bundle certificates (in `admin.bundle.yaml`) are valid for 365 days. To
renew an admin bundle:

```bash
# Issue a new bundle for the operator
sudo cfgms-controller bootstrap-admin \
  --config /etc/cfgms/controller.cfg \
  --name alice \
  --output /etc/cfgms/alice-new.bundle.yaml

# Revoke the old cert after confirming the new bundle works
OLD_SERIAL=$(grep cert_serial /etc/cfgms/alice-old.bundle.yaml | awk '{print $2}')
sudo cfgms-controller bootstrap-admin \
  --config /etc/cfgms/controller.cfg \
  --revoke "$OLD_SERIAL"
```

See [Adding Operators](../single-controller/walkthrough.md#adding-operators) in the
single-controller walkthrough for the full procedure.

### Controller restart

Stewards reconnect automatically after a controller restart. Each steward re-registers
via HTTP on every startup — there is no stored-session resume. Expect a reconnection
delay of up to one minute while the controller starts and the steward's reconnection
backoff triggers.

To restart the controller:

```bash
sudo systemctl restart cfgms-controller
```

Monitor steward reconnection:

```bash
# On a steward VM
sudo journalctl -u cfgms-steward -f
# Look for: "Registration successful via HTTP" and "Connected to controller via gRPC transport"
```

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---------|-------------|-----|
| `cfg controller status` returns cert error | Bundle CA does not match controller CA | Re-copy `admin.bundle.yaml` from controller |
| Steward registration fails: `x509: certificate signed by unknown authority` | `CFGMS_HTTP_CA_CERT_PATH` not set or wrong path | Set env var to the controller's CA cert (`/var/lib/cfgms/certs/ca/ca.crt` on controller) |
| Steward registration fails: `token expired` or `token not found` | Token expired or already used | `cfg token create` to issue a new token |
| Steward registration fails: `controller URL not set` | Binary not built with `STEWARD_CONTROLLER_URL` | `make build-steward STEWARD_CONTROLLER_URL=https://<IP>:9080` |
| `Connected Stewards: 0` in controller metrics | Stewards registered but not connecting on 4433/UDP | Check firewall — port 4433 must be open for UDP |
| `curl` REST API call returns `401` | No valid auth credentials | Extract cert/key from admin bundle; see Phase 5 |
| Convergence not running | Steward is in standalone mode (no regtoken path) | Verify service is using `--regtoken` not `--config` |
| Config not applied after push | `converge_interval` delay | Wait up to 30m, or check push was accepted (202) |
| `cfgms-steward status` shows `not installed` | install subcommand not run as root | Re-run `sudo cfgms-steward install --regtoken <token>` |

### Diagnostic commands

```bash
# Controller health
cfg controller status --url=https://<CONTROLLER_IP>:9080

# Controller transport metrics (shows connected steward count)
cfg controller metrics --url=https://<CONTROLLER_IP>:9080

# Controller logs
sudo journalctl -u cfgms-controller -n 50 --no-pager

# Steward logs (on steward VM)
sudo journalctl -u cfgms-steward -n 50 --no-pager

# Steward service state
cfgms-steward status

# Active tokens
cfg token list --tenant-id=default
```

---

## Known Gaps

The table below collects all `[GAP: ...]` markers from this walkthrough for easy reference:

| Gap | Issue | Phase affected |
|-----|-------|----------------|
| `cfg config deployments <id>` not implemented | [#1526](https://github.com/cfg-is/cfgms/issues/1526) | Phase 7 |
| save=deploy auto-distribution not wired | [#1525](https://github.com/cfg-is/cfgms/issues/1525) | Phase 6 |
| apply/monitor mode toggle not implemented | [#1524](https://github.com/cfg-is/cfgms/issues/1524) | Phase 8 |
| `modules.Monitor()` not implemented by any module | [#1590](https://github.com/cfg-is/cfgms/issues/1590) | Phase 8 |
| Multi-controller / failover not supported | [#1517](https://github.com/cfg-is/cfgms/issues/1517) | Phase 4 |

---

## Next Steps

- **Role configs**: See [Role Config Recipes](../../examples/role-configs/README.md) for
  ready-to-use fleet configs for web servers, database servers, domain controllers, and more.
- **Docker fleet test**: Epic #1501 will validate this walkthrough against a docker-based
  fleet on every PR.
- **Controller cluster**: When you need high availability, see
  [Controller Cluster](../controller-cluster/walkthrough.md) *(planned)*.
