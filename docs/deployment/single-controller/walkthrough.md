# Single Controller Deployment

Deploy one CFGMS controller and set up the controller-steward to keep the node in the desired state.

**Time**: ~30 minutes (first-time setup)

**What you'll have when done**:
- A running controller accepting steward connections
- A controller-steward managing the controller node (directories, firewall, systemd service)
- Validated end-to-end connectivity

## Architecture

```
┌─────────────────────────────────────────────┐
│          Controller Node (Linux)            │
│                                             │
│  ┌───────────────────────────────────────┐  │
│  │  Controller                           │  │
│  │                                       │  │
│  │  REST API (HTTPS)       :9080/TCP     │  │
│  │  Metrics (HTTPS) :9090/TCP (loopback) │  │
│  │  gRPC-over-QUIC (mTLS) :4433/UDP     │  │
│  │  Auto-generated CA + certificates     │  │
│  │  Flatfile+SQLite config storage       │  │
│  └───────────────────────────────────────┘  │
│                                             │
│  ┌───────────────────────────────────────┐  │
│  │  Controller-Steward                   │  │
│  │                                       │  │
│  │  Manages: directories, packages,      │  │
│  │  firewall rules, systemd service,     │  │
│  │  controller.cfg                       │  │
│  │  Convergence loop: 30 min             │  │
│  └───────────────────────────────────────┘  │
└─────────────────────────────────────────────┘
```

## Prerequisites

- **Linux VM**: Debian/Ubuntu (recommended) or RHEL/CentOS
- **Go toolchain**: see `go.mod` for the required version (on the build machine,
  can be the controller VM)
- **Git**: installed on the controller VM
- **Network**: Ports 9080/TCP and 4433/UDP available on the controller. Port
  9090/TCP is reserved for host-local metrics and must not be opened publicly.

## Step 1: Build Binaries

On your build machine (can be the controller VM):

```bash
git clone https://github.com/cfg-is/cfgms.git
cd cfgms
make build
```

This produces `bin/controller`, `bin/cfgms-steward`, and `bin/cfg`.

> **Controller URL**: `make build` bakes `localhost:9080` into the steward binary — the
> correct default for the controller-steward running on the same node. For remote stewards
> deployed to other machines, you can either rebuild with
> `make build-steward STEWARD_CONTROLLER_URL=https://<IP>:9080` (compile-baked trust) or
> pass `--controller-url https://<IP>:9080 --controller-ca ca.crt` to `install.sh` at
> install time (install-pinned trust, ADR-013 §3). Both are equally secure for a single
> self-hosted controller.

## Step 2: Deploy the Controller

Copy the controller binary to the controller VM:

```bash
sudo cp bin/controller /usr/local/bin/cfgms-controller
sudo chmod +x /usr/local/bin/cfgms-controller
```

### Create directories

```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin cfgms 2>/dev/null || \
  test "$(id -u cfgms)" -ge 0
sudo mkdir -p /etc/cfgms /var/lib/cfgms/storage /var/lib/cfgms/certs/ca /var/log/cfgms
sudo chown cfgms:cfgms /etc/cfgms
sudo chown -R cfgms:cfgms /var/lib/cfgms /var/log/cfgms
sudo chmod 0750 /etc/cfgms /var/lib/cfgms /var/log/cfgms

# Generate the external secret-encryption key and seal it to this host's TPM2 in
# a single pipeline. The plaintext key exists only inside the pipe: it is never
# written to a file, so there is no cleartext key on disk and nothing to shred.
sudo sh -c 'umask 077; openssl rand 32 | systemd-creds encrypt \
  --name=cfgms-secrets-key --with-key=tpm2 - /etc/cfgms/secrets.key.cred'
sudo chmod 0400 /etc/cfgms/secrets.key.cred
```

Check the host has a usable TPM2 first with `systemd-analyze has-tpm2`. If it does
not, and you accept the consequence, substitute `--with-key=host`: the key is then
sealed to `/var/lib/systemd/credential.secret` on this host's own disk, so a stolen
disk image or VM snapshot yields the plaintext. Do **not** use `--with-key=auto` —
it silently falls back to the host key when no TPM2 is present, leaving nothing on
the resulting system to distinguish a TPM-bound host from a disk-bound one.

`scripts/tier1-bootstrap.sh` performs all of this (including the TPM2 check and the
`--allow-host-key` opt-in) if you would rather not do it by hand. See
[ADR-030](../../architecture/decisions/030-controller-secret-material-at-rest.md).

### Copy and configure controller.cfg

Copy [controller.cfg](../controller.cfg) to `/etc/cfgms/controller.cfg`:

```bash
sudo cp docs/deployment/controller.cfg /etc/cfgms/controller.cfg
sudo chown root:cfgms /etc/cfgms/controller.cfg
sudo chmod 0640 /etc/cfgms/controller.cfg
```

Open `/etc/cfgms/controller.cfg` in your editor and verify the following variables:

| Variable | Location in file | What to set it to |
|----------|-----------------|-------------------|
| `common_name` | `certificate.server` | Your controller's hostname or IP (e.g. `ctrl.mylab.local`) |
| `dns_names` | `certificate.server` | All hostnames/domains the controller is reachable at |
| `ip_addresses` | `certificate.server` | All IPs the controller is reachable at (include `127.0.0.1`) |
| `organization` | `certificate.server` | Your organization name |
| `listen_addr` | `transport` | Transport bind address and port (default `0.0.0.0:4433`) |
| `metrics_listen_addr` | top level | Keep `127.0.0.1:9090`; startup rejects missing or non-private values |

The REST API listens on port 9080 by default. To change it, set `CFGMS_HTTP_LISTEN_ADDR` in the systemd unit's `Environment=` directive.
The metrics API is not registered on that product listener. Query
`https://localhost:9090/api/v1/monitoring/metrics` locally with a key carrying
`monitoring:read-metrics`.

### Browser passkey login (optional)

Browser-based passkey login and passkey step-up (the "My Passkeys" UI, presence-gated
actions) require a `webauthn:` block in `controller.cfg`. There is no default: without
it, the passkey endpoints answer `503 WEBAUTHN_NOT_CONFIGURED` and the mTLS admin
bundle remains the only login path — which is a valid, supported deployment shape.

```yaml
webauthn:
  rp_id: ctrl.mylab.local            # the controller's effective domain — no scheme, no port
  rp_display_name: "CFGMS Controller" # shown by the authenticator/browser prompt
  rp_origins:
    - "https://ctrl.mylab.local"      # every fully qualified origin admins log in from
```

`rp_id` must be the domain in the URL admins use to reach the controller's REST API —
not an IP address, and not `localhost` unless the controller is genuinely only ever
reached at `https://localhost`. Every entry in `rp_origins` must be `https://`; startup
refuses the config otherwise. Setting `rp_id` without `rp_origins` (or the reverse) is
also a startup error. There is no local-development exception — WebAuthn requires a
real TLS certificate the browser trusts (a certificate from this controller's own CA,
imported into the browser's trust store, is sufficient; a self-signed cert the browser
warns about is not enough because a WebAuthn ceremony refuses to run past a certificate
error).



### Install the systemd service

Copy [cfgms-controller.service](cfgms-controller.service) to `/etc/systemd/system/`:

```bash
sudo cp cfgms-controller.service /etc/systemd/system/cfgms-controller.service
sudo systemctl daemon-reload
```

### Initialize the controller

This is a one-time operation that creates the CA, server certificates, storage backend, and admin credential bundle:

`--init` runs outside systemd, so it has no credential directory of its own.
Unseal the key into a directory on tmpfs for the duration of the run and remove it
afterwards — `/run` is tmpfs on a systemd host, whereas `/tmp` is a directory on
the root filesystem on Debian and Ubuntu, and `shred` cannot reliably undo a write
there:

```bash
sudo sh -c '
  set -e
  test "$(findmnt -no FSTYPE --target /run)" = tmpfs
  d=$(mktemp -d /run/cfgms-init-creds-XXXXXX)
  trap "rm -rf $d" EXIT
  systemd-creds decrypt --name=cfgms-secrets-key /etc/cfgms/secrets.key.cred "$d/key"
  chown -R cfgms:cfgms "$d"
  runuser --user cfgms -- env CFGMS_SECRETS_KEY_FILE="$d/key" \
    cfgms-controller --init --config /etc/cfgms/controller.cfg
'
```

You should see:

```
Controller initialization complete:
  CA Fingerprint:    SHA256:xxxx...
  Storage Provider:  flatfile
  Initialized At:    2026-05-19T00:00:00Z

The controller is now ready to start with: cfgms-controller --config <path>
```

Save the CA fingerprint — stewards verify it during registration. Detailed initialization
logs (CA creation, storage setup, RBAC, bundle issuance) are written to
`/var/log/cfgms/cfgms.log`.

Losing the secret-encryption key makes stored secrets unrecoverable; exposing it
compromises every secret encrypted with it. The systemd unit unseals it into the
service credential directory at runtime and makes the sealed source path
inaccessible inside the service sandbox.

**Backing it up needs care, because the sealed blob is host-bound.**
`/etc/cfgms/secrets.key.cred` can only be decrypted by the TPM2 (or host key) of
the machine that sealed it, so copying that file elsewhere protects you against
losing the file — not against losing the machine. If the host is rebuilt, its TPM
is reset, or its vTPM is removed, the blob is permanently unreadable and so is
every secret encrypted under the key.

For a recoverable backup, export the key while it is unsealed and store it under
encryption and access controls at least as strong as the admin credential bundle
— an offline password manager or an operator keychain, never an unencrypted file
alongside `/var/lib/cfgms`:

```bash
sudo systemd-creds decrypt --name=cfgms-secrets-key /etc/cfgms/secrets.key.cred - | base64
```

To restore onto a rebuilt host, seal the saved value again on that host:

```bash
sudo sh -c 'printf %s "<base64 from backup>" | base64 -d | systemd-creds encrypt \
  --name=cfgms-secrets-key --with-key=tpm2 - /etc/cfgms/secrets.key.cred'
```

### Admin credential bundle

`--init` writes an admin credential bundle to `/etc/cfgms/admin.bundle.yaml` (mode `0600`, owned by the `cfgms` daemon user). This is the one-time bootstrap exception: a fresh controller has no account yet for anyone to log in against, so `controller --init` generates this certificate's keypair itself and hands you both halves. Every credential after this first one should come from the ordinary path, `cfg login`, described in the [cfg Operator Guide](../cfg-operator-guide.md) — not from another bundle. The bundle contains:

- The admin mTLS client certificate and private key
- The CA certificate for server verification
- The controller URL
- The cert serial number and fingerprint (for revocation lookup)

**Protect this file.** It grants full admin access to the controller REST API. Treat it like a root SSH key.

| Platform | Default path |
|----------|-------------|
| Linux    | `/etc/cfgms/admin.bundle.yaml` |
| Windows  | `%ProgramData%\cfgms\admin.bundle.yaml` |

An idempotency marker is written alongside the bundle at `/etc/cfgms/.admin-bundle-issued`. If `--init` is re-run and the bundle file already exists, issuance is skipped and the existing bundle is preserved.

### Bundle recovery

If the bundle file is accidentally deleted after a successful `--init`, the controller detects this on the next `--init` run and refuses to start:

```
controller is initialized (CA fingerprint: <fp>) but admin bundle is missing at /etc/cfgms/admin.bundle.yaml.
To regenerate the bundle, run: cfgms-controller bootstrap-admin --regenerate
```

Run `cfgms-controller bootstrap-admin --regenerate` to re-issue the admin bundle without reinitializing the CA or storage.

### Start the controller

```bash
sudo systemctl enable cfgms-controller
sudo systemctl start cfgms-controller
```

### Validate

```bash
# Service is running
sudo systemctl status cfgms-controller

# REST API responds with CA and hostname verification
curl --fail --cacert /var/lib/cfgms/certs/ca/ca.crt \
  https://localhost:9080/api/v1/health

test "$(curl --silent --output /dev/null --write-out '%{http_code}' \
  --cacert /var/lib/cfgms/certs/ca/ca.crt \
  -H "X-API-Key: ${CFGMS_MONITORING_API_KEY}" \
  https://localhost:9080/api/v1/monitoring/metrics)" = 404

curl --fail --cacert /var/lib/cfgms/certs/ca/ca.crt \
  -H "X-API-Key: ${CFGMS_MONITORING_API_KEY}" \
  https://localhost:9090/api/v1/monitoring/metrics

# Review the effective sandbox (resolve any warning before Internet exposure)
sudo systemd-analyze security cfgms-controller.service

# Logs show clean startup
sudo journalctl -u cfgms-controller --no-pager -n 20
```

Look for: `Certificate manager initialized`, `Transport server listening on :4433`, `REST API server listening on :9080`.

### Startup Warnings

On each startup the controller scans all stored API keys for permissions that overlap the Tier-3 (mTLS-only) endpoint surface. If any key holds such a permission, it cannot be used to reach those endpoints — the tier gate blocks it regardless of what permissions the key carries. The controller logs a warning at `WARN` level for each affected key:

```
WARN  API key holds permissions that overlap Tier-3 (mTLS-only) endpoints;
      these are now unreachable via API key — consider revoking this key
      key_id=<id>  tenant_id=<tenant>  overlapping_permissions=<perm1,perm2,...>
```

**Remediation:**

1. Identify the key from the `key_id` field in the warning.
2. Decide whether the key needs those permissions. If not, revoke it and issue a replacement with only the permissions it actually requires:

   ```bash
   # Revoke the over-privileged key
   cfg api-keys delete --id <key_id>

   # Issue a replacement with only the permissions the caller needs
   cfg api-keys create --name <name> --permissions <perm1,perm2,...>
   ```

3. If the key legitimately needs to call a Tier-3 operation, the caller must use an mTLS admin credential bundle instead. Issue a bundle with `cfgms-controller bootstrap-admin` and update the caller to use it.

These warnings do not prevent the controller from starting or serving requests. They are informational alerts that help operators identify over-privileged keys before a Tier-3 call fails at runtime.

## Step 3: Deploy the Controller-Steward

The controller-steward is the first steward in your environment. It manages the controller node itself — directories, packages, firewall rules, systemd service, and the controller config file. If anything drifts from the desired state, the steward converges it back.

### Copy the steward binary

```bash
sudo cp bin/cfgms-steward /usr/local/bin/cfgms-steward
sudo chmod +x /usr/local/bin/cfgms-steward
```

### Copy and configure controller-steward.cfg

Copy [controller-steward.cfg](controller-steward.cfg) to `/etc/cfgms/controller-steward.cfg`:

```bash
sudo cp controller-steward.cfg /etc/cfgms/controller-steward.cfg
```

Open `/etc/cfgms/controller-steward.cfg` in your editor and verify the following variables. These **must match** the values you set in `controller.cfg`:

| Variable | Where it appears | What to set it to |
|----------|-----------------|-------------------|
| `common_name` | `resources → controller-config → content` | Same hostname/IP as controller.cfg |
| `dns_names` | `resources → controller-config → content` | Same hostnames as controller.cfg |
| `ip_addresses` | `resources → controller-config → content` | Same IPs as controller.cfg |
| `organization` | `resources → controller-config → content` | Same org as controller.cfg |
| `port: 9080` | `resources → controller-rest-port` | Must match REST API port (default 9080) |
| `port: 4433` | `resources → controller-transport-port` | Must match `transport.listen_addr` port in controller.cfg |

### Run the controller-steward

```bash
sudo cfgms-steward --config /etc/cfgms/controller-steward.cfg
```

The steward converges the node:
- Verifies all directories exist with correct permissions
- Installs `git` if missing
- Writes `/etc/cfgms/controller.cfg` (matching your configuration)
- Opens firewall ports 9080/TCP and 4433/UDP
- Installs the systemd unit file
- Starts the controller service (if initialized)

### Validate

```bash
# Firewall rules are in place
sudo ufw status | grep -E "9080|4433"
# or: sudo iptables -L -n | grep -E "9080|4433"

# Controller is still running after steward convergence
sudo systemctl status cfgms-controller

# Health check still responds with certificate verification
curl --fail --cacert /var/lib/cfgms/certs/ca/ca.crt \
  https://localhost:9080/api/v1/health
```

## Step 4: Validate End-to-End

Run through this checklist to confirm the deployment is working:

- [ ] **Controller service**: `sudo systemctl status cfgms-controller` shows `active (running)`
- [ ] **REST API**: `curl --fail --cacert /var/lib/cfgms/certs/ca/ca.crt https://localhost:9080/api/v1/health` returns a healthy response
- [ ] **Service sandbox**: `sudo systemd-analyze security cfgms-controller.service` shows the shipped restrictions are active
- [ ] **Transport**: logs show `Transport server listening on :4433`
- [ ] **Certificates**: `sudo journalctl -u cfgms-controller | grep "Certificate manager initialized"`
- [ ] **Firewall**: ports 9080/TCP and 4433/UDP are open
- [ ] **Controller restart recovery**: `sudo systemctl restart cfgms-controller` — service comes back cleanly
- [ ] **Steward re-convergence**: run `sudo cfgms-steward --config /etc/cfgms/controller-steward.cfg` again — no errors, no unexpected changes

## Troubleshooting

### Controller won't start

```bash
sudo journalctl -u cfgms-controller -n 50
```

| Symptom | Cause | Fix |
|---------|-------|-----|
| `bind: address already in use` | Another process on port 9080 or 4433 | `ss -tlnp \| grep 9080` to find it |
| `permission denied` | Data directories not writable | `ls -la /var/lib/cfgms /var/log/cfgms` |
| Certificate errors | Certificate hostname/SAN or CA trust mismatch | Correct `certificate.server` SANs and the client `--cacert` path; do not bypass verification |

### Controller-steward reports errors

```bash
# Check steward output for specific module failures
sudo cfgms-steward --config /etc/cfgms/controller-steward.cfg 2>&1 | grep -i error
```

| Symptom | Cause | Fix |
|---------|-------|-----|
| `Controller not yet initialized` | Normal on first run before `--init` | Run `sudo cfgms-controller --init` first |
| Package install fails | No internet or package manager issue | `sudo apt update` and retry |
| Firewall module fails | `ufw` or `iptables` not available | Install your distro's firewall tooling |

## Adding Operators

The ordinary way for a team member to obtain a credential is `cfg login` — a
browser passkey assertion that mints a session token, never a file containing a
private key. Issuing another bundle with `bootstrap-admin` is the bootstrap
exception, not the routine way to add an operator: every bundle the controller
issues is a credential whose private key the controller itself generated and
held. It cannot approve a credential enrolment or renew itself, and is
*intended* also to be unable to authorise code execution on a managed endpoint
(see
[ADR-021 Amendment 5](../../architecture/decisions/021-identity-assurance-levels.md));
read the second gap note below before relying on that last part.

> **[GAP: `cfg login` is not yet shipped — see Epic #3711, Story #3721. Until it
> lands, this is the only way to issue additional operator credentials.]**

> **[GAP: the bundle's confinement against endpoint code execution is not yet
> enforced — see Epic #3711, Story #3696. Signer verification on both the steward
> (`features/steward/commands/execute_script.go`) and the controller
> (`features/controller/api/handlers_runs.go`) accepts any admin-marked
> certificate and does not require the payload-signing marker, so any bundle you
> issue here **can** today authorise code execution on managed endpoints.]**

```bash
sudo cfgms-controller bootstrap-admin \
  --config /etc/cfgms/controller.cfg \
  --name alice \
  --output /etc/cfgms/alice.bundle.yaml
```

Copy `alice.bundle.yaml` to the operator securely (treat it like a root SSH key). The
bundle contains the mTLS client certificate and key, the CA certificate, and the
controller URL.

**Name rules:** Alphanumeric characters and hyphens only, max 64 characters. Names must
not begin or end with a hyphen. The following names are reserved and will be rejected:
`system`, `cfgms`, `cfgms-internal`, `cfgms-admin`, and any UUID-format string (reserved
for steward certificates).

**Validity:** Admin certificates are valid for 365 days. When a bundle expires, issue a
new one and revoke the old serial.

### Listing bundles

```bash
cfgms-controller bootstrap-admin --config /etc/cfgms/controller.cfg --list
```

This shows all issued admin certs with their serial numbers and revocation status.

## Revoking Access

When an operator leaves, a machine is decommissioned, or a bundle is compromised,
revoke the cert immediately using the serial number printed at issuance time (also
stored in the bundle file under `cert_serial`).

```bash
cfgms-controller bootstrap-admin \
  --config /etc/cfgms/controller.cfg \
  --revoke <serial>
```

The revocation takes effect immediately — the serial is added to the persistent
revoked-serials list and all subsequent authentication attempts with that cert are
rejected with `CERT_REVOKED`.

**After regenerating the system bundle**, also revoke the old serial:

```bash
# Step 1: note the old serial from the current bundle
OLD_SERIAL=$(grep cert_serial /etc/cfgms/admin.bundle.yaml | awk '{print $2}')

# Step 2: regenerate (follow the interactive confirmation)
sudo cfgms-controller bootstrap-admin --config /etc/cfgms/controller.cfg --regenerate

# Step 3: revoke the old bundle
sudo cfgms-controller bootstrap-admin \
  --config /etc/cfgms/controller.cfg \
  --revoke "$OLD_SERIAL"
```

## Next Steps

- **Register a browser passkey**: `cfg webauthn register` cannot complete a browser
  ceremony from the CLI (a loopback-served ceremony can never satisfy a configured
  relying party — see [ADR-021 Amendment
  4](../../architecture/decisions/021-identity-assurance-levels.md#amendment-4-2026-08-28-relying-party-is-configuration-has-no-default-and-wiring-it-exposed-a-cli-relay-regression)).
  Instead, run `cfg account create --username <admin-username>` to mint a single-use
  enrollment magic link, then open that link in a browser to register the first passkey
  for browser-based controller login (ADR-021 Amendment 1 self-enrollment). The admin
  mTLS certificate (from `bootstrap-admin`) remains your CLI credential either way.
- **Connect stewards**: Create a registration token and deploy stewards to your endpoints.
- **Configure server roles**: See [Role Config Recipes](../../examples/role-configs/README.md) for ready-to-use configs for domain controllers, file servers, SQL servers, web servers, and more.
- **Scale up**: When you're ready for geo-redundant deployment, see [Controller Cluster](../controller-cluster/walkthrough.md).
