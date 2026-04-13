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
│  │  gRPC-over-QUIC (mTLS) :4433/UDP     │  │
│  │  Auto-generated CA + certificates     │  │
│  │  Git+SOPS config storage              │  │
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
- **Go toolchain**: v1.25+ (on the build machine, can be the controller VM)
- **Git**: installed on the controller VM
- **Network**: Ports 9080/TCP and 4433/UDP available on the controller

## Step 1: Build Binaries

On your build machine (can be the controller VM):

```bash
git clone https://github.com/cfg-is/cfgms.git
cd cfgms
make build
```

This produces `bin/controller`, `bin/cfgms-steward`, and `bin/cfg`.

## Step 2: Deploy the Controller

Copy the controller binary to the controller VM:

```bash
sudo cp bin/controller /usr/local/bin/cfgms-controller
sudo chmod +x /usr/local/bin/cfgms-controller
```

### Create directories

```bash
sudo mkdir -p /etc/cfgms /var/lib/cfgms/storage /var/lib/cfgms/certs/ca /var/log/cfgms
```

### Copy and configure controller.cfg

Copy [controller.cfg](controller.cfg) to `/etc/cfgms/controller.cfg`:

```bash
sudo cp controller.cfg /etc/cfgms/controller.cfg
```

Open `/etc/cfgms/controller.cfg` in your editor and verify the following variables:

| Variable | Location in file | What to set it to |
|----------|-----------------|-------------------|
| `common_name` | `certificate.server` | Your controller's hostname or IP (e.g. `ctrl.mylab.local`) |
| `dns_names` | `certificate.server` | All hostnames/domains the controller is reachable at |
| `ip_addresses` | `certificate.server` | All IPs the controller is reachable at (include `127.0.0.1`) |
| `organization` | `certificate.server` | Your organization name |
| `listen_addr` | `transport` | Transport bind address and port (default `0.0.0.0:4433`) |

The REST API listens on port 9080 by default. To change it, set `CFGMS_HTTP_LISTEN_ADDR` in the systemd unit's `Environment=` directive.

### Install the systemd service

Copy [cfgms-controller.service](cfgms-controller.service) to `/etc/systemd/system/`:

```bash
sudo cp cfgms-controller.service /etc/systemd/system/cfgms-controller.service
sudo systemctl daemon-reload
```

### Initialize the controller

This is a one-time operation that creates the CA, server certificates, and storage backend:

```bash
sudo cfgms-controller --init --config /etc/cfgms/controller.cfg
```

You should see:

```
Initializing storage backend... provider=git
Storage backend initialized
Creating Certificate Authority... ca_path=/var/lib/cfgms/certs/ca
Certificate Authority created
Controller initialized successfully
  CA fingerprint: SHA256:xxxx...
```

Save the CA fingerprint — stewards verify it during registration.

### Start the controller

```bash
sudo systemctl enable cfgms-controller
sudo systemctl start cfgms-controller
```

### Validate

```bash
# Service is running
sudo systemctl status cfgms-controller

# REST API responds
curl -k https://localhost:9080/api/v1/health

# Logs show clean startup
sudo journalctl -u cfgms-controller --no-pager -n 20
```

Look for: `Certificate manager initialized`, `Transport server listening on :4433`, `REST API server listening on :9080`.

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

# Health check still responds
curl -k https://localhost:9080/api/v1/health
```

## Step 4: Validate End-to-End

Run through this checklist to confirm the deployment is working:

- [ ] **Controller service**: `sudo systemctl status cfgms-controller` shows `active (running)`
- [ ] **REST API**: `curl -k https://localhost:9080/api/v1/health` returns a healthy response
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
| Certificate errors | CA not initialized or corrupt | `sudo rm -rf /var/lib/cfgms/certs && sudo cfgms-controller --init --config /etc/cfgms/controller.cfg` |

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

## Next Steps

- **Connect stewards**: Create a registration token and deploy stewards to your endpoints.
- **Configure server roles**: See [Steward Examples](../steward-examples/README.md) for ready-to-use configs for domain controllers, file servers, SQL servers, web servers, and more.
- **Scale up**: When you're ready for geo-redundant deployment, see [Controller Cluster](../controller-cluster/walkthrough.md).
