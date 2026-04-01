# Controller Bootstrap with Steward

Production deployment guide for CFGMS controller nodes managed by stewards.

## When to use this guide

Use this guide when you are deploying controller nodes as part of a managed fleet — multiple controllers, automated provisioning, or infrastructure managed by CFGMS itself.

For quick-start and development deployments, the controller is self-sufficient: see the [Home Lab Deployment Guide](home-lab-deployment-guide.md) or [QUICK_START.md](../../QUICK_START.md). The controller creates its own directories, certificates, and storage on first run — no steward required.

## Architecture

```
┌──────────────────────────────────────────────┐
│           Controller Node (Linux)            │
│                                              │
│  ┌────────────────────────────────────────┐  │
│  │  Steward (standalone → connected)      │  │
│  │                                        │  │
│  │  Manages: directories, packages,       │  │
│  │  firewall, systemd, config files       │  │
│  │  Mode: convergence loop (30 min)       │  │
│  └────────────────────────────────────────┘  │
│                                              │
│  ┌────────────────────────────────────────┐  │
│  │  Controller                            │  │
│  │                                        │  │
│  │  Manages: fleet orchestration, RBAC,   │  │
│  │  config distribution, workflows,       │  │
│  │  CA + certificates, storage            │  │
│  │  Listens: :8080 (REST), :4433 (gRPC)   │  │
│  └────────────────────────────────────────┘  │
└──────────────────────────────────────────────┘
```

**Steward manages the node.** Directories, packages, firewall rules, systemd services, and the controller config file. If the node drifts (package removed, firewall rule dropped, service stopped), the steward converges it back.

**Controller manages the fleet.** CA and certificates, RBAC, config distribution, workflow engine, storage. The controller is an application running on a steward-managed node.

## Prerequisites

- Vanilla Linux VM (Debian/Ubuntu, RHEL/CentOS, or similar)
- `cfgms-steward` and `cfgms-controller` binaries (built or downloaded)
- Network: ports 8080/TCP and 4433/UDP accessible to stewards

## Bootstrap Sequence

### Phase 1: Steward prepares the node

Place the steward binary and the controller-node config on the machine:

```bash
# Copy binaries
sudo cp cfgms-steward /usr/local/bin/cfgms-steward
sudo cp cfgms-controller /usr/local/bin/cfgms-controller
sudo chmod +x /usr/local/bin/cfgms-steward /usr/local/bin/cfgms-controller

# Copy the example config (customize for your environment first)
sudo mkdir -p /etc/cfgms
sudo cp controller-node.cfg /etc/cfgms/controller-node.cfg
```

Before running, edit `/etc/cfgms/controller-node.cfg` and replace `controller.example.com` with your controller's actual hostname or IP address. See [docs/examples/controller-node.cfg](../examples/controller-node.cfg) for the full example.

Run the steward in standalone mode:

```bash
sudo cfgms-steward --config /etc/cfgms/controller-node.cfg
```

The steward converges the node:
- Creates `/etc/cfgms/`, `/var/lib/cfgms/`, `/var/log/cfgms/`, cert directories
- Installs `git` package
- Writes `/etc/cfgms/controller.cfg` with your configuration
- Opens firewall ports 8080/TCP and 4433/UDP
- Writes the systemd unit file for `cfgms-controller`
- Checks for initialization marker — prints instructions if not yet initialized

### Phase 2: Initialize the controller

This is a one-time operation that creates the CA, certificates, RBAC defaults, and initialization marker:

```bash
sudo cfgms-controller --init --config /etc/cfgms/controller.cfg
```

You should see:
```
Initializing storage backend... provider=git
Storage backend initialized
Creating Certificate Authority... ca_path=/var/lib/cfgms/certs/ca
Certificate Authority created
RBAC store initialized
Controller initialized successfully
  CA fingerprint: SHA256:xxxx...
```

Save the CA fingerprint — stewards will verify it during registration.

### Phase 3: Start the controller service

Run the steward again to start the controller (it detects the init marker):

```bash
sudo cfgms-steward --config /etc/cfgms/controller-node.cfg
```

This time the script resource finds `.cfgms-initialized` and enables/starts the systemd service.

Verify:

```bash
sudo systemctl status cfgms-controller
curl -k https://localhost:8080/health
```

### Phase 4: Switch steward to controller-connected mode (optional)

Once the controller is running, the steward can register with it and receive configuration updates from the controller instead of the local file:

```bash
# Create a registration token
cfg token create --tenant-id=infrastructure --expires=30d

# Re-install the steward in connected mode
sudo cfgms-steward install --regtoken <TOKEN>
```

The steward now connects to its own controller for config updates. The controller manages the steward's cfg going forward, including the controller node's own infrastructure.

## Scaling: Adding Controller Nodes

In a multi-node deployment, the pattern is:

1. **Controller** decides a new node is needed (scaling policy, workflow trigger)
2. **Controller** provisions the VM via workflow engine (cloud API, Hyper-V, etc.)
3. **Controller** generates a registration token for the new node
4. **Steward** on the new node runs standalone with `controller-node.cfg` (Phase 1)
5. **Operator or automation** runs `cfgms-controller --init` (Phase 2)
6. **Steward** starts the controller service (Phase 3)
7. **New controller** joins the cluster

The steward on existing controller nodes has no role in provisioning — that's the controller's job (orchestration). Each steward only manages its own node.

## Ongoing Node Management

With the steward running in connected mode (Phase 4), node management is automatic:

- **Drift detection**: If a firewall rule is removed or a package uninstalled, the steward's convergence loop restores the desired state
- **Config updates**: Push updated controller configuration from the controller to the steward — the steward writes the new `controller.cfg` and restarts the service
- **Independent failure**: If the controller process crashes, the steward keeps the node healthy (directories, firewall, packages) and restarts the service via systemd

## Troubleshooting

### Steward says "Controller not yet initialized"

This is expected on first run. Run `cfgms-controller --init` (Phase 2), then run the steward again.

### Controller fails to start after init

Check the systemd journal:

```bash
sudo journalctl -u cfgms-controller -n 50
```

Common issues:
- Port already in use: another process on 8080 or 4433
- Certificate path permissions: CA directory should be 0700
- Storage directory not writable

### Steward can't connect in Phase 4

The steward connects to the controller URL compiled into the binary. Ensure the binary was built with the correct `-ldflags "-X main.ControllerURL=..."` pointing to this controller.
