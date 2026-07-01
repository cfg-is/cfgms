# Rolling Cluster Upgrade Runbook

How to perform a zero-downtime rolling upgrade of a CFGMS controller cluster.

## Overview

A rolling cluster upgrade replaces controller nodes one at a time, ensuring the
cluster remains available throughout. Each node is drained before its binary is
replaced, then re-joined once the upgraded binary is healthy.

## Prerequisites

- Admin mTLS bundle (`~/.config/cfgms/admin.bundle.yaml` or `--bundle <path>`)
- Cluster has at least two nodes (single-node clusters cannot drain without downtime)
- All nodes healthy before starting

## Procedure

### 1. Identify the node to upgrade

```bash
# List cluster nodes and their current states (available in a future story)
cfg controller cluster status --url=https://controller.example.com
```

### 2. Drain the node

Draining prevents the node from accepting new work while allowing in-flight
requests to complete.

```bash
cfg controller cluster drain <node-id> \
    --url=https://controller.example.com
```

Wait for the drain to complete. The command prints the resulting node state:

```
Node <node-id> is now draining.
```

### 3. Upgrade the binary on the drained node

SSH to the node and run the upgrade (see `controller-upgrade.md` for the full
single-node upgrade runbook):

```bash
cfg controller upgrade run \
    --binary /opt/cfgms/cfgms-controller-v0.6.0 \
    --config /etc/cfgms/controller.cfg
```

### 4. Decommission the old node entry

After the upgraded node has rejoined the cluster under a new node ID, remove
the old node entry:

```bash
cfg controller cluster decommission <node-id> \
    --url=https://controller.example.com
```

The node must be in `draining` state. If it is not, the command returns HTTP 409
and an error message. The command prints the resulting state on success:

```
Node <node-id> is now decommissioned.
```

### 5. Repeat for each remaining node

Repeat steps 2–4 for each remaining node, one at a time.

## Error handling

| Exit condition | Message | Action |
|---|---|---|
| Node not in draining state | Error from HTTP 409 response | Wait for drain or check node state |
| Not authenticated with admin mTLS | `Error: admin mTLS certificate required` | Ensure admin bundle is present |
| API unreachable | Connection error | Check controller URL and network |

## Authentication

Both `drain` and `decommission` require the admin mTLS bundle. The `--bundle`
flag or `CFGMS_ADMIN_BUNDLE` environment variable selects the bundle file.
The bundle is auto-discovered at `~/.config/cfgms/admin.bundle.yaml` and
`/etc/cfgms/admin.bundle.yaml` when neither flag nor env var is set.
