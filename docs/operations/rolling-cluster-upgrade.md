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

### 3. Verify the load balancer health gate

After drain, confirm `GET /api/v1/health` on the draining node returns HTTP 503.
Poll the node directly (not through the load balancer):

```bash
curl -o /dev/null -w "%{http_code}\n" \
    --cert ~/.config/cfgms/admin.crt \
    --key ~/.config/cfgms/admin.key \
    --cacert ~/.config/cfgms/ca.crt \
    https://<node-host>:9080/api/v1/health
# Expected: 503
```

The `"services"` field in the response body will include `"drain": "draining"`.
The load balancer stops routing new steward connections once it sees the 503.

### 4. Observe session drain

Existing steward sessions established before the drain continue until they close
naturally. Monitor the active session count until it reaches zero before
stopping the process (optional but minimises reconnect storms):

```bash
# Run on the draining node — repeat until count is 0
cfg controller status --url=https://<node-host>:9080
```

In environments where brief reconnect storms are acceptable, you can stop
the controller immediately after the 503 is confirmed; stewards reconnect to
remaining nodes within one heartbeat interval.

### 5. Upgrade the binary on the drained node

SSH to the node and run the upgrade (see [controller-upgrade.md](controller-upgrade.md) for the full
single-node upgrade runbook). Use `upgrade restart` — the supported production
path (Issue #2015) — not `upgrade run`, which is an experimental port-swap
orchestrator frozen per ADR-007 and explicitly not the supported path:

```bash
cfg controller upgrade restart \
    --binary /opt/cfgms/cfgms-controller-v0.6.0 \
    --config /etc/cfgms/controller.cfg
```

### 6. Decommission the old node entry

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

**Timeout behaviour.** The controller waits up to five minutes for all active
steward sessions on the local node to reach zero before marking the node
decommissioned. If sessions have not drained by the end of that window the
node is force-decommissioned and the controller logs a warning at `WARN` level:

```
decommission timeout: sessions still active on node, proceeding
  active_sessions=<n>  node_id=<node-id>
```

Force-decommission on timeout is by design — it bounds the time a rolling
upgrade step can block while still allowing a clean drain in the common case.

### 6a. Verify the node is excluded from active nodes

After the decommission command returns, confirm the node no longer appears in
the active node list (available via the cluster status command in a future
story). You can also query the API directly:

```bash
# Must return an empty list or a list that does not include <node-id>
curl --cert ~/.config/cfgms/admin.crt \
     --key  ~/.config/cfgms/admin.key \
     --cacert ~/.config/cfgms/ca.crt \
     https://controller.example.com/api/v1/cluster/nodes
```

A decommissioned node has state `"decommissioned"` and is not returned by
`ListActiveNodes`. If the node still appears as active, do not proceed — check
the controller logs for errors.

### 7. Repeat for each remaining node

Repeat steps 2–6 for each remaining node, one at a time.

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
