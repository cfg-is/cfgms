# Rolling Cluster Upgrade Runbook

Replace controller binaries one node at a time while healthy peers serve the
fleet. Availability depends on shared stores, remaining capacity and correctly
configured endpoint routing; this procedure does not promise a fixed reconnect time.

## Prerequisites

- A validated [controller cluster](../deployment/controller-cluster/walkthrough.md)
  with enough healthy peers to serve while one node is unavailable.
- A load balancer/VIP that routes HTTPS and QUIC traffic appropriately and
  removes a node when its `/api/v1/health` response is not healthy.
- An authorized operator session for cluster administration. See the
  [operator guide](../deployment/cfg-operator-guide.md).
- The current node IDs, direct node addresses, CA trust and service configuration.
  Use the authenticated `GET /api/v1/ha/nodes` API to inspect the node registry;
  there is no `cfg controller cluster status` command.

## 1. Drain one node

```bash
cfg controller cluster drain <node-id> \
  --url https://controller.example.com
```

Confirm the draining node directly returns `503` from the public liveness gate:

```bash
curl --cacert /path/to/controller-ca.crt \
  --output /dev/null --write-out '%{http_code}\n' \
  https://node.example.com:9080/api/v1/health
```

Check the load balancer has stopped routing new connections to that node.
Existing connections can still be disrupted by stopping the process. Observe
session/connection telemetry where available; `cfg controller status` is a health
summary, not a per-node active-session counter. Do not wait on an invented counter
or assume sessions naturally drain to zero within a fixed heartbeat interval.

## 2. Upgrade and restart the drained service

Follow the [single-controller upgrade procedure](controller-upgrade.md), including
its credential-backed systemd branch, readiness probe and rollback instructions.
Keep the node's identity, shared-store credentials and config unchanged.

For a service without systemd credential directives, the CLI example is:

```bash
sudo cfg controller upgrade restart \
  --binary /opt/cfgms/cfgms-controller-new \
  --config /etc/cfgms/controller.cfg \
  --canonical-api-addr 127.0.0.1:9080
```

The canonical sealed-credential service must use the manual service-manager
procedure in that runbook. Do not use experimental `upgrade run` as a workaround.

## 3. Validate the node before proceeding

```bash
curl --fail --cacert /path/to/controller-ca.crt \
  https://node.example.com:9080/api/v1/ready
curl --fail --cacert /path/to/controller-ca.crt \
  https://node.example.com:9080/api/v1/health
```

Readiness verifies durable-storage access; liveness also reflects the drain gate.
Check both, the node registry, service logs and the load balancer. Verify a steward
can reconnect and complete an operation through the public endpoint. Stop the
rollout and recover this node if either gate remains unhealthy.

A configured `CFGMS_NODE_ID` is stable across binary replacement. Do not generate
a new ID or decommission the live node merely because its process restarted.
If a replacement intentionally uses a different identity, retire the old drained
node through `cfg controller cluster decommission <old-node-id>` only after the
replacement is serving. Decommission is a membership operation, not an ordinary
restart step.

## 4. Repeat

Proceed to the next node only after the upgraded node is healthy and available
through the routing layer. Keep an independently verified previous binary and
recoverable storage backup until the full upgrade has been accepted.

The [cluster service decision](../architecture/decisions/031-controller-cluster-service-model.md)
owns the any-node/shared-store model. The [upgrade lifecycle reference](upgrade-lifecycle.md)
explains which history and status surfaces apply.
