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

## Mixed-version rollout (N and N-1)

During a rolling upgrade, two revisions share one PostgreSQL database: the revision
being rolled out (N) and the previous revision on `develop` (N-1). The schema is
changed so both run at once. The rule and how it is enforced are in
[Schema evolution (N / N-1)](../architecture/storage-architecture.md#schema-evolution-n--n-1).
This applies to the PostgreSQL provider only.

### Read each node's schema range

Every node reports the database schema version it requires and the oldest it tolerates
through the shared node registry. Read both for all nodes with one authenticated
`GET /api/v1/ha/cluster` request (see the [operator guide](../deployment/cfg-operator-guide.md)
for authentication):

```bash
curl --fail --cacert /path/to/controller-ca.crt <authentication options> \
  <controller-url>/api/v1/ha/cluster
```

The caller needs the `ha:read-cluster` permission. Each node object carries:

- `schema_required`: the schema version that node's build creates and expects.
- `schema_min_tolerated`: the oldest recorded schema version that node starts against.

A mixed cluster shows two different `schema_required` values. `0` means unknown (the
node predates the fields or the registry does not track a range), not "no requirement".
A node's entry goes stale about 90 seconds after its last registry update.

### A refused start

A node refuses to start when the database is outside the range its build tolerates. The
service log carries an error that begins `database schema version is outside the range
this controller tolerates`, followed by one of two reasons:

- `recorded schema version is <a> but this controller tolerates <b> through <c>`: the
  database is older than this build accepts. Upgrade the controllers that last wrote the
  database, or restore a database at a tolerated schema version.
- `the database requires controllers at schema version <n> or later but this controller
  is at <m>`: a contract step has already removed schema this build needs. Upgrade this
  controller to the current revision, or restore a database at a tolerated schema
  version.

A refused node does not serve and does not record itself as having passed the gate. The
rest of the cluster is not affected. Inspect `journalctl -u cfgms-controller`, fix the
cause above, then restart the node. Do not edit the version record by hand.

### Roll back one version

Rolling one node back from N to N-1 needs no schema rollback. Replace the binary with the
previous revision using the same drain, replace and validate steps as above. N-1 is
accepted because the contract floor is the marker of the latest contract step: a node
at or above the marker keeps running, and only a node below it is refused. The database
record of the highest applied version (`version`) is never lowered, and N-1 tolerates it.

The contract covers rollback by one version only. If a rolled-back node is refused with
the second error above, the database floor is above that binary's schema version; restore
the backup taken before the upgrade together with the matching binary.

### A contract step waits for older nodes

Removing or narrowing schema (a contract step) is applied on a node start, and only when
no live node still needs the old shape. It is blocked while either of these is true:

- a live node registered with a `schema_required` below the step's marker, including a
  row with `schema_required` of `0` from a node that predates the column;
- a node passed the start-up gate within the last 90 seconds and has not registered yet.

A blocked step is not a failure. The node logs `database contract step not applied yet;
it applies on a later node start once older nodes are gone`, names the blocking nodes,
and starts normally. Nothing retries the step on a timer: it is applied on a later node
start, after the older nodes' registry rows have gone stale. The restarting node's own
row from before the restart also blocks the step for up to the 90 second staleness
window. A contract step therefore takes effect one rollout after the expansion it
follows. Finish the rollout so no N-1 node remains, wait out the staleness window, then
restart one node to apply it.

### Which controls are automatic

The version gate and the contract guard run on every node start. The static checks of
the schema statements run with the database provider's test suite. The two-revision
compatibility run happens at merge-queue time, not on every pull request push. Backfill
design is checked by review only. The architecture document lists each control.

The [cluster service decision](../architecture/decisions/031-controller-cluster-service-model.md)
owns the any-node/shared-store model. The [upgrade lifecycle reference](upgrade-lifecycle.md)
explains which history and status surfaces apply.
