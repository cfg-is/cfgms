# Controller Cluster Deployment

Deploy a geo-redundant CFGMS controller cluster for high availability and regional failover.

**Prerequisite**: Complete [Single Controller](../single-controller/walkthrough.md) first. This guide assumes you have a validated single-controller environment and covers turning it into a multi-node cluster.

## Proven deployment shape

A 3-node `ha.mode: cluster` deployment was live-validated against real hardware in epic #3090.
The full environment, per-node bootstrap procedure, quorum verification, and rollback drills
are documented in the runbook:

**[Controller HA — real-cluster validation runbook](../../testing/controller-ha-real-cluster-runbook.md)**

This section summarises the key operational facts derived from that validation.

### Cluster topology

| Node | Role | `internal_listen_addr` | `internal_delivery_listen_addr` | REST API |
|---|---|---|---|---|
| `ctrl-node-01` | cluster member (original Tier-1 controller) | `<node-private-ip>:9443` | `<node-private-ip>:9444` | `:9080` |
| `ctrl-node-02` | cluster member | `<node-private-ip>:9443` | `<node-private-ip>:9444` | `:9080` |
| `ctrl-node-03` | cluster member | `<node-private-ip>:9443` | `<node-private-ip>:9444` | `:9080` |

All three nodes connect to a **shared PostgreSQL backend** and a **shared S3-compatible
blob store** (MinIO or equivalent). Nodes do not replicate data
between themselves — config data, registration records, audit, and RBAC all live in shared
Postgres, and leadership is a lease held in that shared store (ADR-031).

### Key configuration: per-node env vars

Each node requires its own identity in the cluster. The following environment variables
(delivered via `LoadCredentialEncrypted=` per ADR-030 — never in cleartext on disk)
are the critical per-node values:

| Variable | Purpose |
|---|---|
| `CFGMS_NODE_ID` | This node's stable identity in the cluster (use the node's private IP) |
| `CFGMS_HA_EXTERNAL_ADDRESS` | This node's advertised address to its peers |
| `CFGMS_HA_CLUSTER_NODES` | Comma-separated list of all cluster nodes' internal addresses |
| `CFGMS_HA_CA_CERT_PATH` | Path to the shared cluster CA certificate (from OpenBao or equivalent) |
| `CFGMS_SECRETS_KEY_FILE` | Path to the sealed root-of-trust key (identical value on every node) |
| `CFGMS_STORAGE_DB_PASSWORD_FILE` | Path to the sealed PostgreSQL password |
| `CFGMS_SESSION_HMAC_KEY_FILE` | Path to the sealed session HMAC key (identical value on every node) |

The `CFGMS_SECRETS_KEY_FILE` and `CFGMS_SESSION_HMAC_KEY_FILE` values **must be identical
across all nodes** — they encrypt/authenticate shared rows in the cluster Postgres backend.
Independently generated per-node values produce ciphertext-authentication failures.

### Controller node time sync

Every controller node must sync its clock to a common time source. Clock
disagreement between nodes skews audit timelines and certificate validity
checks. Controller nodes are not stewards, so configure the time daemon on the
host directly.

`systemd-timesyncd` (`/etc/systemd/timesyncd.conf`):

```ini
[Time]
NTP=time1.example.com time2.example.com
```

`chrony` (`chrony.conf`):

```text
server time1.example.com iburst
server time2.example.com iburst
```

### Cross-node command delivery

Set `internal_delivery_listen_addr` on every node (`ha-cluster-node-bootstrap.sh` renders
it, `--delivery-port`, default `9444`). It is the private mTLS listener that lets a node
hand a command to the node holding the target steward's session (ADR-031 Decision 3).
Peers are dialled on this node's port, so the port must be the same on every node.
Without it a node reaches only the stewards connected to itself, and logs a startup
warning saying so.

### mTLS peer identity

Each node presents its own certificate (issued by the shared cluster CA) for mTLS on the
`internal_listen_addr` port (`:9443`). The CA fingerprint is loaded from a shared secret
store (OpenBao in the validation lab). Use `ha-cluster-node-bootstrap.sh` to provision
new nodes — it generates the per-node certificate, wires `LoadCredentialEncrypted=` secret
delivery, and validates the bootstrap before starting the service.

### LB/VIP: when it is and is not required

**Steady-state steward traffic (heartbeat, config delivery):** No LB/VIP is required.
Every cluster node serves steward ControlChannel traffic directly against the shared
Postgres backend — leader election is invisible to a steward whose own node stays up.
A plain liveness probe on `GET /api/v1/health` suffices if you do use an LB for this path.

**Enrollment (registration and token endpoints):** Every node serves these endpoints;
a follower does not answer `503` (ADR-031 removes the leadership gate from the API request
path). A plain liveness probe on `GET /api/v1/health` is enough on every node. Operators who
want to see which node currently holds leadership can query `GET /api/v1/ha/status`
(`is_leader`, lease-backed) on a node, or `GET /api/v1/ha/leader` for the current leader.

**Steward's-own-node failure:** A steward has exactly one controller URL. When its own
node goes down, it retries that node until the node returns. To keep stewards attached
through a node outage, place an LB/VIP in front of the cluster, point the steward's
`--controller-url` at the LB address, and use a plain liveness health gate (not an
`is_leader` gate) for the ControlChannel path.

### Starting and stopping the cluster

Nodes can be started and stopped one at a time, in any order. Each node serves requests
as soon as it is up, against the shared Postgres backend, and leadership moves to another
node through the lease when the holder stops. No coordinated stop-all/start-all is needed.
For a rolling restart, restart one node, confirm `GET /api/v1/health` returns healthy, then
move to the next.

See §3 of the runbook for the full cluster-join procedure, rollback drill, and quorum
verification commands.
