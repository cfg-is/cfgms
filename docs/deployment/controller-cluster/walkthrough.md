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

| Node | Role | `internal_listen_addr` | REST API |
|---|---|---|---|
| `ctrl-node-01` | cluster member (original Tier-1 controller) | `<node-private-ip>:9443` | `:9080` |
| `ctrl-node-02` | cluster member | `<node-private-ip>:9443` | `:9080` |
| `ctrl-node-03` | cluster member | `<node-private-ip>:9443` | `:9080` |

All three nodes connect to a **shared PostgreSQL backend** and a **shared S3-compatible
blob store** (MinIO or equivalent). No data replication is done via Raft — Raft owns
leader election and cluster membership/session bookkeeping only. Config data, registration
records, audit, and RBAC all live in shared Postgres.

### Key configuration: per-node env vars

Each node requires its own identity in the cluster. The following environment variables
(delivered via `LoadCredentialEncrypted=` per ADR-030 — never in cleartext on disk)
are the critical per-node values:

| Variable | Purpose |
|---|---|
| `CFGMS_NODE_ID` | This node's stable identity in the Raft cluster (use the node's private IP) |
| `CFGMS_HA_EXTERNAL_ADDRESS` | This node's advertised address for peer-to-peer Raft traffic |
| `CFGMS_HA_CLUSTER_NODES` | Comma-separated list of all cluster nodes' internal addresses |
| `CFGMS_HA_CA_CERT_PATH` | Path to the shared cluster CA certificate (from OpenBao or equivalent) |
| `CFGMS_SECRETS_KEY_FILE` | Path to the sealed root-of-trust key (identical value on every node) |
| `CFGMS_STORAGE_DB_PASSWORD_FILE` | Path to the sealed PostgreSQL password |
| `CFGMS_SESSION_HMAC_KEY_FILE` | Path to the sealed session HMAC key (identical value on every node) |

The `CFGMS_SECRETS_KEY_FILE` and `CFGMS_SESSION_HMAC_KEY_FILE` values **must be identical
across all nodes** — they encrypt/authenticate shared rows in the cluster Postgres backend.
Independently generated per-node values produce ciphertext-authentication failures.

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

**Enrollment (registration and token endpoints):** After #3473, these endpoints are
gated on `HasLeadership()`. A follower answers `503`. If you use an LB for enrollment,
it **must** health-gate on `GET /api/v1/raft/status` → `is_leader`, not just liveness.

**Steward's-own-node failure:** A steward has exactly one controller URL. When its own
node goes down, it retries that node indefinitely — there is no automatic failover to a
cluster peer. An LB/VIP in front of the cluster is the only operational lever for this
today. Point the steward's `--controller-url` at the LB address, and use a plain liveness
health gate (not an `is_leader` gate) for the ControlChannel path.

### Starting and stopping the cluster

All nodes must be stopped and started **together** for a coordinated restart. The Raft
log is persisted to `<data>/raft-log/raft.db` (since #3284); starting a node alone while
peers are already running risks diverging Raft state. Use the `haRestoreQuorum` helper
(in `test/e2e/ha/leader_election_real_test.go`) as a reference for the safe
stop-all/start-all sequence.

See §3 of the runbook for the full cluster-join procedure, rollback drill, and quorum
verification commands.
