# ADR-028: Raft Log Persistence for Controller Cluster Restarts

**Status:** Superseded by [ADR-031](031-controller-cluster-service-model.md)

**Date:** 2026-08-13

**Deciders:** Founder, Architecture

**Related:** Story [#3284](https://github.com/cfg-is/cfgms/issues/3284) (ha: persist the Raft
log so a controller can restart into its own cluster). ADR-007 (Controller Upgrade and State
Externalization — the broader strategy for durable controller state; this ADR covers the HA
Raft component of that durability goal).

---

## Context

### The restart panic

Before this ADR, every controller node persisted its Raft state only in `raft.MemoryStorage` —
a purely in-process structure that does not survive process exit. When a controller node was
restarted in a running cluster (after an upgrade, crash, or OS reboot), `NewRaftConsensus`
called `raft.StartNode` with the initial peer list, as if the node had never joined the cluster.

This caused an immediate Raft panic:

```
tocommit(7) is out of range [lastIndex(3)]
```

The surviving peers had committed seven entries. The restarting node claimed a log that ended
at index three, then tried to accept a commit pointer it had no entries for. Raft's invariant
(`tocommit ≤ lastIndex`) was violated and the library panicked. The node could not rejoin the
cluster it had previously been a member of.

### Why in-memory state is insufficient for HA

Raft's correctness properties require that a node's **HardState** (current term, vote, and
commit pointer) and **log entries** survive across process boundaries. A node that forgets its
term may grant a second vote in the same term to a different candidate, which is precisely the
vote-uniqueness property Raft is designed to enforce. A node that forgets its entries may
re-apply state-machine commands that were already applied, causing duplicate mutations.

The existing `raft.MemoryStorage` is appropriate for the within-Ready-cycle buffer that the
etcd/raft library requires, but it is not a write-ahead log; it is explicitly documented as
an in-memory implementation.

### Constraint: dependency budget

The story requires exactly one new Go module dependency: `go.etcd.io/bbolt v1.3.11`. No other
new module may be introduced.

---

## Decision

### 1. bbolt as the durable Raft write-ahead log

Each controller node maintains a per-node bbolt database at
`<dna-data-root>/raft-log/raft.db`. bbolt provides:

- **Atomic transactions with fsync-on-commit** — a committed batch is either fully durable or
  fully absent; there are no partial writes visible after a crash.
- **Exclusive OS-level flock** — two processes cannot open the same node's database
  simultaneously, which prevents split-brain from parallel boot.
- **Big-endian key ordering** — log entry keys (8-byte big-endian index) sort numerically,
  enabling a forward cursor scan that reconstructs the log in index order without sorting.

The database uses four buckets:

| Bucket | Key | Value |
|--------|-----|-------|
| `hardstate` | `hs` | protobuf-encoded `raftpb.HardState` |
| `entries` | `<8-byte big-endian index>` | protobuf-encoded `raftpb.Entry` |
| `snapshot` | `snap` | protobuf-encoded `raftpb.Snapshot` |
| `applied` | `idx` | 8-byte big-endian applied index |

A single `bbolt.Update` transaction covers all four bucket writes for a given Ready batch —
one fsync, one atomic commit.

### 2. Per-node state, not shared cluster state

Each node writes only its own log. The bbolt file is local to the node's filesystem and is
never read by other nodes. Replication remains the responsibility of the Raft protocol itself
(which sends log entries from leader to followers over the mTLS transport). This keeps the
durability layer simple and avoids distributed coordination at the storage level.

### 3. Persistence precedes message dispatch; applied index is persisted post-apply

Within the `processReady` loop, the ordering is:

1. Apply snapshot and entries to `raft.MemoryStorage` (in-memory buffer update).
2. Call `logStore.SaveBatch(hardState, entries, snapshot, previousApplied)` — one bbolt fsync.
   **If this fails, panic immediately.** Sending messages after a failed write would violate
   Raft's durability contract: peers would commit entries that the local node cannot prove it
   durably holds.
3. Send outbound messages to peers via the mTLS transport.
4. Apply committed entries to the state machine (updates `rc.appliedIndex`).
5. If any entries were applied: call `logStore.SaveBatch(emptyHardState, nil, emptySnapshot,
   newApplied)` — persists the updated applied index so restart knows the true high-water mark.
   This write is monotonic — if `newApplied ≤ existingApplied`, the stored value is unchanged.
6. Signal leadership changes.
7. Call `node.Advance()`.

The panic-on-write-failure choice is deliberate. A failed fsync means the OS could not
guarantee persistence; continuing as if it succeeded and then losing power would produce a
node whose log diverges from what it claimed to peers. A noisy crash is safer than silent
data loss.

### 4. Boot selection: `RestartNode` when persisted state exists

`NewRaftConsensus` detects whether the node has prior durable state:

```go
hasPersistedState := logStore != nil && logStore.HasData()
useRestart := hasPersistedState || len(peers) == 0
if useRestart {
    rc.node = raft.RestartNode(config)
} else {
    rc.node = raft.StartNode(config, peers)
}
```

`raft.RestartNode` reads state from the supplied `raft.Config.Storage` (which is the
`raft.MemoryStorage` populated from the bbolt database) and does not require a peer list.
`raft.StartNode` is used only for genuinely new nodes. The `len(peers) == 0` branch preserves
existing behavior for single-node bootstrap and test scenarios that do not supply peers.

### 5. Applied index recovery and `raft.Config.Applied`

The applied index is stored alongside the log entries. On boot it is loaded and set as
`raft.Config.Applied`, which tells the Raft library to skip re-delivering entries up to that
index to the state machine. Without this, every entry committed before the restart would be
re-applied after boot, causing duplicate state-machine mutations.

### 6. `raftLogDir` threaded from server bootstrap

`features/controller/server/server.go` computes:

```go
raftLogDir := filepath.Join(resolveDNADataRoot(cfg), "raft-log")
```

and passes it through `initializeHAManager` → `ha.NewManager` → `ha.NewRaftConsensus` →
`OpenRaftLogStore`. An empty string disables the log store entirely (used in tests that
exercise non-HA paths or that do not need persistence).

### 7. Classification within the central provider system

`pkg/ha` is already a Direct Provider (listed in CLAUDE.md). A single-implementation WAL
inside a Direct Provider does not require the pluggable-interface treatment that multi-consumer
providers need. The store is package-private enough that its bbolt dependency does not leak
into callers; callers interact with `ha.Manager` and `ha.RaftConsensus`, not with bbolt types.

---

## Alternatives Considered

### WAL files (write-append-only segment files)

Custom WAL files give fine-grained control over segment rotation and compaction but require
implementing the segment index, checksum, and recovery logic from scratch. bbolt's existing
correctness guarantees and the one-dependency constraint make a custom WAL impractical for
this story.

### etcd's own WAL library (`go.etcd.io/etcd/server/...`)

The etcd WAL implementation exists but it carries the full etcd server module graph as a
dependency, far exceeding the one-new-module budget. bbolt is a direct bbolt dependency that
the etcd project itself uses for its stable bucket store; using it directly is lower weight.

### External distributed key-value store (Redis, etcd cluster)

Externalizing Raft log storage adds an operational dependency and a network call in the hot
path of every Ready cycle. The requirement is per-node local persistence, not shared
distributed storage.

---

## Consequences

### Positive

- Controller nodes survive process restart without losing cluster membership or triggering
  the `tocommit out of range` panic.
- The durability ordering (fsync before message dispatch) closes the message-before-persist
  window that could have caused log divergence on power loss.
- bbolt's exclusive flock prevents two concurrent node processes from corrupting the same
  database.
- Existing single-node and test scenarios are unaffected: passing an empty `raftLogDir`
  keeps the previous in-memory-only behavior.

### Negative / Trade-offs

- Every Ready cycle now includes a bbolt fsync. This is the inherent cost of durability; the
  same cost applies to any correct Raft WAL. Benchmarks on modern NVMe storage show bbolt
  fsync latency is dominated by hardware (typically 0.1–2 ms), not by the library.
- The controller node's data root directory must be on persistent storage. A node whose
  `<dna-data-root>` is on a tmpfs or ephemeral volume will lose its log on every restart,
  reverting to the pre-ADR behavior. This is a deployment constraint, not a code constraint.
- Log compaction (truncating entries before the last applied snapshot) is not implemented in
  this story. The entries bucket will grow until a snapshot clears it. This is acceptable at
  current cluster sizes and is tracked for a follow-on story.
