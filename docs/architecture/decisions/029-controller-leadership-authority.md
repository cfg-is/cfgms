# ADR-029: Controller Leadership Authority — Lease-Backed Authority and Fenced Side Effects

**Status:** Amended by [ADR-031](031-controller-cluster-service-model.md) — request-path authority gating and Raft substrate superseded; lease authority model retained (see ADR-031 §Supersedes)

**Date:** 2026-08-18

**Deciders:** Founder, Architecture

**Related:** Epic [#3386](https://github.com/cfg-is/cfgms/issues/3386) (controller leadership
authority — this ADR is its design gate; every other story under it implements against this
document). Story [#3095](https://github.com/cfg-is/cfgms/issues/3095) under epic
[#3090](https://github.com/cfg-is/cfgms/issues/3090) (real-cluster partition validation — its
`TestRealClusterPartition_NoDualLeader` is the acceptance test for this design and its
criterion is **not** weakened). Epic
[#3411](https://github.com/cfg-is/cfgms/issues/3411) (extending authority gating to the
remaining side-effecting endpoints — **Decision 6's reset guarantee is contingent on it**).
ADR-028 (Raft log persistence). Issue #2037 (heartbeat flapping root-caused to wall-clock
skew — the precedent for Decision 2). CLAUDE.md Threat Model.

---

## Context

### The controller uses a replication-protocol flag as an authorization primitive

`ha.Manager.IsLeader()` (`pkg/ha/manager.go:373`) delegates to
`RaftConsensus.IsLeader()` (`pkg/ha/raft_consensus.go:798`), which returns
`rc.clusterState.Leader == rc.nodeID` — a cached view of Raft `SoftState`.

Raft's leader-completeness property protects **the replicated log**. It makes no statement
about side effects that escape the log. Three call sites gate work on that flag today:

- `features/controller/api/handlers_push.go:57` — `POST /api/v1/config/push`
- `features/controller/api/server.go:408` — the same gate
- `features/controller/server/server.go` — `resumePendingPushes` at startup (`:2077` at time of writing; cite the symbol, the line drifts)

Reading `handleConfigPush` past the gate: it resolves the selector, queries the fleet, writes
desired state into the entity graph, and fans out to stewards via `commandPublisher`. **There
is no Raft commit anywhere in that path.** The effect leaves the cluster entirely.

### The overlap is measured, not theoretical

`TestRealClusterPartition_NoDualLeader` fails reproducibly against the real cluster, with
measured dual-leader overlaps of 2.0s and 5.5s across two runs. Traced through vendored
`go.etcd.io/raft/v3 v3.7.0`:

- The isolated leader's `MsgCheckQuorum` step-down lands anywhere in
  `(ElectionTimeout, 2×ElectionTimeout]` — `tickHeartbeat` / `r.checkQuorum` at
  `raft.go:862,868`; `case pb.MsgCheckQuorum:` at `raft.go:1281`.
- The majority's `randomizedElectionTimeout` lands in `[ElectionTimeout, 2×ElectionTimeout)` —
  `pastElectionTimeout` at `raft.go:2046`; `resetRandomizedElectionTimeout` at
  `raft.go:2053-2054`.

Two independent, unordered timers with overlapping ranges. The majority can finish electing
before the isolated node notices it lost quorum, so both report `is_leader: true` for up to one
`ElectionTimeout` — 10s at production defaults (`pkg/ha/config.go:28-29`).

### Why this is settled in an ADR before implementation

The lease bound is a correctness argument, not a tuning constant. Getting it wrong reintroduces
the overlap silently and without a failing test. The remaining stories under #3386 implement
against the decisions below rather than re-deriving them.

---

## Decision 1 — The lease bound is a ratio of `ElectionTimeout`, not a fixed duration

`HasLeadership()` returns true only while the node is Raft leader **and** less than
`leaseDuration` has elapsed since its last quorum-acknowledged heartbeat.

```
leaseDuration = 0.8 × ElectionTimeout
```

**Derivation.** A new leader cannot be elected until a full `ElectionTimeout` of missed
heartbeats has elapsed on some follower (`pastElectionTimeout`, `raft.go:2046`; the randomized
timeout has a *minimum* of `ElectionTimeout`, `raft.go:2053-2054`). The outgoing leader's
authority must therefore expire strictly before `ElectionTimeout` measured from the same
reference point. The safety margin is the difference:

```
margin = ElectionTimeout − leaseDuration = 0.2 × ElectionTimeout
```

At production defaults (`ElectionTimeout` 10s): **lease 8s, margin 2s.**

**Why a ratio and not `ElectionTimeout − 2s`.** `FastElectionConfig()`
(`pkg/ha/config.go:302`) uses a 200ms `ElectionTimeout`. A fixed 2s margin is arithmetically
impossible there, and the alternative — forbidding fast timings — would push every HA test onto
10-second elections, which is precisely what that config exists to avoid. A ratio holds at both
scales and lets tests exercise the real lease code path.

**The margin at test scale is not pause-safe** (40ms). This is accepted because
`FastElectionConfig` is test-only — it is referenced from `features/controller/api/server_tls_ha_test.go`
and `pkg/ha/config_test.go` and nowhere else, and the real-cluster runbook records that its
suite deliberately avoids it. A production deployment must never adopt those timings.

### What the margin is actually for

**Not clock skew.** The leader measures its lease on its own monotonic clock; a follower
measures its election timeout on its own. Neither reads the other's clock, so absolute offset
between hosts is irrelevant by construction. Only relative *rate* drift matters, and on
commodity hardware that is on the order of a millisecond over ten seconds.

**Pauses.** The margin covers the interval during which a leader has lost authority but has not
yet *noticed* — a GC pause, a scheduling stall, or a hypervisor descheduling the whole guest.
The last is the binding case: CFGMS controllers run as VMs, and a guest cannot observe its own
descheduling. 2s at production defaults is sized for that, deliberately generous, on the
reasoning that the cost of being wrong is asymmetric: a too-large margin costs a brief retry,
a too-small one costs the property this epic exists to establish.

---

## Decision 2 — All lease arithmetic uses a monotonic clock

Lease elapsed time is computed from Go's monotonic clock reading only. Wall-clock time must not
appear in the lease path, in any form — not as a transmitted timestamp, not as a persisted one,
not as a fallback.

Issue #2037 is the precedent: heartbeat flapping was root-caused to host wall-clock skew rather
than delivery loss. Decision 1's derivation depends on this — it is what makes cross-host clock
offset irrelevant rather than merely small.

Suspend/resume: Go's monotonic reading does not advance while suspended on the platforms CFGMS
targets, so a resumed leader sees a lease that has not aged. It will discover quorum loss
through the ordinary heartbeat path within one `ElectionTimeout`. This is acceptable because
the fencing token (Decision 5) does not depend on the lease being correct.

---

## Decision 3 — The API splits into three primitives

| Method | Meaning | Use |
|---|---|---|
| `IsRaftLeader()` | Raw replication-protocol state. Free to flap. | Status, observability, debugging. |
| `HasLeadership()` | Lease-backed authority. | **The admission primitive.** Every side-effecting path. |
| `GetTerm()` | Current Raft term. | The fencing token source (Decision 5). |

**The ergonomic name belongs to the safe one.** The ambiguity of a single `IsLeader()` is what
allowed the category error, so `IsLeader()` is **removed outright**, not retained as a
deprecated alias. CFGMS is pre-production and the house rule is a hard break over a migration
shim: every call site is forced through review exactly once, rather than the unsafe primitive
remaining reachable by a name that reads correct.

**Placement.** `RaftConsensus` (`pkg/ha/raft_consensus.go`) is a concrete struct with no
interface wrapper. The only defined interface is `ClusterManager`
(`pkg/ha/interfaces.go:103-136`, implemented by `Manager`), whose `IsLeader() bool` is declared
at `interfaces.go:119-120`. There is no `ConsensusProvider` type in this codebase.

- `IsRaftLeader()`, `HasLeadership()` and `GetTerm()` become concrete methods on
  `RaftConsensus`, mirrored on `Manager`.
- `ClusterManager` gains `HasLeadership()` and loses `IsLeader()`.
- `IsRaftLeader()` is deliberately **not** added to `ClusterManager` — the interface exposes
  the safe primitive only. Status surfaces reach the raw value through the concrete type.

**`GetTerm()` is new and load-bearing.** The term is currently reachable only inside `pkg/ha`;
nothing exports it. `RaftConsensus.GetLeader()` (`raft_consensus.go:805-809`) is the existing
pattern to mirror — a thin read under the same lock discipline. Without it, Decision 5 is not
implementable.

Implementers note: raft v3.7.0 is a protobuf-v2 migration. `raft.Status` embeds `*pb.HardState`
and the term is read via the generated accessor — `node.Status().GetTerm()`, as
`pkg/ha/raft_transport.go:294` already does. **`node.Status().Term` does not compile.**

---

## Decision 4 — `SingleServerMode` behaviour is unchanged

`Manager.IsLeader()` returns unconditionally true in `SingleServerMode` (`pkg/ha/manager.go`).
`HasLeadership()` inherits that exactly: in `SingleServerMode` it returns true unconditionally,
with no lease, no expiry and no new rejection path.

There is no quorum to lose and no peer to overlap with, so the lease has nothing to protect
against. Single-node OSS deployments must observe **no behaviour change whatsoever** from this
epic. This is an explicit, tested criterion on every story that touches an admission path, not
an implementation detail.

---

## Decision 5 — Outbound commands are fenced with `(clusterID, term)`

The lease shrinks the window. A fencing token closes it, and makes correctness independent of
the timing assumptions in Decision 1 rather than dependent on them.

**The token is a pair**, not the Raft term alone:

- **`term`** — the Raft term, from `GetTerm()`. Monotonic within one cluster incarnation.
- **`clusterID`** — an opaque identifier minted once when a cluster is first bootstrapped and
  stored in OpenBao alongside the cluster CA (see `docs/operations/cluster-ca.md`).

Both ride in the command envelope. The steward records the highest `(clusterID, term)` it has
observed and rejects any command carrying a lower term **for the same `clusterID`**.

### Why `clusterID` is required

Raft terms restart at 1 when a cluster is rebuilt from scratch. The term alone is therefore not
monotonic across a rebuild — and #3130 deliberately made the CA independent of the raft
cluster, so a rebuild that **preserves** the CA is both possible and the likely recovery path.

In that case terms reset, certificates stay valid, no re-enrollment is triggered, and every
steward would hold a high-water term far above 1 and permanently reject the legitimate new
controller. Recovery would require touching every endpoint by hand. **That failure is worse
than the defect this epic fixes** — a duplicated config push is recoverable; fleet-wide loss of
control is not.

Pairing the term with a cluster identity makes the reset automatic rather than procedural. A
partitioned node carries the *same* `clusterID` as the majority, so it cannot use this to clear
anything; minting a new one requires write access to the vault, which is already the trust
root.

---

## Decision 6 — The steward-side fence is a durable three-state ratchet

State is persisted on the steward and survives restart. A fence that an ordinary reboot erases
is a fence with a documented bypass.

| Steward state | Unstamped command | Stamped command |
|---|---|---|
| Never seen a stamped command | **Accept** — genuine bootstrap, or mid-rollout behind an older controller | **Accept**, record `(clusterID, term)`, set the flag |
| Has seen a stamped command | **Reject — downgrade attempt**, not legacy traffic | Accept iff `clusterID` differs (new cluster → reset) or `term >= highest_seen` |

Both the high-water `(clusterID, term)` and the has-seen-stamped flag persist. The stored flag —
not any property of the arriving command — is what distinguishes a genuine first-ever command
from a controller omitting the field to bypass the fence.

**Real Raft terms are never 0 once a leader has been elected** (`becomeCandidate` increments
before campaigning), so a zero/absent term arriving at a steward that has an established
baseline is indistinguishable from a downgrade attempt and is refused.

### Enrollment seeds the ratchet

A steward enrolling against a fencing-capable controller records the current
`(clusterID, term)` at enrollment and starts with the flag **set**. Bootstrap-accept therefore
applies only to stewards enrolled before this ships — a finite, shrinking set — rather than to
every new machine indefinitely.

### Lost state fails open, and the controller detects it

A steward whose persisted state is lost (disk replacement, reimage, corruption) returns to
bootstrap and accepts unstamped commands until its next stamped one. It cannot distinguish
itself from a new machine.

**The controller can.** An already-enrolled steward reporting bootstrap state is anomalous and
must be surfaced. Fail open on the device, detect on the controller.

Rationale, examined against the actual adversary: commanding a steward requires both reaching
it at the URL compiled into its binary (`-X main.ControllerURL`) and presenting a server
certificate signed by the fleet CA (`RootCAs` pinning, `pkg/cert/tls.go:181,245`). An outsider
without the CA cannot complete the handshake at all; an attacker holding the CA has already
won. The only meaningful adversary is a legitimate-but-stale node — and for it to exploit
bootstrap state it must first destroy the steward's stored state, which requires local write
access to that host. Local privilege already defeats fencing on that machine, so fail-open adds
no remotely reachable path. Attempting to wipe the state *via* a command is self-defeating: the
fence rejects that command too.

Fail-closed would trade a narrow, local-access-dependent window for a guaranteed manual
re-enrollment on every disk event, and for machines that go silently dark when a file corrupts.

**Implementation prerequisite:** confirm no steward client path reaches the command transport
with `InsecureSkipVerify` set (`pkg/transport/quic/tls.go:50`, `pkg/cert/tls.go:222` —
the latter is documented as intentional for unauthenticated liveness probing). The reasoning
above depends on the CA pinning being unconditional on the command path. This is a required
verification task, not an assumption.

### The reset path is authenticated, and its guarantee is currently contingent

The ratchet clears on a `clusterID` change or on re-enrollment — both gated on mTLS identity.
**No inbound command, field or flag may clear it.** If a command could clear the fence, clearing
the fence becomes step one of every attack.

**Contingency, stated plainly:** re-enrollment is not itself authority-gated today. The
registration and token endpoints perform no leadership check, so a partitioned node can still
complete an enrollment. Until the registration-gating work under epic #3411 lands, the
re-enrollment half of this reset path does not require anything the epic's own adversary lacks.
The `clusterID` half is unaffected — it is gated on vault write access, not on enrollment.

---

## Decision 7 — Both status surfaces report authority, with raw state preserved

`GET /api/v1/raft/status` (`pkg/ha/raft_transport.go`, `HandleStatus` at `:289`) and
`GET /api/v1/ha/status` (`features/controller/api/handlers_ha.go:41-76`) both expose
`is_leader` sourced from the unsafe primitive today.

After the split, on both surfaces:

- **`is_leader` means lease-backed authority** — `HasLeadership()`.
- Raw Raft state is preserved under a **distinct field** for debugging, sourced from
  `IsRaftLeader()`.

This is what makes `TestRealClusterPartition_NoDualLeader` pass **as originally written**: the
test asserts that no two nodes simultaneously report themselves leader, and after this change
`is_leader` means the property the test is actually checking. #3095's criterion is correct and
is not weakened.

The two surfaces must agree. A test asserting that is required.

**Information disclosure:** a non-authoritative node's 503, and the new status fields, must not
name or imply which other node holds leadership.

---

## Consequences

### Accepted cost: availability during handover

A leader that briefly loses quorum contact becomes non-authoritative and returns 503 on pushes
for up to a lease duration, even where it would have retained leadership under current
behaviour.

**Quantified:** during a normal handover the worst-case interval with no authoritative node in
a healthy cluster is the margin — **2s at production defaults**. Callers see 503 and retry.

This is the correct trade for a system that mutates endpoint state: a clear "no current
leadership, retry" beats a stale leader acting. It is accepted deliberately here rather than
discovered later.

### Not closed by this ADR

- Authority gating for the ~20 other mutating controller endpoints — epic #3411. The
  highest-severity item there is cluster node drain/decommission, which is ungated today.
- Multi-region / WAN-latency tuning — out of scope, as in epic #3090.
- `go.etcd.io/raft/v3` is not modified or forked. The lease layers on top.

### Correction to existing documentation

`docs/architecture/controller-operating-model.md` describes `CheckQuorum:true` as the mechanism
that makes leadership safe. That claim is corrected by this ADR: `CheckQuorum` guarantees
replicated-log write safety and says nothing about side effects that never reach the log, and
its step-down timing is one of the two overlapping timers that produce the measured window.
