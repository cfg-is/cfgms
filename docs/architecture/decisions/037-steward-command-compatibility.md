# ADR-037: Steward Command Compatibility — Capability Declaration, Connection-Scoped Floor and the Support-Floor Rule

**Status:** Accepted

**Date:** 2026-11-18

**Deciders:** Founder, Architecture

**Related:** Epic [#6307](https://github.com/cfg-is/cfgms/issues/6307) (this ADR is its overview; stories #6263, #6310, #6311, #6312, #6313 and #6314 implement the mechanisms). [ADR-013](013-steward-controller-trust-and-distribution.md) (steward–controller trust and the signed upgrade channel — the controller serves stewards it did not just build). [ADR-029](029-controller-leadership-authority.md) (lease-backed authority and the fencing term that command signing has to carry). [ADR-031](031-controller-cluster-service-model.md) (any-node service and the durable delivery record that reports a refused command).

---

## Context

A steward is upgraded on its own schedule. At any moment a controller serves stewards built from several releases, and it must keep serving the oldest release the platform still supports. Three kinds of version skew break that without anyone changing a line of the steward:

1. **A command type the steward does not know.** The steward verifies a command by rebuilding its signed bytes from the decoded command, and those bytes include the command type. A type it cannot map can never verify, and the failure looks like tampering.
2. **A signing payload version the steward does not know.** The payload version selects which fields the signature covers. A steward that predates version 2 verifies only version 1.
3. **A signing form the steward refuses.** A current steward refuses every command that carries a fencing term (`Term > 0`) signed over version 1, because that form leaves the term unauthenticated. A controller that signs for a current steward in the old form has a command refused.

Before this ADR the controller had no way to tell which kind of steward it was talking to. It signed in one form and sent every command type, and a mismatch surfaced on the steward as a signature rejection or on the operator as a delivery that never completes.

The mechanisms are described where they live: the [steward operating model](../steward-operating-model.md#capability-declaration-issue-6310), the [controller operating model](../controller-operating-model.md#steward-capability-record-issue-6310), [storage architecture](../storage-architecture.md) and the [compat harness](../../testing/steward-compat.md). This ADR states the contract they implement together, the reasons for its shape, and the procedure for changing it.

## Decision

### 1. The contract

The founder contract is:

> The current controller keeps serving the oldest supported steward release (the **floor**) without that steward needing to change. A command the controller sends to a steward is either one the steward can verify and run, or one the controller does not send and reports as unsupported. No supported steward ever sees a signature rejection that is really version skew.

The floor is one release, recorded in `test/compat/steward-support.yaml`. It is currently v0.10.5. Supporting a release means it has an entry in that file and the compat harness runs it against the controller built from every change (§8).

### 2. Capability declaration

Every steward build declares what it handles in the first message on each control-channel stream: the command type numbers and signing payload versions it supports (`StewardCapabilities`, `ControlMessage.capabilities`). The lists are derived from the build's own tables, so a declaration cannot drift from what the code does. The controller sends nothing back and the steward never waits.

The declaration carries no authority. The controller treats it as untrusted input: it checks the steward ID against the mTLS identity, drops unknown numbers, removes duplicates and caps the lists. A steward can narrow what the controller sends it; it cannot cause the controller to sign in a form or send a type the controller would not otherwise use.

### 3. The connection rule

The controller keeps a capability record per connection, with three states:

| State | Meaning |
|---|---|
| `pending` | The connection started and has declared nothing yet. |
| `declared` | The first declaration arrived. It is final for the connection. |
| `floor` | No declaration arrived within the grace period (default 5 s). The record holds the floor profile: command types 1 to 13 and signing payload version 1. |

The rules that make this safe:

- **Pending is bounded, not blocking.** A caller that needs the profile (the signing step, the command-type check) waits on the connection's settled signal, but only until a bounded time after the connection started (3 s). The wait is measured from the connection start, not from the call, so a publish long after connect to a silent steward returns the floor at once. No connect hook waits.
- **The floor applies to that connection only.** A connection settled at the floor is floor for that connection. The controller keeps no record that survives the connection: a steward that reconnects starts `pending` again, and a pending connection never reads the previous connection's record. A steward upgraded between two connections is therefore served as current on the next one with no operator action.
- **The selection reads controller-held state only.** A `signing_payload_version` on a command, or a capability-looking parameter, never influences it.
- **The record is shared.** It is kept in memory on the node that owns the connection and durably in the steward record, written by a compare-and-set on the connection ID, so any node answers from the same record (ADR-031) and a write from a superseded stream is refused.
- **A steward with no record is current.** The floor is taken only from a connection that settled there, not from a missing record.

### 4. Signing-form selection is an availability decision

The controller signs a command over version 2 unless the target connection's profile is the floor, in which case it signs over version 1. The choice only decides whether the command is accepted:

- Version 2 sent to a floor steward fails verification there: refused, not run.
- Version 1 with a stamped term sent to a current steward is refused before signature verification: refused, not run.

Neither error makes the steward run a command it should not. So the choice is **not a security boundary**; a wrong answer costs a delivery, never an authentication. The current steward keeps refusing stamped version 1 from first start, with no state consulted, so a controller record that says a current steward supports only version 1 does not make it accept one. Verification is never relaxed to make a command pass.

### 5. The term stays on version 1 for the floor, and the residual risk

A steward that enforces the fencing term (ADR-029) refuses an unstamped command as a downgrade once it has seen a stamped one. The controller does not assume a floor steward lacks the fence, and dropping the term from version 1 commands would switch the fence off for floor stewards that have it. The term therefore stays on the command, but version 1 does not cover it with the signature.

**Residual risk, scoped to the floor profile.** For a floor connection, the term is transport-trusted only (mTLS, not the signature). A party between signer and steward, such as an mTLS-terminating hop or a non-leader controller node, can rewrite it. Raising it defeats the fence for that steward, and setting it to the maximum wedges the steward's persisted high-water mark. A current steward does not carry this risk, because version 2 covers the term.

The risk is accepted for the floor profile and ends when the floor moves to a release that verifies version 2 (§7). It does not grow with the number of current stewards, and a current steward never has it forced on it: a downgrade to the unsigned-term form is refused.

### 6. Unsupported is produced by the controller

A floor steward cannot say a command is unsupported. It has no code for the case, and its own response to an unmapped type would be a signature failure. The controller produces the outcome, before anything is signed or sent, for the types outside the target connection's profile. For the floor those are steward action (type 14) and advertise transport address (type 15).

| Path | Outcome |
|---|---|
| Steward action (type 14), dispatcher | Refused before signing. The run result is `unsupported`: "steward too old: it does not support this action". |
| Controller-originated command (type 15) | Quiet skip: an Info log with `command_not_sent_peer_unsupported`; no error and no retry. |
| Pending delivery row | Terminal `rejected` with detail `command_type_unsupported_by_peer`, not retried on a later reconnect. |
| Any other publish | `commands.ErrCommandTypeUnsupportedByPeer`; nothing signed or sent. |

A steward that does know the type and reports `unsupported` itself, such as a platform with no handler, keeps its own path. A type the controller does not know, and a steward with no record, are not gated.

A current steward that receives a type it does not know (a controller newer than the steward) refuses it as unsupported with the distinct reason `invalid_command`, not as an authentication failure. That refusal is the steward's half of the same contract.

**Test coverage split.** The unsupported-command check for type 14 is at controller-test level, against the real dispatcher and run manager. The check for type 15 is at e2e level in the compat harness (story S6 of the epic): type 15 is not sent to the floor steward and no signature rejection appears after connect. The harness today runs the shared-command scenario only. There is no e2e type-14 scenario, and a reader should not expect one.

### 7. Residuals of the design

- **Mixed-controller window.** A floor steward connected to a controller node that predates the declaration has no record. That node treats it as current and signs version 2, and the steward refuses it. The refusal ends when the steward reconnects to an upgraded node. This is a one-time window at the first rollout of the declaration and does not recur.
- **Drain-in-grace.** A current steward on a slow host can declare after the grace period already settled its connection at the floor. A command the pending-delivery drain hook sent in version 1 during that time is refused. When the late declaration arrives, the controller marks each tracked row that is still `pending` or `delivered` as `rejected` with the detail `signing_form_refused_reissue`. The operator text is "command was not run and must be re-issued". The detail is written by the controller and is not one of the steward's reason codes, so the operator can tell it apart from tampering. The controller then replays the hooks that sign (`signing_rotation`, `migration`, `drain`, `transport_address`) once, now signed for the declared profile. The tracking is in memory and bounded; a controller restart between the send and the declaration loses it, and a version 1 command from a path with no delivery row is refused and not marked. The steward's own refusal still reaches the recorder.
- **Rollback tolerance.** The controller's receive loop ignores a control payload it does not know and keeps the stream open (`TestUnknownControlPayloadIgnored`). A newer steward that sends the declaration therefore talks to a controller rolled back to a build without it, and that controller treats it as it always did. The declaration is a message of its own because a heartbeat field could be dropped by admission queues.

### 8. Changing the floor

The floor is a **support-window change**, decided by the founder, never a side effect of another change. Moving it, for example when no supported release lacks signing payload version 2, is one change set that edits these together:

1. `test/compat/steward-support.yaml`: the new `floor`, the entries that remain, and their profiles. No entry may sort below the floor by semantic version; `TestRepositoryManifest` enforces it.
2. `types.FloorProfile()` (`pkg/controlplane/types/capabilities.go`): the command types and payload versions assumed for a steward that never declares.
3. These docs: this ADR, the two operating models and the [compat harness](../../testing/steward-compat.md), updating the floor named in each.

Moving the floor removes the §5 residual risk and, when the new floor handles version 2, lets the controller stop signing version 1. Removing the version 1 path is its own change and not part of the floor move. The change set is reviewed against the compat harness result for the new floor, built from its release tag.

**Adding a matrix entry.** A release that changes the command set or the signing payload gets a new `stewards` entry in the same release checklist that tags it: the tag, and the profile it runs under (`declared` for any release that sends the declaration). Entries are explicit; there is no computed "latest tag". The compat harness builds each tag with the tag's own `Makefile` recipe, and the merge-queue job is required only after a green history.

## Alternatives Considered

- **Version negotiation by steward version number.** The controller already holds the version. It identifies a build, not what the build handles, and it moves every release. A declaration derived from the build's own tables cannot go stale.
- **A reply to the declaration.** A controller reply would let the steward choose a form, but a steward that never receives one must still work, so the controller still needs the floor. The one-way message has one fewer state.
- **A record that outlives the connection.** It would save the grace wait on reconnect but lets a downgraded or replaced steward inherit the previous connection's profile. A per-connection record cannot be stale.
- **Signing both forms and letting the steward choose.** It lets a party that holds a captured command pick the weaker form.
- **Relaxing the current steward's stamped version 1 refusal.** It would remove the §7 window but weakens the term's authentication for every steward. The refusal stays.

## Consequences

**Easier:** a controller upgrade does not strand an older steward, and a steward upgrade is picked up on the next connection. An operator sees `unsupported`, `command_type_unsupported_by_peer` or `signing_form_refused_reissue` instead of a signature failure. The support window is one file and one function, checked by a harness that runs the real floor binary.

**Harder:** the controller carries two signing forms until the floor moves. A floor steward's term is not authenticated by the signature until then (§5). A command sent during the grace to a slow current steward may need to be re-issued (§7). Every release that changes the command set needs a matrix entry.

**Not covered:** the compat harness is Linux only. A Windows or macOS regression in compatibility is not caught by it.
