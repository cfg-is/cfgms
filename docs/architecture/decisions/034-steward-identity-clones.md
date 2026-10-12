# ADR-034: Steward Identity Clones — Detection, Split and Removal

**Status:** Proposed

**Date:** 2026-10-11

**Deciders:** Founder, Architecture

**Related:** Issue [#4556](https://github.com/cfg-is/cfgms/issues/4556) (steward identity lifecycle — this ADR is its design step). ADR-011 (registration-refresh: device key, lifecycle states §3, revocation-before-PoP §5, provenance §7, Amendment 1 re-admission). Issue #4930 (revoked certificate serials refused at control-plane admission — the removal path depends on it). Issue #4532 (re-admission and approval delivery).

---

## Context

A steward's identity is its Ed25519 device key (ADR-011 §1) plus its mTLS client certificate. Two real situations produce more than one endpoint presenting the same identity:

- **Planned clones.** A base image is built from a machine that already enrolled a steward, then cloned into many machines. Every clone starts with the same device key and certificate.
- **A copied identity.** The key and certificate are copied off a compromised host. The copy may run on different hardware, or on a byte-for-byte copy of the original.

Today the controller cannot tell copies apart. Every copy matches the same `StewardRecord`, and whichever one is connected receives that steward's configuration and commands. The threat model (`CLAUDE.md`) assumes stewards may run on compromised hosts, so a copied identity is in scope.

## Decision

### 1. One rule: the approved identity keeps its record; every other copy goes through device approval

- **Identity never approved** (no `StewardRecord` yet, only a pending registration): each copy is an unknown device. Each one goes through the normal device approval flow (`PendingRegistrationStore`, `cfg registration approve|deny`) on its own. No special handling.
- **Identity already approved:** the machine that matches the approved record keeps the identity and keeps working without interruption. Every other copy is refused the identity and is placed in the **device approval queue** as a new device. An operator then either approves it (a **split**: it becomes a new, unique identity) or denies it (a **removal**).

No copy is ever silently given an approved identity. The operator is the only path from "copy" to "managed device".

### 2. Which machine is "the approved one"

Both copies hold the same key and certificate, so the cryptographic proof cannot decide. The controller decides from these signals, in order:

1. **Provenance match** (ADR-011 §7 host attributes: machine UUID, disk serials, NIC MACs, install date, certificate-serial lineage). The approved record stores the attributes last accepted for it. A connection whose attributes match the record is the approved machine; a connection whose attributes diverge is a copy, **even if it connects while the original is offline**. This keeps a copy on different hardware from taking over the identity while the real machine is down.
2. **Already connected.** When provenance cannot separate them (a byte-for-byte clone), the endpoint that already holds the control channel keeps it, and the newcomer is the copy.

Provenance stays demote-only, as ADR-011 §7 requires: it can send a connection to the approval queue, and it can never admit a connection that the lifecycle and revocation gates refuse.

### 3. Detection signals

The controller treats an identity as in use by more than one endpoint when any of these holds:

- **Concurrent control channels.** A second `ControlChannel` opens for a steward ID that already has an open stream from a different peer address or session.
- **Provenance divergence.** A connection or refresh presents host attributes that fall below the ADR-011 §7 match threshold against the approved record.
- **Lineage divergence.** A connection presents a certificate serial that is older than one the controller has already seen superseded for that record (a copy taken before a rotation).

Each detection is recorded as an audit event and surfaced to the operator (UI alert and `cfg` listing) with the evidence: both peer addresses, the provenance diff, and the serials.

### 4. What the steward does when it is refused as a copy

The controller refuses the copy at control-plane admission with a distinct reason ("identity in use by another device"). A steward that receives this reason:

1. Generates a **new device key** and a new CSR. It never reuses the copied key.
2. Registers as a new device, referencing the original steward ID as `clone_of` so the operator sees the relationship.
3. Waits in the device approval queue, using the existing claim flow (#4532 / ADR-011 Amendment 1).

A copy controlled by an attacker can ignore step 1 and keep retrying with the copied identity. It stays refused under §2. The removal path in §5 cuts it off for good.

### 5. Split and removal

- **Split (approve the queued copy):** the copy gets a new `StewardRecord` with its own device key and certificate. The original record continues unchanged.
- **Removal (deny the queued copy):** the pending entry is denied. If the operator judges that the copy holds the original's credentials, the operator **rotates** the original: the controller issues the approved machine a new certificate and **revokes the old serial**. Revoked serials are refused at control-plane admission (#4930), so the copy's stolen certificate stops working. The approved machine proves possession of its device key for the new certificate (ADR-011 §4–5); a copy without the key gets nothing.
- **Wrong original:** if the operator decides the machine that kept the identity is the copy, the operator moves the identity: approve the queued machine as the identity's holder, then revoke the other. This is an explicit operator action, never automatic.

Certificate rotation revokes the old serial at the end of its overlap window, so a copy taken before a rotation stops working when that window closes.

Decommission stays the path that rejects a whole device.

### 6. Planned clones: prepare the image before cloning

The steward installer gains an **image-preparation step** (for example `cfgms-steward prepare-image`). It removes the enrolled identity (device key, certificate and steward ID) and leaves only the trust anchor and the registration token. Every clone made from the prepared image enrolls as a unique device on first boot, through the normal registration and approval flow, with no operator intervention beyond the usual approval policy.

A clone made from an image that was **not** prepared is handled by §1: it is a copy and goes to the approval queue.

## Consequences

**Positive**
- A copied identity cannot silently receive another machine's configuration or commands.
- Planned cloning has a supported, no-surprise path.
- The rule reuses the existing approval queue, provenance matcher and re-admission flow; no new approval mechanism.

**Negative**
- A byte-for-byte copy that connects while the original is offline cannot be told apart by provenance; it holds the identity until the original reconnects, which triggers detection. The original then keeps the open stream only if it connected first. The operator alert and the rotate-and-revoke removal path bound this window.
- Provenance attributes change on legitimate hardware repairs (a new NIC or disk). That machine lands in the approval queue, the same friction ADR-011 §7 already accepts.

## Implementation (to be decomposed into stories under #4556)

1. Duplicate-connection detection at `ControlChannel` and the operator alert and audit event (§3).
2. Provenance comparison at control-plane admission, not only at refresh (§2).
3. The "identity in use by another device" refusal reason, and the steward's re-key-and-register response with `clone_of` (§4).
4. Operator commands: list detected clones, move the identity to the other machine, and rotate-and-revoke (§5).
5. The image-preparation step in the installer (§6).

Revocation at admission (#4930) is a prerequisite for §5 and is already in progress.
