# ADR-034: Steward Identity Clones — Detection, Split and Removal

**Status:** Accepted

**Date:** 2026-10-11 (amended 2026-10-11: hardware-backed keys, limits, rolling token rejected)

**Deciders:** Founder, Architecture

**Related:** Issue [#4556](https://github.com/cfg-is/cfgms/issues/4556) (steward identity lifecycle — this ADR is its design step). ADR-011 (registration-refresh: device key, lifecycle states §3, revocation-before-PoP §5, provenance §7, Amendment 1 re-admission). Issue #4930 (revoked certificate serials refused at control-plane admission — the removal path depends on it). Issue #4532 (re-admission and approval delivery).

---

## Context

A steward's identity is its device key (ADR-011 §1; Ed25519, or P-256 when hardware-backed per ADR-011 Amendment 3) plus its mTLS client certificate. Two real situations produce more than one endpoint presenting the same identity:

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

### 7. Hardware-backed device keys when the endpoint has them; file-backed otherwise

A copy can exist only because the device key is a file. Where the endpoint has a hardware key store, the steward generates the device key **inside it, non-exportable**, through the ADR-011 §2 `KeyStore` interface:

- Windows: TPM 2.0 through the platform crypto provider.
- Linux: TPM 2.0.
- macOS: Secure Enclave.

Hardware stores generate P-256 keys, not Ed25519. The key algorithm, the DeviceID encoding, the libraries and the fallback rules are fixed in ADR-011 Amendment 3.

The key never leaves the hardware, so copying the steward's files does not copy the identity: a copy cannot answer the proof-of-possession challenge (ADR-011 §4–5) and is refused. For these endpoints, clone detection becomes certain — the machine that can sign with the key is the original.

An endpoint without usable hardware falls back to the file-backed `KeyStore` (ADR-011 v1). This is automatic and needs no operator action; the steward never fails to enroll because hardware is missing.

The steward reports the result in ADR-011's `key_protection_level` (`tpm`, `secure-enclave` or `file`), and the controller stores it on the `StewardRecord` and shows it to the operator. A tenant setting that **requires** a hardware-backed level for new enrollments is a possible later addition; it is out of scope here and defaults to off.

A steward never moves an existing file-backed key into hardware in place (the old file would remain a valid copy). An endpoint that gains a TPM gets a hardware-backed key by re-enrolling through the normal flow.

## Consequences

**Positive**
- A copied identity cannot silently receive another machine's configuration or commands.
- Planned cloning has a supported, no-surprise path.
- The rule reuses the existing approval queue, provenance matcher and re-admission flow; no new approval mechanism.

**Negative**
- A byte-for-byte copy that connects while the original is offline cannot be told apart by provenance; it holds the identity until the original reconnects, which triggers detection. The original then keeps the open stream only if it connected first. The operator alert and the rotate-and-revoke removal path bound this window.
- Provenance attributes change on legitimate hardware repairs (a new NIC or disk). That machine lands in the approval queue, the same friction ADR-011 §7 already accepts.

## Limits — when the original cannot be proven

For a **file-backed** key, every copy holds the same key and certificate, so no cryptographic check separates them. The controller cannot prove which machine is the original in these cases:

1. **An exact copy** (a VM clone or a disk image of the running machine). Hardware attributes often match too; §2 falls back to the already-connected endpoint, which is ordering, not proof.
2. **A stolen identity that reports false hardware attributes.** Host attributes are reported by the steward process; an attacker who holds the key controls that process. If the original is offline, the copy connects first and keeps the identity until the original reconnects and detection fires.
3. **The original changed hardware** (a disk or network card replaced). The original looks like the copy and lands in the approval queue.
4. **A VM rolled back to an earlier snapshot.** It is the same machine at an earlier point and looks like a copy taken before a rotation.

In each case the controller reports the ambiguity plainly (both endpoints, the provenance diff, the serials) and the operator decides by checking the machines directly, using §5. No copy is auto-trusted for a split. For a **hardware-backed** key (§7), none of these cases exist: only the machine holding the hardware key can prove possession.

## Alternatives considered

- **A rolling per-connection token** (the controller issues a one-time token on every connection; the steward must present it next time, so diverged copies are detected for certain). Rejected: it makes the connection fragile. A steward that crashes or loses its disk write after receiving a token but before persisting it is locked out on its next connection, and network retries can consume a token twice. It also detects a split without proving which side is the original.

## Implementation (to be decomposed into stories under #4556)

1. Duplicate-connection detection at `ControlChannel` and the operator alert and audit event (§3).
2. Provenance comparison at control-plane admission, not only at refresh (§2).
3. The "identity in use by another device" refusal reason, and the steward's re-key-and-register response with `clone_of` (§4).
4. Operator commands: list detected clones, move the identity to the other machine, and rotate-and-revoke (§5).
5. The image-preparation step in the installer (§6).
6. Hardware-backed `KeyStore` implementations (TPM 2.0 on Windows and Linux, Secure Enclave on macOS) with automatic file-backed fallback, and `key_protection_level` stored on the record and shown to the operator (§7).

Revocation at admission (#4930) is a prerequisite for §5 and is already in progress.
