# Control Plane Threat Model

How the control plane defends against steward identity and impersonation attacks, and which threats are explicitly out of scope for this release.

This document records design decisions made during Epic #747 (pkg/controlplane — prevent steward impersonation). Future contributors should read this before proposing message-signing or replay-protection changes.

## Context

The control plane carries lightweight messages between controller and stewards: heartbeats, commands, events, DNA deltas. The primary security concern is **steward identity**: can a malicious or compromised endpoint impersonate another steward?

Epic #747 addresses this through CN-binding enforcement at the TLS session level (stories #827, #828, #829).

## Authentication Boundary

The primary authentication boundary is the **mTLS session**.

Every controller-steward connection uses mutual TLS over QUIC (port 4433). Both sides present certificates:

- The **controller** presents a certificate signed by the fleet CA.
- The **steward** presents a certificate signed by the fleet CA, with its steward ID embedded in the Common Name (CN) field.

The controller enforces CN-binding: the CN in the steward's certificate must match the steward ID claimed in every message sent over that session. A steward that presents cert CN `steward-abc` cannot send messages claiming to be `steward-xyz`. This enforcement is implemented in stories #827, #828, and #829 of Epic #747.

This means:

- **Authentication happens at session establishment**, not per-message.
- **Identity is bound to the certificate**, not to a claim inside the message payload.
- All messages on a session inherit the identity proven at handshake time.

## Attack Scenarios

### 1. Hijacked Steward

**Scenario:** An attacker gains code execution on a legitimate steward and uses its existing certificate to communicate with the controller.

**Mitigation:** The attacker can act only as that steward. CN-binding prevents using the stolen session to impersonate any other steward. The blast radius is limited to the compromised device's own identity and configuration scope.

**Remaining exposure:** The attacker has full steward-level access for the compromised device until the certificate is rotated or revoked. Detection relies on behavioral anomalies, not message signing.

### 2. Stolen Certificate

**Scenario:** An attacker extracts a steward's private key and certificate (e.g., via disk access, memory dump, or backup compromise) and uses them from a different machine.

**Mitigation:** The attacker can register and emit as exactly that steward — no others. They cannot pivot to other steward identities because each steward has a unique certificate with a unique CN. Detection relies on certificate rotation and revocation policies, not per-message signing.

**Remaining exposure:** Until revocation, the attacker has steward-level access for that one identity. Revocation and rotation procedures are operational controls outside the scope of this epic.

### 3. Replayed Message Within a Single TLS Session

**Scenario:** An attacker captures a message in transit on an active TLS session and re-injects it on the same session (e.g., to re-issue a command or duplicate an event).

**Mitigation:** Exploiting this requires compromising TLS itself — breaking TLS record-layer integrity or gaining access to the session keys. At that point, per-message signing provides marginal added value over the integrity guarantees already provided by TLS. This scenario is **OUT OF SCOPE** for this release (see rationale below).

### 4. Stale Message Across Sessions

**Scenario:** An attacker captures a message from an earlier session and attempts to replay it after that session has terminated (e.g., to re-execute a command on a reconnected steward).

**Mitigation:** TLS session state naturally prevents cross-session replay. A message encrypted under session N cannot be decrypted or injected into session N+1 because the session keys differ. This scenario is **OUT OF SCOPE** for this release (see rationale below).

## OUT OF SCOPE for This Release

### Per-Message Signing

Per-message signing (HMAC, digital signatures over individual message payloads) is **explicitly OUT OF SCOPE** for this release.

**Rationale:**

1. mTLS with CN-binding (stories #827, #828, #829 of this epic) closes the impersonation vector at the session level. A malicious or misbehaving steward can no longer claim another steward's ID.
2. Per-message signing adds CPU cost at 50k-steward scale without a defined threat it mitigates beyond what TLS already covers.
3. Replay within a TLS session requires compromising TLS itself; at that point, signing the inner messages offers marginal added value over the TLS integrity guarantees.
4. A future story can introduce signing if a specific threat emerges (e.g., compliance requirement, MITM through controller proxy). Opening that story is a PO decision, not a dev-agent decision.

### Replay Protection (Nonce / Monotonic Sequence)

Per-message replay protection via nonces or monotonic sequence numbers is **explicitly OUT OF SCOPE** for this release.

**Rationale:**

1. mTLS with CN-binding (stories #827, #828, #829 of this epic) closes the impersonation vector at the session level. A malicious or misbehaving steward can no longer claim another steward's ID.
2. Per-message signing adds CPU cost at 50k-steward scale without a defined threat it mitigates beyond what TLS already covers.
3. Replay within a TLS session requires compromising TLS itself; at that point, signing the inner messages offers marginal added value over the TLS integrity guarantees.
4. A future story can introduce signing if a specific threat emerges (e.g., compliance requirement, MITM through controller proxy). Opening that story is a PO decision, not a dev-agent decision.

The same rationale applies to both mechanisms: the TLS session boundary already provides the replay protection relevant to the current threat model. Adding application-layer counters or nonces would duplicate TLS's existing guarantees without closing a real gap.

## What This Epic Does Not Address

This document is a record of deliberate scope decisions. The following are not bugs or omissions — they are known boundaries:

- **Certificate revocation latency** — there is no real-time revocation check on every message. A revoked cert can continue to operate until the TLS session is terminated.
- **Insider threat at the controller** — a compromised controller can issue arbitrary commands. This is outside the steward-impersonation threat model.
- **Message confidentiality beyond TLS** — messages are not double-encrypted. TLS provides the confidentiality layer.
- **Compliance-driven signing** — if a future compliance requirement mandates signed messages, a new epic should be opened. This is a PO decision.

## Cross-References

- [Operating Model](operating-model.md) — component roles and communication model
- [Steward Operating Model](steward-operating-model.md) — steward convergence loop and identity
- [Controller Operating Model](controller-operating-model.md) — controller startup, fleet management
- Epic #747 — parent epic: prevent steward impersonation (Register + ControlChannel identity)
- Stories #827, #828, #829 — CN-binding enforcement implementation
