# Control Plane Threat Model

Security boundaries, attack scenarios, and deliberate out-of-scope decisions for the
`pkg/controlplane` communication layer.

For the system-level operating model, see [operating-model.md](operating-model.md).
For control plane implementation details, see [pkg/controlplane/README.md](../../pkg/controlplane/README.md).

## Context

The control plane carries lightweight messages between controllers and stewards:
heartbeats, commands, events, and DNA deltas. All communication flows over a
gRPC-over-QUIC connection on port 4433 with mutual TLS (mTLS) required on both sides.

Epic #747 (pkg/controlplane — prevent steward impersonation) hardens the identity
boundary at the session level. Stories #827, #828, and #829 of that epic deliver
Common Name (CN) binding: the controller enforces that each steward's TLS certificate
CN matches the steward ID it presents at registration and on every subsequent message.

## Primary Authentication Boundary

**mTLS is the session-level authentication boundary.** Both the controller and steward
present certificates signed by the CFGMS certificate authority (`pkg/cert.Manager`).
Handshake failure terminates the connection before any application-level message is
exchanged. There is no unauthenticated fallback.

**CN-binding tightens this boundary at the application level.** A valid mTLS session
proves the steward holds the private key for its certificate. CN-binding additionally
proves the certificate CN matches the steward ID the process claims to be. A steward
that presents a cert with CN `steward-A` cannot register or send messages as `steward-B`.

Together, mTLS + CN-binding form a two-layer identity guarantee:

| Layer | Enforced by | What it proves |
|-------|-------------|----------------|
| Transport | mTLS handshake | Steward holds a CA-signed private key |
| Application | CN-binding (epic #747) | Steward's claimed ID matches its certificate CN |

## Attack Scenarios

### Scenario 1 — Hijacked Steward

**Attack:** An attacker gains code-execution on a legitimate steward device and uses
its certificate and identity to communicate with the controller.

**Mitigation:** The attacker can act only as the hijacked steward. CN-binding means
the certificate's CN constrains which steward ID can be asserted. The attacker cannot
impersonate any other steward in the fleet. Blast radius is limited to the single
compromised device.

**Residual risk:** The attacker can emit authentic-looking heartbeats and events for
that steward. Detection relies on behavioral anomalies, not message authentication.
Remediation is certificate revocation and device re-imaging.

---

### Scenario 2 — Stolen Certificate

**Attack:** An attacker extracts a steward's private key and certificate from the
device (e.g., via disk access or memory dump) and uses them from a different host.

**Mitigation:** The attacker can register and communicate as exactly that steward, and
no others. CN-binding prevents lateral movement to other steward identities. Detection
relies on concurrent-connection anomalies, certificate rotation, and revocation —
not on per-message signing.

**Residual risk:** Until the certificate is revoked, the stolen cert grants access
equivalent to the legitimate steward. The recommended response is certificate rotation
on a regular schedule and immediate revocation upon detection.

---

### Scenario 3 — Replayed Message Within a Single TLS Session

**Attack:** An attacker with access to the TLS session (e.g., via a compromised
controller proxy) captures a control plane message (heartbeat, command, event) and
re-injects it on the same TLS session.

**Mitigation:** This scenario requires the attacker to have already compromised TLS
integrity. TLS provides record-layer integrity and sequencing guarantees; an in-session
replay requires breaking those guarantees first. Defending against this with per-message
nonces or monotonic sequence numbers offers marginal added value over the TLS integrity
guarantees already in place.

**Decision:** **OUT OF SCOPE for this release.** See [Out-of-Scope Decisions](#out-of-scope-decisions).

---

### Scenario 4 — Stale Message Across Sessions

**Attack:** An attacker captures a control plane message from an earlier TLS session
and attempts to replay it after that session has terminated (i.e., using a new TLS
connection to replay an old message).

**Mitigation:** TLS session state is ephemeral. A message captured in session A cannot
be injected into session B because the session keys differ. Cross-session replay
requires the attacker to establish their own authenticated mTLS session, which
requires a valid CA-signed certificate — returning to Scenario 1 or 2.

**Decision:** **OUT OF SCOPE for this release.** See [Out-of-Scope Decisions](#out-of-scope-decisions).

---

## Out-of-Scope Decisions

### Per-Message Signing — OUT OF SCOPE for this release

Per-message HMAC or asymmetric signing of control plane messages is deliberately not
implemented in this release. The rationale is:

1. mTLS with CN-binding (stories #827, #828, #829 of this epic) closes the
   impersonation vector at the session level. A malicious or misbehaving steward can
   no longer claim another steward's ID.
2. Per-message signing adds CPU cost at 50k-steward scale without a defined threat it
   mitigates beyond what TLS already covers.
3. Replay within a TLS session requires compromising TLS itself; at that point, signing
   the inner messages offers marginal added value over the TLS integrity guarantees.
4. A future story can introduce signing if a specific threat emerges (e.g., compliance
   requirement, MITM through controller proxy). Opening that story is a PO decision,
   not a dev-agent decision.

### Replay Protection (Nonce / Monotonic Sequence) — OUT OF SCOPE for this release

Per-message nonce or monotonic sequence number fields are deliberately not added to
control plane message types in this release. The rationale is identical:

1. mTLS with CN-binding (stories #827, #828, #829 of this epic) closes the
   impersonation vector at the session level. A malicious or misbehaving steward can
   no longer claim another steward's ID.
2. Per-message signing adds CPU cost at 50k-steward scale without a defined threat it
   mitigates beyond what TLS already covers.
3. Replay within a TLS session requires compromising TLS itself; at that point, signing
   the inner messages offers marginal added value over the TLS integrity guarantees.
4. A future story can introduce signing if a specific threat emerges (e.g., compliance
   requirement, MITM through controller proxy). Opening that story is a PO decision,
   not a dev-agent decision.

These decisions are PO-ratified (Issue #830). Future contributors who encounter this
document should treat them as deliberate, not as oversights. If a new threat emerges
that these controls do not address, open a new epic with the PO — do not reopen this
one.

## Threat Summary Table

| Attack | Mitigated? | Mechanism |
|--------|-----------|-----------|
| Hijacked steward impersonates another steward | Yes | CN-binding (epic #747) |
| Stolen cert used to impersonate another steward | Yes | CN-binding (epic #747) |
| Stolen cert used to act as the cert's own steward | Partially | Cert rotation + revocation |
| In-session message replay | Out of scope | TLS integrity; marginal value |
| Cross-session message replay | Out of scope | TLS session isolation |
| Unauthenticated connection | Yes | mTLS mandatory, no fallback |
