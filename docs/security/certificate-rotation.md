# Certificate Rotation

## Overview

CFGMS supports online rotation of the signing certificate — the CodeSigning-EKU
certificate that authenticates config and DNA payloads delivered to stewards.
Rotation replaces the active signing key while maintaining fleet continuity through
a configurable **overlap window** and an automatic **refresh-on-connect** mechanism
for stewards that were offline during rotation.

See [certificate-architecture.md](certificate-architecture.md) for the full purpose
model, key properties, and type enum stability rules.

## Rotation Model

### Signing Certificate Role

The signing certificate (`PurposeSigning`, `CertificateTypeConfigSigning`) is the
steward's trust anchor for config verification. Stewards pin this certificate when
they register with the controller. Any config payload signed by a different key is
rejected — this is an intentional fail-closed defense.

### Overlap Window

When a rotation is triggered, the controller mints a new signing cert and enters a
**rotation overlap** state. During this window:

- The controller signs new outgoing configs with the **new** cert.
- The controller accepts steward-facing operations that reference either the **old
  or the new** serial.
- Stewards that are online receive the new cert via the refresh-on-connect push
  immediately after the rotation completes.

The overlap window closes after `overlap_days` days (default: 30). After the window
closes, only the new cert serial is trusted.

### Retirement at Overlap End

When the window closes, the controller retires the superseded certificate from the fleet
instead of leaving stewards to trust it indefinitely. The controller node that holds
leadership checks the signing cursor once a minute. When a rotating serial exists, its
window has elapsed and it is not yet retired, that node sends every steward a
`push_signing_cert` carrying the current certificate and `retire_serials` naming the
rotating serial (a JSON array of strings), then marks the cursor retired with a
conditional write. Only the leader sweeps; a node without leadership sends nothing. The
sweep is skipped while the cluster still signs with per-node local keys (the legacy
identity), because retiring there would strand stewards that do not trust the current
key. The retirement is audit-logged as `signing_certificate_retired`.

A steward that is offline at that moment does not get a second command. The
refresh-on-connect push it receives when it reconnects already carries `retire_serials`
(the elapsed rotating serial plus every serial revoked as a signing certificate), so
connect still delivers one command, signed by a key that steward trusts.

### Refresh-on-Connect (Story B2d)

Stewards that are offline during rotation receive the updated signing cert
automatically when they reconnect via the ControlChannel. This is the primary
recovery path for offline stewards:

- **During overlap**: the steward reconnects, receives the new cert, and can verify
  configs signed by either cert (overlap acceptance).
- **After overlap expiry**: the steward reconnects, receives the new cert via
  refresh-on-connect, updates its trust anchor, and can then verify configs signed
  by the new cert.

Refresh-on-connect makes the overlap window a **defense-in-depth parameter** rather
than a hard deadline. Even if a steward is offline for longer than `overlap_days`,
it will recover on its next connection.

### Steward Trust-Set Rules

A steward applies a `push_signing_cert` command only when **both** checks pass:
the command signature verifies against a key the steward already trusts, and the
pushed certificate chains to the controller CA the steward pins, with the
CodeSigning key usage. The CA check applies even when the steward holds no trust
set yet, so omitting the command signature never bypasses it. Intermediates are
taken from the PEM bundle the controller pushes (leaf first, issuer chain after);
the controller therefore sends the issuer chain with each signing certificate it
pushes, so certificates issued by an imported intermediate CA verify. Only the
leaf is stored.

- **De-duplication**: the trust set is de-duplicated by the SHA-256 fingerprint of
  the certificate DER, on every push and when the persisted set is loaded at
  startup. Re-pushing a certificate, or pushing it with different PEM whitespace
  or a trailing chain, does not add an entry.
- **Rejected pushes**: a certificate that is expired, lacks CodeSigning, or does
  not chain to the pinned CA is rejected, as is any push when the steward has no
  valid pinned CA roots. A rejected push changes neither the in-memory nor the
  persisted trust set, and error text carries no certificate bytes.
- **`retire_serials`**: an optional JSON array of serial strings (decimal
  `SerialNumber.String()` form) naming certificates to remove from the trust set.
  Unknown serials are ignored. The certificate carried by the same command is never
  removed, and a command that would leave the set empty is rejected. Removal is
  persisted before it is applied in memory.
- **`retire_old`** is unchanged: it replaces the whole set with the pushed
  certificate.

### Rotation State Machine

The rotation lifecycle is guarded by a cursor with the following states:

| State | Description |
|-------|-------------|
| `Stable` | No rotation in progress; single active signing cert. |
| `Rotating` (RotatingSerial set) | Rotation in progress; overlap window open. |

A second `rotate` call while `RotatingSerial` is set is rejected with HTTP 409
"rotation in progress". Operators must wait for the first rotation to complete
before starting another.

### Clustered Controllers

When controller nodes share a signing identity (shared secret store), a rotation
requested through any node runs as one cluster-wide event:

1. The node takes the cluster-wide rotation claim (`config-signing/claims/rotation`,
   create-if-absent with a 2-minute TTL). If another node holds it, the request fails
   with HTTP 409 `ROTATION_IN_PROGRESS` before any key is generated. Retry once the
   other rotation finishes; an abandoned claim expires on its own.
2. The node generates the new certificate and stores it, with its key, in the shared
   key store (create-if-absent).
3. The node transitions the shared cursor (`CurrentSerial` = new, `RotatingSerial` =
   old; `force` bypasses only the overlap guard, not the claim).
4. The claim is released, on success or failure.

Every node resolves the new current certificate from the shared store (within a few
seconds, the resolve-cache interval), and any node can sign the fan-out and
refresh-on-connect pushes with the rotating certificate. No signing key is written to
a node's local disk.

If the cluster has not yet moved to the shared signing identity (nodes still sign with
local keys), rotation is refused with HTTP 409 `SIGNING_MIGRATION_PENDING` and nothing
changes. The move is described in
[Cluster Signing Identity Migration](../operations/cluster-signing-migration.md), including
the transition window in which a steward that trusts only a legacy node key rejects what the
cluster signs.

The cluster behaviour in this section, retirement at overlap end and emergency revoke are
exercised end to end by `features/steward/client/signing_identity_cluster_test.go` (three
controller nodes, shared stores, real steward handlers) and by the fleet suite
(`TestFleetRotation`, legs `RetirementAtOverlapEnd` and `EmergencyRevoke`). The design is
recorded in the cluster signing identity amendment of
[ADR-031](../architecture/decisions/031-controller-cluster-service-model.md).

A node that crashes between step 2 and step 3 leaves a stored key that no cursor
references. It is harmless — nothing signs with it and a later rotation generates a
fresh certificate — and it is not swept automatically.

Each successful rotation is audit-logged (`signing_certificate_rotated`) with the
operator's certificate serial, the old and new serials and the performing node's ID.

## CLI Reference

### `cfg controller signing-cert rotate`

```
USAGE:
  cfg controller signing-cert rotate [--overlap-days N] [flags]

FLAGS:
  --overlap-days int   Days the old signing certificate remains valid after rotation
                       (default: 30)
  --url string         Controller API URL (required, or set CFGMS_API_URL)
  --bundle string      Path to admin bundle file for mTLS auth (env: CFGMS_ADMIN_BUNDLE)
  --tls-ca-cert string Path to CA cert for TLS verification
  --tls-insecure       Skip TLS verification (dev only)
```

**Example output:**

```
Signing certificate rotated successfully

Old serial:        3a4b5c6d7e8f...
New serial:        9a0b1c2d3e4f...
Overlap days:      30
Stewards notified: 12
```

### Examples

```bash
# Rotate with default 30-day overlap (recommended for most fleets)
cfg controller signing-cert rotate --url https://controller.example.com

# Rotate with a 14-day overlap window
cfg controller signing-cert rotate --url https://controller.example.com --overlap-days 14

# Expire the old certificate immediately (test environments only — breaks offline stewards)
cfg controller signing-cert rotate --url https://controller.example.com --overlap-days 0

# With explicit admin bundle (mTLS auth)
cfg controller signing-cert rotate --bundle /etc/cfgms/admin.bundle.yaml
```

## Operator Runbook

### Planned Rotation

**Recommended frequency:** Annually, or when a signing key is suspected compromised.

**Before you start:**

1. Determine the longest expected offline duration for any steward in the fleet.
2. Set `--overlap-days` to at least that value (see [Choosing overlap-days](#choosing---overlap-days)).
3. Verify all stewards are currently connected (`cfg controller steward list`).
4. Confirm no other rotation is in progress (second rotate call returns HTTP 409).

**Procedure:**

```bash
# 1. Trigger rotation
cfg controller signing-cert rotate \
  --url https://controller.example.com \
  --overlap-days 30

# 2. Verify output shows distinct old/new serials and the expected steward count
#    Old serial:        <old>
#    New serial:        <new>
#    Overlap days:      30
#    Stewards notified: <N>

# 3. Monitor steward connectivity — all online stewards should remain connected
cfg controller status --url https://controller.example.com

# 4. After overlap_days have passed, the old cert serial is automatically
#    deactivated by the controller. No manual step required.
```

**Post-rotation checklist:**

- [ ] All online stewards received refresh push (check controller logs: `signing_cert_refreshed`)
- [ ] Config pushes succeed for all stewards
- [ ] No steward reports cert verification failures

### Emergency Key Compromise Rotation

If the signing key is suspected compromised:

1. Rotate immediately with `--overlap-days 0`:
   ```bash
   cfg controller signing-cert rotate --overlap-days 0
   ```
   This expires the compromised cert instantly. **Offline stewards will be unable to
   verify configs until they reconnect and receive the new cert via refresh-on-connect.**

2. Bring offline stewards online as soon as possible so refresh-on-connect can deliver
   the new cert.

### Emergency Revoke of a Superseded Signing Certificate

To withdraw one named signing certificate from the whole fleet without waiting for its
overlap window, revoke it. The current signing certificate cannot be revoked in one step,
so the runbook is:

1. Rotate with no overlap, so the compromised certificate becomes the superseded one:
   ```bash
   cfg controller signing-cert rotate --overlap-days 0
   ```
2. Revoke the old serial (admin certificate, root scope; the same gates as rotation):
   ```bash
   curl --cert admin.crt --key admin.key --cacert ca.crt -X POST \
     https://controller.example.com/api/v1/certificates/signing/revoke \
     -H 'Content-Type: application/json' \
     -d '{"serial": "<old serial>", "reason": "key exposed in a build log"}'
   ```

The controller records the serial in the revocation store with a signing-certificate
reason, retires it from the cursor when it is the rotating serial, and sends
`retire_serials` to every steward. The response reports `stewards_notified`. Attempting
to revoke the current serial returns `409 CURRENT_SIGNING_CERT`. The revoke is audit-logged
as `signing_certificate_revoked`.

From the moment a serial is revoked the controller does not sign anything with it. The one
exception is the push that retires that same serial for a steward that was offline and
trusts nothing else; that single delivery is signed by the serial it retires so the steward
can verify it.

**Offline stewards:** a steward that was offline for the revoke receives the retirement on
its next connect, in the same single push that refreshes its signing certificate.

### Offline Steward Recovery

If a steward was offline during rotation and reconnects after the overlap window:

**With refresh-on-connect (story B2d):** The steward reconnects, receives the new
signing cert automatically, and resumes normal operation. No manual intervention needed.

**Without refresh-on-connect (pre-B2d controllers):** The steward's pinned cert no
longer matches the controller's active signing cert. The steward will reject all
config pushes. Recovery options:
1. Re-register the steward (issues a fresh client cert and delivers the current signing cert).
2. Upgrade the controller to a version with refresh-on-connect.

### Choosing `--overlap-days`

The overlap window is a defense-in-depth buffer between rotation and old-cert expiry.
With refresh-on-connect enabled, even overlap_days=0 is recoverable — but a positive
overlap window gives stewards more time to receive the update passively.

**Guideline:** Set `--overlap-days` to exceed your fleet's maximum expected offline duration.
Align with your heartbeat SLO if you have one.

| Fleet profile | Recommended `--overlap-days` |
|---------------|------------------------------|
| Always-online (servers, containers) | 7–14 days |
| Standard mixed fleet | 30 days (default) |
| Fleet with extended offline endpoints (laptops, field devices) | 60–90 days |
| Test environment | 0 (immediate expiry) |

## Failure Modes

| Failure | Symptom | Recovery |
|---------|---------|----------|
| Second rotate call during active rotation | HTTP 409 "rotation in progress" | Wait for first rotation to complete or contact support |
| Rotate while another cluster node is rotating | HTTP 409 `ROTATION_IN_PROGRESS` | Retry after the other rotation finishes (claim TTL: 2 minutes) |
| Rotate before the cluster has a shared signing identity | HTTP 409 `SIGNING_MIGRATION_PENDING` | Complete the signing identity migration first |
| Steward offline past overlap, pre-B2d controller | Config push rejected after reconnect | Re-register steward, or upgrade controller |
| Steward offline past overlap, B2d controller | Normal reconnect, refresh-on-connect delivers cert | No action needed — automatic |
| Network partition during rotation | Some stewards not notified | Stewards receive cert on reconnect via refresh-on-connect |
| Old cert used after overlap expiry | Steward rejects payload with signature verification error | Ensure refresh-on-connect has run; check steward logs |

## Implementation Notes

- The rotation endpoint is `POST /api/v1/certificates/signing/rotate` (implemented in story B2b, Issue #1816).
- The overlap model and `RotatingSerial` cursor are implemented in the lifecycle state machine (story B1, Issue #1814).
- Refresh-on-connect is implemented in story B2d (Issue #1817).
- The certificates-by-type lookup is unexported (`getCertificatesByType` in `pkg/cert`) to enforce purpose-based access; `TestNoGetCertificatesByTypeOutsideCertPackage` in `pkg/cert/architecture_test.go` enforces the boundary.
