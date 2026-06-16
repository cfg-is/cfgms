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

### Rotation State Machine

The rotation lifecycle is guarded by a cursor with the following states:

| State | Description |
|-------|-------------|
| `Stable` | No rotation in progress; single active signing cert. |
| `Rotating` (RotatingSerial set) | Rotation in progress; overlap window open. |

A second `rotate` call while `RotatingSerial` is set is rejected with HTTP 409
"rotation in progress". Operators must wait for the first rotation to complete
before starting another.

## CLI Reference

### `cfg controller signing-cert rotate`

```
USAGE:
  cfg controller signing-cert rotate [--overlap-days N] [flags]

FLAGS:
  --overlap-days int   Days the old signing certificate remains valid after rotation
                       (default: 30)
  --url string         Controller API URL (required, or set CFGMS_API_URL)
  --api-key string     API key for authentication
  --bundle string      Path to admin bundle file for mTLS auth
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
2. Set `--overlap-days` to at least that value (see [Choosing overlap-days](#choosing-overlap-days)).
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

3. If a steward cannot reconnect and its cert is known compromised, revoke its client
   certificate:
   ```bash
   # (future: cfg controller steward revoke --id <steward-id>)
   ```

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
| Steward offline past overlap, pre-B2d controller | Config push rejected after reconnect | Re-register steward, or upgrade controller |
| Steward offline past overlap, B2d controller | Normal reconnect, refresh-on-connect delivers cert | No action needed — automatic |
| Network partition during rotation | Some stewards not notified | Stewards receive cert on reconnect via refresh-on-connect |
| Old cert used after overlap expiry | Steward rejects payload with signature verification error | Ensure refresh-on-connect has run; check steward logs |

## Implementation Notes

- The rotation endpoint is `POST /api/v1/certificates/signing/rotate` (implemented in story B2b, Issue #1816).
- The overlap model and `RotatingSerial` cursor are implemented in the lifecycle state machine (story B1, Issue #1814).
- Refresh-on-connect is implemented in story B2d (Issue #1817).
- The `GetCertificatesByType` internal API will be unexported in story B3 to enforce purpose-based access.
