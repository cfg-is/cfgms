# ADR-011: Registration-Refresh for Stewards Offline Past mTLS Cert Expiry

**Status:** Accepted

**Date:** 2026-06-20

**Deciders:** Founder, Architecture

**Related:** [001](001-central-provider-compliance-enforcement.md) (secrets central provider), [010](010-steward-side-provisioning-enrollment.md) (enrollment, which this protocol follows). Epic: #1845. Stories: S2 (steward detect + handshake), S3 (controller endpoint + policy), S4 (cfg CLI), S5 (fleet E2E).

---

## Context

A steward that was offline past its mTLS cert expiry is today completely locked out: its certificate is expired, mTLS handshakes fail, and re-registration from scratch loses fleet identity (tenant, group, audit history, pinned config). MSPs managing 50k+ endpoints across multiple time zones cannot guarantee all devices stay online within cert validity windows — devices hibernate, sites lose WAN for weeks, devices are in a warehouse.

Three design questions had to be settled before any implementation could proceed, because the answers span multiple stories (S2–S5) and getting them wrong mid-implementation would require rewrites:

1. **Device identity**: what credential proves "I am the same device that originally registered" when the mTLS cert is expired?
2. **Proof of possession**: how does the controller verify that credential without trusting the expired cert at the TLS layer?
3. **Revocation gate ordering**: how do we prevent the refresh path from becoming a re-registration bypass for a genuinely revoked steward?

This ADR records the founder-approved answers so that S2–S5 implementers have no open design questions and any future change to the security model requires an explicit ADR update.

---

## Decision

### 1. Stable Ed25519 device identity key, separate from the rotating mTLS cert

Each steward holds an **Ed25519 device identity key pair** (`device_id_ed25519.key` / `.pub`) that is generated once at first registration and never replaced. This is categorically different from the mTLS client certificate, which is short-lived and rotated:

| | mTLS cert | Device identity key |
|---|---|---|
| Purpose | Transport authentication | Device identity across cert rotations |
| Lifetime | Short (e.g. 90 days) | Permanent (per device) |
| Rotation | Yes, on renewal / refresh | Never |
| Used by | gRPC-over-QUIC TLS handshake | Registration-refresh PoP only |

The **64-char lowercase hex SHA-256 hash of the Ed25519 public key** is the `DeviceID`. It is stable across mTLS cert rotations and is the primary key in `GetStewardByDeviceID`. The controller stores the public key in the steward record at first registration.

The key is stored locally on the steward with a `key_protection_level` attribute:

```
key_protection_level: file   # v1 — encrypted at rest via OS-level disk encryption
# key_protection_level: tpm  # future drop-in when TPM is supported
```

### 2. File-backed KeyStore in v1; TPM as a future drop-in

The `KeyStore` interface abstracts key material storage:

```go
type KeyStore interface {
    LoadDeviceKey() (ed25519.PrivateKey, error)
    StoreDeviceKey(key ed25519.PrivateKey) error
    KeyProtectionLevel() string
}
```

V1 ships `FileKeyStore` (`key_protection_level: "file"`), which persists the private key to the steward's state directory. TPM-backed storage is a future drop-in that implements the same interface with `key_protection_level: "tpm"` — no other code changes required. V1 does not implement TPM; TPM integration is explicitly out of scope for this epic.

### 3. Lifecycle state machine — new states for this epic

The existing steward lifecycle (`registered` → `active` → `lost` / `deregistered`) is extended with three new states:

```
registered ──► active ──► lost ──────────────────────────────┐
                   │                                          │
                   └──► archived ──► (pending-refresh queue) │
                          │                                   │
                          └──► dormant  (backstop, default OFF)
                                  │
                          revoked ◄┘──── (any state → revoked is always allowed)
```

| New State | Meaning | Refresh allowed? |
|-----------|---------|-----------------|
| `archived` | Offline past mTLS cert expiry; identity intact | Yes — queued for approval |
| `dormant` | Offline past `MaxDormancyDays` threshold (backstop) | No — must re-register |
| `revoked` | Explicitly revoked by admin | No — 403 immediately |

**Provenance is demote-only:** state transitions can only move a steward to a more-restricted state. An admin cannot directly promote `archived` → `active`; promotion happens only via a completed refresh that results in cert issuance. `revoked` is a terminal state — no direct path back to `active` (re-registration after revocation requires manual admin action).

**Dormancy backstop** (`MaxDormancyDays`): an optional config knob that auto-demotes `archived` → `dormant` after N days of no contact. Default is **OFF** (`MaxDormancyDays: nil`). When nil, stewards stay `archived` indefinitely. MSPs with stricter policies can set this; it is never a silent surprise default.

**Pending-refresh queue:** when an `archived` steward initiates refresh and policy is `require_approval`, a `PendingRefresh` record is created and the steward polls until approved or rejected. Only `archived` stewards enter the pending queue; `dormant` and `revoked` stewards receive 403 immediately.

### 4. Registration-refresh wire protocol — two new endpoints

The existing no-op HA stub at `POST /api/v1/stewards/{id}/auth/refresh` (`features/controller/api/handlers_stewards.go:561`, `handleStewardAuthRefresh`) is **NOT** this epic's endpoint. It is an HA test instrumentation surface that acknowledges refresh requests without modifying any credential state. It must not be modified or repurposed by this epic.

This epic adds two new endpoints in a new file `features/controller/api/handlers_registration_refresh.go`:

```
POST /api/v1/stewards/{device_id}/refresh/challenge
POST /api/v1/stewards/{device_id}/refresh/complete
```

#### Challenge phase (`/refresh/challenge`)

Request: `{ "device_id": "<64-char hex>" }`

Controller response (200):
```json
{
  "nonce": "<base64url-encoded 32 random bytes>",
  "server_ts": <unix-seconds-uint64>,
  "expires_in": 60
}
```

The nonce is single-use, stored in an in-memory cache with a **65-second TTL** (60 s enforced server-side + 5 s grace for clock drift). Any replay of the same nonce after first use returns 409 Conflict.

Before issuing the nonce, the controller checks:
1. `GetStewardByDeviceID(device_id)` — if record not found → 404
2. `record.Status == revoked` → 403 **immediately** (no nonce issued)
3. `record.Status == dormant` → 403 (dormant stewards must re-register)
4. `record.Status == archived` → 200 + nonce (valid refresh candidate)

#### Complete phase (`/refresh/complete`)

Request:
```json
{
  "device_id": "<64-char hex>",
  "nonce":     "<base64url nonce from /challenge>",
  "pop":       "<base64url ed25519 signature>"
}
```

The `pop` (proof-of-possession) signature covers the following digest, computed identically by the steward (S2) and the controller (S3b):

```
digest = sha256(nonce_bytes || device_id_utf8 || server_ts_big_endian_uint64)
```

Where:
- `nonce_bytes` — raw bytes of the base64url-decoded nonce (32 bytes)
- `device_id_utf8` — UTF-8 bytes of the 64-character lowercase hex `DeviceID`
- `server_ts_big_endian_uint64` — the `server_ts` value from the challenge response, encoded as a big-endian unsigned 64-bit integer (8 bytes)

**This formula must appear identically in S2 (steward side) and S3b (controller side).** Any deviation between the two is a security bug.

### 5. Revocation-before-PoP ordering invariant (mandatory)

The revocation check MUST precede signature verification in `/refresh/complete`. The controller handler MUST follow this order:

```
1. GetStewardByDeviceID(device_id)      → 404 if not found
2. record.Status == revoked             → 403 BEFORE any ed25519.Verify call
3. consume nonce (mark used)            → 409 if already consumed
4. ed25519.Verify(pubkey, digest, pop)  → 401 if signature invalid
5. apply refresh policy                 → 202 (pending) or 200 (cert issued)
```

**Why this order matters:** if PoP verification precedes the revocation check, an attacker with a stolen device key can learn "my key is still valid" from a successful signature check even though the device is revoked. The 403 from revocation must be unconditional and prior to any cryptographic feedback.

The controller implements this via an injectable `PoPVerifier` interface:

```go
type PoPVerifier interface {
    // VerifyPoP checks the proof-of-possession for the given device.
    // Returns ErrDeviceRevoked before any cryptographic check if the device is revoked.
    // Returns ErrNonceExpiredOrUsed if the nonce is invalid.
    // Returns ErrInvalidPoP if the signature does not verify.
    VerifyPoP(ctx context.Context, deviceID string, nonce string, pop []byte) error
}
```

The interface is injectable to allow test implementations that exercise each error path without real Ed25519 operations.

### 6. Policy defaults

| Policy knob | Default | Meaning |
|-------------|---------|---------|
| `refresh_policy` | `require_approval` | Admin must approve each refresh request |
| `auto_accept` | (not the default) | Auto-issue cert without approval; only if explicitly configured |
| `MaxDormancyDays` | `nil` (OFF) | No automatic dormancy; stewards stay `archived` indefinitely |

The default is `require_approval` (not `auto_accept`) because the threat model for registration-refresh is similar to initial registration: an admin account may be transiently compromised, and automatic cert issuance without approval expands the blast radius of such a compromise. Operators who trust their infrastructure can opt into `auto_accept`.

---

## Consequences

**Positive**
- Stewards that go offline past cert expiry recover fleet identity without manual re-registration.
- Stable device ID (Ed25519 key hash) survives mTLS rotations, controller upgrades, and hostname changes.
- Revocation gate ordering is explicit and tested — the refresh path cannot bypass a revoked status.
- `KeyStore` interface makes TPM support a future drop-in with no protocol changes.
- Conservative defaults (`require_approval`, dormancy OFF) match the operator threat model; operators opt into looser policies, not into tighter ones.

**Negative / risks (accepted)**
- A stolen device key allows an attacker to initiate a refresh handshake. Mitigation: the revocation check fires before PoP, so a revoked device key produces a 403 before the attacker learns anything cryptographic. For non-revoked devices, the `require_approval` default means an admin must approve before a cert is issued.
- File-backed key storage (`key_protection_level: file`) relies on OS disk encryption for confidentiality. This is acceptable for v1 given the threat model (stewards run on managed, EDR-covered endpoints); TPM is the hardening path.
- Nonce TTL of 65 s means the challenge–complete round trip must complete within that window. This is generous for any non-hibernating network path.

## Alternatives considered

- **Reuse the existing `/auth/refresh` HA stub endpoint.** Rejected — the stub is an HA test surface with no cryptographic semantics. Repurposing it would conflate two unrelated operations and introduce subtle HA-vs-security coupling.
- **Use the expired mTLS cert directly as proof of identity.** Rejected — expired certs are not verifiable at the TLS layer without special exemptions, which would require disabling standard TLS validation for the refresh path. The Ed25519 identity key is explicitly not subject to cert expiry.
- **Auto-accept by default.** Rejected — the `require_approval` default is intentional. Auto-accept expands blast radius for compromised admin accounts. Operators opt into auto-accept explicitly.
- **Shared nonce cache via HA replication.** Deferred — single-instance controller in v1; nonce cache is in-process. When multi-controller HA ships, the nonce cache moves to the shared durable store (same pattern as session store).
- **TPM-backed key storage in v1.** Explicitly deferred — out of scope for this epic. The `KeyStore` interface is designed so TPM is a drop-in.
