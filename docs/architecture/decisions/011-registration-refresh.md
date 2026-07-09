# ADR-011: Registration-Refresh for Stewards Offline Past mTLS Cert Expiry

**Status:** Accepted

**Date:** 2026-06-20

**Deciders:** Founder, Architecture

**Related:** [001](001-central-provider-compliance-enforcement.md) (secrets central provider), [010](010-steward-side-provisioning-enrollment.md) (enrollment, which this protocol follows). Epic: #1845. Stories: #2092 (this ADR), #2093 (storage foundation), #2094 (steward identity key + handshake), #2095 (controller persist-at-registration), #2096 (controller gate), #2097 (cfg admin CLI), #2098 (fleet E2E).

---

## Context

A steward that was offline past its mTLS cert expiry is today completely locked out: its certificate is expired, mTLS handshakes fail, and re-registration from scratch loses fleet identity (tenant, group, audit history, pinned config). MSPs managing 50k+ endpoints across multiple time zones cannot guarantee all devices stay online within cert validity windows — devices hibernate, sites lose WAN for weeks, devices sit in a warehouse.

Three design questions had to be settled before any implementation could proceed, because the answers span multiple stories and getting them wrong mid-implementation would require rewrites:

1. **Device identity**: what credential proves "I am the same device that originally registered" when the mTLS cert is expired?
2. **Proof of possession**: how does the controller verify that credential without trusting the expired cert at the TLS layer?
3. **Gate ordering and blast radius**: how do we prevent the refresh path from becoming a re-registration bypass for a revoked steward, and how do we honor "reconnect like nothing happened" for a normal long-offline device without auto-rehydrating a device an admin has retired?

The three founder requirements this protocol must satisfy:

- **R1 — Archived devices need manual approval.** A device an admin has explicitly retired (`archived`) must never auto-rehydrate; it requires manual approval.
- **R2 — Long-disconnected devices reconnect seamlessly.** A device offline for an extended period (even past mTLS cert expiry) can reconnect "like nothing happened," subject to the operator's policy.
- **R3 — Always match the existing object.** A returning device is always matched to its existing record by stable `DeviceID` — it never registers as a new object, and recovery never destroys identity.

This ADR records the founder-approved answers so implementers have no open design questions and any future change to the security model requires an explicit ADR update.

---

## Decision

### 1. Stable Ed25519 device identity key, separate from the rotating mTLS cert

Each steward holds an **Ed25519 device identity key pair** that is generated once at first registration and never replaced. This is categorically different from the mTLS client certificate, which is short-lived and rotated:

| | mTLS cert | Device identity key |
|---|---|---|
| Purpose | Transport authentication | Device identity across cert rotations |
| Lifetime | Short (e.g. 90 days) | Permanent (per device) |
| Rotation | Yes, on renewal / refresh | Never |
| Used by | gRPC-over-QUIC TLS handshake | Registration-refresh PoP only |

The **64-char lowercase hex SHA-256 hash of the Ed25519 public key** is the `DeviceID`: `hex.EncodeToString(sha256(publicKeyBytes))`. It is stable across mTLS cert rotations and is the primary lookup key in `GetStewardByDeviceID`. The controller stores the public key on the steward record at first registration (#2095); the expired mTLS cert serial is retained as a chain-of-custody/audit signal only, never as the PoP credential.

The key carries a `key_protection_level` attribute (`file` in v1; `tpm` / `secure-enclave` as future drop-ins). Whether a tenant *requires* a hardware-backed level is a future policy knob; v1 ships `file` and records the attested level so "require TPM" is additive later, not a re-architecture.

### 2. File-backed KeyStore in v1, encrypted at rest at the application layer; TPM as a future drop-in

The private key is **encrypted at rest by the application**, via the existing steward secrets provider `pkg/secrets/providers/steward/crypto.go` (AES-256-GCM, HKDF-SHA256 from machine ID). It is written to `{identityDir}/device_identity.enc` with mode `0600`. **The plaintext private key never touches disk**, and the on-disk bytes are ciphertext — they must fail to parse as PEM or DER (this is a required test in #2094). This is stronger than relying on OS-level disk encryption alone, which would leave a cleartext key readable by any process with file access and violates the CFGMS "no cleartext secrets on disk, even in dev" rule.

The `KeyStore` interface abstracts key material storage and signing so a TPM/secure-enclave backend is a future drop-in with no protocol change:

```go
type KeyStore interface {
    // GenerateOrLoad returns the device identity keypair, creating and
    // persisting it (encrypted) on first call.
    GenerateOrLoad(ctx context.Context) (ed25519.PublicKey, ed25519.PrivateKey, error)
    // DeviceID returns the stable 64-char lowercase hex DeviceID.
    DeviceID() string
    // Sign signs the PoP digest with the device identity private key.
    Sign(message []byte) ([]byte, error)
}
```

### 3. Lifecycle state machine — the rehydration decision is gated on object state, not connectivity

The existing steward lifecycle (`registered` → `active` → `lost` / `deregistered`) gains three states. The controller resolves the object by `DeviceID`, then gates the refresh outcome on that object's state. **Connectivity is not a state an admin sets** — a normally-offline device stays `active` (or `dormant` only if the backstop is enabled and tripped). Only an explicit admin **archive** action moves a device into the approval branch.

| State | Set by | Refresh outcome |
|-------|--------|-----------------|
| `active` / `registered` | normal operation | **Policy-governed** (see §6): `auto_accept` → 200 seamless cert; `require_approval` → 202 queued; `reject` → 403. Provenance (§7) may demote `auto_accept` → 202. |
| `dormant` | dormancy backstop (default OFF) | Same policy-governed path as `active`; when the backstop is enabled and the device is past `MaxDormancyDays`, the decision is **escalated to `require_approval`** (202) for that request. Never re-register — identity is preserved (R3). |
| `archived` | **explicit admin action** | **Always 202 queued for approval, regardless of policy** (R1). Archive is how an admin says "this device must not silently come back." |
| `revoked` | **explicit admin action** | **Always 403, checked before PoP** (§5). Terminal — return to service requires a deliberate admin action, not a refresh. |

This satisfies all three requirements: a normal long-offline device rehydrates per policy and can be seamless (R2: operator sets `auto_accept`); an admin-archived device always needs approval (R1); every returning device is matched to its existing record and never loses identity (R3).

**State transitions are monotonic (non-promoting):** a refresh can never move a steward to a *less*-restricted state. An archived/revoked device is never auto-promoted to `active` by the refresh path; promotion to `active` happens only through a completed, approved refresh that issues a cert (for `archived`) or an explicit admin action (for `revoked`). This monotonicity is a separate property from §7 provenance — do not conflate the two.

**Dormancy backstop** (`MaxDormancyDays`): an optional per-tenant config knob. Default **OFF** (`nil`) — stewards rehydrate per policy indefinitely, honoring R2 out of the box. When set, a device past the threshold is escalated to `require_approval` for its next refresh (it is *not* rejected and *not* forced to re-register). MSPs with stricter blast-radius requirements opt in; it is never a silent default.

### 4. Registration-refresh wire protocol — two new endpoints

The existing no-op HA stub at `POST /api/v1/stewards/{id}/auth/refresh` (`features/controller/api/handlers_stewards.go:561`, `handleStewardAuthRefresh`) is **NOT** this epic's endpoint. It is an HA test-instrumentation surface that acknowledges refresh requests without modifying credential state. It must not be modified or repurposed by this epic.

This epic adds two endpoints in a new file `features/controller/api/handlers_registration_refresh.go`:

```
POST /api/v1/stewards/{device_id}/refresh/challenge
POST /api/v1/stewards/{device_id}/refresh/complete
```

#### Challenge phase (`/refresh/challenge`)

Request: `{ "device_id": "<64-char hex>" }`

Before issuing a nonce, the controller checks:
1. `GetStewardByDeviceID(device_id)` — not found → **404**
2. `record.Status == revoked` → **403 immediately** (no nonce issued — a revoked device gets no cryptographic feedback)
3. any other state (`active` / `registered` / `dormant` / `archived`) → **200 + nonce** (a refresh candidate; the lifecycle/policy decision is made at `/complete`)

Response (200):
```json
{ "nonce": "<base64url 32 random bytes>", "server_ts": <unix-seconds-uint64>, "expires_in": 60 }
```

The nonce is single-use, stored in an in-memory cache with a **65-second TTL** (60 s enforced server-side + 5 s grace for clock drift). It is consumed (deleted) on first use at `/complete`. A replayed, expired, or absent nonce is rejected with **401** — identical handling for all three, so a caller learns nothing from the distinction.

#### Complete phase (`/refresh/complete`)

Request:
```json
{
  "device_id":       "<64-char hex>",
  "nonce":           "<base64url nonce from /challenge>",
  "pop":             "<base64url ed25519 signature>",
  "host_attributes": { "...": "..." }
}
```

The `pop` (proof-of-possession) signature covers a digest computed **identically** by the steward (#2094) and the controller (#2096):

```
digest = sha256(nonce_bytes || device_id_utf8 || server_ts_big_endian_uint64)
```

- `nonce_bytes` — raw bytes of the base64url-decoded nonce (32 bytes)
- `device_id_utf8` — UTF-8 bytes of the 64-char lowercase hex `DeviceID`
- `server_ts_big_endian_uint64` — the `server_ts` from the challenge response, big-endian uint64 (8 bytes)

**Any deviation between the two implementations is a security bug.**

### 5. Revocation-before-PoP ordering invariant (mandatory)

The controller `/refresh/complete` handler MUST follow this order; each step short-circuits:

```
1. GetStewardByDeviceID(device_id)        → 404 if not found
2. record.Status == revoked               → 403 BEFORE any ed25519.Verify call
3. tenant check: record.TenantID != req   → 403 (not 404 — 404 leaks existence)
4. consume nonce (delete; 401 if absent/expired/used)
5. PoPVerifier.Verify(pubkey, digest, pop) → 401 if signature invalid
6. lifecycle + policy + provenance gate (§3, §6, §7) → 200 / 202 / 403
7. audit the outcome (accept / queue / reject) → before WriteHeader
```

**Why the order matters:** the device-revocation signal is `record.Status == revoked`, *not* the cert-serial revocation store (`pkg/cert/revocation.go`), which is serial-keyed and admin-cert-scoped and is **not** populated when a steward device is revoked. The authoritative check is therefore the status check, and it must precede signature verification — otherwise a stolen-but-revoked device key produces a successful verify and the attacker learns the key is still valid. Revocation must be unconditional and prior to any cryptographic feedback. The cert-serial revocation store MAY be consulted as a secondary defense-in-depth check, but it is not the primary signal.

The check is implemented behind an injectable `PoPVerifier` so tests can assert `Verify` is called **zero times** for a revoked device (a 403 response alone does not prove the invariant):

```go
type PoPVerifier interface {
    Verify(pub ed25519.PublicKey, msg, sig []byte) bool
}
```

### 6. Refresh policy — per-tenant, safe default

Policy governs only the `active` / `dormant` path (`archived` and `revoked` are policy-independent per §3).

| Policy `Mode` | Default? | Outcome for active/dormant |
|---------------|----------|----------------------------|
| `require_approval` | **yes** | 202 — admin must approve each refresh |
| `auto_accept` | no (opt-in) | 200 — cert issued without approval (the seamless R2 experience); subject to provenance demotion |
| `reject` | no | 403 — refresh disabled for the tenant |

`GetPolicy` returns `{Mode: "require_approval", DormancyBackstopEnabled: false, MaxDormancyDays: nil}` when no record exists. The default is `require_approval`, not `auto_accept`: the refresh threat model mirrors initial registration — a transiently compromised admin account should not yield automatic cert issuance. Operators who want "reconnect like nothing happened" with no human in the loop opt into `auto_accept` deliberately (R2 is achievable, not the unsafe default).

### 7. Provenance — demote-only confidence signal from soft host attributes

On `/refresh/complete`, the steward includes a `host_attributes` map (SMBIOS/machine UUID, disk serial(s), NIC MAC(s), install date, cert-serial lineage). The controller's `ProvenanceMatcher.FuzzyMatch(stored, incoming) → ProvenanceResult{Score, MatchedFields, TotalFields}` compares them, N-of-M tolerant, against the last-known recorded set (default threshold **60%**). The result is recorded to `StewardRecord.LastProvenanceJSON`.

Provenance is strictly **demote-only**:
- A below-threshold score **demotes** an `auto_accept` decision to `require_approval` (202), so a device whose hardware fingerprint looks wrong gets a human in the loop even under `auto_accept`. The admin sees the attribute diff in the pending-refresh queue.
- Provenance can **never promote**: an `archived` or `revoked` device is never auto-rehydrated regardless of a perfect provenance score. The revocation/lifecycle gates (§3, §5) run *before* provenance is consulted. (Required test: revoked + perfect score → 403, `PoPVerifier.Verify` call count == 0.)
- **DNA is explicitly not a provenance input.** Config/managed-state DNA (`dna_hash`, `dna_aggregate`) is non-secret and shared across a ring — it has near-zero per-device entropy and is excluded from `FuzzyMatch` inputs (enforced by test).

Provenance is corroboration, not proof: the cryptographic identity proof is the PoP (§4–5). A device-image attacker holds both the key and the attributes, so provenance only ever *adds* friction (demote), never removes a gate.

---

## Consequences

**Positive**
- Stewards offline past cert expiry recover fleet identity without manual re-registration; identity (`DeviceID`) survives mTLS rotations, controller upgrades, and hostname changes (R3).
- A normal long-offline device reconnects per policy and can be made seamless via `auto_accept` (R2); an admin-archived device always requires approval (R1).
- Revocation gate ordering is explicit and tested — the refresh path cannot bypass a revoked status, and no cryptographic feedback precedes the revocation check.
- Identity key is application-encrypted at rest; the `KeyStore` interface makes TPM a future drop-in with no protocol change.
- Conservative defaults (`require_approval`, dormancy OFF) match the operator threat model; operators opt into looser policies, not into tighter ones.

**Negative / risks (accepted)**
- A stolen device key allows an attacker to *initiate* a refresh handshake. Mitigations: revocation check fires before PoP (revoked → 403 with no crypto feedback); the `require_approval` default keeps a human in the loop; provenance demotes a mismatched-hardware refresh to approval even under `auto_accept`.
- File-backed key storage is application-encrypted (AES-256-GCM) but still resident on a host that may be compromised; TPM is the hardening path (deferred), made cheap by the `KeyStore` abstraction and the recorded `key_protection_level`.
- Nonce TTL of 65 s means the challenge→complete round trip must complete within that window — generous for any non-hibernating path.

## Alternatives considered

- **Reuse the existing `/auth/refresh` HA stub.** Rejected — the stub is an HA test surface with no cryptographic semantics; repurposing it conflates two unrelated operations.
- **Use the expired mTLS cert directly as proof of identity.** Rejected — expired certs are not verifiable at the TLS layer without disabling standard validation for the refresh path. The Ed25519 identity key is explicitly not subject to cert expiry. (The expired cert serial is kept only as an audit/chain-of-custody signal.)
- **Auto-accept by default.** Rejected — expands blast radius for a compromised admin account. `require_approval` is the default; `auto_accept` is opt-in.
- **Treat every offline-past-expiry device as needing approval (no seamless path).** Rejected — this breaks R2. The seamless path exists via the `active`/`dormant` policy branch with `auto_accept`; only explicit admin `archive` forces approval.
- **`dormant` → force full re-registration.** Rejected — re-registration destroys fleet identity (violates R3). The dormancy backstop escalates to `require_approval`, preserving identity.
- **Cert-serial revocation store as the device-revocation signal.** Rejected — it is admin-cert-scoped and not populated on device revocation; `StewardStatus == revoked` is the authoritative signal.
- **DNA as an identity/provenance input.** Rejected — non-secret and ring-shared; excluded from provenance scoring.
- **Shared nonce cache via HA replication.** Deferred — single-instance controller in v1; nonce cache is in-process and moves to the shared durable store when multi-controller HA ships.
- **TPM-backed key storage in v1.** Deferred — out of scope; the `KeyStore` interface and `key_protection_level` attribute make it a drop-in.
