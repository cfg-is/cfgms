# Test-Cell Deploy Agent

A test cell is a separate controller and steward fleet used to exercise
releases before they reach production. This document is the product-side
contract a deploy agent uses against a test cell: which setting to enable,
which credential to mint, which routes to call and what the controller
records. It describes the product only. Hostnames, addresses, key material and
other environment details belong in the operator's own deployment records, not
in this repository. Examples use placeholders such as `cell.example` and
`acme-corp`.

For status sources across the upgrade operations, see the
[Upgrade Lifecycle Reference](upgrade-lifecycle.md).

## Test cell only

The unattended-rollouts setting exists so that a machine credential can publish
a steward binary and start a rollout without a person approving each one. That
is the point of a test cell, where a deploy agent ships every candidate build.
It is not a production control: in production, binary approval and rollout
start remain human decisions.

- The setting is **off by default**. A new controller, and any controller that
  has never had the setting changed, refuses the rollout credential on the
  gated routes.
- Turning it on is a deliberate act by a person with a presence tap, and is
  audited with the principal and the previous and new value.
- Enable it on a test-cell controller only. Do not enable it on a controller
  that manages production endpoints.

## Prerequisites

- The test-cell steward fleet runs `module_trust.mode: strict` with the
  test-cell publisher key, so each steward verifies publisher signatures
  independently of the controller.
- The test-cell controller build bakes the test-cell publisher **public** key.
  The key is chosen by the operator and is not named here. The publish route
  checks the publisher signature against that baked key before anything is
  stored.
- Rollout start, push dispatch and steward self-fetch all need an **approved**
  steward binary. A binary that is published but not approved is not rolled
  out and is not handed to a steward. Approval normally uses the tap-gated
  approve route; the rollout credential's publish approves the binary
  automatically, and only while the unattended-rollouts setting is on.

## Routes

All routes below are under `https://cell.example/api/v1`, except the marker
routes, which are served on the private metrics listener only.

| Step | Route | Permission | Authentication |
|---|---|---|---|
| Read the setting | `GET /rollout-settings/unattended` | `rollout-automation:read` | Any authorized principal |
| Enable or disable the setting | `PUT /rollout-settings/unattended` | `rollout-automation:set` | Strong assurance and a presence tap; no API key |
| Mint the rollout credential | `POST /rollout-credentials` | `rollout-credential:create` | Strong assurance and a presence tap; no API key |
| Revoke a credential | `DELETE /api-keys/{id}` | `api-key:delete` | Strong assurance |
| Publish a steward binary | `POST /installer/steward-binaries/{version}/{platform}/{arch}` | `installer:publish:steward` | Rollout credential, setting on |
| Start a rollout | `POST /rollout` | `installer:dispatch:steward` | Rollout credential, setting on |
| Read rollout status | `GET /rollout/{rollout_id}` | `installer:read` | Rollout credential |
| Halt a rollout | `POST /rollout/{rollout_id}/halt` | `installer:dispatch:steward` | Rollout credential; not gated by the setting |
| Dispatch one upgrade | `POST /stewards/upgrade` | `installer:dispatch:steward` | Rollout credential, setting on |
| Roll back one upgrade | `POST /stewards/upgrade/{upgrade_id}/rollback` | `installer:dispatch:steward` | Rollout credential; not gated by the setting |
| Post a deploy marker | `POST /monitoring/markers` | `monitoring:write-markers` | Rollout credential, private listener |
| List markers | `GET /monitoring/markers` | `monitoring:read-markers` | Private listener |

### 1. Enable the setting (tap)

A person with the `rollout-automation:set` permission sends:

```http
PUT /api/v1/rollout-settings/unattended
{"enabled": true}
```

The body is exactly one JSON object with a boolean `enabled`; a missing field
or an unknown field is rejected with `400`. The change is audited before it is
made: if the audit event cannot be recorded, the setting is left as it was and
the route returns `503` (`AUDIT_UNAVAILABLE`). Send `{"enabled": false}` to turn
it off. Setting the value the cell already has goes through the same tap and
audit.

### 2. Mint the rollout credential (tap)

A person who holds all four permissions of the credential, with a presence tap,
sends:

```http
POST /api/v1/rollout-credentials
{"name": "deploy-agent", "expires_at": "2026-12-01T00:00:00Z"}
```

- `expires_at` is required, must be in the future and may be at most **90
  days** from now. A longer expiry is refused with `400` (`EXPIRY_TOO_LONG`).
- `name` is optional (default `rollout-credential`, at most 128 characters).
- The request cannot add or remove permissions. The credential carries exactly
  `installer:dispatch:steward`, `installer:read`,
  `installer:publish:steward` and `monitoring:write-markers`.
- The key belongs to the caller's own tenant. The plaintext key is returned
  once in the `201` response and is never recorded; store it in the deploy
  agent's secret store.
- Minting is audited as `rollout_credential_created` with the principal, key id
  and expiry.

The controller identifies the credential by the kind recorded on the key, not
by its permission list. A key with the same four permissions minted any other
way is not a rollout credential and is not subject to the gate or the
publish-time auto-approval.

### 3. Expiry and revocation

- **Expiry.** The credential stops working at `expires_at`, at most 90 days
  after it was minted. Mint a new one with a tap before then; the deploy agent
  does not renew itself.
- **Revocation.** `DELETE /api/v1/api-keys/{id}` (strong assurance) revokes the
  credential. The key id is in the mint response and in the
  `rollout_credential_created` audit row.
- **Setting off.** Setting `enabled` to `false` takes effect on the next
  request: the setting is read from the store on every gated call, with no
  cache. While it is off, the credential is refused on publish, rollout start
  and push dispatch with `403` (`UNATTENDED_ROLLOUTS_DISABLED`), and each
  refusal is audited as `unattended_rollout_refused`. If the setting cannot be
  read, the credential is refused with `503` rather than treated as on.

### 4. Publish, then roll out

1. Publish the signed steward binary:
   `POST /api/v1/installer/steward-binaries/{version}/{platform}/{arch}` with
   the binary as the request body and the publisher signature in the
   `signature` query parameter (base64) or a multipart `signature` field.
   `platform` and `arch` use the product's supported values (`amd64` and
   `arm64` for `arch`). The signature binds the content hash, version,
   platform and arch to the baked publisher key. A binary published by the
   rollout credential while the setting is on is approved automatically and
   audited as `steward_binary_auto_approved`; a binary published by any other
   principal stays unapproved until the approve route
   (`POST .../{version}/{platform}/{arch}/approve`, audited as
   `steward_binary.approve`) is used by a person.
2. Start the rollout:

   ```http
   POST /api/v1/rollout
   {"target_version": "1.2.3", "tenant_id": "acme-corp"}
   ```

   The response carries the `rollout_id`. The rollout proceeds ring by ring.
3. Poll `GET /api/v1/rollout/{rollout_id}` for `status`, `current_ring`,
   `on_version_pct`, `failed_count` and `pending_count`. The controller can
   halt a rollout itself when ring health cannot be read or the failure rate
   is exceeded; that is audited as `rollout_auto_halted`.

### 5. Halt

`POST /api/v1/rollout/{rollout_id}/halt` stops further rings. It is not gated
by the unattended-rollouts setting, so a deploy agent can always halt, and the
route is exempt from the presence tap so a machine credential can call it.
Halting is audited as `rollout_halted`.

### 6. Roll back by rolling out the previous version

To return the fleet to the previous release, roll out the previous version:
publish it again if it is no longer approved, then call `POST /api/v1/rollout`
with the previous `target_version`. The rollout treats it as any other target.
For a single upgrade that was dispatched with `POST /api/v1/stewards/upgrade`,
`POST /api/v1/stewards/upgrade/{upgrade_id}/rollback` with
`{"version": "<previous version>"}` restores that version; it is audited as
`steward_upgrade_rolled_back` and, like halt, is not gated by the setting.

### 7. Post deploy markers

A deploy agent records what it did so that signals can be read against it:

```http
POST /api/v1/monitoring/markers
{"kind": "deploy", "revision": "1.2.3", "note": "candidate build"}
```

- `kind` is one of `deploy`, `rollback`, `chaos_start`, `chaos_end`.
- `revision` is a hex commit id (7 to 64 digits) or a semantic version.
- `note` is optional, at most 256 characters.
- The route is on the private metrics listener only. It is absent from the
  public router. See [Service-Level Signals](service-level-signals.md) for the
  listener and the marker surface.

## Audit and markers

Every deploy, rollback and halt is audited with the principal and the revision,
and appears as a marker. Rollout and upgrade events are written twice: as an
audit row under the owning tenant and as a `marker_*` row under the system
tenant. Markers are read with `GET /api/v1/monitoring/markers`.

| Audit action | Recorded when |
|---|---|
| `unattended_rollouts_changed` | The setting is turned on or off (principal, previous, new value) |
| `rollout_credential_created` | A rollout credential is minted (principal, key id, expiry) |
| `steward_binary_auto_approved` | The rollout credential publishes a binary and it is approved automatically |
| `steward_binary.approve` | A person approves a published binary |
| `unattended_rollout_refused` | The rollout credential is refused on a gated route (principal, route, reason) |
| `rollout_started` | A rollout starts |
| `rollout_completed` | A rollout completes |
| `rollout_halted` | A rollout is halted by a caller |
| `rollout_auto_halted` | The controller halts a rollout (ring health query failure or failure rate exceeded) |
| `steward_upgrade_dispatched` | An upgrade is dispatched to a steward |
| `steward_upgrade_rolled_back` | An upgrade is rolled back |

Rollout and upgrade events appear as `marker_rollout_started`,
`marker_rollout_completed`, `marker_rollout_halted`,
`marker_rollout_auto_halted`, `marker_upgrade_dispatched` and
`marker_upgrade_rolled_back`. Markers a deploy agent posts appear as
`marker_deploy`, `marker_rollback`, `marker_chaos_start` and
`marker_chaos_end`.

## Deploy-agent responsibilities

The controller provides the routes above. It does not provide the following;
these are the deploy agent's responsibility, not product features:

- **Controller node replacement.** Replacing or upgrading the test-cell
  controller nodes is done by the deploy agent following the
  [Rolling Cluster Upgrade Runbook](rolling-cluster-upgrade.md) or
  [Controller Upgrade Runbook](controller-upgrade.md). The rollout routes
  above upgrade stewards, not controllers.
- **Gate evaluation.** Deciding whether a rollout is good enough to continue,
  promote or roll back is done by the deploy agent, by reading rollout status
  and signals and acting with the halt and rollback routes. The controller's
  automatic halt is a safety stop, not a promotion gate.
