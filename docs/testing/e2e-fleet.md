# Fleet E2E Upgrade Tests

`test/e2e/fleet/upgrade_test.go` — Docker-based integration tests for the steward
fleet upgrade flow (Issue #1948).

## Required infrastructure

All tests require:

```
docker compose --profile fleet -f docker-compose.test.yml up -d
CFGMS_FLEET_TEST=1
```

All tests guard with `testing.Short()` and are skipped outside the Docker fleet
environment.

Containers involved:

| Container | Tenant | Role |
|-----------|--------|------|
| `fleet-controller` | root | Controller; hosts the steward binary blob store at `/app/data/installers` |
| `fleet-steward-1` | `fleet-root/fleet-child-a` | Upgrade target for happy-path and negative tests |
| `fleet-steward-2` | `fleet-root/fleet-child-b` | Used only by the cross-tenant test |

The upgrade-test API key (`cfgms-upgrade-test-key`) is seeded in the controller
at startup (env `CFGMS_API_KEY_UPGRADE_TEST`). It is scoped to `fleet-root/fleet-child-a`
with permissions `installer:publish:steward`, `installer:dispatch:steward`, `installer:read`.

Both the controller and steward containers accept the zero-seed Ed25519 public key
(`O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik=`) for binary signature verification.
Tests sign binaries with `ed25519.NewKeyFromSeed(make([]byte, 32))`.

## Test scenarios

### TestFleetStewardUpgradeHappyPath

Full upgrade dispatch lifecycle for fleet-steward-1.

1. Extract the running steward binary from `fleet-steward-1:/app/steward`.
2. Publish as `v0.5.99-test/linux/amd64` with a valid zero-seed Ed25519 signature.
3. Dispatch upgrade via `POST /api/v1/stewards/upgrade` with selector `id:<steward-id>`.
4. Poll `GET /api/v1/stewards/upgrade/{upgrade_id}` until status reaches `committed`
   or 35 s elapses.
5. Assert status == `committed`.
6. Assert `GET /api/v1/stewards/{id}` returns `connection_state: connected`.

Expected outcome: the launcher stages the binary and the command completes successfully.
Status: `committed`.

### TestFleetStewardUpgradeBrokenBinaryRollback

Simulates a binary that was tampered with on the controller's storage after signing.

1. Publish a known-good payload as `v0.5.100-broken/linux/amd64` with a valid signature.
2. Corrupt the blob file on disk: `printf 'CORRUPTED-BY-E2E-TEST' > <blob-path>`.
3. Dispatch. The controller recomputes SHA-256 over the corrupted content and sends that
   hash with the original signature. The steward downloads the corrupted content, verifies
   SHA-256 (passes), then verifies the Ed25519 signature against the new hash (fails).
4. Assert status reaches `failed` or `rolled_back` within 35 s.
5. Assert steward is still `connected`.

Expected outcome: signature verification fails at the steward.
Status: `failed`.

### TestFleetUpgrade_CrossTenantDispatchReturns403

The upgrade-test API key is scoped to `fleet-root/fleet-child-a`. Dispatching with
selector `id:<steward-2-id>` (which belongs to `fleet-root/fleet-child-b`) returns 403
because the fleet query finds no stewards in the caller's tenant matching the selector.

Expected outcome: HTTP 403 Forbidden from the dispatch endpoint.

### TestFleetUpgrade_DowngradeRejected

Publishes `v0.4.99/linux/amd64` (older than the running `0.5.0-dev`) and dispatches.
The steward's version-monotonicity check (`isNewerVersion("v0.4.99", "0.5.0-dev")` →
false) rejects the command with `ErrDowngradeDenied`, which triggers `EventCommandFailed`.

Expected outcome: upgrade status reaches `failed` within 35 s.

### TestFleetUpgrade_SignatureMismatchRejected

Publishes a binary with a valid signature, then replaces the stored `signature` field in
the blob metadata JSON with 64 zero bytes encoded as RawURLEncoding base64 (86 `A`
characters). At dispatch the controller forwards the tampered signature; Ed25519
verification at the steward fails.

Expected outcome: upgrade status reaches `failed` within 35 s.

### TestFleetUpgrade_DuplicatePublishReturns409

Posts the same `{version, platform, arch}` tuple twice to
`POST /api/v1/installer/steward-binaries/{v}/{p}/{a}` without the `?force=true` flag.
The controller's duplicate guard returns 409 Conflict on the second request.

Expected outcome: second POST returns HTTP 409 Conflict.

### TestFleetUpgrade_ConcurrentUpgradeRejected

Dispatches two upgrades to the same steward in rapid succession. The first dispatch
creates an upgrade record with status `dispatched` (non-terminal). The second dispatch
finds this record in `ListUpgradesBySteward` and returns 409 Conflict.

Expected outcome: second dispatch returns HTTP 409 Conflict.

## Helper functions

| Function | Location | Purpose |
|----------|----------|---------|
| `fetchUpgradeStatus(t, client, upgradeID, timeout)` | `framework_test.go` | Polls upgrade status until terminal or timeout |
| `(s) waitForStewardVersion(t, container, version, timeout)` | `framework_test.go` | Polls steward log for a version string |
| `testUpgradePrivKey()` | `upgrade_test.go` | Returns the zero-seed Ed25519 signing key |
| `signUploadContent(content)` | `upgrade_test.go` | Signs content; returns base64 signature |
| `publishStewardBin(t, client, version, content, force)` | `upgrade_test.go` | HTTP publish helper |
| `doDispatchUpgrade(t, client, stewardID, version)` | `upgrade_test.go` | HTTP dispatch helper; returns (statusCode, upgradeID) |
| `dispatchUpgrade(t, client, stewardID, version)` | `upgrade_test.go` | Asserts 202; returns upgradeID |
| `blobPath(version)` | `upgrade_test.go` | Filesystem path of blob inside fleet-controller |
| `blobMetaPath(version)` | `upgrade_test.go` | Filesystem path of blob metadata JSON |

## Running the tests

```bash
# Start the fleet stack
docker compose --profile fleet -f docker-compose.test.yml up -d --build

# Run only upgrade tests
CFGMS_FLEET_TEST=1 go test ./test/e2e/fleet/... -run 'TestFleet.*Upgrade|TestFleetSteward' -v -timeout 5m

# Run all fleet E2E tests
make test-e2e-fleet
```
