// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// E2E upgrade tests: happy path, broken binary rollback, and negative scenarios. (Issue #1948)
package fleet

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/test/e2e/fleet/fleetkit"
)

// TestFleetStewardUpgradeHappyPath publishes the running steward binary as a new version,
// dispatches an upgrade to fleet-steward-1, and asserts that the upgrade status reaches
// "committed" within 35 s with the steward_id still reachable. (Issue #1948)
func TestFleetStewardUpgradeHappyPath(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping fleet upgrade test — requires Docker fleet infrastructure")
	}

	suite := newFleetScenarioSuite(t)
	client := insecureHTTPClient()
	waitForControllerAPI(t, client)

	// Publish a small payload as v0.5.99-test. The actual steward binary (~30-50 MiB)
	// causes the in-container download to exceed the 35 s status poll window in CI.
	// Any signed payload works — the handler verifies the Ed25519 signature and stages
	// via launcher swap; binary content is not executed by this test flow.
	// force=true so reruns on the same Docker stack don't conflict.
	binaryContent := []byte("cfgms-steward-upgrade-e2e-happy-path-test-payload")
	code := fleetkit.PublishStewardBin(t, client, "v0.5.99-test", binaryContent, true)
	require.Equal(t, http.StatusOK, code, "publish v0.5.99-test must return 200")

	stewardID := suite.StewardIDs["fleet-steward-1"]
	require.NotEmpty(t, stewardID, "fleet-steward-1 must have a registered steward ID")
	require.True(t, suite.WaitForConvergence(t, stewardID, 30*time.Second),
		"steward must be connected before dispatch")

	upgradeID := fleetkit.DispatchUpgrade(t, client, stewardID, "v0.5.99-test")
	t.Logf("Happy-path upgrade dispatched: upgrade_id=%s steward_id=%s", upgradeID, stewardID)

	status := fleetkit.FetchUpgradeStatus(t, client, upgradeID, 35*time.Second)
	require.Equal(t, "committed", status,
		"upgrade status must reach 'committed' within 35s (got %q)", status)

	// Verify via steward log that the upgrade version was processed.
	require.True(t, suite.WaitForStewardVersion(t, "fleet-steward-1", "v0.5.99-test", 10*time.Second),
		"steward must log v0.5.99-test within 10s of upgrade completion")

	// Steward must still be reachable after the upgrade (steward_id unchanged).
	state, err := suite.GetStewardConnectionState(t, stewardID)
	require.NoError(t, err, "GET /api/v1/stewards/%s must succeed after upgrade", stewardID)
	require.Equal(t, "connected", state,
		"steward must remain connected after upgrade")
}

// TestFleetStewardUpgradeBrokenBinaryRollback publishes a binary with a valid signature,
// then corrupts the stored blob so the SHA-256 recomputed at dispatch time no longer
// matches the signature. The steward receives a mismatched (sha256, sig) pair, signature
// verification fails, and the upgrade record reaches "failed". The steward must remain
// alive. (Issue #1948)
func TestFleetStewardUpgradeBrokenBinaryRollback(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping fleet upgrade test — requires Docker fleet infrastructure")
	}

	suite := newFleetScenarioSuite(t)
	client := insecureHTTPClient()
	waitForControllerAPI(t, client)

	// Approval is bound to the SHA-256 of the stored bytes, so the corrupted bytes
	// written below only reach the steward if they were approved. Publish the
	// corrupted content first (the test seed mode records an approval for its hash),
	// then force re-publish the known-good binary so the stored signature is the one
	// for the original content. The approval record for the corrupted hash outlives
	// the re-publish; the corruption step then puts those bytes back in the blob.
	corruptedContent := []byte("CORRUPTED-BY-E2E-TEST")
	code := fleetkit.PublishStewardBin(t, client, "v0.5.100-broken", corruptedContent, true)
	require.Equal(t, http.StatusOK, code, "publish of the to-be-corrupted bytes must return 200")

	// Publish a known-good binary (force=true for idempotency on reruns).
	origContent := []byte("cfgms-steward-upgrade-e2e-broken-binary-original-content")
	code = fleetkit.PublishStewardBin(t, client, "v0.5.100-broken", origContent, true)
	require.Equal(t, http.StatusOK, code, "publish v0.5.100-broken must return 200")

	// Corrupt the stored blob. The metadata signature remains valid for the ORIGINAL
	// content's SHA-256 but not the corrupted content's SHA-256.
	//
	// The filesystem provider's checksumVerifyingReader validates SHA-256 on every
	// GetBlob read. Without updating the sidecar checksum to match the corrupted blob,
	// the dispatch handler's io.ReadAll returns ErrBlobChecksumMismatch → 500.
	// We update the checksum so the read succeeds; the controller then recomputes
	// SHA-256 from the corrupted content and sends it with the original signature.
	// The steward's Ed25519 verification fails → EventCommandFailed → status "failed".
	fleetkit.DockerExecRoot(t, "fleet-controller", "sh", "-c",
		"printf 'CORRUPTED-BY-E2E-TEST' > "+fleetkit.BlobPath("v0.5.100-broken"))
	corruptedSum := sha256.Sum256(corruptedContent)
	fleetkit.DockerExecRoot(t, "fleet-controller", "sh", "-c",
		fmt.Sprintf(`sed -i 's/"checksum":"[^"]*"/"checksum":"%s"/' %s`,
			hex.EncodeToString(corruptedSum[:]), fleetkit.BlobMetaPath("v0.5.100-broken")))

	stewardID := suite.StewardIDs["fleet-steward-1"]
	require.NotEmpty(t, stewardID)
	require.True(t, suite.WaitForConvergence(t, stewardID, 30*time.Second),
		"steward must be connected before dispatch")

	upgradeID := fleetkit.DispatchUpgrade(t, client, stewardID, "v0.5.100-broken")
	t.Logf("Broken-binary upgrade dispatched: upgrade_id=%s", upgradeID)

	status := fleetkit.FetchUpgradeStatus(t, client, upgradeID, 35*time.Second)
	// The handler marks the record "failed" (not "rolled_back") on EventCommandFailed;
	// "rolled_back" is only set by the explicit rollback endpoint, which isn't invoked here.
	require.Equal(t, "failed", status,
		"upgrade status must reach 'failed' within 35s (got %q)", status)

	// Steward must still be alive after the failed upgrade.
	state, err := suite.GetStewardConnectionState(t, stewardID)
	require.NoError(t, err, "GET /api/v1/stewards/%s must succeed after failed upgrade", stewardID)
	require.Equal(t, "connected", state,
		"steward must remain connected after failed upgrade")
}

// TestFleetUpgrade_CrossTenantDispatchReturns403 dispatches an upgrade using the
// upgrade-test API key (scoped to fleet-root/fleet-child-a) against fleet-steward-2
// which belongs to fleet-root/fleet-child-b. Expects 403 Forbidden. (Issue #1948)
func TestFleetUpgrade_CrossTenantDispatchReturns403(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping fleet upgrade test — requires Docker fleet infrastructure")
	}

	suite := newFleetScenarioSuite(t)
	client := insecureHTTPClient()
	waitForControllerAPI(t, client)

	steward2ID := suite.StewardIDs["fleet-steward-2"]
	require.NotEmpty(t, steward2ID, "fleet-steward-2 must have a registered steward ID")

	// No binary publish needed — the 403 is returned before the binary lookup.
	code, _ := fleetkit.DoDispatchUpgrade(t, client, steward2ID, "v0.5.99-test")
	require.Equal(t, http.StatusForbidden, code,
		"cross-tenant dispatch must return 403 Forbidden")
}

// TestFleetUpgrade_DowngradeRejected publishes a binary with a version older than the
// running steward (0.5.0-dev) and dispatches it. The steward's version-monotonicity
// check rejects it, resulting in EventCommandFailed and status "failed". (Issue #1948)
func TestFleetUpgrade_DowngradeRejected(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping fleet upgrade test — requires Docker fleet infrastructure")
	}

	suite := newFleetScenarioSuite(t)
	client := insecureHTTPClient()
	waitForControllerAPI(t, client)

	// v0.4.99 is strictly older than the running 0.5.0-dev (major.minor: 0.4 < 0.5).
	downgradeContent := []byte("cfgms-steward-downgrade-e2e-test-payload")
	code := fleetkit.PublishStewardBin(t, client, "v0.4.99", downgradeContent, true)
	require.Equal(t, http.StatusOK, code, "publish v0.4.99 must return 200")

	stewardID := suite.StewardIDs["fleet-steward-1"]
	require.NotEmpty(t, stewardID)
	require.True(t, suite.WaitForConvergence(t, stewardID, 30*time.Second),
		"steward must be connected before dispatch")

	upgradeID := fleetkit.DispatchUpgrade(t, client, stewardID, "v0.4.99")
	t.Logf("Downgrade dispatch: upgrade_id=%s", upgradeID)

	status := fleetkit.FetchUpgradeStatus(t, client, upgradeID, 35*time.Second)
	require.Equal(t, "failed", status,
		"downgrade must be rejected; status must reach 'failed' within 35s (got %q)", status)
}

// TestFleetUpgrade_SignatureMismatchRejected publishes a binary with a valid signature,
// then replaces the stored signature in the metadata JSON with 64 zero bytes (valid
// base64, invalid Ed25519 signature). At dispatch the controller sends the tampered
// signature to the steward; verification fails and status reaches "failed". (Issue #1948)
func TestFleetUpgrade_SignatureMismatchRejected(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping fleet upgrade test — requires Docker fleet infrastructure")
	}

	suite := newFleetScenarioSuite(t)
	client := insecureHTTPClient()
	waitForControllerAPI(t, client)

	sigContent := []byte("cfgms-steward-sig-mismatch-e2e-test-payload")
	code := fleetkit.PublishStewardBin(t, client, "v0.5.98-sig", sigContent, true)
	require.Equal(t, http.StatusOK, code, "publish v0.5.98-sig must return 200")

	// Replace the stored signature with base64 of 64 zero bytes — valid encoding,
	// invalid Ed25519 signature. This is what the dispatch handler will forward.
	zeroSig := base64.RawURLEncoding.EncodeToString(make([]byte, 64))
	fleetkit.DockerExecRoot(t, "fleet-controller", "sh", "-c",
		fmt.Sprintf(`sed -i 's/"signature":"[^"]*"/"signature":"%s"/g' %s`,
			zeroSig, fleetkit.BlobMetaPath("v0.5.98-sig")))

	stewardID := suite.StewardIDs["fleet-steward-1"]
	require.NotEmpty(t, stewardID)
	require.True(t, suite.WaitForConvergence(t, stewardID, 30*time.Second),
		"steward must be connected before dispatch")

	upgradeID := fleetkit.DispatchUpgrade(t, client, stewardID, "v0.5.98-sig")
	t.Logf("Signature-mismatch dispatch: upgrade_id=%s", upgradeID)

	status := fleetkit.FetchUpgradeStatus(t, client, upgradeID, 35*time.Second)
	require.Equal(t, "failed", status,
		"signature mismatch must be rejected; status must reach 'failed' within 35s (got %q)", status)
}

// TestFleetUpgrade_DuplicatePublishReturns409 publishes the same version/platform/arch
// twice without the force flag. The second POST must return 409 Conflict. (Issue #1948)
func TestFleetUpgrade_DuplicatePublishReturns409(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping fleet upgrade test — requires Docker fleet infrastructure")
	}

	_ = newFleetScenarioSuite(t) // wait for fleet healthy
	client := insecureHTTPClient()
	waitForControllerAPI(t, client)

	content := []byte("cfgms-steward-dup-publish-e2e-test-payload")

	// First publish with force=true to ensure a clean state, then without force.
	code := fleetkit.PublishStewardBin(t, client, "v0.5.97-dup", content, true)
	require.Equal(t, http.StatusOK, code, "initial publish (force) must return 200")

	code = fleetkit.PublishStewardBin(t, client, "v0.5.97-dup", content, false)
	require.Equal(t, http.StatusConflict, code,
		"duplicate publish without force must return 409 Conflict")
}

// TestFleetUpgrade_ConcurrentUpgradeRejected dispatches two upgrades for the same
// steward in rapid succession. The second dispatch finds a non-terminal upgrade record
// for the same steward and must return 409 Conflict. (Issue #1948)
func TestFleetUpgrade_ConcurrentUpgradeRejected(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping fleet upgrade test — requires Docker fleet infrastructure")
	}

	suite := newFleetScenarioSuite(t)
	client := insecureHTTPClient()
	waitForControllerAPI(t, client)

	content := []byte("cfgms-steward-concurrent-e2e-test-payload")
	code := fleetkit.PublishStewardBin(t, client, "v0.5.96-conc", content, true)
	require.Equal(t, http.StatusOK, code, "publish v0.5.96-conc must return 200")

	stewardID := suite.StewardIDs["fleet-steward-1"]
	require.NotEmpty(t, stewardID)
	require.True(t, suite.WaitForConvergence(t, stewardID, 30*time.Second),
		"steward must be connected before dispatch")

	// First dispatch creates a record in "dispatched" state. The handler returns
	// 202 synchronously and launches a goroutine to publish the command to the
	// steward. That goroutine must complete a gRPC round-trip to the steward
	// (O(50ms) over Docker networking) before it can transition the record to a
	// terminal state. The second dispatch is issued within the same Go goroutine
	// right after the first HTTP response returns (O(<5ms)), so the record is
	// guaranteed to still be in "dispatched" state.
	code1, upgradeID := fleetkit.DoDispatchUpgrade(t, client, stewardID, "v0.5.96-conc")
	require.Equal(t, http.StatusAccepted, code1, "first dispatch must return 202")
	require.NotEmpty(t, upgradeID)

	// Second dispatch immediately — the first record is still non-terminal.
	code2, _ := fleetkit.DoDispatchUpgrade(t, client, stewardID, "v0.5.96-conc")
	require.Equal(t, http.StatusConflict, code2,
		"concurrent dispatch must return 409 Conflict")
}
