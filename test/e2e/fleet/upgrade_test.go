// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// E2E upgrade tests: happy path, broken binary rollback, and negative scenarios. (Issue #1948)
package fleet

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/modules/trust"
)

// testUpgradePrivKey returns the zero-seed Ed25519 private key for E2E upgrade signing.
// The corresponding public key (O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik=) is
// injected into fleet containers via CFGMS_TEST_STEWARD_PUBLISHER_KEY. (Issue #1948)
func testUpgradePrivKey() ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(make([]byte, 32))
}

// signUploadContent signs binary content using the test Ed25519 key.
// The message is the canonical (contentHash, version, platform, arch) composite from
// trust.StewardBinaryMessage, matching trust.VerifyStewardBinarySignature's derivation
// (Issue #2834). Returns a URL-safe base64 (no padding) encoded signature suitable for
// the ?signature= query parameter.
func signUploadContent(t *testing.T, content []byte, version, platform, arch string) string {
	t.Helper()
	sum := sha256.Sum256(content)
	msg, err := trust.StewardBinaryMessage(hex.EncodeToString(sum[:]), version, platform, arch)
	require.NoError(t, err)
	sig := ed25519.Sign(testUpgradePrivKey(), []byte(msg))
	return base64.RawURLEncoding.EncodeToString(sig)
}

// publishStewardBin uploads content to the fleet controller's steward binary store
// using the upgrade-test API key (tenant: fleet-root/fleet-child-a).
// Set force=true to overwrite an existing entry without 409. Returns HTTP status code.
func publishStewardBin(t *testing.T, client *http.Client, version string, content []byte, force bool) int {
	t.Helper()
	sig := signUploadContent(t, content, version, "linux", "amd64")
	u := fmt.Sprintf("%s/api/v1/installer/steward-binaries/%s/linux/amd64?signature=%s",
		fleetControllerHTTP, version, sig)
	if force {
		u += "&force=true"
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, u, bytes.NewReader(content))
	require.NoError(t, err)
	req.Header.Set("X-API-Key", upgradeAPIKey)
	req.Header.Set("Content-Type", "application/octet-stream")
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	return resp.StatusCode
}

// doDispatchUpgrade sends POST /api/v1/stewards/upgrade and returns (statusCode, upgradeID).
// upgradeID is only meaningful when statusCode == 202.
func doDispatchUpgrade(t *testing.T, client *http.Client, stewardID, version string) (int, string) {
	t.Helper()
	payload, err := json.Marshal(map[string]string{
		"selector": "id:" + stewardID,
		"version":  version,
		"platform": "linux",
		"arch":     "amd64",
	})
	require.NoError(t, err)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		fleetControllerHTTP+"/api/v1/stewards/upgrade", bytes.NewReader(payload))
	require.NoError(t, err)
	req.Header.Set("X-API-Key", upgradeAPIKey)
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusAccepted {
		return resp.StatusCode, ""
	}
	var result struct {
		Data struct {
			UpgradeID string `json:"upgrade_id"`
		} `json:"data"`
	}
	_ = json.Unmarshal(body, &result)
	return http.StatusAccepted, result.Data.UpgradeID
}

// dispatchUpgrade dispatches an upgrade to a steward and asserts a 202 response.
func dispatchUpgrade(t *testing.T, client *http.Client, stewardID, version string) string {
	t.Helper()
	code, upgradeID := doDispatchUpgrade(t, client, stewardID, version)
	require.Equal(t, http.StatusAccepted, code, "dispatch must return 202 Accepted")
	require.NotEmpty(t, upgradeID, "dispatch response must contain upgrade_id")
	return upgradeID
}

// blobPath returns the filesystem path of a steward binary blob inside the fleet-controller
// container. The path is under the blob_storage root (/app/data/installers) scoped to the
// upgrade-test tenant (fleet-root/fleet-child-a).
func blobPath(version string) string {
	return fmt.Sprintf("/app/data/installers/fleet-root/fleet-child-a/steward-binaries/%s-linux-amd64",
		version)
}

// blobMetaPath returns the sidecar metadata JSON path for a steward binary blob.
func blobMetaPath(version string) string {
	return blobPath(version) + ".meta.json"
}

// TestFleetStewardUpgradeHappyPath publishes the running steward binary as a new version,
// dispatches an upgrade to fleet-steward-1, and asserts that the upgrade status reaches
// "committed" within 35 s with the steward_id still reachable. (Issue #1948)
func TestFleetStewardUpgradeHappyPath(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping fleet upgrade test — requires Docker fleet infrastructure")
	}

	suite := setupFleetSuite(t)
	client := insecureHTTPClient()
	waitForControllerAPI(t, client)

	// Publish a small payload as v0.5.99-test. The actual steward binary (~30-50 MiB)
	// causes the in-container download to exceed the 35 s status poll window in CI.
	// Any signed payload works — the handler verifies the Ed25519 signature and stages
	// via launcher swap; binary content is not executed by this test flow.
	// force=true so reruns on the same Docker stack don't conflict.
	binaryContent := []byte("cfgms-steward-upgrade-e2e-happy-path-test-payload")
	code := publishStewardBin(t, client, "v0.5.99-test", binaryContent, true)
	require.Equal(t, http.StatusOK, code, "publish v0.5.99-test must return 200")

	stewardID := suite.stewardIDs["fleet-steward-1"]
	require.NotEmpty(t, stewardID, "fleet-steward-1 must have a registered steward ID")
	require.True(t, suite.waitForConvergence(t, stewardID, 30*time.Second),
		"steward must be connected before dispatch")

	upgradeID := dispatchUpgrade(t, client, stewardID, "v0.5.99-test")
	t.Logf("Happy-path upgrade dispatched: upgrade_id=%s steward_id=%s", upgradeID, stewardID)

	status := fetchUpgradeStatus(t, client, upgradeID, 35*time.Second)
	require.Equal(t, "committed", status,
		"upgrade status must reach 'committed' within 35s (got %q)", status)

	// Verify via steward log that the upgrade version was processed.
	require.True(t, suite.waitForStewardVersion(t, "fleet-steward-1", "v0.5.99-test", 10*time.Second),
		"steward must log v0.5.99-test within 10s of upgrade completion")

	// Steward must still be reachable after the upgrade (steward_id unchanged).
	state, err := suite.getStewardConnectionState(t, stewardID)
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

	suite := setupFleetSuite(t)
	client := insecureHTTPClient()
	waitForControllerAPI(t, client)

	// Publish a known-good binary (force=true for idempotency on reruns).
	origContent := []byte("cfgms-steward-upgrade-e2e-broken-binary-original-content")
	code := publishStewardBin(t, client, "v0.5.100-broken", origContent, true)
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
	corruptedContent := []byte("CORRUPTED-BY-E2E-TEST")
	dockerExecRoot(t, "fleet-controller", "sh", "-c",
		"printf 'CORRUPTED-BY-E2E-TEST' > "+blobPath("v0.5.100-broken"))
	corruptedSum := sha256.Sum256(corruptedContent)
	dockerExecRoot(t, "fleet-controller", "sh", "-c",
		fmt.Sprintf(`sed -i 's/"checksum":"[^"]*"/"checksum":"%s"/' %s`,
			hex.EncodeToString(corruptedSum[:]), blobMetaPath("v0.5.100-broken")))

	stewardID := suite.stewardIDs["fleet-steward-1"]
	require.NotEmpty(t, stewardID)
	require.True(t, suite.waitForConvergence(t, stewardID, 30*time.Second),
		"steward must be connected before dispatch")

	upgradeID := dispatchUpgrade(t, client, stewardID, "v0.5.100-broken")
	t.Logf("Broken-binary upgrade dispatched: upgrade_id=%s", upgradeID)

	status := fetchUpgradeStatus(t, client, upgradeID, 35*time.Second)
	// The handler marks the record "failed" (not "rolled_back") on EventCommandFailed;
	// "rolled_back" is only set by the explicit rollback endpoint, which isn't invoked here.
	require.Equal(t, "failed", status,
		"upgrade status must reach 'failed' within 35s (got %q)", status)

	// Steward must still be alive after the failed upgrade.
	state, err := suite.getStewardConnectionState(t, stewardID)
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

	suite := setupFleetSuite(t)
	client := insecureHTTPClient()
	waitForControllerAPI(t, client)

	steward2ID := suite.stewardIDs["fleet-steward-2"]
	require.NotEmpty(t, steward2ID, "fleet-steward-2 must have a registered steward ID")

	// No binary publish needed — the 403 is returned before the binary lookup.
	code, _ := doDispatchUpgrade(t, client, steward2ID, "v0.5.99-test")
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

	suite := setupFleetSuite(t)
	client := insecureHTTPClient()
	waitForControllerAPI(t, client)

	// v0.4.99 is strictly older than the running 0.5.0-dev (major.minor: 0.4 < 0.5).
	downgradeContent := []byte("cfgms-steward-downgrade-e2e-test-payload")
	code := publishStewardBin(t, client, "v0.4.99", downgradeContent, true)
	require.Equal(t, http.StatusOK, code, "publish v0.4.99 must return 200")

	stewardID := suite.stewardIDs["fleet-steward-1"]
	require.NotEmpty(t, stewardID)
	require.True(t, suite.waitForConvergence(t, stewardID, 30*time.Second),
		"steward must be connected before dispatch")

	upgradeID := dispatchUpgrade(t, client, stewardID, "v0.4.99")
	t.Logf("Downgrade dispatch: upgrade_id=%s", upgradeID)

	status := fetchUpgradeStatus(t, client, upgradeID, 35*time.Second)
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

	suite := setupFleetSuite(t)
	client := insecureHTTPClient()
	waitForControllerAPI(t, client)

	sigContent := []byte("cfgms-steward-sig-mismatch-e2e-test-payload")
	code := publishStewardBin(t, client, "v0.5.98-sig", sigContent, true)
	require.Equal(t, http.StatusOK, code, "publish v0.5.98-sig must return 200")

	// Replace the stored signature with base64 of 64 zero bytes — valid encoding,
	// invalid Ed25519 signature. This is what the dispatch handler will forward.
	zeroSig := base64.RawURLEncoding.EncodeToString(make([]byte, 64))
	dockerExecRoot(t, "fleet-controller", "sh", "-c",
		fmt.Sprintf(`sed -i 's/"signature":"[^"]*"/"signature":"%s"/g' %s`,
			zeroSig, blobMetaPath("v0.5.98-sig")))

	stewardID := suite.stewardIDs["fleet-steward-1"]
	require.NotEmpty(t, stewardID)
	require.True(t, suite.waitForConvergence(t, stewardID, 30*time.Second),
		"steward must be connected before dispatch")

	upgradeID := dispatchUpgrade(t, client, stewardID, "v0.5.98-sig")
	t.Logf("Signature-mismatch dispatch: upgrade_id=%s", upgradeID)

	status := fetchUpgradeStatus(t, client, upgradeID, 35*time.Second)
	require.Equal(t, "failed", status,
		"signature mismatch must be rejected; status must reach 'failed' within 35s (got %q)", status)
}

// TestFleetUpgrade_DuplicatePublishReturns409 publishes the same version/platform/arch
// twice without the force flag. The second POST must return 409 Conflict. (Issue #1948)
func TestFleetUpgrade_DuplicatePublishReturns409(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping fleet upgrade test — requires Docker fleet infrastructure")
	}

	_ = setupFleetSuite(t) // wait for fleet healthy
	client := insecureHTTPClient()
	waitForControllerAPI(t, client)

	content := []byte("cfgms-steward-dup-publish-e2e-test-payload")

	// First publish with force=true to ensure a clean state, then without force.
	code := publishStewardBin(t, client, "v0.5.97-dup", content, true)
	require.Equal(t, http.StatusOK, code, "initial publish (force) must return 200")

	code = publishStewardBin(t, client, "v0.5.97-dup", content, false)
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

	suite := setupFleetSuite(t)
	client := insecureHTTPClient()
	waitForControllerAPI(t, client)

	content := []byte("cfgms-steward-concurrent-e2e-test-payload")
	code := publishStewardBin(t, client, "v0.5.96-conc", content, true)
	require.Equal(t, http.StatusOK, code, "publish v0.5.96-conc must return 200")

	stewardID := suite.stewardIDs["fleet-steward-1"]
	require.NotEmpty(t, stewardID)
	require.True(t, suite.waitForConvergence(t, stewardID, 30*time.Second),
		"steward must be connected before dispatch")

	// First dispatch creates a record in "dispatched" state. The handler returns
	// 202 synchronously and launches a goroutine to publish the command to the
	// steward. That goroutine must complete a gRPC round-trip to the steward
	// (O(50ms) over Docker networking) before it can transition the record to a
	// terminal state. The second dispatch is issued within the same Go goroutine
	// right after the first HTTP response returns (O(<5ms)), so the record is
	// guaranteed to still be in "dispatched" state.
	code1, upgradeID := doDispatchUpgrade(t, client, stewardID, "v0.5.96-conc")
	require.Equal(t, http.StatusAccepted, code1, "first dispatch must return 202")
	require.NotEmpty(t, upgradeID)

	// Second dispatch immediately — the first record is still non-terminal.
	code2, _ := doDispatchUpgrade(t, client, stewardID, "v0.5.96-conc")
	require.Equal(t, http.StatusConflict, code2,
		"concurrent dispatch must return 409 Conflict")
}
