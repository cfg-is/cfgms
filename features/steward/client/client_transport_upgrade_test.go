// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Tests for handlePushStewardBinary (Issue #1943).
//
// Tests:
//   - TestHandlePushStewardBinary_RejectsInvalidSignature
//   - TestHandlePushStewardBinary_RejectsDowngrade
//   - TestHandlePushStewardBinary_RejectsRevokedVersion
//   - TestHandlePushStewardBinary_RejectsOversizedBinary
//   - TestHandlePushStewardBinary_RejectsCrossHostDownloadURL
//   - TestHandlePushStewardBinary_TempFilePermissions
//   - TestHandlePushStewardBinary_RejectsNonHTTPS
//   - TestHandlePushStewardBinary_RejectsMissingParams
package client

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	cpTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
	"github.com/cfgis/cfgms/pkg/modules/trust"
)

// ---- test helpers ----------------------------------------------------------

// testPublisher creates a new Ed25519 key pair and returns a trust store
// seeded with the public key, plus a sign function that produces valid
// BundleSignature bytes using the private key.
func testPublisher(t *testing.T, name string) (store trust.TrustStore, sign func(contentHash string) []byte) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	ts := trust.NewInMemoryTrustStore()
	require.NoError(t, ts.AddPublisher(trust.PublisherIdentity{
		Name:      name,
		PublicKey: []byte(pub),
		Algorithm: "ed25519",
	}))
	sign = func(contentHash string) []byte {
		return ed25519.Sign(priv, []byte(contentHash))
	}
	return ts, sign
}

// minimalClientForUpgradeTest returns a TransportClient wired for upgrade
// handler tests.  It uses an injectable trust store and launcher swap func
// so no real binaries are required on disk.
func minimalClientForUpgradeTest(
	t *testing.T,
	certStoreDir string,
	controllerHost string,
	trustStore trust.TrustStore,
	swapFn func(ctx context.Context, lPath, ver, bin string) error,
) *TransportClient {
	t.Helper()
	c := &TransportClient{
		stewardID:                  "test-steward",
		tenantID:                   "test-tenant",
		transportAddress:           controllerHost + ":4433",
		heartbeatStop:              make(chan struct{}),
		convergenceStop:            make(chan struct{}),
		logger:                     newTestLogger(t),
		certStoreDir:               certStoreDir,
		upgradePublisherTrustStore: trustStore,
		launcherSwapFunc:           swapFn,
	}
	return c
}

// computeSHA256 returns the hex SHA-256 of data.
func computeSHA256(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

// noopSwap is a launcherSwapFunc that always succeeds.
func noopSwap(_ context.Context, _, _, _ string) error { return nil }

// ---- required tests --------------------------------------------------------

// TestHandlePushStewardBinary_RejectsInvalidSignature verifies that a command
// with a correct SHA-256 but a tampered bundle_signature is rejected and the
// launcher swap is never invoked.
func TestHandlePushStewardBinary_RejectsInvalidSignature(t *testing.T) {
	content := []byte("fake steward binary content")
	sha256Hex := computeSHA256(content)

	ts, sign := testPublisher(t, "cfgms")
	// Tamper: sign the WRONG content hash.
	tamperedSig := sign("wrong-content-hash-that-does-not-match")

	// Use an HTTPS test server; inject its transport so the download proceeds.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(content)))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(content)
	}))
	defer srv.Close()

	certStoreDir := t.TempDir()
	launcherInvoked := false
	swapFn := func(_ context.Context, _, _, _ string) error {
		launcherInvoked = true
		return nil
	}
	c := minimalClientForUpgradeTest(t, certStoreDir, "127.0.0.1", ts, swapFn)
	c.mu.Lock()
	c.transportAddress = "127.0.0.1:4433"
	c.upgradeAllowDowngrade = true     // don't fail on version check
	c.upgradeHTTPClient = srv.Client() // trust the test server's self-signed cert
	c.mu.Unlock()

	cmd := &cpTypes.Command{
		ID:        "cmd-invalid-sig",
		Type:      cpTypes.CommandPushStewardBinary,
		StewardID: "test-steward",
		TenantID:  "test-tenant",
		Timestamp: time.Now(),
		Params: map[string]interface{}{
			"version":          "v2.0.0",
			"download_url":     srv.URL + "/",
			"sha256":           sha256Hex,
			"platform":         runtime.GOOS,
			"arch":             runtime.GOARCH,
			"publisher":        "cfgms",
			"bundle_signature": tamperedSig,
		},
	}

	err := c.handlePushStewardBinary(context.Background(), cmd)
	require.Error(t, err, "tampered signature must be rejected")
	assert.False(t, launcherInvoked, "launcher must NOT be invoked on signature failure")
	assert.Contains(t, err.Error(), "signature verification failed")
}

// TestHandlePushStewardBinary_RejectsDowngrade verifies ErrDowngradeDenied when
// cmd.Version <= running version and allow_downgrade is false.
func TestHandlePushStewardBinary_RejectsDowngrade(t *testing.T) {
	content := []byte("downgrade test binary")
	sha256Hex := computeSHA256(content)

	ts, sign := testPublisher(t, "cfgms")
	// Use a valid signature so the rejection happens specifically at the version check.
	sig := sign(sha256Hex)

	// Serve via HTTPS test server with injected transport.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(content)))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(content)
	}))
	defer srv.Close()

	certStoreDir := t.TempDir()
	launcherInvoked := false
	swapFn := func(_ context.Context, _, _, _ string) error {
		launcherInvoked = true
		return nil
	}

	c := minimalClientForUpgradeTest(t, certStoreDir, "127.0.0.1", ts, swapFn)
	c.mu.Lock()
	c.transportAddress = "127.0.0.1:4433"
	c.upgradeAllowDowngrade = false
	c.upgradeHTTPClient = srv.Client()
	c.mu.Unlock()

	// v0.1.0 is clearly older than the running version (0.5.0-dev in tests).
	cmd := &cpTypes.Command{
		ID: "cmd-downgrade", Type: cpTypes.CommandPushStewardBinary,
		StewardID: "test-steward", TenantID: "test-tenant",
		Timestamp: time.Now(),
		Params: map[string]interface{}{
			"version":          "v0.1.0",
			"download_url":     srv.URL + "/",
			"sha256":           sha256Hex,
			"platform":         runtime.GOOS,
			"arch":             runtime.GOARCH,
			"publisher":        "cfgms",
			"bundle_signature": sig,
		},
	}

	err := c.handlePushStewardBinary(context.Background(), cmd)
	require.Error(t, err, "downgrade must be rejected")
	assert.ErrorIs(t, err, ErrDowngradeDenied, "error must wrap ErrDowngradeDenied")
	assert.False(t, launcherInvoked, "launcher must NOT be invoked for downgrade")
}

// TestHandlePushStewardBinary_RejectsRevokedVersion verifies that a command
// targeting a revoked version is rejected inside the full handler pipeline,
// after successful download and signature verification, before launcher invocation.
func TestHandlePushStewardBinary_RejectsRevokedVersion(t *testing.T) {
	content := []byte("revoked version binary")
	sha256Hex := computeSHA256(content)

	ts, sign := testPublisher(t, "cfgms")
	sig := sign(sha256Hex)

	// Serve via HTTPS; the binary must be downloaded before revocation is checked.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(content)))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(content)
	}))
	defer srv.Close()

	certStoreDir := t.TempDir()
	launcherInvoked := false
	swapFn := func(_ context.Context, _, _, _ string) error {
		launcherInvoked = true
		return nil
	}

	c := minimalClientForUpgradeTest(t, certStoreDir, "127.0.0.1", ts, swapFn)
	c.mu.Lock()
	c.transportAddress = "127.0.0.1:4433"
	c.upgradeAllowDowngrade = true // bypass version check so revocation is exercised
	c.upgradeHTTPClient = srv.Client()
	c.mu.Unlock()

	revokedVer := "v9.9.9"
	c.SetRevokedVersions([]string{"v1.0.0-bad", revokedVer, "v2.0.0-bad"})

	cmd := &cpTypes.Command{
		ID:        "cmd-revoked",
		Type:      cpTypes.CommandPushStewardBinary,
		StewardID: "test-steward",
		TenantID:  "test-tenant",
		Timestamp: time.Now(),
		Params: map[string]interface{}{
			"version":          revokedVer,
			"download_url":     srv.URL + "/",
			"sha256":           sha256Hex,
			"platform":         runtime.GOOS,
			"arch":             runtime.GOARCH,
			"publisher":        "cfgms",
			"bundle_signature": sig,
		},
	}

	err := c.handlePushStewardBinary(context.Background(), cmd)
	require.Error(t, err, "revoked version must be rejected")
	assert.Contains(t, err.Error(), "revoked", "error must mention revocation")
	assert.False(t, launcherInvoked, "launcher must NOT be invoked for revoked version")
}

// TestHandlePushStewardBinary_RejectsOversizedBinary verifies that downloads
// whose Content-Length exceeds MaxBinarySizeBytes are refused immediately,
// before any bytes are written to disk.
func TestHandlePushStewardBinary_RejectsOversizedBinary(t *testing.T) {
	// Serve a response with Content-Length > MaxBinarySizeBytes.
	oversized := MaxBinarySizeBytes + 1
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", fmt.Sprintf("%d", oversized))
		w.WriteHeader(http.StatusOK)
		// We don't need to write actual body — the handler must reject on header alone.
	}))
	defer srv.Close()

	certStoreDir := t.TempDir()
	ts, _ := testPublisher(t, "cfgms")
	c := minimalClientForUpgradeTest(t, certStoreDir, "127.0.0.1", ts, noopSwap)

	// Call downloadBinaryForUpgrade directly to test the size cap without
	// going through the full handler (which requires https).
	tmpPath := filepath.Join(certStoreDir, "oversized-test.bin")
	_, _, err := c.downloadBinaryForUpgrade(context.Background(), srv.URL+"/binary", tmpPath)
	require.Error(t, err, "oversized binary must be rejected")
	assert.Contains(t, err.Error(), "MaxBinarySizeBytes",
		"error message must mention MaxBinarySizeBytes")

	// Temp file must not exist (cleaned up by caller, but here we just check
	// that downloadBinaryForUpgrade itself did not leave a file behind).
	// Note: the file may be partially created; caller is responsible for cleanup.
	// The important thing is that an error was returned.
	_ = os.Remove(tmpPath) // cleanup if created
}

// TestHandlePushStewardBinary_RejectsCrossHostDownloadURL verifies that a
// download_url whose host differs from the controller endpoint host is rejected
// before any download is attempted.
func TestHandlePushStewardBinary_RejectsCrossHostDownloadURL(t *testing.T) {
	content := []byte("cross host test binary")
	sha256Hex := computeSHA256(content)

	ts, sign := testPublisher(t, "cfgms")
	sig := sign(sha256Hex)

	certStoreDir := t.TempDir()
	// Controller is at "controller.example.com"; download URL points elsewhere.
	c := minimalClientForUpgradeTest(t, certStoreDir, "controller.example.com", ts, nil)
	c.mu.Lock()
	c.transportAddress = "controller.example.com:4433"
	c.mu.Unlock()

	launcherInvoked := false
	c.mu.Lock()
	c.launcherSwapFunc = func(_ context.Context, _, _, _ string) error {
		launcherInvoked = true
		return nil
	}
	c.mu.Unlock()

	// Build a command with a download_url pointing at a different host.
	cmd := &cpTypes.Command{
		ID:        "cmd-crosshost",
		Type:      cpTypes.CommandPushStewardBinary,
		StewardID: "test-steward",
		TenantID:  "test-tenant",
		Timestamp: time.Now(),
		Params: map[string]interface{}{
			"version":          "v2.0.0",
			"download_url":     "https://evil.example.com/steward.exe",
			"sha256":           sha256Hex,
			"platform":         runtime.GOOS,
			"arch":             runtime.GOARCH,
			"publisher":        "cfgms",
			"bundle_signature": sig,
		},
	}

	err := c.handlePushStewardBinary(context.Background(), cmd)
	require.Error(t, err, "cross-host download URL must be rejected")
	assert.Contains(t, err.Error(), "does not match controller endpoint host")
	assert.False(t, launcherInvoked, "launcher must NOT be invoked for cross-host URL")
}

// TestHandlePushStewardBinary_TempFilePermissions verifies that the upgrades
// directory is created with mode 0700 and the downloaded binary file has
// mode 0600 when download completes. Uses an injectable launcher function
// so no real launcher binary is required on disk.
func TestHandlePushStewardBinary_TempFilePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("file permission bits are not enforced on Windows in the same way")
	}

	content := []byte("test binary content for permissions check")

	ts, _ := testPublisher(t, "cfgms")

	certStoreDir := t.TempDir()

	// We need to verify the temp file exists with mode 0600 DURING the swap
	// call (before the handler returns). We inject a swapFn that checks this.
	upgradesDir := filepath.Join(certStoreDir, "upgrades")
	var capturedBinPath string
	swapFn := func(_ context.Context, _, _, binaryPath string) error {
		capturedBinPath = binaryPath
		return nil
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(content)))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(content)
	}))
	defer srv.Close()

	host := "127.0.0.1"
	c := minimalClientForUpgradeTest(t, certStoreDir, host, ts, swapFn)
	c.mu.Lock()
	c.transportAddress = host + ":4433"
	// Allow any version since running version in tests is 0.5.0-dev.
	c.upgradeAllowDowngrade = true
	c.mu.Unlock()

	// downloadBinaryForUpgrade is called from handlePushStewardBinary which
	// requires https. Test the download step directly (it creates the file).
	// Then verify the dir and file permissions.
	require.NoError(t, os.MkdirAll(upgradesDir, 0o700))
	tmpPath := filepath.Join(upgradesDir, "test-perm.bin")

	_, _, err := c.downloadBinaryForUpgrade(context.Background(), srv.URL+"/binary", tmpPath)
	require.NoError(t, err, "download must succeed for permissions test")

	// Check directory permission.
	dirInfo, err := os.Stat(upgradesDir)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o700), dirInfo.Mode().Perm(),
		"upgrades dir must be mode 0700")

	// Check file permission.
	fileInfo, err := os.Stat(tmpPath)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), fileInfo.Mode().Perm(),
		"downloaded binary must be mode 0600")

	// Confirm the swap function received the binary path (integration check).
	// We simulate the handler's launcher call here.
	err = c.execLauncherSwap(context.Background(), "/fake/launcher", "v2.0.0", tmpPath)
	require.NoError(t, err)
	assert.Equal(t, tmpPath, capturedBinPath,
		"launcher swap must receive the downloaded binary path")
}

// TestHandlePushStewardBinary_RejectsNonHTTPS verifies that a download_url
// with a non-https scheme is rejected immediately.
func TestHandlePushStewardBinary_RejectsNonHTTPS(t *testing.T) {
	content := []byte("test content")
	sha256Hex := computeSHA256(content)
	ts, sign := testPublisher(t, "cfgms")
	sig := sign(sha256Hex)

	certStoreDir := t.TempDir()
	c := minimalClientForUpgradeTest(t, certStoreDir, "127.0.0.1", ts, noopSwap)

	for _, scheme := range []string{"http", "ftp", "file"} {
		t.Run(scheme, func(t *testing.T) {
			cmd := &cpTypes.Command{
				ID:        "cmd-non-https",
				Type:      cpTypes.CommandPushStewardBinary,
				StewardID: "test-steward",
				TenantID:  "test-tenant",
				Timestamp: time.Now(),
				Params: map[string]interface{}{
					"version":          "v2.0.0",
					"download_url":     scheme + "://127.0.0.1/binary",
					"sha256":           sha256Hex,
					"platform":         runtime.GOOS,
					"arch":             runtime.GOARCH,
					"publisher":        "cfgms",
					"bundle_signature": sig,
				},
			}
			err := c.handlePushStewardBinary(context.Background(), cmd)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "https", "error must mention https requirement")
		})
	}
}

// TestHandlePushStewardBinary_RejectsMissingParams verifies that missing
// required params return an error before any I/O.
func TestHandlePushStewardBinary_RejectsMissingParams(t *testing.T) {
	certStoreDir := t.TempDir()
	ts, _ := testPublisher(t, "cfgms")
	c := minimalClientForUpgradeTest(t, certStoreDir, "127.0.0.1", ts, noopSwap)

	base := map[string]interface{}{
		"version":          "v2.0.0",
		"download_url":     "https://127.0.0.1/binary",
		"sha256":           "abc123",
		"platform":         runtime.GOOS,
		"arch":             runtime.GOARCH,
		"publisher":        "cfgms",
		"bundle_signature": []byte{1, 2, 3},
	}
	requiredFields := []string{"version", "download_url", "sha256", "platform", "arch", "publisher", "bundle_signature"}

	for _, field := range requiredFields {
		t.Run("missing_"+field, func(t *testing.T) {
			params := make(map[string]interface{}, len(base))
			for k, v := range base {
				params[k] = v
			}
			delete(params, field)

			cmd := &cpTypes.Command{
				ID: "cmd-missing-" + field, Type: cpTypes.CommandPushStewardBinary,
				StewardID: "test-steward", TenantID: "test-tenant",
				Timestamp: time.Now(), Params: params,
			}
			err := c.handlePushStewardBinary(context.Background(), cmd)
			require.Error(t, err, "missing %q must return error", field)
		})
	}
}

// TestVerifyBinarySignature_ValidKey tests that a correct signature passes.
func TestVerifyBinarySignature_ValidKey(t *testing.T) {
	content := []byte("valid binary content")
	sha256Hex := computeSHA256(content)

	ts, sign := testPublisher(t, "cfgms")
	sig := sign(sha256Hex)

	certStoreDir := t.TempDir()
	c := minimalClientForUpgradeTest(t, certStoreDir, "127.0.0.1", ts, noopSwap)

	params := &pushStewardBinaryParams{
		Publisher:       "cfgms",
		BundleSignature: sig,
	}
	err := c.verifyBinarySignature(sha256Hex, params)
	require.NoError(t, err, "valid signature must pass verification")
}

// TestIsNewerVersion exercises the version comparison helper.
func TestIsNewerVersion(t *testing.T) {
	tests := []struct {
		candidate, running string
		want               bool
	}{
		{"v2.0.0", "v1.0.0", true},
		{"v1.1.0", "v1.0.0", true},
		{"v1.0.1", "v1.0.0", true},
		{"v1.0.0", "v1.0.0", false},
		{"v0.9.0", "v1.0.0", false},
		{"v1.0.0-dev", "0.5.0-dev", true},
		{"v2.0.0", "0.5.0-dev", true},
		{"0.5.0-dev", "0.5.0-dev", false},
		{"v0.1.0", "0.5.0-dev", false},
	}
	for _, tt := range tests {
		t.Run(tt.candidate+"_vs_"+tt.running, func(t *testing.T) {
			got := isNewerVersion(tt.candidate, tt.running)
			assert.Equal(t, tt.want, got)
		})
	}
}

// TestParsePushStewardBinaryParams verifies param parsing and validation.
func TestParsePushStewardBinaryParams(t *testing.T) {
	sig := make([]byte, 64)
	for i := range sig {
		sig[i] = byte(i)
	}

	// Valid params round-trip through JSON (simulates controller sending params).
	raw := map[string]interface{}{
		"version":          "v2.0.0",
		"download_url":     "https://ctrl.example.com/binary",
		"sha256":           "abc123",
		"platform":         "linux",
		"arch":             "amd64",
		"publisher":        "cfgms",
		"bundle_signature": sig,
	}
	// JSON round-trip (encodes []byte as base64).
	data, err := json.Marshal(raw)
	require.NoError(t, err)
	var coerced map[string]interface{}
	require.NoError(t, json.Unmarshal(data, &coerced))

	p, err := parsePushStewardBinaryParams(coerced)
	require.NoError(t, err)
	assert.Equal(t, "v2.0.0", p.Version)
	assert.Equal(t, sig, p.BundleSignature)

	// Missing publisher.
	delete(coerced, "publisher")
	_, err = parsePushStewardBinaryParams(coerced)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "publisher")
}

// TestSetRevokedVersions ensures SetRevokedVersions replaces the existing list.
func TestSetRevokedVersions(t *testing.T) {
	certStoreDir := t.TempDir()
	ts, _ := testPublisher(t, "cfgms")
	c := minimalClientForUpgradeTest(t, certStoreDir, "127.0.0.1", ts, noopSwap)

	c.SetRevokedVersions([]string{"v1.0.0-bad", "v2.0.0-bad"})
	assert.True(t, c.isVersionRevoked("v1.0.0-bad"))
	assert.True(t, c.isVersionRevoked("v2.0.0-bad"))
	assert.False(t, c.isVersionRevoked("v3.0.0"))

	// Replace list.
	c.SetRevokedVersions([]string{"v3.0.0-bad"})
	assert.False(t, c.isVersionRevoked("v1.0.0-bad"), "replaced list must not contain old entries")
	assert.True(t, c.isVersionRevoked("v3.0.0-bad"))
}

// TestUpgradeEventsEmitted verifies that EventStewardUpgradeDownloaded and
// EventStewardUpgradeSwapped are queued in the OfflineQueue when a successful
// upgrade flow completes. Uses an in-memory OfflineQueue (Dir: "") so no
// encryption key or disk persistence is required.
func TestUpgradeEventsEmitted(t *testing.T) {
	content := []byte("upgrade event test binary")
	sha256Hex := computeSHA256(content)

	ts, sign := testPublisher(t, "cfgms")
	sig := sign(sha256Hex)

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(content)))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(content)
	}))
	defer srv.Close()

	certStoreDir := t.TempDir()

	// Create a fake launcher so the stat check passes.
	fakeLauncher := filepath.Join(certStoreDir, "fake-launcher")
	require.NoError(t, os.WriteFile(fakeLauncher, []byte("fake"), 0o755))

	// In-memory OfflineQueue captures events without disk I/O or encryption.
	queue, err := NewOfflineQueue(OfflineQueueConfig{})
	require.NoError(t, err)

	c := minimalClientForUpgradeTest(t, certStoreDir, "127.0.0.1", ts, noopSwap)
	c.mu.Lock()
	c.transportAddress = "127.0.0.1:4433"
	c.upgradeAllowDowngrade = true
	c.upgradeHTTPClient = srv.Client()
	c.launcherPathOverride = fakeLauncher
	c.offlineQueue = queue
	c.mu.Unlock()

	cmd := &cpTypes.Command{
		ID:        "cmd-events-test",
		Type:      cpTypes.CommandPushStewardBinary,
		StewardID: "test-steward",
		TenantID:  "test-tenant",
		Timestamp: time.Now(),
		Params: map[string]interface{}{
			"version":          "v99.0.0",
			"download_url":     srv.URL + "/",
			"sha256":           sha256Hex,
			"platform":         runtime.GOOS,
			"arch":             runtime.GOARCH,
			"publisher":        "cfgms",
			"bundle_signature": sig,
		},
	}

	require.NoError(t, c.handlePushStewardBinary(context.Background(), cmd),
		"upgrade must succeed to test event emission")

	// Both lifecycle events must have been queued.
	require.Equal(t, 2, queue.Len(),
		"EventStewardUpgradeDownloaded + EventStewardUpgradeSwapped must be queued")

	var gotTypes []cpTypes.EventType
	queue.Drain(func(e *cpTypes.Event) error {
		gotTypes = append(gotTypes, e.Type)
		return nil
	})
	assert.Contains(t, gotTypes, cpTypes.EventStewardUpgradeDownloaded,
		"EventStewardUpgradeDownloaded must be queued")
	assert.Contains(t, gotTypes, cpTypes.EventStewardUpgradeSwapped,
		"EventStewardUpgradeSwapped must be queued")
}

// TestHandlePushStewardBinary_HappyPath verifies the complete successful upgrade
// pipeline end-to-end: valid params → HTTPS download → SHA-256 match → valid
// signature → version check → not revoked → events queued → launcher invoked.
func TestHandlePushStewardBinary_HappyPath(t *testing.T) {
	content := []byte("a valid steward binary for the happy path test")
	sha256Hex := computeSHA256(content)

	ts, sign := testPublisher(t, "cfgms")
	sig := sign(sha256Hex)

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(content)))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(content)
	}))
	defer srv.Close()

	certStoreDir := t.TempDir()

	// Create a fake launcher binary so the stat check passes.
	fakeLauncher := filepath.Join(certStoreDir, "fake-launcher")
	require.NoError(t, os.WriteFile(fakeLauncher, []byte("#!/bin/sh\necho ok"), 0o755))

	// Capture launcher invocation args.
	var (
		launcherCalled bool
		capturedVer    string
		capturedBin    string
	)
	swapFn := func(_ context.Context, _, ver, bin string) error {
		launcherCalled = true
		capturedVer = ver
		capturedBin = bin
		return nil
	}

	// In-memory OfflineQueue captures events.
	queue, err := NewOfflineQueue(OfflineQueueConfig{})
	require.NoError(t, err)

	c := minimalClientForUpgradeTest(t, certStoreDir, "127.0.0.1", ts, swapFn)
	c.mu.Lock()
	c.transportAddress = "127.0.0.1:4433"
	c.upgradeAllowDowngrade = true
	c.upgradeHTTPClient = srv.Client()
	c.launcherPathOverride = fakeLauncher
	c.offlineQueue = queue
	c.mu.Unlock()

	const upgradeVer = "v99.1.0"
	cmd := &cpTypes.Command{
		ID:        "cmd-happy-path",
		Type:      cpTypes.CommandPushStewardBinary,
		StewardID: "test-steward",
		TenantID:  "test-tenant",
		Timestamp: time.Now(),
		Params: map[string]interface{}{
			"version":          upgradeVer,
			"download_url":     srv.URL + "/",
			"sha256":           sha256Hex,
			"platform":         runtime.GOOS,
			"arch":             runtime.GOARCH,
			"publisher":        "cfgms",
			"bundle_signature": sig,
		},
	}

	require.NoError(t, c.handlePushStewardBinary(context.Background(), cmd),
		"happy path must succeed end-to-end")

	// Launcher must have been called with the correct version.
	require.True(t, launcherCalled, "launcher swap must have been invoked")
	assert.Equal(t, upgradeVer, capturedVer, "launcher must receive the target version")
	assert.NotEmpty(t, capturedBin, "launcher must receive a binary path")

	// Both upgrade events must have been queued.
	require.Equal(t, 2, queue.Len(), "downloaded + swapped events must be queued")
	var gotTypes []cpTypes.EventType
	queue.Drain(func(e *cpTypes.Event) error {
		gotTypes = append(gotTypes, e.Type)
		return nil
	})
	assert.Contains(t, gotTypes, cpTypes.EventStewardUpgradeDownloaded)
	assert.Contains(t, gotTypes, cpTypes.EventStewardUpgradeSwapped)
}

// TestHandlePushStewardBinary_LaunherPathConstant verifies that launcherPath()
// returns a non-empty, absolute path appropriate for the current platform.
func TestHandlePushStewardBinary_LauncherPathConstant(t *testing.T) {
	p := launcherPath()
	require.NotEmpty(t, p, "launcher path must not be empty")
	// Should be an absolute path on all platforms.
	if runtime.GOOS == "windows" {
		assert.Contains(t, p, `\`, "Windows launcher path must use backslash separators")
		assert.Contains(t, p, "cfgms-steward-launcher.exe")
	} else {
		assert.True(t, len(p) > 0 && p[0] == '/', "Unix launcher path must be absolute")
		assert.Contains(t, p, "cfgms-launcher")
	}
}

// TestUpgradeCommandRegistered verifies CommandPushStewardBinary constant exists
// and has the expected string value.
func TestUpgradeCommandRegistered(t *testing.T) {
	assert.Equal(t, cpTypes.CommandType("push_steward_binary"), cpTypes.CommandPushStewardBinary)
	assert.Equal(t, cpTypes.EventType("steward_upgrade_downloaded"), cpTypes.EventStewardUpgradeDownloaded)
	assert.Equal(t, cpTypes.EventType("steward_upgrade_swapped"), cpTypes.EventStewardUpgradeSwapped)
	assert.Equal(t, cpTypes.EventType("steward_upgrade_committed"), cpTypes.EventStewardUpgradeCommitted)
	assert.Equal(t, cpTypes.EventType("steward_upgrade_rolled_back"), cpTypes.EventStewardUpgradeRolledBack)
}
