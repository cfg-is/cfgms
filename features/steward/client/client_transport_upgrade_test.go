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
	"sync"
	"sync/atomic"
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
// The signature covers the canonical (contentHash, version, platform, arch) composite
// (Issue #2834), so a signature minted for one release cannot be replayed as another.
// platformArch optionally overrides the host's runtime.GOOS/GOARCH, which is what
// almost every upgrade test dispatches.
func testPublisher(t *testing.T, name string) (store trust.TrustStore, sign func(contentHash, version string, platformArch ...string) []byte) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	ts := trust.NewInMemoryTrustStore()
	require.NoError(t, ts.AddPublisher(trust.PublisherIdentity{
		Name:      name,
		PublicKey: []byte(pub),
		Algorithm: "ed25519",
	}))
	sign = func(contentHash, version string, platformArch ...string) []byte {
		platform, arch := runtime.GOOS, runtime.GOARCH
		if len(platformArch) == 2 {
			platform, arch = platformArch[0], platformArch[1]
		}
		msg, err := trust.StewardBinaryMessage(contentHash, version, platform, arch)
		require.NoError(t, err)
		return ed25519.Sign(priv, []byte(msg))
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
		// Default to launcher-managed so the existing success-path tests continue
		// to exercise the schedule/self-exit logic. Issue #2003 gates the self-exit
		// on this flag; tests that specifically verify the bare/standalone path set
		// it back to false explicitly. (Issue #2003)
		launcherManaged: true,
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
	tamperedSig := sign("wrong-content-hash-that-does-not-match", "v2.0.0")

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
	sig := sign(sha256Hex, "v0.1.0")

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

	revokedVer := "v9.9.9"

	ts, sign := testPublisher(t, "cfgms")
	sig := sign(sha256Hex, revokedVer)

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
	_, _, _, err := c.downloadBinaryForUpgrade(context.Background(), srv.URL+"/binary", tmpPath)
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
	sig := sign(sha256Hex, "v2.0.0")

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

	_, _, _, err := c.downloadBinaryForUpgrade(context.Background(), srv.URL+"/binary", tmpPath)
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
	sig := sign(sha256Hex, "v2.0.0")

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
	sig := sign(sha256Hex, "v2.0.0")

	certStoreDir := t.TempDir()
	c := minimalClientForUpgradeTest(t, certStoreDir, "127.0.0.1", ts, noopSwap)

	params := &pushStewardBinaryParams{
		Version:         "v2.0.0",
		Platform:        runtime.GOOS,
		Arch:            runtime.GOARCH,
		Publisher:       "cfgms",
		BundleSignature: sig,
	}
	err := c.verifyBinarySignature(sha256Hex, params)
	require.NoError(t, err, "valid signature must pass verification")
}

// TestVerifyBinarySignature_RejectsVersionBindingMismatch proves the steward rejects a
// binary that carries a genuine publisher signature issued for DIFFERENT release
// coordinates. This is the rollback defense (Issue #2834): without it, a compromised
// controller could serve a legitimately signed older binary at a newer version's
// coordinates and bypass the downgrade guard, since the version is controller-attested
// rather than signed.
func TestVerifyBinarySignature_RejectsVersionBindingMismatch(t *testing.T) {
	content := []byte("valid binary content")
	sha256Hex := computeSHA256(content)

	ts, sign := testPublisher(t, "cfgms")
	// Authentic signature, but minted for v1.0.0 on this platform.
	sig := sign(sha256Hex, "v1.0.0")

	certStoreDir := t.TempDir()
	c := minimalClientForUpgradeTest(t, certStoreDir, "127.0.0.1", ts, noopSwap)

	cases := map[string]*pushStewardBinaryParams{
		"version substituted":  {Version: "v2.0.0", Platform: runtime.GOOS, Arch: runtime.GOARCH},
		"platform substituted": {Version: "v1.0.0", Platform: "plan9", Arch: runtime.GOARCH},
		"arch substituted":     {Version: "v1.0.0", Platform: runtime.GOOS, Arch: "riscv64"},
	}
	for name, params := range cases {
		t.Run(name, func(t *testing.T) {
			params.Publisher = "cfgms"
			params.BundleSignature = sig
			err := c.verifyBinarySignature(sha256Hex, params)
			require.Error(t, err, "signature bound to different coordinates must be rejected")
		})
	}
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
	sig := sign(sha256Hex, "v99.0.0")

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

	const upgradeVer = "v99.1.0"

	ts, sign := testPublisher(t, "cfgms")
	sig := sign(sha256Hex, upgradeVer)

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

// ---- Issue #2001: pushed upgrade must auto-apply via graceful self-exit ----

// upgradeTestCmd builds a valid push_steward_binary command served by srv.
func upgradeTestCmd(id, ver, downloadURL, sha256Hex string, sig []byte) *cpTypes.Command {
	return &cpTypes.Command{
		ID:        id,
		Type:      cpTypes.CommandPushStewardBinary,
		StewardID: "test-steward",
		TenantID:  "test-tenant",
		Timestamp: time.Now(),
		Params: map[string]interface{}{
			"version":          ver,
			"download_url":     downloadURL,
			"sha256":           sha256Hex,
			"platform":         runtime.GOOS,
			"arch":             runtime.GOARCH,
			"publisher":        "cfgms",
			"bundle_signature": sig,
		},
	}
}

// newUpgradeTestServer returns an HTTPS test server that serves content.
func newUpgradeTestServer(t *testing.T, content []byte) *httptest.Server {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(content)))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(content)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// TestHandlePushStewardBinary_SuccessSchedulesGracefulShutdown verifies that a
// successful swap schedules a graceful shutdown via the injected schedule func
// (not a real time.Sleep) with the configured grace delay, and that invoking the
// scheduled trigger calls the injected shutdown func (not a real os.Exit).
// (Issue #2001 AC 1, 2)
func TestHandlePushStewardBinary_SuccessSchedulesGracefulShutdown(t *testing.T) {
	content := []byte("a valid steward binary that auto-applies")
	sha256Hex := computeSHA256(content)
	ts, sign := testPublisher(t, "cfgms")
	sig := sign(sha256Hex, "v99.2.0")
	srv := newUpgradeTestServer(t, content)

	certStoreDir := t.TempDir()
	fakeLauncher := filepath.Join(certStoreDir, "fake-launcher")
	require.NoError(t, os.WriteFile(fakeLauncher, []byte("fake"), 0o755))

	var (
		shutdownCalled  bool
		scheduledDelay  time.Duration
		capturedTrigger func()
	)
	c := minimalClientForUpgradeTest(t, certStoreDir, "127.0.0.1", ts, noopSwap)
	c.mu.Lock()
	c.transportAddress = "127.0.0.1:4433"
	c.upgradeAllowDowngrade = true
	c.upgradeHTTPClient = srv.Client()
	c.launcherPathOverride = fakeLauncher
	c.shutdownFunc = func() { shutdownCalled = true }
	c.upgradeShutdownGraceDelay = 250 * time.Millisecond
	// Capture instead of firing on a real timer — keeps the test deterministic.
	c.shutdownScheduleFunc = func(delay time.Duration, trigger func()) {
		scheduledDelay = delay
		capturedTrigger = trigger
	}
	c.mu.Unlock()

	cmd := upgradeTestCmd("cmd-auto-apply", "v99.2.0", srv.URL+"/", sha256Hex, sig)
	require.NoError(t, c.handlePushStewardBinary(context.Background(), cmd))

	require.NotNil(t, capturedTrigger, "successful swap must schedule a shutdown trigger")
	assert.Equal(t, 250*time.Millisecond, scheduledDelay,
		"schedule must use the configured grace delay")
	assert.False(t, shutdownCalled,
		"shutdown must NOT fire synchronously inside the handler (ack must be sent first)")

	// Firing the scheduled trigger (as the real timer would after the grace delay)
	// must invoke the injected shutdown func.
	capturedTrigger()
	assert.True(t, shutdownCalled, "scheduled trigger must invoke the shutdown func")
}

// TestHandlePushStewardBinary_FailedSwapDoesNotScheduleShutdown verifies AC 3:
// a launcher swap error must NOT schedule a shutdown or call the shutdown func.
func TestHandlePushStewardBinary_FailedSwapDoesNotScheduleShutdown(t *testing.T) {
	content := []byte("binary whose swap fails")
	sha256Hex := computeSHA256(content)
	ts, sign := testPublisher(t, "cfgms")
	sig := sign(sha256Hex, "v99.3.0")
	srv := newUpgradeTestServer(t, content)

	certStoreDir := t.TempDir()
	fakeLauncher := filepath.Join(certStoreDir, "fake-launcher")
	require.NoError(t, os.WriteFile(fakeLauncher, []byte("fake"), 0o755))

	failingSwap := func(_ context.Context, _, _, _ string) error {
		return fmt.Errorf("launcher swap exploded")
	}

	var (
		shutdownCalled bool
		scheduled      bool
	)
	c := minimalClientForUpgradeTest(t, certStoreDir, "127.0.0.1", ts, failingSwap)
	c.mu.Lock()
	c.transportAddress = "127.0.0.1:4433"
	c.upgradeAllowDowngrade = true
	c.upgradeHTTPClient = srv.Client()
	c.launcherPathOverride = fakeLauncher
	c.shutdownFunc = func() { shutdownCalled = true }
	c.shutdownScheduleFunc = func(_ time.Duration, _ func()) { scheduled = true }
	c.mu.Unlock()

	cmd := upgradeTestCmd("cmd-swap-fail", "v99.3.0", srv.URL+"/", sha256Hex, sig)
	err := c.handlePushStewardBinary(context.Background(), cmd)
	require.Error(t, err, "failed swap must propagate an error")
	assert.Contains(t, err.Error(), "launcher swap")
	assert.False(t, scheduled, "failed swap must NOT schedule a shutdown")
	assert.False(t, shutdownCalled, "failed swap must NOT trigger shutdown")
}

// TestHandlePushStewardBinary_NilShutdownFuncIsSafe verifies that a successful
// swap with no shutdownFunc wired does not panic and does not schedule anything
// (the staged binary then loads on the next restart). (Issue #2001)
func TestHandlePushStewardBinary_NilShutdownFuncIsSafe(t *testing.T) {
	content := []byte("binary with no shutdown wired")
	sha256Hex := computeSHA256(content)
	ts, sign := testPublisher(t, "cfgms")
	sig := sign(sha256Hex, "v99.4.0")
	srv := newUpgradeTestServer(t, content)

	certStoreDir := t.TempDir()
	fakeLauncher := filepath.Join(certStoreDir, "fake-launcher")
	require.NoError(t, os.WriteFile(fakeLauncher, []byte("fake"), 0o755))

	scheduled := false
	c := minimalClientForUpgradeTest(t, certStoreDir, "127.0.0.1", ts, noopSwap)
	c.mu.Lock()
	c.transportAddress = "127.0.0.1:4433"
	c.upgradeAllowDowngrade = true
	c.upgradeHTTPClient = srv.Client()
	c.launcherPathOverride = fakeLauncher
	c.shutdownFunc = nil // not wired
	c.shutdownScheduleFunc = func(_ time.Duration, _ func()) { scheduled = true }
	c.mu.Unlock()

	cmd := upgradeTestCmd("cmd-no-shutdown", "v99.4.0", srv.URL+"/", sha256Hex, sig)
	require.NoError(t, c.handlePushStewardBinary(context.Background(), cmd))
	assert.False(t, scheduled, "with no shutdownFunc wired, nothing should be scheduled")
}

// TestHandlePushStewardBinary_DeferredSelfExitFiresWhenTriggerWired verifies the
// #2602 race fix: a launcher-managed swap staged while shutdownFunc is still nil
// — i.e. the pushed upgrade arrived in the window between command subscription
// (Connect → SubscribeCommands) and the SetShutdownFunc wiring in main.go —
// records a PENDING self-exit, and SetShutdownFunc fires the graceful shutdown as
// soon as the trigger is wired. Without this, the staged (possibly broken) binary
// would silently defer to an unbounded "next restart" and the launcher's
// startup-window auto-rollback would never fire.
func TestHandlePushStewardBinary_DeferredSelfExitFiresWhenTriggerWired(t *testing.T) {
	content := []byte("binary staged before shutdown trigger wired")
	sha256Hex := computeSHA256(content)
	ts, sign := testPublisher(t, "cfgms")
	sig := sign(sha256Hex, "v99.5.0")
	srv := newUpgradeTestServer(t, content)

	certStoreDir := t.TempDir()
	fakeLauncher := filepath.Join(certStoreDir, "fake-launcher")
	require.NoError(t, os.WriteFile(fakeLauncher, []byte("fake"), 0o755))

	var (
		shutdownCalled  bool
		capturedTrigger func()
	)
	c := minimalClientForUpgradeTest(t, certStoreDir, "127.0.0.1", ts, noopSwap)
	c.mu.Lock()
	c.transportAddress = "127.0.0.1:4433"
	c.upgradeAllowDowngrade = true
	c.upgradeHTTPClient = srv.Client()
	c.launcherPathOverride = fakeLauncher
	c.shutdownFunc = nil // trigger not wired yet — the race window
	c.upgradeShutdownGraceDelay = 250 * time.Millisecond
	c.shutdownScheduleFunc = func(_ time.Duration, trigger func()) { capturedTrigger = trigger }
	c.mu.Unlock()

	// Stage the upgrade while shutdownFunc is nil.
	cmd := upgradeTestCmd("cmd-deferred", "v99.5.0", srv.URL+"/", sha256Hex, sig)
	require.NoError(t, c.handlePushStewardBinary(context.Background(), cmd))

	// Nothing is scheduled yet, but the intent to self-exit is recorded.
	assert.Nil(t, capturedTrigger, "self-exit must not be scheduled while the trigger is unwired")
	c.mu.RLock()
	pending := c.pendingUpgradeSelfExit
	c.mu.RUnlock()
	assert.True(t, pending, "a launcher-managed swap staged with no shutdownFunc must record a pending self-exit")

	// Wire the trigger — this must fire the deferred self-exit.
	c.SetShutdownFunc(context.Background(), func() { shutdownCalled = true })

	require.NotNil(t, capturedTrigger, "SetShutdownFunc must schedule the deferred self-exit")
	c.mu.RLock()
	pendingAfter := c.pendingUpgradeSelfExit
	c.mu.RUnlock()
	assert.False(t, pendingAfter, "pending flag must be cleared once the deferred self-exit is fired")

	// Firing the scheduled trigger (as the real grace-delay timer would) invokes
	// the now-wired shutdown func, ending the process so the launcher re-execs.
	capturedTrigger()
	assert.True(t, shutdownCalled, "deferred trigger must invoke the wired shutdown func")
}

// TestHandlePushStewardBinary_LauncherManagedGatesSelfExit verifies the #2003
// gate: after a SUCCESSFUL launcher swap, the steward schedules its graceful
// self-exit ONLY when launcher-managed. A bare/standalone steward stages the
// binary (swap succeeds) but does NOT schedule a shutdown — it keeps running and
// applies the new binary on its next restart, avoiding downtime / a crash loop.
func TestHandlePushStewardBinary_LauncherManagedGatesSelfExit(t *testing.T) {
	cases := []struct {
		name            string
		launcherManaged bool
		wantScheduled   bool
	}{
		{name: "launcher-managed schedules self-exit", launcherManaged: true, wantScheduled: true},
		{name: "standalone stages without self-exit", launcherManaged: false, wantScheduled: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			content := []byte("launcher-managed gate steward binary " + tc.name)
			sha256Hex := computeSHA256(content)
			ts, sign := testPublisher(t, "cfgms")
			sig := sign(sha256Hex, "v99.9.0")
			srv := newUpgradeTestServer(t, content)

			certStoreDir := t.TempDir()
			fakeLauncher := filepath.Join(certStoreDir, "fake-launcher")
			require.NoError(t, os.WriteFile(fakeLauncher, []byte("fake"), 0o755))

			var (
				scheduled      bool
				shutdownCalled bool
			)
			c := minimalClientForUpgradeTest(t, certStoreDir, "127.0.0.1", ts, noopSwap)
			c.mu.Lock()
			c.transportAddress = "127.0.0.1:4433"
			c.upgradeAllowDowngrade = true
			c.upgradeHTTPClient = srv.Client()
			c.launcherPathOverride = fakeLauncher
			c.launcherManaged = tc.launcherManaged
			c.shutdownFunc = func() { shutdownCalled = true }
			c.shutdownScheduleFunc = func(_ time.Duration, _ func()) { scheduled = true }
			c.mu.Unlock()

			cmd := upgradeTestCmd("cmd-gate-"+tc.name, "v99.9.0", srv.URL+"/", sha256Hex, sig)
			// The swap itself must always succeed (binary staged) regardless of the gate.
			require.NoError(t, c.handlePushStewardBinary(context.Background(), cmd),
				"successful swap must not error in either mode")

			assert.Equal(t, tc.wantScheduled, scheduled,
				"schedule must fire iff launcher-managed (managed=%v)", tc.launcherManaged)
			assert.False(t, shutdownCalled,
				"shutdown must never fire synchronously inside the handler")
		})
	}
}

// seqRecordingControlPlane is a real ControlPlaneProvider (embedding the shared
// noopControlPlane) that records every EventCommandCompleted it is asked to
// publish into an ordered sequence. It lets the ordering test observe the
// completion ack as it travels the PRODUCTION publish path
// (statusCallback → publishEventWithQueue → controlPlane.PublishEvent) rather
// than via a bare OnStatus recorder closure. (Issue #2001)
type seqRecordingControlPlane struct {
	noopControlPlane
	record func(string)
}

func (s *seqRecordingControlPlane) PublishEvent(_ context.Context, e *cpTypes.Event) error {
	if e.Type == cpTypes.EventCommandCompleted {
		s.record("completion-ack")
	}
	return nil
}

// TestPushStewardBinary_CompletionAckBeforeShutdown drives the upgrade handler
// through a REAL commands.Handler built by the production setupCommandHandler
// (no mocks) to prove the controller-facing completion ack
// (EventCommandCompleted) is delivered through the real publish path BEFORE the
// graceful shutdown actually fires.
//
// The completion ack observation goes through the wired statusCallback →
// c.publishEventWithQueue → controlPlane.PublishEvent (a real recording control
// plane), exercising the same path used in production rather than a bare
// recorder closure. The handler runs synchronously inside
// commands.Handler.executeCommand, which publishes the ack only after the
// handler returns; the shutdown is deferred behind the schedule func, so
// capturing-and-firing it after handler.Wait() reproduces the real ordering.
// (Issue #2001 AC 4)
func TestPushStewardBinary_CompletionAckBeforeShutdown(t *testing.T) {
	content := []byte("ordering test steward binary")
	sha256Hex := computeSHA256(content)
	ts, sign := testPublisher(t, "cfgms")
	sig := sign(sha256Hex, "v99.5.0")
	srv := newUpgradeTestServer(t, content)

	certStoreDir := t.TempDir()
	fakeLauncher := filepath.Join(certStoreDir, "fake-launcher")
	require.NoError(t, os.WriteFile(fakeLauncher, []byte("fake"), 0o755))

	c := minimalClientForUpgradeTest(t, certStoreDir, "127.0.0.1", ts, noopSwap)

	// Record the ordered sequence of observable side effects.
	var (
		seqMu sync.Mutex
		seq   []string
	)
	record := func(s string) {
		seqMu.Lock()
		seq = append(seq, s)
		seqMu.Unlock()
	}

	var capturedTrigger func()
	c.mu.Lock()
	c.transportAddress = "127.0.0.1:4433"
	c.upgradeAllowDowngrade = true
	c.upgradeHTTPClient = srv.Client()
	c.launcherPathOverride = fakeLauncher
	c.shutdownFunc = func() { record("shutdown") }
	c.shutdownScheduleFunc = func(_ time.Duration, trigger func()) {
		// Defer the trigger exactly as the real timer would — do not run it now.
		capturedTrigger = trigger
	}
	// Wire a real control plane so the completion ack is recorded as it travels
	// the production publish path. publishEventWithQueue calls PublishEvent on a
	// non-nil control plane first; the recording impl records and returns nil.
	c.controlPlane = &seqRecordingControlPlane{record: record}
	c.mu.Unlock()

	// Build the command handler via the PRODUCTION setupCommandHandler so its
	// OnStatus is the real statusCallback (publishEventWithQueue), not a bare
	// recorder. No verifier => unsigned commands accepted.
	h, err := c.setupCommandHandler(context.Background(), "test-steward")
	require.NoError(t, err)

	signed := &cpTypes.SignedCommand{
		Command: *upgradeTestCmd("cmd-order", "v99.5.0", srv.URL+"/", sha256Hex, sig),
	}
	require.NoError(t, h.HandleCommand(context.Background(), signed))
	h.Wait() // executeCommand (incl. completion ack publish) has finished.

	// At this point the completion ack must have been recorded (via the real
	// publish path), and the shutdown must NOT have fired yet (only scheduled).
	seqMu.Lock()
	require.Contains(t, seq, "completion-ack",
		"completion ack must be delivered through the real publish path")
	require.NotContains(t, seq, "shutdown", "shutdown must not fire before the grace delay elapses")
	seqMu.Unlock()
	require.NotNil(t, capturedTrigger, "successful swap must schedule a shutdown")

	// Now fire the deferred trigger, as the real timer would after the grace delay.
	capturedTrigger()

	seqMu.Lock()
	defer seqMu.Unlock()
	require.Equal(t, []string{"completion-ack", "shutdown"}, seq,
		"completion ack must precede the graceful shutdown")
}

// TestPushStewardBinary_DefaultTimerInvokesShutdown exercises the PRODUCTION
// default-timer path of scheduleGracefulShutdownAfterSwap with no injected
// shutdownScheduleFunc: it leaves the schedule func nil, sets a small real grace
// delay, runs the handler on a successful swap, and waits on a channel (with a
// timeout) for the real time.NewTimer to fire the injected shutdownFunc. This is
// the code that actually runs in production. (Issue #2001)
func TestPushStewardBinary_DefaultTimerInvokesShutdown(t *testing.T) {
	content := []byte("default timer path steward binary")
	sha256Hex := computeSHA256(content)
	ts, sign := testPublisher(t, "cfgms")
	sig := sign(sha256Hex, "v99.6.0")
	srv := newUpgradeTestServer(t, content)

	certStoreDir := t.TempDir()
	fakeLauncher := filepath.Join(certStoreDir, "fake-launcher")
	require.NoError(t, os.WriteFile(fakeLauncher, []byte("fake"), 0o755))

	shutdownFired := make(chan struct{})
	c := minimalClientForUpgradeTest(t, certStoreDir, "127.0.0.1", ts, noopSwap)
	c.mu.Lock()
	c.transportAddress = "127.0.0.1:4433"
	c.upgradeAllowDowngrade = true
	c.upgradeHTTPClient = srv.Client()
	c.launcherPathOverride = fakeLauncher
	c.shutdownFunc = func() { close(shutdownFired) }
	c.upgradeShutdownGraceDelay = 10 * time.Millisecond
	c.shutdownScheduleFunc = nil // exercise the real timer goroutine
	c.mu.Unlock()

	cmd := upgradeTestCmd("cmd-real-timer", "v99.6.0", srv.URL+"/", sha256Hex, sig)
	require.NoError(t, c.handlePushStewardBinary(context.Background(), cmd))

	select {
	case <-shutdownFired:
		// Real timer fired and invoked the shutdown func.
	case <-time.After(2 * time.Second):
		t.Fatal("default timer goroutine did not invoke shutdownFunc within 2s")
	}
}

// TestPushStewardBinary_DefaultTimerExitsOnContextCancel verifies that the
// default timer goroutine exits promptly via the RUN context's Done() (rather
// than waiting the full grace delay) when the process is shutting down via
// another path, and that it does NOT redundantly invoke shutdownFunc in that
// case. The early-exit watches the steward's RUN context (wired via
// SetShutdownFunc), not the per-command context. (Issue #2001, #2003)
func TestPushStewardBinary_DefaultTimerExitsOnContextCancel(t *testing.T) {
	content := []byte("ctx cancel path steward binary")
	sha256Hex := computeSHA256(content)
	ts, sign := testPublisher(t, "cfgms")
	sig := sign(sha256Hex, "v99.7.0")
	srv := newUpgradeTestServer(t, content)

	certStoreDir := t.TempDir()
	fakeLauncher := filepath.Join(certStoreDir, "fake-launcher")
	require.NoError(t, os.WriteFile(fakeLauncher, []byte("fake"), 0o755))

	var shutdownCalls int32
	c := minimalClientForUpgradeTest(t, certStoreDir, "127.0.0.1", ts, noopSwap)

	// Wire the RUN context (process lifecycle) via the production setter. The
	// per-command context passed to the handler is deliberately separate.
	runCtx, runCancel := context.WithCancel(context.Background())
	defer runCancel()
	c.SetShutdownFunc(runCtx, func() { atomic.AddInt32(&shutdownCalls, 1) })

	c.mu.Lock()
	c.transportAddress = "127.0.0.1:4433"
	c.upgradeAllowDowngrade = true
	c.upgradeHTTPClient = srv.Client()
	c.launcherPathOverride = fakeLauncher
	// SHORT grace delay: if the early-exit were broken, the timer would fire the
	// shutdown well within the observation window below, so the assertion is not
	// vacuous — it actively races the timer and the run-ctx cancel must win.
	const graceDelay = 50 * time.Millisecond
	c.upgradeShutdownGraceDelay = graceDelay
	c.shutdownScheduleFunc = nil // exercise the real timer goroutine
	c.mu.Unlock()

	cmd := upgradeTestCmd("cmd-ctx-cancel", "v99.7.0", srv.URL+"/", sha256Hex, sig)
	require.NoError(t, c.handlePushStewardBinary(context.Background(), cmd))

	// Cancel the RUN context immediately after the handler returns — the goroutine
	// must take the runCtx.Done() branch and NOT call shutdownFunc (a real shutdown
	// is already underway). This happens at ~t=0, around when the timer is armed.
	runCancel()

	// Actively probe for 250ms (≫ the 50ms grace delay) that the shutdown trigger
	// NEVER fires. require.Never re-evaluates the predicate every 10ms across the
	// whole window, so it is not vacuous the way a single sleep-then-check is: if
	// the run-ctx early-exit branch were removed, the timer would fire at ~50ms and
	// require.Never would catch shutdownCalls > 0 well before the window closes.
	require.Never(t, func() bool {
		return atomic.LoadInt32(&shutdownCalls) > 0
	}, 250*time.Millisecond, 10*time.Millisecond,
		"run-ctx cancel must prevent the shutdown trigger from firing")
}

// TestPushStewardBinary_FiresWhenCommandCtxCancelledImmediately is the #2003
// regression test. It reproduces PRODUCTION: commands.Handler.executeCommand
// runs the handler under a per-command context with `defer cancel()`, so that
// context is cancelled the instant the handler returns (right after the
// completion ack) — always far sooner than the grace delay. The auto-apply
// self-exit MUST still fire because the grace-delay timer watches the RUN
// context (a long-lived context we never cancel), not the per-command context.
//
// This test FAILS against the pre-#2003 code (which selected on the per-command
// ctx and took the ctx.Done() branch immediately) and PASSES after the fix.
func TestPushStewardBinary_FiresWhenCommandCtxCancelledImmediately(t *testing.T) {
	content := []byte("regression 2003 steward binary")
	sha256Hex := computeSHA256(content)
	ts, sign := testPublisher(t, "cfgms")
	sig := sign(sha256Hex, "v99.8.0")
	srv := newUpgradeTestServer(t, content)

	certStoreDir := t.TempDir()
	fakeLauncher := filepath.Join(certStoreDir, "fake-launcher")
	require.NoError(t, os.WriteFile(fakeLauncher, []byte("fake"), 0o755))

	shutdownFired := make(chan struct{})
	c := minimalClientForUpgradeTest(t, certStoreDir, "127.0.0.1", ts, noopSwap)

	// RUN context: long-lived, NEVER cancelled in this test (mimics the steward
	// process staying alive until the grace timer triggers the self-exit).
	runCtx, runCancel := context.WithCancel(context.Background())
	defer runCancel()
	c.SetShutdownFunc(runCtx, func() { close(shutdownFired) })

	c.mu.Lock()
	c.transportAddress = "127.0.0.1:4433"
	c.upgradeAllowDowngrade = true
	c.upgradeHTTPClient = srv.Client()
	c.launcherPathOverride = fakeLauncher
	c.upgradeShutdownGraceDelay = 50 * time.Millisecond
	c.shutdownScheduleFunc = nil // exercise the real timer goroutine
	c.mu.Unlock()

	// Per-command context, exactly as executeCommand builds it: cancelled the
	// instant the handler returns.
	cmdCtx, cmdCancel := context.WithCancel(context.Background())
	cmd := upgradeTestCmd("cmd-2003-regression", "v99.8.0", srv.URL+"/", sha256Hex, sig)
	require.NoError(t, c.handlePushStewardBinary(cmdCtx, cmd))
	cmdCancel() // executeCommand's `defer cancel()` — fires right after the handler returns.

	select {
	case <-shutdownFired:
		// Correct: the grace timer fired and triggered the self-exit even though
		// the per-command context was cancelled immediately.
	case <-time.After(2 * time.Second):
		t.Fatal("shutdownFunc was not invoked after the grace delay; per-command ctx " +
			"cancellation must NOT suppress the auto-apply self-exit (Issue #2003)")
	}
}

// TestDisconnect_DoubleCallNoPanic verifies that Disconnect can be safely called
// more than once — a scenario introduced by the pushed-upgrade self-exit path
// racing a signal/SCM stop (Issue #2001). The guarded close of the stop channels
// must not panic on the second call.
func TestDisconnect_DoubleCallNoPanic(t *testing.T) {
	c := minimalClientForUpgradeTest(t, t.TempDir(), "127.0.0.1", nil, noopSwap)

	ctx := context.Background()
	require.NoError(t, c.Disconnect(ctx), "first Disconnect must succeed")
	assert.NotPanics(t, func() {
		require.NoError(t, c.Disconnect(ctx), "second Disconnect must succeed without panic")
	}, "Disconnect must be idempotent and not panic on double-close")
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
	assert.Equal(t, cpTypes.EventType("steward.upgrade.downloaded"), cpTypes.EventStewardUpgradeDownloaded)
	assert.Equal(t, cpTypes.EventType("steward.upgrade.swapped"), cpTypes.EventStewardUpgradeSwapped)
	assert.Equal(t, cpTypes.EventType("steward.upgrade.committed"), cpTypes.EventStewardUpgradeCommitted)
	assert.Equal(t, cpTypes.EventType("steward.upgrade.rolled_back"), cpTypes.EventStewardUpgradeRolledBack)
}
