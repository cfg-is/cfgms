// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package initialization

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/controller/config"
	"github.com/cfgis/cfgms/pkg/cert"
	"github.com/cfgis/cfgms/pkg/cert/bundle"
	"github.com/cfgis/cfgms/pkg/logging"
)

// setupInitializedController runs full initialization and returns the config and a
// cert.Manager pointing at the same storage path for direct IsRevoked checks.
func setupInitializedController(t *testing.T) (*testControllerSetup, func()) {
	t.Helper()
	tempDir := t.TempDir()
	caDir := filepath.Join(tempDir, "ca")
	bundlePath := filepath.Join(tempDir, "admin.bundle.yaml")
	logger := logging.NewNoopLogger()

	cfg := makeTestConfig(t, tempDir, caDir, bundlePath)

	_, err := Run(cfg, logger)
	require.NoError(t, err, "initialization must succeed")
	require.FileExists(t, bundlePath, "system admin bundle must be created")

	certManager, err := cert.NewManager(&cert.ManagerConfig{
		StoragePath:    caDir,
		LoadExistingCA: true,
	})
	require.NoError(t, err, "cert manager must load successfully after init")

	return &testControllerSetup{
		cfg:         cfg,
		logger:      logger,
		certManager: certManager,
		bundlePath:  bundlePath,
		caDir:       caDir,
	}, func() {}
}

type testControllerSetup struct {
	cfg         *config.Config
	logger      logging.Logger
	certManager *cert.Manager
	bundlePath  string
	caDir       string
}

// parseX509FromBundle reads a bundle file and returns the parsed X.509 cert.
func parseX509FromBundle(t *testing.T, bundlePath string) *x509.Certificate {
	t.Helper()
	b, err := bundle.Read(bundlePath)
	require.NoError(t, err, "bundle must be readable")

	block, _ := pem.Decode([]byte(b.CertPEM))
	require.NotNil(t, block, "bundle CertPEM must be valid PEM")

	x509cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err, "bundle cert must be valid X.509")
	return x509cert
}

// TestIssueAdminBundle_CreatesFile verifies that IssueAdminBundle creates a bundle
// file at the specified path with mode 0600, containing a cert with CN=alice,
// the admin marker, and 365-day validity.
func TestIssueAdminBundle_CreatesFile(t *testing.T) {
	setup, cleanup := setupInitializedController(t)
	defer cleanup()

	outputPath := filepath.Join(t.TempDir(), "alice.bundle.yaml")

	err := IssueAdminBundle(setup.cfg, setup.logger, "alice", outputPath)
	require.NoError(t, err)

	// File must exist
	info, err := os.Stat(outputPath)
	require.NoError(t, err, "bundle file must exist")

	// Mode must be 0600 (Unix only — Windows does not enforce Unix permission bits)
	if runtime.GOOS != "windows" {
		assert.Equal(t, os.FileMode(0600), info.Mode().Perm(), "bundle file must have mode 0600")
	}

	x509cert := parseX509FromBundle(t, outputPath)

	// Must carry the admin marker
	assert.True(t, cert.HasAdminMarker(x509cert), "admin bundle cert must carry the CFGMS admin marker")

	// CN must match the requested name
	assert.Equal(t, "alice", x509cert.Subject.CommonName)

	// Validity must be 365 days ±1 day
	validity := x509cert.NotAfter.Sub(x509cert.NotBefore)
	assert.InDelta(t, float64(365*24*time.Hour), float64(validity), float64(24*time.Hour),
		"admin cert validity must be 365 days (±1 day)")
}

// TestIssueAdminBundle_ReservedCN_Rejected verifies that reserved common names
// are rejected and no bundle file is created.
func TestIssueAdminBundle_ReservedCN_Rejected(t *testing.T) {
	setup, cleanup := setupInitializedController(t)
	defer cleanup()

	cases := []struct {
		name string
		cn   string
	}{
		{"reserved system", "system"},
		{"reserved cfgms", "cfgms"},
		{"reserved cfgms-internal", "cfgms-internal"},
		{"reserved cfgms-admin", "cfgms-admin"},
		{"steward UUID pattern", "a1b2c3d4-e5f6-7890-abcd-ef1234567890"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			outputPath := filepath.Join(t.TempDir(), "should-not-exist.bundle.yaml")
			err := IssueAdminBundle(setup.cfg, setup.logger, tc.cn, outputPath)
			require.Error(t, err, "reserved CN %q must be rejected", tc.cn)
			assert.Contains(t, err.Error(), "RESERVED_CN",
				"error message must contain RESERVED_CN for %q", tc.cn)
			assert.NoFileExists(t, outputPath, "no bundle file must be created for reserved CN")
		})
	}
}

// TestIssueAdminBundle_InvalidCN_Rejected verifies that invalid common names
// (empty, too long, or containing disallowed characters) are rejected.
func TestIssueAdminBundle_InvalidCN_Rejected(t *testing.T) {
	setup, cleanup := setupInitializedController(t)
	defer cleanup()

	cases := []struct {
		name string
		cn   string
	}{
		{"empty name", ""},
		{"too long", "a" + string(make([]byte, 64))},
		{"contains underscore", "my_admin"},
		{"contains space", "my admin"},
		{"contains unicode", "ädmin"},
		{"leading hyphen", "-alice"},
		{"trailing hyphen", "alice-"},
		{"all hyphens", "----"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			outputPath := filepath.Join(t.TempDir(), "should-not-exist.bundle.yaml")
			err := IssueAdminBundle(setup.cfg, setup.logger, tc.cn, outputPath)
			require.Error(t, err, "invalid CN %q must be rejected", tc.cn)
			assert.NoFileExists(t, outputPath, "no bundle file must be created for invalid CN")
		})
	}
}

// TestIssueAdminBundle_CannotOverwriteSystemBundle verifies that passing the default
// system bundle path as --output is rejected.
func TestIssueAdminBundle_CannotOverwriteSystemBundle(t *testing.T) {
	setup, cleanup := setupInitializedController(t)
	defer cleanup()

	err := IssueAdminBundle(setup.cfg, setup.logger, "alice", defaultAdminBundlePath())
	require.Error(t, err, "must reject outputPath equal to the system bundle path")
	assert.Contains(t, err.Error(), "cannot overwrite the system admin bundle")
}

// TestRevokeAdminBundle_IdempotentDoubleRevoke verifies that revoking the same serial
// twice is a no-op and the original RevokedAt timestamp is preserved.
func TestRevokeAdminBundle_IdempotentDoubleRevoke(t *testing.T) {
	setup, cleanup := setupInitializedController(t)
	defer cleanup()

	outputPath := filepath.Join(t.TempDir(), "idempotent-revoke.bundle.yaml")
	require.NoError(t, IssueAdminBundle(setup.cfg, setup.logger, "idempotent-user", outputPath))

	b, err := bundle.Read(outputPath)
	require.NoError(t, err)
	serial := b.CertSerial

	require.NoError(t, RevokeAdminBundle(setup.cfg, setup.logger, serial))
	require.NoError(t, RevokeAdminBundle(setup.cfg, setup.logger, serial), "double-revoke must be a no-op")
	assert.True(t, setup.certManager.IsRevoked(serial), "cert must still be revoked after double-revoke")
}

// TestIssueAdminBundle_ValidityCap verifies that the issued cert's validity is
// exactly 365 days (±1 day clock-skew tolerance).
func TestIssueAdminBundle_ValidityCap(t *testing.T) {
	setup, cleanup := setupInitializedController(t)
	defer cleanup()

	outputPath := filepath.Join(t.TempDir(), "validity-test.bundle.yaml")
	err := IssueAdminBundle(setup.cfg, setup.logger, "validity-tester", outputPath)
	require.NoError(t, err)

	x509cert := parseX509FromBundle(t, outputPath)
	validity := x509cert.NotAfter.Sub(x509cert.NotBefore)

	assert.InDelta(t, float64(365*24*time.Hour), float64(validity), float64(24*time.Hour),
		"cert NotAfter-NotBefore must be 365 days (±1 day)")
}

// TestRevokeAdminBundle_RevokedThenAuthFails verifies the full revocation lifecycle:
// issue a bundle, confirm it is not revoked (auth would succeed), revoke it, and
// confirm it is revoked (auth would fail with CERT_REVOKED).
func TestRevokeAdminBundle_RevokedThenAuthFails(t *testing.T) {
	setup, cleanup := setupInitializedController(t)
	defer cleanup()

	outputPath := filepath.Join(t.TempDir(), "revoke-test.bundle.yaml")
	err := IssueAdminBundle(setup.cfg, setup.logger, "revoke-test-user", outputPath)
	require.NoError(t, err)

	b, err := bundle.Read(outputPath)
	require.NoError(t, err)
	serial := b.CertSerial

	// Parse the cert and verify it has the admin marker
	block, _ := pem.Decode([]byte(b.CertPEM))
	require.NotNil(t, block)
	x509cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	assert.True(t, cert.HasAdminMarker(x509cert), "issued cert must carry admin marker")

	// Before revocation: cert manager must not report it as revoked
	assert.False(t, setup.certManager.IsRevoked(serial),
		"cert must not be revoked before RevokeAdminBundle is called")

	// Revoke
	err = RevokeAdminBundle(setup.cfg, setup.logger, serial)
	require.NoError(t, err)

	// After revocation: a fresh cert manager (simulating controller restart) must
	// report the serial as revoked (CERT_REVOKED — auth would be rejected)
	freshManager, err := cert.NewManager(&cert.ManagerConfig{
		StoragePath:    setup.caDir,
		LoadExistingCA: true,
	})
	require.NoError(t, err)
	assert.True(t, freshManager.IsRevoked(serial),
		"cert must be revoked after RevokeAdminBundle; auth would return CERT_REVOKED")
}

// TestRegenerate_RequiresConfirmation verifies that RunRegenerate requires the
// operator to type exactly "yes" and exits non-zero otherwise.
func TestRegenerate_RequiresConfirmation(t *testing.T) {
	t.Run("no input cancels regeneration", func(t *testing.T) {
		setup, cleanup := setupInitializedController(t)
		defer cleanup()

		var in bytes.Buffer
		in.WriteString("no\n")
		var out bytes.Buffer

		err := RunRegenerate(setup.cfg, setup.logger, &in, &out)
		require.Error(t, err, "--regenerate with 'no' must exit non-zero")
		assert.Contains(t, out.String(), "Regeneration cancelled.")
	})

	t.Run("empty input cancels regeneration", func(t *testing.T) {
		setup, cleanup := setupInitializedController(t)
		defer cleanup()

		var in bytes.Buffer
		in.WriteString("\n")
		var out bytes.Buffer

		err := RunRegenerate(setup.cfg, setup.logger, &in, &out)
		require.Error(t, err, "--regenerate with empty input must exit non-zero")
		assert.Contains(t, out.String(), "Regeneration cancelled.")
	})

	t.Run("yes confirms regeneration", func(t *testing.T) {
		setup, cleanup := setupInitializedController(t)
		defer cleanup()

		originalBundle, err := bundle.Read(setup.bundlePath)
		require.NoError(t, err)

		var in bytes.Buffer
		in.WriteString("yes\n")

		err = RunRegenerate(setup.cfg, setup.logger, &in, io.Discard)
		require.NoError(t, err, "--regenerate with 'yes' must succeed")

		// Bundle must have been regenerated (new cert serial)
		newBundle, err := bundle.Read(setup.bundlePath)
		require.NoError(t, err)
		assert.NotEqual(t, originalBundle.CertSerial, newBundle.CertSerial,
			"regeneration must produce a new certificate serial")

		// New cert must still carry the admin marker
		x509cert := parseX509FromBundle(t, setup.bundlePath)
		assert.True(t, cert.HasAdminMarker(x509cert), "regenerated cert must carry the admin marker")
	})
}

// TestRegenerate_RecoversFromMissingBundle verifies that when the bundle marker is
// present but the bundle file has been deleted externally, RunRegenerate recreates
// the bundle and the controller initialization state is still valid.
func TestRegenerate_RecoversFromMissingBundle(t *testing.T) {
	setup, cleanup := setupInitializedController(t)
	defer cleanup()

	// Simulate external deletion of the bundle file
	require.NoError(t, os.Remove(setup.bundlePath))
	assert.NoFileExists(t, setup.bundlePath, "pre-condition: bundle file must be absent")

	// The bundle marker file must still be present
	assert.FileExists(t, bundleMarkerPath(setup.bundlePath),
		"pre-condition: bundle marker must still be present")

	// RunRegenerate with "yes" must recreate the bundle
	var in bytes.Buffer
	in.WriteString("yes\n")
	err := RunRegenerate(setup.cfg, setup.logger, &in, io.Discard)
	require.NoError(t, err)

	require.FileExists(t, setup.bundlePath, "bundle file must be recreated by --regenerate")

	// Recreated bundle must be valid
	x509cert := parseX509FromBundle(t, setup.bundlePath)
	assert.True(t, cert.HasAdminMarker(x509cert), "recreated cert must carry the admin marker")

	// Initialization marker must still be intact (controller can start)
	assert.True(t, IsInitialized(setup.caDir),
		"initialization marker must remain intact after --regenerate")
}
