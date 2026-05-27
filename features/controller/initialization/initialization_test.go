// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package initialization

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/controller/config"
	"github.com/cfgis/cfgms/pkg/cert"
	"github.com/cfgis/cfgms/pkg/cert/bundle"
	"github.com/cfgis/cfgms/pkg/logging"
)

func TestIsInitialized(t *testing.T) {
	tempDir := t.TempDir()

	// Not initialized yet
	assert.False(t, IsInitialized(tempDir))

	// Write marker
	marker := &InitMarker{
		Version:           1,
		ControllerVersion: "v0.5.0-test",
		StorageProvider:   "git",
		CAFingerprint:     "test-fingerprint",
	}
	err := WriteInitMarker(tempDir, marker)
	require.NoError(t, err)

	// Now initialized
	assert.True(t, IsInitialized(tempDir))
}

func TestReadWriteInitMarker(t *testing.T) {
	tempDir := t.TempDir()

	original := &InitMarker{
		Version:           1,
		ControllerVersion: "v0.5.0-test",
		StorageProvider:   "git",
		CAFingerprint:     "abc123def456",
	}

	// Write
	err := WriteInitMarker(tempDir, original)
	require.NoError(t, err)

	// Read back
	readBack, err := ReadInitMarker(tempDir)
	require.NoError(t, err)

	assert.Equal(t, original.Version, readBack.Version)
	assert.Equal(t, original.ControllerVersion, readBack.ControllerVersion)
	assert.Equal(t, original.StorageProvider, readBack.StorageProvider)
	assert.Equal(t, original.CAFingerprint, readBack.CAFingerprint)
}

func TestReadInitMarker_NotFound(t *testing.T) {
	tempDir := t.TempDir()

	_, err := ReadInitMarker(tempDir)
	assert.Error(t, err)
}

func TestCreateLegacyMarker(t *testing.T) {
	tempDir := t.TempDir()

	// Create a CA so the fingerprint can be read
	_, err := cert.NewManager(&cert.ManagerConfig{
		StoragePath: tempDir,
		CAConfig: &cert.CAConfig{
			Organization: "Legacy Test",
			Country:      "US",
			ValidityDays: 3650,
			StoragePath:  tempDir,
		},
		LoadExistingCA: false,
	})
	require.NoError(t, err)

	// Create legacy marker
	err = CreateLegacyMarker(tempDir)
	require.NoError(t, err)

	// Verify marker exists and has content
	assert.True(t, IsInitialized(tempDir))

	marker, err := ReadInitMarker(tempDir)
	require.NoError(t, err)
	assert.Equal(t, 1, marker.Version)
	assert.NotEmpty(t, marker.CAFingerprint)
	assert.NotEqual(t, "unknown-legacy", marker.CAFingerprint, "Should compute real fingerprint when CA exists")
}

func TestCreateLegacyMarker_NoCA(t *testing.T) {
	tempDir := t.TempDir()

	// Create legacy marker without CA files — should still succeed with fallback fingerprint
	err := CreateLegacyMarker(tempDir)
	require.NoError(t, err)

	marker, err := ReadInitMarker(tempDir)
	require.NoError(t, err)
	assert.Equal(t, "unknown-legacy", marker.CAFingerprint)
}

func TestCAFilesExist(t *testing.T) {
	tempDir := t.TempDir()

	// No files
	assert.False(t, CAFilesExist(tempDir))

	// Only ca.crt
	require.NoError(t, os.WriteFile(filepath.Join(tempDir, "ca.crt"), []byte("cert"), 0600))
	assert.False(t, CAFilesExist(tempDir))

	// Both ca.crt and ca.key
	require.NoError(t, os.WriteFile(filepath.Join(tempDir, "ca.key"), []byte("key"), 0600))
	assert.True(t, CAFilesExist(tempDir))
}

func TestRollbackTracker(t *testing.T) {
	var order []string

	tracker := NewRollbackTracker()
	tracker.Add("step1", func() error {
		order = append(order, "step1")
		return nil
	})
	tracker.Add("step2", func() error {
		order = append(order, "step2")
		return nil
	})
	tracker.Add("step3", func() error {
		order = append(order, "step3")
		return nil
	})

	err := tracker.Execute()
	assert.NoError(t, err)
	assert.Equal(t, []string{"step3", "step2", "step1"}, order, "Rollback should execute in reverse order")
}

func TestRollbackTracker_Empty(t *testing.T) {
	tracker := NewRollbackTracker()
	err := tracker.Execute()
	assert.NoError(t, err)
}

func TestRun_FullInitialization(t *testing.T) {
	tempDir := t.TempDir()
	caDir := filepath.Join(tempDir, "ca")
	bundlePath := filepath.Join(tempDir, "admin.bundle.yaml")
	logger := logging.NewNoopLogger()

	cfg := &config.Config{
		ListenAddr:      "127.0.0.1:0",
		ExternalURL:     "https://controller.test:9080",
		CertPath:        caDir,
		AdminBundlePath: bundlePath,
		Certificate: &config.CertificateConfig{
			EnableCertManagement:   true,
			CAPath:                 caDir,
			ServerCertValidityDays: 90,
			RenewalThresholdDays:   7,
			Server: &config.ServerCertificateConfig{
				CommonName:   "test-controller",
				DNSNames:     []string{"localhost"},
				IPAddresses:  []string{"127.0.0.1"},
				Organization: "Test Org",
			},
		},
		Storage: &config.StorageConfig{
			Provider:     "flatfile",
			FlatfileRoot: filepath.Join(tempDir, "flatfile"),
			SQLitePath:   filepath.Join(tempDir, "cfgms.db"),
		},
	}

	result, err := Run(cfg, logger)
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.NotEmpty(t, result.CAFingerprint)
	assert.Equal(t, "flatfile", result.StorageProvider)
	assert.False(t, result.InitializedAt.IsZero())

	// Verify CA files were created
	assert.True(t, CAFilesExist(caDir))

	// Verify marker was written
	assert.True(t, IsInitialized(caDir))

	marker, err := ReadInitMarker(caDir)
	require.NoError(t, err)
	assert.Equal(t, result.CAFingerprint, marker.CAFingerprint)
}

func TestRun_AlreadyInitialized(t *testing.T) {
	tempDir := t.TempDir()
	caDir := filepath.Join(tempDir, "ca")
	bundlePath := filepath.Join(tempDir, "admin.bundle.yaml")
	logger := logging.NewNoopLogger()

	cfg := &config.Config{
		ListenAddr:      "127.0.0.1:0",
		ExternalURL:     "https://controller.test:9080",
		CertPath:        caDir,
		AdminBundlePath: bundlePath,
		Certificate: &config.CertificateConfig{
			EnableCertManagement: true,
			CAPath:               caDir,
			Server: &config.ServerCertificateConfig{
				CommonName:   "test-controller",
				Organization: "Test Org",
			},
		},
		Storage: &config.StorageConfig{
			Provider:     "flatfile",
			FlatfileRoot: filepath.Join(tempDir, "flatfile"),
			SQLitePath:   filepath.Join(tempDir, "cfgms.db"),
		},
	}

	// First init should succeed
	_, err := Run(cfg, logger)
	require.NoError(t, err)

	// Second init should fail with "already initialized"
	_, err = Run(cfg, logger)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "already initialized")
}

func TestRun_NilConfig(t *testing.T) {
	logger := logging.NewNoopLogger()
	_, err := Run(nil, logger)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "configuration is required")
}

func TestRun_CertManagementDisabled(t *testing.T) {
	logger := logging.NewNoopLogger()
	cfg := &config.Config{
		Certificate: &config.CertificateConfig{
			EnableCertManagement: false,
		},
	}
	_, err := Run(cfg, logger)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "certificate management must be enabled")
}

// --- Story B: Required tests ---

// TestInit_ProducesAdminBundle verifies that Run writes an admin bundle with a valid
// admin-marked certificate, 365-day validity, and the correct subject.
func TestInit_ProducesAdminBundle(t *testing.T) {
	tempDir := t.TempDir()
	caDir := filepath.Join(tempDir, "ca")
	bundlePath := filepath.Join(tempDir, "admin.bundle.yaml")
	logger := logging.NewNoopLogger()

	cfg := makeTestConfig(t, tempDir, caDir, bundlePath)

	_, err := Run(cfg, logger)
	require.NoError(t, err)

	// Bundle file must exist
	require.FileExists(t, bundlePath)

	b, err := bundle.Read(bundlePath)
	require.NoError(t, err)

	// Parse the cert from the bundle
	block, _ := pem.Decode([]byte(b.CertPEM))
	require.NotNil(t, block, "bundle CertPEM must be valid PEM")
	x509cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)

	// Must carry the admin marker
	assert.True(t, cert.HasAdminMarker(x509cert), "admin cert must carry the CFGMS admin marker OID")

	// Validity must be ~365 days (allow 1-day tolerance for test execution time)
	validity := x509cert.NotAfter.Sub(x509cert.NotBefore)
	assert.InDelta(t, 365*24*time.Hour, validity, float64(24*time.Hour),
		"admin cert validity must be 365 days")

	// Subject: CN=cfgms-admin, O=CFGMS
	assert.Equal(t, "cfgms-admin", x509cert.Subject.CommonName)
	require.Len(t, x509cert.Subject.Organization, 1)
	assert.Equal(t, "CFGMS", x509cert.Subject.Organization[0])
	assert.Empty(t, x509cert.Subject.OrganizationalUnit, "OU must not be set")
}

// TestInit_BundleSerialMatchesMarker verifies that the idempotency marker's serial= line
// matches the serial in the bundle file.
func TestInit_BundleSerialMatchesMarker(t *testing.T) {
	tempDir := t.TempDir()
	caDir := filepath.Join(tempDir, "ca")
	bundlePath := filepath.Join(tempDir, "admin.bundle.yaml")
	logger := logging.NewNoopLogger()

	cfg := makeTestConfig(t, tempDir, caDir, bundlePath)

	_, err := Run(cfg, logger)
	require.NoError(t, err)

	b, err := bundle.Read(bundlePath)
	require.NoError(t, err)

	markerFile, err := readBundleMarker(bundlePath)
	require.NoError(t, err)

	assert.Equal(t, b.CertSerial, markerFile.Serial,
		"bundle marker serial= must match bundle CertSerial")
}

// TestInit_Idempotent_BundleNotOverwritten verifies that if the bundle file already
// exists when Run is called, it is left untouched.
func TestInit_Idempotent_BundleNotOverwritten(t *testing.T) {
	tempDir := t.TempDir()
	caDir := filepath.Join(tempDir, "ca")
	bundlePath := filepath.Join(tempDir, "admin.bundle.yaml")
	logger := logging.NewNoopLogger()

	// Pre-write a sentinel bundle file before initialization
	sentinel := "sentinel-content-do-not-overwrite"
	require.NoError(t, os.WriteFile(bundlePath, []byte(sentinel), 0600))

	cfg := makeTestConfig(t, tempDir, caDir, bundlePath)

	_, err := Run(cfg, logger)
	require.NoError(t, err)

	// The sentinel content must be unchanged
	got, err := os.ReadFile(bundlePath)
	require.NoError(t, err)
	assert.Equal(t, sentinel, string(got), "Run must not overwrite a pre-existing bundle file")
}

// TestInit_MarkerPresent_BundleMissing_Errors verifies that when the bundle issuance
// marker is present but the bundle file has been externally deleted, Run returns
// the operator recovery error pointing at bootstrap-admin --regenerate.
func TestInit_MarkerPresent_BundleMissing_Errors(t *testing.T) {
	tempDir := t.TempDir()
	caDir := filepath.Join(tempDir, "ca")
	bundlePath := filepath.Join(tempDir, "admin.bundle.yaml")
	logger := logging.NewNoopLogger()

	cfg := makeTestConfig(t, tempDir, caDir, bundlePath)

	// First run succeeds: writes init marker, bundle, and bundle issuance marker.
	_, err := Run(cfg, logger)
	require.NoError(t, err)
	require.FileExists(t, bundlePath)

	// Simulate external deletion of the bundle file.
	require.NoError(t, os.Remove(bundlePath))

	// Second run must return the recovery error.
	_, err = Run(cfg, logger)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "admin bundle is missing at")
	assert.Contains(t, err.Error(), "bootstrap-admin --regenerate")
}

// makeTestConfig builds a minimal valid Config for initialization tests using temp dirs.
func makeTestConfig(t *testing.T, tempDir, caDir, bundlePath string) *config.Config {
	t.Helper()
	return &config.Config{
		ListenAddr:      "127.0.0.1:0",
		ExternalURL:     "https://controller.test:9080",
		CertPath:        caDir,
		AdminBundlePath: bundlePath,
		Certificate: &config.CertificateConfig{
			EnableCertManagement: true,
			CAPath:               caDir,
			RenewalThresholdDays: 7,
			Server: &config.ServerCertificateConfig{
				CommonName:   "test-controller",
				DNSNames:     []string{"localhost"},
				IPAddresses:  []string{"127.0.0.1"},
				Organization: "Test Org",
			},
		},
		Storage: &config.StorageConfig{
			Provider:     "flatfile",
			FlatfileRoot: filepath.Join(tempDir, "flatfile"),
			SQLitePath:   filepath.Join(tempDir, "cfgms.db"),
		},
	}
}
