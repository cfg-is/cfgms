// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package initialization

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/controller/config"
	"github.com/cfgis/cfgms/pkg/cert"
	"github.com/cfgis/cfgms/pkg/logging"

	// Register storage providers for init tests
	_ "github.com/cfgis/cfgms/pkg/storage/providers/git"
)

func TestIsInitialized(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "init_marker_test")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tempDir) }()

	// Not initialized yet
	assert.False(t, IsInitialized(tempDir))

	// Write marker
	marker := &InitMarker{
		Version:           1,
		ControllerVersion: "v0.5.0-test",
		StorageProvider:   "git",
		CAFingerprint:     "test-fingerprint",
	}
	err = WriteInitMarker(tempDir, marker)
	require.NoError(t, err)

	// Now initialized
	assert.True(t, IsInitialized(tempDir))
}

func TestReadWriteInitMarker(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "init_marker_rw_test")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tempDir) }()

	original := &InitMarker{
		Version:           1,
		ControllerVersion: "v0.5.0-test",
		StorageProvider:   "git",
		CAFingerprint:     "abc123def456",
	}

	// Write
	err = WriteInitMarker(tempDir, original)
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
	tempDir, err := os.MkdirTemp("", "init_marker_notfound_test")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tempDir) }()

	_, err = ReadInitMarker(tempDir)
	assert.Error(t, err)
}

func TestCreateLegacyMarker(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "init_legacy_test")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tempDir) }()

	// Create a CA so the fingerprint can be read
	_, err = cert.NewManager(&cert.ManagerConfig{
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
	tempDir, err := os.MkdirTemp("", "init_legacy_noca_test")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tempDir) }()

	// Create legacy marker without CA files — should still succeed with fallback fingerprint
	err = CreateLegacyMarker(tempDir)
	require.NoError(t, err)

	marker, err := ReadInitMarker(tempDir)
	require.NoError(t, err)
	assert.Equal(t, "unknown-legacy", marker.CAFingerprint)
}

func TestCAFilesExist(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "ca_files_test")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tempDir) }()

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
	tempDir, err := os.MkdirTemp("", "init_full_test")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tempDir) }()

	caDir := filepath.Join(tempDir, "ca")
	logger := logging.NewNoopLogger()

	cfg := &config.Config{
		ListenAddr: "127.0.0.1:0",
		CertPath:   caDir,
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
			Provider: "git",
			Config: map[string]interface{}{
				"repository_path": filepath.Join(tempDir, "storage"),
				"branch":          "main",
				"auto_init":       true,
			},
		},
	}

	result, err := Run(cfg, logger)
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.NotEmpty(t, result.CAFingerprint)
	assert.Equal(t, "git", result.StorageProvider)
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
	tempDir, err := os.MkdirTemp("", "init_already_test")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tempDir) }()

	caDir := filepath.Join(tempDir, "ca")
	logger := logging.NewNoopLogger()

	cfg := &config.Config{
		ListenAddr: "127.0.0.1:0",
		CertPath:   caDir,
		Certificate: &config.CertificateConfig{
			EnableCertManagement: true,
			CAPath:               caDir,
			Server: &config.ServerCertificateConfig{
				CommonName:   "test-controller",
				Organization: "Test Org",
			},
		},
		Storage: &config.StorageConfig{
			Provider: "git",
			Config: map[string]interface{}{
				"repository_path": filepath.Join(tempDir, "storage"),
				"branch":          "main",
				"auto_init":       true,
			},
		},
	}

	// First init should succeed
	_, err = Run(cfg, logger)
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
