// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package initialization

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/controller/config"
	"github.com/cfgis/cfgms/pkg/cert"
	"github.com/cfgis/cfgms/pkg/logging"
)

// initializationrunCharConfig returns a valid flatfile config rooted below a fresh data root.
func initializationrunCharConfig(t *testing.T) (*config.Config, string, string) {
	t.Helper()
	root := controllerDataRoot(t)
	caDir := filepath.Join(root, "ca")
	bundlePath := filepath.Join(root, "admin.bundle.yaml")
	return makeTestConfig(t, root, caDir, bundlePath), caDir, bundlePath
}

// initializationrunCharAssertNothingWritten asserts the preconditions fired before any side effect.
func initializationrunCharAssertNothingWritten(t *testing.T, cfg *config.Config, caDir, bundlePath string) {
	t.Helper()
	assert.NoFileExists(t, bundlePath)
	assert.False(t, IsInitialized(caDir))
	assert.False(t, CAFilesExist(caDir))
	_, err := os.Stat(caDir)
	assert.True(t, os.IsNotExist(err), "CA directory must not be created")
	_, err = os.Stat(cfg.Storage.FlatfileRoot)
	assert.True(t, os.IsNotExist(err), "storage must not be opened")
}

func TestInitializationRunChar_PreconditionsFailBeforeAnyWrite(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(cfg *config.Config)
		env     string
		wantErr string
	}{
		{
			name: "cluster production without realm",
			mutate: func(cfg *config.Config) {
				cfg.HA = &config.HAConfig{Mode: "cluster"}
			},
			env:     "production",
			wantErr: "no realm configured",
		},
		{
			name: "cluster with unrecognised environment",
			mutate: func(cfg *config.Config) {
				cfg.HA = &config.HAConfig{Mode: "cluster"}
			},
			env:     "prod-ish",
			wantErr: "not a recognised deployment",
		},
		{
			name:    "malformed realm",
			mutate:  func(cfg *config.Config) { cfg.RealmID = "Not/A/Label" },
			wantErr: "not a valid realm identifier",
		},
		{
			name:    "cert management disabled",
			mutate:  func(cfg *config.Config) { cfg.Certificate.EnableCertManagement = false },
			wantErr: "certificate management must be enabled",
		},
		{
			name:    "certificate section missing",
			mutate:  func(cfg *config.Config) { cfg.Certificate = nil },
			wantErr: "certificate management must be enabled",
		},
		{
			name:    "missing external_url",
			mutate:  func(cfg *config.Config) { cfg.ExternalURL = "" },
			wantErr: "external_url",
		},
		{
			name:    "empty CA path",
			mutate:  func(cfg *config.Config) { cfg.Certificate.CAPath = "" },
			wantErr: "certificate CA path is required",
		},
		{
			name:    "missing storage config",
			mutate:  func(cfg *config.Config) { cfg.Storage = nil },
			wantErr: "storage configuration is required for initialization",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, caDir, bundlePath := initializationrunCharConfig(t)
			flatRoot := cfg.Storage.FlatfileRoot
			if tt.env != "" {
				t.Setenv("CFGMS_TELEMETRY_ENVIRONMENT", tt.env)
			}
			tt.mutate(cfg)

			result, err := Run(cfg, logging.NewNoopLogger())
			require.Error(t, err)
			assert.Nil(t, result)
			assert.Contains(t, err.Error(), tt.wantErr)

			assert.NoFileExists(t, bundlePath)
			assert.False(t, IsInitialized(caDir))
			assert.False(t, CAFilesExist(caDir))
			_, statErr := os.Stat(flatRoot)
			assert.True(t, os.IsNotExist(statErr), "storage must not be opened")
		})
	}
}

func TestInitializationRunChar_ClusterWithoutRealmWritesNothing(t *testing.T) {
	cfg, caDir, bundlePath := initializationrunCharConfig(t)
	t.Setenv("CFGMS_TELEMETRY_ENVIRONMENT", "production")
	cfg.HA = &config.HAConfig{Mode: "cluster"}

	_, err := Run(cfg, logging.NewNoopLogger())
	require.Error(t, err)
	initializationrunCharAssertNothingWritten(t, cfg, caDir, bundlePath)
}

func TestInitializationRunChar_MissingExternalURLWritesNothing(t *testing.T) {
	cfg, caDir, bundlePath := initializationrunCharConfig(t)
	cfg.ExternalURL = ""

	_, err := Run(cfg, logging.NewNoopLogger())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "external_url")
	initializationrunCharAssertNothingWritten(t, cfg, caDir, bundlePath)
}

func TestInitializationRunChar_SecondRunRefuses(t *testing.T) {
	cfg, caDir, _ := initializationrunCharConfig(t)

	first, err := Run(cfg, logging.NewNoopLogger())
	require.NoError(t, err)

	_, err = Run(cfg, logging.NewNoopLogger())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "controller is already initialized (initialized at ")
	assert.Contains(t, err.Error(), "with CA fingerprint "+first.CAFingerprint)
	assert.Contains(t, err.Error(), "remove the CA directory at "+caDir+" and run --init again")
	assert.NotContains(t, err.Error(), "admin bundle is missing")
}

func TestInitializationRunChar_UnreadableMarkerRefuses(t *testing.T) {
	cfg, caDir, _ := initializationrunCharConfig(t)
	_, err := Run(cfg, logging.NewNoopLogger())
	require.NoError(t, err)

	// Corrupt the marker so it exists but cannot be decoded.
	markerPath := filepath.Join(caDir, markerFileName)
	require.NoError(t, os.WriteFile(markerPath, []byte("{not json"), 0600))

	_, err = Run(cfg, logging.NewNoopLogger())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "controller is already initialized but marker is unreadable")
}

func TestInitializationRunChar_BundleDeletedGivesDistinctError(t *testing.T) {
	cfg, _, bundlePath := initializationrunCharConfig(t)

	first, err := Run(cfg, logging.NewNoopLogger())
	require.NoError(t, err)
	require.NoError(t, os.Remove(bundlePath))

	_, err = Run(cfg, logging.NewNoopLogger())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "controller is initialized (CA fingerprint: "+first.CAFingerprint+") but admin bundle is missing at "+bundlePath)
	assert.Contains(t, err.Error(), "cfgms-controller bootstrap-admin --regenerate")
	assert.NotContains(t, err.Error(), "already initialized")
}

func TestInitializationRunChar_SuccessResultMatchesMarkerAndBundle(t *testing.T) {
	cfg, caDir, bundlePath := initializationrunCharConfig(t)

	result, err := Run(cfg, logging.NewNoopLogger())
	require.NoError(t, err)
	assert.Equal(t, "flatfile", result.StorageProvider)

	marker, err := ReadInitMarker(caDir)
	require.NoError(t, err)
	assert.Equal(t, result.CAFingerprint, marker.CAFingerprint)
	assert.Equal(t, "flatfile", marker.StorageProvider)
	assert.Equal(t, 1, marker.Version)
	assert.True(t, result.InitializedAt.Equal(marker.InitializedAt))
	assert.FileExists(t, bundlePath)
	assert.DirExists(t, caDir)
}

func TestInitializationRunChar_ExistingBundleIsNotOverwritten(t *testing.T) {
	cfg, _, bundlePath := initializationrunCharConfig(t)
	require.NoError(t, os.MkdirAll(filepath.Dir(bundlePath), 0700))
	require.NoError(t, os.WriteFile(bundlePath, []byte("pre-existing"), 0600))

	_, err := Run(cfg, logging.NewNoopLogger())
	require.NoError(t, err)

	got, err := os.ReadFile(bundlePath) // #nosec G304 -- test temp path
	require.NoError(t, err)
	assert.Equal(t, "pre-existing", string(got))
}

func TestInitializationRunChar_CAOrganizationAndCertCommonNames(t *testing.T) {
	cfg, caDir, _ := initializationrunCharConfig(t)
	cfg.Certificate.Server.Organization = "Char Org"
	cfg.Certificate.Internal = &config.InternalCertConfig{CommonName: "char-internal"}
	cfg.Certificate.InternalCertValidityDays = 30

	_, err := Run(cfg, logging.NewNoopLogger())
	require.NoError(t, err)

	mgr, err := cert.NewManager(&cert.ManagerConfig{StoragePath: filepath.Dir(caDir), LoadExistingCA: true})
	require.NoError(t, err)

	tc, err := mgr.GetCurrentCertForPurpose(cert.PurposeTransport)
	require.NoError(t, err)
	block, _ := pem.Decode(tc.CertificatePEM)
	require.NotNil(t, block)
	x, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	assert.Equal(t, "char-internal", x.Subject.CommonName)
	assert.Equal(t, 30, int(x.NotAfter.Sub(x.NotBefore).Hours()/24+0.5))
}

func TestInitializationRunChar_SANsIncludeExternalHostname(t *testing.T) {
	t.Setenv("CFGMS_EXTERNAL_HOSTNAME", "char-controller.example")
	cfg, caDir, _ := initializationrunCharConfig(t)

	_, err := Run(cfg, logging.NewNoopLogger())
	require.NoError(t, err)

	mgr, err := cert.NewManager(&cert.ManagerConfig{StoragePath: filepath.Dir(caDir), LoadExistingCA: true})
	require.NoError(t, err)
	tc, err := mgr.GetCurrentCertForPurpose(cert.PurposeTransport)
	require.NoError(t, err)
	block, _ := pem.Decode(tc.CertificatePEM)
	require.NotNil(t, block)
	x, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	assert.Contains(t, x.DNSNames, "char-controller.example")
	assert.Contains(t, x.DNSNames, "localhost")
}

func TestInitializationRunChar_StorageOpenFailureLeavesNoCAMaterial(t *testing.T) {
	cfg, caDir, bundlePath := initializationrunCharConfig(t)
	blocker := filepath.Join(filepath.Dir(caDir), "blocker")
	require.NoError(t, os.WriteFile(blocker, []byte("file"), 0600))
	cfg.Storage.FlatfileRoot = filepath.Join(blocker, "flatfile")

	_, err := Run(cfg, logging.NewNoopLogger())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to initialize OSS composite storage")
	assert.False(t, IsInitialized(caDir))
	assert.False(t, CAFilesExist(caDir))
	assert.NoFileExists(t, bundlePath)
}

func TestInitializationRunChar_CADirectoryCreationFailure(t *testing.T) {
	cfg, caDir, bundlePath := initializationrunCharConfig(t)
	blocker := filepath.Join(filepath.Dir(caDir), "blocker")
	require.NoError(t, os.WriteFile(blocker, []byte("file"), 0600))
	badCA := filepath.Join(blocker, "ca")
	cfg.Certificate.CAPath = badCA

	_, err := Run(cfg, logging.NewNoopLogger())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create CA directory")
	assert.False(t, IsInitialized(badCA))
	assert.NoFileExists(t, bundlePath)
}
