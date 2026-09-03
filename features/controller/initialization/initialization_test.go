// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package initialization

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	_ "github.com/lib/pq"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/controller/config"
	"github.com/cfgis/cfgms/pkg/cert"
	"github.com/cfgis/cfgms/pkg/cert/bundle"
	"github.com/cfgis/cfgms/pkg/logging"
	secretsinterfaces "github.com/cfgis/cfgms/pkg/secrets/interfaces"
)

// getTestDBPassword returns the test database password from CFGMS_TEST_DB_PASSWORD,
// or generates a cryptographically secure random password when unset.
// Inlined here to avoid the pkg/testutil → features/controller/initialization import cycle.
func getTestDBPassword() string {
	if pw := os.Getenv("CFGMS_TEST_DB_PASSWORD"); pw != "" {
		return pw
	}
	return generateSecureTestPassword()
}

// generateSecureTestPassword generates a cryptographically secure random password.
// Mirrors pkg/testutil.GenerateSecurePassword() — inlined to avoid the import cycle.
func generateSecureTestPassword() string {
	randomBytes := make([]byte, 32)
	if _, err := rand.Read(randomBytes); err != nil {
		return fmt.Sprintf("test-fallback-%d", 0) // rand.Read failure is extremely rare
	}
	pw := base64.StdEncoding.EncodeToString(randomBytes)
	pw = strings.ReplaceAll(pw, "=", "")
	pw = strings.ReplaceAll(pw, "+", "")
	pw = strings.ReplaceAll(pw, "/", "")
	if len(pw) > 25 {
		pw = pw[:25]
	}
	return pw
}

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

// TestRun_RejectsUnsetExternalURL verifies that Run fails with an actionable error
// when external_url is not configured, and that no CA material or init marker is
// written (the check fires before any side-effecting initialization step).
func TestRun_RejectsUnsetExternalURL(t *testing.T) {
	tempDir := t.TempDir()
	caDir := filepath.Join(tempDir, "ca")
	bundlePath := filepath.Join(tempDir, "admin.bundle.yaml")
	logger := logging.NewNoopLogger()

	cfg := makeTestConfig(t, tempDir, caDir, bundlePath)
	cfg.ExternalURL = ""

	_, err := Run(cfg, logger)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "external_url",
		"error must name the field that needs to be set")
	assert.NoFileExists(t, bundlePath,
		"no admin bundle must be written when external_url is unset")
	assert.False(t, IsInitialized(caDir),
		"init marker must not be written when external_url is unset: check must fire before CA material")
}

// TestRun_BundleHonoursExternalURL verifies that the ControllerURL in the system
// admin bundle matches the configured external_url after initialization.
func TestRun_BundleHonoursExternalURL(t *testing.T) {
	tempDir := t.TempDir()
	caDir := filepath.Join(tempDir, "ca")
	bundlePath := filepath.Join(tempDir, "admin.bundle.yaml")
	logger := logging.NewNoopLogger()

	cfg := makeTestConfig(t, tempDir, caDir, bundlePath)
	cfg.ExternalURL = "https://controller.example.com:9080"

	_, err := Run(cfg, logger)
	require.NoError(t, err)

	b, err := bundle.Read(bundlePath)
	require.NoError(t, err)
	assert.Equal(t, "https://controller.example.com:9080", b.ControllerURL,
		"bundle ControllerURL must reflect the configured external_url")
}

// makeTestConfig builds a minimal valid Config for initialization tests using temp dirs.
// TestRun_TransportCertHonorsExternalHostname is the regression test for the
// fleet-e2e failure on PR #1820: the fleet-controller container ran --init
// with CFGMS_EXTERNAL_HOSTNAME=fleet-controller and a controller.cfg that set
// certificate.server.dns_names: [fleet-controller, localhost], but the cert
// generated by --init had only the hard-coded default SANs. Once --init mints
// the transport cert, EnsureSeparatedCertificates is idempotent — startup will
// not regenerate, so any SAN the steward needs must be present on the cert
// minted here.
func TestRun_TransportCertHonorsExternalHostname(t *testing.T) {
	t.Setenv("CFGMS_EXTERNAL_HOSTNAME", "fleet-controller")

	tempDir := t.TempDir()
	caDir := filepath.Join(tempDir, "ca")
	bundlePath := filepath.Join(tempDir, "admin.bundle.yaml")
	logger := logging.NewNoopLogger()

	cfg := &config.Config{
		ListenAddr:      "127.0.0.1:0",
		ExternalURL:     "https://fleet-controller:9080",
		CertPath:        caDir,
		AdminBundlePath: bundlePath,
		Certificate: &config.CertificateConfig{
			EnableCertManagement: true,
			CAPath:               caDir,
			RenewalThresholdDays: 7,
			Server: &config.ServerCertificateConfig{
				CommonName:   "fleet-controller",
				DNSNames:     []string{"fleet-controller", "localhost"},
				IPAddresses:  []string{"127.0.0.1"},
				Organization: "CFGMS Fleet Test",
			},
		},
		Storage: &config.StorageConfig{
			Provider:     "flatfile",
			FlatfileRoot: filepath.Join(tempDir, "flatfile"),
			SQLitePath:   filepath.Join(tempDir, "cfgms.db"),
		},
	}

	_, err := Run(cfg, logger)
	require.NoError(t, err)

	// Reopen the cert manager and inspect the InternalServer (PurposeTransport)
	// certificate that --init persisted to the store.
	// StoragePath is the parent of "ca/" — matching the invariant in cert.NewManager.
	certManager, err := cert.NewManager(&cert.ManagerConfig{
		StoragePath:    tempDir,
		LoadExistingCA: true,
	})
	require.NoError(t, err)

	transportCert, err := certManager.GetCurrentCertForPurpose(cert.PurposeTransport)
	require.NoError(t, err, "transport cert must exist after --init")

	block, _ := pem.Decode(transportCert.CertificatePEM)
	require.NotNil(t, block)
	x509Cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)

	assert.Contains(t, x509Cert.DNSNames, "fleet-controller",
		"transport cert SAN list must include CFGMS_EXTERNAL_HOSTNAME and certificate.server.dns_names; missing fleet-controller is the fleet-e2e regression")
	assert.Contains(t, x509Cert.DNSNames, "localhost", "loopback SAN must be preserved")
	assert.Contains(t, x509Cert.DNSNames, "controller-standalone", "transport default SAN must be preserved")
}

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

// buildInitTestPostgresDSN returns a DSN for the shared test Postgres instance.
func buildInitTestPostgresDSN() string {
	pw := getTestDBPassword()
	port := 5432
	if p := os.Getenv("CFGMS_TEST_DB_PORT"); p != "" {
		if pi, err := strconv.Atoi(p); err == nil {
			port = pi
		}
	}
	dbName := "cfgms_test"
	if v := os.Getenv("CFGMS_TEST_DB_NAME"); v != "" {
		dbName = v
	}
	dbUser := "cfgms_test"
	if v := os.Getenv("CFGMS_TEST_DB_USER"); v != "" {
		dbUser = v
	}
	return fmt.Sprintf("host=localhost port=%d dbname=%s user=%s password=%s sslmode=disable",
		port, dbName, dbUser, pw)
}

// skipInitTestIfNoPostgres skips the calling test if the Postgres instance is unreachable.
func skipInitTestIfNoPostgres(t *testing.T) string {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping Postgres test in short mode")
	}
	dsn := buildInitTestPostgresDSN()
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Skip("Postgres not available:", err)
	}
	defer func() { _ = db.Close() }()
	if err := db.Ping(); err != nil {
		t.Skip("Postgres not reachable:", err)
	}
	return dsn
}

// TestRun_ClusterMode_VaultKeyPathValidation verifies that Run returns a clear error
// when ha.mode is cluster, cluster_ca is configured, but vault_key_path is malformed.
// This test does not require a running OpenBao instance.
func TestRun_ClusterMode_VaultKeyPathValidation(t *testing.T) {
	pgDSN := skipInitTestIfNoPostgres(t)

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
			RenewalThresholdDays: 7,
			Server: &config.ServerCertificateConfig{
				CommonName:   "test-controller",
				Organization: "Test Org",
			},
			ClusterCA: &config.ClusterCAConfig{
				VaultAddress: "https://vault.example.com:8200",
				VaultKeyPath: "malformed-no-slash", // intentionally invalid
			},
		},
		Storage: &config.StorageConfig{
			Provider: "database",
			Cluster: &config.ClusterStorageConfig{
				PostgresDSN: pgDSN,
			},
		},
		HA: &config.HAConfig{Mode: "cluster"},
	}

	_, err := Run(cfg, logger)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "vault_key_path")
}

// TestRun_ClusterMode_UsesDatabaseProvider is the REQUIRED test for Issue #2119:
// Run() with ha.Mode == ClusterMode + a test Postgres DSN must succeed and report
// "database" as the storage provider, confirming the database-backed steward store
// (not flatfile/SQLite) is selected.
func TestRun_ClusterMode_UsesDatabaseProvider(t *testing.T) {
	pgDSN := skipInitTestIfNoPostgres(t)

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
			RenewalThresholdDays: 7,
			Server: &config.ServerCertificateConfig{
				CommonName:   "test-controller",
				DNSNames:     []string{"localhost"},
				IPAddresses:  []string{"127.0.0.1"},
				Organization: "Test Org",
			},
		},
		Storage: &config.StorageConfig{
			Provider: "database",
			Cluster: &config.ClusterStorageConfig{
				PostgresDSN: pgDSN,
			},
		},
		HA: &config.HAConfig{Mode: "cluster"},
	}

	result, err := Run(cfg, logger)
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, "database", result.StorageProvider,
		"cluster-mode init must record database as the storage provider")
	assert.NotEmpty(t, result.CAFingerprint)
	assert.False(t, result.InitializedAt.IsZero())
}

// TestRun_AdminBundleControllerURLMatchesTier1BootstrapTemplate verifies that the
// admin bundle produced by initialization.Run embeds the controller's real ExternalURL
// rather than the localhost:8080 default.
// Regression test for Issue #3170: the bootstrap template omitted the top-level
// external_url key, so cfg.ExternalURL stayed at its compiled default "https://localhost:8080"
// and every issued admin bundle pointed at the wrong address.
// TestRun_HonorsAbsoluteCAPath verifies that initialization.Run writes CA files at
// exactly the configured certificate.ca_path (an absolute path), regardless of the
// test process's working directory. This is the core regression test for Issue #3171,
// where cfg.CertPath (a non-empty compiled relative default) shadowed CAPath and caused
// CA files to land under <CWD>/certs/ca/ instead of the configured absolute location.
func TestRun_HonorsAbsoluteCAPath(t *testing.T) {
	tempDir := t.TempDir()
	// Use a nested directory to make the absolute path unambiguous.
	caDir := filepath.Join(tempDir, "certs", "ca")
	bundlePath := filepath.Join(tempDir, "admin.bundle.yaml")
	logger := logging.NewNoopLogger()

	cfg := &config.Config{
		ListenAddr:      "127.0.0.1:0",
		ExternalURL:     "https://controller.test:9080",
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

	_, err := Run(cfg, logger)
	require.NoError(t, err)

	// CA files must exist at the configured caDir — not at a CWD-relative location.
	assert.FileExists(t, filepath.Join(caDir, "ca.crt"),
		"ca.crt must be written at the configured certificate.ca_path, not at a CWD-relative path")
	assert.FileExists(t, filepath.Join(caDir, "ca.key"),
		"ca.key must be written at the configured certificate.ca_path")

	// Init marker must be at caDir too (IsInitialized checks caDir/.cfgms-initialized).
	assert.True(t, IsInitialized(caDir),
		"init marker must be written at the configured certificate.ca_path")

	// A cert.NewManager using StoragePath=filepath.Dir(caDir) must reload the CA without
	// error — this mirrors what loadExistingCertificateManager does on server startup,
	// proving that --init and startup agree on the same storage location.
	reloadManager, err := cert.NewManager(&cert.ManagerConfig{
		StoragePath:    filepath.Dir(caDir),
		LoadExistingCA: true,
	})
	require.NoError(t, err, "cert manager must reload CA written by initialization.Run")
	require.NotNil(t, reloadManager)
}

// TestRun_HonorsTrailingSlashCAPath verifies that a trailing slash in
// certificate.ca_path is handled correctly by filepath.Clean — the CA must still land
// at the configured directory, not at a wrong nested path.
func TestRun_HonorsTrailingSlashCAPath(t *testing.T) {
	tempDir := t.TempDir()
	caDir := filepath.Join(tempDir, "certs", "ca")
	bundlePath := filepath.Join(tempDir, "admin.bundle.yaml")
	logger := logging.NewNoopLogger()

	cfg := &config.Config{
		ListenAddr:      "127.0.0.1:0",
		ExternalURL:     "https://controller.test:9080",
		AdminBundlePath: bundlePath,
		Certificate: &config.CertificateConfig{
			EnableCertManagement: true,
			CAPath:               caDir + "/", // trailing slash — filepath.Clean must normalize it
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

	_, err := Run(cfg, logger)
	require.NoError(t, err)

	// CA files must exist at caDir (without the trailing slash).
	assert.FileExists(t, filepath.Join(caDir, "ca.crt"),
		"trailing slash in ca_path must not change where CA files land")
	assert.FileExists(t, filepath.Join(caDir, "ca.key"))

	// Server-startup equivalent: reload via StoragePath=filepath.Dir(filepath.Clean(caDir+"/"))=filepath.Dir(caDir).
	reloadManager, err := cert.NewManager(&cert.ManagerConfig{
		StoragePath:    filepath.Dir(caDir),
		LoadExistingCA: true,
	})
	require.NoError(t, err, "trailing-slash ca_path must not break CA reload")
	require.NotNil(t, reloadManager)
}

func TestRun_AdminBundleControllerURLMatchesTier1BootstrapTemplate(t *testing.T) {
	tempDir := t.TempDir()
	caDir := filepath.Join(tempDir, "ca")
	bundlePath := filepath.Join(tempDir, "admin.bundle.yaml")
	logger := logging.NewNoopLogger()

	// Config mirroring the fixed tier1-bootstrap.sh template output for a host
	// named "ctrl.tier1.lab" with the default REST port 9080.
	cfg := &config.Config{
		ListenAddr:      "127.0.0.1:0",
		ExternalURL:     "https://ctrl.tier1.lab:9080",
		CertPath:        caDir,
		AdminBundlePath: bundlePath,
		Transport: &config.TransportConfig{
			ListenAddr:      "0.0.0.0:4433",
			ExternalAddress: "ctrl.tier1.lab",
			UseCertManager:  true,
			MaxConnections:  50000,
			KeepalivePeriod: config.Duration(30 * time.Second),
			IdleTimeout:     config.Duration(5 * time.Minute),
		},
		Certificate: &config.CertificateConfig{
			EnableCertManagement:   true,
			CAPath:                 caDir,
			ServerCertValidityDays: 90,
			RenewalThresholdDays:   7,
			Server: &config.ServerCertificateConfig{
				CommonName:   "ctrl.tier1.lab",
				DNSNames:     []string{"ctrl.tier1.lab", "localhost"},
				IPAddresses:  []string{"127.0.0.1"},
				Organization: "CFGMS Tier 1",
			},
		},
		Storage: &config.StorageConfig{
			Provider:     "flatfile",
			FlatfileRoot: filepath.Join(tempDir, "flatfile"),
			SQLitePath:   filepath.Join(tempDir, "cfgms.db"),
		},
	}

	_, err := Run(cfg, logger)
	require.NoError(t, err)

	b, err := bundle.Read(bundlePath)
	require.NoError(t, err)

	assert.Equal(t, "https://ctrl.tier1.lab:9080", b.ControllerURL,
		"admin bundle controller_url must embed the configured ExternalURL, not localhost:8080")
	assert.NotContains(t, b.ControllerURL, "localhost:8080",
		"admin bundle must not embed the compiled default ExternalURL")
}

// inMemSecretStore is a minimal thread-safe in-memory SecretStore for unit
// tests. It exercises the real SecretStore interface without requiring a
// running OpenBao instance — mirrors pkg/cert's identically-named test helper.
type inMemSecretStore struct {
	mu       sync.RWMutex
	secrets  map[string]string
	versions map[string]int
}

func newInMemSecretStore() *inMemSecretStore {
	return &inMemSecretStore{secrets: make(map[string]string), versions: make(map[string]int)}
}

func (s *inMemSecretStore) StoreSecret(_ context.Context, req *secretsinterfaces.SecretRequest) error {
	if req.TenantID == "" {
		return fmt.Errorf("TenantID is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.secrets[req.TenantID+"/"+req.Key] = req.Value
	s.versions[req.TenantID+"/"+req.Key]++
	return nil
}

// CompareAndSwapSecret honours expectedVersion per the SecretStore contract
// (Issue #3775): version 0 means create-if-absent, and a mismatch is reported as
// ok=false with a nil error rather than as a failure.
func (s *inMemSecretStore) CompareAndSwapSecret(_ context.Context, key string, expectedVersion int, req *secretsinterfaces.SecretRequest) (int, bool, error) {
	if req.TenantID == "" {
		return 0, false, fmt.Errorf("TenantID is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.versions[key] != expectedVersion {
		return 0, false, nil
	}
	s.secrets[req.TenantID+"/"+req.Key] = req.Value
	s.versions[key]++
	return s.versions[key], true, nil
}

func (s *inMemSecretStore) GetSecret(_ context.Context, key string) (*secretsinterfaces.Secret, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	val, ok := s.secrets[key]
	if !ok {
		return nil, fmt.Errorf("%w: %s", secretsinterfaces.ErrSecretNotFound, key)
	}
	return &secretsinterfaces.Secret{Key: key, Value: val}, nil
}

func (s *inMemSecretStore) DeleteSecret(_ context.Context, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.secrets, key)
	delete(s.versions, key)
	return nil
}

func (s *inMemSecretStore) ListSecrets(_ context.Context, _ *secretsinterfaces.SecretFilter) ([]*secretsinterfaces.SecretMetadata, error) {
	return nil, nil
}

func (s *inMemSecretStore) GetSecrets(ctx context.Context, keys []string) (map[string]*secretsinterfaces.Secret, error) {
	result := make(map[string]*secretsinterfaces.Secret, len(keys))
	for _, k := range keys {
		if sec, err := s.GetSecret(ctx, k); err == nil {
			result[k] = sec
		}
	}
	return result, nil
}

func (s *inMemSecretStore) StoreSecrets(ctx context.Context, secrets map[string]*secretsinterfaces.SecretRequest) error {
	for _, req := range secrets {
		if err := s.StoreSecret(ctx, req); err != nil {
			return err
		}
	}
	return nil
}

func (s *inMemSecretStore) GetSecretVersion(_ context.Context, key string, _ int) (*secretsinterfaces.Secret, error) {
	return s.GetSecret(context.Background(), key)
}

func (s *inMemSecretStore) ListSecretVersions(_ context.Context, _ string) ([]*secretsinterfaces.SecretVersion, error) {
	return nil, nil
}

func (s *inMemSecretStore) GetSecretMetadata(_ context.Context, key string) (*secretsinterfaces.SecretMetadata, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if _, ok := s.secrets[key]; !ok {
		return nil, fmt.Errorf("%w: %s", secretsinterfaces.ErrSecretNotFound, key)
	}
	now := time.Now()
	return &secretsinterfaces.SecretMetadata{Key: key, CreatedAt: now, UpdatedAt: now}, nil
}

func (s *inMemSecretStore) UpdateSecretMetadata(_ context.Context, _ string, _ map[string]string) error {
	return nil
}

func (s *inMemSecretStore) RotateSecret(_ context.Context, key string, newValue string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.secrets[key] = newValue
	return nil
}

func (s *inMemSecretStore) ExpireSecret(ctx context.Context, key string) error {
	return s.DeleteSecret(ctx, key)
}

func (s *inMemSecretStore) HealthCheck(_ context.Context) error { return nil }
func (s *inMemSecretStore) Close() error                        { return nil }

var _ secretsinterfaces.SecretStore = (*inMemSecretStore)(nil)

// externalIntermediateFixture builds a real root CA and a regional
// intermediate signed under it — mirroring an offline root ceremony's output —
// and writes the intermediate's certificate, private key, and root-terminal
// issuer chain to PEM files, returning their paths plus the PEM bytes needed
// for assertions.
func externalIntermediateFixture(t *testing.T) (certPath, keyPath, chainPath string, intermediateCertPEM, rootCertPEM []byte) {
	t.Helper()

	rootMgr, err := cert.NewManager(&cert.ManagerConfig{
		StoragePath: t.TempDir(),
		CAConfig: &cert.CAConfig{
			Organization:  "Test Offline Root",
			Country:       "US",
			ValidityDays:  3650,
			PathLength:    1,
			PathLengthSet: true,
		},
	})
	require.NoError(t, err)

	rootCertPEM, err = rootMgr.GetCACertificate()
	require.NoError(t, err)

	subKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	subCert, err := rootMgr.SignSubordinateCA(&subKey.PublicKey, &cert.SubordinateCAConfig{
		CommonName:   "Regional Intermediate",
		Organization: "Test Org",
		ValidityDays: 3650,
		PathLength:   0,
	})
	require.NoError(t, err)
	subKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(subKey),
	})

	dir := t.TempDir()
	certPath = filepath.Join(dir, "intermediate.crt")
	keyPath = filepath.Join(dir, "intermediate.key")
	chainPath = filepath.Join(dir, "chain.pem")
	require.NoError(t, os.WriteFile(certPath, subCert.CertificatePEM, 0600))
	require.NoError(t, os.WriteFile(keyPath, subKeyPEM, 0600))
	require.NoError(t, os.WriteFile(chainPath, rootCertPEM, 0600))

	return certPath, keyPath, chainPath, subCert.CertificatePEM, rootCertPEM
}

// clusterCAConfigWithExternalPaths builds the cluster-mode controller config
// the external-intermediate tests boot from.
func clusterCAConfigWithExternalPaths(certPath, keyPath, chainPath string) *config.Config {
	return &config.Config{
		Certificate: &config.CertificateConfig{
			EnableCertManagement: true,
			Server: &config.ServerCertificateConfig{
				Organization: "Test Cluster",
			},
			ClusterCA: &config.ClusterCAConfig{
				VaultAddress:                  "https://vault.test:8200",
				VaultKeyPath:                  "root/cluster-ca",
				ExternalIntermediateCertPath:  certPath,
				ExternalIntermediateKeyPath:   keyPath,
				ExternalIntermediateChainPath: chainPath,
			},
		},
	}
}

// TestBuildClusterCertManager_ExternalIntermediate_TrustAnchorIsRoot is the
// REQUIRED test for Issue #3779: booting a cluster-mode controller with
// certificate.cluster_ca external-intermediate paths set must produce a
// Manager whose GetCACertificate() equals the offline root's certificate PEM
// byte-for-byte, and NOT the imported intermediate's own certificate — the
// trust-anchor-identity check security review required, since chain validity
// alone would pass whether the pinned anchor is the root or the intermediate.
// A freshly issued leaf's IssuerChainPEM must carry the intermediate, proving
// the two fields carry deliberately different material.
//
// The vault is a real in-process SecretStore implementation injected through
// BuildClusterCertManagerWithStore — the same cluster-CA code path production
// runs, with only the OpenBao connection replaced by the caller.
func TestBuildClusterCertManager_ExternalIntermediate_TrustAnchorIsRoot(t *testing.T) {
	certPath, keyPath, chainPath, intermediateCertPEM, rootCertPEM := externalIntermediateFixture(t)

	store := newInMemSecretStore()
	cfg := clusterCAConfigWithExternalPaths(certPath, keyPath, chainPath)

	certStorageDir := t.TempDir()
	logger := logging.NewNoopLogger()

	mgr, err := BuildClusterCertManagerWithStore(context.Background(), cfg, certStorageDir, store, logger)
	require.NoError(t, err)

	anchor, err := mgr.GetCACertificate()
	require.NoError(t, err)
	assert.Equal(t, rootCertPEM, anchor, "GetCACertificate() must equal the offline root's certificate PEM")
	assert.NotEqual(t, intermediateCertPEM, anchor, "GetCACertificate() must NOT equal the imported intermediate's own certificate PEM")

	leaf, err := mgr.GenerateClientCertificate(&cert.ClientCertConfig{
		CommonName:   "steward-001",
		Organization: "CFGMS Stewards",
		ClientID:     "steward-001",
		ValidityDays: 365,
	})
	require.NoError(t, err)
	assert.Equal(t, intermediateCertPEM, leaf.IssuerChainPEM,
		"a freshly issued leaf's IssuerChainPEM must carry the imported intermediate, for handshake chain assembly")

	// The intermediate's private key must never be written to any node disk.
	keyPaths := []string{
		filepath.Join(certStorageDir, "ca.key"),
		filepath.Join(certStorageDir, "ca", "ca.key"),
	}
	for _, kp := range keyPaths {
		_, statErr := os.Stat(kp)
		assert.True(t, os.IsNotExist(statErr), "ca.key must not exist at %s", kp)
	}
}

// TestBuildClusterCertManager_PeerLoadingFromVaultPinsTheSameRoot is the
// cluster-convergence half of the trust-anchor guarantee: a peer node whose own
// config has no external_intermediate_* keys — so it takes the
// cert.NewManagerFromSecretStore load path against the same vault — must
// publish the SAME anchor (the offline root) and issue leaves carrying the
// intermediate. If the importing node's issuer chain were not persisted, this
// peer would pin the routinely-rotated intermediate as the fleet root and the
// two nodes would hand stewards different permanent anchors.
func TestBuildClusterCertManager_PeerLoadingFromVaultPinsTheSameRoot(t *testing.T) {
	certPath, keyPath, chainPath, intermediateCertPEM, rootCertPEM := externalIntermediateFixture(t)

	store := newInMemSecretStore()
	ctx := context.Background()
	logger := logging.NewNoopLogger()

	_, err := BuildClusterCertManagerWithStore(ctx, clusterCAConfigWithExternalPaths(certPath, keyPath, chainPath), t.TempDir(), store, logger)
	require.NoError(t, err)

	peerCfg := &config.Config{
		Certificate: &config.CertificateConfig{
			EnableCertManagement: true,
			ClusterCA: &config.ClusterCAConfig{
				VaultAddress: "https://vault.test:8200",
				VaultKeyPath: "root/cluster-ca",
			},
		},
	}
	peerMgr, err := BuildClusterCertManagerWithStore(ctx, peerCfg, t.TempDir(), store, logger)
	require.NoError(t, err)

	peerAnchor, err := peerMgr.GetCACertificate()
	require.NoError(t, err)
	assert.Equal(t, rootCertPEM, peerAnchor,
		"a peer loading the cluster CA from the vault must pin the offline root, not the intermediate")
	assert.NotEqual(t, intermediateCertPEM, peerAnchor)

	peerLeaf, err := peerMgr.GenerateClientCertificate(&cert.ClientCertConfig{
		CommonName:   "steward-002",
		Organization: "CFGMS Stewards",
		ClientID:     "steward-002",
		ValidityDays: 365,
	})
	require.NoError(t, err)
	assert.Equal(t, intermediateCertPEM, peerLeaf.IssuerChainPEM,
		"leaves issued by the vault-loading peer must carry the intermediate so they chain to the root")
}

// TestBuildClusterCertManager_ImportRefusesToReplaceExistingVaultIdentity
// proves the import path never silently re-roots a cluster: adding the
// external_intermediate_* keys to a cluster whose vault already holds a
// self-generated fleet root must fail closed, leaving the published CA
// untouched, rather than overwriting it and breaking every certificate already
// issued under it.
func TestBuildClusterCertManager_ImportRefusesToReplaceExistingVaultIdentity(t *testing.T) {
	certPath, keyPath, chainPath, _, _ := externalIntermediateFixture(t)

	store := newInMemSecretStore()
	ctx := context.Background()
	logger := logging.NewNoopLogger()

	selfGenCfg := &config.Config{
		Certificate: &config.CertificateConfig{
			EnableCertManagement: true,
			ClusterCA: &config.ClusterCAConfig{
				VaultAddress: "https://vault.test:8200",
				VaultKeyPath: "root/cluster-ca",
			},
		},
	}
	selfGenMgr, err := BuildClusterCertManagerWithStore(ctx, selfGenCfg, t.TempDir(), store, logger)
	require.NoError(t, err)
	originalAnchor, err := selfGenMgr.GetCACertificate()
	require.NoError(t, err)

	_, err = BuildClusterCertManagerWithStore(ctx, clusterCAConfigWithExternalPaths(certPath, keyPath, chainPath), t.TempDir(), store, logger)
	require.Error(t, err, "importing different material over an established cluster CA must fail closed")
	assert.Contains(t, err.Error(), "refusing to overwrite")

	stored, err := store.GetSecret(ctx, "root/cluster-ca")
	require.NoError(t, err)
	assert.Equal(t, string(originalAnchor), stored.Value,
		"the vault must still hold the original self-generated CA certificate")
}

// TestBuildClusterCertManager_ExternalIntermediateReadFailures covers the three
// file reads importClusterIntermediateCA performs: a configured path that names
// a missing file, and one that names a directory, must each surface as an
// explicit error naming which piece of material could not be read — not as a
// panic, a nil manager, or a confusing downstream parse error.
func TestBuildClusterCertManager_ExternalIntermediateReadFailures(t *testing.T) {
	tests := []struct {
		name       string
		breakPaths func(t *testing.T, certPath, keyPath, chainPath string) (string, string, string)
		wantErr    string
	}{
		{
			name: "missing certificate file",
			breakPaths: func(t *testing.T, certPath, keyPath, chainPath string) (string, string, string) {
				require.NoError(t, os.Remove(certPath))
				return certPath, keyPath, chainPath
			},
			wantErr: "failed to read external intermediate CA certificate",
		},
		{
			name: "certificate path is a directory",
			breakPaths: func(t *testing.T, _, keyPath, chainPath string) (string, string, string) {
				return t.TempDir(), keyPath, chainPath
			},
			wantErr: "failed to read external intermediate CA certificate",
		},
		{
			name: "missing private key file",
			breakPaths: func(t *testing.T, certPath, keyPath, chainPath string) (string, string, string) {
				require.NoError(t, os.Remove(keyPath))
				return certPath, keyPath, chainPath
			},
			wantErr: "failed to read external intermediate CA private key",
		},
		{
			name: "private key path is a directory",
			breakPaths: func(t *testing.T, certPath, _, chainPath string) (string, string, string) {
				return certPath, t.TempDir(), chainPath
			},
			wantErr: "failed to read external intermediate CA private key",
		},
		{
			name: "missing issuer chain file",
			breakPaths: func(t *testing.T, certPath, keyPath, chainPath string) (string, string, string) {
				require.NoError(t, os.Remove(chainPath))
				return certPath, keyPath, chainPath
			},
			wantErr: "failed to read external intermediate CA issuer chain",
		},
		{
			name: "issuer chain path is a directory",
			breakPaths: func(t *testing.T, certPath, keyPath, _ string) (string, string, string) {
				return certPath, keyPath, t.TempDir()
			},
			wantErr: "failed to read external intermediate CA issuer chain",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			certPath, keyPath, chainPath, _, _ := externalIntermediateFixture(t)
			certPath, keyPath, chainPath = tc.breakPaths(t, certPath, keyPath, chainPath)

			store := newInMemSecretStore()
			mgr, err := BuildClusterCertManagerWithStore(context.Background(),
				clusterCAConfigWithExternalPaths(certPath, keyPath, chainPath),
				t.TempDir(), store, logging.NewNoopLogger())

			require.Error(t, err)
			assert.Nil(t, mgr)
			assert.Contains(t, err.Error(), tc.wantErr)

			// A failed read must publish nothing to the vault.
			_, getErr := store.GetSecret(context.Background(), "root/cluster-ca")
			assert.Error(t, getErr, "no CA material may be published when the external material could not be read")
		})
	}
}

// TestBuildClusterCertManager_NoExternalPaths_SelfGeneratesAndStoresInVault
// verifies that omitting the external intermediate paths preserves today's
// self-generate-and-store-in-vault cluster CA behavior unmodified.
func TestBuildClusterCertManager_NoExternalPaths_SelfGeneratesAndStoresInVault(t *testing.T) {
	store := newInMemSecretStore()

	cfg := &config.Config{
		Certificate: &config.CertificateConfig{
			EnableCertManagement: true,
			Server: &config.ServerCertificateConfig{
				Organization: "Test Cluster",
			},
			ClusterCA: &config.ClusterCAConfig{
				VaultAddress: "https://vault.test:8200",
				VaultKeyPath: "root/cluster-ca",
			},
		},
	}

	certStorageDir := t.TempDir()
	logger := logging.NewNoopLogger()

	mgr, err := BuildClusterCertManagerWithStore(context.Background(), cfg, certStorageDir, store, logger)
	require.NoError(t, err)

	info, err := mgr.GetCAInfo()
	require.NoError(t, err)
	assert.NotEmpty(t, info.CommonName)

	anchor, err := mgr.GetCACertificate()
	require.NoError(t, err)
	assert.NotEmpty(t, anchor)

	_, statErr := os.Stat(filepath.Join(certStorageDir, "ca", "ca.key"))
	assert.True(t, os.IsNotExist(statErr), "self-generated cluster CA key must not be written to local disk")
	assert.FileExists(t, filepath.Join(certStorageDir, "ca", "ca.crt"))
}

// TestBuildClusterCertManager_PartialExternalIntermediatePathsRejected proves
// a partially configured external-intermediate path set fails closed at
// config validation, before any vault or file I/O happens, rather than
// failing deep inside a file read with a confusing error.
func TestBuildClusterCertManager_PartialExternalIntermediatePathsRejected(t *testing.T) {
	cfg := &config.Config{
		Certificate: &config.CertificateConfig{
			EnableCertManagement: true,
			ClusterCA: &config.ClusterCAConfig{
				VaultAddress:                 "https://vault.test:8200",
				VaultKeyPath:                 "root/cluster-ca",
				ExternalIntermediateCertPath: "/tmp/only-cert-path-set.pem",
			},
		},
	}

	_, err := BuildClusterCertManager(context.Background(), cfg, t.TempDir(), nil, logging.NewNoopLogger())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "must all be set together")
}
