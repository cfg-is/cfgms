// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package initialization

import (
	"crypto/rand"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	_ "github.com/lib/pq"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/controller/config"
	"github.com/cfgis/cfgms/pkg/cert"
	"github.com/cfgis/cfgms/pkg/cert/bundle"
	"github.com/cfgis/cfgms/pkg/logging"
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
