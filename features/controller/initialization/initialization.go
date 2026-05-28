// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

// Package initialization implements first-run initialization for the CFGMS controller.
//
// The controller must be explicitly initialized before normal startup using
// `controller --init`. This prevents silent auto-generation of a new CA when
// storage mounts are missing or config paths are wrong — which would break
// mTLS trust with the entire fleet.
package initialization

import (
	"context"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"time"

	"github.com/cfgis/cfgms/features/controller/config"
	"github.com/cfgis/cfgms/features/rbac"
	"github.com/cfgis/cfgms/pkg/cert"
	"github.com/cfgis/cfgms/pkg/cert/bundle"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/storage/interfaces"
	_ "github.com/cfgis/cfgms/pkg/storage/providers/flatfile" // register flatfile provider for OSS composite manager
	_ "github.com/cfgis/cfgms/pkg/storage/providers/sqlite"   // register sqlite provider for OSS composite manager
	"github.com/cfgis/cfgms/pkg/version"
)

// Result contains the outcome of a successful initialization.
type Result struct {
	CAFingerprint   string
	StorageProvider string
	InitializedAt   time.Time
}

// Run performs first-run initialization of the controller.
// It creates the CA, storage backend, RBAC defaults, default tenant,
// and writes the initialization marker. If any step fails, all changes
// are rolled back.
func Run(cfg *config.Config, logger logging.Logger) (*Result, error) {
	if cfg == nil {
		return nil, fmt.Errorf("configuration is required for initialization")
	}

	if cfg.Certificate == nil || !cfg.Certificate.EnableCertManagement {
		return nil, fmt.Errorf("certificate management must be enabled for initialization (certificate.enable_cert_management: true)")
	}

	caPath := cfg.Certificate.CAPath
	if caPath == "" {
		return nil, fmt.Errorf("certificate CA path is required for initialization (certificate.ca_path)")
	}

	bundlePath := cfg.AdminBundlePath
	if bundlePath == "" {
		bundlePath = defaultAdminBundlePath()
	}

	// Idempotent guard: refuse if already initialized
	if IsInitialized(caPath) {
		existing, err := ReadInitMarker(caPath)
		if err != nil {
			return nil, fmt.Errorf("controller is already initialized but marker is unreadable: %w", err)
		}

		// Check if bundle was issued but bundle file is now missing (external deletion).
		if isBundleMarkerPresent(bundlePath) && !fileExists(bundlePath) {
			return nil, fmt.Errorf("controller is initialized (CA fingerprint: %s) but admin bundle is missing at %s.\n"+
				"To regenerate the bundle, run: cfgms-controller bootstrap-admin --regenerate",
				existing.CAFingerprint, bundlePath)
		}

		return nil, fmt.Errorf("controller is already initialized (initialized at %s with CA fingerprint %s). "+
			"To re-initialize, remove the CA directory at %s and run --init again",
			existing.InitializedAt.Format(time.RFC3339), existing.CAFingerprint, caPath)
	}

	rollback := NewRollbackTracker()

	// Step 1: Initialize storage backend
	if cfg.Storage == nil {
		return nil, fmt.Errorf("storage configuration is required for initialization")
	}

	var (
		storageManager *interfaces.StorageManager
		err            error
	)
	// OSS composite path: flatfile (config/audit/steward) + SQLite (business data)
	logger.Info("Initializing OSS composite storage backend...",
		"flatfile_root", cfg.Storage.FlatfileRoot,
		"sqlite_path", cfg.Storage.SQLitePath)
	storageManager, err = interfaces.CreateOSSStorageManager(cfg.Storage.FlatfileRoot, cfg.Storage.SQLitePath)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize OSS composite storage: %w", err)
	}
	defer func() {
		if cErr := storageManager.Close(); cErr != nil {
			logger.Error("Failed to close storage manager during initialization", "error", cErr)
		}
	}()
	logger.Info("OSS composite storage backend initialized")

	// Step 2: Create CA and certificates
	logger.Info("Creating Certificate Authority...", "ca_path", caPath)

	// Ensure CA directory exists
	if err := os.MkdirAll(caPath, 0700); err != nil {
		return nil, fmt.Errorf("failed to create CA directory: %w", err)
	}
	rollback.Add("remove CA directory", func() error {
		return os.RemoveAll(caPath)
	})

	certPath := cfg.CertPath
	if certPath == "" {
		certPath = caPath
	}

	caConfig := &cert.CAConfig{
		Organization: "CFGMS",
		Country:      "US",
		ValidityDays: 3650, // 10 years for CA
		StoragePath:  caPath,
	}
	if cfg.Certificate.Server != nil && cfg.Certificate.Server.Organization != "" {
		caConfig.Organization = cfg.Certificate.Server.Organization
	}

	certManager, err := cert.NewManager(&cert.ManagerConfig{
		StoragePath:          certPath,
		CAConfig:             caConfig,
		LoadExistingCA:       false,
		EnableAutoRenewal:    cfg.Certificate.EnableCertManagement,
		RenewalThresholdDays: cfg.Certificate.RenewalThresholdDays,
	})
	if err != nil {
		if rbErr := rollback.Execute(); rbErr != nil {
			logger.Error("Rollback failed after CA creation error", "rollback_error", rbErr.Error())
		}
		return nil, fmt.Errorf("failed to create Certificate Authority: %w", err)
	}
	logger.Info("Certificate Authority created")

	// Step 2b: Generate purpose-specific certificates (mandatory separated architecture)
	if err := cfg.Certificate.ValidateCertificateArchitecture(); err != nil {
		if rbErr := rollback.Execute(); rbErr != nil {
			logger.Error("Rollback failed after architecture validation error", "rollback_error", rbErr.Error())
		}
		return nil, err
	}
	logger.Info("Creating separated certificates (internal mTLS + config signing)...")
	// TransportCertSANs merges defaults, legacy cfg.Certificate.Server SANs,
	// cfg.Certificate.Internal SANs, and CFGMS_EXTERNAL_HOSTNAME so a steward
	// dialing the controller by its external hostname can verify the cert.
	// EnsureSeparatedCertificates is idempotent — if --init mints the cert
	// here, controller startup will not regenerate it, so the SAN set written
	// during --init is what stewards see for the cert's full lifetime.
	dnsNames, ipAddresses := TransportCertSANs(cfg)
	internalCfg := &cert.ServerCertConfig{
		CommonName:   "cfgms-internal",
		DNSNames:     dnsNames,
		IPAddresses:  ipAddresses,
		ValidityDays: 365,
	}
	if cfg.Certificate.Internal != nil && cfg.Certificate.Internal.CommonName != "" {
		internalCfg.CommonName = cfg.Certificate.Internal.CommonName
	}
	if cfg.Certificate.InternalCertValidityDays > 0 {
		internalCfg.ValidityDays = cfg.Certificate.InternalCertValidityDays
	}

	signingCfg := &cert.SigningCertConfig{
		CommonName:   "cfgms-config-signer",
		ValidityDays: 1095,
		KeySize:      4096,
	}
	if cfg.Certificate.Signing != nil {
		if cfg.Certificate.Signing.CommonName != "" {
			signingCfg.CommonName = cfg.Certificate.Signing.CommonName
		}
		if cfg.Certificate.Signing.Organization != "" {
			signingCfg.Organization = cfg.Certificate.Signing.Organization
		}
	}
	if cfg.Certificate.SigningCertValidityDays > 0 {
		signingCfg.ValidityDays = cfg.Certificate.SigningCertValidityDays
	}

	if err := certManager.EnsureSeparatedCertificates(internalCfg, signingCfg); err != nil {
		if rbErr := rollback.Execute(); rbErr != nil {
			logger.Error("Rollback failed after separated cert error", "rollback_error", rbErr.Error())
		}
		return nil, fmt.Errorf("failed to create separated certificates: %w", err)
	}
	logger.Info("Separated certificates created")

	// Note: Server certificates are NOT generated during initialization.
	// They are created by the controller startup (gRPC-over-QUIC transport)
	// which knows the specific cert names and file paths they require.

	// Step 3: Initialize RBAC
	logger.Info("Initializing RBAC...")
	auditStore := storageManager.GetAuditStore()
	clientTenantStore := storageManager.GetClientTenantStore()
	rbacStore := storageManager.GetRBACStore()

	rbacManager := rbac.NewManagerWithStorage(auditStore, clientTenantStore, rbacStore)
	if err := rbacManager.Initialize(context.Background()); err != nil {
		logger.Warn("RBAC initialization warning (non-fatal)", "error", err.Error())
	}
	logger.Info("RBAC initialized")

	// Step 4: Get CA fingerprint for marker
	caInfo, err := certManager.GetCAInfo()
	if err != nil {
		if rbErr := rollback.Execute(); rbErr != nil {
			logger.Error("Rollback failed after CA info error", "rollback_error", rbErr.Error())
		}
		return nil, fmt.Errorf("failed to get CA info: %w", err)
	}

	// Step 5: Write init marker (LAST — all-or-nothing)
	logger.Info("Writing initialization marker...")
	marker := &InitMarker{
		Version:           1,
		InitializedAt:     time.Now().UTC(),
		ControllerVersion: version.Short(),
		StorageProvider:   cfg.Storage.Provider,
		CAFingerprint:     caInfo.Fingerprint,
	}

	if err := WriteInitMarker(caPath, marker); err != nil {
		if rbErr := rollback.Execute(); rbErr != nil {
			logger.Error("Rollback failed after marker write error", "rollback_error", rbErr.Error())
		}
		return nil, fmt.Errorf("failed to write initialization marker: %w", err)
	}

	// Step 6: Issue admin credential bundle
	logger.Info("Checking admin bundle...", "path", bundlePath)
	if fileExists(bundlePath) {
		logger.Info("Admin bundle already exists, skipping issuance", "path", bundlePath)
	} else {
		if err := issueAdminBundle(bundlePath, cfg, certManager, logger); err != nil {
			return nil, err
		}
	}

	logger.Info("Initialization complete",
		"ca_fingerprint", caInfo.Fingerprint,
		"storage_provider", cfg.Storage.Provider,
		"controller_version", version.Short())

	return &Result{
		CAFingerprint:   caInfo.Fingerprint,
		StorageProvider: cfg.Storage.Provider,
		InitializedAt:   marker.InitializedAt,
	}, nil
}

// issueAdminBundle generates an admin client certificate with the CFGMS admin marker,
// writes the bundle file, and writes the idempotency marker.
func issueAdminBundle(bundlePath string, cfg *config.Config, certManager *cert.Manager, logger logging.Logger) error {
	// Issue an admin client cert with the CFGMS admin X.509 extension.
	// Subject: CN=cfgms-admin, O=CFGMS (no OU — the extension OID is the identity marker).
	// Validity: 365 days hard cap (Story D enforces renewal).
	adminCert, err := certManager.GenerateClientCertificate(&cert.ClientCertConfig{
		CommonName:       "cfgms-admin",
		Organization:     "CFGMS",
		ValidityDays:     365,
		TemplateModifier: cert.SetAdminMarker,
	})
	if err != nil {
		return fmt.Errorf("failed to issue admin certificate: %w", err)
	}

	caPEM, err := certManager.GetCACertificate()
	if err != nil {
		return fmt.Errorf("failed to get CA certificate PEM: %w", err)
	}

	controllerURL := cfg.ExternalURL

	b := &bundle.Bundle{
		CertPEM:         string(adminCert.CertificatePEM),
		KeyPEM:          string(adminCert.PrivateKeyPEM),
		CAPEM:           string(caPEM),
		ControllerURL:   controllerURL,
		AuditSubject:    "admin:cfgms-admin",
		CertSerial:      adminCert.SerialNumber,
		CertFingerprint: adminCert.Fingerprint,
	}

	if err := bundle.Write(bundlePath, b); err != nil {
		return fmt.Errorf("failed to write admin bundle: %w", err)
	}

	// Write the idempotency marker AFTER bundle.Write succeeds.
	// Marker presence implies the bundle was successfully written at BundlePath.
	bundleMarker := &BundleMarker{
		Serial:      adminCert.SerialNumber,
		Fingerprint: adminCert.Fingerprint,
		IssuedAt:    time.Now().UTC(),
		BundlePath:  bundlePath,
	}
	if err := writeBundleMarker(bundlePath, bundleMarker); err != nil {
		return fmt.Errorf("failed to write bundle issuance marker: %w", err)
	}

	chownBundleFiles(bundlePath, logger)

	logger.Info("Admin bundle issued",
		"path", bundlePath,
		"serial", adminCert.SerialNumber)
	return nil
}

// chownBundleFiles transfers ownership of the bundle and marker files to the
// cfgms daemon user on Linux when running as root. No-op on Windows.
func chownBundleFiles(bundlePath string, logger logging.Logger) {
	if runtime.GOOS == "windows" {
		return
	}
	if os.Getuid() != 0 {
		return
	}
	u, err := user.Lookup("cfgms")
	if err != nil {
		logger.Warn("cfgms user not found, skipping chown on bundle files", "error", err.Error())
		return
	}
	uid, uidErr := strconv.Atoi(u.Uid)
	if uidErr != nil {
		logger.Warn("Invalid UID for cfgms user, skipping chown", "uid", u.Uid, "error", uidErr.Error())
		return
	}
	gid, gidErr := strconv.Atoi(u.Gid)
	if gidErr != nil {
		logger.Warn("Invalid GID for cfgms user, skipping chown", "gid", u.Gid, "error", gidErr.Error())
		return
	}
	for _, path := range []string{bundlePath, bundleMarkerPath(bundlePath)} {
		if chownErr := os.Chown(path, uid, gid); chownErr != nil {
			logger.Warn("Failed to chown bundle file", "path", path, "error", chownErr.Error())
		}
	}
}

// CAFilesExist checks whether the CA certificate and key files exist at the given path.
// It checks both direct placement (caPath/ca.crt) and the subdirectory layout used by
// cert.NewManager (caPath/ca/ca.crt).
func CAFilesExist(caPath string) bool {
	// Check direct placement first (caPath/ca.crt, caPath/ca.key)
	if fileExists(filepath.Join(caPath, "ca.crt")) && fileExists(filepath.Join(caPath, "ca.key")) {
		return true
	}
	// Check cert manager subdirectory layout (caPath/ca/ca.crt, caPath/ca/ca.key)
	if fileExists(filepath.Join(caPath, "ca", "ca.crt")) && fileExists(filepath.Join(caPath, "ca", "ca.key")) {
		return true
	}
	return false
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
