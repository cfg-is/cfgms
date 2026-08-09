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
	"strings"
	"time"

	"github.com/cfgis/cfgms/features/controller/config"
	"github.com/cfgis/cfgms/features/rbac"
	"github.com/cfgis/cfgms/pkg/cert"
	"github.com/cfgis/cfgms/pkg/cert/bundle"
	"github.com/cfgis/cfgms/pkg/logging"
	secretsinterfaces "github.com/cfgis/cfgms/pkg/secrets/interfaces"
	_ "github.com/cfgis/cfgms/pkg/secrets/providers/openbao" // register OpenBao provider for cluster CA
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

	// Check external_url before any CA material or markers are written so that
	// a misconfigured operator gets a clear error without a half-initialized controller.
	if err := validateBundleExternalURL(cfg); err != nil {
		return nil, err
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

	storageManager, err := openStorageManager(cfg, logger)
	if err != nil {
		return nil, err
	}
	defer func() {
		if cErr := storageManager.Close(); cErr != nil {
			logger.Error("Failed to close storage manager during initialization", "error", cErr)
		}
	}()

	// Step 2: Create CA and certificates
	logger.Info("Creating Certificate Authority...", "ca_path", caPath)

	// Ensure CA directory exists
	if err := os.MkdirAll(caPath, 0700); err != nil {
		return nil, fmt.Errorf("failed to create CA directory: %w", err)
	}
	rollback.Add("remove CA directory", func() error {
		return os.RemoveAll(caPath)
	})

	// StoragePath for cert.NewManager must be the parent of the "ca/" subdirectory;
	// NewManager always stores the CA at filepath.Join(StoragePath,"ca").
	certPath := filepath.Dir(filepath.Clean(caPath))

	caConfig := &cert.CAConfig{
		Organization: "CFGMS",
		Country:      "US",
		ValidityDays: 3650, // 10 years for CA
		StoragePath:  caPath,
	}
	if cfg.Certificate.Server != nil && cfg.Certificate.Server.Organization != "" {
		caConfig.Organization = cfg.Certificate.Server.Organization
	}

	managerCfg := &cert.ManagerConfig{
		StoragePath:          certPath,
		CAConfig:             caConfig,
		LoadExistingCA:       false,
		EnableAutoRenewal:    cfg.Certificate.EnableCertManagement,
		RenewalThresholdDays: cfg.Certificate.RenewalThresholdDays,
	}

	var certManager *cert.Manager
	if cfg.HA.IsClusterMode() && cfg.Certificate.ClusterCA != nil {
		certManager, err = initClusterCA(context.Background(), cfg, managerCfg, logger)
	} else {
		certManager, err = cert.NewManager(managerCfg)
	}
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
	// Reflect the actual backing provider: cluster mode uses "database" regardless of
	// what cfg.Storage.Provider says, so second-node bootstrap can identify the backend.
	storageProviderName := cfg.Storage.Provider
	if cfg.HA.IsClusterMode() {
		storageProviderName = "database"
	}
	marker := &InitMarker{
		Version:           1,
		InitializedAt:     time.Now().UTC(),
		ControllerVersion: version.Short(),
		StorageProvider:   storageProviderName,
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
		"storage_provider", storageProviderName,
		"controller_version", version.Short())

	return &Result{
		CAFingerprint:   caInfo.Fingerprint,
		StorageProvider: storageProviderName,
		InitializedAt:   marker.InitializedAt,
	}, nil
}

// openStorageManager opens the configured business storage backend — shared Postgres in
// cluster mode, or the OSS flatfile+SQLite composite otherwise. Used by first-run
// initialization and by any other controller-local tooling (e.g. bootstrap-admin's
// root-scoped-issuance audit trail) that needs durable storage before the server starts.
// Callers are responsible for closing the returned manager.
func openStorageManager(cfg *config.Config, logger logging.Logger) (*interfaces.StorageManager, error) {
	if cfg.Storage == nil {
		return nil, fmt.Errorf("storage configuration is required")
	}
	if cfg.HA.IsClusterMode() {
		// Cluster mode: all business stores backed by shared Postgres so every node sees
		// the same fleet state immediately after --init. S3 blob store is configured
		// separately at startup; only the DSN is needed here.
		pgDSN := ""
		sessionHMACKey := ""
		if cfg.Storage.Cluster != nil {
			pgDSN = cfg.Storage.Cluster.PostgresDSN
			sessionHMACKey = cfg.Storage.Cluster.SessionHMACKey
		}
		var s3Config map[string]interface{}
		if cfg.Storage.Cluster != nil {
			s3Config = cfg.Storage.Cluster.S3
		}
		logger.Info("Cluster mode: initializing Postgres business store backend...",
			"ha_mode", cfg.HA.Mode)
		storageManager, err := interfaces.CreateClusterStorageManager(pgDSN, sessionHMACKey, s3Config)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize cluster storage: %w", err)
		}
		logger.Info("Cluster storage backend initialized")
		return storageManager, nil
	}

	// OSS composite path: flatfile (config/audit/steward) + SQLite (business data)
	logger.Info("Initializing OSS composite storage backend...",
		"flatfile_root", cfg.Storage.FlatfileRoot,
		"sqlite_path", cfg.Storage.SQLitePath)
	storageManager, err := interfaces.CreateOSSStorageManager(cfg.Storage.FlatfileRoot, cfg.Storage.SQLitePath)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize OSS composite storage: %w", err)
	}
	logger.Info("OSS composite storage backend initialized")
	return storageManager, nil
}

// issueAdminBundle generates an admin client certificate with the CFGMS admin marker,
// writes the bundle file, and writes the idempotency marker. Shared by first-run
// initialization (Run, above) and RegenerateSystemBundle (admin_bundle.go) — both mint
// the deployment's one system admin bundle.
func issueAdminBundle(bundlePath string, cfg *config.Config, certManager *cert.Manager, logger logging.Logger) error {
	// Issue an admin client cert with the CFGMS admin X.509 extension.
	// Subject: CN=cfgms-admin, O=CFGMS (no OU — the extension OID is the identity marker).
	// Validity: 365 days hard cap (Story D enforces renewal).
	//
	// Deliberately NOT the root-scope marker (pkg/cert's SetRootScopeMarker; see its own
	// architecture allow-list test) — ADR-025 Amendment 1 A1.3, founder decision
	// 2026-08-09, PR #3215. This is the system admin bundle, the deployment's only admin
	// credential on every single-root and on-prem install. Marking it would subject that
	// admin to the ADR-025 Decision 1 root<->MSP boundary and lock it out of everything
	// below "root" with no way to grant itself a crossing — a lockout, not hardening.
	// Unmarked stays the default everywhere; the opt-in lives only on the named-operator
	// path (IssueAdminBundle in admin_bundle.go, via bootstrap-admin --root-scoped).
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

// initClusterCA creates the cert Manager using a CA sourced from OpenBao. It
// builds the vault config from cfg.Certificate.ClusterCA, splits the VaultKeyPath
// into tenantID and key components, and delegates to cert.NewManagerFromSecretStore.
// The vault token must come from OPENBAO_TOKEN or BAO_TOKEN env vars; it is not
// read from the config file.
func initClusterCA(ctx context.Context, cfg *config.Config, managerCfg *cert.ManagerConfig, logger logging.Logger) (*cert.Manager, error) {
	clusterCA := cfg.Certificate.ClusterCA

	logger.Info("Cluster mode: loading CA from vault",
		"vault_address", clusterCA.VaultAddress,
		"vault_key_path", clusterCA.VaultKeyPath)

	vaultConfig := map[string]interface{}{
		"address": clusterCA.VaultAddress,
	}
	if clusterCA.VaultMountPath != "" {
		vaultConfig["mount_path"] = clusterCA.VaultMountPath
	}
	if clusterCA.VaultTLSCert != "" {
		vaultConfig["tls_cert"] = clusterCA.VaultTLSCert
	}

	parts := strings.SplitN(clusterCA.VaultKeyPath, "/", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return nil, fmt.Errorf("certificate.cluster_ca.vault_key_path must be in format 'tenantID/key-name', got: %q", clusterCA.VaultKeyPath)
	}
	tenantID, keyPath := parts[0], parts[1]

	store, err := secretsinterfaces.CreateSecretStoreFromConfig("openbao", vaultConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create OpenBao secret store for cluster CA: %w", err)
	}
	defer func() {
		if cErr := store.Close(); cErr != nil {
			logger.Error("Failed to close vault secret store after CA init", "error", cErr)
		}
	}()

	manager, err := cert.NewManagerFromSecretStore(ctx, store, tenantID, keyPath, managerCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize cluster CA from vault: %w", err)
	}

	logger.Info("Cluster CA loaded from vault", "tenant_id", tenantID, "key_path", keyPath)
	return manager, nil
}
