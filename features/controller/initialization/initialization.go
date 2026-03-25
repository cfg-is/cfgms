// SPDX-License-Identifier: Apache-2.0
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
	"path/filepath"
	"time"

	"github.com/cfgis/cfgms/features/controller/config"
	"github.com/cfgis/cfgms/features/rbac"
	"github.com/cfgis/cfgms/pkg/cert"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/storage/interfaces"
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

	// Idempotent guard: refuse if already initialized
	if IsInitialized(caPath) {
		existing, err := ReadInitMarker(caPath)
		if err != nil {
			return nil, fmt.Errorf("controller is already initialized but marker is unreadable: %w", err)
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
	logger.Info("Initializing storage backend...", "provider", cfg.Storage.Provider)

	storageManager, err := interfaces.CreateAllStoresFromConfig(cfg.Storage.Provider, cfg.Storage.Config)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize storage provider '%s': %w", cfg.Storage.Provider, err)
	}
	logger.Info("Storage backend initialized", "provider", cfg.Storage.Provider)

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

	// Step 2b: Separated certificate architecture (if configured)
	if cfg.Certificate.IsSeparatedArchitecture() {
		logger.Info("Creating separated certificates (internal mTLS + config signing)...")
		internalCfg := &cert.ServerCertConfig{
			CommonName:   "cfgms-internal",
			DNSNames:     []string{"localhost", "cfgms-internal", "controller-standalone"},
			IPAddresses:  []string{"127.0.0.1", "0.0.0.0"},
			ValidityDays: 365,
		}
		if cfg.Certificate.Internal != nil {
			if cfg.Certificate.Internal.CommonName != "" {
				internalCfg.CommonName = cfg.Certificate.Internal.CommonName
			}
			if len(cfg.Certificate.Internal.DNSNames) > 0 {
				internalCfg.DNSNames = cfg.Certificate.Internal.DNSNames
			}
			if len(cfg.Certificate.Internal.IPAddresses) > 0 {
				internalCfg.IPAddresses = cfg.Certificate.Internal.IPAddresses
			}
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
	}

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
