// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz

// Package acme implements automated TLS certificate management via the ACME
// protocol (RFC 8555). It uses the lego library to interact with ACME servers
// such as Let's Encrypt for certificate issuance and renewal.
//
// The module supports both HTTP-01 and DNS-01 challenge types, with DNS-01
// supporting Cloudflare, Route53, and Azure DNS providers. Certificate storage
// uses a local filesystem layout with proper key permissions (0600).
//
// This module can run on both Steward and Controller. On Controller, after
// successful certificate obtain/renew, the certificate is additionally imported
// into the cert.Manager as CertificateTypePublicAPI.
package acme

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math"
	"time"

	"github.com/cfgis/cfgms/features/modules"
	"github.com/cfgis/cfgms/pkg/logging"
)

// acmeModule implements the modules.Module interface for ACME certificate management
type acmeModule struct {
	modules.DefaultLoggingSupport
	modules.DefaultSecretStoreSupport
}

// New creates a new instance of the ACME module
func New() modules.Module {
	return &acmeModule{}
}

// Get returns the current certificate state for the given domain (resourceID).
// If no certificate exists, returns an ACMEConfig with State: "absent".
func (m *acmeModule) Get(ctx context.Context, resourceID string) (modules.ConfigState, error) {
	if resourceID == "" {
		return nil, modules.ErrInvalidResourceID
	}

	logger := m.GetEffectiveLogger(logging.ForModule("acme"))
	logger.InfoCtx(ctx, "Getting ACME certificate state",
		"operation", "acme_get",
		"resource_id", resourceID)

	// Use the default cert store path for Get; the user can override via Set config
	store, err := NewACMECertStore("")
	if err != nil {
		return nil, fmt.Errorf("failed to initialize certificate store: %w", err)
	}

	// Inject secret store for account operations
	if secretStore, injected := m.GetSecretStore(); injected {
		store.SetSecretStore(secretStore)
	}

	if !store.CertificateExists(resourceID) {
		return &ACMEConfig{
			State: "absent",
		}, nil
	}

	certPEM, _, err := store.LoadCertificate(resourceID)
	if err != nil {
		return nil, fmt.Errorf("failed to load certificate: %w", err)
	}

	// Parse certificate for status
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return &ACMEConfig{State: "absent"}, nil
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return &ACMEConfig{State: "absent"}, nil
	}

	now := time.Now()
	daysUntilExpiry := int(math.Ceil(cert.NotAfter.Sub(now).Hours() / 24))

	// Load metadata for additional context
	config := &ACMEConfig{
		State:   "present",
		Domains: cert.DNSNames,
		CertificateStatus: &CertificateStatus{
			Issuer:          cert.Issuer.CommonName,
			NotAfter:        cert.NotAfter,
			DaysUntilExpiry: daysUntilExpiry,
			SerialNumber:    cert.SerialNumber.String(),
			NeedsRenewal:    daysUntilExpiry <= 30, // default threshold
		},
	}

	// Try to enrich from metadata file
	meta, err := store.LoadCertificateMetadata(resourceID)
	if err == nil {
		config.Email = meta.Email
		config.KeyType = meta.KeyType
	}

	return config, nil
}

// Set applies the desired ACME certificate state. It is idempotent:
//   - If the certificate is valid and not within renewal threshold, no-op
//   - If no cert exists or domains changed, obtain new certificate
//   - If within renewal threshold, renew existing certificate
//   - If state is "absent", remove the certificate
func (m *acmeModule) Set(ctx context.Context, resourceID string, config modules.ConfigState) error {
	logger := m.GetEffectiveLogger(logging.ForModule("acme"))
	tenantID := logging.ExtractTenantFromContext(ctx)

	if resourceID == "" {
		return modules.ErrInvalidResourceID
	}
	if config == nil {
		return modules.ErrInvalidInput
	}

	acmeConfig, ok := config.(*ACMEConfig)
	if !ok {
		return fmt.Errorf("%w: expected *ACMEConfig, got %T", modules.ErrInvalidInput, config)
	}

	if err := acmeConfig.Validate(); err != nil {
		return err
	}

	logger.InfoCtx(ctx, "Setting ACME certificate state",
		"operation", "acme_set",
		"resource_id", resourceID,
		"tenant_id", tenantID,
		"state", acmeConfig.State,
		"challenge_type", acmeConfig.ChallengeType)

	// Initialize cert store
	store, err := NewACMECertStore(acmeConfig.CertStorePath)
	if err != nil {
		return fmt.Errorf("failed to initialize certificate store: %w", err)
	}

	// Inject secret store for account operations
	if secretStore, injected := m.GetSecretStore(); injected {
		store.SetSecretStore(secretStore)
	}

	// Load existing certificate if any
	var existingCertPEM []byte
	if store.CertificateExists(resourceID) {
		existingCertPEM, _, _ = store.LoadCertificate(resourceID)
	}

	// Determine what action to take
	decision, err := DetermineAction(acmeConfig, existingCertPEM)
	if err != nil {
		return fmt.Errorf("failed to determine action: %w", err)
	}

	logger.InfoCtx(ctx, "ACME action determined",
		"operation", "acme_set",
		"resource_id", resourceID,
		"decision", decision.String())

	switch decision {
	case DecisionNone:
		logger.InfoCtx(ctx, "Certificate is valid, no action needed",
			"operation", "acme_set",
			"resource_id", resourceID,
			"status", "no_change")
		return nil

	case DecisionRemove:
		if err := store.DeleteCertificate(resourceID); err != nil {
			logger.ErrorCtx(ctx, "Failed to remove certificate",
				"operation", "acme_set",
				"resource_id", resourceID,
				"error_code", "CERT_REMOVAL_FAILED",
				"error_details", err.Error())
			return err
		}
		logger.InfoCtx(ctx, "Certificate removed",
			"operation", "acme_set",
			"resource_id", resourceID,
			"status", "completed")
		return nil

	case DecisionObtain:
		return m.obtainCertificate(ctx, acmeConfig, store, resourceID, logger)

	case DecisionRenew:
		return m.renewCertificate(ctx, acmeConfig, store, resourceID, logger)

	default:
		return fmt.Errorf("unknown decision: %d", decision)
	}
}

func (m *acmeModule) obtainCertificate(ctx context.Context, cfg *ACMEConfig, store *ACMECertStore, resourceID string, logger logging.Logger) error {
	solver, err := m.createChallengeSolver(cfg)
	if err != nil {
		return err
	}
	defer func() { _ = solver.Cleanup() }()

	client, err := NewACMEClient(cfg, store, solver)
	if err != nil {
		return err
	}

	certPEM, keyPEM, issuerPEM, err := client.ObtainCertificate()
	if err != nil {
		logger.ErrorCtx(ctx, "Failed to obtain certificate",
			"operation", "acme_set",
			"resource_id", resourceID,
			"error_code", "CERT_OBTAIN_FAILED",
			"error_details", err.Error())
		return err
	}

	// Parse the certificate for metadata
	meta := m.buildMetadata(certPEM, cfg)

	if err := store.StoreCertificate(resourceID, certPEM, keyPEM, issuerPEM, meta); err != nil {
		return fmt.Errorf("failed to store certificate: %w", err)
	}

	logger.InfoCtx(ctx, "Certificate obtained successfully",
		"operation", "acme_set",
		"resource_id", resourceID,
		"domains", cfg.Domains,
		"status", "completed")

	return nil
}

func (m *acmeModule) renewCertificate(ctx context.Context, cfg *ACMEConfig, store *ACMECertStore, resourceID string, logger logging.Logger) error {
	existingCertPEM, existingKeyPEM, err := store.LoadCertificate(resourceID)
	if err != nil {
		// If we can't load the existing cert, fall back to obtain
		return m.obtainCertificate(ctx, cfg, store, resourceID, logger)
	}

	solver, err := m.createChallengeSolver(cfg)
	if err != nil {
		return err
	}
	defer func() { _ = solver.Cleanup() }()

	client, err := NewACMEClient(cfg, store, solver)
	if err != nil {
		return err
	}

	certPEM, keyPEM, issuerPEM, err := client.RenewCertificate(existingCertPEM, existingKeyPEM)
	if err != nil {
		logger.ErrorCtx(ctx, "Failed to renew certificate",
			"operation", "acme_set",
			"resource_id", resourceID,
			"error_code", "CERT_RENEW_FAILED",
			"error_details", err.Error())
		return err
	}

	meta := m.buildMetadata(certPEM, cfg)

	if err := store.StoreCertificate(resourceID, certPEM, keyPEM, issuerPEM, meta); err != nil {
		return fmt.Errorf("failed to store renewed certificate: %w", err)
	}

	logger.InfoCtx(ctx, "Certificate renewed successfully",
		"operation", "acme_set",
		"resource_id", resourceID,
		"domains", cfg.Domains,
		"status", "completed")

	return nil
}

func (m *acmeModule) createChallengeSolver(cfg *ACMEConfig) (ChallengeSolver, error) {
	switch cfg.ChallengeType {
	case "http-01":
		return NewHTTPChallengeSolver(cfg.HTTPBindAddress), nil
	case "dns-01":
		secretStore, injected := m.GetSecretStore()
		if !injected {
			return nil, fmt.Errorf("%w: DNS-01 requires secret store for credential retrieval", ErrChallengeFailed)
		}
		if cfg.DNSProvider == "" {
			return nil, ErrDNSProviderRequired
		}
		if cfg.DNSCredentialKey == "" {
			return nil, ErrDNSCredentialKeyRequired
		}
		factory := NewDNSProviderFactory(secretStore)
		provider, err := factory.CreateProvider(context.Background(), cfg.DNSProvider, cfg.DNSCredentialKey)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrChallengeFailed, err)
		}
		return NewDNSChallengeSolver(provider), nil
	default:
		return nil, ErrInvalidChallengeType
	}
}

func (m *acmeModule) buildMetadata(certPEM []byte, cfg *ACMEConfig) *CertificateMetadata {
	meta := &CertificateMetadata{
		Domain:   cfg.Domains[0],
		Email:    cfg.Email,
		IssuedAt: time.Now(),
		KeyType:  cfg.KeyType,
	}

	if cfg.ACMEServer != "" {
		meta.ACMEServer = cfg.ACMEServer
	}

	block, _ := pem.Decode(certPEM)
	if block != nil {
		cert, err := x509.ParseCertificate(block.Bytes)
		if err == nil {
			meta.ExpiresAt = cert.NotAfter
			meta.Issuer = cert.Issuer.CommonName
			meta.Serial = cert.SerialNumber.String()
		}
	}

	return meta
}
