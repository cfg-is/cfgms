// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

// Package cert_trust provides idempotent Get/Set management of OS-level trust
// store entries for the CFGMS steward. It supports Linux (Debian-family,
// /etc/ssl/certs + update-ca-certificates), Windows (CertOpenSystemStore), and
// macOS (Security framework) through platform-specific executor implementations
// selected at compile time via build tags.
//
// The module operates exclusively on the OS trust store (which CAs the OS
// trusts system-wide). It is distinct from pkg/cert, which manages CFGMS's own
// mTLS certificate lifecycle and must never be called from this module.
//
// No private key material is handled by this module. Trust-store entries are
// public certificates only. If any implementation detail would require a private
// key, that is a design mismatch and must be flagged rather than worked around.
package cert_trust

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"regexp"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/cfgis/cfgms/features/modules"
	"github.com/cfgis/cfgms/pkg/logging"
)

// fingerprintPattern restricts fingerprints to exactly 64 lowercase hex characters
// (SHA-256 output). This is the stable identity used as the resource ID.
var fingerprintPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

// CertTrustConfig represents the desired and observed state of a trust-store entry.
//
// The Fingerprint field is the stable resource identity: it uniquely identifies
// the certificate without reference to filesystem paths or OS-specific handles.
// CertPEM is only used as install payload in Set (state: present); it is never
// returned by Get and never included in AsMap().
type CertTrustConfig struct {
	// Fingerprint is the SHA-256 fingerprint (lowercase hex, no colons).
	Fingerprint string `yaml:"fingerprint"`
	// Subject is the certificate subject distinguished name (observed, not set by caller).
	Subject string `yaml:"subject,omitempty"`
	// Issuer is the certificate issuer distinguished name (observed, not set by caller).
	Issuer string `yaml:"issuer,omitempty"`
	// NotAfter is the certificate expiry in RFC3339 format (observed, not set by caller).
	NotAfter string `yaml:"not_after,omitempty"`
	// TrustedFor describes the intended trust purpose (e.g. "any", "tls", "code_signing").
	TrustedFor string `yaml:"trusted_for,omitempty"`
	// State is "present" or "absent".
	State string `yaml:"state"`
	// CertPEM is the PEM-encoded certificate to install. Only used by Set when
	// state is "present". Must encode a CA certificate with no private key.
	// Not included in AsMap() because it is install payload, not observable state.
	CertPEM string `yaml:"cert_pem,omitempty"`
}

// AsMap returns the observable configuration state for field-by-field comparison.
// CertPEM is intentionally excluded — it is install payload, not an observable
// property of the trust-store entry that should drive drift detection.
func (c *CertTrustConfig) AsMap() map[string]interface{} {
	result := map[string]interface{}{
		"fingerprint": c.Fingerprint,
		"state":       c.State,
	}
	if c.Subject != "" {
		result["subject"] = c.Subject
	}
	if c.Issuer != "" {
		result["issuer"] = c.Issuer
	}
	if c.NotAfter != "" {
		result["not_after"] = c.NotAfter
	}
	if c.TrustedFor != "" {
		result["trusted_for"] = c.TrustedFor
	}
	return result
}

// ToYAML serializes the configuration to YAML.
func (c *CertTrustConfig) ToYAML() ([]byte, error) {
	return yaml.Marshal(c)
}

// FromYAML deserializes YAML data into the configuration.
func (c *CertTrustConfig) FromYAML(data []byte) error {
	return yaml.Unmarshal(data, c)
}

// Validate checks that the configuration is valid before applying it.
func (c *CertTrustConfig) Validate() error {
	switch c.State {
	case "present", "absent":
		// valid
	case "":
		return fmt.Errorf("%w: state is required (present or absent)", modules.ErrInvalidInput)
	default:
		return fmt.Errorf("%w: state must be 'present' or 'absent', got %q", modules.ErrInvalidInput, c.State)
	}
	if c.State == "present" && c.CertPEM == "" {
		return fmt.Errorf("%w: cert_pem is required when state is 'present'", modules.ErrInvalidInput)
	}
	return nil
}

// GetManagedFields returns the list of observable fields this configuration manages.
func (c *CertTrustConfig) GetManagedFields() []string {
	return []string{"fingerprint", "state", "subject", "issuer", "not_after", "trusted_for"}
}

// certTrustModule implements modules.Module for OS trust store management.
type certTrustModule struct {
	modules.DefaultLoggingSupport
	executor trustStoreExecutor
}

// New creates a new instance of the cert_trust module with the platform-appropriate
// trust store executor.
func New() modules.Module {
	return &certTrustModule{
		executor: newExecutor(),
	}
}

// Get returns the current state of the trust-store entry identified by fingerprint.
//
// The resourceID must be a 64-character lowercase hex SHA-256 fingerprint. If no
// certificate with that fingerprint is present in the trust store, Get returns a
// CertTrustConfig with State: "absent" — analogous to how the file module returns
// State: "absent" for non-existent files.
func (m *certTrustModule) Get(ctx context.Context, resourceID string) (modules.ConfigState, error) {
	if resourceID == "" {
		return nil, modules.ErrInvalidResourceID
	}
	if !fingerprintPattern.MatchString(resourceID) {
		return nil, fmt.Errorf("%w: resource ID must be a 64-character lowercase hex SHA-256 fingerprint, got %q",
			modules.ErrInvalidResourceID, logging.SanitizeLogValue(resourceID))
	}

	logger := m.GetEffectiveLogger(logging.ForModule("cert_trust"))
	tenantID := logging.ExtractTenantFromContext(ctx)

	logger.InfoCtx(ctx, "Getting trust store entry",
		"operation", "cert_trust_get",
		"resource_id", logging.SanitizeLogValue(resourceID),
		"tenant_id", tenantID,
		"resource_type", "cert_trust")

	entries, err := m.executor.list()
	if err != nil {
		logger.ErrorCtx(ctx, "Failed to list trust store entries",
			"operation", "cert_trust_get",
			"resource_id", logging.SanitizeLogValue(resourceID),
			"error_code", "CERT_TRUST_LIST_FAILED",
			"error_details", err.Error())
		return nil, fmt.Errorf("cert_trust: list trust store: %w", err)
	}

	for _, e := range entries {
		if e.Fingerprint == resourceID {
			config := &CertTrustConfig{
				Fingerprint: e.Fingerprint,
				Subject:     e.Subject,
				Issuer:      e.Issuer,
				NotAfter:    e.NotAfter,
				TrustedFor:  e.TrustedFor,
				State:       "present",
			}
			logger.InfoCtx(ctx, "Trust store entry found",
				"operation", "cert_trust_get",
				"resource_id", logging.SanitizeLogValue(resourceID),
				"subject", logging.SanitizeLogValue(e.Subject),
				"status", "completed")
			return config, nil
		}
	}

	logger.InfoCtx(ctx, "Trust store entry not present",
		"operation", "cert_trust_get",
		"resource_id", logging.SanitizeLogValue(resourceID),
		"status", "absent")

	return &CertTrustConfig{
		Fingerprint: resourceID,
		State:       "absent",
	}, nil
}

// Set applies the desired trust-store entry configuration.
//
// The resourceID must be a SHA-256 fingerprint. When state is "present", the
// config must include cert_pem with a PEM-encoded CA certificate whose fingerprint
// matches the resourceID. When state is "absent", the certificate with the given
// fingerprint is removed from the trust store (no-op if already absent).
//
// Set is idempotent: installing an already-present cert or removing an
// already-absent cert performs no observable change.
//
// Trust-store mutations are security-sensitive (they control which CAs the OS
// trusts system-wide). All mutations are logged via SanitizeLogValue per the
// CLAUDE.md threat model for this module.
func (m *certTrustModule) Set(ctx context.Context, resourceID string, config modules.ConfigState) error {
	if resourceID == "" {
		return modules.ErrInvalidResourceID
	}
	if !fingerprintPattern.MatchString(resourceID) {
		return fmt.Errorf("%w: resource ID must be a 64-character lowercase hex SHA-256 fingerprint, got %q",
			modules.ErrInvalidResourceID, logging.SanitizeLogValue(resourceID))
	}
	if config == nil {
		return modules.ErrInvalidInput
	}

	logger := m.GetEffectiveLogger(logging.ForModule("cert_trust"))
	tenantID := logging.ExtractTenantFromContext(ctx)

	logger.InfoCtx(ctx, "Setting trust store entry",
		"operation", "cert_trust_set",
		"resource_id", logging.SanitizeLogValue(resourceID),
		"tenant_id", tenantID,
		"resource_type", "cert_trust")

	configMap := config.AsMap()
	trustConfig := &CertTrustConfig{}

	if state, ok := configMap["state"].(string); ok {
		trustConfig.State = state
	}
	// CertPEM is not in AsMap(); recover it from the concrete type if available.
	if concrete, ok := config.(*CertTrustConfig); ok {
		trustConfig.CertPEM = concrete.CertPEM
	}

	if err := trustConfig.Validate(); err != nil {
		logger.ErrorCtx(ctx, "Trust store configuration validation failed",
			"operation", "cert_trust_set",
			"resource_id", logging.SanitizeLogValue(resourceID),
			"error_code", "CONFIG_VALIDATION_FAILED",
			"error_details", err.Error())
		return err
	}

	switch trustConfig.State {
	case "present":
		certDER, err := parsePEMCert(trustConfig.CertPEM)
		if err != nil {
			logger.ErrorCtx(ctx, "Failed to parse certificate PEM",
				"operation", "cert_trust_set",
				"resource_id", logging.SanitizeLogValue(resourceID),
				"error_code", "CERT_PARSE_FAILED",
				"error_details", err.Error())
			return fmt.Errorf("cert_trust: parse cert_pem: %w", err)
		}

		// Verify the fingerprint of the supplied cert matches the resource ID.
		fp := certFingerprint(certDER)
		if fp != resourceID {
			return fmt.Errorf("%w: cert_pem fingerprint %s does not match resource ID %s",
				modules.ErrInvalidInput, fp, logging.SanitizeLogValue(resourceID))
		}

		if err := m.executor.install(certDER); err != nil {
			logger.ErrorCtx(ctx, "Failed to install certificate in trust store",
				"operation", "cert_trust_set",
				"resource_id", logging.SanitizeLogValue(resourceID),
				"error_code", "CERT_TRUST_INSTALL_FAILED",
				"error_details", err.Error())
			return fmt.Errorf("cert_trust: install: %w", err)
		}

		logger.InfoCtx(ctx, "Certificate installed in trust store",
			"operation", "cert_trust_set",
			"resource_id", logging.SanitizeLogValue(resourceID),
			"status", "completed")

	case "absent":
		if err := m.executor.remove(resourceID); err != nil {
			logger.ErrorCtx(ctx, "Failed to remove certificate from trust store",
				"operation", "cert_trust_set",
				"resource_id", logging.SanitizeLogValue(resourceID),
				"error_code", "CERT_TRUST_REMOVE_FAILED",
				"error_details", err.Error())
			return fmt.Errorf("cert_trust: remove: %w", err)
		}

		logger.InfoCtx(ctx, "Certificate removed from trust store",
			"operation", "cert_trust_set",
			"resource_id", logging.SanitizeLogValue(resourceID),
			"status", "completed")
	}

	return nil
}

// parsePEMCert decodes the first CERTIFICATE block from a PEM string and returns
// the raw DER bytes. Returns an error if no CERTIFICATE block is found.
func parsePEMCert(pemData string) ([]byte, error) {
	rest := []byte(pemData)
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			return block.Bytes, nil
		}
	}
	return nil, fmt.Errorf("no CERTIFICATE block found in PEM data")
}

// certFingerprint returns the SHA-256 fingerprint of a DER-encoded certificate
// as a lowercase hex string (no colons).
func certFingerprint(certDER []byte) string {
	sum := sha256.Sum256(certDER)
	return hex.EncodeToString(sum[:])
}

// certEntryFromDER parses a DER-encoded certificate and returns a certEntry.
func certEntryFromDER(certDER []byte) (certEntry, error) {
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return certEntry{}, fmt.Errorf("parse certificate: %w", err)
	}
	return certEntry{
		Fingerprint: certFingerprint(certDER),
		Subject:     cert.Subject.String(),
		Issuer:      cert.Issuer.String(),
		NotAfter:    cert.NotAfter.UTC().Format(time.RFC3339),
		TrustedFor:  "any",
	}, nil
}
