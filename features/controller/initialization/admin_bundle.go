// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package initialization

import (
	"bufio"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"

	"github.com/cfgis/cfgms/features/controller/config"
	"github.com/cfgis/cfgms/pkg/cert"
	"github.com/cfgis/cfgms/pkg/cert/bundle"
	"github.com/cfgis/cfgms/pkg/logging"
)

// reservedCNs are CN values that cannot be used for operator admin bundles.
// "system" prevents impersonation of audit.SystemUserID (pkg/audit/manager.go:90).
// "cfgms", "cfgms-internal", and "cfgms-admin" are reserved for system-internal certs.
// "cfgms-admin" is the CN used by the system admin bundle issued during --init; reserving
// it prevents audit log ambiguity from a duplicate operator bundle with the same CN.
var reservedCNs = []string{"system", "cfgms", "cfgms-internal", "cfgms-admin"}

// stewardCNPattern matches raw steward UUIDs as used in the controller registration
// handler (features/controller/api/handlers_registration.go:206-211).
// Steward client certs use the raw steward UUID as CN with Organization="CFGMS Stewards".
var stewardCNPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// adminCertValidityDays is the hard-coded maximum validity for admin certs (L3 fix).
// All admin cert issuance paths pass this value explicitly; no caller can supply higher.
const adminCertValidityDays = 365

// IssueAdminBundle issues a new admin client cert+key bundle for the named operator.
// The name must be non-empty, alphanumeric+hyphens only, max 64 chars, and must not
// match any reserved CN or steward UUID pattern. The bundle is written to outputPath
// with mode 0600 (enforced by bundle.Write).
func IssueAdminBundle(cfg *config.Config, logger logging.Logger, name, outputPath string) error {
	if err := validateCN(name); err != nil {
		return err
	}
	if outputPath == defaultAdminBundlePath() {
		return fmt.Errorf("cannot overwrite the system admin bundle; use --regenerate to replace it")
	}

	certManager, err := loadCertManager(cfg)
	if err != nil {
		return fmt.Errorf("failed to load cert manager: %w", err)
	}

	adminCert, err := certManager.GenerateClientCertificate(&cert.ClientCertConfig{
		CommonName:       name,
		Organization:     "CFGMS",
		ValidityDays:     adminCertValidityDays,
		TemplateModifier: cert.SetAdminMarker,
	})
	if err != nil {
		return fmt.Errorf("failed to issue admin certificate: %w", err)
	}

	// L3 defensive check: catch future regressions in GenerateClientCertificate
	validity := adminCert.ExpiresAt.Sub(adminCert.CreatedAt)
	maxValidity := time.Duration(adminCertValidityDays+1) * 24 * time.Hour
	if validity > maxValidity {
		return fmt.Errorf("issued cert validity %v exceeds cap of %d days: this is a bug in GenerateClientCertificate",
			validity, adminCertValidityDays)
	}

	caPEM, err := certManager.GetCACertificate()
	if err != nil {
		return fmt.Errorf("failed to get CA certificate PEM: %w", err)
	}

	b := &bundle.Bundle{
		CertPEM:         string(adminCert.CertificatePEM),
		KeyPEM:          string(adminCert.PrivateKeyPEM),
		CAPEM:           string(caPEM),
		ControllerURL:   cfg.ExternalURL,
		AuditSubject:    "admin:" + name,
		CertSerial:      adminCert.SerialNumber,
		CertFingerprint: adminCert.Fingerprint,
	}

	if err := bundle.Write(outputPath, b); err != nil {
		return fmt.Errorf("failed to write admin bundle: %w", err)
	}

	bm := &BundleMarker{
		Serial:      adminCert.SerialNumber,
		Fingerprint: adminCert.Fingerprint,
		IssuedAt:    time.Now().UTC(),
		BundlePath:  outputPath,
	}
	if err := writeBundleMarker(outputPath, bm); err != nil {
		return fmt.Errorf("failed to write bundle issuance marker: %w", err)
	}

	logger.Info("Admin bundle issued",
		"path", logging.SanitizeLogValue(outputPath),
		"name", logging.SanitizeLogValue(name),
		"serial", adminCert.SerialNumber)
	return nil
}

// RegenerateSystemBundle issues a fresh admin cert and overwrites the system bundle.
// The old cert remains valid until explicitly revoked via RevokeAdminBundle — the
// caller is responsible for running revocation after regeneration.
func RegenerateSystemBundle(cfg *config.Config, logger logging.Logger) error {
	bundlePath := cfg.AdminBundlePath
	if bundlePath == "" {
		bundlePath = defaultAdminBundlePath()
	}

	certManager, err := loadCertManager(cfg)
	if err != nil {
		return fmt.Errorf("failed to load cert manager: %w", err)
	}

	return issueAdminBundle(bundlePath, cfg, certManager, logger)
}

// RunRegenerate handles the --regenerate flow with an explicit confirmation prompt.
// The caller supplies in (user input) and out (prompt destination) so tests can
// inject non-interactive readers without relying on os.Stdin.
//
// After regenerating, run `cfgms-controller bootstrap-admin --revoke <old-serial>`
// to invalidate the previous bundle.
func RunRegenerate(cfg *config.Config, logger logging.Logger, in io.Reader, out io.Writer) error {
	bundlePath := cfg.AdminBundlePath
	if bundlePath == "" {
		bundlePath = defaultAdminBundlePath()
	}

	_, _ = fmt.Fprintf(out, "This will issue a new system admin bundle and overwrite the existing one at %s.\n", bundlePath)
	_, _ = fmt.Fprintln(out, "The old bundle remains valid until you explicitly revoke its certificate.")
	_, _ = fmt.Fprintln(out, "Type 'yes' to confirm:")

	scanner := bufio.NewScanner(in)
	var response string
	if scanner.Scan() {
		response = scanner.Text()
	}

	if response != "yes" {
		_, _ = fmt.Fprintln(out, "Regeneration cancelled.")
		return fmt.Errorf("regeneration cancelled by operator")
	}

	return RegenerateSystemBundle(cfg, logger)
}

// RevokeAdminBundle revokes the admin bundle identified by serialNumber.
// Returns an error if the serial is not found in the certificate store.
func RevokeAdminBundle(cfg *config.Config, logger logging.Logger, serialNumber string) error {
	certManager, err := loadCertManager(cfg)
	if err != nil {
		return fmt.Errorf("failed to load cert manager: %w", err)
	}

	if err := certManager.Revoke(serialNumber); err != nil {
		return fmt.Errorf("failed to revoke serial %s: %w", serialNumber, err)
	}

	logger.Info("Admin bundle revoked", "serial", logging.SanitizeLogValue(serialNumber))
	return nil
}

// validateCN enforces naming rules for operator admin cert CNs.
// Returns an error with code "RESERVED_CN" in the message when the name is reserved.
func validateCN(name string) error {
	if name == "" {
		return fmt.Errorf("name is required")
	}
	if len(name) > 64 {
		return fmt.Errorf("name must be 64 characters or fewer")
	}
	for _, c := range name {
		if !isAlphanumHyphen(c) {
			return fmt.Errorf("name must contain only alphanumeric characters and hyphens, got %q", name)
		}
	}
	if strings.HasPrefix(name, "-") || strings.HasSuffix(name, "-") {
		return fmt.Errorf("name must not begin or end with a hyphen, got %q", name)
	}
	lower := strings.ToLower(name)
	for _, reserved := range reservedCNs {
		if lower == reserved {
			return fmt.Errorf("RESERVED_CN: %q is a reserved common name", name)
		}
	}
	if stewardCNPattern.MatchString(lower) {
		return fmt.Errorf("RESERVED_CN: %q matches the steward UUID CN pattern and cannot be used for operator bundles", name)
	}
	return nil
}

func isAlphanumHyphen(c rune) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
		(c >= '0' && c <= '9') || c == '-'
}

// loadCertManager loads a cert.Manager from an already-initialized controller.
// The StoragePath is resolved from cfg.CertPath, falling back to cfg.Certificate.CAPath.
func loadCertManager(cfg *config.Config) (*cert.Manager, error) {
	certPath := cfg.CertPath
	if certPath == "" && cfg.Certificate != nil {
		certPath = cfg.Certificate.CAPath
	}
	if certPath == "" {
		return nil, fmt.Errorf("certificate path not configured (cert_path or certificate.ca_path required)")
	}
	return cert.NewManager(&cert.ManagerConfig{
		StoragePath:    certPath,
		LoadExistingCA: true,
	})
}
