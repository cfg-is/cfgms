// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package cert manager provides a high-level interface for certificate management.
//
// The Manager combines CA management, certificate storage, validation, and renewal
// into a single, easy-to-use interface for CFGMS certificate operations.
//
// Example usage:
//
//	// Initialize certificate manager
//	manager, err := cert.NewManager(&cert.ManagerConfig{
//		CAConfig: &cert.CAConfig{
//			Organization: "CFGMS",
//			Country:      "US",
//			ValidityDays: 3650,
//		},
//		StoragePath: "/etc/cfgms/certs",
//	})
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	// Generate controller certificate
//	controllerCert, err := manager.GenerateServerCertificate(&cert.ServerCertConfig{
//		CommonName:   "cfgms-controller",
//		DNSNames:     []string{"localhost", "controller.local"},
//		ValidityDays: 365,
//	})
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	// Generate steward certificate
//	stewardCert, err := manager.GenerateClientCertificate(&cert.ClientCertConfig{
//		CommonName:   "steward-001",
//		Organization: "CFGMS Stewards",
//		ClientID:     "steward-001",
//		ValidityDays: 365,
//	})
//	if err != nil {
//		log.Fatal(err)
//	}
package cert

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	secretsinterfaces "github.com/cfgis/cfgms/pkg/secrets/interfaces"
)

// ManagerConfig contains configuration for the certificate manager
type ManagerConfig struct {
	// CA configuration (required for new CAs)
	CAConfig *CAConfig

	// StoragePath is the parent directory that contains (or will contain) the "ca/"
	// subdirectory where CA cert and key files live.  NewManager always derives the
	// real CA directory as filepath.Join(StoragePath, "ca"), so callers must pass the
	// parent of the configured CA path — not the CA path itself.  For example, if
	// certificate.ca_path is "/var/lib/cfgms/certs/ca", StoragePath must be
	// "/var/lib/cfgms/certs" (i.e. filepath.Dir(caPath)).
	StoragePath string

	// Whether to load existing CA or create new one
	LoadExistingCA bool

	// Automatic renewal settings
	EnableAutoRenewal    bool
	RenewalThresholdDays int
}

// Manager provides high-level certificate management functionality
type Manager struct {
	ca         *CA
	store      *FileStore
	validator  *Validator
	renewer    *Renewer
	config     *ManagerConfig
	revocation *revocationStore
	rotateMu   sync.Mutex // serialises RotateSigningCertificate calls
}

// NewManager creates a new certificate manager
func NewManager(config *ManagerConfig) (*Manager, error) {
	if config == nil {
		return nil, fmt.Errorf("manager config is required")
	}

	if config.StoragePath == "" {
		return nil, fmt.Errorf("storage path is required")
	}

	// Set defaults
	if config.RenewalThresholdDays == 0 {
		config.RenewalThresholdDays = 30
	}

	// Initialize certificate store
	store, err := NewFileStore(config.StoragePath)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize certificate store: %w", err)
	}

	// Initialize CA
	var ca *CA
	if config.LoadExistingCA {
		// Try to load existing CA
		ca = &CA{}
		caPath := filepath.Join(config.StoragePath, "ca")
		if err := ca.LoadCA(caPath); err != nil {
			return nil, fmt.Errorf("failed to load existing CA: %w", err)
		}
	} else {
		// Create new CA
		if config.CAConfig == nil {
			return nil, fmt.Errorf("CA config is required for new CA creation")
		}

		// Set storage path for CA
		config.CAConfig.StoragePath = filepath.Join(config.StoragePath, "ca")

		ca, err = NewCA(config.CAConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to create CA: %w", err)
		}

		if err := ca.Initialize(config.CAConfig); err != nil {
			return nil, fmt.Errorf("failed to initialize CA: %w", err)
		}
	}

	// Initialize validator
	caCert := ca.certificate
	validator := NewValidator(caCert)

	// Initialize renewer
	renewer := NewRenewer(ca, store, validator)

	// Initialize revocation store (reads existing list if present, empty list if not)
	revStore, err := newRevocationStore(config.StoragePath)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize revocation store: %w", err)
	}

	manager := &Manager{
		ca:         ca,
		store:      store,
		validator:  validator,
		renewer:    renewer,
		config:     config,
		revocation: revStore,
	}

	// Store the CA certificate in the certificate store for easy retrieval. Reads
	// ca.certificate directly rather than calling ca.GetCACertificate(): once that
	// method means "the ultimate trust root" (see its doc comment), pairing its PEM
	// with this CA's own metadata (CommonName, SerialNumber, Fingerprint) would be
	// self-contradictory for an imported intermediate. This block only ever runs on
	// fresh generation (!config.LoadExistingCA), so it is byte-identical to today's
	// behavior for the self-generated-root case this always was.
	if !config.LoadExistingCA {
		caInfo, err := ca.GetCAInfo()
		if err == nil {
			caCertPEM := pem.EncodeToMemory(&pem.Block{
				Type:  "CERTIFICATE",
				Bytes: ca.certificate.Raw,
			})
			// Create a Certificate object for the CA
			caCertificate := &Certificate{
				Type:           CertificateTypeCA,
				CommonName:     caInfo.CommonName,
				SerialNumber:   caInfo.SerialNumber,
				CreatedAt:      caInfo.CreatedAt,
				ExpiresAt:      caInfo.ExpiresAt,
				IsValid:        caInfo.IsValid,
				CertificatePEM: caCertPEM,
				Fingerprint:    caInfo.Fingerprint,
				Issuer:         "Self-signed CA",
			}

			// Store the CA certificate (ignore errors as this is for convenience)
			_ = store.StoreCertificate(caCertificate)
		}
	}

	return manager, nil
}

// GetCACertificate returns the CA certificate in PEM format
func (m *Manager) GetCACertificate() ([]byte, error) {
	return m.ca.GetCACertificate()
}

// GetCAInfo returns information about the CA
func (m *Manager) GetCAInfo() (*CertificateInfo, error) {
	return m.ca.GetCAInfo()
}

// GenerateServerCertificate creates a new server certificate
func (m *Manager) GenerateServerCertificate(config *ServerCertConfig) (*Certificate, error) {
	cert, err := m.ca.GenerateServerCertificate(config)
	if err != nil {
		return nil, err
	}

	// Store the certificate
	if err := m.store.StoreCertificate(cert); err != nil {
		return nil, fmt.Errorf("failed to store server certificate: %w", err)
	}

	return cert, nil
}

// GenerateClientCertificate creates a new client certificate
func (m *Manager) GenerateClientCertificate(config *ClientCertConfig) (*Certificate, error) {
	cert, err := m.ca.GenerateClientCertificate(config)
	if err != nil {
		return nil, err
	}

	// Store the certificate
	if err := m.store.StoreCertificate(cert); err != nil {
		return nil, fmt.Errorf("failed to store client certificate: %w", err)
	}

	return cert, nil
}

// SignClientCertificateRequest signs a caller-supplied public key into a client
// certificate and stores it. The CA never generates or sees a private key for this
// credential, so the stored Certificate.PrivateKeyPEM is empty and FileStore never
// writes a key.pem for it.
func (m *Manager) SignClientCertificateRequest(pubKey crypto.PublicKey, config *ClientCertConfig) (*Certificate, error) {
	cert, err := m.ca.SignClientCertificateRequest(pubKey, config)
	if err != nil {
		return nil, err
	}

	// Store the certificate
	if err := m.store.StoreCertificate(cert); err != nil {
		return nil, fmt.Errorf("failed to store client certificate: %w", err)
	}

	return cert, nil
}

// SignSubordinateCA signs a caller-supplied public key into a subordinate
// (intermediate) CA certificate and stores it. The CA never generates or sees
// a private key for this credential, so the stored Certificate.PrivateKeyPEM
// is empty and FileStore never writes a key.pem for it.
func (m *Manager) SignSubordinateCA(pubKey crypto.PublicKey, config *SubordinateCAConfig) (*Certificate, error) {
	cert, err := m.ca.SignSubordinateCA(pubKey, config)
	if err != nil {
		return nil, err
	}

	// Store the certificate
	if err := m.store.StoreCertificate(cert); err != nil {
		return nil, fmt.Errorf("failed to store subordinate CA certificate: %w", err)
	}

	return cert, nil
}

// GenerateSigningCertificate creates a config signing certificate and stores it
func (m *Manager) GenerateSigningCertificate(config *SigningCertConfig) (*Certificate, error) {
	cert, err := m.ca.GenerateSigningCertificate(config)
	if err != nil {
		return nil, err
	}

	if err := m.store.StoreCertificate(cert); err != nil {
		return nil, fmt.Errorf("failed to store signing certificate: %w", err)
	}

	return cert, nil
}

// GenerateInternalServerCertificate creates an internal mTLS server certificate and stores it
func (m *Manager) GenerateInternalServerCertificate(config *ServerCertConfig) (*Certificate, error) {
	cert, err := m.ca.GenerateInternalServerCertificate(config)
	if err != nil {
		return nil, err
	}

	if err := m.store.StoreCertificate(cert); err != nil {
		return nil, fmt.Errorf("failed to store internal server certificate: %w", err)
	}

	return cert, nil
}

// EnsureSeparatedCertificates generates missing separated-mode certificates.
// Idempotent: safe to call on every startup. Only generates certs that don't exist yet.
func (m *Manager) EnsureSeparatedCertificates(internalCfg *ServerCertConfig, signingCfg *SigningCertConfig) error {
	// Check for existing internal server certificate
	internalCerts, err := m.store.getCertificatesByType(CertificateTypeInternalServer)
	if err != nil {
		return fmt.Errorf("failed to check for internal server certificates: %w", err)
	}

	if len(internalCerts) == 0 {
		if internalCfg == nil {
			internalCfg = &ServerCertConfig{
				CommonName:   "cfgms-internal",
				DNSNames:     []string{"localhost", "cfgms-internal"},
				IPAddresses:  []string{"127.0.0.1"},
				ValidityDays: 365,
			}
		}
		if _, err := m.GenerateInternalServerCertificate(internalCfg); err != nil {
			return fmt.Errorf("failed to generate internal server certificate: %w", err)
		}
	}

	// Check for existing config signing certificate
	signingCerts, err := m.store.getCertificatesByType(CertificateTypeConfigSigning)
	if err != nil {
		return fmt.Errorf("failed to check for config signing certificates: %w", err)
	}

	if len(signingCerts) == 0 {
		if signingCfg == nil {
			signingCfg = &SigningCertConfig{
				CommonName:   "cfgms-config-signer",
				ValidityDays: 1095,
				KeySize:      4096,
			}
		}
		if _, err := m.GenerateSigningCertificate(signingCfg); err != nil {
			return fmt.Errorf("failed to generate config signing certificate: %w", err)
		}
	}

	return nil
}

// EnsureSigningCertificate generates a dedicated config-signing certificate if
// none exists yet. Idempotent: safe to call on every controller startup.
//
// The config signer must remain STABLE across controller restarts. A steward
// caches the controller's signing certificate at registration (and restores it
// from disk on a cert-reuse reconnect) and rejects any command or config signed
// by a different key. A dedicated, persisted config-signing certificate gives
// the controller a durable signing identity — unlike the gRPC server
// certificate, which may be regenerated per boot. When signingCfg is nil, a
// default 1095-day RSA-4096 signing certificate is generated.
func (m *Manager) EnsureSigningCertificate(signingCfg *SigningCertConfig) error {
	signingCerts, err := m.store.getCertificatesByType(CertificateTypeConfigSigning)
	if err != nil {
		return fmt.Errorf("failed to check for config signing certificates: %w", err)
	}
	if len(signingCerts) > 0 {
		return nil
	}

	if signingCfg == nil {
		signingCfg = &SigningCertConfig{
			CommonName:   "cfgms-config-signer",
			ValidityDays: 1095,
			KeySize:      4096,
		}
	}
	if _, err := m.GenerateSigningCertificate(signingCfg); err != nil {
		return fmt.Errorf("failed to generate config signing certificate: %w", err)
	}
	return nil
}

// RotateSigningCertificate generates a new ConfigSigning certificate and atomically
// transitions the lifecycle cursor, making the new cert active and keeping the old
// one valid for the overlap window so in-flight verifications are not disrupted.
//
// Returns an error if a rotation is already in progress (RotatingSerial is set and
// still within the overlap window). Concurrent callers are serialised; the second
// caller will fail with "rotation already in progress" once the first completes.
func (m *Manager) RotateSigningCertificate(overlapWindowDays int) (*Certificate, error) {
	return m.rotateSigningCertificate(overlapWindowDays, false)
}

// ForceRotateSigningCertificate behaves like RotateSigningCertificate but bypasses
// the in-progress guard. Used by operator-initiated rotations to recover when the
// previous overlap window has not yet expired but a fresh rotation is required.
// The in-progress RotatingSerial in the cursor is cleared atomically before the
// new cert is generated and the cursor is re-transitioned.
func (m *Manager) ForceRotateSigningCertificate(overlapWindowDays int) (*Certificate, error) {
	return m.rotateSigningCertificate(overlapWindowDays, true)
}

func (m *Manager) rotateSigningCertificate(overlapWindowDays int, force bool) (*Certificate, error) {
	m.rotateMu.Lock()
	defer m.rotateMu.Unlock()

	cursor, err := loadSigningCursor(m.store.basePath)
	if err != nil {
		return nil, fmt.Errorf("load signing cursor: %w", err)
	}

	if cursor != nil && cursor.RotatingSerial != "" {
		if force {
			// Clear in-progress state so the cursor transition proceeds as if the
			// previous overlap had already closed. The just-cleared cursor is then
			// re-read by transitionSigningCursor inside the same rotateMu critical
			// section, so the bypass is atomic with respect to other rotations.
			cursor.RotatingSerial = ""
			if err := saveSigningCursor(m.store.basePath, cursor); err != nil {
				return nil, fmt.Errorf("clear signing cursor for force rotate: %w", err)
			}
		} else {
			overlapDuration := time.Duration(cursor.OverlapWindowDays) * 24 * time.Hour
			if time.Since(cursor.RotatedAt) < overlapDuration {
				return nil, fmt.Errorf(
					"%w: rotating serial %q is still within %d-day overlap window (rotated %s ago)",
					ErrSigningRotationInProgress,
					cursor.RotatingSerial,
					cursor.OverlapWindowDays,
					time.Since(cursor.RotatedAt).Truncate(time.Second),
				)
			}
		}
	}

	newCert, err := m.ca.GenerateSigningCertificate(&SigningCertConfig{
		CommonName:   "cfgms-config-signer",
		ValidityDays: 1095,
		KeySize:      4096,
	})
	if err != nil {
		return nil, fmt.Errorf("generate signing certificate: %w", err)
	}

	if err := m.store.StoreCertificate(newCert); err != nil {
		return nil, fmt.Errorf("store signing certificate: %w", err)
	}

	if err := transitionSigningCursor(m.store, m.store.basePath, newCert.SerialNumber, overlapWindowDays); err != nil {
		return nil, fmt.Errorf("transition signing cursor: %w", err)
	}

	return newCert, nil
}

// purposeToType maps a CertificatePurpose to its underlying CertificateType.
func purposeToType(p CertificatePurpose) (CertificateType, error) {
	switch p {
	case PurposeTransport:
		return CertificateTypeInternalServer, nil
	case PurposeAPI:
		return CertificateTypePublicAPI, nil
	case PurposeSigning:
		return CertificateTypeConfigSigning, nil
	case PurposeClient:
		return CertificateTypeClient, nil
	default:
		return 0, fmt.Errorf("unknown certificate purpose: %d", p)
	}
}

// GetCurrentCertForPurpose returns the current (newest valid) certificate for the
// given purpose. Returns an error if no valid certificate exists. Presentation and
// signing paths use this method; verification/trust paths use
// GetAllValidCertificatesForPurpose instead.
func (m *Manager) GetCurrentCertForPurpose(purpose CertificatePurpose) (*Certificate, error) {
	certType, err := purposeToType(purpose)
	if err != nil {
		return nil, err
	}

	certs, err := m.store.getCertificatesByType(certType)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve certificates for purpose %s: %w", purpose, err)
	}

	// getCertificatesByType returns newest-first; return the first valid one.
	for _, info := range certs {
		if info.IsValid {
			c, cerr := m.store.GetCertificate(info.SerialNumber)
			if cerr != nil {
				continue
			}
			return c, nil
		}
	}

	return nil, fmt.Errorf("no valid certificate found for purpose %s", purpose)
}

// GetAllValidCertificatesForPurpose returns all currently valid certificates for
// the given purpose, newest first. Verification and trust paths use this method
// to accept all valid certs during rotation overlap windows.
func (m *Manager) GetAllValidCertificatesForPurpose(purpose CertificatePurpose) ([]*CertificateInfo, error) {
	certType, err := purposeToType(purpose)
	if err != nil {
		return nil, err
	}

	certs, err := m.store.getCertificatesByType(certType)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve certificates for purpose %s: %w", purpose, err)
	}

	var valid []*CertificateInfo
	for _, info := range certs {
		if info.IsValid {
			valid = append(valid, info)
		}
	}
	return valid, nil
}

// CheckForLegacyCertificates returns an error if the certificate store contains
// any certificates with the removed unified-mode type (integer value 1, formerly
// CertificateTypeServer). Their presence indicates a pre-migration deployment.
// See docs/security/certificate-architecture.md#migrating-from-unified-mode.
func (m *Manager) CheckForLegacyCertificates() error {
	const legacyServerType = CertificateType(1)
	legacy, err := m.store.getCertificatesByType(legacyServerType)
	if err != nil {
		return fmt.Errorf("failed to scan for legacy certificates: %w", err)
	}
	if len(legacy) > 0 {
		return fmt.Errorf(
			"startup blocked: found %d legacy unified-mode certificate(s) (type=1, "+
				"formerly CertificateTypeServer) in the certificate store; "+
				"this deployment predates the separated-architecture requirement; "+
				"wipe the certificate store and re-run 'controller --init'; "+
				"see docs/security/certificate-architecture.md#migrating-from-unified-mode",
			len(legacy),
		)
	}
	return nil
}

// GetSigningCertificate returns the current config signing certificate PEM (public only)
func (m *Manager) GetSigningCertificate() ([]byte, error) {
	c, err := m.GetCurrentCertForPurpose(PurposeSigning)
	if err != nil {
		return nil, fmt.Errorf("no config signing certificate found: %w", err)
	}
	if len(c.CertificatePEM) == 0 {
		return nil, fmt.Errorf("signing certificate PEM data is empty")
	}
	return c.CertificatePEM, nil
}

// GetCertificate retrieves a certificate by serial number
func (m *Manager) GetCertificate(serialNumber string) (*Certificate, error) {
	return m.store.GetCertificate(serialNumber)
}

// ListCertificates returns all certificates
func (m *Manager) ListCertificates() ([]*CertificateInfo, error) {
	return m.store.ListCertificates()
}

// GetCertificateByCommonName retrieves certificates by common name
func (m *Manager) GetCertificateByCommonName(commonName string) ([]*CertificateInfo, error) {
	return m.store.GetCertificateByCommonName(commonName)
}

// ValidateCertificate validates a certificate
func (m *Manager) ValidateCertificate(certPEM []byte) (*ValidationResult, error) {
	return m.validator.ValidateCertificateFile(certPEM)
}

// GetExpiringCertificates returns certificates expiring within the specified days
func (m *Manager) GetExpiringCertificates(withinDays int) ([]*CertificateInfo, error) {
	if withinDays <= 0 {
		withinDays = m.config.RenewalThresholdDays
	}

	return m.store.GetExpiringCertificates(withinDays)
}

// GetRenewalCandidates returns certificates that need renewal
func (m *Manager) GetRenewalCandidates(withinDays int) ([]*RenewalInfo, error) {
	if withinDays <= 0 {
		withinDays = m.config.RenewalThresholdDays
	}

	return m.renewer.GetRenewalCandidates(withinDays)
}

// RenewCertificate renews a certificate
func (m *Manager) RenewCertificate(serialNumber string, config interface{}) (*Certificate, error) {
	return m.renewer.RenewCertificate(serialNumber, config)
}

// AutoRenewCertificates automatically renews expiring certificates
func (m *Manager) AutoRenewCertificates(withinDays int) ([]*Certificate, error) {
	if withinDays <= 0 {
		withinDays = m.config.RenewalThresholdDays
	}

	if !m.config.EnableAutoRenewal {
		return nil, fmt.Errorf("automatic renewal is disabled")
	}

	return m.renewer.AutoRenewCertificates(withinDays)
}

// DeleteCertificate removes a certificate from storage
func (m *Manager) DeleteCertificate(serialNumber string) error {
	return m.store.DeleteCertificate(serialNumber)
}

// SaveCertificateFiles saves a certificate and its private key to files
func (m *Manager) SaveCertificateFiles(serialNumber, certPath, keyPath string) error {
	cert, err := m.store.GetCertificate(serialNumber)
	if err != nil {
		return fmt.Errorf("failed to get certificate: %w", err)
	}

	return SaveCertificateToFile(cert, certPath, keyPath)
}

// ImportCertificate imports an existing certificate into storage
func (m *Manager) ImportCertificate(certPEM, keyPEM []byte, certType CertificateType) (*Certificate, error) {
	// Parse the certificate to extract information
	x509Cert, err := ParseCertificateFromPEM(certPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	// Validate the key pair if private key is provided
	if keyPEM != nil {
		if err := ValidateKeyPair(certPEM, keyPEM); err != nil {
			return nil, fmt.Errorf("certificate and key do not match: %w", err)
		}
	}

	// Create certificate object
	cert := &Certificate{
		Type:           certType,
		CommonName:     x509Cert.Subject.CommonName,
		SerialNumber:   x509Cert.SerialNumber.String(),
		CreatedAt:      x509Cert.NotBefore,
		ExpiresAt:      x509Cert.NotAfter,
		IsValid:        !IsCertificateExpired(x509Cert),
		CertificatePEM: certPEM,
		PrivateKeyPEM:  keyPEM,
		Fingerprint:    func() string { h := sha256.Sum256(x509Cert.Raw); return hex.EncodeToString(h[:]) }(),
		Issuer:         x509Cert.Issuer.CommonName,
	}

	// Store the certificate
	if err := m.store.StoreCertificate(cert); err != nil {
		return nil, fmt.Errorf("failed to store imported certificate: %w", err)
	}

	return cert, nil
}

// ExportCertificate exports a certificate and optionally its private key. When
// includeChain is true and the certificate carries a non-empty IssuerChainPEM
// (only possible when it was issued by an intermediate CA), the chain is appended
// to certPEM after the leaf.
func (m *Manager) ExportCertificate(serialNumber string, includePrivateKey, includeChain bool) (certPEM []byte, keyPEM []byte, err error) {
	cert, err := m.store.GetCertificate(serialNumber)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get certificate: %w", err)
	}

	certPEM = cert.CertificatePEM
	if includeChain && len(cert.IssuerChainPEM) > 0 {
		certPEM = append(append([]byte{}, certPEM...), cert.IssuerChainPEM...)
	}

	if includePrivateKey && cert.PrivateKeyPEM != nil {
		keyPEM = cert.PrivateKeyPEM
	}

	return certPEM, keyPEM, nil
}

// GetManagerStats returns statistics about the certificate manager
func (m *Manager) GetManagerStats() (*ManagerStats, error) {
	allCerts, err := m.store.ListCertificates()
	if err != nil {
		return nil, fmt.Errorf("failed to list certificates: %w", err)
	}

	expiringCerts, err := m.store.GetExpiringCertificates(m.config.RenewalThresholdDays)
	if err != nil {
		return nil, fmt.Errorf("failed to get expiring certificates: %w", err)
	}

	renewalCandidates, err := m.renewer.GetRenewalCandidates(m.config.RenewalThresholdDays)
	if err != nil {
		return nil, fmt.Errorf("failed to get renewal candidates: %w", err)
	}

	stats := &ManagerStats{
		TotalCertificates:    len(allCerts),
		ExpiringCertificates: len(expiringCerts),
		RenewalCandidates:    len(renewalCandidates),
		CertificatesByType:   make(map[CertificateType]int),
	}

	// Count certificates by type
	for _, cert := range allCerts {
		stats.CertificatesByType[cert.Type]++
	}

	// Get CA information
	if caInfo, err := m.ca.GetCAInfo(); err == nil {
		stats.CAInfo = caInfo
	}

	return stats, nil
}

// ManagerStats provides statistics about the certificate manager
type ManagerStats struct {
	TotalCertificates    int
	ExpiringCertificates int
	RenewalCandidates    int
	CertificatesByType   map[CertificateType]int
	CAInfo               *CertificateInfo
}

// GetClientCertificate returns the latest steward client certificate for TLS handshakes.
// Each call reads the current certificate from the store so cert rotations are picked
// up automatically — no explicit notification needed.
func (m *Manager) GetClientCertificate(_ context.Context) (*tls.Certificate, error) {
	clientCerts, err := m.store.getCertificatesByType(CertificateTypeClient)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve client certificates: %w", err)
	}
	if len(clientCerts) == 0 {
		return nil, fmt.Errorf("no client certificate found in store")
	}

	// getCertificatesByType returns newest-first.
	certInfo := clientCerts[0]
	c, err := m.store.GetCertificate(certInfo.SerialNumber)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve client certificate data: %w", err)
	}
	if len(c.CertificatePEM) == 0 || len(c.PrivateKeyPEM) == 0 {
		return nil, fmt.Errorf("client certificate or private key is missing from store")
	}

	tlsCert, err := tls.X509KeyPair(c.CertificatePEM, c.PrivateKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to load client certificate key pair: %w", err)
	}
	return &tlsCert, nil
}

// GetStoragePath returns the certificate storage path
func (m *Manager) GetStoragePath() string {
	return m.store.GetStoragePath()
}

// Revoke adds serial to the revoked-serials list and persists it atomically.
// Returns an error if the serial is not found in the certificate store — revoking
// an unknown serial is an operator error that must surface explicitly.
func (m *Manager) Revoke(serial string) error {
	if _, err := m.store.GetCertificate(serial); err != nil {
		return fmt.Errorf("cannot revoke unknown serial %q: %w", serial, err)
	}
	return m.revocation.addAndPersist(RevocationEntry{
		Serial:    serial,
		RevokedAt: time.Now().UTC(),
	})
}

// IsRevoked reports whether the given certificate serial number appears in the
// revoked-serials list. Called on every mTLS admin cert authentication request.
func (m *Manager) IsRevoked(serial string) bool {
	return m.revocation.isRevoked(serial)
}

// ListRevoked returns all revocation entries for auditing and --list output.
func (m *Manager) ListRevoked() ([]RevocationEntry, error) {
	return m.revocation.allEntries(), nil
}

// GetAllValidSigningCertificates returns the set of certificates that are valid
// for verifying config signatures right now. It uses GetAllValidCertificatesForPurpose
// as the source list, then filters by the signing cursor state:
//   - CurrentSerial is always included (if valid).
//   - RotatingSerial is included only while still within its overlap window.
//   - If no cursor file exists (no rotation in progress) all valid signing certs are returned.
func (m *Manager) GetAllValidSigningCertificates() ([]*CertificateInfo, error) {
	all, err := m.GetAllValidCertificatesForPurpose(PurposeSigning)
	if err != nil {
		return nil, err
	}

	cursor, err := loadSigningCursor(m.store.basePath)
	if err != nil {
		return nil, fmt.Errorf("failed to load signing cursor: %w", err)
	}

	if cursor == nil {
		return all, nil
	}

	allowed := make(map[string]bool, 2)
	allowed[cursor.CurrentSerial] = true

	if cursor.RotatingSerial != "" {
		overlapDuration := time.Duration(cursor.OverlapWindowDays) * 24 * time.Hour
		if time.Since(cursor.RotatedAt) < overlapDuration {
			allowed[cursor.RotatingSerial] = true
		}
	}

	result := make([]*CertificateInfo, 0, len(all))
	for _, info := range all {
		if allowed[info.SerialNumber] {
			result = append(result, info)
		}
	}
	return result, nil
}

// GetSigningCursorState returns the current signing cursor, or nil if no rotation
// has been initiated. Use this to inspect lifecycle state without modifying it.
func (m *Manager) GetSigningCursorState() (*SigningCertCursor, error) {
	return loadSigningCursor(m.store.basePath)
}

// NewManagerFromSecretStore creates a Manager that loads or bootstraps the cluster CA
// from a SecretStore. The CA private key is never written to local disk.
//
// If no CA exists at caKeyPath in the store, a new CA is generated using config.CAConfig
// and stored. Only the CA public certificate is written to storagePath/ca/ca.crt so
// the TLS stack can load it; the private key remains in-process only.
//
// This is the cluster-mode entry point. Use NewManager for single-node deployments.
func NewManagerFromSecretStore(ctx context.Context, store secretsinterfaces.SecretStore, tenantID, caKeyPath string, config *ManagerConfig) (*Manager, error) {
	if store == nil {
		return nil, fmt.Errorf("secret store is required")
	}
	if tenantID == "" || caKeyPath == "" {
		return nil, fmt.Errorf("tenantID and caKeyPath are required")
	}
	if config == nil {
		return nil, fmt.Errorf("manager config is required")
	}
	if config.StoragePath == "" {
		return nil, fmt.Errorf("storage path is required")
	}

	if config.RenewalThresholdDays == 0 {
		config.RenewalThresholdDays = 30
	}

	fileStore, err := NewFileStore(config.StoragePath)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize certificate store: %w", err)
	}

	ca := &CA{}
	loadErr := ca.LoadCAFromSecretStore(ctx, store, tenantID, caKeyPath)
	if loadErr != nil {
		if config.CAConfig == nil {
			return nil, fmt.Errorf("CA config required to generate new cluster CA (load failed: %w)", loadErr)
		}

		// Generate CA in-memory: StoragePath="" prevents any disk write of ca.key.
		genConfig := &CAConfig{
			Organization:       config.CAConfig.Organization,
			Country:            config.CAConfig.Country,
			State:              config.CAConfig.State,
			City:               config.CAConfig.City,
			OrganizationalUnit: config.CAConfig.OrganizationalUnit,
			ValidityDays:       config.CAConfig.ValidityDays,
			KeySize:            config.CAConfig.KeySize,
			StoragePath:        "",
		}

		newCA, err := NewCA(genConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to create cluster CA: %w", err)
		}
		if err := newCA.Initialize(genConfig); err != nil {
			return nil, fmt.Errorf("failed to initialize cluster CA: %w", err)
		}
		if err := newCA.StoreCAToSecretStore(ctx, store, tenantID, caKeyPath); err != nil {
			return nil, fmt.Errorf("failed to store cluster CA in secret store: %w", err)
		}
		ca = newCA
	}

	// Write only the CA certificate (public) to disk for TLS config.
	// The private key is intentionally NOT written to disk on cluster nodes.
	caDir := filepath.Join(config.StoragePath, "ca")
	if err := os.MkdirAll(caDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create CA directory: %w", err)
	}
	caCertPEM, err := ca.GetCACertificate()
	if err != nil {
		return nil, fmt.Errorf("failed to get CA certificate: %w", err)
	}
	if err := os.WriteFile(filepath.Join(caDir, "ca.crt"), caCertPEM, 0600); err != nil {
		return nil, fmt.Errorf("failed to write CA certificate to disk: %w", err)
	}

	validator := NewValidator(ca.certificate)
	renewer := NewRenewer(ca, fileStore, validator)

	revStore, err := newRevocationStore(config.StoragePath)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize revocation store: %w", err)
	}

	return &Manager{
		ca:         ca,
		store:      fileStore,
		validator:  validator,
		renewer:    renewer,
		config:     config,
		revocation: revStore,
	}, nil
}

// NewManagerFromCAMaterial builds a Manager whose active CA identity is an
// already-issued certificate and its caller-held private key, with issuerChainPEM
// recorded as the chain from that certificate's own issuer up to and including
// the ultimate trust root (empty when certPEM is itself a root).
//
// issuerChainPEM is validated in full before it is recorded (see
// validateIssuerChain): it must be ordered nearest-issuer-first with the root
// last, every entry must be signed by its successor, its first entry must have
// issued certPEM, and its terminal entry must be self-signed. A chain supplied in
// the conventional root-first bundle order is rejected here rather than silently
// publishing an intermediate as the fleet's permanent trust anchor.
//
// This is the in-memory primitive underneath what will become S3's
// ImportSubordinateCA (vault-backed offline-root import) — that story adds the
// storage plumbing; this story only needs the resulting shape to exist so
// callers outside pkg/cert can exercise "the cert manager is backed by an
// intermediate CA" (Issue #3778) without waiting on it. Production managers are
// built via NewManager or NewManagerFromSecretStore.
func NewManagerFromCAMaterial(config *ManagerConfig, certPEM, keyPEM, issuerChainPEM []byte) (*Manager, error) {
	if config == nil {
		return nil, fmt.Errorf("manager config is required")
	}
	if config.StoragePath == "" {
		return nil, fmt.Errorf("storage path is required")
	}
	if config.RenewalThresholdDays == 0 {
		config.RenewalThresholdDays = 30
	}

	store, err := NewFileStore(config.StoragePath)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize certificate store: %w", err)
	}

	x509Cert, err := ParseCertificateFromPEM(certPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CA certificate: %w", err)
	}

	parsedKey, err := ParsePrivateKeyFromPEM(keyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CA private key: %w", err)
	}
	rsaKey, ok := parsedKey.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("CA private key must be RSA, got unsupported key type")
	}

	if err := ValidateKeyPair(certPEM, keyPEM); err != nil {
		return nil, fmt.Errorf("CA key does not match certificate: %w", err)
	}

	// The issuer chain is caller-supplied material whose terminal entry becomes the
	// fleet's permanently-pinned trust anchor (GetCACertificate -> ca/ca.crt,
	// installers, registration/refresh ca_cert, steward TOFU pin). Validate it here,
	// at the boundary it enters on, rather than trusting its position: reject unless
	// it links to certPEM, links internally, and terminates in a self-signed root.
	if err := validateIssuerChain(x509Cert, issuerChainPEM); err != nil {
		return nil, fmt.Errorf("invalid CA issuer chain: %w", err)
	}

	org := "CFGMS"
	if len(x509Cert.Subject.Organization) > 0 {
		org = x509Cert.Subject.Organization[0]
	}

	ca := &CA{
		certificate:    x509Cert,
		privateKey:     rsaKey,
		config:         &CAConfig{Organization: org},
		initialized:    true,
		issuerChainPEM: issuerChainPEM,
	}

	validator := NewValidator(ca.certificate)
	renewer := NewRenewer(ca, store, validator)

	revStore, err := newRevocationStore(config.StoragePath)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize revocation store: %w", err)
	}

	return &Manager{
		ca:         ca,
		store:      store,
		validator:  validator,
		renewer:    renewer,
		config:     config,
		revocation: revStore,
	}, nil
}
