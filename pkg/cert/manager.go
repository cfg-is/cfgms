// SPDX-License-Identifier: Apache-2.0
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
	"fmt"
	"path/filepath"
)

// ManagerConfig contains configuration for the certificate manager
type ManagerConfig struct {
	// CA configuration (required for new CAs)
	CAConfig *CAConfig

	// Storage path for certificates and CA
	StoragePath string

	// Whether to load existing CA or create new one
	LoadExistingCA bool

	// Automatic renewal settings
	EnableAutoRenewal    bool
	RenewalThresholdDays int
}

// Manager provides high-level certificate management functionality
type Manager struct {
	ca        CAManager
	store     CertificateStore
	validator CertificateValidator
	renewer   CertificateRenewer
	config    *ManagerConfig
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

	manager := &Manager{
		ca:        ca,
		store:     store,
		validator: validator,
		renewer:   renewer,
		config:    config,
	}

	// Store the CA certificate in the certificate store for easy retrieval
	if !config.LoadExistingCA {
		caInfo, err := ca.GetCAInfo()
		if err == nil {
			// Get the CA certificate PEM
			caCertPEM, err := ca.GetCACertificate()
			if err == nil {
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

// GetServerCertificate returns the server certificate in PEM format
// This retrieves the first server certificate from the store
// Used for configuration signature verification in HA clusters
func (m *Manager) GetServerCertificate() ([]byte, error) {
	// Get all server certificates from the store
	serverCertInfos, err := m.store.GetCertificatesByType(CertificateTypeServer)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve server certificates: %w", err)
	}

	if len(serverCertInfos) == 0 {
		return nil, fmt.Errorf("no server certificate found")
	}

	// Get the full certificate data using the serial number
	// In practice, there should only be one server certificate per controller
	certInfo := serverCertInfos[0]
	cert, err := m.store.GetCertificate(certInfo.SerialNumber)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve server certificate data: %w", err)
	}

	if len(cert.CertificatePEM) == 0 {
		return nil, fmt.Errorf("server certificate PEM data is empty")
	}

	return cert.CertificatePEM, nil
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

// GetCertificate retrieves a certificate by serial number
func (m *Manager) GetCertificate(serialNumber string) (*Certificate, error) {
	return m.store.GetCertificate(serialNumber)
}

// ListCertificates returns all certificates
func (m *Manager) ListCertificates() ([]*CertificateInfo, error) {
	return m.store.ListCertificates()
}

// GetCertificatesByType returns certificates of a specific type
func (m *Manager) GetCertificatesByType(certType CertificateType) ([]*CertificateInfo, error) {
	return m.store.GetCertificatesByType(certType)
}

// GetCertificateByCommonName retrieves certificates by common name
func (m *Manager) GetCertificateByCommonName(commonName string) ([]*CertificateInfo, error) {
	return m.store.GetCertificateByCommonName(commonName)
}

// ValidateCertificate validates a certificate
func (m *Manager) ValidateCertificate(certPEM []byte) (*ValidationResult, error) {
	return m.ca.ValidateCertificate(certPEM)
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
		Fingerprint:    GetCertificateFingerprint(x509Cert),
		Issuer:         x509Cert.Issuer.CommonName,
	}

	// Store the certificate
	if err := m.store.StoreCertificate(cert); err != nil {
		return nil, fmt.Errorf("failed to store imported certificate: %w", err)
	}

	return cert, nil
}

// ExportCertificate exports a certificate and optionally its private key
func (m *Manager) ExportCertificate(serialNumber string, includePrivateKey bool) (certPEM []byte, keyPEM []byte, err error) {
	cert, err := m.store.GetCertificate(serialNumber)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get certificate: %w", err)
	}

	certPEM = cert.CertificatePEM

	if includePrivateKey && cert.PrivateKeyPEM != nil {
		keyPEM = cert.PrivateKeyPEM
	}

	return certPEM, keyPEM, nil
}

// GetCertificateStatus provides detailed status information for a certificate
func (m *Manager) GetCertificateStatus(serialNumber string) (*CertificateStatus, error) {
	cert, err := m.store.GetCertificate(serialNumber)
	if err != nil {
		return nil, fmt.Errorf("failed to get certificate: %w", err)
	}

	// Validate the certificate
	validationResult, err := m.validator.ValidateCertificateFile(cert.CertificatePEM)
	if err != nil {
		return nil, fmt.Errorf("failed to validate certificate: %w", err)
	}

	return &CertificateStatus{
		Certificate:  cert,
		Validation:   validationResult,
		NeedsRenewal: validationResult.DaysUntilExpiration <= m.config.RenewalThresholdDays,
	}, nil
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

// CertificateStatus provides detailed status information for a certificate
type CertificateStatus struct {
	Certificate  *Certificate
	Validation   *ValidationResult
	NeedsRenewal bool
}

// ManagerStats provides statistics about the certificate manager
type ManagerStats struct {
	TotalCertificates    int
	ExpiringCertificates int
	RenewalCandidates    int
	CertificatesByType   map[CertificateType]int
	CAInfo               *CertificateInfo
}

// GetStoragePath returns the certificate storage path
func (m *Manager) GetStoragePath() string {
	return m.store.GetStoragePath()
}

// InitializeCA initializes the CA if not already initialized
func (m *Manager) InitializeCA() error {
	// CA should already be initialized in NewManager
	// This method is for compatibility with test code
	return nil
}
