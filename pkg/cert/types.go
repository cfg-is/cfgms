// Package cert provides certificate management functionality for CFGMS.
//
// This package implements automated certificate management for mTLS authentication
// between controller and steward components. It provides Certificate Authority (CA)
// management, certificate generation, validation, renewal, and secure storage.
//
// Key features:
//   - Automated CA initialization and management
//   - Steward certificate generation and signing
//   - Certificate lifecycle management (renewal, revocation)
//   - Secure certificate storage and distribution
//   - Certificate validation and health monitoring
//
// Basic usage for CA operations:
//
//	ca, err := cert.NewCA(&cert.CAConfig{
//		Organization: "CFGMS",
//		Country:      "US",
//		ValidityDays: 3650,
//	})
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	// Generate controller certificate
//	controllerCert, err := ca.GenerateServerCertificate(&cert.ServerCertConfig{
//		CommonName: "cfgms-controller",
//		DNSNames:   []string{"localhost", "controller.cfgms.local"},
//		ValidityDays: 365,
//	})
//
// Basic usage for steward certificates:
//
//	stewardCert, err := ca.GenerateClientCertificate(&cert.ClientCertConfig{
//		CommonName:   "steward-" + stewardID,
//		Organization: "CFGMS Stewards",
//		ValidityDays: 365,
//	})
//
package cert

import (
	"crypto/x509"
	"time"
)

// CertificateType represents the type of certificate
type CertificateType int

const (
	// CertificateTypeCA represents a Certificate Authority certificate
	CertificateTypeCA CertificateType = iota
	// CertificateTypeServer represents a server certificate
	CertificateTypeServer
	// CertificateTypeClient represents a client certificate
	CertificateTypeClient
)

// String returns the string representation of the certificate type
func (ct CertificateType) String() string {
	switch ct {
	case CertificateTypeCA:
		return "CA"
	case CertificateTypeServer:
		return "Server"
	case CertificateTypeClient:
		return "Client"
	default:
		return "Unknown"
	}
}

// CAConfig contains configuration for Certificate Authority creation
type CAConfig struct {
	// Organization name for the CA
	Organization string
	
	// Country code (e.g., "US")
	Country string
	
	// State or province
	State string
	
	// City or locality
	City string
	
	// Organizational unit
	OrganizationalUnit string
	
	// Certificate validity period in days
	ValidityDays int
	
	// RSA key size (2048, 4096)
	KeySize int
	
	// Storage path for CA files
	StoragePath string
}

// ServerCertConfig contains configuration for server certificate generation
type ServerCertConfig struct {
	// Common name (typically the hostname)
	CommonName string
	
	// DNS names for Subject Alternative Names
	DNSNames []string
	
	// IP addresses for Subject Alternative Names  
	IPAddresses []string
	
	// Organization name
	Organization string
	
	// Certificate validity period in days
	ValidityDays int
	
	// RSA key size (2048, 4096)
	KeySize int
}

// ClientCertConfig contains configuration for client certificate generation
type ClientCertConfig struct {
	// Common name (typically steward ID)
	CommonName string
	
	// Organization name
	Organization string
	
	// Organizational unit
	OrganizationalUnit string
	
	// Certificate validity period in days
	ValidityDays int
	
	// RSA key size (2048, 4096)
	KeySize int
	
	// Client identifier for tracking
	ClientID string
}

// Certificate represents a generated certificate with its metadata
type Certificate struct {
	// Certificate type
	Type CertificateType
	
	// Common name from the certificate
	CommonName string
	
	// Certificate serial number
	SerialNumber string
	
	// Certificate creation time
	CreatedAt time.Time
	
	// Certificate expiration time
	ExpiresAt time.Time
	
	// Whether the certificate is valid
	IsValid bool
	
	// Certificate data in PEM format
	CertificatePEM []byte
	
	// Private key data in PEM format (only available for newly generated certificates)
	PrivateKeyPEM []byte
	
	// Certificate fingerprint (SHA256)
	Fingerprint string
	
	// Issuer information
	Issuer string
	
	// Client ID (for client certificates)
	ClientID string
}

// CertificateInfo contains certificate information without sensitive data
type CertificateInfo struct {
	// Certificate type
	Type CertificateType
	
	// Common name from the certificate
	CommonName string
	
	// Certificate serial number
	SerialNumber string
	
	// Certificate creation time
	CreatedAt time.Time
	
	// Certificate expiration time
	ExpiresAt time.Time
	
	// Whether the certificate is valid
	IsValid bool
	
	// Certificate fingerprint (SHA256)
	Fingerprint string
	
	// Issuer information
	Issuer string
	
	// Client ID (for client certificates)
	ClientID string
	
	// Days until expiration
	DaysUntilExpiration int
	
	// Whether the certificate needs renewal
	NeedsRenewal bool
}

// ValidationResult contains certificate validation results
type ValidationResult struct {
	// Whether the certificate is valid
	IsValid bool
	
	// Validation errors
	Errors []string
	
	// Warnings (non-fatal issues)
	Warnings []string
	
	// Certificate chain depth
	ChainDepth int
	
	// Whether the certificate is expired
	IsExpired bool
	
	// Whether the certificate is revoked
	IsRevoked bool
	
	// Days until expiration
	DaysUntilExpiration int
}

// RenewalInfo contains information about certificate renewal
type RenewalInfo struct {
	// Certificate that needs renewal
	Certificate *CertificateInfo
	
	// Reason for renewal
	Reason string
	
	// Priority (high, medium, low)
	Priority string
	
	// Recommended renewal date
	RecommendedRenewalDate time.Time
	
	// Whether renewal is urgent
	IsUrgent bool
}

// CAManager provides Certificate Authority management functionality
type CAManager interface {
	// Initialize creates a new Certificate Authority
	Initialize(config *CAConfig) error
	
	// LoadCA loads an existing Certificate Authority
	LoadCA(storagePath string) error
	
	// GetCACertificate returns the CA certificate in PEM format
	GetCACertificate() ([]byte, error)
	
	// IsInitialized returns true if the CA is initialized
	IsInitialized() bool
	
	// GetCAInfo returns information about the CA
	GetCAInfo() (*CertificateInfo, error)
	
	// GenerateServerCertificate creates a new server certificate
	GenerateServerCertificate(config *ServerCertConfig) (*Certificate, error)
	
	// GenerateClientCertificate creates a new client certificate
	GenerateClientCertificate(config *ClientCertConfig) (*Certificate, error)
	
	// ValidateCertificate validates a certificate against this CA
	ValidateCertificate(certPEM []byte) (*ValidationResult, error)
	
	// RevokeCertificate revokes a certificate
	RevokeCertificate(serialNumber string, reason string) error
	
	// GetRevokedCertificates returns the list of revoked certificates
	GetRevokedCertificates() ([]string, error)
}

// CertificateStore provides certificate storage and retrieval functionality
type CertificateStore interface {
	// StoreCertificate stores a certificate
	StoreCertificate(cert *Certificate) error
	
	// GetCertificate retrieves a certificate by serial number
	GetCertificate(serialNumber string) (*Certificate, error)
	
	// GetCertificateByCommonName retrieves certificates by common name
	GetCertificateByCommonName(commonName string) ([]*CertificateInfo, error)
	
	// GetCertificatesByType retrieves certificates by type
	GetCertificatesByType(certType CertificateType) ([]*CertificateInfo, error)
	
	// ListCertificates returns all certificates
	ListCertificates() ([]*CertificateInfo, error)
	
	// DeleteCertificate removes a certificate from storage
	DeleteCertificate(serialNumber string) error
	
	// GetExpiringCertificates returns certificates expiring within the specified days
	GetExpiringCertificates(withinDays int) ([]*CertificateInfo, error)
	
	// GetStoragePath returns the base storage path
	GetStoragePath() string
}

// CertificateValidator provides certificate validation functionality
type CertificateValidator interface {
	// ValidateChain validates a certificate chain
	ValidateChain(certChain []*x509.Certificate) (*ValidationResult, error)
	
	// ValidateCertificate validates a single certificate
	ValidateCertificate(cert *x509.Certificate) (*ValidationResult, error)
	
	// ValidateCertificateFile validates a certificate from PEM file data
	ValidateCertificateFile(certPEM []byte) (*ValidationResult, error)
	
	// ValidateCertificateChainFiles validates a certificate chain from PEM file data
	ValidateCertificateChainFiles(certChainPEM []byte) (*ValidationResult, error)
	
	// CheckExpiration checks if certificates are expiring
	CheckExpiration(certs []*CertificateInfo, withinDays int) ([]*RenewalInfo, error)
	
	// VerifyHostname verifies if a certificate is valid for a hostname
	VerifyHostname(cert *x509.Certificate, hostname string) error
}

// CertificateRenewer provides certificate renewal functionality
type CertificateRenewer interface {
	// GetRenewalCandidates returns certificates that need renewal
	GetRenewalCandidates(withinDays int) ([]*RenewalInfo, error)
	
	// RenewCertificate renews a certificate
	RenewCertificate(serialNumber string, config interface{}) (*Certificate, error)
	
	// AutoRenewCertificates automatically renews expiring certificates
	AutoRenewCertificates(withinDays int) ([]*Certificate, error)
	
	// ScheduleRenewal schedules automatic renewal for a certificate
	ScheduleRenewal(serialNumber string, renewalDate time.Time) error
}