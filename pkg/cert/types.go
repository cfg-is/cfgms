// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
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
package cert

import (
	"crypto/x509"
	"time"
)

// CertificateType represents the type of certificate
type CertificateType int

const (
	// CertificateTypeCA represents a Certificate Authority certificate
	CertificateTypeCA CertificateType = 0
	// CertificateTypeServer represents a server certificate (unified mode - all purposes)
	CertificateTypeServer CertificateType = 1
	// CertificateTypeClient represents a client certificate
	CertificateTypeClient CertificateType = 2

	// Three-certificate architecture types (Story #377)
	// Explicit values prevent iota reordering from corrupting stored metadata.json

	// CertificateTypePublicAPI is for HTTPS REST API only (external-facing)
	CertificateTypePublicAPI CertificateType = 3
	// CertificateTypeInternalServer is for gRPC-over-QUIC mutual TLS (internal)
	CertificateTypeInternalServer CertificateType = 4
	// CertificateTypeConfigSigning is for config/DNA signing only (CodeSigning EKU)
	CertificateTypeConfigSigning CertificateType = 5
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
	case CertificateTypePublicAPI:
		return "PublicAPI"
	case CertificateTypeInternalServer:
		return "InternalServer"
	case CertificateTypeConfigSigning:
		return "ConfigSigning"
	default:
		return "Unknown"
	}
}

// SigningCertConfig contains configuration for config signing certificate generation
type SigningCertConfig struct {
	// Common name for the signing certificate
	CommonName string

	// Organization name
	Organization string

	// Certificate validity period in days (default: 1095 = 3 years)
	ValidityDays int

	// RSA key size (default: 4096)
	KeySize int
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

	// TemplateModifier is an optional function applied to the certificate template
	// before signing. Pass SetAdminMarker (from the cert package) to issue admin certificates.
	TemplateModifier func(*x509.Certificate)
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
