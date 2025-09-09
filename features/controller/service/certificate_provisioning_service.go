package service

import (
	"fmt"
	"time"

	"github.com/cfgis/cfgms/pkg/cert"
	"github.com/cfgis/cfgms/pkg/logging"
)

// CertificateProvisioningRequest represents a request to provision a certificate
type CertificateProvisioningRequest struct {
	StewardID    string
	CommonName   string
	Organization string
	ValidityDays int
}

// CertificateProvisioningResponse represents the response from certificate provisioning
type CertificateProvisioningResponse struct {
	Success          bool
	Message          string
	CertificatePEM   []byte
	PrivateKeyPEM    []byte
	CACertificatePEM []byte
	SerialNumber     string
	ExpiresAt        time.Time
}

// CertificateProvisioningService provides certificate provisioning functionality
type CertificateProvisioningService struct {
	certManager        *cert.Manager
	logger            logging.Logger
	defaultValidityDays int
	defaultOrganization string
}

// NewCertificateProvisioningService creates a new certificate provisioning service
func NewCertificateProvisioningService(certManager *cert.Manager, logger logging.Logger) *CertificateProvisioningService {
	return &CertificateProvisioningService{
		certManager:        certManager,
		logger:            logger,
		defaultValidityDays: 365, // Default to 1 year
		defaultOrganization: "CFGMS Stewards",
	}
}

// SetCertificateDefaults sets default values for certificate provisioning
func (s *CertificateProvisioningService) SetCertificateDefaults(validityDays int, organization string) {
	if validityDays > 0 {
		s.defaultValidityDays = validityDays
	}
	if organization != "" {
		s.defaultOrganization = organization
	}
}

// ProvisionCertificate provisions a new certificate for a steward
func (s *CertificateProvisioningService) ProvisionCertificate(req *CertificateProvisioningRequest) (*CertificateProvisioningResponse, error) {
	if req == nil {
		return &CertificateProvisioningResponse{
			Success: false,
			Message: "Request cannot be nil",
		}, fmt.Errorf("provision request is required")
	}

	if req.StewardID == "" {
		return &CertificateProvisioningResponse{
			Success: false,
			Message: "Steward ID is required",
		}, fmt.Errorf("steward ID is required")
	}

	// Set defaults
	commonName := req.CommonName
	if commonName == "" {
		commonName = req.StewardID
	}

	organization := req.Organization
	if organization == "" {
		organization = s.defaultOrganization
	}

	validityDays := req.ValidityDays
	if validityDays <= 0 {
		validityDays = s.defaultValidityDays
	}

	// Create client certificate configuration
	clientConfig := &cert.ClientCertConfig{
		CommonName:         commonName,
		Organization:       organization,
		OrganizationalUnit: "Stewards",
		ValidityDays:       validityDays,
		KeySize:           2048,
		ClientID:          req.StewardID,
	}

	s.logger.Info("Provisioning certificate for steward",
		"steward_id", req.StewardID,
		"common_name", commonName,
		"organization", organization,
		"validity_days", validityDays)

	// Generate the certificate
	certificate, err := s.certManager.GenerateClientCertificate(clientConfig)
	if err != nil {
		s.logger.Error("Failed to generate certificate",
			"steward_id", req.StewardID,
			"common_name", commonName,
			"error", err)
		return &CertificateProvisioningResponse{
			Success: false,
			Message: fmt.Sprintf("Failed to generate certificate: %v", err),
		}, fmt.Errorf("failed to generate certificate: %w", err)
	}

	// Get CA certificate
	caCertPEM, err := s.certManager.GetCACertificate()
	if err != nil {
		s.logger.Error("Failed to get CA certificate",
			"steward_id", req.StewardID,
			"error", err)
		return &CertificateProvisioningResponse{
			Success: false,
			Message: fmt.Sprintf("Failed to get CA certificate: %v", err),
		}, fmt.Errorf("failed to get CA certificate: %w", err)
	}

	s.logger.Info("Certificate provisioned successfully",
		"steward_id", req.StewardID,
		"serial_number", certificate.SerialNumber,
		"expires_at", certificate.ExpiresAt)

	return &CertificateProvisioningResponse{
		Success:          true,
		Message:          "Certificate provisioned successfully",
		CertificatePEM:   certificate.CertificatePEM,
		PrivateKeyPEM:    certificate.PrivateKeyPEM,
		CACertificatePEM: caCertPEM,
		SerialNumber:     certificate.SerialNumber,
		ExpiresAt:        certificate.ExpiresAt,
	}, nil
}

// GetCertificateInfo retrieves certificate information by serial number
func (s *CertificateProvisioningService) GetCertificateInfo(serialNumber string) (*cert.CertificateInfo, error) {
	certificate, err := s.certManager.GetCertificate(serialNumber)
	if err != nil {
		return nil, fmt.Errorf("failed to get certificate: %w", err)
	}

	return &cert.CertificateInfo{
		Type:                certificate.Type,
		CommonName:          certificate.CommonName,
		SerialNumber:        certificate.SerialNumber,
		CreatedAt:           certificate.CreatedAt,
		ExpiresAt:           certificate.ExpiresAt,
		IsValid:             certificate.IsValid,
		Fingerprint:         certificate.Fingerprint,
		Issuer:              certificate.Issuer,
		ClientID:            certificate.ClientID,
		DaysUntilExpiration: int(time.Until(certificate.ExpiresAt).Hours() / 24),
		NeedsRenewal:        time.Until(certificate.ExpiresAt).Hours()/24 <= 30,
	}, nil
}

// ListCertificatesBySteward retrieves all certificates for a specific steward
func (s *CertificateProvisioningService) ListCertificatesBySteward(stewardID string) ([]*cert.CertificateInfo, error) {
	return s.certManager.GetCertificateByCommonName(stewardID)
}

// RevokeCertificate revokes a certificate (placeholder for future implementation)
func (s *CertificateProvisioningService) RevokeCertificate(serialNumber string, reason string) error {
	// Certificate revocation is not yet implemented in the underlying cert manager
	// This is a placeholder for future implementation
	return fmt.Errorf("certificate revocation not yet implemented")
}