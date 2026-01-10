// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package cert

import (
	"fmt"
	"sort"
	"time"
)

// Renewer implements CertificateRenewer for certificate renewal operations
type Renewer struct {
	ca        CAManager
	store     CertificateStore
	validator CertificateValidator
}

// NewRenewer creates a new certificate renewer
func NewRenewer(ca CAManager, store CertificateStore, validator CertificateValidator) *Renewer {
	return &Renewer{
		ca:        ca,
		store:     store,
		validator: validator,
	}
}

// GetRenewalCandidates returns certificates that need renewal
func (r *Renewer) GetRenewalCandidates(withinDays int) ([]*RenewalInfo, error) {
	if withinDays <= 0 {
		withinDays = 30 // Default to 30 days
	}

	// Get all certificates from storage
	allCerts, err := r.store.ListCertificates()
	if err != nil {
		return nil, fmt.Errorf("failed to list certificates: %w", err)
	}

	// Use validator to check expiration
	renewalInfos, err := r.validator.CheckExpiration(allCerts, withinDays)
	if err != nil {
		return nil, fmt.Errorf("failed to check certificate expiration: %w", err)
	}

	// Sort by priority (urgent first, then by expiration date)
	sort.Slice(renewalInfos, func(i, j int) bool {
		// Urgent certificates first
		if renewalInfos[i].IsUrgent != renewalInfos[j].IsUrgent {
			return renewalInfos[i].IsUrgent
		}

		// Then by expiration date (soonest first)
		return renewalInfos[i].Certificate.ExpiresAt.Before(renewalInfos[j].Certificate.ExpiresAt)
	})

	return renewalInfos, nil
}

// RenewCertificate renews a certificate
func (r *Renewer) RenewCertificate(serialNumber string, config interface{}) (*Certificate, error) {
	if serialNumber == "" {
		return nil, fmt.Errorf("serial number is required")
	}

	// Get the existing certificate
	existingCert, err := r.store.GetCertificate(serialNumber)
	if err != nil {
		return nil, fmt.Errorf("failed to get existing certificate: %w", err)
	}

	// Generate new certificate based on the existing one's type and configuration
	var newCert *Certificate

	switch existingCert.Type {
	case CertificateTypeServer:
		serverConfig, ok := config.(*ServerCertConfig)
		if !ok {
			// Create default config based on existing certificate
			serverConfig = &ServerCertConfig{
				CommonName:   existingCert.CommonName,
				Organization: "CFGMS", // Default organization
				ValidityDays: 365,     // Default validity
				KeySize:      2048,    // Default key size
			}

			// Try to extract additional information from the existing certificate
			if existingCert.CertificatePEM != nil {
				if cert, err := ParseCertificateFromPEM(existingCert.CertificatePEM); err == nil {
					serverConfig.DNSNames = cert.DNSNames
					for _, ip := range cert.IPAddresses {
						serverConfig.IPAddresses = append(serverConfig.IPAddresses, ip.String())
					}
					if len(cert.Subject.Organization) > 0 {
						serverConfig.Organization = cert.Subject.Organization[0]
					}
				}
			}
		}

		newCert, err = r.ca.GenerateServerCertificate(serverConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to generate new server certificate: %w", err)
		}

	case CertificateTypeClient:
		clientConfig, ok := config.(*ClientCertConfig)
		if !ok {
			// Create default config based on existing certificate
			clientConfig = &ClientCertConfig{
				CommonName:   existingCert.CommonName,
				Organization: "CFGMS", // Default organization
				ValidityDays: 365,     // Default validity
				KeySize:      2048,    // Default key size
				ClientID:     existingCert.ClientID,
			}

			// Try to extract additional information from the existing certificate
			if existingCert.CertificatePEM != nil {
				if cert, err := ParseCertificateFromPEM(existingCert.CertificatePEM); err == nil {
					if len(cert.Subject.Organization) > 0 {
						clientConfig.Organization = cert.Subject.Organization[0]
					}
					if len(cert.Subject.OrganizationalUnit) > 0 {
						clientConfig.OrganizationalUnit = cert.Subject.OrganizationalUnit[0]
					}
				}
			}
		}

		newCert, err = r.ca.GenerateClientCertificate(clientConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to generate new client certificate: %w", err)
		}

	case CertificateTypeCA:
		return nil, fmt.Errorf("CA certificate renewal is not supported through this method")

	default:
		return nil, fmt.Errorf("unsupported certificate type: %s", existingCert.Type.String())
	}

	// Store the new certificate
	if err := r.store.StoreCertificate(newCert); err != nil {
		return nil, fmt.Errorf("failed to store new certificate: %w", err)
	}

	// Note: We don't automatically delete the old certificate to maintain history
	// The caller can decide whether to delete or mark the old certificate as superseded

	return newCert, nil
}

// AutoRenewCertificates automatically renews expiring certificates
func (r *Renewer) AutoRenewCertificates(withinDays int) ([]*Certificate, error) {
	if withinDays <= 0 {
		withinDays = 30 // Default to 30 days
	}

	// Get renewal candidates
	renewalCandidates, err := r.GetRenewalCandidates(withinDays)
	if err != nil {
		return nil, fmt.Errorf("failed to get renewal candidates: %w", err)
	}

	var renewedCerts []*Certificate
	var failures []string

	for _, candidate := range renewalCandidates {
		// Skip CA certificates for auto-renewal
		if candidate.Certificate.Type == CertificateTypeCA {
			continue
		}

		// Attempt to renew the certificate
		newCert, err := r.RenewCertificate(candidate.Certificate.SerialNumber, nil)
		if err != nil {
			failures = append(failures, fmt.Sprintf("Failed to renew certificate %s (%s): %v",
				candidate.Certificate.SerialNumber, candidate.Certificate.CommonName, err))
			continue
		}

		renewedCerts = append(renewedCerts, newCert)
	}

	// If there were failures, include them in the error
	if len(failures) > 0 {
		return renewedCerts, fmt.Errorf("some certificates failed to renew: %v", failures)
	}

	return renewedCerts, nil
}

// ScheduleRenewal schedules automatic renewal for a certificate
func (r *Renewer) ScheduleRenewal(serialNumber string, renewalDate time.Time) error {
	// This is a placeholder implementation
	// In a real system, this would integrate with a job scheduler or cron system

	if serialNumber == "" {
		return fmt.Errorf("serial number is required")
	}

	if renewalDate.Before(time.Now()) {
		return fmt.Errorf("renewal date cannot be in the past")
	}

	// Verify the certificate exists
	_, err := r.store.GetCertificate(serialNumber)
	if err != nil {
		return fmt.Errorf("certificate not found: %w", err)
	}

	// TODO: Implement actual scheduling mechanism
	// This could involve:
	// - Adding to a database table with renewal schedules
	// - Creating cron jobs
	// - Adding to a job queue system
	// - Integrating with Kubernetes CronJobs

	return fmt.Errorf("automatic renewal scheduling not yet implemented")
}

// GetRenewalSchedule returns the renewal schedule for a certificate
func (r *Renewer) GetRenewalSchedule(serialNumber string) (time.Time, error) {
	if serialNumber == "" {
		return time.Time{}, fmt.Errorf("serial number is required")
	}

	// TODO: Implement actual schedule retrieval
	// This would query the scheduling system for the renewal date

	return time.Time{}, fmt.Errorf("renewal schedule retrieval not yet implemented")
}

// CancelRenewalSchedule cancels a scheduled renewal
func (r *Renewer) CancelRenewalSchedule(serialNumber string) error {
	if serialNumber == "" {
		return fmt.Errorf("serial number is required")
	}

	// TODO: Implement actual schedule cancellation
	// This would remove the certificate from the scheduling system

	return fmt.Errorf("renewal schedule cancellation not yet implemented")
}

// RenewServerCertificate is a convenience method for renewing server certificates
func (r *Renewer) RenewServerCertificate(serialNumber string, config *ServerCertConfig) (*Certificate, error) {
	return r.RenewCertificate(serialNumber, config)
}

// RenewClientCertificate is a convenience method for renewing client certificates
func (r *Renewer) RenewClientCertificate(serialNumber string, config *ClientCertConfig) (*Certificate, error) {
	return r.RenewCertificate(serialNumber, config)
}

// GetCertificatesByExpirationPriority returns certificates grouped by renewal priority
func (r *Renewer) GetCertificatesByExpirationPriority(withinDays int) (map[string][]*CertificateInfo, error) {
	renewalCandidates, err := r.GetRenewalCandidates(withinDays)
	if err != nil {
		return nil, err
	}

	priorityGroups := map[string][]*CertificateInfo{
		"high":   {},
		"medium": {},
		"low":    {},
	}

	for _, candidate := range renewalCandidates {
		priorityGroups[candidate.Priority] = append(priorityGroups[candidate.Priority], candidate.Certificate)
	}

	return priorityGroups, nil
}

// ValidateRenewalConfig validates renewal configuration for a certificate type
func (r *Renewer) ValidateRenewalConfig(certType CertificateType, config interface{}) error {
	switch certType {
	case CertificateTypeServer:
		if config == nil {
			return nil // Default config will be used
		}

		serverConfig, ok := config.(*ServerCertConfig)
		if !ok {
			return fmt.Errorf("expected ServerCertConfig for server certificate renewal")
		}

		if serverConfig.CommonName == "" {
			return fmt.Errorf("common name is required for server certificate")
		}

		if serverConfig.ValidityDays <= 0 {
			return fmt.Errorf("validity days must be positive")
		}

		if serverConfig.KeySize != 0 && serverConfig.KeySize < 2048 {
			return fmt.Errorf("key size must be at least 2048 bits")
		}

	case CertificateTypeClient:
		if config == nil {
			return nil // Default config will be used
		}

		clientConfig, ok := config.(*ClientCertConfig)
		if !ok {
			return fmt.Errorf("expected ClientCertConfig for client certificate renewal")
		}

		if clientConfig.CommonName == "" {
			return fmt.Errorf("common name is required for client certificate")
		}

		if clientConfig.ValidityDays <= 0 {
			return fmt.Errorf("validity days must be positive")
		}

		if clientConfig.KeySize != 0 && clientConfig.KeySize < 2048 {
			return fmt.Errorf("key size must be at least 2048 bits")
		}

	case CertificateTypeCA:
		return fmt.Errorf("CA certificate renewal is not supported")

	default:
		return fmt.Errorf("unsupported certificate type: %s", certType.String())
	}

	return nil
}
