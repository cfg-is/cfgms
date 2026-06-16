// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package cert

import (
	"fmt"
	"sort"
)

// Renewer provides certificate renewal operations
type Renewer struct {
	ca        *CA
	store     *FileStore
	validator *Validator
}

// NewRenewer creates a new certificate renewer
func NewRenewer(ca *CA, store *FileStore, validator *Validator) *Renewer {
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
	case CertificateTypePublicAPI:
		serverConfig, ok := config.(*ServerCertConfig)
		if !ok {
			serverConfig = &ServerCertConfig{
				CommonName:   existingCert.CommonName,
				Organization: "CFGMS",
				ValidityDays: 365,
				KeySize:      2048,
			}

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
			return nil, fmt.Errorf("failed to generate new public API certificate: %w", err)
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

	case CertificateTypeInternalServer:
		serverConfig, ok := config.(*ServerCertConfig)
		if !ok {
			serverConfig = &ServerCertConfig{
				CommonName:   existingCert.CommonName,
				Organization: "CFGMS",
				ValidityDays: 365,
				KeySize:      2048,
			}

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

		newCert, err = r.ca.GenerateInternalServerCertificate(serverConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to generate new internal server certificate: %w", err)
		}

	case CertificateTypeConfigSigning:
		signingConfig, ok := config.(*SigningCertConfig)
		if !ok {
			signingConfig = &SigningCertConfig{
				CommonName:   existingCert.CommonName,
				Organization: "CFGMS",
				ValidityDays: 1095,
				KeySize:      4096,
			}

			if existingCert.CertificatePEM != nil {
				if cert, err := ParseCertificateFromPEM(existingCert.CertificatePEM); err == nil {
					if len(cert.Subject.Organization) > 0 {
						signingConfig.Organization = cert.Subject.Organization[0]
					}
				}
			}
		}

		newCert, err = r.ca.GenerateSigningCertificate(signingConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to generate new signing certificate: %w", err)
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
