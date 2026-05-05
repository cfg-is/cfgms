// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package cert

import (
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"time"
)

// Validator provides certificate validation operations
type Validator struct {
	// Optional CA certificate for chain validation
	caCert *x509.Certificate

	// Certificate pools for validation
	rootCAs         *x509.CertPool
	intermediateCAs *x509.CertPool
}

// NewValidator creates a new certificate validator
func NewValidator(caCert *x509.Certificate) *Validator {
	validator := &Validator{
		caCert:          caCert,
		rootCAs:         x509.NewCertPool(),
		intermediateCAs: x509.NewCertPool(),
	}

	// Add CA certificate to root pool if provided
	if caCert != nil {
		validator.rootCAs.AddCert(caCert)
	}

	return validator
}

// ValidateCertificate validates a single certificate
func (v *Validator) ValidateCertificate(cert *x509.Certificate) (*ValidationResult, error) {
	if cert == nil {
		return &ValidationResult{
			IsValid: false,
			Errors:  []string{"certificate is nil"},
		}, nil
	}

	result := &ValidationResult{
		IsValid:             true,
		Errors:              []string{},
		Warnings:            []string{},
		ChainDepth:          1,
		DaysUntilExpiration: int(time.Until(cert.NotAfter).Hours() / 24),
	}

	// Basic certificate validation
	if err := v.validateBasicConstraints(cert, result); err != nil {
		return result, err
	}

	// Check certificate warnings
	if err := v.checkCertificateWarnings(cert, 0, result); err != nil {
		return result, err
	}

	// If we have a CA certificate, verify signature
	if v.caCert != nil {
		if err := cert.CheckSignatureFrom(v.caCert); err != nil {
			result.IsValid = false
			result.Errors = append(result.Errors, fmt.Sprintf("signature verification failed: %v", err))
		}
	}

	return result, nil
}

// CheckExpiration checks if certificates are expiring
func (v *Validator) CheckExpiration(certs []*CertificateInfo, withinDays int) ([]*RenewalInfo, error) {
	if withinDays <= 0 {
		withinDays = 30 // Default to 30 days
	}

	cutoffDate := time.Now().Add(time.Duration(withinDays) * 24 * time.Hour)
	var renewalInfos []*RenewalInfo

	for _, cert := range certs {
		if cert.ExpiresAt.Before(cutoffDate) && cert.ExpiresAt.After(time.Now()) {
			daysUntilExpiration := int(time.Until(cert.ExpiresAt).Hours() / 24)

			// Determine priority based on expiration time
			priority := "low"
			isUrgent := false
			reason := fmt.Sprintf("Certificate expires in %d days", daysUntilExpiration)

			if daysUntilExpiration <= 7 {
				priority = "high"
				isUrgent = true
				reason = fmt.Sprintf("Certificate expires in %d days - URGENT", daysUntilExpiration)
			} else if daysUntilExpiration <= 15 {
				priority = "medium"
				reason = fmt.Sprintf("Certificate expires in %d days - soon", daysUntilExpiration)
			}

			// Recommend renewal at 2/3 of the remaining time
			renewalDays := int(float64(daysUntilExpiration) * 0.67)
			if renewalDays < 1 {
				renewalDays = 1
			}
			recommendedRenewalDate := time.Now().Add(time.Duration(renewalDays) * 24 * time.Hour)

			renewalInfos = append(renewalInfos, &RenewalInfo{
				Certificate:            cert,
				Reason:                 reason,
				Priority:               priority,
				RecommendedRenewalDate: recommendedRenewalDate,
				IsUrgent:               isUrgent,
			})
		}
	}

	return renewalInfos, nil
}

// validateBasicConstraints performs basic certificate validation
func (v *Validator) validateBasicConstraints(cert *x509.Certificate, result *ValidationResult) error {
	now := time.Now()

	// Check validity period
	if now.Before(cert.NotBefore) {
		result.IsValid = false
		result.Errors = append(result.Errors, "certificate is not yet valid")
	}

	if now.After(cert.NotAfter) {
		result.IsValid = false
		result.IsExpired = true
		result.Errors = append(result.Errors, "certificate has expired")
	}

	// Check key usage
	if cert.KeyUsage == 0 {
		result.Warnings = append(result.Warnings, "certificate has no key usage specified")
	}

	// Check basic constraints for CA certificates
	if cert.IsCA {
		if !cert.BasicConstraintsValid {
			result.Warnings = append(result.Warnings, "CA certificate has invalid basic constraints")
		}
	}

	// Check subject information
	if cert.Subject.CommonName == "" {
		result.Warnings = append(result.Warnings, "certificate has no common name")
	}

	// Check key size (for RSA keys)
	if cert.PublicKeyAlgorithm == x509.RSA {
		if rsaKey, ok := cert.PublicKey.(*rsa.PublicKey); ok && rsaKey.N.BitLen() < 2048 {
			result.Warnings = append(result.Warnings,
				fmt.Sprintf("RSA key size %d bits is below minimum recommended 2048 bits", rsaKey.N.BitLen()))
		}
	}

	return nil
}

// checkCertificateWarnings checks for potential issues that aren't fatal errors
func (v *Validator) checkCertificateWarnings(cert *x509.Certificate, position int, result *ValidationResult) error {
	// Check if certificate is expiring soon
	daysUntilExpiration := int(time.Until(cert.NotAfter).Hours() / 24)

	if daysUntilExpiration <= 30 && daysUntilExpiration > 0 {
		result.Warnings = append(result.Warnings,
			fmt.Sprintf("certificate expires in %d days", daysUntilExpiration))
	}

	if daysUntilExpiration <= 7 && daysUntilExpiration > 0 {
		result.Warnings = append(result.Warnings,
			fmt.Sprintf("certificate expires VERY SOON (%d days)", daysUntilExpiration))
	}

	// Check for weak signature algorithms
	switch cert.SignatureAlgorithm {
	case x509.MD5WithRSA, x509.SHA1WithRSA:
		result.Warnings = append(result.Warnings,
			fmt.Sprintf("certificate uses weak signature algorithm: %s", cert.SignatureAlgorithm))
	}

	// Check certificate position in chain
	if position == 0 && cert.IsCA {
		result.Warnings = append(result.Warnings,
			"leaf certificate is marked as CA - this may indicate a chain ordering issue")
	}

	if position > 0 && !cert.IsCA {
		result.Warnings = append(result.Warnings,
			"intermediate certificate is not marked as CA")
	}

	// Check subject alternative names for server certificates
	if !cert.IsCA && len(cert.DNSNames) == 0 && len(cert.IPAddresses) == 0 {
		result.Warnings = append(result.Warnings,
			"server certificate has no Subject Alternative Names")
	}

	return nil
}

// ValidateCertificateFile validates a certificate from PEM file data
func (v *Validator) ValidateCertificateFile(certPEM []byte) (*ValidationResult, error) {
	// Parse the certificate from PEM
	cert, err := ParseCertificateFromPEM(certPEM)
	if err != nil {
		return &ValidationResult{
			IsValid: false,
			Errors:  []string{fmt.Sprintf("failed to parse certificate: %v", err)},
		}, nil
	}

	return v.ValidateCertificate(cert)
}
