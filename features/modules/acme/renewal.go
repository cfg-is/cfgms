// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package acme

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math"
	"time"
)

// RenewalDecision represents what action to take for a certificate
type RenewalDecision int

const (
	// DecisionNone means the certificate is valid and no action is needed
	DecisionNone RenewalDecision = iota
	// DecisionObtain means a new certificate needs to be obtained
	DecisionObtain
	// DecisionRenew means the existing certificate should be renewed
	DecisionRenew
	// DecisionRemove means the certificate should be removed (state=absent)
	DecisionRemove
)

// String returns a human-readable representation of the decision
func (d RenewalDecision) String() string {
	switch d {
	case DecisionNone:
		return "none"
	case DecisionObtain:
		return "obtain"
	case DecisionRenew:
		return "renew"
	case DecisionRemove:
		return "remove"
	default:
		return "unknown"
	}
}

// DetermineAction decides what action to take based on the desired config and
// the current certificate state. This is a pure function with no side effects,
// making it trivially testable without any ACME server.
func DetermineAction(config *ACMEConfig, certPEM []byte) (RenewalDecision, error) {
	if config == nil {
		return DecisionNone, fmt.Errorf("config cannot be nil")
	}

	// State "absent" means remove any existing certificate
	if config.State == "absent" {
		return DecisionRemove, nil
	}

	// No certificate exists — need to obtain one
	if len(certPEM) == 0 {
		return DecisionObtain, nil
	}

	// Parse the existing certificate
	cert, err := parseCertificatePEM(certPEM)
	if err != nil {
		// Certificate is corrupted — re-obtain
		return DecisionObtain, nil
	}

	// Check if the certificate has expired
	now := time.Now()
	if now.After(cert.NotAfter) {
		return DecisionObtain, nil
	}

	// Check if the domains match
	if !domainsMatch(config.Domains, cert) {
		return DecisionObtain, nil
	}

	// Check if within renewal threshold
	daysUntilExpiry := int(math.Ceil(cert.NotAfter.Sub(now).Hours() / 24))
	if daysUntilExpiry <= config.RenewalThresholdDays {
		return DecisionRenew, nil
	}

	// Certificate is valid and not within renewal window
	return DecisionNone, nil
}

// parseCertificatePEM parses the first certificate from PEM-encoded data
func parseCertificatePEM(certPEM []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}
	return x509.ParseCertificate(block.Bytes)
}

// domainsMatch checks if the certificate covers all requested domains
func domainsMatch(requestedDomains []string, cert *x509.Certificate) bool {
	certDomains := make(map[string]bool)
	certDomains[cert.Subject.CommonName] = true
	for _, san := range cert.DNSNames {
		certDomains[san] = true
	}

	for _, requested := range requestedDomains {
		if !certDomains[requested] {
			return false
		}
	}
	return true
}
