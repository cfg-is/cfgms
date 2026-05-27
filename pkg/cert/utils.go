// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package cert

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"time"
)

// ParseCertificateFromPEM parses a single certificate from PEM data
func ParseCertificateFromPEM(certPEM []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	if block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("expected CERTIFICATE, got %s", block.Type)
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	return cert, nil
}

// ParseCertificateChainFromPEM parses multiple certificates from PEM data
func ParseCertificateChainFromPEM(certChainPEM []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate

	remaining := certChainPEM
	for {
		block, rest := pem.Decode(remaining)
		if block == nil {
			break
		}

		if block.Type != "CERTIFICATE" {
			remaining = rest
			continue
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse certificate in chain: %w", err)
		}

		certs = append(certs, cert)
		remaining = rest
	}

	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificates found in PEM data")
	}

	return certs, nil
}

// ParsePrivateKeyFromPEM parses a private key from PEM data
func ParsePrivateKeyFromPEM(keyPEM []byte) (interface{}, error) {
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	switch block.Type {
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	case "PRIVATE KEY":
		return x509.ParsePKCS8PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(block.Bytes)
	default:
		return nil, fmt.Errorf("unsupported private key type: %s", block.Type)
	}
}

// ValidateKeyPair validates that a certificate and private key match
func ValidateKeyPair(certPEM, keyPEM []byte) error {
	// Parse certificate
	cert, err := ParseCertificateFromPEM(certPEM)
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %w", err)
	}

	// Parse private key
	privateKey, err := ParsePrivateKeyFromPEM(keyPEM)
	if err != nil {
		return fmt.Errorf("failed to parse private key: %w", err)
	}

	// Check if the public key in the certificate matches the private key
	switch privKey := privateKey.(type) {
	case *rsa.PrivateKey:
		pubKey, ok := cert.PublicKey.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("certificate public key is not RSA")
		}
		if privKey.N.Cmp(pubKey.N) != 0 || privKey.E != pubKey.E {
			return fmt.Errorf("private key does not match certificate public key")
		}
	default:
		return fmt.Errorf("unsupported private key type for validation")
	}

	return nil
}

// SaveCertificateToFile saves a certificate to a file in PEM format
func SaveCertificateToFile(cert *Certificate, certPath, keyPath string) error {
	// Save certificate
	if err := os.WriteFile(certPath, cert.CertificatePEM, 0600); err != nil {
		return fmt.Errorf("failed to write certificate file: %w", err)
	}

	// Save private key (if available)
	if cert.PrivateKeyPEM != nil && keyPath != "" {
		if err := os.WriteFile(keyPath, cert.PrivateKeyPEM, 0600); err != nil {
			return fmt.Errorf("failed to write private key file: %w", err)
		}
	}

	return nil
}

// IsCertificateExpired checks if a certificate has expired
func IsCertificateExpired(cert *x509.Certificate) bool {
	if cert == nil {
		return true
	}

	return time.Now().After(cert.NotAfter)
}
