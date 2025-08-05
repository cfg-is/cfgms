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

// GetCertificateFingerprint calculates the SHA256 fingerprint of a certificate
func GetCertificateFingerprint(cert *x509.Certificate) string {
	if cert == nil {
		return ""
	}
	
	// The fingerprint calculation is already implemented in ca.go
	// We'll reuse that logic here by creating a temporary CA instance
	ca := &CA{}
	return ca.calculateFingerprint(cert.Raw)
}

// GetCertificateInfo extracts basic information from a certificate
func GetCertificateInfo(cert *x509.Certificate) *CertificateInfo {
	if cert == nil {
		return nil
	}
	
	certType := CertificateTypeClient
	if cert.IsCA {
		certType = CertificateTypeCA
	} else {
		// Check if it's a server certificate by looking at extended key usage
		for _, usage := range cert.ExtKeyUsage {
			if usage == x509.ExtKeyUsageServerAuth {
				certType = CertificateTypeServer
				break
			}
		}
	}
	
	daysUntilExpiration := int(cert.NotAfter.Sub(cert.NotBefore).Hours() / 24)
	if cert.NotAfter.Before(cert.NotBefore) {
		daysUntilExpiration = 0
	}
	
	return &CertificateInfo{
		Type:                certType,
		CommonName:          cert.Subject.CommonName,
		SerialNumber:        cert.SerialNumber.String(),
		CreatedAt:           cert.NotBefore,
		ExpiresAt:           cert.NotAfter,
		IsValid:             cert.NotBefore.Before(cert.NotAfter),
		Fingerprint:         GetCertificateFingerprint(cert),
		Issuer:              cert.Issuer.CommonName,
		DaysUntilExpiration: daysUntilExpiration,
		NeedsRenewal:        daysUntilExpiration < 30,
	}
}

// LoadCertificateFromFile loads a certificate from a file
func LoadCertificateFromFile(filename string) (*x509.Certificate, error) {
	certPEM, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read certificate file: %w", err)
	}
	
	return ParseCertificateFromPEM(certPEM)
}

// LoadCertificateChainFromFile loads a certificate chain from a file
func LoadCertificateChainFromFile(filename string) ([]*x509.Certificate, error) {
	certChainPEM, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read certificate chain file: %w", err)
	}
	
	return ParseCertificateChainFromPEM(certChainPEM)
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

// IsCertificateExpiring checks if a certificate is expiring within the specified days
func IsCertificateExpiring(cert *x509.Certificate, withinDays int) bool {
	if cert == nil {
		return false
	}
	
	expirationThreshold := time.Now().Add(time.Duration(withinDays) * 24 * time.Hour)
	return cert.NotAfter.Before(expirationThreshold) && cert.NotAfter.After(time.Now())
}

// IsCertificateExpired checks if a certificate has expired
func IsCertificateExpired(cert *x509.Certificate) bool {
	if cert == nil {
		return true
	}
	
	return time.Now().After(cert.NotAfter)
}

// FormatCertificateInfo returns a human-readable string representation of certificate info
func FormatCertificateInfo(info *CertificateInfo) string {
	if info == nil {
		return "No certificate information"
	}
	
	status := "Valid"
	if !info.IsValid {
		status = "Invalid"
	} else if info.DaysUntilExpiration <= 0 {
		status = "Expired"
	} else if info.NeedsRenewal {
		status = "Expiring Soon"
	}
	
	return fmt.Sprintf(
		"Type: %s, CN: %s, Serial: %s, Status: %s, Expires: %s (%d days)",
		info.Type.String(),
		info.CommonName,
		info.SerialNumber,
		status,
		info.ExpiresAt.Format("2006-01-02"),
		info.DaysUntilExpiration,
	)
}