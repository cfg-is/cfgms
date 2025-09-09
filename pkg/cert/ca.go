package cert

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

// CA represents a Certificate Authority with its certificate and private key
type CA struct {
	certificate *x509.Certificate
	privateKey  *rsa.PrivateKey
	config      *CAConfig
	initialized bool
}

// NewCA creates a new Certificate Authority manager
func NewCA(config *CAConfig) (*CA, error) {
	if config == nil {
		return nil, fmt.Errorf("CA config is required")
	}
	
	// Set defaults
	if config.KeySize == 0 {
		config.KeySize = 2048
	}
	if config.ValidityDays == 0 {
		config.ValidityDays = 3650 // 10 years default for CA
	}
	if config.Organization == "" {
		config.Organization = "CFGMS"
	}
	if config.Country == "" {
		config.Country = "US"
	}
	
	return &CA{
		config: config,
	}, nil
}

// Initialize creates a new Certificate Authority with the given configuration
func (ca *CA) Initialize(config *CAConfig) error {
	if config != nil {
		ca.config = config
	}
	
	if ca.config == nil {
		return fmt.Errorf("CA configuration is required")
	}
	
	// Generate CA private key
	privateKey, err := rsa.GenerateKey(rand.Reader, ca.config.KeySize)
	if err != nil {
		return fmt.Errorf("failed to generate CA private key: %w", err)
	}
	
	// Create CA certificate template
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization:       []string{ca.config.Organization},
			Country:            []string{ca.config.Country},
			Province:           []string{ca.config.State},
			Locality:           []string{ca.config.City},
			OrganizationalUnit: []string{ca.config.OrganizationalUnit},
			CommonName:         fmt.Sprintf("%s Root CA", ca.config.Organization),
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Duration(ca.config.ValidityDays) * 24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}
	
	// Create the CA certificate
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return fmt.Errorf("failed to create CA certificate: %w", err)
	}
	
	// Parse the created certificate
	caCert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return fmt.Errorf("failed to parse CA certificate: %w", err)
	}
	
	ca.certificate = caCert
	ca.privateKey = privateKey
	ca.initialized = true
	
	// Save CA to storage if path is specified
	if ca.config.StoragePath != "" {
		if err := ca.saveToStorage(); err != nil {
			return fmt.Errorf("failed to save CA to storage: %w", err)
		}
	}
	
	return nil
}

// LoadCA loads an existing Certificate Authority from storage
func (ca *CA) LoadCA(storagePath string) error {
	ca.config = &CAConfig{
		StoragePath: storagePath,
	}
	
	// Load CA certificate
	caCertPath := filepath.Join(storagePath, "ca.crt")
	// #nosec G304 - CA management requires loading CA certificate files from controlled paths
	caCertPEM, err := os.ReadFile(caCertPath)
	if err != nil {
		return fmt.Errorf("failed to read CA certificate: %w", err)
	}
	
	block, _ := pem.Decode(caCertPEM)
	if block == nil {
		return fmt.Errorf("failed to decode CA certificate PEM")
	}
	
	caCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse CA certificate: %w", err)
	}
	
	// Load CA private key
	caKeyPath := filepath.Join(storagePath, "ca.key")
	// #nosec G304 - CA management requires loading CA private key files from controlled paths
	caKeyPEM, err := os.ReadFile(caKeyPath)
	if err != nil {
		return fmt.Errorf("failed to read CA private key: %w", err)
	}
	
	keyBlock, _ := pem.Decode(caKeyPEM)
	if keyBlock == nil {
		return fmt.Errorf("failed to decode CA private key PEM")
	}
	
	caKey, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse CA private key: %w", err)
	}
	
	ca.certificate = caCert
	ca.privateKey = caKey
	ca.initialized = true
	
	return nil
}

// GetCACertificate returns the CA certificate in PEM format
func (ca *CA) GetCACertificate() ([]byte, error) {
	if !ca.initialized {
		return nil, fmt.Errorf("CA is not initialized")
	}
	
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: ca.certificate.Raw,
	})
	
	return certPEM, nil
}

// IsInitialized returns true if the CA is initialized
func (ca *CA) IsInitialized() bool {
	return ca.initialized
}

// GetCAInfo returns information about the CA
func (ca *CA) GetCAInfo() (*CertificateInfo, error) {
	if !ca.initialized {
		return nil, fmt.Errorf("CA is not initialized")
	}
	
	fingerprint := ca.calculateFingerprint(ca.certificate.Raw)
	daysUntilExpiration := int(time.Until(ca.certificate.NotAfter).Hours() / 24)
	
	return &CertificateInfo{
		Type:                CertificateTypeCA,
		CommonName:          ca.certificate.Subject.CommonName,
		SerialNumber:        ca.certificate.SerialNumber.String(),
		CreatedAt:           ca.certificate.NotBefore,
		ExpiresAt:           ca.certificate.NotAfter,
		IsValid:             time.Now().Before(ca.certificate.NotAfter),
		Fingerprint:         fingerprint,
		Issuer:              ca.certificate.Issuer.CommonName,
		DaysUntilExpiration: daysUntilExpiration,
		NeedsRenewal:        daysUntilExpiration < 30, // Renew 30 days before expiration
	}, nil
}

// GenerateServerCertificate creates a new server certificate signed by this CA
func (ca *CA) GenerateServerCertificate(config *ServerCertConfig) (*Certificate, error) {
	if !ca.initialized {
		return nil, fmt.Errorf("CA is not initialized")
	}
	
	if config == nil {
		return nil, fmt.Errorf("server certificate config is required")
	}
	
	// Set defaults
	if config.KeySize == 0 {
		config.KeySize = 2048
	}
	if config.ValidityDays == 0 {
		config.ValidityDays = 365
	}
	if config.Organization == "" {
		config.Organization = ca.config.Organization
	}
	
	// Generate server private key
	privateKey, err := rsa.GenerateKey(rand.Reader, config.KeySize)
	if err != nil {
		return nil, fmt.Errorf("failed to generate server private key: %w", err)
	}
	
	// Generate serial number
	serialNumber, err := ca.generateSerialNumber()
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %w", err)
	}
	
	// Parse IP addresses
	var ipAddresses []net.IP
	for _, ipStr := range config.IPAddresses {
		if ip := net.ParseIP(ipStr); ip != nil {
			ipAddresses = append(ipAddresses, ip)
		}
	}
	
	// Add localhost IP if not present
	hasLocalhost := false
	for _, ip := range ipAddresses {
		if ip.Equal(net.IPv4(127, 0, 0, 1)) || ip.Equal(net.IPv6loopback) {
			hasLocalhost = true
			break
		}
	}
	if !hasLocalhost {
		ipAddresses = append(ipAddresses, net.IPv4(127, 0, 0, 1))
	}
	
	// Create server certificate template
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{config.Organization},
			CommonName:   config.CommonName,
		},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Duration(config.ValidityDays) * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  ipAddresses,
		DNSNames:     config.DNSNames,
	}
	
	// Create the server certificate
	certDER, err := x509.CreateCertificate(rand.Reader, template, ca.certificate, &privateKey.PublicKey, ca.privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create server certificate: %w", err)
	}
	
	// Encode certificate and key to PEM
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})
	
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})
	
	fingerprint := ca.calculateFingerprint(certDER)
	
	return &Certificate{
		Type:           CertificateTypeServer,
		CommonName:     config.CommonName,
		SerialNumber:   serialNumber.String(),
		CreatedAt:      template.NotBefore,
		ExpiresAt:      template.NotAfter,
		IsValid:        true,
		CertificatePEM: certPEM,
		PrivateKeyPEM:  keyPEM,
		Fingerprint:    fingerprint,
		Issuer:         ca.certificate.Subject.CommonName,
	}, nil
}

// GenerateClientCertificate creates a new client certificate signed by this CA
func (ca *CA) GenerateClientCertificate(config *ClientCertConfig) (*Certificate, error) {
	if !ca.initialized {
		return nil, fmt.Errorf("CA is not initialized")
	}
	
	if config == nil {
		return nil, fmt.Errorf("client certificate config is required")
	}
	
	// Set defaults
	if config.KeySize == 0 {
		config.KeySize = 2048
	}
	if config.ValidityDays == 0 {
		config.ValidityDays = 365
	}
	if config.Organization == "" {
		config.Organization = ca.config.Organization
	}
	
	// Generate client private key
	privateKey, err := rsa.GenerateKey(rand.Reader, config.KeySize)
	if err != nil {
		return nil, fmt.Errorf("failed to generate client private key: %w", err)
	}
	
	// Generate serial number
	serialNumber, err := ca.generateSerialNumber()
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %w", err)
	}
	
	// Create client certificate template
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization:       []string{config.Organization},
			OrganizationalUnit: []string{config.OrganizationalUnit},
			CommonName:         config.CommonName,
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(time.Duration(config.ValidityDays) * 24 * time.Hour),
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	
	// Create the client certificate
	certDER, err := x509.CreateCertificate(rand.Reader, template, ca.certificate, &privateKey.PublicKey, ca.privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create client certificate: %w", err)
	}
	
	// Encode certificate and key to PEM
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})
	
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})
	
	fingerprint := ca.calculateFingerprint(certDER)
	
	return &Certificate{
		Type:           CertificateTypeClient,
		CommonName:     config.CommonName,
		SerialNumber:   serialNumber.String(),
		CreatedAt:      template.NotBefore,
		ExpiresAt:      template.NotAfter,
		IsValid:        true,
		CertificatePEM: certPEM,
		PrivateKeyPEM:  keyPEM,
		Fingerprint:    fingerprint,
		Issuer:         ca.certificate.Subject.CommonName,
		ClientID:       config.ClientID,
	}, nil
}

// ValidateCertificate validates a certificate against this CA
func (ca *CA) ValidateCertificate(certPEM []byte) (*ValidationResult, error) {
	if !ca.initialized {
		return nil, fmt.Errorf("CA is not initialized")
	}
	
	// Decode the certificate
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return &ValidationResult{
			IsValid: false,
			Errors:  []string{"failed to decode certificate PEM"},
		}, nil
	}
	
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return &ValidationResult{
			IsValid: false,
			Errors:  []string{fmt.Sprintf("failed to parse certificate: %v", err)},
		}, nil
	}
	
	result := &ValidationResult{
		IsValid:             true,
		Errors:              []string{},
		Warnings:            []string{},
		ChainDepth:          1,
		DaysUntilExpiration: int(time.Until(cert.NotAfter).Hours() / 24),
	}
	
	// Check if certificate is expired
	now := time.Now()
	if now.After(cert.NotAfter) {
		result.IsValid = false
		result.IsExpired = true
		result.Errors = append(result.Errors, "certificate is expired")
	}
	
	if now.Before(cert.NotBefore) {
		result.IsValid = false
		result.Errors = append(result.Errors, "certificate is not yet valid")
	}
	
	// Verify certificate was signed by this CA
	err = cert.CheckSignatureFrom(ca.certificate)
	if err != nil {
		result.IsValid = false
		result.Errors = append(result.Errors, fmt.Sprintf("certificate signature verification failed: %v", err))
	}
	
	// Check if certificate is expiring soon (within 30 days)
	if result.DaysUntilExpiration <= 30 && result.DaysUntilExpiration > 0 {
		result.Warnings = append(result.Warnings, fmt.Sprintf("certificate expires in %d days", result.DaysUntilExpiration))
	}
	
	return result, nil
}

// RevokeCertificate revokes a certificate (implementation for future CRL support)
func (ca *CA) RevokeCertificate(serialNumber string, reason string) error {
	// TODO: Implement certificate revocation list (CRL) support
	return fmt.Errorf("certificate revocation not yet implemented")
}

// GetRevokedCertificates returns the list of revoked certificates
func (ca *CA) GetRevokedCertificates() ([]string, error) {
	// TODO: Implement certificate revocation list (CRL) support
	return []string{}, nil
}

// saveToStorage saves the CA certificate and private key to storage
func (ca *CA) saveToStorage() error {
	if ca.config.StoragePath == "" {
		return fmt.Errorf("storage path not configured")
	}
	
	// Create storage directory
	if err := os.MkdirAll(ca.config.StoragePath, 0750); err != nil {
		return fmt.Errorf("failed to create storage directory: %w", err)
	}
	
	// Save CA certificate
	caCertPath := filepath.Join(ca.config.StoragePath, "ca.crt")
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: ca.certificate.Raw,
	})
	
	if err := os.WriteFile(caCertPath, certPEM, 0600); err != nil {
		return fmt.Errorf("failed to write CA certificate: %w", err)
	}
	
	// Save CA private key (with restricted permissions)
	caKeyPath := filepath.Join(ca.config.StoragePath, "ca.key")
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(ca.privateKey),
	})
	
	if err := os.WriteFile(caKeyPath, keyPEM, 0600); err != nil {
		return fmt.Errorf("failed to write CA private key: %w", err)
	}
	
	return nil
}

// generateSerialNumber generates a unique serial number for certificates
func (ca *CA) generateSerialNumber() (*big.Int, error) {
	// Generate a random 128-bit number
	max := new(big.Int)
	max.Exp(big.NewInt(2), big.NewInt(128), nil).Sub(max, big.NewInt(1))
	
	serialNumber, err := rand.Int(rand.Reader, max)
	if err != nil {
		return nil, err
	}
	
	return serialNumber, nil
}

// calculateFingerprint calculates the SHA256 fingerprint of certificate data
func (ca *CA) calculateFingerprint(certDER []byte) string {
	hash := sha256.Sum256(certDER)
	return hex.EncodeToString(hash[:])
}