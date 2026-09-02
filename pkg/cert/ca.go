// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package cert

import (
	"bytes"
	"context"
	"crypto"
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

	secretsinterfaces "github.com/cfgis/cfgms/pkg/secrets/interfaces"
)

// CA represents a Certificate Authority with its certificate and private key
type CA struct {
	certificate *x509.Certificate
	privateKey  *rsa.PrivateKey
	config      *CAConfig
	initialized bool

	// issuerChainPEM is the PEM-concatenated chain from this CA's own issuer up to
	// and including the ultimate trust root, ordered nearest-issuer-first / root-
	// last — so its terminal (last) entry is always the root. Empty when this CA is
	// itself the root (self-signed) CA, which is true for every CA today: nothing
	// populates this field before S3's ImportSubordinateCA. Settable at load/init
	// time by a caller that loads this CA as a previously-signed subordinate.
	issuerChainPEM []byte
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

	// Path-length constraint: an explicit PathLengthSet honors the caller's
	// PathLength (validated 0-6); otherwise preserve today's leaf-only
	// default (MaxPathLen: 0, MaxPathLenZero: true) exactly, since
	// PathLength's zero value is itself a valid "leaf-only" setting distinct
	// from "not set".
	maxPathLen := 0
	maxPathLenZero := true
	if ca.config.PathLengthSet {
		if ca.config.PathLength < 0 || ca.config.PathLength > 6 {
			return fmt.Errorf("CA path length must be between 0 and 6, got %d", ca.config.PathLength)
		}
		maxPathLen = ca.config.PathLength
		maxPathLenZero = ca.config.PathLength == 0
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
		MaxPathLen:            maxPathLen,
		MaxPathLenZero:        maxPathLenZero,
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

	parsedKey, err := ParsePrivateKeyFromPEM(caKeyPEM)
	if err != nil {
		return fmt.Errorf("failed to parse CA private key: %w", err)
	}

	rsaKey, ok := parsedKey.(*rsa.PrivateKey)
	if !ok {
		return fmt.Errorf("CA private key must be RSA, got unsupported key type")
	}

	if err := ValidateKeyPair(caCertPEM, caKeyPEM); err != nil {
		return fmt.Errorf("CA key does not match certificate: %w", err)
	}

	ca.certificate = caCert
	ca.privateKey = rsaKey
	ca.initialized = true

	return nil
}

// GetCACertificate returns the PEM-encoded trust anchor a caller should treat as
// permanent — for a self-signed root this is the CA's own certificate; for an
// imported regional intermediate (see ImportSubordinateCA) this is the true
// offline root, never the intermediate's own currently-active certificate.
func (ca *CA) GetCACertificate() ([]byte, error) {
	if !ca.initialized {
		return nil, fmt.Errorf("CA is not initialized")
	}

	if len(ca.issuerChainPEM) == 0 {
		return ca.ownCertificatePEM(), nil
	}

	parents, err := ParseCertificateChainFromPEM(ca.issuerChainPEM)
	if err != nil || len(parents) == 0 {
		return nil, fmt.Errorf("failed to parse issuer chain to locate trust root: %w", err)
	}

	// Defense in depth for the fleet-wide, permanently-pinned value this returns:
	// the terminal entry is only the trust root if it is actually self-signed. A
	// chain handed over in the conventional root-FIRST bundle order would
	// otherwise silently publish an intermediate as the fleet's permanent anchor.
	// Callers entering the trust boundary are validated in full by
	// validateIssuerChain; this re-check covers *CA values assembled by any other
	// path inside the package, and fails closed rather than returning the wrong
	// anchor.
	root := parents[len(parents)-1]
	if err := verifySelfSigned(root); err != nil {
		return nil, fmt.Errorf("terminal issuer chain entry is not a self-signed root, so no trust anchor can be determined "+
			"(the chain must be ordered nearest-issuer-first with the root last): %w", err)
	}

	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: root.Raw,
	}), nil
}

// validateIssuerChain verifies that issuerChainPEM is a usable issuer chain for
// caCert before any of it is allowed to become a trust anchor. The chain is
// ordered nearest-issuer-first / root-last, so a valid chain satisfies all of:
//
//  1. its first entry actually issued caCert,
//  2. every entry is signed by its successor (the chain links, with no gaps),
//  3. its terminal entry is a self-signed root.
//
// An empty chain declares caCert itself to be the trust anchor, which is only
// true when caCert is self-signed.
//
// Every rule fails closed: GetCACertificate's result is written to ca/ca.crt,
// baked into installers, returned as ca_cert on registration and refresh, and
// TOFU-pinned permanently by stewards, so an unverified blob reaching it turns
// an intermediate compromise into a permanent fleet-wide root compromise.
func validateIssuerChain(caCert *x509.Certificate, issuerChainPEM []byte) error {
	if caCert == nil {
		return fmt.Errorf("CA certificate is required")
	}

	if len(issuerChainPEM) == 0 {
		if err := verifySelfSigned(caCert); err != nil {
			return fmt.Errorf("CA certificate is not self-signed but no issuer chain was supplied: %w", err)
		}
		return nil
	}

	parents, err := ParseCertificateChainFromPEM(issuerChainPEM)
	if err != nil {
		return fmt.Errorf("failed to parse issuer chain: %w", err)
	}

	// chain[0] is the CA's own certificate; each subsequent entry must be the
	// issuer of the one before it.
	chain := append([]*x509.Certificate{caCert}, parents...)
	for i := 0; i < len(chain)-1; i++ {
		if err := verifyIssuedBy(chain[i], chain[i+1]); err != nil {
			if i == 0 {
				return fmt.Errorf("issuer chain entry 0 did not issue the CA certificate: %w", err)
			}
			return fmt.Errorf("issuer chain does not link: entry %d is not signed by entry %d: %w", i-1, i, err)
		}
	}

	root := chain[len(chain)-1]
	if err := verifySelfSigned(root); err != nil {
		return fmt.Errorf("terminal issuer chain entry is not a self-signed root "+
			"(the chain must be ordered nearest-issuer-first with the root last): %w", err)
	}

	return nil
}

// verifyIssuedBy reports whether parent issued child: parent must be a CA, its
// subject must match child's issuer, and it must have produced child's signature.
func verifyIssuedBy(child, parent *x509.Certificate) error {
	if !parent.IsCA {
		return fmt.Errorf("issuer certificate is not a CA")
	}
	if !bytes.Equal(child.RawIssuer, parent.RawSubject) {
		return fmt.Errorf("issuer name mismatch")
	}
	if err := child.CheckSignatureFrom(parent); err != nil {
		return fmt.Errorf("signature verification failed: %w", err)
	}
	return nil
}

// verifySelfSigned reports whether cert is a self-signed root: its own subject is
// its issuer and its own key produced its signature.
func verifySelfSigned(cert *x509.Certificate) error {
	return verifyIssuedBy(cert, cert)
}

// ownCertificatePEM returns this CA's own certificate re-encoded as PEM.
func (ca *CA) ownCertificatePEM() []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: ca.certificate.Raw,
	})
}

// issuedCertIssuerChainPEM returns the value that belongs in IssuerChainPEM for a
// certificate this CA signs: the chain from the signed certificate's direct issuer
// (this CA) up to but not including the ultimate trust root. Empty when this CA is
// itself the root, since the direct issuer of the signed certificate is then the
// root and there is nothing between issuer and root to record.
func (ca *CA) issuedCertIssuerChainPEM() []byte {
	if len(ca.issuerChainPEM) == 0 {
		return nil
	}

	chain := append([]byte{}, ca.ownCertificatePEM()...)

	// ca.issuerChainPEM is root-terminal; every entry except the final one (the
	// root) belongs alongside this CA's own certificate in the issued
	// certificate's chain.
	parents, err := ParseCertificateChainFromPEM(ca.issuerChainPEM)
	if err != nil || len(parents) == 0 {
		return chain
	}
	for _, p := range parents[:len(parents)-1] {
		chain = append(chain, pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: p.Raw,
		})...)
	}
	return chain
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
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(time.Duration(config.ValidityDays) * 24 * time.Hour),
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: ipAddresses,
		DNSNames:    config.DNSNames,
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
		Type:           CertificateTypePublicAPI,
		CommonName:     config.CommonName,
		SerialNumber:   serialNumber.String(),
		CreatedAt:      template.NotBefore,
		ExpiresAt:      template.NotAfter,
		IsValid:        true,
		CertificatePEM: certPEM,
		IssuerChainPEM: ca.issuedCertIssuerChainPEM(),
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
	subject := pkix.Name{
		Organization: []string{config.Organization},
		CommonName:   config.CommonName,
	}
	if config.OrganizationalUnit != "" {
		subject.OrganizationalUnit = []string{config.OrganizationalUnit}
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      subject,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Duration(config.ValidityDays) * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	if config.TemplateModifier != nil {
		config.TemplateModifier(template)
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
		IssuerChainPEM: ca.issuedCertIssuerChainPEM(),
		PrivateKeyPEM:  keyPEM,
		Fingerprint:    fingerprint,
		Issuer:         ca.certificate.Subject.CommonName,
		ClientID:       config.ClientID,
	}, nil
}

// SignClientCertificateRequest signs a caller-supplied public key into a client
// certificate. Unlike GenerateClientCertificate, the CA never generates or sees a
// private key for this credential: the caller generates the keypair locally and
// submits only pubKey. The returned Certificate.PrivateKeyPEM is empty — there is
// no private key for the CA to return or for FileStore to persist.
//
// This is the CA-side primitive for both the CLI-driven CSR flow (Story S10) and a
// future browser-based enrollment flow (admin authenticates via passkey, the CLI
// generates a keypair locally, the controller signs the submitted public key) —
// it is not designed to be reachable only from one caller.
func (ca *CA) SignClientCertificateRequest(pubKey crypto.PublicKey, config *ClientCertConfig) (*Certificate, error) {
	if !ca.initialized {
		return nil, fmt.Errorf("CA is not initialized")
	}

	if config == nil {
		return nil, fmt.Errorf("client certificate config is required")
	}

	if pubKey == nil {
		return nil, fmt.Errorf("public key is required")
	}

	// Set defaults
	if config.ValidityDays == 0 {
		config.ValidityDays = 365
	}
	if config.Organization == "" {
		config.Organization = ca.config.Organization
	}

	// Generate serial number
	serialNumber, err := ca.generateSerialNumber()
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	// Create client certificate template
	subject := pkix.Name{
		Organization: []string{config.Organization},
		CommonName:   config.CommonName,
	}
	if config.OrganizationalUnit != "" {
		subject.OrganizationalUnit = []string{config.OrganizationalUnit}
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      subject,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Duration(config.ValidityDays) * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	if config.TemplateModifier != nil {
		config.TemplateModifier(template)
	}

	// Sign the caller-supplied public key directly — the CA never generates or
	// holds a private key for this credential.
	certDER, err := x509.CreateCertificate(rand.Reader, template, ca.certificate, pubKey, ca.privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create client certificate: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
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
		IssuerChainPEM: ca.issuedCertIssuerChainPEM(),
		PrivateKeyPEM:  nil,
		Fingerprint:    fingerprint,
		Issuer:         ca.certificate.Subject.CommonName,
		ClientID:       config.ClientID,
	}, nil
}

// SignSubordinateCA signs a caller-supplied public key into a subordinate
// (intermediate) CA certificate. Like SignClientCertificateRequest, the CA
// never generates or sees a private key for the subordinate: the caller
// generates the keypair locally and submits only pubKey. The returned
// Certificate.PrivateKeyPEM is empty.
//
// A signer whose own path-length constraint is zero (today's default) can
// never sign a subordinate CA, and a subordinate's requested path length
// must always be strictly less than the signer's own — otherwise the chain
// could exceed the signer's RFC 5280 §4.2.1.9 pathLenConstraint. Both are
// rejected with an explicit error rather than left to x509.CreateCertificate,
// which does not enforce this relationship on its own.
func (ca *CA) SignSubordinateCA(pubKey crypto.PublicKey, config *SubordinateCAConfig) (*Certificate, error) {
	if !ca.initialized {
		return nil, fmt.Errorf("CA is not initialized")
	}

	if config == nil {
		return nil, fmt.Errorf("subordinate CA config is required")
	}

	if pubKey == nil {
		return nil, fmt.Errorf("public key is required")
	}

	if config.PathLength < 0 || config.PathLength > 6 {
		return nil, fmt.Errorf("subordinate CA path length must be between 0 and 6, got %d", config.PathLength)
	}

	// A path-length-zero signer may not be followed by any intermediate CA
	// certificate in a valid path, so it can never sign a subordinate CA.
	if ca.certificate.MaxPathLenZero {
		return nil, fmt.Errorf("signer CA has path length 0 and cannot sign a subordinate CA")
	}

	// A signer with no pathLenConstraint present (MaxPathLen == -1) is
	// unconstrained; otherwise the subordinate must leave room within the
	// signer's own constraint.
	if ca.certificate.MaxPathLen >= 0 && config.PathLength >= ca.certificate.MaxPathLen {
		return nil, fmt.Errorf("subordinate CA path length %d must be strictly less than signer path length %d", config.PathLength, ca.certificate.MaxPathLen)
	}

	// Set defaults
	if config.ValidityDays == 0 {
		config.ValidityDays = 3650
	}
	if config.Organization == "" {
		config.Organization = ca.config.Organization
	}

	// Generate serial number
	serialNumber, err := ca.generateSerialNumber()
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	// Create subordinate CA certificate template
	subject := pkix.Name{
		Organization: []string{config.Organization},
		CommonName:   config.CommonName,
	}
	if config.OrganizationalUnit != "" {
		subject.OrganizationalUnit = []string{config.OrganizationalUnit}
	}

	template := &x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               subject,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Duration(config.ValidityDays) * 24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		MaxPathLen:            config.PathLength,
		MaxPathLenZero:        config.PathLength == 0,
	}

	// Sign the caller-supplied public key directly — the CA never generates
	// or holds a private key for this subordinate.
	certDER, err := x509.CreateCertificate(rand.Reader, template, ca.certificate, pubKey, ca.privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create subordinate CA certificate: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	fingerprint := ca.calculateFingerprint(certDER)

	return &Certificate{
		Type:           CertificateTypeCA,
		CommonName:     config.CommonName,
		SerialNumber:   serialNumber.String(),
		CreatedAt:      template.NotBefore,
		ExpiresAt:      template.NotAfter,
		IsValid:        true,
		CertificatePEM: certPEM,
		IssuerChainPEM: ca.issuedCertIssuerChainPEM(),
		PrivateKeyPEM:  nil,
		Fingerprint:    fingerprint,
		Issuer:         ca.certificate.Subject.CommonName,
	}, nil
}

// GenerateSigningCertificate creates a config signing certificate with CodeSigning EKU.
// This certificate is used exclusively for signing configurations and DNA packages.
// Key properties: 4096-bit RSA, CodeSigning EKU (NOT ServerAuth), DigitalSignature only, 3-year default validity.
func (ca *CA) GenerateSigningCertificate(config *SigningCertConfig) (*Certificate, error) {
	if !ca.initialized {
		return nil, fmt.Errorf("CA is not initialized")
	}

	if config == nil {
		return nil, fmt.Errorf("signing certificate config is required")
	}

	// Set defaults
	if config.KeySize == 0 {
		config.KeySize = 4096
	}
	if config.ValidityDays == 0 {
		config.ValidityDays = 1095 // 3 years
	}
	if config.Organization == "" {
		config.Organization = ca.config.Organization
	}
	if config.CommonName == "" {
		config.CommonName = "cfgms-config-signer"
	}

	// Generate signing private key (4096-bit RSA for long-lived signing)
	privateKey, err := rsa.GenerateKey(rand.Reader, config.KeySize)
	if err != nil {
		return nil, fmt.Errorf("failed to generate signing private key: %w", err)
	}

	// Generate serial number
	serialNumber, err := ca.generateSerialNumber()
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	// Create signing certificate template
	// KeyUsage: DigitalSignature ONLY (no KeyEncipherment - not for TLS)
	// ExtKeyUsage: CodeSigning ONLY (not ServerAuth)
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{config.Organization},
			CommonName:   config.CommonName,
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(time.Duration(config.ValidityDays) * 24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
	}

	// Create the signing certificate
	certDER, err := x509.CreateCertificate(rand.Reader, template, ca.certificate, &privateKey.PublicKey, ca.privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create signing certificate: %w", err)
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
		Type:           CertificateTypeConfigSigning,
		CommonName:     config.CommonName,
		SerialNumber:   serialNumber.String(),
		CreatedAt:      template.NotBefore,
		ExpiresAt:      template.NotAfter,
		IsValid:        true,
		CertificatePEM: certPEM,
		IssuerChainPEM: ca.issuedCertIssuerChainPEM(),
		PrivateKeyPEM:  keyPEM,
		Fingerprint:    fingerprint,
		Issuer:         ca.certificate.Subject.CommonName,
	}, nil
}

// GenerateInternalServerCertificate creates a server certificate for internal mTLS (gRPC-over-QUIC).
// This has the same properties as GenerateServerCertificate but returns CertificateTypeInternalServer.
func (ca *CA) GenerateInternalServerCertificate(config *ServerCertConfig) (*Certificate, error) {
	cert, err := ca.GenerateServerCertificate(config)
	if err != nil {
		return nil, err
	}
	cert.Type = CertificateTypeInternalServer
	return cert, nil
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

// LoadCAFromSecretStore retrieves CA cert+key PEM from a SecretStore and
// populates the CA in-memory without writing the key to local disk.
// keyPath is the secret key name for the CA certificate (without tenantID prefix).
// The CA private key is loaded from "<tenantID>/<keyPath>-key".
// This is the cluster-mode path — call LoadCA for single-node deployments.
func (ca *CA) LoadCAFromSecretStore(ctx context.Context, store secretsinterfaces.SecretStore, tenantID, keyPath string) error {
	certSecret, err := store.GetSecret(ctx, tenantID+"/"+keyPath)
	if err != nil {
		return fmt.Errorf("failed to get CA certificate from secret store: %w", err)
	}

	keySecret, err := store.GetSecret(ctx, tenantID+"/"+keyPath+"-key")
	if err != nil {
		return fmt.Errorf("failed to get CA private key from secret store: %w", err)
	}

	caCertPEM := []byte(certSecret.Value)
	caKeyPEM := []byte(keySecret.Value)

	block, _ := pem.Decode(caCertPEM)
	if block == nil {
		return fmt.Errorf("failed to decode CA certificate PEM from secret store")
	}

	caCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse CA certificate from secret store: %w", err)
	}

	parsedKey, err := ParsePrivateKeyFromPEM(caKeyPEM)
	if err != nil {
		return fmt.Errorf("failed to parse CA private key from secret store: %w", err)
	}

	rsaKey, ok := parsedKey.(*rsa.PrivateKey)
	if !ok {
		return fmt.Errorf("CA private key must be RSA, got unsupported key type")
	}

	if err := ValidateKeyPair(caCertPEM, caKeyPEM); err != nil {
		return fmt.Errorf("CA key does not match certificate in secret store: %w", err)
	}

	org := "CFGMS"
	if len(caCert.Subject.Organization) > 0 {
		org = caCert.Subject.Organization[0]
	}
	ca.config = &CAConfig{Organization: org}
	ca.certificate = caCert
	ca.privateKey = rsaKey
	ca.initialized = true

	return nil
}

// StoreCAToSecretStore stores the CA certificate and private key PEM in a SecretStore.
// Called during cluster-mode first-boot init to publish CA material to the shared
// vault so subsequent nodes can load it via LoadCAFromSecretStore.
// The cert is stored at "<tenantID>/<keyPath>" and the key at "<tenantID>/<keyPath>-key".
func (ca *CA) StoreCAToSecretStore(ctx context.Context, store secretsinterfaces.SecretStore, tenantID, keyPath string) error {
	if !ca.initialized {
		return fmt.Errorf("CA is not initialized")
	}

	certPEM, err := ca.GetCACertificate()
	if err != nil {
		return fmt.Errorf("failed to get CA certificate: %w", err)
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(ca.privateKey),
	})

	if err := store.StoreSecret(ctx, &secretsinterfaces.SecretRequest{
		Key:         keyPath,
		Value:       string(certPEM),
		TenantID:    tenantID,
		CreatedBy:   "cfgms-controller-init",
		Description: "CFGMS cluster CA certificate",
	}); err != nil {
		return fmt.Errorf("failed to store CA certificate in secret store: %w", err)
	}

	if err := store.StoreSecret(ctx, &secretsinterfaces.SecretRequest{
		Key:         keyPath + "-key",
		Value:       string(keyPEM),
		TenantID:    tenantID,
		CreatedBy:   "cfgms-controller-init",
		Description: "CFGMS cluster CA private key",
	}); err != nil {
		return fmt.Errorf("failed to store CA private key in secret store: %w", err)
	}

	return nil
}
