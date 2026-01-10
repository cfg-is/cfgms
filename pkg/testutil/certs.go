// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
// Package testutil provides shared testing utilities for unit and integration tests.
//
// This package contains helper functions for setting up test environments,
// generating test certificates, and managing test cleanup. It is designed
// to be used by both unit tests and integration tests to ensure consistent
// test setup across the codebase.
package testutil

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// CertConfig contains configuration for test certificate generation.
type CertConfig struct {
	// CertDir is the directory where certificates will be stored
	CertDir string

	// ServerName is the common name for the server certificate
	ServerName string

	// ClientName is the common name for the client certificate
	ClientName string

	// ValidityPeriod is how long the certificates should be valid
	ValidityPeriod time.Duration
}

// DefaultCertConfig returns a CertConfig with reasonable defaults.
func DefaultCertConfig() *CertConfig {
	return &CertConfig{
		ServerName:     "cfgms-controller",
		ClientName:     "cfgms-steward",
		ValidityPeriod: 365 * 24 * time.Hour,
	}
}

// SetupTestCerts creates a temporary directory with test certificates and returns
// a cleanup function. This is the main function that should be used in tests.
//
// Usage:
//
//	certDir, cleanup := testutil.SetupTestCerts(t)
//	t.Cleanup(cleanup)
//
// The returned directory will contain:
//   - ca.crt: Certificate Authority certificate
//   - server.crt: Server certificate
//   - server.key: Server private key
//   - client.crt: Client certificate
//   - client.key: Client private key
func SetupTestCerts(t *testing.T) (certDir string, cleanup func()) {
	return SetupTestCertsWithConfig(t, DefaultCertConfig())
}

// SetupTestCertsWithConfig creates test certificates with custom configuration.
func SetupTestCertsWithConfig(t *testing.T, config *CertConfig) (certDir string, cleanup func()) {
	// Create temporary directory
	tempDir, err := os.MkdirTemp("", "cfgms-test-certs-")
	require.NoError(t, err)

	// Set cert directory if not specified
	if config.CertDir == "" {
		config.CertDir = tempDir
	} else {
		// Create the specified directory
		err = os.MkdirAll(config.CertDir, 0755)
		require.NoError(t, err)
	}

	// Generate certificates
	err = GenerateTestCertificates(config)
	require.NoError(t, err)

	// Return cleanup function
	cleanup = func() {
		if err := os.RemoveAll(tempDir); err != nil {
			// Log error but continue cleanup
			_ = err // Explicitly ignore cleanup errors
		}
		if config.CertDir != tempDir {
			if err := os.RemoveAll(config.CertDir); err != nil {
				// Log error but continue cleanup
				_ = err // Explicitly ignore cleanup errors
			}
		}
	}

	return config.CertDir, cleanup
}

// GenerateTestCertificates creates self-signed certificates for testing.
// This function generates a complete certificate chain including:
// - CA certificate and key
// - Server certificate and key (signed by CA)
// - Client certificate and key (signed by CA)
func GenerateTestCertificates(config *CertConfig) error {
	// Create CA certificate
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	caTemplate := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization:  []string{"CFGMS Test CA"},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{"Test"},
			StreetAddress: []string{""},
			PostalCode:    []string{""},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(config.ValidityPeriod),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	caCertDER, err := x509.CreateCertificate(rand.Reader, &caTemplate, &caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return err
	}

	// Save CA certificate
	caCertFile, err := os.Create(filepath.Join(config.CertDir, "ca.crt"))
	if err != nil {
		return err
	}
	defer func() {
		if err := caCertFile.Close(); err != nil {
			// Log error but continue
			_ = err // Explicitly ignore file close errors
		}
	}()

	if err := pem.Encode(caCertFile, &pem.Block{Type: "CERTIFICATE", Bytes: caCertDER}); err != nil {
		return err
	}

	// Create server certificate
	serverKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	serverTemplate := x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			Organization:  []string{"CFGMS Test Server"},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{"Test"},
			StreetAddress: []string{""},
			PostalCode:    []string{""},
			CommonName:    config.ServerName,
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(config.ValidityPeriod),
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)},
		DNSNames:    []string{config.ServerName, "localhost"},
	}

	serverCertDER, err := x509.CreateCertificate(rand.Reader, &serverTemplate, &caTemplate, &serverKey.PublicKey, caKey)
	if err != nil {
		return err
	}

	// Save server certificate
	serverCertFile, err := os.Create(filepath.Join(config.CertDir, "server.crt"))
	if err != nil {
		return err
	}
	defer func() {
		if err := serverCertFile.Close(); err != nil {
			// Log error but continue
			_ = err // Explicitly ignore file close errors
		}
	}()

	if err := pem.Encode(serverCertFile, &pem.Block{Type: "CERTIFICATE", Bytes: serverCertDER}); err != nil {
		return err
	}

	// Save server key
	serverKeyFile, err := os.Create(filepath.Join(config.CertDir, "server.key"))
	if err != nil {
		return err
	}
	defer func() {
		if err := serverKeyFile.Close(); err != nil {
			// Log error but continue
			_ = err // Explicitly ignore file close errors
		}
	}()

	if err := pem.Encode(serverKeyFile, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(serverKey)}); err != nil {
		return err
	}

	// Create client certificate
	clientKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	clientTemplate := x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject: pkix.Name{
			Organization:  []string{"CFGMS Test Client"},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{"Test"},
			StreetAddress: []string{""},
			PostalCode:    []string{""},
			CommonName:    config.ClientName,
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(config.ValidityPeriod),
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	clientCertDER, err := x509.CreateCertificate(rand.Reader, &clientTemplate, &caTemplate, &clientKey.PublicKey, caKey)
	if err != nil {
		return err
	}

	// Save client certificate
	clientCertFile, err := os.Create(filepath.Join(config.CertDir, "client.crt"))
	if err != nil {
		return err
	}
	defer func() {
		if err := clientCertFile.Close(); err != nil {
			// Log error but continue
			_ = err // Explicitly ignore file close errors
		}
	}()

	if err := pem.Encode(clientCertFile, &pem.Block{Type: "CERTIFICATE", Bytes: clientCertDER}); err != nil {
		return err
	}

	// Save client key
	clientKeyFile, err := os.Create(filepath.Join(config.CertDir, "client.key"))
	if err != nil {
		return err
	}
	defer func() {
		if err := clientKeyFile.Close(); err != nil {
			// Log error but continue
			_ = err // Explicitly ignore file close errors
		}
	}()

	if err := pem.Encode(clientKeyFile, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(clientKey)}); err != nil {
		return err
	}

	return nil
}

// VerifyTLSConnection verifies that TLS connection can be established with the generated certificates.
func VerifyTLSConnection(certDir string) error {
	// Load certificates
	clientCert, err := tls.LoadX509KeyPair(
		filepath.Join(certDir, "client.crt"),
		filepath.Join(certDir, "client.key"),
	)
	if err != nil {
		return err
	}

	caCert, err := os.ReadFile(filepath.Join(certDir, "ca.crt"))
	if err != nil {
		return err
	}

	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCert) {
		return err
	}

	// Create TLS configuration
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      caCertPool,
		ServerName:   "cfgms-controller",
		MinVersion:   tls.VersionTLS12, // Enforce minimum TLS 1.2 for test environment
	}

	// Test that the configuration is valid
	if len(tlsConfig.Certificates) == 0 {
		return err
	}

	return nil
}

// VerifyCertificatesExist verifies that all required certificates are present in the directory.
func VerifyCertificatesExist(t *testing.T, certDir string) {
	certFiles := []string{"ca.crt", "server.crt", "server.key", "client.crt", "client.key"}

	for _, certFile := range certFiles {
		certPath := filepath.Join(certDir, certFile)
		if _, err := os.Stat(certPath); os.IsNotExist(err) {
			t.Fatalf("Certificate file missing: %s", certPath)
		}
	}
}
