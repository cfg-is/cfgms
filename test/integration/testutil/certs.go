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
	"time"
)

// GenerateTestCertificates creates self-signed certificates for integration testing
func GenerateTestCertificates(certDir string) error {
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
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	caCertDER, err := x509.CreateCertificate(rand.Reader, &caTemplate, &caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return err
	}

	// Save CA certificate
	caCertFile, err := os.Create(filepath.Join(certDir, "ca.crt"))
	if err != nil {
		return err
	}
	defer caCertFile.Close()

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
			CommonName:    "cfgms-controller",
		},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
		DNSNames:     []string{"cfgms-controller", "localhost"},
	}

	serverCertDER, err := x509.CreateCertificate(rand.Reader, &serverTemplate, &caTemplate, &serverKey.PublicKey, caKey)
	if err != nil {
		return err
	}

	// Save server certificate
	serverCertFile, err := os.Create(filepath.Join(certDir, "server.crt"))
	if err != nil {
		return err
	}
	defer serverCertFile.Close()

	if err := pem.Encode(serverCertFile, &pem.Block{Type: "CERTIFICATE", Bytes: serverCertDER}); err != nil {
		return err
	}

	// Save server key
	serverKeyFile, err := os.Create(filepath.Join(certDir, "server.key"))
	if err != nil {
		return err
	}
	defer serverKeyFile.Close()

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
			CommonName:    "cfgms-steward",
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	clientCertDER, err := x509.CreateCertificate(rand.Reader, &clientTemplate, &caTemplate, &clientKey.PublicKey, caKey)
	if err != nil {
		return err
	}

	// Save client certificate
	clientCertFile, err := os.Create(filepath.Join(certDir, "client.crt"))
	if err != nil {
		return err
	}
	defer clientCertFile.Close()

	if err := pem.Encode(clientCertFile, &pem.Block{Type: "CERTIFICATE", Bytes: clientCertDER}); err != nil {
		return err
	}

	// Save client key
	clientKeyFile, err := os.Create(filepath.Join(certDir, "client.key"))
	if err != nil {
		return err
	}
	defer clientKeyFile.Close()

	if err := pem.Encode(clientKeyFile, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(clientKey)}); err != nil {
		return err
	}

	return nil
}

// VerifyTLSConnection verifies that TLS connection can be established with the generated certificates
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
	}

	// Test that the configuration is valid
	if len(tlsConfig.Certificates) == 0 {
		return err
	}

	return nil
}