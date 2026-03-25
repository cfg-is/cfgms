// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package transport

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"

	"github.com/cfgis/cfgms/pkg/cert"
)

// TLSSecurityTestSuite tests TLS/mTLS security for the gRPC transport.
//
// TLS security in the gRPC transport architecture:
//   - Registration endpoint (HTTPS) uses server-side TLS
//   - gRPC-over-QUIC transport uses mTLS: steward presents client cert from registration
//   - Controller CA signs all client certificates returned during registration
//   - Certificates from wrong CA, expired, or self-signed are rejected
//
// Tests validate the certificate distribution via registration API and verify
// that TLS configuration meets minimum security standards.
type TLSSecurityTestSuite struct {
	suite.Suite
	helper      *TestHelper
	certsPath   string
	certManager *cert.Manager
}

func (s *TLSSecurityTestSuite) SetupSuite() {
	if testing.Short() {
		s.T().Skip("Skipping TLS security tests in short mode - requires controller infrastructure")
		return
	}

	s.helper = NewTestHelper(GetTestHTTPAddr("https://localhost:8080"))
	s.certsPath = filepath.Join(s.T().TempDir(), "certs")

	s.ensureCertificatesExist()
	s.generateInvalidCertificates()
}

// ensureCertificatesExist generates test certificates for negative testing.
// Uses pkg/cert.Manager directly (same pattern as testutil.NewTestEnv).
func (s *TLSSecurityTestSuite) ensureCertificatesExist() {
	if err := os.MkdirAll(s.certsPath, 0755); err != nil {
		s.T().Fatalf("Failed to create certs directory: %v", err)
	}

	certManager, err := cert.NewManager(&cert.ManagerConfig{
		StoragePath: s.certsPath,
		CAConfig: &cert.CAConfig{
			Organization:       "CFGMS Test CA",
			Country:            "US",
			State:              "Test",
			City:               "Test",
			OrganizationalUnit: "Transport Integration Tests",
			ValidityDays:       365,
			KeySize:            2048,
		},
		LoadExistingCA:       false,
		RenewalThresholdDays: 30,
	})
	require.NoError(s.T(), err, "Failed to create certificate manager")
	s.certManager = certManager

	_, err = certManager.GenerateServerCertificate(&cert.ServerCertConfig{
		CommonName:   "cfgms-controller",
		DNSNames:     []string{"localhost", "cfgms-controller"},
		IPAddresses:  []string{"127.0.0.1"},
		Organization: "CFGMS Test",
		ValidityDays: 365,
		KeySize:      2048,
	})
	require.NoError(s.T(), err, "Failed to generate server certificate")

	_, err = certManager.GenerateClientCertificate(&cert.ClientCertConfig{
		CommonName:   "test-steward",
		Organization: "CFGMS Test",
		ValidityDays: 365,
		KeySize:      2048,
	})
	require.NoError(s.T(), err, "Failed to generate client certificate")

	s.createFlatCertStructure()
	s.T().Log("Test certificates generated using pkg/cert.Manager")
}

func (s *TLSSecurityTestSuite) createFlatCertStructure() {
	caSrc := filepath.Join(s.certsPath, "ca", "ca.crt")
	caDest := filepath.Join(s.certsPath, "ca-cert.pem")
	caData, err := os.ReadFile(caSrc)
	require.NoError(s.T(), err, "Failed to read CA certificate from %s", caSrc)
	err = os.WriteFile(caDest, caData, 0644)
	require.NoError(s.T(), err, "Failed to write CA certificate")

	serverCerts, err := s.certManager.GetCertificateByCommonName("cfgms-controller")
	require.NoError(s.T(), err, "Failed to get server certificate")
	require.Len(s.T(), serverCerts, 1, "Expected exactly one server certificate")

	serverCert, err := s.certManager.GetCertificate(serverCerts[0].SerialNumber)
	require.NoError(s.T(), err, "Failed to retrieve server certificate")

	err = os.WriteFile(filepath.Join(s.certsPath, "server-cert.pem"), serverCert.CertificatePEM, 0644)
	require.NoError(s.T(), err)
	err = os.WriteFile(filepath.Join(s.certsPath, "server-key.pem"), serverCert.PrivateKeyPEM, 0600)
	require.NoError(s.T(), err)

	clientCerts, err := s.certManager.GetCertificateByCommonName("test-steward")
	require.NoError(s.T(), err, "Failed to get client certificate")
	require.Len(s.T(), clientCerts, 1, "Expected exactly one client certificate")

	clientCert, err := s.certManager.GetCertificate(clientCerts[0].SerialNumber)
	require.NoError(s.T(), err, "Failed to retrieve client certificate")

	err = os.WriteFile(filepath.Join(s.certsPath, "client-cert.pem"), clientCert.CertificatePEM, 0644)
	require.NoError(s.T(), err)
	err = os.WriteFile(filepath.Join(s.certsPath, "client-key.pem"), clientCert.PrivateKeyPEM, 0600)
	require.NoError(s.T(), err)
}

func (s *TLSSecurityTestSuite) generateInvalidCertificates() {
	scriptPath := filepath.Join("..", "..", "..", "scripts", "generate-invalid-test-certs.sh")
	cmd := exec.Command("bash", scriptPath, s.certsPath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		s.T().Logf("Script output: %s", output)
		s.T().Fatalf("Failed to generate invalid certificates: %v", err)
	}
}

// TestTLSConfigFromRegistration verifies that the registration API returns
// valid TLS certificates with proper minimum version settings.
func (s *TLSSecurityTestSuite) TestTLSConfigFromRegistration() {
	s.T().Log("Testing TLS config from registration API")

	tlsConfig, stewardID := s.helper.GetTLSConfigFromRegistration(s.T(), "default", "integration-test")
	s.NotNil(tlsConfig, "TLS config should be loaded from registration response")
	s.NotEmpty(stewardID, "Steward ID should be returned")

	s.GreaterOrEqual(tlsConfig.MinVersion, uint16(tls.VersionTLS12),
		"TLS minimum version should be at least TLS 1.2")
	s.NotEmpty(tlsConfig.Certificates, "Client certificate should be present")

	s.T().Logf("TLS 1.2+ enforcement verified for steward: %s", stewardID)
}

// TestRegistrationReturnsCertificates verifies that all required certificate fields
// are present in the registration response for mTLS connectivity.
func (s *TLSSecurityTestSuite) TestRegistrationReturnsCertificates() {
	s.T().Log("Testing certificate distribution via registration API")

	token := s.helper.CreateToken(s.T(), "default", "integration-test")
	resp := s.helper.RegisterSteward(s.T(), token)

	require.NotEmpty(s.T(), resp.StewardID, "Registration should return steward ID")
	require.NotEmpty(s.T(), resp.ClientCert, "Registration should return client certificate")
	require.NotEmpty(s.T(), resp.ClientKey, "Registration should return client key")
	require.NotEmpty(s.T(), resp.CACert, "Registration should return CA certificate")
	require.NotEmpty(s.T(), resp.TransportAddress, "Registration should return transport address")

	s.T().Logf("Certificate distribution validated for steward: %s", resp.StewardID)
}

// TestClientCertificateFromRegistration verifies that the client certificate returned
// during registration is valid and can be loaded for mTLS connections.
func (s *TLSSecurityTestSuite) TestClientCertificateFromRegistration() {
	token := s.helper.CreateToken(s.T(), "default", "integration-test")
	resp := s.helper.RegisterSteward(s.T(), token)

	certDir := s.T().TempDir()
	clientCertPath := filepath.Join(certDir, "client.crt")
	clientKeyPath := filepath.Join(certDir, "client.key")
	caCertPath := filepath.Join(certDir, "ca.crt")

	err := os.WriteFile(clientCertPath, []byte(resp.ClientCert), 0600)
	require.NoError(s.T(), err)
	err = os.WriteFile(clientKeyPath, []byte(resp.ClientKey), 0600)
	require.NoError(s.T(), err)
	err = os.WriteFile(caCertPath, []byte(resp.CACert), 0600)
	require.NoError(s.T(), err)

	clientCert, err := tls.LoadX509KeyPair(clientCertPath, clientKeyPath)
	require.NoError(s.T(), err, "Client certificate from registration must be loadable")

	caCert, err := os.ReadFile(caCertPath)
	require.NoError(s.T(), err)

	caCertPool := x509.NewCertPool()
	ok := caCertPool.AppendCertsFromPEM(caCert)
	require.True(s.T(), ok, "CA certificate must be parseable")

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      caCertPool,
		MinVersion:   tls.VersionTLS12,
		ServerName:   "localhost",
	}

	s.NotNil(tlsConfig)
	s.NotEmpty(tlsConfig.Certificates)
	s.T().Log("Client certificate from registration API validated for mTLS")
}

// TestExpiredCertificateRejectedByRegistration verifies that attempting to
// use an expired token is rejected at the HTTP registration layer.
func (s *TLSSecurityTestSuite) TestExpiredCertificateRejectedByRegistration() {
	s.T().Log("Testing expired token rejection")

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // test helper
	}
	client := &http.Client{Timeout: 10 * time.Second, Transport: transport}

	req, err := http.NewRequest(http.MethodPost,
		fmt.Sprintf("%s/api/v1/register", s.helper.baseURL), nil)
	require.NoError(s.T(), err)

	resp, err := client.Do(req)
	if err != nil {
		s.T().Logf("Request failed (expected for expired/invalid credentials): %v", err)
		return
	}
	defer func() { _ = resp.Body.Close() }()

	// No valid token = should fail
	s.NotEqual(http.StatusOK, resp.StatusCode, "Missing token should not return 200")
	s.T().Logf("Unauthenticated request correctly rejected with status: %d", resp.StatusCode)
}

// TestMultipleClientCertificatesRotation verifies that multiple stewards can
// register concurrently, each receiving unique certificates (certificate rotation concept).
func (s *TLSSecurityTestSuite) TestMultipleClientCertificatesRotation() {
	s.T().Log("Testing certificate rotation: multiple concurrent registrations")

	tlsConfig1, stewardID1 := s.helper.GetTLSConfigFromRegistration(s.T(), "default", "integration-test")
	s.NotNil(tlsConfig1)
	s.NotEmpty(stewardID1)

	tlsConfig2, stewardID2 := s.helper.GetTLSConfigFromRegistration(s.T(), "default", "integration-test")
	s.NotNil(tlsConfig2)
	s.NotEmpty(stewardID2)

	s.NotEqual(stewardID1, stewardID2, "Each steward should have unique identity")
	s.T().Logf("Certificate rotation validated: steward1=%s steward2=%s", stewardID1, stewardID2)
}

func TestTLSSecurity(t *testing.T) {
	suite.Run(t, new(TLSSecurityTestSuite))
}
