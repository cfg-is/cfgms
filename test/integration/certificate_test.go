// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 CFGMS Contributors
package integration

import (
	"testing"
	"time"

	"github.com/stretchr/testify/suite"

	"github.com/cfgis/cfgms/pkg/cert"
	"github.com/cfgis/cfgms/test/integration/testutil"
)

// CertificateTestSuite tests certificate management functionality
type CertificateTestSuite struct {
	suite.Suite
	env *testutil.TestEnv
}

func (s *CertificateTestSuite) SetupSuite() {
	s.env = testutil.NewTestEnv(s.T())
}

func (s *CertificateTestSuite) TearDownSuite() {
	s.env.Cleanup()
}

func (s *CertificateTestSuite) SetupTest() {
	s.env.Reset()
}

// TestCertificateManagerInitialization tests that the certificate manager is properly initialized
func (s *CertificateTestSuite) TestCertificateManagerInitialization() {
	certManager := s.env.GetCertificateManager()
	s.NotNil(certManager, "Certificate manager should be initialized")

	// Validate that all required certificates are present
	err := s.env.ValidateCertificateSetup()
	s.NoError(err, "Certificate setup should be valid")
}

// TestCACertificateExists tests that CA certificate is properly created
func (s *CertificateTestSuite) TestCACertificateExists() {
	caCerts, err := s.env.GetCertificateInfo(cert.CertificateTypeCA)
	s.NoError(err, "Should be able to retrieve CA certificates")
	s.Len(caCerts, 1, "Should have exactly one CA certificate")

	caCert := caCerts[0]
	s.Equal(cert.CertificateTypeCA, caCert.Type, "Certificate should be CA type")
	s.True(caCert.IsValid, "CA certificate should be valid")
	s.True(caCert.ExpiresAt.After(time.Now()), "CA certificate should not be expired")
	s.Equal("CFGMS Test CA Root CA", caCert.CommonName, "CA certificate should have correct common name")
}

// TestServerCertificateExists tests that server certificate is properly created
func (s *CertificateTestSuite) TestServerCertificateExists() {
	serverCerts, err := s.env.GetCertificateInfo(cert.CertificateTypeServer)
	s.NoError(err, "Should be able to retrieve server certificates")
	s.Len(serverCerts, 1, "Should have exactly one server certificate")

	serverCert := serverCerts[0]
	s.Equal(cert.CertificateTypeServer, serverCert.Type, "Certificate should be server type")
	s.True(serverCert.IsValid, "Server certificate should be valid")
	s.True(serverCert.ExpiresAt.After(time.Now()), "Server certificate should not be expired")
	s.Equal("cfgms-controller", serverCert.CommonName, "Server certificate should have correct common name")
}

// TestClientCertificateExists tests that client certificate is properly created
func (s *CertificateTestSuite) TestClientCertificateExists() {
	clientCerts, err := s.env.GetCertificateInfo(cert.CertificateTypeClient)
	s.NoError(err, "Should be able to retrieve client certificates")

	// Find the original test-steward certificate (the test environment creates 1, the generation test creates another)
	var testStewardCert *cert.CertificateInfo
	for _, certInfo := range clientCerts {
		if certInfo.CommonName == "test-steward" {
			testStewardCert = certInfo
			break
		}
	}

	s.NotNil(testStewardCert, "Should find test-steward client certificate")
	s.Equal(cert.CertificateTypeClient, testStewardCert.Type, "Certificate should be client type")
	s.True(testStewardCert.IsValid, "Client certificate should be valid")
	s.True(testStewardCert.ExpiresAt.After(time.Now()), "Client certificate should not be expired")
	s.Equal("test-steward", testStewardCert.CommonName, "Client certificate should have correct common name")
}

// TestCertificateGeneration tests generating additional certificates
func (s *CertificateTestSuite) TestCertificateGeneration() {
	certManager := s.env.GetCertificateManager()

	// Generate a new client certificate
	newClientCert, err := certManager.GenerateClientCertificate(&cert.ClientCertConfig{
		CommonName:         "test-steward-2",
		Organization:       "CFGMS Test Stewards",
		OrganizationalUnit: "Integration Tests",
		ValidityDays:       365,
		KeySize:            2048,
		ClientID:           "test-steward-2",
	})
	s.NoError(err, "Should be able to generate new client certificate")
	s.NotNil(newClientCert, "New client certificate should not be nil")
	s.Equal("test-steward-2", newClientCert.CommonName, "New certificate should have correct common name")
	s.True(newClientCert.IsValid, "New certificate should be valid")

	// Verify that we now have 2 client certificates
	clientCerts, err := s.env.GetCertificateInfo(cert.CertificateTypeClient)
	s.NoError(err, "Should be able to retrieve client certificates")
	s.Len(clientCerts, 2, "Should have two client certificates after generation")
}

// TestCertificateValidation tests certificate validation functionality
func (s *CertificateTestSuite) TestCertificateValidation() {
	certManager := s.env.GetCertificateManager()

	// Get the server certificate
	serverCerts, err := s.env.GetCertificateInfo(cert.CertificateTypeServer)
	s.NoError(err, "Should be able to retrieve server certificates")
	s.Len(serverCerts, 1, "Should have exactly one server certificate")

	// Get the actual certificate data for validation
	serverCert, err := certManager.GetCertificate(serverCerts[0].SerialNumber)
	s.NoError(err, "Should be able to get server certificate")

	// Validate the certificate
	validationResult, err := certManager.ValidateCertificate(serverCert.CertificatePEM)
	s.NoError(err, "Should be able to validate certificate")
	s.True(validationResult.IsValid, "Server certificate should be valid")
	s.Empty(validationResult.Errors, "Valid certificate should have no errors")
}

// TestCertificateExpirationChecking tests certificate expiration functionality
func (s *CertificateTestSuite) TestCertificateExpirationChecking() {
	certManager := s.env.GetCertificateManager()

	// Check for expiring certificates (should be none since we just created them)
	expiringCerts, err := certManager.GetExpiringCertificates(30)
	s.NoError(err, "Should be able to check for expiring certificates")
	s.Empty(expiringCerts, "Should have no certificates expiring within 30 days")

	// Check for certificates expiring within a year (should include all test certificates)
	expiringCerts, err = certManager.GetExpiringCertificates(400)
	s.NoError(err, "Should be able to check for expiring certificates")
	s.NotEmpty(expiringCerts, "Should have certificates expiring within 400 days")
}

// TestControllerWithCertificates tests that controller starts properly with certificates
func (s *CertificateTestSuite) TestControllerWithCertificates() {
	// Start the controller
	s.env.Start()
	defer s.env.Stop()

	// Verify controller started successfully with certificate management
	s.NotNil(s.env.Controller, "Controller should be initialized")
	s.NotEmpty(s.env.Controller.GetListenAddr(), "Controller should have a listen address")

	// Verify certificates are still valid after controller startup
	err := s.env.ValidateCertificateSetup()
	s.NoError(err, "Certificate setup should remain valid after controller startup")
}

// TestStewardWithCertificates tests that steward starts properly with certificates
func (s *CertificateTestSuite) TestStewardWithCertificates() {
	// Start both controller and steward
	s.env.Start()
	defer s.env.Stop()

	// Give components time to initialize
	time.Sleep(200 * time.Millisecond)

	// Verify steward started successfully with certificate management
	s.NotNil(s.env.Steward, "Steward should be initialized")

	// Verify certificates are still valid after steward startup
	err := s.env.ValidateCertificateSetup()
	s.NoError(err, "Certificate setup should remain valid after steward startup")
}

// TestCertificateHealthMonitoring tests certificate health monitoring functionality
func (s *CertificateTestSuite) TestCertificateHealthMonitoring() {
	// Start both controller and steward to activate health monitoring
	s.env.Start()
	defer s.env.Stop()

	// Give health monitoring time to run
	time.Sleep(500 * time.Millisecond)

	// Check that health monitoring includes certificate status
	// This would require accessing the steward's health monitor, which would need
	// to be exposed in the test environment for full testing
	// For now, we just verify that the system starts and runs without errors
	s.NotNil(s.env.Steward, "Steward should be running with certificate health monitoring")
}

func TestCertificateTestSuite(t *testing.T) {
	suite.Run(t, new(CertificateTestSuite))
}
