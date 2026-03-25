// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
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
	env            *testutil.TestEnv
	sharedCertPath string // Shared certificate storage for suite (simulates persistence)
}

func (s *CertificateTestSuite) SetupSuite() {
	// Create shared certificate storage directory for entire suite
	// This simulates a production controller's certificate storage that persists across reboots
	s.sharedCertPath = s.T().TempDir()
	s.T().Logf("Created shared certificate storage for suite: %s", s.sharedCertPath)

	// First test environment: generates fresh certificates (simulates fresh deployment)
	s.env = testutil.NewTestEnvWithSharedCerts(s.T(), s.sharedCertPath)
}

func (s *CertificateTestSuite) TearDownSuite() {
	if s.env != nil {
		s.env.Cleanup()
	}
}

func (s *CertificateTestSuite) SetupTest() {
	// Reset test environment but reuse shared certificates
	// This simulates a controller reboot where certificates persist on disk
	s.env.Reset()

	// Create new test environment that reuses existing certificates from shared storage
	// This validates the LoadExistingCA code path (production reboot scenario)
	s.env = testutil.NewTestEnvWithSharedCerts(s.T(), s.sharedCertPath)
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
	s.Equal("CFGMS Test Root CA", caCert.CommonName, "CA certificate should have correct common name (Organization + ' Root CA')")
}

// TestServerCertificateExists tests that server certificate is properly created
func (s *CertificateTestSuite) TestServerCertificateExists() {
	serverCerts, err := s.env.GetCertificateInfo(cert.CertificateTypeServer)
	s.NoError(err, "Should be able to retrieve server certificates")
	s.GreaterOrEqual(len(serverCerts), 1, "Should have at least one server certificate")

	// The controller generates a server certificate for the gRPC transport layer
	// Find it by checking for "cfgms-grpc-server" common name
	var serverCert *cert.CertificateInfo
	for _, certInfo := range serverCerts {
		if certInfo.CommonName == "cfgms-grpc-server" {
			serverCert = certInfo
			break
		}
	}

	s.NotNil(serverCert, "Should find server certificate")
	s.Equal(cert.CertificateTypeServer, serverCert.Type, "Certificate should be server type")
	s.True(serverCert.IsValid, "Server certificate should be valid")
	s.True(serverCert.ExpiresAt.After(time.Now()), "Server certificate should not be expired")
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
	})
	s.NoError(err, "Should be able to generate new client certificate")
	s.NotNil(newClientCert, "New client certificate should not be nil")
	s.Equal("test-steward-2", newClientCert.CommonName, "New certificate should have correct common name")
	s.True(newClientCert.IsValid, "New certificate should be valid")

	// Verify that test-steward-2 certificate exists in the manager
	clientCerts, err := s.env.GetCertificateInfo(cert.CertificateTypeClient)
	s.NoError(err, "Should be able to retrieve client certificates")

	// Find the test-steward-2 certificate we just generated
	var foundNewCert bool
	for _, certInfo := range clientCerts {
		if certInfo.CommonName == "test-steward-2" {
			foundNewCert = true
			break
		}
	}
	s.True(foundNewCert, "Should find the newly generated test-steward-2 certificate")
}

// TestCertificateValidation tests certificate validation functionality
func (s *CertificateTestSuite) TestCertificateValidation() {
	certManager := s.env.GetCertificateManager()

	// Get the server certificate
	serverCerts, err := s.env.GetCertificateInfo(cert.CertificateTypeServer)
	s.NoError(err, "Should be able to retrieve server certificates")
	s.GreaterOrEqual(len(serverCerts), 1, "Should have at least one server certificate")

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

// TestCertificatePersistenceAcrossReboots validates that certificates persist and reload correctly
// This test explicitly validates the production controller reboot scenario
func (s *CertificateTestSuite) TestCertificatePersistenceAcrossReboots() {
	// Get certificate info from first "boot"
	certManager1 := s.env.GetCertificateManager()
	caCerts1, err := certManager1.GetCertificatesByType(cert.CertificateTypeCA)
	s.NoError(err, "Should retrieve CA certificates")
	s.Len(caCerts1, 1, "Should have exactly one CA certificate")
	originalCASerial := caCerts1[0].SerialNumber

	serverCerts1, err := certManager1.GetCertificatesByType(cert.CertificateTypeServer)
	s.NoError(err, "Should retrieve server certificates")
	s.GreaterOrEqual(len(serverCerts1), 1, "Should have at least one server certificate")
	// Track the primary gRPC server certificate serial across reboots
	originalServerSerial := serverCerts1[0].SerialNumber
	for _, c := range serverCerts1 {
		if c.CommonName == "cfgms-grpc-server" {
			originalServerSerial = c.SerialNumber
			break
		}
	}

	// Simulate controller reboot by creating new test environment with same cert storage
	// This validates that LoadExistingCA=true works correctly
	s.env.Reset()
	s.env = testutil.NewTestEnvWithSharedCerts(s.T(), s.sharedCertPath)

	// Verify certificates were reloaded, not regenerated
	certManager2 := s.env.GetCertificateManager()
	caCerts2, err := certManager2.GetCertificatesByType(cert.CertificateTypeCA)
	s.NoError(err, "Should retrieve CA certificates after reboot")
	s.Len(caCerts2, 1, "Should still have exactly one CA certificate after reboot")
	s.Equal(originalCASerial, caCerts2[0].SerialNumber, "CA certificate serial should be same after reboot (not regenerated)")

	serverCerts2, err := certManager2.GetCertificatesByType(cert.CertificateTypeServer)
	s.NoError(err, "Should retrieve server certificates after reboot")
	s.GreaterOrEqual(len(serverCerts2), 1, "Should have at least one server certificate after reboot")
	// Verify the primary server certificate was preserved (not regenerated)
	var serverCertFound bool
	for _, c := range serverCerts2 {
		if c.SerialNumber == originalServerSerial {
			serverCertFound = true
			break
		}
	}
	s.True(serverCertFound, "Server certificate serial should be same after reboot (not regenerated)")

	// Verify controller starts successfully with reloaded certificates
	s.env.Start()
	defer s.env.Stop()

	s.NotNil(s.env.Controller, "Controller should start with persisted certificates")
	s.NotEmpty(s.env.Controller.GetListenAddr(), "Controller should be listening")

	// Verify certificates are still valid after reboot
	err = s.env.ValidateCertificateSetup()
	s.NoError(err, "Certificate setup should remain valid after reboot")
}

func TestCertificateTestSuite(t *testing.T) {
	suite.Run(t, new(CertificateTestSuite))
}
