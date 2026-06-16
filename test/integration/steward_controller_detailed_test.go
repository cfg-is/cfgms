// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package integration

import (
	"testing"
	"time"

	"github.com/stretchr/testify/suite"

	"github.com/cfgis/cfgms/pkg/cert"
	"github.com/cfgis/cfgms/test/integration/testutil"
)

// DetailedIntegrationTestSuite provides comprehensive steward-controller integration tests.
//
// Architecture note: the controller and transport client run in the same Go process.
// The gRPC data plane provider is a process-level singleton; when the controller starts
// it in server mode, the transport client cannot start it again in client mode. Full
// QUIC connection testing therefore lives in the E2E suite (test/e2e/), where controller
// and steward run in separate processes. These tests focus on the parts that can be
// exercised in-process: controller startup, certificate configuration, transport client
// creation, and error resilience.
type DetailedIntegrationTestSuite struct {
	suite.Suite
	env *testutil.TestEnv
}

func (s *DetailedIntegrationTestSuite) SetupSuite() {
	s.env = testutil.NewTestEnv(s.T())
}

func (s *DetailedIntegrationTestSuite) TearDownSuite() {
	s.env.Cleanup()
}

func (s *DetailedIntegrationTestSuite) SetupTest() {
	s.env.Reset()
}

// TestHeartbeatProcessing validates the controller-side infrastructure that heartbeats
// depend on: the controller starts, transport client is created without error, and the
// connection attempt exercises the TLS / control-plane initialization path.
//
// Full heartbeat round-trip (steward → controller) requires separate processes and is
// covered by the E2E test suite.
func (s *DetailedIntegrationTestSuite) TestHeartbeatProcessing() {
	// Start controller
	s.env.Start()

	// Allow initialization to settle
	time.Sleep(2 * time.Second)

	// Stop components
	s.env.Stop()

	// The transport client was created and a connection was attempted.
	// Verify the controller was running (has a certificate manager initialized).
	certMgr := s.env.CertManager
	s.NotNil(certMgr, "Controller certificate manager should be initialized")

	// No panic or fatal log should have occurred during the connection attempt
	errorLogs := s.env.Logger.GetLogs("error")
	for _, log := range errorLogs {
		s.NotContains(log.Message, "panic", "No panics should occur during connection attempt")
		s.NotContains(log.Message, "fatal", "No fatal errors should occur during connection attempt")
	}
}

// TestDNASynchronization validates that the transport layer infrastructure needed for
// DNA sync is present. DNA collection runs in the standalone steward convergence loop;
// reporting to the controller uses the gRPC data plane transport.
//
// This test verifies: controller starts, transport client is created with the correct
// CA so TLS verification would succeed in a separate-process scenario.
func (s *DetailedIntegrationTestSuite) TestDNASynchronization() {
	// Start controller and create transport client
	s.env.Start()

	// Allow initialization
	time.Sleep(1 * time.Second)

	// Stop components
	s.env.Stop()

	// Verify certificate setup is valid — this is the prerequisite for DNA sync TLS
	err := s.env.ValidateCertificateSetup()
	s.NoError(err, "Certificate setup should be valid (prerequisite for DNA sync TLS)")

	// TransportClient was created — verify it was constructed
	// (Start() fatals the test if creation fails, so reaching here means it succeeded)
	s.T().Log("TransportClient created successfully — DNA sync transport infrastructure is available")
}

// TestMTLSAuthentication validates that mTLS certificates are correctly configured.
// The transport client is created with the CA cert from the controller's cert manager,
// meaning it would successfully verify the controller's server cert in a separate-process
// scenario. In-process QUIC connection is not possible because the global data plane
// provider is already in server mode (started by the controller).
func (s *DetailedIntegrationTestSuite) TestMTLSAuthentication() {
	// Verify certificates are properly configured
	err := s.env.ValidateCertificateSetup()
	s.NoError(err, "Certificate setup should be valid for mTLS authentication")

	// Start controller
	s.env.Start()

	// Allow time for initialization
	time.Sleep(500 * time.Millisecond)

	// Stop components
	s.env.Stop()

	// Verify CA, server, and client certs are all present and valid
	caCerts, err := s.env.GetCertificateInfo(cert.CertificateTypeCA)
	s.NoError(err, "Should be able to query CA certificates")
	s.NotEmpty(caCerts, "CA certificate should be present")

	serverCerts, err := s.env.GetCertificateInfo(cert.CertificateTypeInternalServer)
	s.NoError(err, "Should be able to query internal server certificates")
	s.NotEmpty(serverCerts, "Internal server certificate should be present")

	clientCerts, err := s.env.GetCertificateInfo(cert.CertificateTypeClient)
	s.NoError(err, "Should be able to query client certificates")
	s.NotEmpty(clientCerts, "Client certificate should be present for mTLS")

	// Confirm no TLS-related errors logged
	errorLogs := s.env.Logger.GetLogs("error")
	for _, log := range errorLogs {
		s.NotContains(log.Message, "Certificate verification failed",
			"No certificate verification failures expected")
		s.NotContains(log.Message, "TLS handshake failed",
			"No TLS handshake failures expected")
	}
}

// TestErrorHandlingAndResilience validates that the controller survives a start/stop/start cycle.
func (s *DetailedIntegrationTestSuite) TestErrorHandlingAndResilience() {
	// Cycle 1: normal startup and shutdown
	s.env.Start()
	s.env.Stop()

	// Cycle 2: restart after clean stop
	s.env.Reset()
	s.env.Start()
	s.env.Stop()

	// Verify no panic or fatal errors occurred across both cycles
	errorLogs := s.env.Logger.GetLogs("error")
	for _, log := range errorLogs {
		s.NotContains(log.Message, "panic")
		s.NotContains(log.Message, "fatal")
	}
}

func TestDetailedIntegration(t *testing.T) {
	suite.Run(t, new(DetailedIntegrationTestSuite))
}
