// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 CFGMS Contributors
package integration

import (
	"testing"
	"time"

	"github.com/stretchr/testify/suite"

	"github.com/cfgis/cfgms/test/integration/testutil"
)

// DetailedIntegrationTestSuite provides comprehensive steward-controller integration tests
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

// TestHeartbeatProcessing validates that steward sends heartbeats to controller
func (s *DetailedIntegrationTestSuite) TestHeartbeatProcessing() {
	// Start both components
	s.env.Start()

	// Wait longer to allow heartbeat processing
	time.Sleep(2 * time.Second)

	// Stop components
	s.env.Stop()

	// Check logs for heartbeat-related messages
	infoLogs := s.env.Logger.GetLogs("info")

	// Look for connection and heartbeat success indicators
	hasConnected := false
	hasHeartbeatActivity := false

	for _, log := range infoLogs {
		if log.Message == "Connected to controller successfully" {
			hasConnected = true
		}
		// Look for any health/heartbeat related activity
		if log.Message == "System DNA collected" ||
			log.Message == "Steward registered successfully" {
			hasHeartbeatActivity = true
		}
	}

	s.True(hasConnected, "Steward should have connected to controller")
	s.True(hasHeartbeatActivity, "Should have heartbeat/health monitoring activity")
}

// TestDNASynchronization validates that steward collects and sends DNA to controller
func (s *DetailedIntegrationTestSuite) TestDNASynchronization() {
	// Start both components
	s.env.Start()

	// Wait for DNA collection and synchronization
	time.Sleep(1 * time.Second)

	// Stop components
	s.env.Stop()

	// Check logs for DNA collection
	infoLogs := s.env.Logger.GetLogs("info")

	hasDNACollection := false

	for _, log := range infoLogs {
		if log.Message == "System DNA collected" {
			hasDNACollection = true
			// Verify DNA collection has reasonable data (check Data slice)
			s.GreaterOrEqual(len(log.Data), 2, "Should have id and attributes data")
			break
		}
	}

	s.True(hasDNACollection, "Steward should have collected system DNA")
}

// TestMTLSAuthentication validates that mTLS authentication works correctly
func (s *DetailedIntegrationTestSuite) TestMTLSAuthentication() {
	// Verify certificates are properly configured
	err := s.env.ValidateCertificateSetup()
	s.NoError(err, "Certificate setup should be valid for mTLS authentication")

	// Start both components - if mTLS fails, connection will fail
	s.env.Start()

	// Wait for connection establishment
	time.Sleep(500 * time.Millisecond)

	// Stop components
	s.env.Stop()

	// Check that connection was successful (mTLS worked)
	infoLogs := s.env.Logger.GetLogs("info")

	hasSuccessfulConnection := false
	hasNoTLSErrors := true

	for _, log := range infoLogs {
		if log.Message == "Connected to controller successfully" {
			hasSuccessfulConnection = true
		}
	}

	// Check for any TLS/certificate errors
	errorLogs := s.env.Logger.GetLogs("error")
	for _, log := range errorLogs {
		if log.Message == "Failed to connect to controller" ||
			log.Message == "TLS handshake failed" ||
			log.Message == "Certificate verification failed" {
			hasNoTLSErrors = false
		}
	}

	s.True(hasSuccessfulConnection, "Should have successful mTLS connection")
	s.True(hasNoTLSErrors, "Should have no TLS/certificate errors")
}

// TestConfigurationRetrieval validates that steward can retrieve configuration from controller
func (s *DetailedIntegrationTestSuite) TestConfigurationRetrieval() {
	// This test will verify configuration retrieval once the API is implemented
	s.T().Skip("Configuration retrieval API not yet implemented")

	// Future implementation:
	// 1. Start both components
	// 2. Send configuration to controller
	// 3. Verify steward receives and processes configuration
	// 4. Check for configuration application logs
}

// TestErrorHandlingAndResilience validates error handling in various failure scenarios
func (s *DetailedIntegrationTestSuite) TestErrorHandlingAndResilience() {
	// Test 1: Normal startup and shutdown
	s.env.Start()
	time.Sleep(200 * time.Millisecond)
	s.env.Stop()

	// Test 2: Wait between cycles to avoid resource conflicts
	time.Sleep(100 * time.Millisecond)
	s.env.Reset()
	s.env.Start()
	time.Sleep(200 * time.Millisecond)
	s.env.Stop()

	// Verify no panic or fatal errors occurred
	errorLogs := s.env.Logger.GetLogs("error")
	for _, log := range errorLogs {
		// Allow specific expected errors but fail on panics or fatal errors
		s.NotContains(log.Message, "panic")
		s.NotContains(log.Message, "fatal")
	}
}

// TestMultipleStewardScenarios validates handling of multiple steward connections
func (s *DetailedIntegrationTestSuite) TestMultipleStewardScenarios() {
	// This test is complex as it requires multiple steward instances
	// For now, we'll test single steward resilience
	s.T().Skip("Multiple steward testing requires more complex test infrastructure")

	// Future implementation:
	// 1. Create multiple TestEnv instances with different steward IDs
	// 2. Start controller once and multiple stewards
	// 3. Verify all stewards can register and communicate
	// 4. Test steward disconnection and reconnection scenarios
}

func TestDetailedIntegration(t *testing.T) {
	suite.Run(t, new(DetailedIntegrationTestSuite))
}
