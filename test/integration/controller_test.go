// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 CFGMS Contributors
package integration

import (
	"testing"

	"github.com/stretchr/testify/suite"

	"github.com/cfgis/cfgms/test/integration/testutil"
)

// ControllerTestSuite is a test suite for controller integration tests
type ControllerTestSuite struct {
	suite.Suite
	env *testutil.TestEnv
}

func (s *ControllerTestSuite) SetupSuite() {
	s.T().Skip("Skipping until Issue #294: E2E test framework for MQTT+QUIC mode not yet implemented - requires running controller with full infrastructure")
	// Create a new test environment for the suite
	s.env = testutil.NewTestEnv(s.T())
}

func (s *ControllerTestSuite) TearDownSuite() {
	// Clean up the test environment
	s.env.Cleanup()
}

func (s *ControllerTestSuite) SetupTest() {
	// Reset the test environment before each test
	s.env.Reset()
}

func (s *ControllerTestSuite) TearDownTest() {
	// Stop any running components
	// (only if they were started in the test)
}

func (s *ControllerTestSuite) TestControllerStartStop() {
	// Start the controller
	_ = s.env.Controller.Start(s.env.GetContext())

	// Verify the controller logged startup
	infoLogs := s.env.Logger.GetLogs("info")
	s.Require().GreaterOrEqual(len(infoLogs), 1)
	s.Require().Equal("Starting controller", infoLogs[0].Message)

	// Stop the controller
	_ = s.env.Controller.Stop(s.env.GetContext())

	// Verify the controller logged shutdown
	infoLogs = s.env.Logger.GetLogs("info")
	s.Require().GreaterOrEqual(len(infoLogs), 3)

	// Find the "Stopping controller" message
	found := false
	for _, log := range infoLogs {
		if log.Message == "Stopping controller" {
			found = true
			break
		}
	}
	s.Require().True(found, "Should have logged 'Stopping controller'")
}

func (s *ControllerTestSuite) TestStewardConnectToController() {
	// Skip: This test checks for specific log messages that are implementation details
	// and change frequently. It should be rewritten to test actual behavior:
	// - MQTT broker is listening and accepting connections
	// - QUIC server is listening and accepting connections
	// - Heartbeat monitoring is active
	// - Registration handler is responding
	// Instead of testing log message strings, test observable system behavior.
	s.T().Skip("Test needs rewrite: should test behavior (endpoints available, connections accepted) not log messages")
}

// This test will be implemented once we have the registration API
func (s *ControllerTestSuite) TestStewardRegistration() {
	s.T().Skip("This test will be implemented when the controller's registration API is ready")
}

func TestControllerIntegration(t *testing.T) {
	suite.Run(t, new(ControllerTestSuite))
}

// This test will be updated once the controller's registration API is implemented
func TestControllerRegistration(t *testing.T) {
	t.Skip("This test will be implemented when the controller's registration API is ready")
}
