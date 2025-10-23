// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 CFGMS Contributors
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
	// This test will be implemented when we have the mTLS communication
	// layer in place. For now, we'll just verify both components start
	// and stop properly.

	// Start both components
	s.env.Start()

	// Stop both components
	s.env.Stop()

	// Verify logs for startup and shutdown
	infoLogs := s.env.Logger.GetLogs("info")

	// Search for key log messages
	hasControllerStart := false
	hasControllerStop := false
	hasStewardStart := false
	hasStewardStop := false

	for _, log := range infoLogs {
		switch log.Message {
		case "Starting controller":
			hasControllerStart = true
		case "Stopping controller":
			hasControllerStop = true
		case "Starting steward in controller mode":
			hasStewardStart = true
		case "Stopping steward in controller mode":
			hasStewardStop = true
		}
	}

	s.True(hasControllerStart, "Controller should have logged startup")
	s.True(hasControllerStop, "Controller should have logged shutdown")
	s.True(hasStewardStart, "Steward should have logged startup")
	s.True(hasStewardStop, "Steward should have logged shutdown")
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
