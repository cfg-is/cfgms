// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz

// Package controller contains Docker-based E2E tests for controller + steward deployment
// Validates single controller with connected steward (Tier 2)
package controller

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

// ControllerTestSuite validates single controller with connected steward
// Tests run in Docker containers with real binaries for production-realistic validation
type ControllerTestSuite struct {
	suite.Suite
	docker *DockerComposeHelper
}

func (s *ControllerTestSuite) SetupSuite() {
	if testing.Short() {
		s.T().Skip("Skipping controller E2E tests in short mode - requires Docker infrastructure")
	}

	s.docker = NewDockerComposeHelper()

	s.T().Log("Starting controller and steward in Docker...")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	err := s.docker.StartController(ctx)
	require.NoError(s.T(), err, "Failed to start controller")

	// Poll until controller is accepting connections (replaces hardcoded sleep)
	waitCtx, waitCancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer waitCancel()
	err = s.docker.WaitForControllerReady(waitCtx)
	require.NoError(s.T(), err, "Controller did not become ready in time")
}

func (s *ControllerTestSuite) TearDownSuite() {
	if s.docker != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()

		s.T().Log("Stopping controller and steward...")
		_ = s.docker.StopController(ctx)
	}
}

// TestControllerStartup validates that the controller starts and has logs
func (s *ControllerTestSuite) TestControllerStartup() {
	s.T().Log("Validating controller startup")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Controller container should be running
	assert.True(s.T(), s.docker.IsContainerRunning("controller-standalone"),
		"Controller container should be running")

	// Controller should have produced log output (proves it started)
	logs, err := s.docker.GetControllerLogs(ctx)
	require.NoError(s.T(), err, "Should be able to retrieve controller logs")
	assert.NotEmpty(s.T(), logs, "Controller should have produced log output")

	s.T().Log("Controller started successfully")
}

// TestControllerAPI validates that the controller HTTPS API is accessible
func (s *ControllerTestSuite) TestControllerAPI() {
	s.T().Log("Validating controller HTTPS API")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// The controller should respond to HTTPS requests
	// WaitForControllerReady already verified this, but we test explicitly here
	output, err := s.docker.CurlController(ctx, "/api/v1/register")
	// We expect the register endpoint to reject GET requests or require a body,
	// but the important thing is we got a response (not a connection refused)
	s.T().Logf("API response: err=%v, output=%s", err, output)

	// If curl succeeded (exit code 0), the HTTPS server is responding
	// Even error responses (400, 404, 405) prove the API is up
	assert.NoError(s.T(), err, "Controller HTTPS API should be reachable")

	s.T().Log("Controller HTTPS API is accessible")
}

// TestStewardContainer validates that the steward container is running and healthy
func (s *ControllerTestSuite) TestStewardContainer() {
	s.T().Log("Validating steward container")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Steward container should be running
	assert.True(s.T(), s.docker.IsContainerRunning("steward-standalone"),
		"Steward container should be running")

	// Steward should have produced log output (proves it started)
	logs, err := s.docker.GetStewardLogs(ctx)
	require.NoError(s.T(), err, "Should be able to retrieve steward logs")
	assert.NotEmpty(s.T(), logs, "Steward should have produced log output")

	// Steward should have registered storage/logging providers (proves initialization)
	assert.True(s.T(),
		strings.Contains(logs, "Registered") || strings.Contains(logs, "provider"),
		"Steward logs should show provider registration (proves initialization)")

	s.T().Log("Steward container validated")
}

// TestStorageInitialization validates that the controller initialized storage
func (s *ControllerTestSuite) TestStorageInitialization() {
	s.T().Log("Validating controller storage initialization")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// The health endpoint proves storage initialized - the controller cannot
	// start serving if storage initialization failed
	output, err := s.docker.CurlController(ctx, "/api/v1/health")
	require.NoError(s.T(), err, "Health endpoint should be reachable")
	assert.NotEmpty(s.T(), output, "Health endpoint should return status")

	// Check controller logs for storage initialization evidence
	logs, logErr := s.docker.GetControllerLogs(ctx)
	require.NoError(s.T(), logErr)
	assert.True(s.T(),
		strings.Contains(logs, "storage") || strings.Contains(logs, "Registered storage provider"),
		"Controller logs should show storage initialization")

	s.T().Log("Controller storage initialized (controller is serving requests)")
}

// TestModuleExecution validates that the steward workspace is available for module execution
func (s *ControllerTestSuite) TestModuleExecution() {
	s.T().Log("Validating module execution workspace on steward")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Verify /test-workspace directory exists in steward container
	output, err := s.docker.ExecInSteward(ctx, "test", "-d", "/test-workspace")
	assert.NoError(s.T(), err, "/test-workspace directory should exist in steward container")

	// Verify we can create and read a file (proves workspace is writable)
	_, err = s.docker.ExecInSteward(ctx, "sh", "-c",
		"echo 'controller-test-probe' > /test-workspace/.controller-test-probe && cat /test-workspace/.controller-test-probe")
	assert.NoError(s.T(), err, "Should be able to write and read files in /test-workspace")

	// Clean up probe file
	_, _ = s.docker.ExecInSteward(ctx, "rm", "-f", "/test-workspace/.controller-test-probe")

	s.T().Logf("Workspace check output: %s", output)
	s.T().Log("Module execution workspace validated")
}

// TestCertificateManagement validates that certificates are being managed
func (s *ControllerTestSuite) TestCertificateManagement() {
	s.T().Log("Validating certificate management")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Controller with cert manager enabled should have generated certificates
	// Check for CA certificate and steward certs in the controller's cert storage (CFGMS_CERT_PATH=/app/certs)
	output, err := s.docker.ExecInController(ctx, "sh", "-c",
		"find /app/certs -name 'ca.crt' -o -name 'ca.key' -o -name '*.pem' 2>/dev/null | head -10")
	s.T().Logf("Certificate files found: %s", output)

	require.NoError(s.T(), err, "Should be able to search cert directory")
	assert.NotEmpty(s.T(), strings.TrimSpace(output),
		"Controller should have generated certificate files in /app/certs")

	s.T().Log("Certificate management validated")
}

func TestController(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping controller E2E tests in short mode - requires Docker infrastructure")
	}
	suite.Run(t, new(ControllerTestSuite))
}
