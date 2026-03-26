// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package integration

import (
	"context"
	"os/exec"
	"testing"

	"github.com/stretchr/testify/suite"
)

// DockerIntegrationTestSuite tests against actual Docker containers.
// Transport-specific tests (TestStewardHeartbeat, TestStewardDNACollection,
// TestStewardStatusReporting, TestTransportPortAccessibility) have been removed
// as part of Phase 10.11 (Issue #522) — replaced by gRPC-over-QUIC transport.
// Equivalent validation is in test/integration/transport/.
type DockerIntegrationTestSuite struct {
	suite.Suite
}

func (s *DockerIntegrationTestSuite) SetupSuite() {
	// Skip in short mode - requires Docker infrastructure
	if testing.Short() {
		s.T().Skip("Skipping Docker integration tests in short mode - requires Docker infrastructure")
	}
}

// TestContainerHealth validates both containers are running
func (s *DockerIntegrationTestSuite) TestContainerHealth() {
	// Check controller is healthy
	ctx, cancel := context.WithTimeout(context.Background(), 5*1e9)
	defer cancel()

	cmd := exec.CommandContext(ctx, "docker", "ps", "--filter", "name=controller-standalone", "--filter", "health=healthy", "--format", "{{.Names}}")
	output, err := cmd.CombinedOutput()
	s.NoError(err, "Docker command should succeed")
	s.Contains(string(output), "controller-standalone", "Controller should be healthy")

	// Check steward is running (it may not have healthcheck)
	cmd = exec.CommandContext(ctx, "docker", "ps", "--filter", "name=steward-standalone", "--format", "{{.Names}}")
	output, err = cmd.CombinedOutput()
	s.NoError(err, "Docker command should succeed")
	s.Contains(string(output), "steward-standalone", "Steward should be running")
}

func TestDockerIntegration(t *testing.T) {
	// Skip in short mode - requires Docker infrastructure
	if testing.Short() {
		t.Skip("Skipping Docker integration tests in short mode - requires Docker infrastructure")
		return
	}

	suite.Run(t, new(DockerIntegrationTestSuite))
}
