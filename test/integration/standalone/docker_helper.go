// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 CFGMS Contributors

package standalone

import (
	"context"
	"fmt"
	"os/exec"
)

// DockerComposeHelper manages Docker Compose operations for standalone steward testing
type DockerComposeHelper struct {
	ComposeFile string
	ProjectName string
}

// NewDockerComposeHelper creates a new Docker Compose helper
// Uses the unified docker-compose.test.yml with --profile standalone
func NewDockerComposeHelper() *DockerComposeHelper {
	return &DockerComposeHelper{
		ComposeFile: "../../../docker-compose.test.yml", // Unified test configuration
		ProjectName: "cfgms-test",                       // Use same project name as other integration tests
	}
}

// StartStandalone starts the standalone steward using Docker Compose
func (h *DockerComposeHelper) StartStandalone(ctx context.Context) error {
	// Step 1: Clean up any existing containers
	fmt.Println("Step 1/3: Cleaning up existing Docker resources...")
	cleanupCmd := exec.CommandContext(ctx, "docker", "compose",
		"-f", h.ComposeFile,
		"-p", h.ProjectName,
		"--profile", "standalone",
		"down", "-v", "--remove-orphans")

	cleanupOutput, err := cleanupCmd.CombinedOutput()
	if err != nil {
		// Don't fail on cleanup errors - might not exist
		fmt.Printf("Cleanup warnings (non-fatal): %s\n", string(cleanupOutput))
	}

	// Step 2: Build the steward image
	fmt.Println("Step 2/3: Building steward Docker image...")
	buildCmd := exec.CommandContext(ctx, "docker", "compose",
		"-f", h.ComposeFile,
		"-p", h.ProjectName,
		"--profile", "standalone",
		"build", "--pull")

	buildOutput, err := buildCmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to build image: %w\nOutput: %s", err, string(buildOutput))
	}

	// Step 3: Start the standalone steward
	fmt.Println("Step 3/3: Starting standalone steward...")
	startCmd := exec.CommandContext(ctx, "docker", "compose",
		"-f", h.ComposeFile,
		"-p", h.ProjectName,
		"--profile", "standalone",
		"up", "-d")

	startOutput, err := startCmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to start standalone steward: %w\nOutput: %s", err, string(startOutput))
	}

	fmt.Println("Standalone steward started successfully")
	return nil
}

// StopStandalone stops the standalone steward and cleans up resources
func (h *DockerComposeHelper) StopStandalone(ctx context.Context) error {
	fmt.Println("Stopping standalone steward and cleaning up...")
	stopCmd := exec.CommandContext(ctx, "docker", "compose",
		"-f", h.ComposeFile,
		"-p", h.ProjectName,
		"--profile", "standalone",
		"down", "-v")

	stopOutput, err := stopCmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to stop standalone: %w\nOutput: %s", err, string(stopOutput))
	}

	return nil
}

// ExecInContainer executes a command inside the standalone steward container
func (h *DockerComposeHelper) ExecInContainer(ctx context.Context, command ...string) (string, error) {
	args := []string{"compose", "-f", h.ComposeFile, "-p", h.ProjectName, "exec", "-T", "steward-true-standalone"}
	args = append(args, command...)

	cmd := exec.CommandContext(ctx, "docker", args...)
	output, err := cmd.CombinedOutput()
	return string(output), err
}

// GetLogs retrieves logs from the standalone steward container
func (h *DockerComposeHelper) GetLogs(ctx context.Context) (string, error) {
	cmd := exec.CommandContext(ctx, "docker", "compose", "-f", h.ComposeFile, "-p", h.ProjectName, "logs", "steward-true-standalone")
	output, err := cmd.CombinedOutput()
	return string(output), err
}
