// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 CFGMS Contributors

package controller

import (
	"context"
	"fmt"
	"os/exec"
)

// DockerComposeHelper manages Docker Compose operations for controller testing
type DockerComposeHelper struct {
	ComposeFile string
	ProjectName string
}

// NewDockerComposeHelper creates a new Docker Compose helper
// Uses the unified docker-compose.test.yml with --profile ha (includes controller-standalone)
func NewDockerComposeHelper() *DockerComposeHelper {
	return &DockerComposeHelper{
		ComposeFile: "../../../docker-compose.test.yml",
		ProjectName: "cfgms-test",
	}
}

// StartController starts the controller and connected steward using Docker Compose
func (h *DockerComposeHelper) StartController(ctx context.Context) error {
	// Step 0: Generate test credentials if not already present
	fmt.Println("Step 0/4: Ensuring test credentials are generated...")
	credCmd := exec.CommandContext(ctx, "bash", "-c", "cd ../../../ && ./scripts/generate-test-credentials.sh")
	credOutput, err := credCmd.CombinedOutput()
	if err != nil {
		fmt.Printf("Credential generation warnings: %s\n", string(credOutput))
	}

	// Step 1: Clean up any existing containers
	fmt.Println("Step 1/4: Cleaning up existing Docker resources...")
	cleanupCmd := exec.CommandContext(ctx, "docker", "compose",
		"-f", h.ComposeFile,
		"--env-file", "../../../.env.test",
		"-p", h.ProjectName,
		"--profile", "ha",
		"--profile", "timescale",
		"down", "-v", "--remove-orphans")

	cleanupOutput, err := cleanupCmd.CombinedOutput()
	if err != nil {
		fmt.Printf("Cleanup warnings (non-fatal): %s\n", string(cleanupOutput))
	}

	// Step 2: Build images
	fmt.Println("Step 2/4: Building Docker images...")
	buildCmd := exec.CommandContext(ctx, "docker", "compose",
		"-f", h.ComposeFile,
		"--env-file", "../../../.env.test",
		"-p", h.ProjectName,
		"--profile", "ha",
		"--profile", "timescale",
		"build", "--pull")

	buildOutput, err := buildCmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to build images: %w\nOutput: %s", err, string(buildOutput))
	}

	// Step 3: Start only controller-standalone and steward-standalone
	fmt.Println("Step 3/4: Starting controller and steward...")
	startCmd := exec.CommandContext(ctx, "docker", "compose",
		"-f", h.ComposeFile,
		"--env-file", "../../../.env.test",
		"-p", h.ProjectName,
		"up", "-d",
		"timescaledb-test",
		"controller-standalone",
		"steward-standalone")

	startOutput, err := startCmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to start controller: %w\nOutput: %s", err, string(startOutput))
	}

	fmt.Println("Step 4/4: Controller and steward started successfully")
	return nil
}

// StopController stops the controller and cleans up resources
func (h *DockerComposeHelper) StopController(ctx context.Context) error {
	fmt.Println("Stopping controller and cleaning up...")
	stopCmd := exec.CommandContext(ctx, "docker", "compose",
		"-f", h.ComposeFile,
		"-p", h.ProjectName,
		"down", "-v")

	stopOutput, err := stopCmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to stop controller: %w\nOutput: %s", err, string(stopOutput))
	}

	return nil
}

// ExecInController executes a command inside the controller container
func (h *DockerComposeHelper) ExecInController(ctx context.Context, command ...string) (string, error) {
	args := []string{"compose", "-f", h.ComposeFile, "--env-file", "../../../.env.test", "-p", h.ProjectName, "exec", "-T", "controller-standalone"}
	args = append(args, command...)

	cmd := exec.CommandContext(ctx, "docker", args...)
	output, err := cmd.CombinedOutput()
	return string(output), err
}

// ExecInSteward executes a command inside the steward container
func (h *DockerComposeHelper) ExecInSteward(ctx context.Context, command ...string) (string, error) {
	args := []string{"compose", "-f", h.ComposeFile, "--env-file", "../../../.env.test", "-p", h.ProjectName, "exec", "-T", "steward-standalone"}
	args = append(args, command...)

	cmd := exec.CommandContext(ctx, "docker", args...)
	output, err := cmd.CombinedOutput()
	return string(output), err
}

// GetControllerLogs retrieves logs from the controller container
func (h *DockerComposeHelper) GetControllerLogs(ctx context.Context) (string, error) {
	cmd := exec.CommandContext(ctx, "docker", "compose", "-f", h.ComposeFile, "--env-file", "../../../.env.test", "-p", h.ProjectName, "logs", "controller-standalone")
	output, err := cmd.CombinedOutput()
	return string(output), err
}

// GetStewardLogs retrieves logs from the steward container
func (h *DockerComposeHelper) GetStewardLogs(ctx context.Context) (string, error) {
	cmd := exec.CommandContext(ctx, "docker", "compose", "-f", h.ComposeFile, "--env-file", "../../../.env.test", "-p", h.ProjectName, "logs", "steward-standalone")
	output, err := cmd.CombinedOutput()
	return string(output), err
}

// CurlController makes an HTTP request to the controller API
func (h *DockerComposeHelper) CurlController(ctx context.Context, endpoint string) (string, error) {
	url := fmt.Sprintf("http://localhost:8080%s", endpoint)
	cmd := exec.CommandContext(ctx, "curl", "-s", url)
	output, err := cmd.CombinedOutput()
	return string(output), err
}
