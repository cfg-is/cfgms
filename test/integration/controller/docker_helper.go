// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz

package controller

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// DockerComposeHelper manages Docker Compose operations for controller testing
type DockerComposeHelper struct {
	ComposeFile    string
	ProjectName    string
	startedBySuite bool // true if this suite started the containers (vs CI/make target)
}

// NewDockerComposeHelper creates a new Docker Compose helper
// Uses the unified docker-compose.test.yml with --profile ha (includes controller-standalone)
func NewDockerComposeHelper() *DockerComposeHelper {
	return &DockerComposeHelper{
		ComposeFile: "../../../docker-compose.test.yml",
		ProjectName: "cfgms-test",
	}
}

// IsInfrastructureRunning checks if the required Docker containers are already running
// (e.g., started by CI workflow or make test-mqtt-quic-setup)
func (h *DockerComposeHelper) IsInfrastructureRunning() bool {
	cmd := exec.Command("docker", "ps", "--filter", "name=controller-standalone",
		"--filter", "name=steward-standalone", "--filter", "name=cfgms-timescaledb-test",
		"--format", "{{.Names}}")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return false
	}
	names := string(output)
	return strings.Contains(names, "controller-standalone") &&
		strings.Contains(names, "steward-standalone") &&
		strings.Contains(names, "cfgms-timescaledb-test")
}

// StartController starts the controller and connected steward using Docker Compose.
// If infrastructure is already running (CI or make target), this is a no-op.
func (h *DockerComposeHelper) StartController(ctx context.Context) error {
	if h.IsInfrastructureRunning() {
		fmt.Println("Found existing infrastructure (likely started by CI/make target)")
		h.startedBySuite = false
		return nil
	}

	h.startedBySuite = true

	// Generate test credentials if not already present
	fmt.Println("Step 1/3: Ensuring test credentials are generated...")
	credCmd := exec.CommandContext(ctx, "bash", "-c", "cd ../../../ && ./scripts/generate-test-credentials.sh")
	credOutput, err := credCmd.CombinedOutput()
	if err != nil {
		fmt.Printf("Credential generation warnings: %s\n", string(credOutput))
	}

	// Build and start containers
	fmt.Println("Step 2/3: Building Docker images...")
	buildCmd := exec.CommandContext(ctx, "docker", "compose",
		"-f", h.ComposeFile,
		"--env-file", "../../../.env.test",
		"-p", h.ProjectName,
		"--profile", "ha",
		"--profile", "timescale",
		"build")

	buildOutput, err := buildCmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to build images: %w\nOutput: %s", err, string(buildOutput))
	}

	fmt.Println("Step 3/3: Starting controller and steward...")
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

	return nil
}

// WaitForControllerReady polls until the controller is accepting HTTPS connections
// or the context deadline is exceeded.
func (h *DockerComposeHelper) WaitForControllerReady(ctx context.Context) error {
	fmt.Println("Waiting for controller to be ready...")
	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("timed out waiting for controller to be ready")
		default:
		}

		// Try to reach the controller's HTTPS endpoint
		checkCmd := exec.CommandContext(ctx, "curl", "-sk", "--max-time", "2",
			"-o", "/dev/null", "-w", "%{http_code}",
			"https://localhost:8080/health")
		output, err := checkCmd.CombinedOutput()
		if err == nil {
			code := strings.TrimSpace(string(output))
			if code == "200" || code == "404" {
				// 200 = health endpoint exists; 404 = server responding but no health route
				// Either way, the controller is accepting connections
				fmt.Printf("Controller ready (HTTP %s)\n", code)
				return nil
			}
		}

		time.Sleep(2 * time.Second)
	}
}

// StopController stops the controller and cleans up resources.
// Only stops if this suite started the containers.
func (h *DockerComposeHelper) StopController(ctx context.Context) error {
	if !h.startedBySuite {
		fmt.Println("Skipping container cleanup (containers managed externally)")
		return nil
	}

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
	args := []string{"exec", "controller-standalone"}
	args = append(args, command...)

	cmd := exec.CommandContext(ctx, "docker", args...)
	output, err := cmd.CombinedOutput()
	return string(output), err
}

// ExecInSteward executes a command inside the steward container
func (h *DockerComposeHelper) ExecInSteward(ctx context.Context, command ...string) (string, error) {
	args := []string{"exec", "steward-standalone"}
	args = append(args, command...)

	cmd := exec.CommandContext(ctx, "docker", args...)
	output, err := cmd.CombinedOutput()
	return string(output), err
}

// GetControllerLogs retrieves logs from the controller container
func (h *DockerComposeHelper) GetControllerLogs(ctx context.Context) (string, error) {
	cmd := exec.CommandContext(ctx, "docker", "logs", "controller-standalone")
	output, err := cmd.CombinedOutput()
	return string(output), err
}

// GetStewardLogs retrieves logs from the steward container
func (h *DockerComposeHelper) GetStewardLogs(ctx context.Context) (string, error) {
	cmd := exec.CommandContext(ctx, "docker", "logs", "steward-standalone")
	output, err := cmd.CombinedOutput()
	return string(output), err
}

// CurlController makes an HTTPS request to the controller API
// Uses -k to accept self-signed certificates from auto-generated cert manager
func (h *DockerComposeHelper) CurlController(ctx context.Context, endpoint string) (string, error) {
	url := fmt.Sprintf("https://localhost:8080%s", endpoint)
	cmd := exec.CommandContext(ctx, "curl", "-sk", "--max-time", "5", url)
	output, err := cmd.CombinedOutput()
	return string(output), err
}

// IsContainerRunning checks if a specific container is running
func (h *DockerComposeHelper) IsContainerRunning(containerName string) bool {
	cmd := exec.Command("docker", "inspect", "--format={{.State.Running}}", containerName)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(output)) == "true"
}
