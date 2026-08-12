// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

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
	// Step 1: Remove this suite's own container from a previous run.
	//
	// Scoped to steward-true-standalone. `down -v --remove-orphans` is
	// project-wide regardless of --profile: it tore down the HA cluster, the
	// shared database and the standalone controller belonging to
	// test/integration/{ha,controller,logging}, which run concurrently against
	// this same Compose project, and `-v` took their volumes with it.
	// #nosec G204 -- integration-only Docker Compose invocation; executable is
	// fixed and file/project arguments come from the local test harness.
	cleanupCmd := exec.CommandContext(ctx, "docker", "compose",
		"-f", h.ComposeFile,
		"-p", h.ProjectName,
		"--profile", "standalone",
		"rm", "-f", "-s", "-v", "steward-true-standalone")

	cleanupOutput, err := cleanupCmd.CombinedOutput()
	if err != nil {
		// Don't fail on cleanup errors - might not exist
		fmt.Printf("Cleanup warnings (non-fatal): %s\n", string(cleanupOutput))
	}

	// Step 2: Build the steward image
	fmt.Println("Step 2/3: Building steward Docker image...")
	// #nosec G204 -- integration-only Docker Compose invocation; executable is
	// fixed and file/project arguments come from the local test harness.
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
	// #nosec G204 -- integration-only Docker Compose invocation; executable is
	// fixed and file/project arguments come from the local test harness.
	startCmd := exec.CommandContext(ctx, "docker", "compose",
		"-f", h.ComposeFile,
		"-p", h.ProjectName,
		"--profile", "standalone",
		"up", "-d", "--force-recreate", "--no-deps", "steward-true-standalone")

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
	// #nosec G204 -- integration-only Docker Compose invocation; executable is
	// fixed and file/project arguments come from the local test harness.
	// Scoped for the same reason as the cleanup in StartStandalone.
	stopCmd := exec.CommandContext(ctx, "docker", "compose",
		"-f", h.ComposeFile,
		"-p", h.ProjectName,
		"--profile", "standalone",
		"rm", "-f", "-s", "-v", "steward-true-standalone")

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

	// #nosec G204 -- integration-only Docker invocation; args are assembled by
	// this isolated harness from its local Compose file and project name.
	cmd := exec.CommandContext(ctx, "docker", args...)
	output, err := cmd.CombinedOutput()
	return string(output), err
}

// GetLogs retrieves the standalone steward's log output.
//
// The steward runs with the file logging provider (CFGMS_LOG_PROVIDER=file), so
// its structured records go to CFGMS_LOG_DIR inside the container and its
// container stdout carries only a single startup banner. Reading the log files
// is therefore the only way to observe what the steward actually did; asserting
// against `docker compose logs` could only ever see that banner.
func (h *DockerComposeHelper) GetLogs(ctx context.Context) (string, error) {
	logs, err := h.ExecInContainer(ctx, "sh", "-c", "cat /tmp/cfgms/*.log")
	if err != nil {
		return logs, fmt.Errorf("failed to read steward log files: %w\nOutput: %s", err, logs)
	}
	return logs, nil
}
