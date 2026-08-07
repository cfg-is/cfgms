// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package ha

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// DockerComposeHelper manages Docker Compose operations for HA testing
type DockerComposeHelper struct {
	ComposeFile string
	ProjectName string
}

// prepareTimeout bounds the one-time credential generation and image build.
// The suite runs under a 10-minute binary timeout in CI, so an unresponsive
// Docker daemon must surface as a named error with a diagnosable message
// rather than consuming the whole budget inside exec.Cmd.Wait.
const prepareTimeout = 8 * time.Minute

var (
	prepareOnce sync.Once
	prepareErr  error
)

// ensurePrepared generates test credentials and builds the Compose images at
// most once per test binary.
//
// Image builds are the dominant cost in this suite: a cold build of the
// controller image takes minutes, and every test calls StartCluster. Building
// per test made the cumulative Docker time exceed the binary timeout, so the
// build is hoisted here behind a sync.Once and reuses the layer cache. Cluster
// lifecycle (down/up) stays per test, which preserves the isolation each test
// relies on at container-start cost rather than image-build cost.
func (h *DockerComposeHelper) ensurePrepared() error {
	prepareOnce.Do(func() {
		prepareErr = h.prepare()
	})
	return prepareErr
}

func (h *DockerComposeHelper) prepare() error {
	ctx, cancel := context.WithTimeout(context.Background(), prepareTimeout)
	defer cancel()

	if err := h.ensureCredentials(ctx); err != nil {
		return err
	}

	fmt.Println("HA test setup: building Compose images (once per test binary)...")
	// #nosec G204 -- integration-only Docker Compose invocation; executable is
	// fixed and all variable arguments are owned by the local HA test harness.
	buildCmd := exec.CommandContext(ctx, "docker", "compose",
		"-f", h.ComposeFile,
		"--env-file", h.envFile(),
		"-p", h.ProjectName,
		"--profile", "ha",
		"--profile", "timescale",
		"build")

	buildOutput, err := buildCmd.CombinedOutput()
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return fmt.Errorf("image build did not finish within %v (%w)\nOutput: %s",
				prepareTimeout, ctxErr, string(buildOutput))
		}
		return fmt.Errorf("failed to build images: %w\nOutput: %s", err, string(buildOutput))
	}

	fmt.Println("HA test setup: Compose images ready")
	return nil
}

// ensureCredentials generates .env.test only when it is absent. CI generates it
// before the suite runs and exports the same values into the test process
// environment; regenerating would rotate the passwords out from under those
// exported values.
func (h *DockerComposeHelper) ensureCredentials(ctx context.Context) error {
	if _, err := os.Stat(h.envFile()); err == nil {
		return nil
	}

	fmt.Println("HA test setup: generating test credentials...")
	credCmd := exec.CommandContext(ctx, "./scripts/generate-test-credentials.sh")
	credCmd.Dir = h.repoRoot()
	if output, err := credCmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to generate test credentials: %w\nOutput: %s", err, string(output))
	}
	return nil
}

// repoRoot returns the repository root relative to the package directory, which
// is where `go test` runs this suite from.
func (h *DockerComposeHelper) repoRoot() string {
	return filepath.Join("..", "..", "..")
}

// envFile returns the path to the generated Compose environment file.
func (h *DockerComposeHelper) envFile() string {
	return filepath.Join(h.repoRoot(), ".env.test")
}

// NewDockerComposeHelper creates a new Docker Compose helper
// Uses the unified docker-compose.test.yml with --profile ha
func NewDockerComposeHelper() *DockerComposeHelper {
	return &DockerComposeHelper{
		ComposeFile: "../../../docker-compose.test.yml", // Unified test configuration
		ProjectName: "cfgms-test",                       // Use same project name as other integration tests
	}
}

// StartCluster starts the HA cluster using Docker Compose with --profile ha.
//
// Credentials and images are prepared once per test binary (see ensurePrepared);
// each call then recreates the containers so the test gets a cluster with empty
// volumes and freshly started controllers.
func (h *DockerComposeHelper) StartCluster(ctx context.Context) error {
	// Step 1: one-time credential generation and image build.
	fmt.Println("Step 1/3: Ensuring credentials and images are prepared...")
	if err := h.ensurePrepared(); err != nil {
		return err
	}

	// Step 2: drop containers, networks and volumes left by a previous test.
	// Images are deliberately kept (no --rmi) so the build from step 1 is
	// reused for every test in the package.
	fmt.Println("Step 2/3: Removing containers and volumes from previous tests...")
	// #nosec G204 -- integration-only Docker Compose invocation; executable is
	// fixed and all variable arguments are owned by the local HA test harness.
	cleanupCmd := exec.CommandContext(ctx, "docker", "compose",
		"-f", h.ComposeFile,
		"--env-file", h.envFile(),
		"-p", h.ProjectName,
		"--profile", "ha",
		"--profile", "timescale", // Also include timescaledb-test
		"down", "-v", "--remove-orphans")

	cleanupOutput, err := cleanupCmd.CombinedOutput()
	if err != nil {
		// Don't fail on cleanup errors - might not exist
		fmt.Printf("Cleanup warnings (non-fatal): %s\n", string(cleanupOutput))
	}

	// Step 3: Start the cluster from the prepared images and test credentials
	fmt.Println("Step 3/3: Starting HA cluster with credentials...")
	// #nosec G204 -- integration-only Docker Compose invocation; executable is
	// fixed and all variable arguments are owned by the local HA test harness.
	startCmd := exec.CommandContext(ctx, "docker", "compose",
		"-f", h.ComposeFile,
		"--env-file", h.envFile(),
		"-p", h.ProjectName,
		"--profile", "ha",
		"--profile", "timescale",
		"up", "-d", "--force-recreate")

	startOutput, err := startCmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to start cluster: %w\nOutput: %s", err, string(startOutput))
	}

	fmt.Println("HA cluster started")
	return nil
}

// StopCluster stops the HA cluster and cleans up resources
func (h *DockerComposeHelper) StopCluster(ctx context.Context) error {
	// #nosec G204 -- integration-only Docker Compose invocation; executable is
	// fixed and all variable arguments are owned by the local HA test harness.
	cmd := exec.CommandContext(ctx, "docker", "compose",
		"-f", h.ComposeFile,
		"--env-file", h.envFile(),
		"-p", h.ProjectName,
		"--profile", "ha",
		"--profile", "timescale",
		"down", "-v", "--remove-orphans")

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to stop cluster: %w\nOutput: %s", err, string(output))
	}

	return nil
}

// GetContainerLogs retrieves logs from a specific container
func (h *DockerComposeHelper) GetContainerLogs(ctx context.Context, service string) (string, error) {
	// #nosec G204 -- integration-only Docker Compose logs invocation; service
	// names are local harness inputs and no shell interprets them.
	cmd := exec.CommandContext(ctx, "docker", "compose",
		"-f", h.ComposeFile,
		"--env-file", h.envFile(),
		"-p", h.ProjectName,
		"logs", service)

	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to get logs for %s: %w", service, err)
	}

	return string(output), nil
}

// GetStewardLogs retrieves logs from a steward container with filtering
func (h *DockerComposeHelper) GetStewardLogs(ctx context.Context, stewardName string, lines int) (string, error) {
	// #nosec G204 -- integration-only Docker Compose logs invocation; steward
	// name/count are local harness inputs and no shell interprets them.
	cmd := exec.CommandContext(ctx, "docker", "compose",
		"-f", h.ComposeFile,
		"--env-file", h.envFile(),
		"-p", h.ProjectName,
		"logs", "--tail", fmt.Sprintf("%d", lines), stewardName)

	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to get steward logs for %s: %w", stewardName, err)
	}

	return string(output), nil
}

// CheckStewardConnection checks if a steward is connected to controllers
func (h *DockerComposeHelper) CheckStewardConnection(ctx context.Context, stewardName string) (bool, string, error) {
	logs, err := h.GetStewardLogs(ctx, stewardName, 50)
	if err != nil {
		return false, "", err
	}

	// Look for connection indicators in logs
	if strings.Contains(logs, "Connected to controller") ||
		strings.Contains(logs, "gRPC connection established") ||
		strings.Contains(logs, "Heartbeat successful") {

		// Extract controller connection info from logs
		lines := strings.Split(logs, "\n")
		for _, line := range lines {
			if strings.Contains(line, "Connected to controller") {
				// Extract controller name from log line
				parts := strings.Fields(line)
				for i, part := range parts {
					if part == "controller" && i+1 < len(parts) {
						return true, parts[i+1], nil
					}
				}
			}
		}

		return true, "unknown", nil
	}

	return false, "", nil
}

// WaitForStewardConnections waits for all stewards to connect to controllers
func (h *DockerComposeHelper) WaitForStewardConnections(ctx context.Context, timeout time.Duration, stewards ...string) error {
	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		allConnected := true
		for _, steward := range stewards {
			connected, _, err := h.CheckStewardConnection(ctx, steward)
			if err != nil || !connected {
				allConnected = false
				break
			}
		}

		if allConnected {
			return nil
		}

		time.Sleep(2 * time.Second)
	}

	return fmt.Errorf("stewards did not connect within %v", timeout)
}

// StopService stops a specific service in the cluster
func (h *DockerComposeHelper) StopService(ctx context.Context, service string) error {
	// #nosec G204 -- integration-only Docker Compose invocation; service is a
	// harness-selected Compose service and no shell interprets it.
	cmd := exec.CommandContext(ctx, "docker", "compose",
		"-f", h.ComposeFile,
		"--env-file", h.envFile(),
		"-p", h.ProjectName,
		"stop", service)

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to stop %s: %w\nOutput: %s", service, err, string(output))
	}

	return nil
}

// RestartService restarts a specific service in the cluster
func (h *DockerComposeHelper) RestartService(ctx context.Context, service string) error {
	// #nosec G204 -- integration-only Docker Compose invocation; service is a
	// harness-selected Compose service and no shell interprets it.
	cmd := exec.CommandContext(ctx, "docker", "compose",
		"-f", h.ComposeFile,
		"--env-file", h.envFile(),
		"-p", h.ProjectName,
		"restart", service)

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to restart %s: %w\nOutput: %s", service, err, string(output))
	}

	return nil
}

// ScaleService scales a service to the specified number of replicas
func (h *DockerComposeHelper) ScaleService(ctx context.Context, service string, replicas int) error {
	// #nosec G204 -- integration-only Docker Compose invocation; scale inputs
	// are local test values passed without a shell.
	cmd := exec.CommandContext(ctx, "docker", "compose",
		"-f", h.ComposeFile,
		"--env-file", h.envFile(),
		"-p", h.ProjectName,
		"up", "-d", "--scale", fmt.Sprintf("%s=%d", service, replicas))

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to scale %s to %d: %w\nOutput: %s", service, replicas, err, string(output))
	}

	return nil
}

// GetServiceStatus checks if all specified services are running
func (h *DockerComposeHelper) GetServiceStatus(ctx context.Context, services ...string) (map[string]bool, error) {
	// #nosec G204 -- integration-only Docker Compose status invocation with a
	// fixed argument vector; requested services are filtered in Go afterward.
	cmd := exec.CommandContext(ctx, "docker", "compose",
		"-f", h.ComposeFile,
		"--env-file", h.envFile(),
		"-p", h.ProjectName,
		"ps", "--services", "--filter", "status=running")

	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to get service status: %w", err)
	}

	runningServices := make(map[string]bool)
	for _, service := range services {
		runningServices[service] = false
	}

	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" {
			runningServices[line] = true
		}
	}

	return runningServices, nil
}

// WaitForServices waits for all specified services to be running
func (h *DockerComposeHelper) WaitForServices(ctx context.Context, timeout time.Duration, services ...string) error {
	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		status, err := h.GetServiceStatus(ctx, services...)
		if err != nil {
			time.Sleep(2 * time.Second)
			continue
		}

		allRunning := true
		for _, service := range services {
			if !status[service] {
				allRunning = false
				break
			}
		}

		if allRunning {
			return nil
		}

		time.Sleep(2 * time.Second)
	}

	return fmt.Errorf("services did not start within %v", timeout)
}

// SimulateNetworkPartition creates a network partition between regions
func (h *DockerComposeHelper) SimulateNetworkPartition(ctx context.Context, isolatedService string) error {
	// Use the chaos-network container to create network partitions
	cmd := exec.CommandContext(ctx, "docker", "exec", "cfgms-chaos-network",
		"iptables", "-A", "INPUT", "-s", "172.21.1.20,172.21.1.21,172.21.1.22", "-j", "DROP")

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to create network partition: %w\nOutput: %s", err, string(output))
	}

	return nil
}

// RestoreNetwork removes network partitions
func (h *DockerComposeHelper) RestoreNetwork(ctx context.Context) error {
	// Clear all iptables rules to restore network
	cmd := exec.CommandContext(ctx, "docker", "exec", "cfgms-chaos-network",
		"iptables", "-F")

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to restore network: %w\nOutput: %s", err, string(output))
	}

	return nil
}
