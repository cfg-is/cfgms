//go:build commercial
// +build commercial

package ha

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// DockerComposeHelper manages Docker Compose operations for HA testing
type DockerComposeHelper struct {
	ComposeFile string
	ProjectName string
}

// NewDockerComposeHelper creates a new Docker Compose helper
// Uses the unified docker-compose.test.yml with --profile ha
func NewDockerComposeHelper() *DockerComposeHelper {
	return &DockerComposeHelper{
		ComposeFile: "../../../docker-compose.test.yml",  // Unified test configuration
		ProjectName: "cfgms-test",  // Use same project name as other integration tests
	}
}

// StartCluster starts the HA cluster using Docker Compose with --profile ha
func (h *DockerComposeHelper) StartCluster(ctx context.Context) error {
	// Step 0: Generate test credentials if not already present
	fmt.Println("Step 0/5: Ensuring test credentials are generated...")
	credCmd := exec.CommandContext(ctx, "bash", "-c", "cd ../../../ && ./scripts/generate-test-credentials.sh")
	credOutput, err := credCmd.CombinedOutput()
	if err != nil {
		fmt.Printf("Credential generation warnings: %s\n", string(credOutput))
	}

	// Step 1: Complete cleanup - remove all containers, networks, volumes, and images
	fmt.Println("Step 1/5: Cleaning up existing Docker resources...")
	cleanupCmd := exec.CommandContext(ctx, "docker", "compose",
		"-f", h.ComposeFile,
		"--env-file", "../../../.env.test",
		"-p", h.ProjectName,
		"--profile", "ha",
		"--profile", "timescale",  // Also include timescaledb-test
		"down", "-v", "--rmi", "all", "--remove-orphans")

	cleanupOutput, err := cleanupCmd.CombinedOutput()
	if err != nil {
		// Don't fail on cleanup errors - might not exist
		fmt.Printf("Cleanup warnings (non-fatal): %s\n", string(cleanupOutput))
	}

	// Step 2: Prune Docker build cache for this project to force complete rebuild
	fmt.Println("Step 2/5: Pruning Docker build cache...")
	pruneCmd := exec.CommandContext(ctx, "docker", "builder", "prune", "-f")
	pruneOutput, err := pruneCmd.CombinedOutput()
	if err != nil {
		fmt.Printf("Build cache prune warnings (non-fatal): %s\n", string(pruneOutput))
	}

	// Step 3: Build images from scratch with no cache
	fmt.Println("Step 3/5: Building fresh Docker images (no cache)...")
	buildCmd := exec.CommandContext(ctx, "docker", "compose",
		"-f", h.ComposeFile,
		"--env-file", "../../../.env.test",  // Use generated test credentials
		"-p", h.ProjectName,
		"--profile", "ha",
		"--profile", "timescale",
		"build", "--no-cache", "--pull")

	buildOutput, err := buildCmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to build images: %w\nOutput: %s", err, string(buildOutput))
	}

	// Step 4: Start the cluster with freshly built images and test credentials
	fmt.Println("Step 4/5: Starting HA cluster with credentials...")
	startCmd := exec.CommandContext(ctx, "docker", "compose",
		"-f", h.ComposeFile,
		"--env-file", "../../../.env.test",  // Use generated test credentials
		"-p", h.ProjectName,
		"--profile", "ha",
		"--profile", "timescale",
		"up", "-d", "--force-recreate")

	startOutput, err := startCmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to start cluster: %w\nOutput: %s", err, string(startOutput))
	}

	fmt.Println("Step 5/5: HA cluster started successfully with fresh images")
	return nil
}

// StopCluster stops the HA cluster and cleans up resources
func (h *DockerComposeHelper) StopCluster(ctx context.Context) error {
	cmd := exec.CommandContext(ctx, "docker", "compose",
		"-f", h.ComposeFile,
		"--env-file", "../../../.env.test",
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
	cmd := exec.CommandContext(ctx, "docker", "compose",
		"-f", h.ComposeFile,
		"--env-file", "../../../.env.test",
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
	cmd := exec.CommandContext(ctx, "docker", "compose",
		"-f", h.ComposeFile,
		"--env-file", "../../../.env.test",
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
	cmd := exec.CommandContext(ctx, "docker", "compose",
		"-f", h.ComposeFile,
		"--env-file", "../../../.env.test",
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
	cmd := exec.CommandContext(ctx, "docker", "compose",
		"-f", h.ComposeFile,
		"--env-file", "../../../.env.test",
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
	cmd := exec.CommandContext(ctx, "docker", "compose",
		"-f", h.ComposeFile,
		"--env-file", "../../../.env.test",
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
	cmd := exec.CommandContext(ctx, "docker", "compose",
		"-f", h.ComposeFile,
		"--env-file", "../../../.env.test",
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