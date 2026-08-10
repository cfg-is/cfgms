// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package ha

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// DockerComposeHelper manages Docker Compose operations for HA testing
type DockerComposeHelper struct {
	ComposeFile string
	ProjectName string
}

// haControllerServices are the Compose services that form the HA controller
// cluster. They carry the `ha` profile and their container names are unique to
// that profile, so this suite can own their lifecycle without touching the
// shared test infrastructure.
var haControllerServices = []string{"controller-east", "controller-central", "controller-west"}

// haSupportServices are the remaining `ha`-profile services started after the
// controllers are healthy: the stewards register against a controller, and the
// HA git server is addressed by the configuration-continuity tests.
var haSupportServices = []string{"steward-east", "steward-central", "steward-west", "git-server-ha"}

// sharedDatabaseContainer is the TimescaleDB container the HA controllers use.
// It carries the `timescale` profile and a fixed container_name, and the CI job
// starts it before the test binary runs (production-gates.yml,
// "Set up Docker test infrastructure" -> make test-integration-setup) under a
// different Compose project. Container names are global to the daemon, so any
// attempt by this suite to create it again fails the whole `up` with
// "Conflict. The container name /cfgms-timescaledb-test is already in use".
const sharedDatabaseContainer = "cfgms-timescaledb-test"

// sharedDatabaseService is the Compose service name for sharedDatabaseContainer.
const sharedDatabaseService = "timescaledb-test"

// prepareTimeout bounds the one-time credential generation and image build.
// The suite runs under a 10-minute binary timeout in CI, so an unresponsive
// Docker daemon must surface as a named error with a diagnosable message
// rather than consuming the whole budget inside exec.Cmd.Wait.
const prepareTimeout = 8 * time.Minute

// controllerReadyTimeout bounds `up --wait` for the three HA controllers and
// databaseReadyTimeout bounds it for the backing store. Both are passed to
// Compose as --wait-timeout so a container that never reports healthy fails the
// calling test with the Compose diagnostics instead of stalling until the test
// binary's own timeout fires.
const (
	controllerReadyTimeout = 3 * time.Minute
	databaseReadyTimeout   = 2 * time.Minute
)

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
// each call then recreates the `ha`-profile containers so the test gets freshly
// started controllers and stewards.
//
// Scope: only `ha`-profile services are created, recreated or removed, and every
// `up` runs with --no-deps. The shared TimescaleDB container is reused when it
// is already running (see ensureDatabase). Recreating the whole Compose project
// broke two things at once, both measured in merge-queue run 31202075054, job
// 92944227941 (2026-08-07):
//
//   - `up` aborted with "Conflict. The container name /cfgms-timescaledb-test is
//     already in use" because the CI job starts that container under a different
//     Compose project before the test binary runs, and a project-scoped `down`
//     cannot remove another project's container. Every StartCluster call in that
//     run failed this way.
//   - `down -v` on the shared project also removed the database, Gitea and
//     standalone-controller containers that test/integration/{controller,
//     standalone,transport} use concurrently in the same `go test ./...`
//     invocation.
func (h *DockerComposeHelper) StartCluster(ctx context.Context) error {
	// Step 1: one-time credential generation and image build.
	fmt.Println("Step 1/4: Ensuring credentials and images are prepared...")
	if err := h.ensurePrepared(); err != nil {
		return err
	}

	// Step 2: the controllers need their backing store before they start.
	fmt.Println("Step 2/4: Ensuring the TimescaleDB backing store is running...")
	if err := h.ensureDatabase(ctx); err != nil {
		return err
	}

	// Step 3: recreate the controllers and wait for their healthchecks. --wait
	// replaces the dependency ordering that --no-deps switches off, so the
	// stewards started in step 4 still find healthy controllers.
	fmt.Println("Step 3/4: Recreating HA controllers...")
	args := append([]string{
		// Both profiles are enabled so the Compose model resolves: the
		// controllers declare depends_on the `timescale`-profile database.
		// --no-deps then keeps this invocation from creating that database,
		// which ensureDatabase has already accounted for.
		"--profile", "ha",
		"--profile", "timescale",
		"up", "-d", "--force-recreate", "--no-deps",
		"--wait", "--wait-timeout", strconv.Itoa(int(controllerReadyTimeout.Seconds())),
	}, haControllerServices...)
	if output, err := h.compose(ctx, args...); err != nil {
		return fmt.Errorf("failed to start HA controllers: %w\nOutput: %s", err, output)
	}

	// Step 4: recreate the stewards and the HA git server against the
	// controllers that step 3 confirmed healthy.
	fmt.Println("Step 4/4: Recreating stewards and HA git server...")
	args = append([]string{
		"--profile", "ha",
		"--profile", "timescale",
		"up", "-d", "--force-recreate", "--no-deps",
	}, haSupportServices...)
	if output, err := h.compose(ctx, args...); err != nil {
		return fmt.Errorf("failed to start HA support services: %w\nOutput: %s", err, output)
	}

	fmt.Println("HA cluster started")
	return nil
}

// StopCluster stops and removes the HA services this suite owns.
//
// The shared TimescaleDB container is deliberately left running: it is started
// by the CI job (and by `make test-integration-setup` locally) for the whole
// integration suite, and removing it breaks the packages running alongside this
// one.
func (h *DockerComposeHelper) StopCluster(ctx context.Context) error {
	services := make([]string, 0, len(haSupportServices)+len(haControllerServices))
	services = append(services, haSupportServices...)
	services = append(services, haControllerServices...)

	args := append([]string{
		"--profile", "ha",
		"--profile", "timescale",
		"rm", "-f", "-s", "-v",
	}, services...)
	output, err := h.compose(ctx, args...)
	if err != nil {
		return fmt.Errorf("failed to stop HA services: %w\nOutput: %s", err, output)
	}

	return nil
}

// ensureDatabase makes sure the TimescaleDB container the HA controllers use is
// running, without recreating it when another Compose project owns it.
func (h *DockerComposeHelper) ensureDatabase(ctx context.Context) error {
	if containerRunning(ctx, sharedDatabaseContainer) {
		fmt.Printf("Reusing the running %s container\n", sharedDatabaseContainer)
		return nil
	}

	output, err := h.compose(ctx,
		"--profile", "timescale",
		"up", "-d", "--wait", "--wait-timeout", strconv.Itoa(int(databaseReadyTimeout.Seconds())),
		sharedDatabaseService)
	if err != nil {
		return fmt.Errorf("failed to start %s: %w\nOutput: %s", sharedDatabaseService, err, output)
	}
	return nil
}

// containerRunning reports whether a container with the given name exists and
// is running. A missing container makes `docker container inspect` exit
// non-zero, which is reported as "not running" rather than as an error.
func containerRunning(ctx context.Context, name string) bool {
	// #nosec G204 -- fixed argv; name is a package-level constant.
	cmd := exec.CommandContext(ctx, "docker", "container", "inspect", "-f", "{{.State.Running}}", name)
	output, err := cmd.Output()
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(output)) == "true"
}

// compose runs `docker compose` against this suite's file, env file and project
// and returns the combined output.
func (h *DockerComposeHelper) compose(ctx context.Context, args ...string) (string, error) {
	argv := append([]string{
		"compose",
		"-f", h.ComposeFile,
		"--env-file", h.envFile(),
		"-p", h.ProjectName,
	}, args...)

	// #nosec G204 -- integration-only Docker Compose invocation; executable is
	// fixed and all variable arguments are owned by the local HA test harness.
	cmd := exec.CommandContext(ctx, "docker", argv...)
	output, err := cmd.CombinedOutput()
	return string(output), err
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
