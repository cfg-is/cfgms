// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package controller

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

// DockerComposeHelper manages Docker Compose operations for controller testing
type DockerComposeHelper struct {
	ComposeFile    string
	ProjectName    string
	controllerAddr string // "localhost:8080" on host, "controller-standalone:9080" in Docker CI
	startedBySuite bool   // true if this suite started the containers (vs CI/make target)
}

// NewDockerComposeHelper creates a new Docker Compose helper
// Uses the unified docker-compose.test.yml with --profile ha (includes controller-standalone)
func NewDockerComposeHelper() *DockerComposeHelper {
	// When running inside a Docker CI container (GITHUB_ACTIONS=true),
	// use container hostname:internal-port instead of localhost:host-port
	// Port mapping: host 8080 → container 9080
	addr := "localhost:8080"
	if os.Getenv("GITHUB_ACTIONS") == "true" {
		addr = "controller-standalone:9080"
	}
	return &DockerComposeHelper{
		ComposeFile:    "../../../docker-compose.test.yml",
		ProjectName:    "cfgms-test",
		controllerAddr: addr,
	}
}

// IsInfrastructureRunning checks if the required Docker containers are already running
// (e.g., started by CI workflow or make test-integration-setup)
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

	// Generate test credentials only when they are actually absent.
	//
	// The comment above always said "if not already present", but the call was
	// unconditional, and generate-test-credentials.sh rotates every secret it
	// writes — including .cfgms-test-secrets.key, the master key the SOPS secret
	// store derives from. Rotating it out from under containers another suite is
	// already running leaves their ciphertext in the shared database undecryptable,
	// and every HA controller then dies at startup with:
	//
	//	load audit HMAC key: failed to decrypt secret:
	//	secret ciphertext authentication failed
	//
	// These packages run concurrently under `go test ./test/integration/...`, so
	// this is a live cross-suite hazard, not a local-only one. Same guard as
	// test/integration/ha's ensureCredentials.
	fmt.Println("Step 1/3: Ensuring test credentials are generated...")
	if _, statErr := os.Stat("../../../.env.test"); os.IsNotExist(statErr) {
		credCmd := exec.CommandContext(ctx, "bash", "-c", "cd ../../../ && ./scripts/generate-test-credentials.sh")
		credOutput, err := credCmd.CombinedOutput()
		if err != nil {
			fmt.Printf("Credential generation warnings: %s\n", string(credOutput))
		}
	}

	// Build and start containers
	fmt.Println("Step 2/3: Building Docker images...")
	// #nosec G204 -- integration-only Docker Compose invocation; executable is
	// fixed and all variable arguments are owned by the local test harness.
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
	// #nosec G204 -- integration-only Docker Compose invocation; executable is
	// fixed and all variable arguments are owned by the local test harness.
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
		// #nosec G204 -- integration-only health probe; curl/options are fixed
		// and the address comes from the harness-created controller container.
		checkCmd := exec.CommandContext(ctx, "curl", "-sk", "--max-time", "2",
			"-o", "/dev/null", "-w", "%{http_code}",
			fmt.Sprintf("https://%s/health", h.controllerAddr))
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
	// Scoped to the two services this suite starts.
	//
	// `down -v` is project-wide: it removed the HA cluster, the shared database
	// and the standalone steward that test/integration/{ha,standalone,logging}
	// are using concurrently in the same `go test ./test/integration/...` run,
	// and `-v` destroyed the volumes holding their secret-store key material.
	// Compose projects are shared by every suite here, so a suite may only ever
	// remove the containers it created.
	// #nosec G204 -- integration-only Docker Compose invocation; executable is
	// fixed and all variable arguments are owned by the local test harness.
	stopCmd := exec.CommandContext(ctx, "docker", "compose",
		"-f", h.ComposeFile,
		"-p", h.ProjectName,
		"--profile", "ha",
		"rm", "-f", "-s", "-v",
		"controller-standalone", "steward-standalone")

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

// harnessContainerNames is the closed set of container names this harness
// creates through docker-compose.test.yml. Helpers that accept a container
// name as a parameter validate against this set before it reaches an argv,
// so no arbitrary caller-supplied string can be passed to docker.
var harnessContainerNames = map[string]struct{}{
	"controller-standalone":  {},
	"steward-standalone":     {},
	"cfgms-timescaledb-test": {},
}

// validateContainerName returns an error unless name is one of the containers
// this harness owns.
func validateContainerName(name string) error {
	if _, ok := harnessContainerNames[name]; !ok {
		return fmt.Errorf("unsupported container %q: only harness-managed containers may be inspected", name)
	}
	return nil
}

// WaitForLogContent polls the named container's logs until they contain at
// least one of the target substrings, or the context deadline is exceeded.
// Reused by tests whose infrastructure may be "managed externally" (started
// concurrently by a sibling package's docker compose invocation, e.g. the ha
// suite's shared controller-standalone/steward-standalone containers), where
// a container being Running does not guarantee its startup logging has
// completed yet. Returns the last observed log output so callers get a
// useful message even on timeout.
func (h *DockerComposeHelper) WaitForLogContent(ctx context.Context, containerName string, substrings ...string) (string, error) {
	if err := validateContainerName(containerName); err != nil {
		return "", err
	}

	var lastLogs string
	var lastErr error
	for {
		// Read the container's log FILES, not its stdout.
		//
		// These containers run with CFGMS_LOG_PROVIDER=file and
		// CFGMS_LOG_DIR=/tmp/cfgms, so `docker logs` shows only a startup
		// banner: the records callers wait for are in the files. Waiting on
		// stdout could only ever time out, which is exactly what the controller
		// suite did — two subtests burning 30s each before failing.
		//
		// #nosec G204 -- integration-only Docker exec; the executable and
		// subcommand are fixed, the shell command is a constant, and
		// containerName is checked against the harness-owned allowlist above.
		cmd := exec.CommandContext(ctx, "docker", "exec", containerName,
			"sh", "-c", "cat /tmp/cfgms/*.log 2>/dev/null")
		output, err := cmd.CombinedOutput()
		if err == nil {
			lastLogs = string(output)
			for _, s := range substrings {
				if strings.Contains(lastLogs, s) {
					return lastLogs, nil
				}
			}
		} else {
			lastErr = err
		}

		select {
		case <-ctx.Done():
			if lastErr != nil {
				return lastLogs, fmt.Errorf("timed out waiting for %s logs to contain expected content: %w", containerName, lastErr)
			}
			return lastLogs, fmt.Errorf("timed out waiting for %s logs to contain expected content", containerName)
		case <-time.After(1 * time.Second):
		}
	}
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
	url := fmt.Sprintf("https://%s%s", h.controllerAddr, endpoint)
	// #nosec G204 -- integration-only HTTPS probe; curl/options are fixed and
	// URL host/path are formed from harness-controlled test inputs.
	cmd := exec.CommandContext(ctx, "curl", "-sk", "--max-time", "5", url)
	output, err := cmd.CombinedOutput()
	return string(output), err
}

// IsContainerRunning checks if a specific container is running
func (h *DockerComposeHelper) IsContainerRunning(containerName string) bool {
	// #nosec G204 -- integration-only Docker inspection; the harness owns the
	// container name and passes it as one argv to a fixed executable.
	cmd := exec.Command("docker", "inspect", "--format={{.State.Running}}", containerName)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(output)) == "true"
}
