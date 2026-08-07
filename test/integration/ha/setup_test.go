// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package ha

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/cfgis/cfgms/pkg/testutil"
)

// getDockerCACert extracts the CA certificate PEM from a Docker container.
// The certificate is read from /app/certs/ca/ca.crt (default CFGMS cert path inside Docker).
func getDockerCACert(containerName string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "docker", "exec", containerName, "cat", "/app/certs/ca/ca.crt")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to read CA cert from container %s: %w", containerName, err)
	}
	return output, nil
}

// buildTLSClient creates an HTTP client with the CA cert from the given Docker container.
// Falls back to the system root pool when Docker is unavailable.
func buildTLSClient(containerName string) *http.Client {
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS13}
	if caCertPEM, err := getDockerCACert(containerName); err == nil {
		caCertPool := x509.NewCertPool()
		if caCertPool.AppendCertsFromPEM(caCertPEM) {
			tlsConfig.RootCAs = caCertPool
		}
	}
	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}
}

// buildMultiControllerTLSClient creates an HTTP client with CA certs from all specified containers.
// This allows a single client to talk to multiple controllers that have different CAs.
// RootCAs is only set when at least one cert is successfully parsed; otherwise the system root pool
// is used so the client never proceeds with an empty trust pool.
func buildMultiControllerTLSClient(containerNames ...string) *http.Client {
	caCertPool := x509.NewCertPool()
	certsAdded := false
	for _, name := range containerNames {
		if caCertPEM, err := getDockerCACert(name); err == nil {
			if caCertPool.AppendCertsFromPEM(caCertPEM) {
				certsAdded = true
			}
		}
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS13}
	if certsAdded {
		tlsConfig.RootCAs = caCertPool
	}
	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}
}

// TestMain sets up the process-level environment for the HA suite.
//
// # Blocking-call localisation (Issue #3187, AC1)
//
// Every test in this package independently calls DockerComposeHelper.StartCluster,
// which ran three sequential Docker operations per invocation:
//
//  1. docker compose down -v --rmi all --remove-orphans   (removes all images)
//  2. docker builder prune -f                              (clears ALL build cache)
//  3. docker compose build --no-cache --pull               (cold-cache rebuild)
//
// Operation 3 was the blocking call: the goroutine sat in
// exec.CommandContext.Wait() inside buildCmd.CombinedOutput(). With ~15 tests
// each triggering a cold-cache image build, the cumulative Docker time exceeded
// the 10-minute binary timeout (600s). Operation 1's --rmi all removed the image
// each test had just built, so the next test paid the full cold-build cost
// again, and operation 2 ensured no layer cache survived between tests.
//
// # CFGMS_SECRETS_KEY_FILE assessment (Issue #3187, AC2)
//
// CFGMS_SECRETS_KEY_FILE is NOT missing from the per-test Docker path.
// StartCluster ensures ./scripts/generate-test-credentials.sh has run, which
// writes CFGMS_SECRETS_KEY_FILE into .env.test, and every Compose invocation
// passes --env-file .env.test to the controller containers.
//
// A secondary failure mode exists in Docker-in-Docker CI environments: the
// generate-test-credentials.sh script resolves $(pwd) to a container-internal
// path (/workspace/...) while the host Docker daemon mounts volumes by host
// path. This mismatch causes controller containers to fail to start (the
// secrets volume mount is missing on the host), but produces a fast error, not
// a hang — it is not the 600s timeout root cause.
//
// This TestMain provisions CFGMS_SECRETS_KEY_FILE at the process level to cover
// any test code that exercises controller initialisation outside of Docker.
//
// # Fix (Issue #3187, AC3)
//
// docker_helper.go now generates credentials and builds images once per test
// binary behind a sync.Once, drops the --rmi all / docker builder prune /
// --no-cache --pull pattern, and bounds the build with prepareTimeout so a
// stalled daemon reports a named error instead of consuming the binary timeout.
// Per-test cluster isolation is unchanged: each StartCluster still recreates
// containers and volumes, at container-start cost rather than image-build cost.
func TestMain(m *testing.M) {
	if err := checkDockerAvailable(); err != nil {
		fmt.Fprintf(os.Stderr, "[SKIP] test/integration/ha: %v\n", err)
		os.Exit(0)
	}

	cleanup, err := testutil.ProvisionSecretsEnv("cfgms-ha-integration-")
	if err != nil {
		fmt.Fprintf(os.Stderr, "provision test secrets: %v\n", err)
		os.Exit(1)
	}
	code := m.Run()
	cleanup()
	os.Exit(code)
}

// checkDockerAvailable returns nil if the Docker daemon is reachable, or an
// error if docker info fails or times out.
func checkDockerAvailable() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// #nosec G204 -- no user input; fixed command for environment probe only.
	cmd := exec.CommandContext(ctx, "docker", "info")
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("docker not available: %w", err)
	}
	return nil
}
