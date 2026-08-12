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

// Controller endpoints used by every test in this package.
//
// The HA controllers publish their HTTP API on the host (9080/9081/9082) and
// listen on the same port inside the cfgms-test Compose network. Which of the
// two addresses works depends on where the test binary runs:
//
//   - on a developer host, the published ports are reachable on localhost;
//   - in CI the binary runs inside a container attached to the same network
//     (production-gates.yml: `docker run --network cfgms-test ... cfgms-test-runner`),
//     where the host's published ports are not reachable and the controllers
//     must be addressed by their Compose service names.
var (
	controllerEastURL    = controllerEndpoint("controller-east", 9080)
	controllerCentralURL = controllerEndpoint("controller-central", 9081)
	controllerWestURL    = controllerEndpoint("controller-west", 9082)
)

// haStewardTenant is the tenant the HA stewards belong to. They register with
// the seeded "integration_reusable" token, which carries this tenant
// (features/controller/server.Server, CFGMS_SEED_TEST_TOKENS block), and the
// API keys this suite authenticates with are scoped to it. Steward reads and
// configuration pushes are both tenant-scoped, so naming any other tenant here
// produces STEWARD_NOT_FOUND and 403 rather than a visible authorization error.
const haStewardTenant = "test-tenant-integration"

// certServerName is the name verified during the TLS handshake with an HA
// controller, pinned here rather than taken from the dial address.
//
// The controllers' server certificate carries every name the cluster is reached
// by: test/fixtures/ha/controller-ha.cfg lists localhost, cfgms-controller and
// all three controller-<region> names under certificate.server.dns_names, and
// docker-compose.test.yml also sets CFGMS_EXTERNAL_HOSTNAME per node, which
// initialization.TransportCertSANs merges in. "localhost" is in that set on
// every node, so pinning it verifies whether the tests address a controller by
// service name (in-container) or through a published port (on the host). The
// handshake is fully verified against the cluster's CA either way; only the
// expected name is fixed.
const certServerName = "localhost"

// controllerEndpoint returns the base URL for an HA controller service.
func controllerEndpoint(service string, port int) string {
	host := "localhost"
	if runningInContainer() {
		host = service
	}
	return fmt.Sprintf("https://%s:%d", host, port)
}

// runningInContainer reports whether this test binary is executing inside a
// container, in which case the Compose network is reachable by service name and
// the host's published ports are not.
func runningInContainer() bool {
	_, err := os.Stat("/.dockerenv")
	return err == nil
}

// controllerTLSConfig returns the TLS settings shared by the suite's HTTP
// clients: TLS 1.3 and, when addressing containers by service name, the
// certificate name to verify against.
func controllerTLSConfig() *tls.Config {
	cfg := &tls.Config{MinVersion: tls.VersionTLS13}
	if runningInContainer() {
		cfg.ServerName = certServerName
	}
	return cfg
}

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
	tlsConfig := controllerTLSConfig()
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
	tlsConfig := controllerTLSConfig()
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
// This is not a static-analysis conclusion — it is confirmed by a goroutine
// dump captured on an actual 600s timeout: CI run 30906412356
// (gh-readonly-queue/develop/pr-3156-…), job 91987111530
// "Controller Integration Tests (Linux)", 2026-08-04T12:25:56Z:
//
//	panic: test timed out after 10m0s
//	running tests:
//	        TestClusterConsistency (15s)
//	...
//	goroutine 45 [syscall]:
//	os/exec.(*Cmd).Wait(0xc00041a680)
//	        /usr/local/go/src/os/exec/exec.go:930 +0xb0
//	os/exec.(*Cmd).Run(0xc00041a680)
//	        /usr/local/go/src/os/exec/exec.go:632 +0x55
//	os/exec.(*Cmd).CombinedOutput(0xc00041a680)
//	        /usr/local/go/src/os/exec/exec.go:1047 +0x1f1
//	github.com/cfgis/cfgms/test/integration/ha.(*DockerComposeHelper).StartCluster(0xc000205dd0, {0x19fe128, 0xc000360150})
//	        /workspace/test/integration/ha/docker_helper.go:77 +0xb3f
//	github.com/cfgis/cfgms/test/integration/ha.TestClusterConsistency(0xc0002acfc8)
//	        /workspace/test/integration/ha/cluster_formation_test.go:168 +0x32d
//
// (line 77 was the pre-fix build-with-no-cache call inside StartCluster; the
// stack is otherwise unchanged by this PR's refactor). The preceding test
// output confirms the sequence above step by step: "Step 1/5: Cleaning up
// existing Docker resources...", "Step 2/5: Pruning Docker build cache...",
// "Step 3/5: Building fresh Docker images (no cache)..." — then the 600s
// alarm fires inside that build's Cmd.Wait. Full log:
// `gh run view --job 91987111530 --log`.
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
// Per-test isolation is preserved by recreating the `ha`-profile containers on
// every StartCluster, at container-start cost rather than image-build cost.
//
// # Cluster lifecycle collision (Issue #3187, AC3)
//
// The second reason the suite consumed its whole time budget is that no test
// could start a cluster at all. StartCluster recreated the entire Compose
// project, including the shared TimescaleDB container that the CI job starts
// beforehand under a different project name. Compose aborted every `up` with
//
//	Error response from daemon: Conflict. The container name
//	"/cfgms-timescaledb-test" is already in use by container "0000c0e4e991…"
//
// (merge-queue run 31202075054, job 92944227941, 2026-08-07T17:41:09Z,
// TestAuthenticationPersistence, authentication_workflow_test.go:76 — the same
// run also shows the project-wide `down -v` taking the standalone controller
// and database out from under test/integration/{controller,standalone,transport},
// which run concurrently in the same `go test ./test/integration/...` command).
// docker_helper.go now confines every create/recreate/remove to `ha`-profile
// services and reuses the running database.
//
// # Execution gate
//
// Issue #3187's AC4 allows a quarantine only when the cause "cannot be confirmed
// and fixed within this story". Both blocking calls above are now identified from
// CI evidence and fixed, so AC3 applies and the suite stays enabled: an env gate
// that no workflow sets would make this required suite a permanent no-op and
// remove the very signal AC3 asks for. Issue #3214 carries the remaining
// lifecycle work (one shared cluster per package run).
//
// The only precondition is a reachable Docker daemon, which the whole cluster
// is built from. When the daemon is missing the suite reports a skip and exits
// 0 — except under CFGMS_TEST_INTEGRATION=1, the variable the integration job
// sets (production-gates.yml, "Run Controller Integration Tests"). There, an
// unreachable daemon is a broken job rather than absent local infrastructure,
// so the suite fails instead of turning green without running anything.
func TestMain(m *testing.M) {
	if err := checkDockerAvailable(); err != nil {
		if os.Getenv("CFGMS_TEST_INTEGRATION") == "1" {
			fmt.Fprintf(os.Stderr, "test/integration/ha: %v (CFGMS_TEST_INTEGRATION=1 requires Docker)\n", err)
			os.Exit(1)
		}
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
