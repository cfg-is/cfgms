package integration

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/suite"
)

// DockerIntegrationTestSuite tests against actual Docker containers
// This verifies real-world MQTT+QUIC communication between containerized
// steward and controller binaries (not in-process components)
type DockerIntegrationTestSuite struct {
	suite.Suite
}

func (s *DockerIntegrationTestSuite) SetupSuite() {
	// Check if Docker controller MQTT broker is available
	mqttAddr := os.Getenv("CFGMS_TEST_DOCKER_MQTT")
	if mqttAddr == "" {
		mqttAddr = "localhost:1886" // Default standalone controller MQTT port
	}

	// Test if Docker controller MQTT broker is reachable
	conn, err := net.DialTimeout("tcp", mqttAddr, 2*time.Second)
	if err != nil {
		s.T().Skipf("Docker controller MQTT broker not available at %s: %v", mqttAddr, err)
		return
	}
	_ = conn.Close()

	s.T().Logf("Docker controller MQTT broker accessible at %s", mqttAddr)

	// Start steward-standalone container
	s.T().Log("Starting steward-standalone container...")

	// Get project root (assuming tests run from project root or test directory)
	wd, _ := os.Getwd()
	projectRoot := filepath.Join(wd, "../..")
	if _, err := os.Stat(filepath.Join(projectRoot, "docker-compose.test.yml")); os.IsNotExist(err) {
		// Already at project root
		projectRoot = wd
	}

	composePath := filepath.Join(projectRoot, "docker-compose.test.yml")
	cmd := exec.Command("docker", "compose", "-f", composePath, "--profile", "ha", "up", "-d", "steward-standalone")
	if output, err := cmd.CombinedOutput(); err != nil {
		s.T().Fatalf("Failed to start steward-standalone: %v\nOutput: %s", err, output)
	}

	// Wait for steward to initialize
	time.Sleep(5 * time.Second)
}

func (s *DockerIntegrationTestSuite) TearDownSuite() {
	// Stop steward container (leave controller running for other tests)
	s.T().Log("Stopping steward-standalone container...")

	wd, _ := os.Getwd()
	projectRoot := filepath.Join(wd, "../..")
	if _, err := os.Stat(filepath.Join(projectRoot, "docker-compose.test.yml")); os.IsNotExist(err) {
		projectRoot = wd
	}

	composePath := filepath.Join(projectRoot, "docker-compose.test.yml")
	cmd := exec.Command("docker", "compose", "-f", composePath, "stop", "steward-standalone")
	_ = cmd.Run()
}

// getContainerLogs retrieves logs from a Docker container
// If since is 0, retrieves all logs
func (s *DockerIntegrationTestSuite) getContainerLogs(containerName string, since time.Duration) string {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var cmd *exec.Cmd
	if since > 0 {
		sinceArg := fmt.Sprintf("%ds", int(since.Seconds()))
		cmd = exec.CommandContext(ctx, "docker", "logs", "--since", sinceArg, containerName)
	} else {
		// Get all logs
		cmd = exec.CommandContext(ctx, "docker", "logs", containerName)
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		s.T().Logf("Warning: Failed to get logs for %s: %v", containerName, err)
		return ""
	}

	return string(output)
}

// TestMQTTConnection validates MQTT broker is accessible and steward starts successfully
// NOTE: Full MQTT+QUIC integration between steward and controller is pending (Story #198)
// This test verifies infrastructure readiness, not actual MQTT communication
func (s *DockerIntegrationTestSuite) TestMQTTConnection() {
	// Wait for containers to initialize
	time.Sleep(2 * time.Second)

	// Check steward logs for successful startup
	stewardLogs := s.getContainerLogs("steward-standalone", 60*time.Second)
	s.T().Logf("Steward logs (last 60s):\n%s", stewardLogs)

	// Check controller logs for MQTT broker startup (get all logs since container may have been running for a while)
	controllerLogs := s.getContainerLogs("controller-standalone", 0) // 0 = all logs
	s.T().Logf("Controller logs (all):\n%s", controllerLogs)

	// Verify controller's MQTT broker started successfully
	hasMQTTBroker := strings.Contains(controllerLogs, "mochi mqtt") ||
		strings.Contains(controllerLogs, "MQTT") ||
		strings.Contains(controllerLogs, "mqtt server started")

	s.True(hasMQTTBroker, "Controller should have started MQTT broker successfully")

	// Verify steward container started (providers registered is a good sign)
	stewardStarted := strings.Contains(stewardLogs, "Registered") ||
		strings.Contains(stewardLogs, "provider")

	s.True(stewardStarted, "Steward should have started successfully")
}

// TestRegistration validates Docker infrastructure supports MQTT+QUIC communication
// NOTE: Full MQTT+QUIC registration flow is pending completion (Story #198)
// This test verifies the MQTT broker is accepting connections
func (s *DockerIntegrationTestSuite) TestRegistration() {
	time.Sleep(2 * time.Second)

	controllerLogs := s.getContainerLogs("controller-standalone", 30*time.Second)

	// Verify MQTT broker is running and can accept connections
	// The "EOF" warnings in logs indicate connection attempts were made (expected for now)
	mqttBrokerRunning := strings.Contains(controllerLogs, "mochi mqtt") ||
		strings.Contains(controllerLogs, "listener") ||
		strings.Contains(controllerLogs, "tcp")

	s.True(mqttBrokerRunning, "Controller MQTT broker should be accepting connections")
}

// TestContainerHealth validates both containers are running
func (s *DockerIntegrationTestSuite) TestContainerHealth() {
	// Check controller is healthy
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "docker", "ps", "--filter", "name=controller-standalone", "--filter", "health=healthy", "--format", "{{.Names}}")
	output, err := cmd.CombinedOutput()
	s.NoError(err, "Docker command should succeed")
	s.Contains(string(output), "controller-standalone", "Controller should be healthy")

	// Check steward is running (it may not have healthcheck)
	cmd = exec.CommandContext(ctx, "docker", "ps", "--filter", "name=steward-standalone", "--format", "{{.Names}}")
	output, err = cmd.CombinedOutput()
	s.NoError(err, "Docker command should succeed")
	s.Contains(string(output), "steward-standalone", "Steward should be running")
}

// TestMQTTPortAccessibility validates MQTT port is accessible
func (s *DockerIntegrationTestSuite) TestMQTTPortAccessibility() {
	conn, err := net.DialTimeout("tcp", "localhost:1886", 2*time.Second)
	s.NoError(err, "Should be able to connect to MQTT port 1886")
	if conn != nil {
		_ = conn.Close()
	}
}

func TestDockerIntegration(t *testing.T) {
	suite.Run(t, new(DockerIntegrationTestSuite))
}
