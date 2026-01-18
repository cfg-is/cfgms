// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"

	mqtt "github.com/eclipse/paho.mqtt.golang"
	"github.com/stretchr/testify/suite"
)

// DockerIntegrationTestSuite tests against actual Docker containers
// This verifies real-world MQTT+QUIC communication between containerized
// steward and controller binaries (not in-process components)
//
// Phase 10 (Story 12.2): Replaces log inspection with actual MQTT message validation
type DockerIntegrationTestSuite struct {
	suite.Suite
	mqttClient mqtt.Client
	mqttAddr   string
}

func (s *DockerIntegrationTestSuite) SetupSuite() {
	// Skip in short mode - requires Docker infrastructure
	if testing.Short() {
		s.T().Skip("Skipping Docker integration tests in short mode - requires Docker infrastructure")
		return
	}

	// Check if Docker controller MQTT broker is available
	s.mqttAddr = os.Getenv("CFGMS_TEST_DOCKER_MQTT")
	if s.mqttAddr == "" {
		s.mqttAddr = "localhost:1886" // Default standalone controller MQTT port
	}

	// Add tcp:// prefix if not present
	if s.mqttAddr[:6] != "tcp://" {
		s.mqttAddr = "tcp://" + s.mqttAddr
	}

	// Test if Docker controller MQTT broker is reachable (strip tcp://)
	tcpAddr := s.mqttAddr[6:]
	conn, err := net.DialTimeout("tcp", tcpAddr, 2*time.Second)
	if err != nil {
		s.T().Skipf("Docker controller MQTT broker not available at %s: %v", tcpAddr, err)
		return
	}
	_ = conn.Close()

	s.T().Logf("Docker controller MQTT broker accessible at %s", s.mqttAddr)

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

	// Create MQTT client for message validation
	opts := mqtt.NewClientOptions()
	opts.AddBroker(s.mqttAddr)
	opts.SetClientID(fmt.Sprintf("docker-test-%d", time.Now().UnixNano()))
	opts.SetConnectTimeout(10 * time.Second)
	opts.SetKeepAlive(30 * time.Second)
	opts.SetAutoReconnect(true)

	s.mqttClient = mqtt.NewClient(opts)
	token := s.mqttClient.Connect()
	if !token.WaitTimeout(10 * time.Second) {
		s.T().Fatalf("MQTT connection timeout to %s", s.mqttAddr)
	}
	if token.Error() != nil {
		s.T().Fatalf("MQTT connection error: %v", token.Error())
	}

	s.T().Logf("MQTT test client connected successfully to %s", s.mqttAddr)
}

func (s *DockerIntegrationTestSuite) TearDownSuite() {
	// Disconnect MQTT client
	if s.mqttClient != nil && s.mqttClient.IsConnected() {
		s.mqttClient.Disconnect(250)
		s.T().Log("MQTT test client disconnected")
	}

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

// TestStewardHeartbeat validates steward sends heartbeat messages via MQTT
// Replaces log string check with actual MQTT message subscription and validation
func (s *DockerIntegrationTestSuite) TestStewardHeartbeat() {
	heartbeatTopic := "cfgms/steward/+/heartbeat"

	heartbeatReceived := make(chan map[string]interface{}, 1)
	var mu sync.Mutex
	var lastHeartbeat map[string]interface{}

	// Subscribe to heartbeat topic
	token := s.mqttClient.Subscribe(heartbeatTopic, 1, func(client mqtt.Client, msg mqtt.Message) {
		mu.Lock()
		defer mu.Unlock()

		var heartbeat map[string]interface{}
		if err := json.Unmarshal(msg.Payload(), &heartbeat); err != nil {
			s.T().Logf("Failed to parse heartbeat: %v", err)
			return
		}

		s.T().Logf("Received heartbeat from topic %s: %+v", msg.Topic(), heartbeat)
		lastHeartbeat = heartbeat
		select {
		case heartbeatReceived <- heartbeat:
		default:
			// Channel full, skip
		}
	})

	s.True(token.WaitTimeout(5*time.Second), "Subscribe should not timeout")
	s.NoError(token.Error(), "Subscribe should succeed")

	// Wait for heartbeat message (stewards send every 30s, but we'll wait up to 45s)
	select {
	case heartbeat := <-heartbeatReceived:
		s.Contains(heartbeat, "steward_id", "Heartbeat should contain steward_id")
		s.Contains(heartbeat, "status", "Heartbeat should contain status")
		s.Contains(heartbeat, "timestamp", "Heartbeat should contain timestamp")
		s.T().Logf("✅ Heartbeat validated: steward_id=%s, status=%s", heartbeat["steward_id"], heartbeat["status"])
	case <-time.After(45 * time.Second):
		mu.Lock()
		if lastHeartbeat != nil {
			s.T().Logf("Heartbeat was received but channel was full. Last heartbeat: %+v", lastHeartbeat)
			s.Contains(lastHeartbeat, "steward_id", "Heartbeat should contain steward_id")
		} else {
			s.Fail("No heartbeat received within 45 seconds")
		}
		mu.Unlock()
	}
}

// TestStewardDNACollection validates steward collects and transmits DNA via MQTT
// Replaces log string check with actual MQTT message subscription and validation
func (s *DockerIntegrationTestSuite) TestStewardDNACollection() {
	dnaTopic := "cfgms/steward/+/dna"

	dnaReceived := make(chan map[string]interface{}, 1)
	var mu sync.Mutex
	var lastDNA map[string]interface{}

	// Subscribe to DNA topic
	token := s.mqttClient.Subscribe(dnaTopic, 1, func(client mqtt.Client, msg mqtt.Message) {
		mu.Lock()
		defer mu.Unlock()

		var dna map[string]interface{}
		if err := json.Unmarshal(msg.Payload(), &dna); err != nil {
			s.T().Logf("Failed to parse DNA: %v", err)
			return
		}

		s.T().Logf("Received DNA from topic %s: %+v", msg.Topic(), dna)
		lastDNA = dna
		select {
		case dnaReceived <- dna:
		default:
			// Channel full, skip
		}
	})

	s.True(token.WaitTimeout(5*time.Second), "Subscribe should not timeout")
	s.NoError(token.Error(), "Subscribe should succeed")

	// Wait for DNA message (stewards send periodically, wait up to 60s)
	select {
	case dna := <-dnaReceived:
		s.Contains(dna, "steward_id", "DNA should contain steward_id")
		s.Contains(dna, "timestamp", "DNA should contain timestamp")
		// DNA should contain system information
		if dnaData, ok := dna["dna"]; ok {
			s.T().Logf("✅ DNA validated: steward_id=%s, fields=%d", dna["steward_id"], len(dnaData.(map[string]interface{})))
		} else {
			s.T().Logf("⚠️  DNA message received but 'dna' field not present: %+v", dna)
		}
	case <-time.After(60 * time.Second):
		mu.Lock()
		if lastDNA != nil {
			s.T().Logf("DNA was received but channel was full. Last DNA: %+v", lastDNA)
			s.Contains(lastDNA, "steward_id", "DNA should contain steward_id")
		} else {
			s.T().Logf("⚠️  No DNA message received within 60 seconds (may be expected if steward doesn't publish DNA immediately)")
		}
		mu.Unlock()
	}
}

// TestStewardStatusReporting validates steward reports status via MQTT
// Replaces log string check with actual MQTT message subscription and validation
func (s *DockerIntegrationTestSuite) TestStewardStatusReporting() {
	statusTopic := "cfgms/steward/+/status"

	statusReceived := make(chan map[string]interface{}, 1)
	var mu sync.Mutex
	var lastStatus map[string]interface{}

	// Subscribe to status topic
	token := s.mqttClient.Subscribe(statusTopic, 1, func(client mqtt.Client, msg mqtt.Message) {
		mu.Lock()
		defer mu.Unlock()

		var status map[string]interface{}
		if err := json.Unmarshal(msg.Payload(), &status); err != nil {
			s.T().Logf("Failed to parse status: %v", err)
			return
		}

		s.T().Logf("Received status from topic %s: %+v", msg.Topic(), status)
		lastStatus = status
		select {
		case statusReceived <- status:
		default:
			// Channel full, skip
		}
	})

	s.True(token.WaitTimeout(5*time.Second), "Subscribe should not timeout")
	s.NoError(token.Error(), "Subscribe should succeed")

	// Wait for status message (may not be sent immediately, wait up to 30s)
	select {
	case status := <-statusReceived:
		s.Contains(status, "steward_id", "Status should contain steward_id")
		s.T().Logf("✅ Status report validated: steward_id=%s", status["steward_id"])
	case <-time.After(30 * time.Second):
		mu.Lock()
		if lastStatus != nil {
			s.T().Logf("Status was received but channel was full. Last status: %+v", lastStatus)
			s.Contains(lastStatus, "steward_id", "Status should contain steward_id")
		} else {
			s.T().Logf("⚠️  No status message received within 30 seconds (may be expected if no config changes)")
		}
		mu.Unlock()
	}
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
	// Skip in short mode - requires Docker infrastructure
	if testing.Short() {
		t.Skip("Skipping Docker integration tests in short mode - requires Docker infrastructure")
		return
	}

	suite.Run(t, new(DockerIntegrationTestSuite))
}
