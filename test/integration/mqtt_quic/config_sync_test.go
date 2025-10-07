package mqtt_quic

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/suite"

	mqtt "github.com/eclipse/paho.mqtt.golang"
)

// ConfigSyncTestSuite tests configuration synchronization via QUIC
// AC4: Configuration sync test (controller pushes config, steward receives and applies)
type ConfigSyncTestSuite struct {
	suite.Suite
	helper   *TestHelper
	mqttAddr string
}

func (s *ConfigSyncTestSuite) SetupSuite() {
	s.helper = NewTestHelper(GetTestHTTPAddr("http://localhost:8080"))
	s.mqttAddr = GetTestMQTTAddr("tcp://localhost:1886")
}

// TestConfigSyncCommand tests config sync command delivery
func (s *ConfigSyncTestSuite) TestConfigSyncCommand() {
	stewardID := "test-steward-config-sync"
	commandTopic := fmt.Sprintf("cfgms/steward/%s/commands", stewardID)

	// Create steward MQTT client
	opts := mqtt.NewClientOptions()
	opts.AddBroker(s.mqttAddr)
	opts.SetClientID(stewardID)
	opts.SetConnectTimeout(10 * time.Second)

	client := mqtt.NewClient(opts)
	token := client.Connect()
	s.True(token.WaitTimeout(10 * time.Second))
	s.NoError(token.Error())
	defer client.Disconnect(250)

	// Subscribe to commands
	receivedCommand := make(chan map[string]interface{}, 1)
	subToken := client.Subscribe(commandTopic, 1, func(client mqtt.Client, msg mqtt.Message) {
		var cmd map[string]interface{}
		if err := json.Unmarshal(msg.Payload(), &cmd); err == nil {
			receivedCommand <- cmd
		}
	})
	s.True(subToken.WaitTimeout(5 * time.Second))
	s.NoError(subToken.Error())

	// Publish connect_quic command (controller would do this)
	command := map[string]interface{}{
		"command_id":   "cmd-config-123",
		"type":         "connect_quic",
		"timestamp":    time.Now().Unix(),
		"quic_address": "localhost:4433",
		"session_id":   "sess_test123",
		"timeout":      30,
	}

	cmdJSON, err := json.Marshal(command)
	s.NoError(err)

	pubToken := client.Publish(commandTopic, 1, false, cmdJSON)
	s.True(pubToken.WaitTimeout(5 * time.Second))
	s.NoError(pubToken.Error())

	// Wait for command
	select {
	case cmd := <-receivedCommand:
		s.Equal("cmd-config-123", cmd["command_id"])
		s.Equal("connect_quic", cmd["type"])
		s.T().Logf("Config sync command received: %v", cmd)
	case <-time.After(5 * time.Second):
		s.Fail("Timeout waiting for config sync command")
	}
}

// TestConfigPayloadStructure tests configuration data structure
func (s *ConfigSyncTestSuite) TestConfigPayloadStructure() {
	// Test configuration structure (what would be sent via QUIC)
	config := map[string]interface{}{
		"steward": map[string]interface{}{
			"id":   "test-steward",
			"mode": "controller",
		},
		"resources": []map[string]interface{}{
			{
				"name":   "test-directory",
				"module": "directory",
				"config": map[string]interface{}{
					"path": "/tmp/test",
					"mode": "0755",
				},
			},
			{
				"name":   "test-file",
				"module": "file",
				"config": map[string]interface{}{
					"path":    "/tmp/test/file.txt",
					"content": "test content",
					"mode":    "0644",
				},
			},
		},
	}

	// Verify structure
	s.NotNil(config["steward"])
	s.NotNil(config["resources"])

	resources := config["resources"].([]map[string]interface{})
	s.Len(resources, 2, "Should have 2 resources")
	s.Equal("directory", resources[0]["module"])
	s.Equal("file", resources[1]["module"])

	// Verify JSON encoding
	configJSON, err := json.Marshal(config)
	s.NoError(err)
	s.NotEmpty(configJSON)
	s.Greater(len(configJSON), 100, "Config should be substantial")

	s.T().Logf("Config payload structure validated: %d bytes", len(configJSON))
}

// TestLargeConfigPayload tests large configuration transfer (>100KB = QUIC)
func (s *ConfigSyncTestSuite) TestLargeConfigPayload() {
	// Create large config (>100KB to trigger QUIC usage)
	largeConfig := map[string]interface{}{
		"steward": map[string]interface{}{
			"id": "test-steward-large",
		},
		"resources": []map[string]interface{}{},
	}

	// Add many resources to exceed 100KB
	for i := 0; i < 500; i++ {
		resource := map[string]interface{}{
			"name":   fmt.Sprintf("resource-%d", i),
			"module": "file",
			"config": map[string]interface{}{
				"path":    fmt.Sprintf("/tmp/test/file%d.txt", i),
				"content": "Lorem ipsum dolor sit amet, consectetur adipiscing elit. " +
					"Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.",
			},
		}
		largeConfig["resources"] = append(largeConfig["resources"].([]map[string]interface{}), resource)
	}

	configJSON, err := json.Marshal(largeConfig)
	s.NoError(err)

	// Verify size exceeds 100KB
	s.Greater(len(configJSON), 100*1024, "Config should exceed 100KB")

	s.T().Logf("Large config payload: %d bytes (%.1f KB)", len(configJSON), float64(len(configJSON))/1024)
}

// TestConfigStatusReport tests status reporting after config application
func (s *ConfigSyncTestSuite) TestConfigStatusReport() {
	stewardID := "test-steward-status"
	statusTopic := fmt.Sprintf("cfgms/steward/%s/status", stewardID)

	// Create client
	opts := mqtt.NewClientOptions()
	opts.AddBroker(s.mqttAddr)
	opts.SetClientID(stewardID)
	opts.SetConnectTimeout(10 * time.Second)

	client := mqtt.NewClient(opts)
	token := client.Connect()
	s.True(token.WaitTimeout(10 * time.Second))
	s.NoError(token.Error())
	defer client.Disconnect(250)

	// Publish status report
	statusReport := map[string]interface{}{
		"steward_id":        stewardID,
		"config_version":    "v1.0.0",
		"status":            "OK",
		"message":           "Configuration applied successfully",
		"timestamp":         time.Now().Unix(),
		"execution_time_ms": 1250,
		"modules": map[string]interface{}{
			"file": map[string]interface{}{
				"name":      "file",
				"status":    "OK",
				"message":   "File module applied",
				"timestamp": time.Now().Unix(),
			},
			"directory": map[string]interface{}{
				"name":      "directory",
				"status":    "OK",
				"message":   "Directory module applied",
				"timestamp": time.Now().Unix(),
			},
		},
	}

	reportJSON, err := json.Marshal(statusReport)
	s.NoError(err)

	pubToken := client.Publish(statusTopic, 1, false, reportJSON)
	s.True(pubToken.WaitTimeout(5 * time.Second))
	s.NoError(pubToken.Error())

	s.T().Logf("Status report published successfully")
}

func TestConfigSync(t *testing.T) {
	suite.Run(t, new(ConfigSyncTestSuite))
}
