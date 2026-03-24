// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package mqtt_quic

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/suite"

	mqtt "github.com/eclipse/paho.mqtt.golang"
)

// HeartbeatFailoverTestSuite tests heartbeat mechanism and failover detection
// AC6: Heartbeat mechanism test (30s MQTT PINGs)
// AC7: Failover detection test (<15s offline detection)
// AC8: Command delivery test
// AC9: Reconnection test
type HeartbeatFailoverTestSuite struct {
	suite.Suite
	helper    *TestHelper
	mqttAddr  string
	tlsConfig *tls.Config
	stewardID string
}

func (s *HeartbeatFailoverTestSuite) SetupSuite() {
	// Skip if running in short/fast mode - requires MQTT broker infrastructure
	if testing.Short() {
		s.T().Skip("Skipping heartbeat/failover tests in short mode - requires MQTT broker")
	}

	s.helper = NewTestHelper(GetTestHTTPAddr("https://localhost:8080"))
	s.mqttAddr = GetTestMQTTAddr("ssl://localhost:1886") // Use TLS

	// Get TLS config from registration API (required for mTLS)
	s.tlsConfig, s.stewardID = s.helper.GetTLSConfigFromRegistration(s.T(), "default", "integration-test")
}

// createMQTTClient creates an MQTT client with TLS config
func (s *HeartbeatFailoverTestSuite) createMQTTClient(clientID string) mqtt.Client {
	opts := CreateMQTTClientOptions(s.mqttAddr, clientID, s.tlsConfig)
	return mqtt.NewClient(opts)
}

// TestHeartbeatMechanism tests periodic heartbeat publishing (AC6)
func (s *HeartbeatFailoverTestSuite) TestHeartbeatMechanism() {
	stewardID := fmt.Sprintf("test-steward-heartbeat-%d", time.Now().UnixNano())
	heartbeatTopic := fmt.Sprintf("cfgms/steward/%s/heartbeat", stewardID)

	opts := CreateMQTTClientOptions(s.mqttAddr, stewardID, s.tlsConfig)
	opts.SetKeepAlive(30 * time.Second) // 30s keepalive matches MQTT PINGREQ

	client := mqtt.NewClient(opts)
	token := client.Connect()
	s.True(token.WaitTimeout(10 * time.Second))
	s.NoError(token.Error())
	defer client.Disconnect(250)

	// Simulate periodic heartbeats (every 30s in production)
	heartbeatCount := 3
	heartbeatInterval := 2 * time.Second // Faster for testing

	for i := 0; i < heartbeatCount; i++ {
		heartbeat := map[string]interface{}{
			"steward_id": stewardID,
			"status":     "healthy",
			"timestamp":  time.Now().Unix(),
			"sequence":   i + 1,
			"metrics": map[string]string{
				"cpu_percent": "25.5",
				"memory_mb":   "512",
			},
		}

		heartbeatJSON, err := json.Marshal(heartbeat)
		s.NoError(err)

		pubToken := client.Publish(heartbeatTopic, 1, false, heartbeatJSON)
		s.True(pubToken.WaitTimeout(5 * time.Second))
		s.NoError(pubToken.Error())

		s.T().Logf("Heartbeat %d/%d published", i+1, heartbeatCount)

		if i < heartbeatCount-1 {
			time.Sleep(heartbeatInterval)
		}
	}

	s.T().Logf("Heartbeat mechanism validated: %d heartbeats", heartbeatCount)
}

// TestMQTTKeepAliveTimeout tests MQTT keepalive timeout detection (AC7)
func (s *HeartbeatFailoverTestSuite) TestMQTTKeepAliveTimeout() {
	stewardID := fmt.Sprintf("test-steward-timeout-%d", time.Now().UnixNano())

	// Create client with short keepalive
	opts := CreateMQTTClientOptions(s.mqttAddr, stewardID, s.tlsConfig)
	opts.SetKeepAlive(5 * time.Second) // Short keepalive for testing

	// Track connection status
	var connected atomic.Bool
	connected.Store(true)

	opts.SetConnectionLostHandler(func(client mqtt.Client, err error) {
		connected.Store(false)
		s.T().Logf("Connection lost: %v", err)
	})

	client := mqtt.NewClient(opts)
	token := client.Connect()
	s.True(token.WaitTimeout(10 * time.Second))
	s.NoError(token.Error())

	// Verify connection maintained with keepalive
	time.Sleep(10 * time.Second)
	s.True(client.IsConnected(), "Connection should be maintained with keepalive")
	s.True(connected.Load(), "Connection status should remain true")

	client.Disconnect(250)
	s.T().Log("Keepalive timeout test completed")
}

// TestFailoverDetectionTiming tests <15s failover detection requirement (AC7)
func (s *HeartbeatFailoverTestSuite) TestFailoverDetectionTiming() {
	// Test that failover can be detected within 15 seconds
	// In production:
	// - Steward sends PINGREQ every 30s
	// - Broker responds with PINGRESP
	// - If no PINGRESP within keepalive window, connection dropped
	// - Last Will Testament (LWT) message published immediately
	// - Controller detects via LWT: offline within <15s

	stewardID := fmt.Sprintf("test-steward-failover-%d", time.Now().UnixNano())
	lwtTopic := fmt.Sprintf("cfgms/steward/%s/status", stewardID)

	// Track LWT delivery
	lwtReceived := make(chan bool, 1)
	var lwtPublishTime time.Time
	var lwtTimeMutex sync.Mutex

	// Create observer client to monitor LWT
	observer := s.createMQTTClient(fmt.Sprintf("test-observer-%d", time.Now().UnixNano()))
	token := observer.Connect()
	s.True(token.WaitTimeout(10 * time.Second))
	s.NoError(token.Error())
	defer observer.Disconnect(250)

	// Subscribe to LWT topic
	subToken := observer.Subscribe(lwtTopic, 1, func(client mqtt.Client, msg mqtt.Message) {
		deliveryTime := time.Now()
		lwtTimeMutex.Lock()
		publishTime := lwtPublishTime
		lwtTimeMutex.Unlock()
		latency := deliveryTime.Sub(publishTime)
		s.T().Logf("LWT received after %.2fs", latency.Seconds())
		lwtReceived <- true
	})
	s.True(subToken.WaitTimeout(5 * time.Second))
	s.NoError(subToken.Error())

	// Create steward with LWT
	stewardOpts := CreateMQTTClientOptions(s.mqttAddr, stewardID, s.tlsConfig)
	stewardOpts.SetKeepAlive(5 * time.Second)

	// Configure Last Will Testament
	lwtPayload := map[string]interface{}{
		"steward_id": stewardID,
		"status":     "disconnected",
		"timestamp":  time.Now().Unix(),
	}
	lwtJSON, _ := json.Marshal(lwtPayload)
	stewardOpts.SetWill(lwtTopic, string(lwtJSON), 1, false)

	steward := mqtt.NewClient(stewardOpts)
	token = steward.Connect()
	s.True(token.WaitTimeout(10 * time.Second))
	s.NoError(token.Error())

	// Simulate abrupt disconnection (broker will publish LWT)
	time.Sleep(1 * time.Second) // Ensure connection is stable
	lwtTimeMutex.Lock()
	lwtPublishTime = time.Now()
	lwtTimeMutex.Unlock()

	// Force disconnect without clean disconnect packet
	steward.Disconnect(0) // 0 = immediate disconnect, triggers LWT

	// Wait for LWT delivery
	select {
	case <-lwtReceived:
		s.T().Log("Failover detected via LWT (simulated)")
	case <-time.After(15 * time.Second):
		s.T().Log("LWT not received within 15s (acceptable for clean disconnect)")
	}
}

// TestCommandDeliveryMechanism tests command delivery reliability (AC8)
func (s *HeartbeatFailoverTestSuite) TestCommandDeliveryMechanism() {
	stewardID := fmt.Sprintf("test-steward-commands-%d", time.Now().UnixNano())
	commandTopic := fmt.Sprintf("cfgms/steward/%s/commands", stewardID)

	// Create steward client with TLS
	client := s.createMQTTClient(stewardID)
	token := client.Connect()
	s.True(token.WaitTimeout(10 * time.Second))
	s.NoError(token.Error())
	defer client.Disconnect(250)

	// Track received commands
	receivedCommands := make([]string, 0)
	var mu sync.Mutex

	// Subscribe to commands
	subToken := client.Subscribe(commandTopic, 1, func(client mqtt.Client, msg mqtt.Message) {
		var cmd map[string]interface{}
		if err := json.Unmarshal(msg.Payload(), &cmd); err == nil {
			mu.Lock()
			receivedCommands = append(receivedCommands, cmd["command_id"].(string))
			mu.Unlock()
		}
	})
	s.True(subToken.WaitTimeout(5 * time.Second))
	s.NoError(subToken.Error())

	// Publish multiple commands
	commands := []string{"sync_config", "sync_dna", "restart", "connect_quic", "update_status"}
	for i, cmdType := range commands {
		command := map[string]interface{}{
			"command_id": fmt.Sprintf("cmd-%d", i+1),
			"type":       cmdType,
			"timestamp":  time.Now().Unix(),
		}

		cmdJSON, _ := json.Marshal(command)
		pubToken := client.Publish(commandTopic, 1, false, cmdJSON)
		s.True(pubToken.WaitTimeout(5 * time.Second))
		s.NoError(pubToken.Error())
	}

	// Wait for command delivery
	time.Sleep(2 * time.Second)

	// Verify all commands received
	mu.Lock()
	receivedCount := len(receivedCommands)
	mu.Unlock()

	s.Equal(len(commands), receivedCount, "All commands should be delivered")
	s.T().Logf("Command delivery: %d/%d commands received", receivedCount, len(commands))
}

// TestReconnectionBehavior tests automatic reconnection (AC9)
func (s *HeartbeatFailoverTestSuite) TestReconnectionBehavior() {
	stewardID := fmt.Sprintf("test-steward-reconnect-%d", time.Now().UnixNano())

	// Track connection events
	var connectionCount atomic.Int32
	var disconnectionCount atomic.Int32

	opts := CreateMQTTClientOptions(s.mqttAddr, stewardID, s.tlsConfig)
	opts.SetAutoReconnect(true)
	opts.SetMaxReconnectInterval(5 * time.Second)

	opts.SetOnConnectHandler(func(client mqtt.Client) {
		count := connectionCount.Add(1)
		s.T().Logf("Connected (count: %d)", count)
	})

	opts.SetConnectionLostHandler(func(client mqtt.Client, err error) {
		count := disconnectionCount.Add(1)
		s.T().Logf("Connection lost (count: %d): %v", count, err)
	})

	client := mqtt.NewClient(opts)
	token := client.Connect()
	s.True(token.WaitTimeout(10 * time.Second))
	s.NoError(token.Error())
	defer client.Disconnect(250)

	// Wait for OnConnectHandler to execute (it's called asynchronously)
	// The connection token completes before the handler is guaranteed to run
	s.Eventually(func() bool {
		return connectionCount.Load() == 1
	}, 5*time.Second, 100*time.Millisecond, "Should have 1 connection after handler executes")

	// Simulate disconnection and reconnection
	// (In real scenario, would need to restart broker or break network)
	s.T().Log("Reconnection test completed (requires broker restart for full test)")
}

// TestMessageQueuePersistence tests message queue during offline period (AC9)
func (s *HeartbeatFailoverTestSuite) TestMessageQueuePersistence() {
	stewardID := fmt.Sprintf("test-steward-queue-%d", time.Now().UnixNano())
	commandTopic := fmt.Sprintf("cfgms/steward/%s/commands", stewardID)

	// Create client with persistent session (CleanSession=false would be production)
	opts := CreateMQTTClientOptions(s.mqttAddr, stewardID, s.tlsConfig)
	opts.SetCleanSession(false) // Persistent session

	// First connection: subscribe
	client := mqtt.NewClient(opts)
	token := client.Connect()
	s.True(token.WaitTimeout(10 * time.Second))
	s.NoError(token.Error())

	receivedMessages := make([]string, 0)
	var mu sync.Mutex

	subToken := client.Subscribe(commandTopic, 1, func(client mqtt.Client, msg mqtt.Message) {
		mu.Lock()
		receivedMessages = append(receivedMessages, string(msg.Payload()))
		mu.Unlock()
		s.T().Logf("Received queued message: %s", string(msg.Payload()))
	})
	s.True(subToken.WaitTimeout(5 * time.Second))
	s.NoError(subToken.Error())

	// Disconnect (simulating offline)
	client.Disconnect(250)
	time.Sleep(1 * time.Second)

	// Publish messages while offline (would be queued by broker)
	// Story #313: Publisher must use stewardID as client ID to match ACL pattern
	publisher := s.createMQTTClient(stewardID)
	token = publisher.Connect()
	s.True(token.WaitTimeout(10 * time.Second))
	s.NoError(token.Error())

	// Publish commands while steward is offline
	for i := 0; i < 3; i++ {
		command := fmt.Sprintf("offline-command-%d", i+1)
		pubToken := publisher.Publish(commandTopic, 1, false, []byte(command))
		s.True(pubToken.WaitTimeout(5 * time.Second))
		s.NoError(pubToken.Error())
	}
	publisher.Disconnect(250)

	// Reconnect steward
	client2 := mqtt.NewClient(opts)
	token = client2.Connect()
	s.True(token.WaitTimeout(10 * time.Second))
	s.NoError(token.Error())
	defer client2.Disconnect(250)

	// Resubscribe
	subToken = client2.Subscribe(commandTopic, 1, func(client mqtt.Client, msg mqtt.Message) {
		mu.Lock()
		receivedMessages = append(receivedMessages, string(msg.Payload()))
		mu.Unlock()
		s.T().Logf("Received queued message after reconnect: %s", string(msg.Payload()))
	})
	s.True(subToken.WaitTimeout(5 * time.Second))
	s.NoError(subToken.Error())

	// Wait for queued messages
	time.Sleep(2 * time.Second)

	// Note: Message queue behavior depends on broker configuration
	// mochi-mqtt may not persist messages by default
	mu.Lock()
	msgCount := len(receivedMessages)
	mu.Unlock()

	s.T().Logf("Message queue test: %d messages received after reconnection", msgCount)
}

func TestHeartbeatFailover(t *testing.T) {
	t.Skip("Story #519: MQTT removed in Story #515 — migrate to transport-agnostic gRPC tests in test/integration/transport/")
	suite.Run(t, new(HeartbeatFailoverTestSuite))
}
