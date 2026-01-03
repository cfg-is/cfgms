// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 CFGMS Contributors
package mqtt_quic

import (
	"encoding/json"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/suite"

	mqtt "github.com/eclipse/paho.mqtt.golang"
)

// MQTTConnectivityTestSuite tests MQTT broker connectivity and messaging
// AC2: MQTT connectivity test (steward connects, subscribes, publishes, receives messages)
type MQTTConnectivityTestSuite struct {
	suite.Suite
	helper     *TestHelper
	mqttClient mqtt.Client
	mqttAddr   string
}

func (s *MQTTConnectivityTestSuite) SetupSuite() {
	s.T().Skip("Skipping until Issue #294: E2E test framework for MQTT+QUIC mode not yet implemented - requires running controller, MQTT broker, and steward infrastructure")
	s.helper = NewTestHelper(GetTestHTTPAddr("http://localhost:8080"))
	s.mqttAddr = GetTestMQTTAddr("ssl://localhost:1886") // Docker controller MQTT broker port with TLS
}

func (s *MQTTConnectivityTestSuite) TearDownSuite() {
	if s.mqttClient != nil && s.mqttClient.IsConnected() {
		s.mqttClient.Disconnect(250)
	}
}

// TestMQTTBrokerConnectivity tests basic MQTT broker connection
func (s *MQTTConnectivityTestSuite) TestMQTTBrokerConnectivity() {
	// Register steward to get certificates (mirrors real-world flow)
	regToken := s.helper.CreateToken(s.T(), "test-tenant", "production")
	regResp := s.helper.RegisterSteward(s.T(), regToken)

	s.T().Logf("Registered steward: %s", regResp.StewardID)
	s.NotEmpty(regResp.ClientCert, "Should receive client certificate")
	s.NotEmpty(regResp.ClientKey, "Should receive client key")
	s.NotEmpty(regResp.CACert, "Should receive CA certificate")

	// Create TLS config from registration response (like real steward)
	tlsConfig, err := LoadTLSConfigFromPEM(
		[]byte(regResp.CACert),
		[]byte(regResp.ClientCert),
		[]byte(regResp.ClientKey),
	)
	s.Require().NoError(err, "Should create TLS config from registration response")

	// Create MQTT client options with TLS
	opts := CreateMQTTClientOptions(
		s.mqttAddr,
		regResp.StewardID,
		tlsConfig,
	)

	// Create client
	client := mqtt.NewClient(opts)

	// Connect to broker
	connectToken := client.Connect()
	success := connectToken.WaitTimeout(10 * time.Second)
	s.True(success, "Should connect to MQTT broker within timeout")
	s.NoError(connectToken.Error(), "Connection should succeed without error")

	// Verify connection
	s.True(client.IsConnected(), "Client should be connected")

	s.T().Logf("Successfully connected to MQTT broker at %s", s.mqttAddr)

	// Disconnect
	client.Disconnect(250)
	time.Sleep(500 * time.Millisecond)
	s.False(client.IsConnected(), "Client should be disconnected")
}

// TestMQTTSubscription tests MQTT topic subscription
func (s *MQTTConnectivityTestSuite) TestMQTTSubscription() {
	// Connect to broker
	opts := mqtt.NewClientOptions()
	opts.AddBroker(s.mqttAddr)
	opts.SetClientID(fmt.Sprintf("test-sub-%d", time.Now().UnixNano()))
	opts.SetConnectTimeout(10 * time.Second)

	client := mqtt.NewClient(opts)
	token := client.Connect()
	s.True(token.WaitTimeout(10 * time.Second))
	s.NoError(token.Error())
	defer client.Disconnect(250)

	// Subscribe to test topic
	testTopic := fmt.Sprintf("cfgms/test/%d", time.Now().UnixNano())
	received := make(chan bool, 1)

	subToken := client.Subscribe(testTopic, 1, func(client mqtt.Client, msg mqtt.Message) {
		s.T().Logf("Received message on topic %s: %s", msg.Topic(), string(msg.Payload()))
		received <- true
	})

	success := subToken.WaitTimeout(5 * time.Second)
	s.True(success, "Should subscribe successfully")
	s.NoError(subToken.Error())

	s.T().Logf("Successfully subscribed to topic %s", testTopic)

	// Publish test message
	pubToken := client.Publish(testTopic, 1, false, []byte("test message"))
	success = pubToken.WaitTimeout(5 * time.Second)
	s.True(success, "Should publish successfully")
	s.NoError(pubToken.Error())

	// Wait for message
	select {
	case <-received:
		s.T().Log("Message received successfully")
	case <-time.After(5 * time.Second):
		s.Fail("Timeout waiting for message")
	}
}

// TestMQTTPublishReceive tests publish and receive on steward command topic
func (s *MQTTConnectivityTestSuite) TestMQTTPublishReceive() {
	// Create steward client
	stewardID := "test-steward-123"
	commandTopic := fmt.Sprintf("cfgms/steward/%s/commands", stewardID)

	opts := mqtt.NewClientOptions()
	opts.AddBroker(s.mqttAddr)
	opts.SetClientID(stewardID)
	opts.SetConnectTimeout(10 * time.Second)

	stewardClient := mqtt.NewClient(opts)
	token := stewardClient.Connect()
	s.True(token.WaitTimeout(10 * time.Second))
	s.NoError(token.Error())
	defer stewardClient.Disconnect(250)

	// Subscribe to command topic
	var mu sync.Mutex
	receivedMessages := []string{}

	subToken := stewardClient.Subscribe(commandTopic, 1, func(client mqtt.Client, msg mqtt.Message) {
		mu.Lock()
		receivedMessages = append(receivedMessages, string(msg.Payload()))
		mu.Unlock()
		s.T().Logf("Steward received command: %s", string(msg.Payload()))
	})

	s.True(subToken.WaitTimeout(5 * time.Second))
	s.NoError(subToken.Error())

	// Create controller client to publish command
	controllerOpts := mqtt.NewClientOptions()
	controllerOpts.AddBroker(s.mqttAddr)
	controllerOpts.SetClientID("test-controller")
	controllerOpts.SetConnectTimeout(10 * time.Second)

	controllerClient := mqtt.NewClient(controllerOpts)
	token = controllerClient.Connect()
	s.True(token.WaitTimeout(10 * time.Second))
	s.NoError(token.Error())
	defer controllerClient.Disconnect(250)

	// Publish command from controller
	command := map[string]interface{}{
		"command_id": "cmd-123",
		"type":       "sync_config",
		"timestamp":  time.Now().Unix(),
		"params": map[string]interface{}{
			"modules": []string{"file", "directory"},
		},
	}

	commandJSON, err := json.Marshal(command)
	s.NoError(err)

	pubToken := controllerClient.Publish(commandTopic, 1, false, commandJSON)
	s.True(pubToken.WaitTimeout(5 * time.Second))
	s.NoError(pubToken.Error())

	// Wait for message delivery
	time.Sleep(1 * time.Second)

	// Verify message received
	mu.Lock()
	msgCount := len(receivedMessages)
	mu.Unlock()

	s.Equal(1, msgCount, "Should receive exactly one command")

	if msgCount > 0 {
		mu.Lock()
		receivedMsg := receivedMessages[0]
		mu.Unlock()

		var receivedCmd map[string]interface{}
		err := json.Unmarshal([]byte(receivedMsg), &receivedCmd)
		s.NoError(err)
		s.Equal("cmd-123", receivedCmd["command_id"])
		s.Equal("sync_config", receivedCmd["type"])
	}
}

// TestMQTTHeartbeatTopic tests heartbeat topic publishing
func (s *MQTTConnectivityTestSuite) TestMQTTHeartbeatTopic() {
	stewardID := "test-steward-heartbeat"
	heartbeatTopic := fmt.Sprintf("cfgms/steward/%s/heartbeat", stewardID)

	// Create steward client
	opts := mqtt.NewClientOptions()
	opts.AddBroker(s.mqttAddr)
	opts.SetClientID(stewardID)
	opts.SetConnectTimeout(10 * time.Second)

	client := mqtt.NewClient(opts)
	token := client.Connect()
	s.True(token.WaitTimeout(10 * time.Second))
	s.NoError(token.Error())
	defer client.Disconnect(250)

	// Publish heartbeat
	heartbeat := map[string]interface{}{
		"steward_id": stewardID,
		"status":     "healthy",
		"timestamp":  time.Now().Unix(),
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

	s.T().Logf("Published heartbeat to %s", heartbeatTopic)
}

// TestMQTTQoSLevels tests different QoS levels
func (s *MQTTConnectivityTestSuite) TestMQTTQoSLevels() {
	opts := mqtt.NewClientOptions()
	opts.AddBroker(s.mqttAddr)
	opts.SetClientID(fmt.Sprintf("test-qos-%d", time.Now().UnixNano()))
	opts.SetConnectTimeout(10 * time.Second)

	client := mqtt.NewClient(opts)
	token := client.Connect()
	s.True(token.WaitTimeout(10 * time.Second))
	s.NoError(token.Error())
	defer client.Disconnect(250)

	testTopic := fmt.Sprintf("cfgms/test/qos/%d", time.Now().UnixNano())

	// Test QoS 0, 1, 2
	qosLevels := []byte{0, 1, 2}
	for _, qos := range qosLevels {
		received := make(chan bool, 1)

		// Subscribe with specific QoS
		subToken := client.Subscribe(testTopic, qos, func(client mqtt.Client, msg mqtt.Message) {
			s.T().Logf("Received message with QoS %d", qos)
			received <- true
		})

		s.True(subToken.WaitTimeout(5 * time.Second))
		s.NoError(subToken.Error())

		// Publish with specific QoS
		payload := fmt.Sprintf("test message QoS %d", qos)
		pubToken := client.Publish(testTopic, qos, false, []byte(payload))
		s.True(pubToken.WaitTimeout(5 * time.Second))
		s.NoError(pubToken.Error())

		// Wait for message
		select {
		case <-received:
			s.T().Logf("QoS %d test successful", qos)
		case <-time.After(5 * time.Second):
			s.Fail(fmt.Sprintf("Timeout waiting for QoS %d message", qos))
		}

		// Unsubscribe before next test
		unsubToken := client.Unsubscribe(testTopic)
		s.True(unsubToken.WaitTimeout(2 * time.Second))
	}
}

// TestMQTTConcurrentConnections tests multiple simultaneous connections
func (s *MQTTConnectivityTestSuite) TestMQTTConcurrentConnections() {
	const numClients = 20

	var wg sync.WaitGroup
	errors := make(chan error, numClients)

	for i := 0; i < numClients; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()

			opts := mqtt.NewClientOptions()
			opts.AddBroker(s.mqttAddr)
			opts.SetClientID(fmt.Sprintf("concurrent-client-%d", idx))
			opts.SetConnectTimeout(10 * time.Second)

			client := mqtt.NewClient(opts)
			token := client.Connect()
			if !token.WaitTimeout(10 * time.Second) {
				errors <- fmt.Errorf("client %d: connection timeout", idx)
				return
			}
			if err := token.Error(); err != nil {
				errors <- fmt.Errorf("client %d: %w", idx, err)
				return
			}

			defer client.Disconnect(250)

			// Publish test message
			topic := fmt.Sprintf("cfgms/test/concurrent/%d", idx)
			pubToken := client.Publish(topic, 1, false, []byte(fmt.Sprintf("message from client %d", idx)))
			if !pubToken.WaitTimeout(5 * time.Second) {
				errors <- fmt.Errorf("client %d: publish timeout", idx)
				return
			}
			if err := pubToken.Error(); err != nil {
				errors <- fmt.Errorf("client %d: publish error: %w", idx, err)
				return
			}

			errors <- nil
		}(i)
	}

	wg.Wait()
	close(errors)

	// Count successes
	successCount := 0
	for err := range errors {
		if err == nil {
			successCount++
		} else {
			s.T().Logf("Connection error: %v", err)
		}
	}

	s.Equal(numClients, successCount, "All concurrent clients should connect successfully")
	s.T().Logf("Successfully connected %d concurrent MQTT clients", successCount)
}

// TestMQTTKeepAlive tests MQTT keepalive mechanism
func (s *MQTTConnectivityTestSuite) TestMQTTKeepAlive() {
	opts := mqtt.NewClientOptions()
	opts.AddBroker(s.mqttAddr)
	opts.SetClientID(fmt.Sprintf("test-keepalive-%d", time.Now().UnixNano()))
	opts.SetKeepAlive(2 * time.Second) // 2 second keepalive
	opts.SetConnectTimeout(10 * time.Second)

	client := mqtt.NewClient(opts)
	token := client.Connect()
	s.True(token.WaitTimeout(10 * time.Second))
	s.NoError(token.Error())
	defer client.Disconnect(250)

	// Wait longer than keepalive interval
	time.Sleep(5 * time.Second)

	// Connection should still be alive
	s.True(client.IsConnected(), "Connection should remain alive with keepalive")

	s.T().Log("Keepalive mechanism working correctly")
}

// TestMQTTReconnection tests automatic reconnection
func (s *MQTTConnectivityTestSuite) TestMQTTReconnection() {
	s.T().Skip("Reconnection test requires broker restart - skipping in CI")

	// This test would require:
	// 1. Connect to broker
	// 2. Simulate broker restart/disconnect
	// 3. Verify automatic reconnection
	// 4. Verify message queue delivery after reconnection
}

func TestMQTTConnectivity(t *testing.T) {
	suite.Run(t, new(MQTTConnectivityTestSuite))
}
