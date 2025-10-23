// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 CFGMS Contributors
package mqtt_quic

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"sync"
	"testing"
	"time"

	mqtt "github.com/eclipse/paho.mqtt.golang"
	"github.com/stretchr/testify/suite"
)

// MultiTenantTestSuite tests multi-tenant isolation in MQTT+QUIC architecture
// Story 12.5: Multi-Tenant Isolation Testing
//
// This suite validates that multiple tenants can run simultaneously with proper isolation:
// - AC1: Multiple tenants run simultaneously in Docker (3 minimum)
// - AC2: MQTT topics enforce tenant isolation (tenant1 vs tenant2)
// - AC3: Cross-tenant message delivery prevention
// - AC4: Configuration routing respects tenant boundaries
// - AC5: DNA collection separated by tenant ID
// - AC6: Heartbeats isolated per tenant
type MultiTenantTestSuite struct {
	suite.Suite
	helper        *TestHelper
	tenantClients map[string]mqtt.Client
	mu            sync.RWMutex
}

func (s *MultiTenantTestSuite) SetupSuite() {
	// Connect to Docker controller
	s.helper = NewTestHelper(GetTestHTTPAddr("http://localhost:9080"))
	s.tenantClients = make(map[string]mqtt.Client)
}

func (s *MultiTenantTestSuite) TearDownSuite() {
	// Disconnect all tenant MQTT clients
	s.mu.Lock()
	defer s.mu.Unlock()

	for tenantID, client := range s.tenantClients {
		if client != nil && client.IsConnected() {
			client.Disconnect(250)
			s.T().Logf("Disconnected tenant %s MQTT client", tenantID)
		}
	}
}

// AC1: TestSimultaneousTenants validates that multiple tenants run simultaneously in Docker
func (s *MultiTenantTestSuite) TestSimultaneousTenants() {
	s.T().Log("AC1: Testing multiple tenants run simultaneously in Docker (3 minimum)")

	// Define tenant configurations
	tenants := []struct {
		tenantID string
		token    string
	}{
		{"tenant1", "cfgms_reg_tenant1"},
		{"tenant2", "cfgms_reg_tenant2"},
		{"tenant3", "cfgms_reg_tenant3"},
	}

	// Register all tenants concurrently
	var wg sync.WaitGroup
	registrations := make(chan *RegistrationResponse, len(tenants))
	errors := make(chan error, len(tenants))

	for _, tenant := range tenants {
		wg.Add(1)
		go func(tenantID, token string) {
			defer wg.Done()

			regResp := s.helper.RegisterSteward(s.T(), token)
			if regResp == nil {
				errors <- fmt.Errorf("registration failed for tenant %s", tenantID)
				return
			}
			registrations <- regResp
		}(tenant.tenantID, tenant.token)
	}

	wg.Wait()
	close(registrations)
	close(errors)

	// Verify no errors
	for err := range errors {
		s.NoError(err, "Tenant registration should not fail")
	}

	// Verify all registrations succeeded
	regCount := 0
	for regResp := range registrations {
		s.NotEmpty(regResp.StewardID, "Steward ID should be assigned")
		s.NotEmpty(regResp.MQTTBroker, "MQTT broker should be assigned")
		regCount++
	}

	s.Equal(3, regCount, "All 3 tenants should successfully register")
	s.T().Logf("✅ AC1 PASSED: 3 tenants running simultaneously")
}

// AC2: TestMQTTTopicIsolation validates MQTT topic isolation between tenants
func (s *MultiTenantTestSuite) TestMQTTTopicIsolation() {
	s.T().Log("AC2: Testing MQTT topic isolation (tenant1 vs tenant2)")

	certsPath := GetTestCertsPath("./certs")
	tlsConfig := LoadTLSConfig(s.T(), certsPath)
	brokerAddr := GetTestMQTTAddr("ssl://localhost:1886")

	// Create MQTT clients for tenant1 and tenant2
	tenant1Client := s.createTenantMQTTClient("tenant1", brokerAddr, tlsConfig)
	tenant2Client := s.createTenantMQTTClient("tenant2", brokerAddr, tlsConfig)

	// Message tracking
	tenant1Messages := make(chan string, 10)
	tenant2Messages := make(chan string, 10)

	// Subscribe tenant1 to its topic
	tenant1Topic := "cfgms/steward/tenant1/#"
	token := tenant1Client.Subscribe(tenant1Topic, 0, func(client mqtt.Client, msg mqtt.Message) {
		tenant1Messages <- string(msg.Payload())
		s.T().Logf("Tenant1 received message on %s: %s", msg.Topic(), msg.Payload())
	})
	s.True(token.WaitTimeout(5*time.Second), "Tenant1 subscribe should succeed")
	s.NoError(token.Error(), "Tenant1 subscribe should not error")

	// Subscribe tenant2 to its topic
	tenant2Topic := "cfgms/steward/tenant2/#"
	token = tenant2Client.Subscribe(tenant2Topic, 0, func(client mqtt.Client, msg mqtt.Message) {
		tenant2Messages <- string(msg.Payload())
		s.T().Logf("Tenant2 received message on %s: %s", msg.Topic(), msg.Payload())
	})
	s.True(token.WaitTimeout(5*time.Second), "Tenant2 subscribe should succeed")
	s.NoError(token.Error(), "Tenant2 subscribe should not error")

	// Publish message to tenant1 topic
	tenant1Msg := "message-for-tenant1"
	token = tenant1Client.Publish("cfgms/steward/tenant1/test", 0, false, tenant1Msg)
	s.True(token.WaitTimeout(5*time.Second), "Tenant1 publish should succeed")

	// Publish message to tenant2 topic
	tenant2Msg := "message-for-tenant2"
	token = tenant2Client.Publish("cfgms/steward/tenant2/test", 0, false, tenant2Msg)
	s.True(token.WaitTimeout(5*time.Second), "Tenant2 publish should succeed")

	// Wait for messages with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	// Verify tenant1 only receives its own message
	select {
	case msg := <-tenant1Messages:
		s.Equal(tenant1Msg, msg, "Tenant1 should receive its own message")
	case <-ctx.Done():
		s.Fail("Tenant1 should receive message before timeout")
	}

	// Verify tenant2 only receives its own message
	ctx2, cancel2 := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel2()

	select {
	case msg := <-tenant2Messages:
		s.Equal(tenant2Msg, msg, "Tenant2 should receive its own message")
	case <-ctx2.Done():
		s.Fail("Tenant2 should receive message before timeout")
	}

	// Verify no cross-tenant message leakage (wait briefly)
	time.Sleep(1 * time.Second)
	select {
	case msg := <-tenant1Messages:
		s.Fail(fmt.Sprintf("Tenant1 should NOT receive tenant2 message: %s", msg))
	default:
		// Expected: no message
	}

	select {
	case msg := <-tenant2Messages:
		s.Fail(fmt.Sprintf("Tenant2 should NOT receive tenant1 message: %s", msg))
	default:
		// Expected: no message
	}

	s.T().Logf("✅ AC2 PASSED: MQTT topic isolation enforced")
}

// AC3: TestCrossTenantMessagePrevention validates cross-tenant message delivery prevention
func (s *MultiTenantTestSuite) TestCrossTenantMessagePrevention() {
	s.T().Log("AC3: Testing cross-tenant message delivery prevention")

	certsPath := GetTestCertsPath("./certs")
	tlsConfig := LoadTLSConfig(s.T(), certsPath)
	brokerAddr := GetTestMQTTAddr("ssl://localhost:1886")

	// Create tenant clients
	tenant1Client := s.createTenantMQTTClient("tenant1", brokerAddr, tlsConfig)
	tenant3Client := s.createTenantMQTTClient("tenant3", brokerAddr, tlsConfig)

	receivedMessages := make(chan string, 10)

	// Tenant1 attempts to subscribe to tenant3's topic (should be isolated)
	maliciousTopic := "cfgms/steward/tenant3/#"
	token := tenant1Client.Subscribe(maliciousTopic, 0, func(client mqtt.Client, msg mqtt.Message) {
		receivedMessages <- string(msg.Payload())
		s.T().Logf("Tenant1 received cross-tenant message: %s", msg.Payload())
	})
	s.True(token.WaitTimeout(5*time.Second), "Subscribe should complete (may succeed or fail)")

	// Tenant3 publishes a message
	tenant3Msg := "secret-tenant3-message"
	token = tenant3Client.Publish("cfgms/steward/tenant3/secret", 0, false, tenant3Msg)
	s.True(token.WaitTimeout(5*time.Second), "Tenant3 publish should succeed")

	// Wait to ensure tenant1 does NOT receive tenant3's message
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	select {
	case msg := <-receivedMessages:
		s.Fail(fmt.Sprintf("Cross-tenant message delivery detected! Tenant1 received: %s", msg))
	case <-ctx.Done():
		// Expected: timeout without receiving message
		s.T().Log("✅ Cross-tenant message delivery prevented")
	}

	s.T().Logf("✅ AC3 PASSED: Cross-tenant message delivery prevention enforced")
}

// AC4: TestConfigurationRoutingBoundaries validates configuration routing respects tenant boundaries
func (s *MultiTenantTestSuite) TestConfigurationRoutingBoundaries() {
	s.T().Log("AC4: Testing configuration routing respects tenant boundaries")

	certsPath := GetTestCertsPath("./certs")
	tlsConfig := LoadTLSConfig(s.T(), certsPath)
	brokerAddr := GetTestMQTTAddr("ssl://localhost:1886")

	// Create tenant clients
	tenant1Client := s.createTenantMQTTClient("tenant1-config", brokerAddr, tlsConfig)
	tenant2Client := s.createTenantMQTTClient("tenant2-config", brokerAddr, tlsConfig)

	tenant1Configs := make(chan string, 10)
	tenant2Configs := make(chan string, 10)

	// Subscribe to configuration topics
	token := tenant1Client.Subscribe("cfgms/steward/tenant1/+/config", 0, func(client mqtt.Client, msg mqtt.Message) {
		tenant1Configs <- string(msg.Payload())
		s.T().Logf("Tenant1 received config on %s", msg.Topic())
	})
	s.True(token.WaitTimeout(5*time.Second), "Tenant1 config subscribe should succeed")

	token = tenant2Client.Subscribe("cfgms/steward/tenant2/+/config", 0, func(client mqtt.Client, msg mqtt.Message) {
		tenant2Configs <- string(msg.Payload())
		s.T().Logf("Tenant2 received config on %s", msg.Topic())
	})
	s.True(token.WaitTimeout(5*time.Second), "Tenant2 config subscribe should succeed")

	// Publish tenant-specific configurations
	tenant1ConfigPayload := `{"version":"1.0","tenant":"tenant1","modules":{"file":[]}}`
	token = tenant1Client.Publish("cfgms/steward/tenant1/steward123/config", 0, false, tenant1ConfigPayload)
	s.True(token.WaitTimeout(5*time.Second), "Tenant1 config publish should succeed")

	tenant2ConfigPayload := `{"version":"1.0","tenant":"tenant2","modules":{"file":[]}}`
	token = tenant2Client.Publish("cfgms/steward/tenant2/steward456/config", 0, false, tenant2ConfigPayload)
	s.True(token.WaitTimeout(5*time.Second), "Tenant2 config publish should succeed")

	// Verify tenant1 receives only its config
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	select {
	case config := <-tenant1Configs:
		s.Contains(config, "tenant1", "Tenant1 should receive its own config")
		s.NotContains(config, "tenant2", "Tenant1 should NOT receive tenant2 config")
	case <-ctx.Done():
		s.Fail("Tenant1 should receive config before timeout")
	}

	// Verify tenant2 receives only its config
	ctx2, cancel2 := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel2()

	select {
	case config := <-tenant2Configs:
		s.Contains(config, "tenant2", "Tenant2 should receive its own config")
		s.NotContains(config, "tenant1", "Tenant2 should NOT receive tenant1 config")
	case <-ctx2.Done():
		s.Fail("Tenant2 should receive config before timeout")
	}

	s.T().Logf("✅ AC4 PASSED: Configuration routing respects tenant boundaries")
}

// AC5: TestDNACollectionSeparation validates DNA collection separated by tenant ID
func (s *MultiTenantTestSuite) TestDNACollectionSeparation() {
	s.T().Log("AC5: Testing DNA collection separated by tenant ID")

	certsPath := GetTestCertsPath("./certs")
	tlsConfig := LoadTLSConfig(s.T(), certsPath)
	brokerAddr := GetTestMQTTAddr("ssl://localhost:1886")

	// Create tenant clients
	tenant1Client := s.createTenantMQTTClient("tenant1-dna", brokerAddr, tlsConfig)
	tenant2Client := s.createTenantMQTTClient("tenant2-dna", brokerAddr, tlsConfig)

	tenant1DNA := make(chan map[string]interface{}, 10)
	tenant2DNA := make(chan map[string]interface{}, 10)

	// Subscribe to DNA update topics
	token := tenant1Client.Subscribe("cfgms/steward/tenant1/+/dna", 0, func(client mqtt.Client, msg mqtt.Message) {
		var dna map[string]interface{}
		if err := json.Unmarshal(msg.Payload(), &dna); err == nil {
			tenant1DNA <- dna
			s.T().Logf("Tenant1 received DNA update: %s", msg.Payload())
		}
	})
	s.True(token.WaitTimeout(5*time.Second), "Tenant1 DNA subscribe should succeed")

	token = tenant2Client.Subscribe("cfgms/steward/tenant2/+/dna", 0, func(client mqtt.Client, msg mqtt.Message) {
		var dna map[string]interface{}
		if err := json.Unmarshal(msg.Payload(), &dna); err == nil {
			tenant2DNA <- dna
			s.T().Logf("Tenant2 received DNA update: %s", msg.Payload())
		}
	})
	s.True(token.WaitTimeout(5*time.Second), "Tenant2 DNA subscribe should succeed")

	// Simulate DNA collection from each tenant
	tenant1DNAPayload := `{"tenant_id":"tenant1","steward_id":"steward-t1","hostname":"host-tenant1","timestamp":"2025-01-01T00:00:00Z"}`
	token = tenant1Client.Publish("cfgms/steward/tenant1/steward-t1/dna", 0, false, tenant1DNAPayload)
	s.True(token.WaitTimeout(5*time.Second), "Tenant1 DNA publish should succeed")

	tenant2DNAPayload := `{"tenant_id":"tenant2","steward_id":"steward-t2","hostname":"host-tenant2","timestamp":"2025-01-01T00:00:00Z"}`
	token = tenant2Client.Publish("cfgms/steward/tenant2/steward-t2/dna", 0, false, tenant2DNAPayload)
	s.True(token.WaitTimeout(5*time.Second), "Tenant2 DNA publish should succeed")

	// Verify tenant1 DNA isolation
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	select {
	case dna := <-tenant1DNA:
		s.Equal("tenant1", dna["tenant_id"], "Tenant1 DNA should have correct tenant_id")
		s.Equal("host-tenant1", dna["hostname"], "Tenant1 DNA should have correct hostname")
	case <-ctx.Done():
		s.Fail("Tenant1 should receive DNA update before timeout")
	}

	// Verify tenant2 DNA isolation
	ctx2, cancel2 := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel2()

	select {
	case dna := <-tenant2DNA:
		s.Equal("tenant2", dna["tenant_id"], "Tenant2 DNA should have correct tenant_id")
		s.Equal("host-tenant2", dna["hostname"], "Tenant2 DNA should have correct hostname")
	case <-ctx2.Done():
		s.Fail("Tenant2 should receive DNA update before timeout")
	}

	s.T().Logf("✅ AC5 PASSED: DNA collection separated by tenant ID")
}

// AC6: TestHeartbeatIsolation validates heartbeats isolated per tenant
func (s *MultiTenantTestSuite) TestHeartbeatIsolation() {
	s.T().Log("AC6: Testing heartbeats isolated per tenant")

	certsPath := GetTestCertsPath("./certs")
	tlsConfig := LoadTLSConfig(s.T(), certsPath)
	brokerAddr := GetTestMQTTAddr("ssl://localhost:1886")

	// Create tenant clients
	tenant1Client := s.createTenantMQTTClient("tenant1-hb", brokerAddr, tlsConfig)
	tenant3Client := s.createTenantMQTTClient("tenant3-hb", brokerAddr, tlsConfig)

	tenant1Heartbeats := make(chan string, 10)
	tenant3Heartbeats := make(chan string, 10)

	// Subscribe to heartbeat topics
	token := tenant1Client.Subscribe("cfgms/steward/tenant1/+/heartbeat", 0, func(client mqtt.Client, msg mqtt.Message) {
		tenant1Heartbeats <- string(msg.Payload())
		s.T().Logf("Tenant1 heartbeat: %s", msg.Payload())
	})
	s.True(token.WaitTimeout(5*time.Second), "Tenant1 heartbeat subscribe should succeed")

	token = tenant3Client.Subscribe("cfgms/steward/tenant3/+/heartbeat", 0, func(client mqtt.Client, msg mqtt.Message) {
		tenant3Heartbeats <- string(msg.Payload())
		s.T().Logf("Tenant3 heartbeat: %s", msg.Payload())
	})
	s.True(token.WaitTimeout(5*time.Second), "Tenant3 heartbeat subscribe should succeed")

	// Publish heartbeats from each tenant
	tenant1HBPayload := `{"tenant_id":"tenant1","steward_id":"steward-t1-hb","status":"online","timestamp":"2025-01-01T00:00:00Z"}`
	token = tenant1Client.Publish("cfgms/steward/tenant1/steward-t1-hb/heartbeat", 0, false, tenant1HBPayload)
	s.True(token.WaitTimeout(5*time.Second), "Tenant1 heartbeat publish should succeed")

	tenant3HBPayload := `{"tenant_id":"tenant3","steward_id":"steward-t3-hb","status":"online","timestamp":"2025-01-01T00:00:00Z"}`
	token = tenant3Client.Publish("cfgms/steward/tenant3/steward-t3-hb/heartbeat", 0, false, tenant3HBPayload)
	s.True(token.WaitTimeout(5*time.Second), "Tenant3 heartbeat publish should succeed")

	// Verify tenant1 receives only its heartbeat
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	select {
	case hb := <-tenant1Heartbeats:
		s.Contains(hb, "tenant1", "Tenant1 should receive its own heartbeat")
		s.NotContains(hb, "tenant3", "Tenant1 should NOT receive tenant3 heartbeat")
	case <-ctx.Done():
		s.Fail("Tenant1 should receive heartbeat before timeout")
	}

	// Verify tenant3 receives only its heartbeat
	ctx2, cancel2 := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel2()

	select {
	case hb := <-tenant3Heartbeats:
		s.Contains(hb, "tenant3", "Tenant3 should receive its own heartbeat")
		s.NotContains(hb, "tenant1", "Tenant3 should NOT receive tenant1 heartbeat")
	case <-ctx2.Done():
		s.Fail("Tenant3 should receive heartbeat before timeout")
	}

	s.T().Logf("✅ AC6 PASSED: Heartbeats isolated per tenant")
}

// createTenantMQTTClient creates an MQTT client for a specific tenant
func (s *MultiTenantTestSuite) createTenantMQTTClient(clientID, brokerAddr string, tlsConfig *tls.Config) mqtt.Client {
	opts := CreateMQTTClientOptions(brokerAddr, clientID, tlsConfig)
	client := mqtt.NewClient(opts)

	token := client.Connect()
	s.True(token.WaitTimeout(10*time.Second), fmt.Sprintf("MQTT connect should succeed for %s", clientID))
	s.NoError(token.Error(), fmt.Sprintf("MQTT connect should not error for %s", clientID))

	// Store client for cleanup
	s.mu.Lock()
	s.tenantClients[clientID] = client
	s.mu.Unlock()

	s.T().Logf("Created MQTT client for %s", clientID)
	return client
}

func TestMultiTenant(t *testing.T) {
	suite.Run(t, new(MultiTenantTestSuite))
}
