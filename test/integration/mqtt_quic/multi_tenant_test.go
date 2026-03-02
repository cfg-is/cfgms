// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
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
	tlsConfig     *tls.Config
	stewardID     string
}

func (s *MultiTenantTestSuite) SetupSuite() {
	// Skip if running in short/fast mode - requires MQTT broker and controller infrastructure
	if testing.Short() {
		s.T().Skip("Skipping multi-tenant tests in short mode - requires infrastructure")
	}

	// Connect to Docker controller
	s.helper = NewTestHelper(GetTestHTTPAddr("https://localhost:8080"))
	s.tenantClients = make(map[string]mqtt.Client)

	// Get TLS config from registration API (required for mTLS)
	s.tlsConfig, s.stewardID = s.helper.GetTLSConfigFromRegistration(s.T(), "default", "integration-test")
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
		group    string
	}{
		{"tenant1", "integration-test"},
		{"tenant2", "integration-test"},
		{"tenant3", "integration-test"},
	}

	// Register all tenants concurrently
	var wg sync.WaitGroup
	registrations := make(chan *RegistrationResponse, len(tenants))
	errors := make(chan error, len(tenants))

	for _, tenant := range tenants {
		wg.Add(1)
		go func(tenantID, group string) {
			defer wg.Done()

			// Create token and register
			token := s.helper.CreateToken(s.T(), tenantID, group)
			regResp := s.helper.RegisterSteward(s.T(), token)
			if regResp == nil {
				errors <- fmt.Errorf("registration failed for tenant %s", tenantID)
				return
			}
			registrations <- regResp
		}(tenant.tenantID, tenant.group)
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

	tlsConfig := s.tlsConfig
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

// AC2-Deny: TestTopicIsolationDenial proves ACLs block cross-tenant topic subscriptions.
// The happy-path AC2 test only validates routing; this test proves the broker actively denies
// cross-tenant access by using the same positive+negative control pattern as AC3.
func (s *MultiTenantTestSuite) TestTopicIsolationDenial() {
	s.T().Log("AC2-Deny: Testing ACL denial of cross-tenant topic subscription")

	brokerAddr := GetTestMQTTAddr("ssl://localhost:1886")

	// Separate registrations — each tenant gets a unique steward ID and certificate
	tenant1TLS, tenant1ID := s.helper.GetTLSConfigFromRegistration(s.T(), "tenant1", "integration-test")
	tenant2TLS, tenant2ID := s.helper.GetTLSConfigFromRegistration(s.T(), "tenant2", "integration-test")

	tenant1Client := s.createTenantMQTTClient(tenant1ID, brokerAddr, tenant1TLS)
	tenant2Client := s.createTenantMQTTClient(tenant2ID, brokerAddr, tenant2TLS)

	ownMessages := make(chan string, 10)
	crossTenantMessages := make(chan string, 10)

	// Tenant1 subscribes to OWN topic (positive control)
	ownTopic := fmt.Sprintf("cfgms/steward/%s/#", tenant1ID)
	token := tenant1Client.Subscribe(ownTopic, 0, func(c mqtt.Client, m mqtt.Message) {
		ownMessages <- string(m.Payload())
	})
	s.True(token.WaitTimeout(5*time.Second), "Own topic subscribe should succeed")
	s.NoError(token.Error())

	// Tenant1 attempts to subscribe to tenant2's topic (should be denied by ACL)
	maliciousTopic := fmt.Sprintf("cfgms/steward/%s/#", tenant2ID)
	token = tenant1Client.Subscribe(maliciousTopic, 0, func(c mqtt.Client, m mqtt.Message) {
		crossTenantMessages <- string(m.Payload())
	})
	s.True(token.WaitTimeout(5*time.Second), "Subscribe should complete")

	time.Sleep(100 * time.Millisecond)

	// Tenant1 publishes to own topic (positive control)
	token = tenant1Client.Publish(fmt.Sprintf("cfgms/steward/%s/test", tenant1ID), 0, false, "own-msg")
	s.True(token.WaitTimeout(5 * time.Second))
	s.NoError(token.Error())

	// Tenant2 publishes to own topic
	token = tenant2Client.Publish(fmt.Sprintf("cfgms/steward/%s/test", tenant2ID), 0, false, "secret-msg")
	s.True(token.WaitTimeout(5 * time.Second))
	s.NoError(token.Error())

	// Positive control: tenant1 MUST receive own message
	select {
	case msg := <-ownMessages:
		s.Equal("own-msg", msg, "Tenant1 should receive own message (positive control)")
	case <-time.After(3 * time.Second):
		s.Fail("Positive control failed: tenant1 did not receive own message")
	}

	// Negative control: tenant1 MUST NOT receive tenant2's message
	select {
	case msg := <-crossTenantMessages:
		s.Fail(fmt.Sprintf("ACL denial failed: tenant1 received tenant2's message: %s", msg))
	case <-time.After(1 * time.Second):
		s.T().Log("ACL denial confirmed: tenant1 did not receive tenant2's message")
	}

	s.T().Logf("✅ AC2-Deny PASSED: ACL blocks cross-tenant topic subscription")
}

// AC3: TestCrossTenantMessagePrevention validates cross-tenant message delivery prevention
// with a positive control to prove messaging works (eliminates timing as explanation).
func (s *MultiTenantTestSuite) TestCrossTenantMessagePrevention() {
	s.T().Log("AC3: Testing cross-tenant message delivery prevention (with positive control)")

	brokerAddr := GetTestMQTTAddr("ssl://localhost:1886")

	// Register separate stewards for each tenant (each gets unique certificate)
	tenant1TLS, tenant1ID := s.helper.GetTLSConfigFromRegistration(s.T(), "tenant1", "integration-test")
	tenant3TLS, tenant3ID := s.helper.GetTLSConfigFromRegistration(s.T(), "tenant3", "integration-test")

	// Create tenant clients with their unique certificates
	tenant1Client := s.createTenantMQTTClient(tenant1ID, brokerAddr, tenant1TLS)
	tenant3Client := s.createTenantMQTTClient(tenant3ID, brokerAddr, tenant3TLS)

	crossTenantMessages := make(chan string, 10)
	ownMessages := make(chan string, 10)

	// Tenant1 attempts to subscribe to tenant3's topic (should be isolated by ACLs)
	maliciousTopic := fmt.Sprintf("cfgms/steward/%s/#", tenant3ID)
	token := tenant1Client.Subscribe(maliciousTopic, 0, func(client mqtt.Client, msg mqtt.Message) {
		crossTenantMessages <- string(msg.Payload())
		s.T().Logf("Tenant1 (%s) received cross-tenant message: %s", tenant1ID, msg.Payload())
	})
	s.True(token.WaitTimeout(5*time.Second), "Subscribe should complete (may succeed or fail)")

	// Positive control: Tenant1 subscribes to their OWN topic
	ownTopic := fmt.Sprintf("cfgms/steward/%s/#", tenant1ID)
	token = tenant1Client.Subscribe(ownTopic, 0, func(client mqtt.Client, msg mqtt.Message) {
		ownMessages <- string(msg.Payload())
		s.T().Logf("Tenant1 (%s) received own message: %s", tenant1ID, msg.Payload())
	})
	s.True(token.WaitTimeout(5*time.Second), "Own topic subscribe should succeed")
	s.NoError(token.Error(), "Own topic subscribe should not error")

	// Publish to tenant1's own topic (positive control)
	tenant1Msg := "tenant1-control-message"
	tenant1Topic := fmt.Sprintf("cfgms/steward/%s/test", tenant1ID)
	token = tenant1Client.Publish(tenant1Topic, 0, false, tenant1Msg)
	s.True(token.WaitTimeout(5*time.Second), "Tenant1 own publish should succeed")

	// Tenant3 publishes a message to their own topic
	tenant3Msg := "secret-tenant3-message"
	tenant3Topic := fmt.Sprintf("cfgms/steward/%s/secret", tenant3ID)
	token = tenant3Client.Publish(tenant3Topic, 0, false, tenant3Msg)
	s.True(token.WaitTimeout(5*time.Second), "Tenant3 publish should succeed")

	// Verify positive control: tenant1 receives their OWN message
	// This proves messaging is working - if this fails, the test infrastructure is broken
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	select {
	case msg := <-ownMessages:
		s.Equal(tenant1Msg, msg, "Tenant1 should receive their own message (positive control)")
		s.T().Log("Positive control passed: tenant1 received own message")
	case <-ctx.Done():
		s.Fail("Positive control failed: tenant1 did not receive their own message - messaging may not be working")
	}

	// Verify negative control: tenant1 does NOT receive tenant3's message
	// Combined with the positive control above, this proves ACLs blocked delivery
	// (not timing, network issues, or test infrastructure problems)
	ctx2, cancel2 := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel2()

	select {
	case msg := <-crossTenantMessages:
		s.Fail(fmt.Sprintf("Cross-tenant message delivery detected! Tenant1 received: %s", msg))
	case <-ctx2.Done():
		// Expected: timeout without receiving message
		s.T().Log("Negative control passed: cross-tenant message delivery prevented")
	}

	s.T().Logf("AC3 PASSED: Cross-tenant message delivery prevention enforced (with positive control)")
}

// AC4: TestConfigurationRoutingBoundaries validates configuration routing respects tenant boundaries
func (s *MultiTenantTestSuite) TestConfigurationRoutingBoundaries() {
	s.T().Log("AC4: Testing configuration routing respects tenant boundaries")

	tlsConfig := s.tlsConfig
	brokerAddr := GetTestMQTTAddr("ssl://localhost:1886")

	// Create tenant clients - use tenant IDs that match the steward topic patterns
	// Story #313: ACLs enforce that client ID must match steward ID in topics
	tenant1Client := s.createTenantMQTTClient("tenant1", brokerAddr, tlsConfig)
	tenant2Client := s.createTenantMQTTClient("tenant2", brokerAddr, tlsConfig)

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

// AC4-Deny: TestConfigRoutingDenial proves ACLs block cross-tenant configuration access.
// The happy-path AC4 test only validates routing; this test proves the broker actively denies
// a steward subscribing to another steward's config topics.
func (s *MultiTenantTestSuite) TestConfigRoutingDenial() {
	s.T().Log("AC4-Deny: Testing ACL denial of cross-tenant configuration subscription")

	brokerAddr := GetTestMQTTAddr("ssl://localhost:1886")

	// Separate registrations for unique steward IDs
	tenant1TLS, tenant1ID := s.helper.GetTLSConfigFromRegistration(s.T(), "tenant1", "integration-test")
	tenant2TLS, tenant2ID := s.helper.GetTLSConfigFromRegistration(s.T(), "tenant2", "integration-test")

	tenant1Client := s.createTenantMQTTClient(tenant1ID, brokerAddr, tenant1TLS)
	tenant2Client := s.createTenantMQTTClient(tenant2ID, brokerAddr, tenant2TLS)

	ownConfigs := make(chan string, 10)
	crossTenantConfigs := make(chan string, 10)

	// Tenant2 subscribes to OWN config topic (positive control)
	ownConfigTopic := fmt.Sprintf("cfgms/steward/%s/+/config", tenant2ID)
	token := tenant2Client.Subscribe(ownConfigTopic, 0, func(c mqtt.Client, m mqtt.Message) {
		ownConfigs <- string(m.Payload())
	})
	s.True(token.WaitTimeout(5*time.Second), "Own config subscribe should succeed")
	s.NoError(token.Error())

	// Tenant2 attempts to subscribe to tenant1's config topic (should be denied by ACL)
	maliciousConfigTopic := fmt.Sprintf("cfgms/steward/%s/+/config", tenant1ID)
	token = tenant2Client.Subscribe(maliciousConfigTopic, 0, func(c mqtt.Client, m mqtt.Message) {
		crossTenantConfigs <- string(m.Payload())
	})
	s.True(token.WaitTimeout(5*time.Second), "Subscribe should complete")

	time.Sleep(100 * time.Millisecond)

	// Tenant2 publishes config to own topic (positive control)
	tenant2ConfigPayload := `{"version":"1.0","tenant":"tenant2","modules":{"file":[]}}`
	token = tenant2Client.Publish(fmt.Sprintf("cfgms/steward/%s/steward-test/config", tenant2ID), 0, false, tenant2ConfigPayload)
	s.True(token.WaitTimeout(5 * time.Second))
	s.NoError(token.Error())

	// Tenant1 publishes config to own topic
	tenant1ConfigPayload := `{"version":"1.0","tenant":"tenant1","modules":{"file":[]}}`
	token = tenant1Client.Publish(fmt.Sprintf("cfgms/steward/%s/steward-test/config", tenant1ID), 0, false, tenant1ConfigPayload)
	s.True(token.WaitTimeout(5 * time.Second))
	s.NoError(token.Error())

	// Positive control: tenant2 MUST receive own config
	select {
	case config := <-ownConfigs:
		s.Contains(config, "tenant2", "Tenant2 should receive own config (positive control)")
	case <-time.After(3 * time.Second):
		s.Fail("Positive control failed: tenant2 did not receive own config")
	}

	// Negative control: tenant2 MUST NOT receive tenant1's config
	select {
	case config := <-crossTenantConfigs:
		s.Fail(fmt.Sprintf("ACL denial failed: tenant2 received tenant1's config: %s", config))
	case <-time.After(1 * time.Second):
		s.T().Log("ACL denial confirmed: tenant2 did not receive tenant1's config")
	}

	s.T().Logf("✅ AC4-Deny PASSED: ACL blocks cross-tenant configuration access")
}

// AC5: TestDNACollectionSeparation validates DNA collection separated by tenant ID
func (s *MultiTenantTestSuite) TestDNACollectionSeparation() {
	s.T().Log("AC5: Testing DNA collection separated by tenant ID")

	tlsConfig := s.tlsConfig
	brokerAddr := GetTestMQTTAddr("ssl://localhost:1886")

	// Create tenant clients - use tenant IDs that match the steward topic patterns
	// Story #313: ACLs enforce that client ID must match steward ID in topics
	tenant1Client := s.createTenantMQTTClient("tenant1", brokerAddr, tlsConfig)
	tenant2Client := s.createTenantMQTTClient("tenant2", brokerAddr, tlsConfig)

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

// AC5-Deny: TestDNACollectionDenial proves ACLs block cross-tenant DNA topic access.
// The happy-path AC5 test only validates routing; this test proves the broker actively denies
// a steward subscribing to another steward's DNA topics.
func (s *MultiTenantTestSuite) TestDNACollectionDenial() {
	s.T().Log("AC5-Deny: Testing ACL denial of cross-tenant DNA subscription")

	brokerAddr := GetTestMQTTAddr("ssl://localhost:1886")

	// Separate registrations for unique steward IDs
	tenant1TLS, tenant1ID := s.helper.GetTLSConfigFromRegistration(s.T(), "tenant1", "integration-test")
	tenant2TLS, tenant2ID := s.helper.GetTLSConfigFromRegistration(s.T(), "tenant2", "integration-test")

	tenant1Client := s.createTenantMQTTClient(tenant1ID, brokerAddr, tenant1TLS)
	tenant2Client := s.createTenantMQTTClient(tenant2ID, brokerAddr, tenant2TLS)

	ownDNA := make(chan string, 10)
	crossTenantDNA := make(chan string, 10)

	// Tenant1 subscribes to OWN DNA topic (positive control)
	ownDNATopic := fmt.Sprintf("cfgms/steward/%s/+/dna", tenant1ID)
	token := tenant1Client.Subscribe(ownDNATopic, 0, func(c mqtt.Client, m mqtt.Message) {
		ownDNA <- string(m.Payload())
	})
	s.True(token.WaitTimeout(5*time.Second), "Own DNA subscribe should succeed")
	s.NoError(token.Error())

	// Tenant1 attempts to subscribe to tenant2's DNA topic (should be denied by ACL)
	maliciousDNATopic := fmt.Sprintf("cfgms/steward/%s/+/dna", tenant2ID)
	token = tenant1Client.Subscribe(maliciousDNATopic, 0, func(c mqtt.Client, m mqtt.Message) {
		crossTenantDNA <- string(m.Payload())
	})
	s.True(token.WaitTimeout(5*time.Second), "Subscribe should complete")

	time.Sleep(100 * time.Millisecond)

	// Tenant1 publishes DNA to own topic (positive control)
	tenant1DNAPayload := fmt.Sprintf(`{"tenant_id":"tenant1","steward_id":"%s","hostname":"host-tenant1"}`, tenant1ID)
	token = tenant1Client.Publish(fmt.Sprintf("cfgms/steward/%s/steward-t1/dna", tenant1ID), 0, false, tenant1DNAPayload)
	s.True(token.WaitTimeout(5 * time.Second))
	s.NoError(token.Error())

	// Tenant2 publishes DNA to own topic
	tenant2DNAPayload := fmt.Sprintf(`{"tenant_id":"tenant2","steward_id":"%s","hostname":"host-tenant2"}`, tenant2ID)
	token = tenant2Client.Publish(fmt.Sprintf("cfgms/steward/%s/steward-t2/dna", tenant2ID), 0, false, tenant2DNAPayload)
	s.True(token.WaitTimeout(5 * time.Second))
	s.NoError(token.Error())

	// Positive control: tenant1 MUST receive own DNA
	select {
	case dna := <-ownDNA:
		s.Contains(dna, "tenant1", "Tenant1 should receive own DNA (positive control)")
	case <-time.After(3 * time.Second):
		s.Fail("Positive control failed: tenant1 did not receive own DNA update")
	}

	// Negative control: tenant1 MUST NOT receive tenant2's DNA
	select {
	case dna := <-crossTenantDNA:
		s.Fail(fmt.Sprintf("ACL denial failed: tenant1 received tenant2's DNA: %s", dna))
	case <-time.After(1 * time.Second):
		s.T().Log("ACL denial confirmed: tenant1 did not receive tenant2's DNA")
	}

	s.T().Logf("✅ AC5-Deny PASSED: ACL blocks cross-tenant DNA access")
}

// AC6: TestHeartbeatIsolation validates heartbeats isolated per tenant
func (s *MultiTenantTestSuite) TestHeartbeatIsolation() {
	s.T().Log("AC6: Testing heartbeats isolated per tenant")

	brokerAddr := GetTestMQTTAddr("ssl://localhost:1886")

	// Register separate stewards for each tenant (each gets unique certificate)
	tenant1TLS, tenant1ID := s.helper.GetTLSConfigFromRegistration(s.T(), "tenant1", "integration-test")
	tenant3TLS, tenant3ID := s.helper.GetTLSConfigFromRegistration(s.T(), "tenant3", "integration-test")

	// Create tenant clients with their unique certificates
	tenant1Client := s.createTenantMQTTClient(tenant1ID, brokerAddr, tenant1TLS)
	tenant3Client := s.createTenantMQTTClient(tenant3ID, brokerAddr, tenant3TLS)

	tenant1Heartbeats := make(chan string, 10)
	tenant3Heartbeats := make(chan string, 10)

	// Each tenant subscribes to their own heartbeat topic
	tenant1Topic := fmt.Sprintf("cfgms/steward/%s/heartbeat", tenant1ID)
	token := tenant1Client.Subscribe(tenant1Topic, 0, func(client mqtt.Client, msg mqtt.Message) {
		tenant1Heartbeats <- string(msg.Payload())
		s.T().Logf("Tenant1 heartbeat: %s", msg.Payload())
	})
	s.True(token.WaitTimeout(5*time.Second), "Tenant1 heartbeat subscribe should succeed")

	tenant3Topic := fmt.Sprintf("cfgms/steward/%s/heartbeat", tenant3ID)
	token = tenant3Client.Subscribe(tenant3Topic, 0, func(client mqtt.Client, msg mqtt.Message) {
		tenant3Heartbeats <- string(msg.Payload())
		s.T().Logf("Tenant3 heartbeat: %s", msg.Payload())
	})
	s.True(token.WaitTimeout(5*time.Second), "Tenant3 heartbeat subscribe should succeed")

	// Publish heartbeats from each tenant to their own topics
	tenant1HBPayload := fmt.Sprintf(`{"tenant_id":"tenant1","steward_id":"%s","status":"online","timestamp":"2025-01-01T00:00:00Z"}`, tenant1ID)
	token = tenant1Client.Publish(tenant1Topic, 0, false, tenant1HBPayload)
	s.True(token.WaitTimeout(5*time.Second), "Tenant1 heartbeat publish should succeed")

	tenant3HBPayload := fmt.Sprintf(`{"tenant_id":"tenant3","steward_id":"%s","status":"online","timestamp":"2025-01-01T00:00:00Z"}`, tenant3ID)
	token = tenant3Client.Publish(tenant3Topic, 0, false, tenant3HBPayload)
	s.True(token.WaitTimeout(5*time.Second), "Tenant3 heartbeat publish should succeed")

	// Verify tenant1 receives only its heartbeat
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	select {
	case hb := <-tenant1Heartbeats:
		s.Contains(hb, tenant1ID, "Tenant1 should receive its own heartbeat")
		s.NotContains(hb, tenant3ID, "Tenant1 should NOT receive tenant3 heartbeat")
	case <-ctx.Done():
		s.Fail("Tenant1 should receive heartbeat before timeout")
	}

	// Verify tenant3 receives only its heartbeat
	ctx2, cancel2 := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel2()

	select {
	case hb := <-tenant3Heartbeats:
		s.Contains(hb, tenant3ID, "Tenant3 should receive its own heartbeat")
		s.NotContains(hb, tenant1ID, "Tenant3 should NOT receive tenant1 heartbeat")
	case <-ctx2.Done():
		s.Fail("Tenant3 should receive heartbeat before timeout")
	}

	s.T().Logf("✅ AC6 PASSED: Heartbeats isolated per tenant")
}

// AC6-Deny: TestHeartbeatIsolationDenial proves ACLs block cross-tenant heartbeat snooping.
// The happy-path AC6 test only validates routing; this test proves the broker actively denies
// a steward subscribing to another steward's heartbeat topic.
func (s *MultiTenantTestSuite) TestHeartbeatIsolationDenial() {
	s.T().Log("AC6-Deny: Testing ACL denial of cross-tenant heartbeat subscription")

	brokerAddr := GetTestMQTTAddr("ssl://localhost:1886")

	// Separate registrations for unique steward IDs
	tenant1TLS, tenant1ID := s.helper.GetTLSConfigFromRegistration(s.T(), "tenant1", "integration-test")
	tenant3TLS, tenant3ID := s.helper.GetTLSConfigFromRegistration(s.T(), "tenant3", "integration-test")

	tenant1Client := s.createTenantMQTTClient(tenant1ID, brokerAddr, tenant1TLS)
	tenant3Client := s.createTenantMQTTClient(tenant3ID, brokerAddr, tenant3TLS)

	ownHeartbeats := make(chan string, 10)
	crossTenantHeartbeats := make(chan string, 10)

	// Tenant1 subscribes to OWN heartbeat topic (positive control)
	ownHBTopic := fmt.Sprintf("cfgms/steward/%s/heartbeat", tenant1ID)
	token := tenant1Client.Subscribe(ownHBTopic, 0, func(c mqtt.Client, m mqtt.Message) {
		ownHeartbeats <- string(m.Payload())
	})
	s.True(token.WaitTimeout(5*time.Second), "Own heartbeat subscribe should succeed")
	s.NoError(token.Error())

	// Tenant1 attempts to subscribe to tenant3's heartbeat topic (should be denied by ACL)
	maliciousHBTopic := fmt.Sprintf("cfgms/steward/%s/heartbeat", tenant3ID)
	token = tenant1Client.Subscribe(maliciousHBTopic, 0, func(c mqtt.Client, m mqtt.Message) {
		crossTenantHeartbeats <- string(m.Payload())
	})
	s.True(token.WaitTimeout(5*time.Second), "Subscribe should complete")

	time.Sleep(100 * time.Millisecond)

	// Tenant1 publishes heartbeat to own topic (positive control)
	tenant1HBPayload := fmt.Sprintf(`{"steward_id":"%s","status":"online"}`, tenant1ID)
	token = tenant1Client.Publish(ownHBTopic, 0, false, tenant1HBPayload)
	s.True(token.WaitTimeout(5 * time.Second))
	s.NoError(token.Error())

	// Tenant3 publishes heartbeat to own topic
	tenant3HBPayload := fmt.Sprintf(`{"steward_id":"%s","status":"online"}`, tenant3ID)
	token = tenant3Client.Publish(fmt.Sprintf("cfgms/steward/%s/heartbeat", tenant3ID), 0, false, tenant3HBPayload)
	s.True(token.WaitTimeout(5 * time.Second))
	s.NoError(token.Error())

	// Positive control: tenant1 MUST receive own heartbeat
	select {
	case hb := <-ownHeartbeats:
		s.Contains(hb, tenant1ID, "Tenant1 should receive own heartbeat (positive control)")
	case <-time.After(3 * time.Second):
		s.Fail("Positive control failed: tenant1 did not receive own heartbeat")
	}

	// Negative control: tenant1 MUST NOT receive tenant3's heartbeat
	select {
	case hb := <-crossTenantHeartbeats:
		s.Fail(fmt.Sprintf("ACL denial failed: tenant1 received tenant3's heartbeat: %s", hb))
	case <-time.After(1 * time.Second):
		s.T().Log("ACL denial confirmed: tenant1 did not receive tenant3's heartbeat")
	}

	s.T().Logf("✅ AC6-Deny PASSED: ACL blocks cross-tenant heartbeat snooping")
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
