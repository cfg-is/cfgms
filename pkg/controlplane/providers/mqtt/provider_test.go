// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package mqtt

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/cfgis/cfgms/pkg/controlplane/types"
	mqttInterfaces "github.com/cfgis/cfgms/pkg/mqtt/interfaces"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockBroker implements mqttInterfaces.Broker for testing
type mockBroker struct {
	mu          sync.RWMutex
	published   []mockMessage
	subscribers map[string]mqttInterfaces.MessageHandler
	failTopics  map[string]error // topics that should return an error on Publish
}

type mockMessage struct {
	topic   string
	payload []byte
	qos     byte
	retain  bool
}

func newMockBroker() *mockBroker {
	return &mockBroker{
		published:   []mockMessage{},
		subscribers: make(map[string]mqttInterfaces.MessageHandler),
		failTopics:  make(map[string]error),
	}
}

func (m *mockBroker) Name() string        { return "mock" }
func (m *mockBroker) Description() string { return "Mock broker for testing" }

func (m *mockBroker) Initialize(config map[string]interface{}) error {
	return nil
}

func (m *mockBroker) Start(ctx context.Context) error {
	return nil
}

func (m *mockBroker) Stop(ctx context.Context) error {
	return nil
}

func (m *mockBroker) Publish(ctx context.Context, topic string, payload []byte, qos byte, retain bool) error {
	m.mu.Lock()

	// Check if this topic should fail
	if err, shouldFail := m.failTopics[topic]; shouldFail {
		m.mu.Unlock()
		return err
	}

	m.published = append(m.published, mockMessage{
		topic:   topic,
		payload: payload,
		qos:     qos,
		retain:  retain,
	})

	// Get handler while holding lock
	handler, exists := m.subscribers[topic]
	m.mu.Unlock()

	// Trigger subscriber outside lock to avoid deadlock
	if exists {
		_ = handler(topic, payload, qos, retain)
	}

	return nil
}

func (m *mockBroker) Subscribe(ctx context.Context, topic string, qos byte, callback mqttInterfaces.MessageHandler) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.subscribers[topic] = callback
	return nil
}

func (m *mockBroker) Unsubscribe(ctx context.Context, topic string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.subscribers, topic)
	return nil
}

func (m *mockBroker) GetStats(ctx context.Context) (mqttInterfaces.BrokerStats, error) {
	return mqttInterfaces.BrokerStats{
		ClientsConnected: 5,
		MessagesSent:     100,
		MessagesReceived: 95,
	}, nil
}

func (m *mockBroker) Available() (bool, error) {
	return true, nil
}

func (m *mockBroker) GetCapabilities() mqttInterfaces.BrokerCapabilities {
	return mqttInterfaces.BrokerCapabilities{}
}

func (m *mockBroker) GetListenAddress() string {
	return "localhost:1883"
}

func (m *mockBroker) SetAuthHandler(handler mqttInterfaces.AuthenticationHandler) {}
func (m *mockBroker) SetACLHandler(handler mqttInterfaces.AuthorizationHandler)   {}

// getLastPublished returns the last published message or nil
func (m *mockBroker) getLastPublished() *mockMessage {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if len(m.published) == 0 {
		return nil
	}
	return &m.published[len(m.published)-1]
}

// getSubscriber returns the handler for a topic if it exists
func (m *mockBroker) getSubscriber(topic string) (mqttInterfaces.MessageHandler, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	handler, exists := m.subscribers[topic]
	return handler, exists
}

func TestProvider_NewServerMode(t *testing.T) {
	provider := New(ModeServer)

	assert.NotNil(t, provider)
	assert.Equal(t, "mqtt", provider.Name())
	assert.Equal(t, ModeServer, provider.mode)
	assert.NotNil(t, provider.stats)
	assert.NotNil(t, provider.commandHandlers)
	assert.NotNil(t, provider.pendingResponses)
}

func TestProvider_NewClientMode(t *testing.T) {
	provider := New(ModeClient)

	assert.NotNil(t, provider)
	assert.Equal(t, "mqtt", provider.Name())
	assert.Equal(t, ModeClient, provider.mode)
}

func TestProvider_InitializeServerMode(t *testing.T) {
	provider := New(ModeServer)
	broker := newMockBroker()

	config := map[string]interface{}{
		"broker": broker,
	}

	ctx := context.Background()
	err := provider.Initialize(ctx, config)

	require.NoError(t, err)
	assert.Equal(t, broker, provider.broker)
}

func TestProvider_InitializeServerMode_MissingBroker(t *testing.T) {
	provider := New(ModeServer)

	config := map[string]interface{}{}

	ctx := context.Background()
	err := provider.Initialize(ctx, config)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "broker")
}

func TestProvider_InitializeClientMode(t *testing.T) {
	provider := New(ModeClient)

	config := map[string]interface{}{
		"broker_addr": "tcp://localhost:1883",
		"client_id":   "test-client",
		"steward_id":  "steward-1",
	}

	ctx := context.Background()
	err := provider.Initialize(ctx, config)

	require.NoError(t, err)
	assert.Equal(t, "tcp://localhost:1883", provider.brokerAddr)
	assert.Equal(t, "test-client", provider.clientID)
	assert.Equal(t, "steward-1", provider.stewardID)
}

func TestProvider_InitializeClientMode_MissingRequired(t *testing.T) {
	tests := []struct {
		name   string
		config map[string]interface{}
	}{
		{
			name: "missing broker_addr",
			config: map[string]interface{}{
				"client_id":  "test-client",
				"steward_id": "steward-1",
			},
		},
		{
			name: "missing client_id",
			config: map[string]interface{}{
				"broker_addr": "tcp://localhost:1883",
				"steward_id":  "steward-1",
			},
		},
		{
			name: "missing steward_id",
			config: map[string]interface{}{
				"broker_addr": "tcp://localhost:1883",
				"client_id":   "test-client",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider := New(ModeClient)
			ctx := context.Background()
			err := provider.Initialize(ctx, tt.config)
			assert.Error(t, err)
		})
	}
}

func TestProvider_StartServerMode(t *testing.T) {
	provider := New(ModeServer)
	broker := newMockBroker()

	config := map[string]interface{}{
		"broker": broker,
	}

	ctx := context.Background()
	err := provider.Initialize(ctx, config)
	require.NoError(t, err)

	err = provider.Start(ctx)
	require.NoError(t, err)

	assert.False(t, provider.startTime.IsZero())
}

func TestProvider_Available_ServerMode(t *testing.T) {
	provider := New(ModeServer)
	broker := newMockBroker()

	config := map[string]interface{}{
		"broker": broker,
	}

	ctx := context.Background()
	err := provider.Initialize(ctx, config)
	require.NoError(t, err)

	available, err := provider.Available()
	assert.True(t, available)
	assert.NoError(t, err)
}

func TestProvider_Available_ClientMode(t *testing.T) {
	provider := New(ModeClient)

	config := map[string]interface{}{
		"broker_addr": "tcp://localhost:1883",
		"client_id":   "test-client",
		"steward_id":  "steward-1",
	}

	ctx := context.Background()
	err := provider.Initialize(ctx, config)
	require.NoError(t, err)

	available, err := provider.Available()
	assert.True(t, available)
	assert.NoError(t, err)
}

func TestProvider_SendCommand(t *testing.T) {
	provider := New(ModeServer)
	broker := newMockBroker()

	config := map[string]interface{}{
		"broker": broker,
	}

	ctx := context.Background()
	err := provider.Initialize(ctx, config)
	require.NoError(t, err)

	// Send command
	cmd := &types.Command{
		ID:        "cmd-123",
		Type:      types.CommandSyncConfig,
		StewardID: "steward-1",
		TenantID:  "tenant-1",
		Timestamp: time.Now(),
		Params: map[string]interface{}{
			"version": "1.0.0",
		},
	}

	err = provider.SendCommand(ctx, cmd)
	require.NoError(t, err)

	// Verify command was published
	msg := broker.getLastPublished()
	require.NotNil(t, msg)
	assert.Equal(t, "cfgms/commands/steward-1", msg.topic)
	assert.Equal(t, byte(1), msg.qos)
	assert.False(t, msg.retain)

	// Verify stats updated
	stats, _ := provider.GetStats(ctx)
	assert.Equal(t, int64(1), stats.CommandsSent)
}

func TestProvider_FanOutCommand(t *testing.T) {
	provider := New(ModeServer)
	broker := newMockBroker()

	config := map[string]interface{}{
		"broker": broker,
	}

	ctx := context.Background()
	err := provider.Initialize(ctx, config)
	require.NoError(t, err)

	cmd := &types.Command{
		ID:        "cmd-fanout",
		Type:      types.CommandExecuteTask,
		Timestamp: time.Now(),
	}

	stewardIDs := []string{"steward-1", "steward-2", "steward-3"}
	result, err := provider.FanOutCommand(ctx, cmd, stewardIDs)
	require.NoError(t, err)
	require.NotNil(t, result)

	// All 3 should succeed
	assert.Len(t, result.Succeeded, 3)
	assert.Empty(t, result.Failed)

	// Verify 3 messages published to correct unicast topics
	broker.mu.RLock()
	assert.Len(t, broker.published, 3)
	topics := make([]string, len(broker.published))
	for i, msg := range broker.published {
		topics[i] = msg.topic
	}
	broker.mu.RUnlock()

	assert.Contains(t, topics, "cfgms/commands/steward-1")
	assert.Contains(t, topics, "cfgms/commands/steward-2")
	assert.Contains(t, topics, "cfgms/commands/steward-3")
}

func TestProvider_FanOutCommand_PartialFailure(t *testing.T) {
	provider := New(ModeServer)
	broker := newMockBroker()

	config := map[string]interface{}{
		"broker": broker,
	}

	ctx := context.Background()
	err := provider.Initialize(ctx, config)
	require.NoError(t, err)

	// Make steward-2's topic fail
	broker.failTopics["cfgms/commands/steward-2"] = fmt.Errorf("connection refused")

	cmd := &types.Command{
		ID:        "cmd-partial",
		Type:      types.CommandExecuteTask,
		Timestamp: time.Now(),
	}

	stewardIDs := []string{"steward-1", "steward-2", "steward-3"}
	result, err := provider.FanOutCommand(ctx, cmd, stewardIDs)
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Len(t, result.Succeeded, 2)
	assert.Len(t, result.Failed, 1)
	assert.Contains(t, result.Failed, "steward-2")
	assert.Contains(t, result.Failed["steward-2"].Error(), "connection refused")
}

func TestProvider_FanOutCommand_EmptyList(t *testing.T) {
	provider := New(ModeServer)
	broker := newMockBroker()

	config := map[string]interface{}{
		"broker": broker,
	}

	ctx := context.Background()
	err := provider.Initialize(ctx, config)
	require.NoError(t, err)

	cmd := &types.Command{
		ID:   "cmd-empty",
		Type: types.CommandExecuteTask,
	}

	result, err := provider.FanOutCommand(ctx, cmd, []string{})
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "stewardIDs must not be empty")
}

func TestProvider_FanOutCommand_ServerModeOnly(t *testing.T) {
	provider := New(ModeClient)

	ctx := context.Background()
	cmd := &types.Command{ID: "cmd-1", Type: types.CommandSyncConfig}

	result, err := provider.FanOutCommand(ctx, cmd, []string{"steward-1"})
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "server mode")
}

func TestProvider_FanOutCommand_Stats(t *testing.T) {
	provider := New(ModeServer)
	broker := newMockBroker()

	config := map[string]interface{}{
		"broker": broker,
	}

	ctx := context.Background()
	err := provider.Initialize(ctx, config)
	require.NoError(t, err)

	// Make one topic fail
	broker.failTopics["cfgms/commands/steward-3"] = fmt.Errorf("timeout")

	cmd := &types.Command{
		ID:        "cmd-stats",
		Type:      types.CommandExecuteTask,
		Timestamp: time.Now(),
	}

	_, err = provider.FanOutCommand(ctx, cmd, []string{"steward-1", "steward-2", "steward-3"})
	require.NoError(t, err)

	stats, err := provider.GetStats(ctx)
	require.NoError(t, err)

	// 2 succeeded, 1 failed
	assert.Equal(t, int64(2), stats.CommandsSent)
	assert.Equal(t, int64(1), stats.DeliveryFailures)
}

func TestProvider_SendCommand_ClientMode_Error(t *testing.T) {
	provider := New(ModeClient)

	ctx := context.Background()
	cmd := &types.Command{ID: "cmd-1", Type: types.CommandSyncConfig}

	err := provider.SendCommand(ctx, cmd)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "server mode")
}

func TestProvider_GetStats(t *testing.T) {
	provider := New(ModeServer)
	broker := newMockBroker()

	config := map[string]interface{}{
		"broker": broker,
	}

	ctx := context.Background()
	err := provider.Initialize(ctx, config)
	require.NoError(t, err)

	err = provider.Start(ctx)
	require.NoError(t, err)

	// Wait briefly to ensure measurable uptime (prevents flaky test on fast Windows CI)
	time.Sleep(10 * time.Millisecond)

	// Get stats
	stats, err := provider.GetStats(ctx)
	require.NoError(t, err)
	assert.NotNil(t, stats)
	assert.Greater(t, stats.Uptime, time.Duration(0))

	// Verify broker stats included in provider metrics
	assert.NotNil(t, stats.ProviderMetrics)
	assert.Equal(t, int64(5), stats.ProviderMetrics["broker_clients_connected"])
	assert.Equal(t, int64(100), stats.ProviderMetrics["broker_messages_sent"])
}

func TestProvider_MarshalUnmarshal(t *testing.T) {
	cmd := &types.Command{
		ID:        "cmd-123",
		Type:      types.CommandSyncConfig,
		StewardID: "steward-1",
		Timestamp: time.Now(),
	}

	// Marshal
	data, err := marshalMessage(cmd)
	require.NoError(t, err)
	assert.NotEmpty(t, data)

	// Unmarshal
	var decoded types.Command
	err = unmarshalMessage(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, cmd.ID, decoded.ID)
	assert.Equal(t, cmd.Type, decoded.Type)
	assert.Equal(t, cmd.StewardID, decoded.StewardID)
}

func TestProvider_StopServerMode(t *testing.T) {
	provider := New(ModeServer)
	broker := newMockBroker()

	config := map[string]interface{}{
		"broker": broker,
	}

	ctx := context.Background()
	err := provider.Initialize(ctx, config)
	require.NoError(t, err)

	err = provider.Start(ctx)
	require.NoError(t, err)

	err = provider.Stop(ctx)
	require.NoError(t, err)

	// Verify handlers cleared
	assert.Empty(t, provider.commandHandlers)
	assert.Empty(t, provider.eventHandlers)
	assert.Empty(t, provider.heartbeatHandlers)
}
