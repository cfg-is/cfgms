// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package mqtt

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/cfgis/cfgms/pkg/controlplane/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestIntegration_CommandFlow tests the critical path: Controller sends command → Steward receives it
// This integration test ensures client-side code works with the broker.
func TestIntegration_CommandFlow(t *testing.T) {
	// This test requires a real broker, so we use our mock broker
	// which simulates the critical publish/subscribe behavior
	broker := newMockBroker()

	// 1. Create controller (server) provider
	controller := New(ModeServer)
	err := controller.Initialize(context.Background(), map[string]interface{}{
		"broker": broker,
	})
	require.NoError(t, err)

	err = controller.Start(context.Background())
	require.NoError(t, err)

	// 2. Create steward (client) provider
	// Note: In a real integration test, this would connect to the broker
	// For now, we test the critical subscription logic using the mock
	steward := New(ModeClient)
	steward.client = nil // Not using real client in this test
	steward.stewardID = "steward-1"
	steward.mode = ModeClient

	// 3. Setup command handler on steward side
	var receivedCommands []*types.Command
	var mu sync.Mutex

	commandHandler := func(ctx context.Context, cmd *types.Command) error {
		mu.Lock()
		receivedCommands = append(receivedCommands, cmd)
		mu.Unlock()
		return nil
	}

	// Manually register handler (simulating SubscribeCommands)
	steward.commandHandlers["steward-1"] = commandHandler
	steward.stats.CommandsReceived = 0

	// 4. Controller sends command to steward
	cmd := &types.Command{
		ID:        "cmd-integration-test",
		Type:      types.CommandSyncConfig,
		StewardID: "steward-1",
		TenantID:  "tenant-1",
		Timestamp: time.Now(),
		Params: map[string]interface{}{
			"test": true,
		},
	}

	err = controller.SendCommand(context.Background(), cmd)
	require.NoError(t, err)

	// 5. Verify command was published to correct topic
	lastMsg := broker.getLastPublished()
	require.NotNil(t, lastMsg)
	assert.Equal(t, "cfgms/commands/steward-1", lastMsg.topic)

	// 6. Simulate broker delivering message to steward
	steward.handleCommandMessage(lastMsg.topic, lastMsg.payload)

	// Wait for async handler
	time.Sleep(50 * time.Millisecond)

	// 7. Verify steward received and processed command
	mu.Lock()
	assert.Len(t, receivedCommands, 1)
	if len(receivedCommands) > 0 {
		assert.Equal(t, "cmd-integration-test", receivedCommands[0].ID)
		assert.Equal(t, types.CommandSyncConfig, receivedCommands[0].Type)
		assert.Equal(t, "steward-1", receivedCommands[0].StewardID)
	}
	mu.Unlock()

	// Cleanup
	_ = controller.Stop(context.Background())
}

// TestIntegration_EventFlow tests the reverse path: Steward publishes event → Controller receives it
func TestIntegration_EventFlow(t *testing.T) {
	broker := newMockBroker()

	// 1. Create controller (server) provider
	controller := New(ModeServer)
	err := controller.Initialize(context.Background(), map[string]interface{}{
		"broker": broker,
	})
	require.NoError(t, err)

	// 2. Subscribe to events on controller side
	var receivedEvents []*types.Event
	var mu sync.Mutex

	eventHandler := func(ctx context.Context, event *types.Event) error {
		mu.Lock()
		receivedEvents = append(receivedEvents, event)
		mu.Unlock()
		return nil
	}

	err = controller.SubscribeEvents(context.Background(), nil, eventHandler)
	require.NoError(t, err)

	// 3. Simulate steward publishing event
	event := &types.Event{
		ID:        "evt-integration-test",
		Type:      types.EventConfigApplied,
		StewardID: "steward-1",
		TenantID:  "tenant-1",
		Timestamp: time.Now(),
		Details: map[string]interface{}{
			"success": true,
		},
	}

	// Steward would call PublishEvent, but we simulate the MQTT publish
	payload, err := marshalMessage(event)
	require.NoError(t, err)

	// Trigger broker's subscriber (simulating MQTT message delivery)
	topic := "cfgms/events/steward-1"
	if handler, exists := broker.getSubscriber("cfgms/events/+"); exists {
		_ = handler(topic, payload, 1, false)
	}

	// Wait for async handler
	time.Sleep(50 * time.Millisecond)

	// 4. Verify controller received event
	mu.Lock()
	assert.Len(t, receivedEvents, 1)
	if len(receivedEvents) > 0 {
		assert.Equal(t, "evt-integration-test", receivedEvents[0].ID)
		assert.Equal(t, types.EventConfigApplied, receivedEvents[0].Type)
		assert.Equal(t, "steward-1", receivedEvents[0].StewardID)
	}
	mu.Unlock()
}

// TestIntegration_FanOutToMultipleStewards tests fan-out delivery to explicit steward list
func TestIntegration_FanOutToMultipleStewards(t *testing.T) {
	broker := newMockBroker()

	// Controller
	controller := New(ModeServer)
	err := controller.Initialize(context.Background(), map[string]interface{}{
		"broker": broker,
	})
	require.NoError(t, err)

	// Fan out command to specific stewards
	cmd := &types.Command{
		ID:        "fanout-cmd",
		Type:      types.CommandExecuteTask,
		Timestamp: time.Now(),
	}

	stewardIDs := []string{"steward-1", "steward-2"}
	result, err := controller.FanOutCommand(context.Background(), cmd, stewardIDs)
	require.NoError(t, err)
	assert.Len(t, result.Succeeded, 2)
	assert.Empty(t, result.Failed)

	// Verify messages published to correct unicast topics
	broker.mu.RLock()
	require.Len(t, broker.published, 2)
	assert.Equal(t, "cfgms/commands/steward-1", broker.published[0].topic)
	assert.Equal(t, "cfgms/commands/steward-2", broker.published[1].topic)
	broker.mu.RUnlock()

	// Verify command can be deserialized from either message
	var decoded types.Command
	err = unmarshalMessage(broker.published[0].payload, &decoded)
	require.NoError(t, err)
	assert.Equal(t, "fanout-cmd", decoded.ID)
}

// TestIntegration_ResponseWaitFlow tests request-response pattern
func TestIntegration_ResponseWaitFlow(t *testing.T) {
	broker := newMockBroker()

	controller := New(ModeServer)
	err := controller.Initialize(context.Background(), map[string]interface{}{
		"broker": broker,
	})
	require.NoError(t, err)

	// Send command
	cmd := &types.Command{
		ID:        "cmd-with-response",
		Type:      types.CommandSyncConfig,
		StewardID: "steward-1",
		Timestamp: time.Now(),
	}

	err = controller.SendCommand(context.Background(), cmd)
	require.NoError(t, err)

	// Wait for response in background
	responseChan := make(chan *types.Response, 1)
	go func() {
		resp, err := controller.WaitForResponse(context.Background(), cmd.ID, 2*time.Second)
		if err == nil {
			responseChan <- resp
		}
	}()

	// Give WaitForResponse time to subscribe
	time.Sleep(50 * time.Millisecond)

	// Simulate steward sending response
	response := &types.Response{
		CommandID: cmd.ID,
		StewardID: "steward-1",
		Success:   true,
		Message:   "Command processed successfully",
		Timestamp: time.Now(),
	}

	payload, _ := marshalMessage(response)
	topic := "cfgms/responses/" + cmd.ID

	// Deliver response via broker
	if handler, exists := broker.getSubscriber(topic); exists {
		_ = handler(topic, payload, 1, false)
	}

	// Verify response received
	select {
	case resp := <-responseChan:
		assert.Equal(t, cmd.ID, resp.CommandID)
		assert.True(t, resp.Success)
		assert.Equal(t, "Command processed successfully", resp.Message)
	case <-time.After(3 * time.Second):
		t.Fatal("Timeout waiting for response")
	}
}
