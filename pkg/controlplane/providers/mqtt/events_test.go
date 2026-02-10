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

func TestProvider_PublishEvent_ClientMode(t *testing.T) {
	// Note: Client mode PublishEvent requires actual MQTT client
	// which needs a real broker connection. This tests the error path.
	provider := New(ModeClient)

	config := map[string]interface{}{
		"broker_addr": "tcp://localhost:1883",
		"client_id":   "test-client",
		"steward_id":  "steward-1",
	}

	ctx := context.Background()
	err := provider.Initialize(ctx, config)
	require.NoError(t, err)

	event := &types.Event{
		ID:        "evt-123",
		Type:      types.EventConfigApplied,
		StewardID: "steward-1",
		TenantID:  "tenant-1",
		Timestamp: time.Now(),
	}

	// Will fail because client not connected, but tests the code path
	err = provider.PublishEvent(ctx, event)
	assert.Error(t, err) // Expected since no real broker
}

func TestProvider_PublishEvent_ServerMode_Error(t *testing.T) {
	provider := New(ModeServer)

	ctx := context.Background()
	event := &types.Event{ID: "evt-1", Type: types.EventConfigApplied}

	err := provider.PublishEvent(ctx, event)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "client mode")
}

func TestProvider_SubscribeEvents(t *testing.T) {
	provider := New(ModeServer)
	broker := newMockBroker()

	config := map[string]interface{}{
		"broker": broker,
	}

	ctx := context.Background()
	err := provider.Initialize(ctx, config)
	require.NoError(t, err)

	// Subscribe to events
	var receivedEvents []*types.Event
	var mu sync.Mutex

	handler := func(ctx context.Context, event *types.Event) error {
		mu.Lock()
		receivedEvents = append(receivedEvents, event)
		mu.Unlock()
		return nil
	}

	filter := &types.EventFilter{
		StewardIDs: []string{"steward-1"},
	}

	err = provider.SubscribeEvents(ctx, filter, handler)
	require.NoError(t, err)

	// Simulate receiving an event
	event := &types.Event{
		ID:        "evt-123",
		Type:      types.EventConfigApplied,
		StewardID: "steward-1",
		Timestamp: time.Now(),
	}

	payload, _ := marshalMessage(event)
	err = provider.handleEventMessage("cfgms/events/steward-1", payload, 1, false)
	require.NoError(t, err)

	// Wait for async handler
	time.Sleep(50 * time.Millisecond)

	// Verify event was received
	mu.Lock()
	assert.Len(t, receivedEvents, 1)
	if len(receivedEvents) > 0 {
		assert.Equal(t, "evt-123", receivedEvents[0].ID)
		assert.Equal(t, types.EventConfigApplied, receivedEvents[0].Type)
	}
	mu.Unlock()

	// Verify stats
	stats, _ := provider.GetStats(ctx)
	assert.Equal(t, int64(1), stats.EventsReceived)
}

func TestProvider_SubscribeEvents_Filtering(t *testing.T) {
	provider := New(ModeServer)
	broker := newMockBroker()

	config := map[string]interface{}{
		"broker": broker,
	}

	ctx := context.Background()
	err := provider.Initialize(ctx, config)
	require.NoError(t, err)

	// Subscribe with filter for steward-1 only
	var receivedCount int
	var mu sync.Mutex

	handler := func(ctx context.Context, event *types.Event) error {
		mu.Lock()
		receivedCount++
		mu.Unlock()
		return nil
	}

	filter := &types.EventFilter{
		StewardIDs: []string{"steward-1"},
	}

	err = provider.SubscribeEvents(ctx, filter, handler)
	require.NoError(t, err)

	// Send event from steward-1 (should match)
	event1 := &types.Event{
		ID:        "evt-1",
		Type:      types.EventConfigApplied,
		StewardID: "steward-1",
		Timestamp: time.Now(),
	}
	payload1, _ := marshalMessage(event1)
	_ = provider.handleEventMessage("cfgms/events/steward-1", payload1, 1, false)

	// Send event from steward-2 (should NOT match)
	event2 := &types.Event{
		ID:        "evt-2",
		Type:      types.EventConfigApplied,
		StewardID: "steward-2",
		Timestamp: time.Now(),
	}
	payload2, _ := marshalMessage(event2)
	_ = provider.handleEventMessage("cfgms/events/steward-2", payload2, 1, false)

	// Wait for async handlers
	time.Sleep(50 * time.Millisecond)

	// Only event1 should have been handled
	mu.Lock()
	assert.Equal(t, 1, receivedCount)
	mu.Unlock()
}

func TestProvider_SubscribeEvents_ClientMode_Error(t *testing.T) {
	provider := New(ModeClient)

	ctx := context.Background()
	handler := func(ctx context.Context, event *types.Event) error {
		return nil
	}

	err := provider.SubscribeEvents(ctx, nil, handler)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "server mode")
}

func TestProvider_HandleEventMessage_InvalidJSON(t *testing.T) {
	provider := New(ModeServer)
	broker := newMockBroker()

	config := map[string]interface{}{
		"broker": broker,
	}

	ctx := context.Background()
	err := provider.Initialize(ctx, config)
	require.NoError(t, err)

	// Handle invalid JSON (should not panic, just log/ignore)
	err = provider.handleEventMessage("cfgms/events/steward-1", []byte("invalid json"), 1, false)
	assert.NoError(t, err) // Should return nil even on invalid JSON
}

func TestProvider_SubscribeEvents_MultipleHandlers(t *testing.T) {
	provider := New(ModeServer)
	broker := newMockBroker()

	config := map[string]interface{}{
		"broker": broker,
	}

	ctx := context.Background()
	err := provider.Initialize(ctx, config)
	require.NoError(t, err)

	// Subscribe multiple handlers
	var count1, count2 int
	var mu sync.Mutex

	handler1 := func(ctx context.Context, event *types.Event) error {
		mu.Lock()
		count1++
		mu.Unlock()
		return nil
	}

	handler2 := func(ctx context.Context, event *types.Event) error {
		mu.Lock()
		count2++
		mu.Unlock()
		return nil
	}

	err = provider.SubscribeEvents(ctx, nil, handler1)
	require.NoError(t, err)

	err = provider.SubscribeEvents(ctx, nil, handler2)
	require.NoError(t, err)

	// Send event
	event := &types.Event{
		ID:        "evt-1",
		Type:      types.EventConfigApplied,
		StewardID: "steward-1",
		Timestamp: time.Now(),
	}
	payload, _ := marshalMessage(event)
	_ = provider.handleEventMessage("cfgms/events/steward-1", payload, 1, false)

	// Wait for async handlers
	time.Sleep(50 * time.Millisecond)

	// Both handlers should have received the event
	mu.Lock()
	assert.Equal(t, 1, count1)
	assert.Equal(t, 1, count2)
	mu.Unlock()

	// Verify stats (subscription count)
	stats, _ := provider.GetStats(ctx)
	assert.Equal(t, int64(2), stats.ActiveSubscriptions)
}
