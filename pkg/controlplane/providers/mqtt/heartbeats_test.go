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

func TestProvider_SendHeartbeat_ClientMode(t *testing.T) {
	// Client mode SendHeartbeat requires actual MQTT client
	provider := New(ModeClient)

	config := map[string]interface{}{
		"broker_addr": "tcp://localhost:1883",
		"client_id":   "test-client",
		"steward_id":  "steward-1",
	}

	ctx := context.Background()
	err := provider.Initialize(ctx, config)
	require.NoError(t, err)

	hb := &types.Heartbeat{
		StewardID: "steward-1",
		Status:    types.StatusHealthy,
		Timestamp: time.Now(),
	}

	// Will fail because client not connected
	err = provider.SendHeartbeat(ctx, hb)
	assert.Error(t, err)
}

func TestProvider_SendHeartbeat_ServerMode_Error(t *testing.T) {
	provider := New(ModeServer)

	ctx := context.Background()
	hb := &types.Heartbeat{StewardID: "steward-1", Status: types.StatusHealthy}

	err := provider.SendHeartbeat(ctx, hb)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "client mode")
}

func TestProvider_SubscribeHeartbeats(t *testing.T) {
	provider := New(ModeServer)
	broker := newMockBroker()

	config := map[string]interface{}{
		"broker": broker,
	}

	ctx := context.Background()
	err := provider.Initialize(ctx, config)
	require.NoError(t, err)

	// Subscribe to heartbeats
	var receivedHeartbeats []*types.Heartbeat
	var mu sync.Mutex

	handler := func(ctx context.Context, hb *types.Heartbeat) error {
		mu.Lock()
		receivedHeartbeats = append(receivedHeartbeats, hb)
		mu.Unlock()
		return nil
	}

	err = provider.SubscribeHeartbeats(ctx, handler)
	require.NoError(t, err)

	// Simulate receiving a heartbeat
	hb := &types.Heartbeat{
		StewardID: "steward-1",
		Status:    types.StatusHealthy,
		Timestamp: time.Now(),
		Metrics: map[string]interface{}{
			"cpu": 25.5,
		},
	}

	payload, _ := marshalMessage(hb)
	err = provider.handleHeartbeatMessage("cfgms/heartbeats/steward-1", payload, 1, false)
	require.NoError(t, err)

	// Wait for async handler
	time.Sleep(50 * time.Millisecond)

	// Verify heartbeat was received
	mu.Lock()
	assert.Len(t, receivedHeartbeats, 1)
	if len(receivedHeartbeats) > 0 {
		assert.Equal(t, "steward-1", receivedHeartbeats[0].StewardID)
		assert.Equal(t, types.StatusHealthy, receivedHeartbeats[0].Status)
	}
	mu.Unlock()

	// Verify stats
	stats, _ := provider.GetStats(ctx)
	assert.Equal(t, int64(1), stats.HeartbeatsReceived)
}

func TestProvider_SubscribeHeartbeats_ClientMode_Error(t *testing.T) {
	provider := New(ModeClient)

	ctx := context.Background()
	handler := func(ctx context.Context, hb *types.Heartbeat) error {
		return nil
	}

	err := provider.SubscribeHeartbeats(ctx, handler)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "server mode")
}

func TestProvider_HandleHeartbeatMessage_InvalidJSON(t *testing.T) {
	provider := New(ModeServer)
	broker := newMockBroker()

	config := map[string]interface{}{
		"broker": broker,
	}

	ctx := context.Background()
	err := provider.Initialize(ctx, config)
	require.NoError(t, err)

	// Handle invalid JSON (should not panic)
	err = provider.handleHeartbeatMessage("cfgms/heartbeats/steward-1", []byte("bad json"), 1, false)
	assert.NoError(t, err)
}

func TestProvider_SubscribeHeartbeats_MultipleHandlers(t *testing.T) {
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

	handler1 := func(ctx context.Context, hb *types.Heartbeat) error {
		mu.Lock()
		count1++
		mu.Unlock()
		return nil
	}

	handler2 := func(ctx context.Context, hb *types.Heartbeat) error {
		mu.Lock()
		count2++
		mu.Unlock()
		return nil
	}

	err = provider.SubscribeHeartbeats(ctx, handler1)
	require.NoError(t, err)

	err = provider.SubscribeHeartbeats(ctx, handler2)
	require.NoError(t, err)

	// Send heartbeat
	hb := &types.Heartbeat{
		StewardID: "steward-1",
		Status:    types.StatusHealthy,
		Timestamp: time.Now(),
	}
	payload, _ := marshalMessage(hb)
	_ = provider.handleHeartbeatMessage("cfgms/heartbeats/steward-1", payload, 1, false)

	// Wait for async handlers
	time.Sleep(50 * time.Millisecond)

	// Both handlers should have received the heartbeat
	mu.Lock()
	assert.Equal(t, 1, count1)
	assert.Equal(t, 1, count2)
	mu.Unlock()
}
