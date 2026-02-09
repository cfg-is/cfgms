// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package mqtt

import (
	"context"
	"testing"
	"time"

	"github.com/cfgis/cfgms/pkg/controlplane/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProvider_SendResponse_ClientMode(t *testing.T) {
	provider := New(ModeClient)

	config := map[string]interface{}{
		"broker_addr": "tcp://localhost:1883",
		"client_id":   "test-client",
		"steward_id":  "steward-1",
	}

	ctx := context.Background()
	err := provider.Initialize(ctx, config)
	require.NoError(t, err)

	resp := &types.Response{
		CommandID: "cmd-123",
		StewardID: "steward-1",
		Success:   true,
		Message:   "Command accepted",
		Timestamp: time.Now(),
	}

	// Will fail because client not connected
	err = provider.SendResponse(ctx, resp)
	assert.Error(t, err)
}

func TestProvider_SendResponse_ServerMode_Error(t *testing.T) {
	provider := New(ModeServer)

	ctx := context.Background()
	resp := &types.Response{CommandID: "cmd-1", Success: true}

	err := provider.SendResponse(ctx, resp)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "client mode")
}

func TestProvider_WaitForResponse_Timeout(t *testing.T) {
	provider := New(ModeServer)
	broker := newMockBroker()

	config := map[string]interface{}{
		"broker": broker,
	}

	ctx := context.Background()
	err := provider.Initialize(ctx, config)
	require.NoError(t, err)

	// Wait for response that never arrives
	resp, err := provider.WaitForResponse(ctx, "cmd-nonexistent", 100*time.Millisecond)

	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "timeout")
}

func TestProvider_WaitForResponse_Success(t *testing.T) {
	provider := New(ModeServer)
	broker := newMockBroker()

	config := map[string]interface{}{
		"broker": broker,
	}

	ctx := context.Background()
	err := provider.Initialize(ctx, config)
	require.NoError(t, err)

	commandID := "cmd-123"

	// Start waiting in goroutine
	responseChan := make(chan *types.Response, 1)
	errorChan := make(chan error, 1)

	go func() {
		resp, err := provider.WaitForResponse(ctx, commandID, 2*time.Second)
		if err != nil {
			errorChan <- err
		} else {
			responseChan <- resp
		}
	}()

	// Give WaitForResponse time to set up subscription
	time.Sleep(50 * time.Millisecond)

	// Simulate response arriving
	response := &types.Response{
		CommandID: commandID,
		StewardID: "steward-1",
		Success:   true,
		Message:   "Command completed",
		Timestamp: time.Now(),
	}

	payload, _ := marshalMessage(response)

	// Find the response topic handler and call it
	topic := "cfgms/responses/" + commandID
	if handler, exists := broker.getSubscriber(topic); exists {
		_ = handler(topic, payload, 1, false)
	}

	// Wait for response
	select {
	case resp := <-responseChan:
		assert.NotNil(t, resp)
		assert.Equal(t, commandID, resp.CommandID)
		assert.True(t, resp.Success)
		assert.Equal(t, "Command completed", resp.Message)

		// Verify stats
		stats, _ := provider.GetStats(ctx)
		assert.Equal(t, int64(1), stats.ResponsesReceived)

	case err := <-errorChan:
		t.Fatalf("Unexpected error: %v", err)

	case <-time.After(3 * time.Second):
		t.Fatal("Timeout waiting for response")
	}
}

func TestProvider_WaitForResponse_ContextCancelled(t *testing.T) {
	provider := New(ModeServer)
	broker := newMockBroker()

	config := map[string]interface{}{
		"broker": broker,
	}

	ctx := context.Background()
	err := provider.Initialize(ctx, config)
	require.NoError(t, err)

	// Create cancellable context
	waitCtx, cancel := context.WithCancel(ctx)

	// Start waiting
	responseChan := make(chan *types.Response, 1)
	errorChan := make(chan error, 1)

	go func() {
		resp, err := provider.WaitForResponse(waitCtx, "cmd-cancel", 5*time.Second)
		if err != nil {
			errorChan <- err
		} else {
			responseChan <- resp
		}
	}()

	// Cancel context after a short delay
	time.Sleep(50 * time.Millisecond)
	cancel()

	// Should get context error
	select {
	case err := <-errorChan:
		assert.Error(t, err)
		assert.ErrorIs(t, err, context.Canceled)

	case <-time.After(1 * time.Second):
		t.Fatal("Timeout waiting for error")
	}
}

func TestProvider_WaitForResponse_ClientMode_Error(t *testing.T) {
	provider := New(ModeClient)

	ctx := context.Background()
	resp, err := provider.WaitForResponse(ctx, "cmd-1", time.Second)

	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "server mode")
}
