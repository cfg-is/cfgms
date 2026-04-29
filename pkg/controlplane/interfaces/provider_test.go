// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package interfaces

import (
	"context"
	"testing"

	"github.com/cfgis/cfgms/pkg/controlplane/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testProvider is a test implementation of ControlPlaneProvider
type testProvider struct {
	name        string
	initialized bool
	started     bool
	connected   bool
}

func newTestProvider(name string) *testProvider {
	return &testProvider{
		name: name,
	}
}

func (m *testProvider) Name() string      { return m.name }
func (m *testProvider) IsConnected() bool { return m.connected }

func (m *testProvider) Initialize(ctx context.Context, config map[string]interface{}) error {
	m.initialized = true
	return nil
}

func (m *testProvider) Start(ctx context.Context) error {
	m.started = true
	m.connected = true
	return nil
}

func (m *testProvider) Stop(ctx context.Context) error {
	m.started = false
	m.connected = false
	return nil
}

func (m *testProvider) SendCommand(ctx context.Context, cmd *types.SignedCommand) error {
	return nil
}

func (m *testProvider) FanOutCommand(ctx context.Context, cmd *types.SignedCommand, stewardIDs []string) (*types.FanOutResult, error) {
	return &types.FanOutResult{Succeeded: stewardIDs, Failed: make(map[string]error)}, nil
}

func (m *testProvider) SubscribeCommands(ctx context.Context, stewardID string, handler CommandHandler) error {
	return nil
}

func (m *testProvider) PublishEvent(ctx context.Context, event *types.Event) error {
	return nil
}

func (m *testProvider) SubscribeEvents(ctx context.Context, filter *types.EventFilter, handler EventHandler) error {
	return nil
}

func (m *testProvider) SendHeartbeat(ctx context.Context, heartbeat *types.Heartbeat) error {
	return nil
}

func (m *testProvider) SubscribeHeartbeats(ctx context.Context, handler HeartbeatHandler) error {
	return nil
}

func (m *testProvider) GetStats(ctx context.Context) (*types.ControlPlaneStats, error) {
	return &types.ControlPlaneStats{}, nil
}

func TestProviderLifecycle(t *testing.T) {
	provider := newTestProvider("lifecycle-test")

	// Initial state
	assert.False(t, provider.initialized)
	assert.False(t, provider.started)
	assert.False(t, provider.connected)

	// Initialize
	ctx := context.Background()
	err := provider.Initialize(ctx, nil)
	require.NoError(t, err)
	assert.True(t, provider.initialized)

	// Start
	err = provider.Start(ctx)
	require.NoError(t, err)
	assert.True(t, provider.started)
	assert.True(t, provider.connected)
	assert.True(t, provider.IsConnected())

	// Stop
	err = provider.Stop(ctx)
	require.NoError(t, err)
	assert.False(t, provider.started)
	assert.False(t, provider.connected)
	assert.False(t, provider.IsConnected())
}

func TestCommandHandler(t *testing.T) {
	// Verify CommandHandler signature accepts SignedCommand
	var handler CommandHandler = func(ctx context.Context, sc *types.SignedCommand) error {
		assert.NotNil(t, ctx)
		assert.NotNil(t, sc)
		return nil
	}

	// Call handler
	ctx := context.Background()
	sc := &types.SignedCommand{Command: types.Command{ID: "test-cmd", Type: types.CommandSyncConfig}}
	err := handler(ctx, sc)
	assert.NoError(t, err)
}

func TestEventHandler(t *testing.T) {
	// Verify EventHandler signature
	var handler EventHandler = func(ctx context.Context, event *types.Event) error {
		assert.NotNil(t, ctx)
		assert.NotNil(t, event)
		return nil
	}

	// Call handler
	ctx := context.Background()
	event := &types.Event{ID: "test-event", Type: types.EventConfigApplied}
	err := handler(ctx, event)
	assert.NoError(t, err)
}

func TestHeartbeatHandler(t *testing.T) {
	// Verify HeartbeatHandler signature
	var handler HeartbeatHandler = func(ctx context.Context, heartbeat *types.Heartbeat) error {
		assert.NotNil(t, ctx)
		assert.NotNil(t, heartbeat)
		return nil
	}

	// Call handler
	ctx := context.Background()
	hb := &types.Heartbeat{StewardID: "test-steward", Status: types.StatusHealthy}
	err := handler(ctx, hb)
	assert.NoError(t, err)
}
