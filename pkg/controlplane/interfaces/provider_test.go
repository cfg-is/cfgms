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

// mockProvider is a test implementation of ControlPlaneProvider
type mockProvider struct {
	name        string
	description string
	initialized bool
	started     bool
	connected   bool
}

func newMockProvider(name string) *mockProvider {
	return &mockProvider{
		name:        name,
		description: "Mock provider for testing",
	}
}

func (m *mockProvider) Name() string             { return m.name }
func (m *mockProvider) Description() string      { return m.description }
func (m *mockProvider) IsConnected() bool        { return m.connected }
func (m *mockProvider) Available() (bool, error) { return true, nil }

func (m *mockProvider) Initialize(ctx context.Context, config map[string]interface{}) error {
	m.initialized = true
	return nil
}

func (m *mockProvider) Start(ctx context.Context) error {
	m.started = true
	m.connected = true
	return nil
}

func (m *mockProvider) Stop(ctx context.Context) error {
	m.started = false
	m.connected = false
	return nil
}

func (m *mockProvider) SendCommand(ctx context.Context, cmd *types.Command) error {
	return nil
}

func (m *mockProvider) FanOutCommand(ctx context.Context, cmd *types.Command, stewardIDs []string) (*types.FanOutResult, error) {
	return &types.FanOutResult{Succeeded: stewardIDs, Failed: make(map[string]error)}, nil
}

func (m *mockProvider) SubscribeCommands(ctx context.Context, stewardID string, handler CommandHandler) error {
	return nil
}

func (m *mockProvider) PublishEvent(ctx context.Context, event *types.Event) error {
	return nil
}

func (m *mockProvider) SubscribeEvents(ctx context.Context, filter *types.EventFilter, handler EventHandler) error {
	return nil
}

func (m *mockProvider) SendHeartbeat(ctx context.Context, heartbeat *types.Heartbeat) error {
	return nil
}

func (m *mockProvider) SubscribeHeartbeats(ctx context.Context, handler HeartbeatHandler) error {
	return nil
}

func (m *mockProvider) GetStats(ctx context.Context) (*types.ControlPlaneStats, error) {
	return &types.ControlPlaneStats{}, nil
}

func TestProviderRegistration(t *testing.T) {
	// Clear registry for test isolation
	providerRegistry = make(map[string]ControlPlaneProvider)

	// Register a mock provider
	mock := newMockProvider("test-provider")
	RegisterProvider(mock)

	// Verify registration
	retrieved := GetProvider("test-provider")
	require.NotNil(t, retrieved)
	assert.Equal(t, "test-provider", retrieved.Name())
	assert.Equal(t, mock, retrieved)
}

func TestProviderRegistration_Duplicate(t *testing.T) {
	// Clear registry for test isolation
	providerRegistry = make(map[string]ControlPlaneProvider)

	// Register first provider
	mock1 := newMockProvider("duplicate")
	RegisterProvider(mock1)

	// Attempt to register duplicate should panic
	mock2 := newMockProvider("duplicate")
	assert.Panics(t, func() {
		RegisterProvider(mock2)
	}, "Registering duplicate provider should panic")
}

func TestGetProvider_NotFound(t *testing.T) {
	// Clear registry for test isolation
	providerRegistry = make(map[string]ControlPlaneProvider)

	// Try to get non-existent provider
	provider := GetProvider("nonexistent")
	assert.Nil(t, provider)
}

func TestGetAvailableProviders(t *testing.T) {
	// Clear registry for test isolation
	providerRegistry = make(map[string]ControlPlaneProvider)

	// Register multiple providers
	RegisterProvider(newMockProvider("provider-a"))
	RegisterProvider(newMockProvider("provider-b"))
	RegisterProvider(newMockProvider("provider-c"))

	// Get available providers
	providers := GetAvailableProviders()
	assert.Len(t, providers, 3)

	// Verify all registered providers are in the list
	providerMap := make(map[string]bool)
	for _, name := range providers {
		providerMap[name] = true
	}

	assert.True(t, providerMap["provider-a"])
	assert.True(t, providerMap["provider-b"])
	assert.True(t, providerMap["provider-c"])
}

func TestProviderLifecycle(t *testing.T) {
	mock := newMockProvider("lifecycle-test")

	// Initial state
	assert.False(t, mock.initialized)
	assert.False(t, mock.started)
	assert.False(t, mock.connected)

	// Initialize
	ctx := context.Background()
	err := mock.Initialize(ctx, nil)
	require.NoError(t, err)
	assert.True(t, mock.initialized)

	// Start
	err = mock.Start(ctx)
	require.NoError(t, err)
	assert.True(t, mock.started)
	assert.True(t, mock.connected)
	assert.True(t, mock.IsConnected())

	// Stop
	err = mock.Stop(ctx)
	require.NoError(t, err)
	assert.False(t, mock.started)
	assert.False(t, mock.connected)
	assert.False(t, mock.IsConnected())
}

func TestCommandHandler(t *testing.T) {
	// Verify CommandHandler signature
	var handler CommandHandler = func(ctx context.Context, cmd *types.Command) error {
		assert.NotNil(t, ctx)
		assert.NotNil(t, cmd)
		return nil
	}

	// Call handler
	ctx := context.Background()
	cmd := &types.Command{ID: "test-cmd", Type: types.CommandSyncConfig}
	err := handler(ctx, cmd)
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
