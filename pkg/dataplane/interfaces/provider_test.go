// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package interfaces

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/dataplane/types"
)

// testProvider is a minimal test implementation of DataPlaneProvider for
// registry and interface-contract tests. Real behavioral tests use the gRPC
// provider via RunDPContractTests in contract_test.go.
type testProvider struct {
	name        string
	description string
	initialized bool
	started     bool
	listening   bool
	connected   bool
	mode        string
}

func newTestProvider(name string) *testProvider {
	return &testProvider{
		name:        name,
		description: "Test data plane provider",
	}
}

func (m *testProvider) Name() string        { return m.name }
func (m *testProvider) Description() string { return m.description }
func (m *testProvider) IsListening() bool   { return m.listening }
func (m *testProvider) IsConnected() bool   { return m.connected }

func (m *testProvider) Available() (bool, error) {
	return true, nil
}

func (m *testProvider) Initialize(ctx context.Context, config map[string]interface{}) error {
	m.initialized = true
	if mode, ok := config["mode"].(string); ok {
		m.mode = mode
	}
	return nil
}

func (m *testProvider) Start(ctx context.Context) error {
	m.started = true
	if m.mode == "server" {
		m.listening = true
	} else {
		m.connected = true
	}
	return nil
}

func (m *testProvider) Stop(ctx context.Context) error {
	m.started = false
	m.listening = false
	m.connected = false
	return nil
}

func (m *testProvider) AcceptConnection(ctx context.Context) (DataPlaneSession, error) {
	return &testSession{id: "session-1", peerID: "steward-1"}, nil
}

func (m *testProvider) Connect(ctx context.Context, serverAddr string) (DataPlaneSession, error) {
	return &testSession{id: "session-1", peerID: "controller"}, nil
}

func (m *testProvider) GetStats(ctx context.Context) (*types.DataPlaneStats, error) {
	return &types.DataPlaneStats{
		ProviderName:   m.name,
		Uptime:         time.Minute,
		ActiveSessions: 1,
	}, nil
}

// testSession is a minimal test implementation of DataPlaneSession.
type testSession struct {
	id         string
	peerID     string
	closed     bool
	localAddr  string
	remoteAddr string
}

func (m *testSession) ID() string                      { return m.id }
func (m *testSession) PeerID() string                  { return m.peerID }
func (m *testSession) IsClosed() bool                  { return m.closed }
func (m *testSession) LocalAddr() string               { return m.localAddr }
func (m *testSession) RemoteAddr() string              { return m.remoteAddr }
func (m *testSession) Close(ctx context.Context) error { m.closed = true; return nil }

func (m *testSession) SendConfig(ctx context.Context, config *types.ConfigTransfer) error {
	return nil
}

func (m *testSession) ReceiveConfig(ctx context.Context) (*types.ConfigTransfer, error) {
	return &types.ConfigTransfer{
		ID:        "config-1",
		StewardID: "steward-1",
		TenantID:  "tenant-1",
		Version:   "1.0.0",
		Data:      []byte("test config data"),
	}, nil
}

func (m *testSession) SendDNA(ctx context.Context, dna *types.DNATransfer) error {
	return nil
}

func (m *testSession) ReceiveDNA(ctx context.Context) (*types.DNATransfer, error) {
	return &types.DNATransfer{
		ID:         "dna-1",
		StewardID:  "steward-1",
		TenantID:   "tenant-1",
		Attributes: []byte("test dna attributes"),
		Delta:      false,
	}, nil
}

func (m *testSession) SendBulk(ctx context.Context, bulk *types.BulkTransfer) error {
	return nil
}

func (m *testSession) ReceiveBulk(ctx context.Context) (*types.BulkTransfer, error) {
	return &types.BulkTransfer{
		ID:        "bulk-1",
		StewardID: "steward-1",
		TenantID:  "tenant-1",
		Direction: "to_steward",
		Type:      "file",
		TotalSize: 1024,
		Data:      []byte("test bulk data"),
	}, nil
}

func TestProviderRegistration(t *testing.T) {
	// Clear registry for test isolation
	providerRegistry = make(map[string]DataPlaneProvider)

	p := newTestProvider("test-provider")
	RegisterProvider(p)

	retrieved := GetProvider("test-provider")
	require.NotNil(t, retrieved, "Provider should be registered")
	assert.Equal(t, "test-provider", retrieved.Name())

	providers := GetAvailableProviders()
	assert.Contains(t, providers, "test-provider")
}

func TestProviderRegistrationDuplicate(t *testing.T) {
	// Clear registry for test isolation
	providerRegistry = make(map[string]DataPlaneProvider)

	p1 := newTestProvider("duplicate")
	RegisterProvider(p1)

	p2 := newTestProvider("duplicate")
	assert.Panics(t, func() {
		RegisterProvider(p2)
	}, "Duplicate registration should panic")
}

func TestProviderLifecycle(t *testing.T) {
	p := newTestProvider("lifecycle-test")
	ctx := context.Background()

	config := map[string]interface{}{
		"mode": "server",
	}
	err := p.Initialize(ctx, config)
	require.NoError(t, err)
	assert.True(t, p.initialized, "Provider should be initialized")

	err = p.Start(ctx)
	require.NoError(t, err)
	assert.True(t, p.started, "Provider should be started")
	assert.True(t, p.listening, "Server should be listening")

	available, err := p.Available()
	require.NoError(t, err)
	assert.True(t, available, "Provider should be available")

	err = p.Stop(ctx)
	require.NoError(t, err)
	assert.False(t, p.started, "Provider should be stopped")
	assert.False(t, p.listening, "Server should not be listening")
}

func TestSessionLifecycle(t *testing.T) {
	session := &testSession{id: "test-session", peerID: "test-peer"}
	ctx := context.Background()

	assert.False(t, session.IsClosed())

	err := session.Close(ctx)
	require.NoError(t, err)
	assert.True(t, session.IsClosed())
}
