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

// mockProvider is a test implementation of DataPlaneProvider
type mockProvider struct {
	name        string
	description string
	initialized bool
	started     bool
	listening   bool
	connected   bool
	mode        string
}

func newMockProvider(name string) *mockProvider {
	return &mockProvider{
		name:        name,
		description: "Mock data plane provider for testing",
	}
}

func (m *mockProvider) Name() string        { return m.name }
func (m *mockProvider) Description() string { return m.description }
func (m *mockProvider) IsListening() bool   { return m.listening }
func (m *mockProvider) IsConnected() bool   { return m.connected }

func (m *mockProvider) Available() (bool, error) {
	return true, nil
}

func (m *mockProvider) Initialize(ctx context.Context, config map[string]interface{}) error {
	m.initialized = true
	if mode, ok := config["mode"].(string); ok {
		m.mode = mode
	}
	return nil
}

func (m *mockProvider) Start(ctx context.Context) error {
	m.started = true
	// Determine mode from initialization
	if m.mode == "server" {
		m.listening = true
	} else {
		m.connected = true
	}
	return nil
}

func (m *mockProvider) Stop(ctx context.Context) error {
	m.started = false
	m.listening = false
	m.connected = false
	return nil
}

func (m *mockProvider) AcceptConnection(ctx context.Context) (DataPlaneSession, error) {
	return &mockSession{id: "session-1", peerID: "steward-1"}, nil
}

func (m *mockProvider) Connect(ctx context.Context, serverAddr string) (DataPlaneSession, error) {
	return &mockSession{id: "session-1", peerID: "controller"}, nil
}

func (m *mockProvider) GetStats(ctx context.Context) (*types.DataPlaneStats, error) {
	return &types.DataPlaneStats{
		ProviderName:   m.name,
		Uptime:         time.Minute,
		ActiveSessions: 1,
	}, nil
}

// mockSession is a test implementation of DataPlaneSession
type mockSession struct {
	id         string
	peerID     string
	closed     bool
	localAddr  string
	remoteAddr string
}

func (m *mockSession) ID() string                      { return m.id }
func (m *mockSession) PeerID() string                  { return m.peerID }
func (m *mockSession) IsClosed() bool                  { return m.closed }
func (m *mockSession) LocalAddr() string               { return m.localAddr }
func (m *mockSession) RemoteAddr() string              { return m.remoteAddr }
func (m *mockSession) Close(ctx context.Context) error { m.closed = true; return nil }

func (m *mockSession) SendConfig(ctx context.Context, config *types.ConfigTransfer) error {
	return nil
}

func (m *mockSession) ReceiveConfig(ctx context.Context) (*types.ConfigTransfer, error) {
	return &types.ConfigTransfer{
		ID:        "config-1",
		StewardID: "steward-1",
		TenantID:  "tenant-1",
		Version:   "1.0.0",
		Data:      []byte("test config data"),
	}, nil
}

func (m *mockSession) SendDNA(ctx context.Context, dna *types.DNATransfer) error {
	return nil
}

func (m *mockSession) ReceiveDNA(ctx context.Context) (*types.DNATransfer, error) {
	return &types.DNATransfer{
		ID:         "dna-1",
		StewardID:  "steward-1",
		TenantID:   "tenant-1",
		Attributes: []byte("test dna attributes"),
		Delta:      false,
	}, nil
}

func (m *mockSession) SendBulk(ctx context.Context, bulk *types.BulkTransfer) error {
	return nil
}

func (m *mockSession) ReceiveBulk(ctx context.Context) (*types.BulkTransfer, error) {
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

func (m *mockSession) OpenStream(ctx context.Context, streamType types.StreamType) (Stream, error) {
	return &mockStream{id: 1, streamType: streamType}, nil
}

func (m *mockSession) AcceptStream(ctx context.Context) (Stream, types.StreamType, error) {
	return &mockStream{id: 2, streamType: types.StreamConfig}, types.StreamConfig, nil
}

// mockStream is a test implementation of Stream
type mockStream struct {
	id         uint64
	streamType types.StreamType
	closed     bool
}

func (m *mockStream) Read(p []byte) (n int, err error)           { return 0, nil }
func (m *mockStream) Write(p []byte) (n int, err error)          { return len(p), nil }
func (m *mockStream) Close() error                               { m.closed = true; return nil }
func (m *mockStream) ID() uint64                                 { return m.id }
func (m *mockStream) Type() types.StreamType                     { return m.streamType }
func (m *mockStream) SetDeadline(deadline context.Context) error { return nil }

func TestProviderRegistration(t *testing.T) {
	// Clear registry for test isolation
	providerRegistry = make(map[string]DataPlaneProvider)

	// Register a mock provider
	mock := newMockProvider("test-provider")
	RegisterProvider(mock)

	// Verify provider is registered
	retrieved := GetProvider("test-provider")
	require.NotNil(t, retrieved, "Provider should be registered")
	assert.Equal(t, "test-provider", retrieved.Name())

	// Verify provider list
	providers := GetAvailableProviders()
	assert.Contains(t, providers, "test-provider")
}

func TestProviderRegistrationDuplicate(t *testing.T) {
	// Clear registry for test isolation
	providerRegistry = make(map[string]DataPlaneProvider)

	// Register first provider
	mock1 := newMockProvider("duplicate")
	RegisterProvider(mock1)

	// Attempt to register duplicate should panic
	mock2 := newMockProvider("duplicate")
	assert.Panics(t, func() {
		RegisterProvider(mock2)
	}, "Duplicate registration should panic")
}

func TestProviderLifecycle(t *testing.T) {
	mock := newMockProvider("lifecycle-test")
	ctx := context.Background()

	// Test initialization
	config := map[string]interface{}{
		"mode": "server",
	}
	err := mock.Initialize(ctx, config)
	require.NoError(t, err)
	assert.True(t, mock.initialized, "Provider should be initialized")

	// Test start
	err = mock.Start(ctx)
	require.NoError(t, err)
	assert.True(t, mock.started, "Provider should be started")
	assert.True(t, mock.listening, "Server should be listening")

	// Test availability
	available, err := mock.Available()
	require.NoError(t, err)
	assert.True(t, available, "Provider should be available")

	// Test stop
	err = mock.Stop(ctx)
	require.NoError(t, err)
	assert.False(t, mock.started, "Provider should be stopped")
	assert.False(t, mock.listening, "Server should not be listening")
}

func TestProviderServerMode(t *testing.T) {
	mock := newMockProvider("server-test")
	ctx := context.Background()

	// Initialize as server
	config := map[string]interface{}{
		"mode": "server",
	}
	err := mock.Initialize(ctx, config)
	require.NoError(t, err)

	err = mock.Start(ctx)
	require.NoError(t, err)

	// Test accept connection
	session, err := mock.AcceptConnection(ctx)
	require.NoError(t, err)
	assert.NotNil(t, session)
	assert.Equal(t, "session-1", session.ID())
	assert.Equal(t, "steward-1", session.PeerID())
}

func TestProviderClientMode(t *testing.T) {
	mock := newMockProvider("client-test")
	ctx := context.Background()

	// Initialize as client
	config := map[string]interface{}{
		"mode": "client",
	}
	err := mock.Initialize(ctx, config)
	require.NoError(t, err)

	err = mock.Start(ctx)
	require.NoError(t, err)

	// Test connect
	session, err := mock.Connect(ctx, "controller:4433")
	require.NoError(t, err)
	assert.NotNil(t, session)
	assert.Equal(t, "session-1", session.ID())
	assert.Equal(t, "controller", session.PeerID())
}

func TestProviderStats(t *testing.T) {
	mock := newMockProvider("stats-test")
	ctx := context.Background()

	stats, err := mock.GetStats(ctx)
	require.NoError(t, err)
	assert.NotNil(t, stats)
	assert.Equal(t, "stats-test", stats.ProviderName)
	assert.Equal(t, time.Minute, stats.Uptime)
	assert.Equal(t, 1, stats.ActiveSessions)
}

func TestSessionConfigTransfer(t *testing.T) {
	session := &mockSession{id: "test-session", peerID: "test-peer"}
	ctx := context.Background()

	// Test send config
	config := &types.ConfigTransfer{
		ID:        "config-1",
		StewardID: "steward-1",
		TenantID:  "tenant-1",
		Version:   "1.0.0",
		Data:      []byte("test config"),
	}
	err := session.SendConfig(ctx, config)
	require.NoError(t, err)

	// Test receive config
	received, err := session.ReceiveConfig(ctx)
	require.NoError(t, err)
	assert.NotNil(t, received)
	assert.Equal(t, "config-1", received.ID)
	assert.Equal(t, "steward-1", received.StewardID)
	assert.Equal(t, "1.0.0", received.Version)
}

func TestSessionDNATransfer(t *testing.T) {
	session := &mockSession{id: "test-session", peerID: "test-peer"}
	ctx := context.Background()

	// Test send DNA
	dna := &types.DNATransfer{
		ID:         "dna-1",
		StewardID:  "steward-1",
		TenantID:   "tenant-1",
		Attributes: []byte("test attributes"),
		Delta:      true,
	}
	err := session.SendDNA(ctx, dna)
	require.NoError(t, err)

	// Test receive DNA
	received, err := session.ReceiveDNA(ctx)
	require.NoError(t, err)
	assert.NotNil(t, received)
	assert.Equal(t, "dna-1", received.ID)
	assert.Equal(t, "steward-1", received.StewardID)
	assert.False(t, received.Delta) // Mock returns false
}

func TestSessionBulkTransfer(t *testing.T) {
	session := &mockSession{id: "test-session", peerID: "test-peer"}
	ctx := context.Background()

	// Test send bulk
	bulk := &types.BulkTransfer{
		ID:        "bulk-1",
		StewardID: "steward-1",
		TenantID:  "tenant-1",
		Direction: "to_controller",
		Type:      "logs",
		TotalSize: 2048,
		Data:      []byte("test bulk"),
	}
	err := session.SendBulk(ctx, bulk)
	require.NoError(t, err)

	// Test receive bulk
	received, err := session.ReceiveBulk(ctx)
	require.NoError(t, err)
	assert.NotNil(t, received)
	assert.Equal(t, "bulk-1", received.ID)
	assert.Equal(t, "to_steward", received.Direction) // Mock returns to_steward
	assert.Equal(t, int64(1024), received.TotalSize)  // Mock returns 1024
}

func TestSessionStreams(t *testing.T) {
	session := &mockSession{id: "test-session", peerID: "test-peer"}
	ctx := context.Background()

	// Test open stream
	stream, err := session.OpenStream(ctx, types.StreamConfig)
	require.NoError(t, err)
	assert.NotNil(t, stream)
	assert.Equal(t, uint64(1), stream.ID())
	assert.Equal(t, types.StreamConfig, stream.Type())

	// Test accept stream
	acceptedStream, streamType, err := session.AcceptStream(ctx)
	require.NoError(t, err)
	assert.NotNil(t, acceptedStream)
	assert.Equal(t, types.StreamConfig, streamType)
	assert.Equal(t, uint64(2), acceptedStream.ID())
}

func TestSessionLifecycle(t *testing.T) {
	session := &mockSession{id: "test-session", peerID: "test-peer"}
	ctx := context.Background()

	// Session should not be closed initially
	assert.False(t, session.IsClosed())

	// Close session
	err := session.Close(ctx)
	require.NoError(t, err)
	assert.True(t, session.IsClosed())
}

func TestStreamOperations(t *testing.T) {
	stream := &mockStream{id: 1, streamType: types.StreamDNA}

	// Test read
	buf := make([]byte, 10)
	n, err := stream.Read(buf)
	require.NoError(t, err)
	assert.Equal(t, 0, n) // Mock returns 0

	// Test write
	data := []byte("test data")
	n, err = stream.Write(data)
	require.NoError(t, err)
	assert.Equal(t, len(data), n)

	// Test properties
	assert.Equal(t, uint64(1), stream.ID())
	assert.Equal(t, types.StreamDNA, stream.Type())

	// Test close
	err = stream.Close()
	require.NoError(t, err)
	assert.True(t, stream.closed)
}

func TestStreamDeadline(t *testing.T) {
	stream := &mockStream{id: 1, streamType: types.StreamConfig}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	err := stream.SetDeadline(ctx)
	require.NoError(t, err)
}
