// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package grpc

import (
	"context"
	"crypto/tls"
	"testing"

	"github.com/cfgis/cfgms/pkg/dataplane/interfaces"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestProvider_Registration verifies the provider registers itself as "grpc" via init().
func TestProvider_Registration(t *testing.T) {
	p := interfaces.GetProvider("grpc")
	require.NotNil(t, p, "grpc provider should be registered via init()")
	assert.Equal(t, "grpc", p.Name())
}

// TestProvider_Name verifies Name() returns "grpc".
func TestProvider_Name(t *testing.T) {
	p := New()
	assert.Equal(t, "grpc", p.Name())
}

// TestProvider_Description verifies Description() is non-empty.
func TestProvider_Description(t *testing.T) {
	p := New()
	assert.NotEmpty(t, p.Description())
}

// TestProvider_InitializeServer verifies server mode initialization with valid config.
func TestProvider_InitializeServer(t *testing.T) {
	p := New()
	err := p.Initialize(context.Background(), map[string]interface{}{
		"mode":        "server",
		"listen_addr": "127.0.0.1:0",
		"tls_config":  &tls.Config{MinVersion: tls.VersionTLS13}, //nolint:gosec // test config
	})
	require.NoError(t, err)
	assert.Equal(t, "server", p.mode)
	assert.Equal(t, "127.0.0.1:0", p.listenAddr)
}

// TestProvider_InitializeClient verifies client mode initialization with grpc_conn.
func TestProvider_InitializeClient(t *testing.T) {
	p := New()
	// Use a nil *grpc.ClientConn placeholder — the provider only checks for
	// key presence in Initialize; actual usage happens in Start/Connect.
	err := p.Initialize(context.Background(), map[string]interface{}{
		"mode":        "client",
		"server_addr": "127.0.0.1:4433",
		"tls_config":  &tls.Config{MinVersion: tls.VersionTLS13}, //nolint:gosec // test config
		"steward_id":  "steward-test",
	})
	require.NoError(t, err)
	assert.Equal(t, "client", p.mode)
	assert.Equal(t, "steward-test", p.stewardID)
}

// TestProvider_InitializeMissingMode verifies an error when mode is absent.
func TestProvider_InitializeMissingMode(t *testing.T) {
	p := New()
	err := p.Initialize(context.Background(), map[string]interface{}{
		"listen_addr": "127.0.0.1:0",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "mode")
}

// TestProvider_InitializeInvalidMode verifies an error for unknown mode strings.
func TestProvider_InitializeInvalidMode(t *testing.T) {
	p := New()
	err := p.Initialize(context.Background(), map[string]interface{}{
		"mode": "banana",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "mode")
}

// TestProvider_InitializeServerMissingAddr verifies an error when listen_addr is absent in server mode.
func TestProvider_InitializeServerMissingAddr(t *testing.T) {
	p := New()
	err := p.Initialize(context.Background(), map[string]interface{}{
		"mode":       "server",
		"tls_config": &tls.Config{MinVersion: tls.VersionTLS13}, //nolint:gosec // test config
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "listen_addr")
}

// TestProvider_InitializeClientMissingAddrAndConn verifies an error when neither
// server_addr nor grpc_conn is provided in client mode.
func TestProvider_InitializeClientMissingAddrAndConn(t *testing.T) {
	p := New()
	err := p.Initialize(context.Background(), map[string]interface{}{
		"mode":       "client",
		"tls_config": &tls.Config{MinVersion: tls.VersionTLS13}, //nolint:gosec // test config
		"steward_id": "steward-test",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "server_addr")
}

// TestProvider_Available_Uninitialized verifies Available returns false before init.
func TestProvider_Available_Uninitialized(t *testing.T) {
	p := New()
	ok, err := p.Available()
	assert.False(t, ok)
	require.Error(t, err)
}

// TestProvider_Available_Server verifies Available returns true after server init.
func TestProvider_Available(t *testing.T) {
	p := New()
	err := p.Initialize(context.Background(), map[string]interface{}{
		"mode":        "server",
		"listen_addr": "127.0.0.1:0",
		"tls_config":  &tls.Config{MinVersion: tls.VersionTLS13}, //nolint:gosec // test config
	})
	require.NoError(t, err)

	ok, err := p.Available()
	require.NoError(t, err)
	assert.True(t, ok)
}

// TestProvider_Stats verifies GetStats returns a correctly named stats struct.
func TestProvider_Stats(t *testing.T) {
	p := New()
	stats, err := p.GetStats(context.Background())
	require.NoError(t, err)
	require.NotNil(t, stats)
	assert.Equal(t, "grpc", stats.ProviderName)
	assert.Equal(t, 0, stats.ActiveSessions)
}

// TestProvider_StatsTracking verifies that AcceptConnection increments session counters.
func TestProvider_StatsTracking(t *testing.T) {
	p := New()
	err := p.Initialize(context.Background(), map[string]interface{}{
		"mode":        "server",
		"listen_addr": "127.0.0.1:0",
		"tls_config":  &tls.Config{MinVersion: tls.VersionTLS13}, //nolint:gosec // test config
	})
	require.NoError(t, err)

	// Manually mark as started and set up handler to avoid needing real QUIC
	p.started.Store(true)
	p.handler = newDataPlaneHandler()
	p.sessions = make(map[string]*Session)

	_, err = p.AcceptConnection(context.Background())
	require.NoError(t, err)

	stats, err := p.GetStats(context.Background())
	require.NoError(t, err)
	assert.Equal(t, int64(1), stats.TotalSessionsAccepted)
	assert.Equal(t, 1, stats.ActiveSessions)
}

// TestProvider_IsListening returns false before Start.
func TestProvider_IsListening(t *testing.T) {
	p := New()
	err := p.Initialize(context.Background(), map[string]interface{}{
		"mode":        "server",
		"listen_addr": "127.0.0.1:0",
		"tls_config":  &tls.Config{MinVersion: tls.VersionTLS13}, //nolint:gosec // test config
	})
	require.NoError(t, err)
	assert.False(t, p.IsListening(), "not listening before Start")
}

// TestProvider_IsConnected returns false before Start.
func TestProvider_IsConnected(t *testing.T) {
	p := New()
	err := p.Initialize(context.Background(), map[string]interface{}{
		"mode":        "client",
		"server_addr": "127.0.0.1:4433",
		"tls_config":  &tls.Config{MinVersion: tls.VersionTLS13}, //nolint:gosec // test config
		"steward_id":  "steward-test",
	})
	require.NoError(t, err)
	assert.False(t, p.IsConnected(), "not connected before Start")
}
