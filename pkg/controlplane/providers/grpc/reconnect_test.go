// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz

package grpc

import (
	"context"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cfgis/cfgms/pkg/controlplane/types"
	"github.com/cfgis/cfgms/pkg/transport/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// restartServerAndRepoint starts a new server on an ephemeral port and updates
// the client's addr so the reconnection loop dials the new server.
// This avoids UDP port reuse issues where quic-go's internal transport holds
// the socket after listener close.
func restartServerAndRepoint(t *testing.T, client *Provider, tc *testCA, reg registry.Registry) *Provider {
	t.Helper()
	server := New(ModeServer)
	require.NoError(t, server.Initialize(context.Background(), map[string]interface{}{
		"mode":       "server",
		"addr":       "127.0.0.1:0",
		"tls_config": tc.serverTLSConfig(t),
		"registry":   reg,
	}))
	require.NoError(t, server.Start(context.Background()))
	t.Cleanup(func() { forceStopServer(server) })

	// Point the client's reconnection loop at the new server address.
	// Use sendMu because dialAndOpenStream reads addr under sendMu.
	client.sendMu.Lock()
	client.addr = server.listener.Addr().String()
	client.sendMu.Unlock()

	return server
}

// forceStopServer forcefully kills a gRPC server without waiting for streams to finish.
// GracefulStop() hangs on long-lived ControlChannel streams; this is needed for
// reconnection tests that simulate server crashes.
// Listener is closed first to release the UDP socket, then gRPC is force-stopped.
func forceStopServer(s *Provider) {
	if s.listener != nil {
		_ = s.listener.Close()
	}
	if s.grpcServer != nil {
		s.grpcServer.Stop()
	}
}

func TestMain(m *testing.M) {
	// Use fast backoff for all reconnection tests to avoid timeouts with race detector.
	testBackoffOverride = &backoff{
		initial:    50 * time.Millisecond,
		max:        200 * time.Millisecond,
		multiplier: 2.0,
		jitter:     0.1,
	}
	os.Exit(m.Run())
}

func TestReconnectAfterServerRestart(t *testing.T) {
	tc := newTestCA(t)
	reg := registry.NewRegistry()

	// Start server
	server := New(ModeServer)
	require.NoError(t, server.Initialize(context.Background(), map[string]interface{}{
		"mode":       "server",
		"addr":       "127.0.0.1:0",
		"tls_config": tc.serverTLSConfig(t),
		"registry":   reg,
	}))
	require.NoError(t, server.Start(context.Background()))

	listenAddr := server.listener.Addr().String()

	// Set up command handler before connecting — handler survives reconnection
	received := make(chan *types.SignedCommand, 1)

	client := New(ModeClient)
	require.NoError(t, client.Initialize(context.Background(), map[string]interface{}{
		"mode":       "client",
		"addr":       listenAddr,
		"tls_config": tc.clientTLSConfig(t, "steward-reconnect"),
		"steward_id": "steward-reconnect",
	}))
	require.NoError(t, client.SubscribeCommands(context.Background(), "steward-reconnect", func(ctx context.Context, sc *types.SignedCommand) error {
		received <- sc
		return nil
	}))
	require.NoError(t, client.Start(context.Background()))
	t.Cleanup(func() { _ = client.Stop(context.Background()) })

	// Verify initial connection
	require.Eventually(t, func() bool {
		_, ok := reg.Get("steward-reconnect")
		return ok
	}, 5*time.Second, 10*time.Millisecond)
	assert.True(t, client.IsConnected())

	forceStopServer(server)

	// Client should detect disconnection
	require.Eventually(t, func() bool {
		return client.getState() != StateConnected
	}, 5*time.Second, 10*time.Millisecond, "client should detect disconnection")

	// Restart server (new port, client addr updated automatically)
	server2 := restartServerAndRepoint(t, client, tc, reg)

	// Client should reconnect automatically
	require.Eventually(t, func() bool {
		return client.getState() == StateConnected
	}, 30*time.Second, 100*time.Millisecond, "client should reconnect")

	// Steward should be back in the registry
	require.Eventually(t, func() bool {
		_, ok := reg.Get("steward-reconnect")
		return ok
	}, 5*time.Second, 10*time.Millisecond, "steward should be re-registered")

	// Verify commands work after reconnect
	require.NoError(t, server2.SendCommand(context.Background(), &types.SignedCommand{Command: types.Command{
		ID:        "cmd-after-reconnect",
		Type:      types.CommandSyncConfig,
		StewardID: "steward-reconnect",
		Timestamp: time.Now(),
	}}))

	select {
	case got := <-received:
		assert.Equal(t, "cmd-after-reconnect", got.Command.ID)
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for command after reconnect")
	}
}

func TestStopDuringReconnection(t *testing.T) {
	tc := newTestCA(t)
	reg := registry.NewRegistry()

	// Start and immediately stop server to force reconnection
	server := New(ModeServer)
	require.NoError(t, server.Initialize(context.Background(), map[string]interface{}{
		"mode":       "server",
		"addr":       "127.0.0.1:0",
		"tls_config": tc.serverTLSConfig(t),
		"registry":   reg,
	}))
	require.NoError(t, server.Start(context.Background()))
	listenAddr := server.listener.Addr().String()

	client := New(ModeClient)
	require.NoError(t, client.Initialize(context.Background(), map[string]interface{}{
		"mode":       "client",
		"addr":       listenAddr,
		"tls_config": tc.clientTLSConfig(t, "steward-stop-reconnect"),
		"steward_id": "steward-stop-reconnect",
	}))
	require.NoError(t, client.Start(context.Background()))

	// Wait for connection
	require.Eventually(t, func() bool {
		return client.getState() == StateConnected
	}, 5*time.Second, 10*time.Millisecond)

	// Kill server to trigger reconnection
	forceStopServer(server)

	// Wait for client to enter reconnecting state
	require.Eventually(t, func() bool {
		s := client.getState()
		return s == StateReconnecting || s == StateDisconnected
	}, 5*time.Second, 10*time.Millisecond)

	// Stop the client during reconnection — should not hang or leak goroutines
	done := make(chan struct{})
	go func() {
		_ = client.Stop(context.Background())
		close(done)
	}()

	select {
	case <-done:
		// Clean shutdown — success
	case <-time.After(5 * time.Second):
		t.Fatal("client.Stop() hung during reconnection")
	}

	assert.Equal(t, StateDisconnected, client.getState())
}

func TestSendsDuringDisconnectionReturnErrors(t *testing.T) {
	tc := newTestCA(t)
	reg := registry.NewRegistry()

	server := New(ModeServer)
	require.NoError(t, server.Initialize(context.Background(), map[string]interface{}{
		"mode":       "server",
		"addr":       "127.0.0.1:0",
		"tls_config": tc.serverTLSConfig(t),
		"registry":   reg,
	}))
	require.NoError(t, server.Start(context.Background()))
	listenAddr := server.listener.Addr().String()

	client := New(ModeClient)
	require.NoError(t, client.Initialize(context.Background(), map[string]interface{}{
		"mode":       "client",
		"addr":       listenAddr,
		"tls_config": tc.clientTLSConfig(t, "steward-send-err"),
		"steward_id": "steward-send-err",
	}))
	require.NoError(t, client.Start(context.Background()))
	t.Cleanup(func() { _ = client.Stop(context.Background()) })

	require.Eventually(t, func() bool {
		return client.getState() == StateConnected
	}, 5*time.Second, 10*time.Millisecond)

	// Kill server
	forceStopServer(server)

	// Wait for disconnection
	require.Eventually(t, func() bool {
		return client.getState() != StateConnected
	}, 5*time.Second, 10*time.Millisecond)

	// All send methods should return errors (state may be disconnected or reconnecting)
	err := client.PublishEvent(context.Background(), &types.Event{
		ID: "evt-fail", Type: types.EventError, StewardID: "steward-send-err", Timestamp: time.Now(), Severity: "error",
	})
	require.Error(t, err)
	assert.True(t, assert.ObjectsAreEqual(true,
		strings.Contains(err.Error(), "disconnected") || strings.Contains(err.Error(), "reconnecting")),
		"error should mention disconnected or reconnecting, got: %s", err.Error())

	err = client.SendHeartbeat(context.Background(), &types.Heartbeat{
		StewardID: "steward-send-err", Status: types.StatusHealthy, Timestamp: time.Now(),
	})
	require.Error(t, err)

	err = client.SendResponse(context.Background(), &types.Response{
		CommandID: "cmd-1", StewardID: "steward-send-err", Timestamp: time.Now(),
	})
	require.Error(t, err)

	// DeliveryFailures should be incremented
	assert.True(t, client.deliveryFailures.Load() >= 3)
}

func TestOnStateChangeCallback(t *testing.T) {
	tc := newTestCA(t)
	reg := registry.NewRegistry()

	var mu sync.Mutex
	var transitions []ConnectionState

	server := New(ModeServer)
	require.NoError(t, server.Initialize(context.Background(), map[string]interface{}{
		"mode":       "server",
		"addr":       "127.0.0.1:0",
		"tls_config": tc.serverTLSConfig(t),
		"registry":   reg,
	}))
	require.NoError(t, server.Start(context.Background()))
	listenAddr := server.listener.Addr().String()

	client := New(ModeClient)
	require.NoError(t, client.Initialize(context.Background(), map[string]interface{}{
		"mode":       "client",
		"addr":       listenAddr,
		"tls_config": tc.clientTLSConfig(t, "steward-callback"),
		"steward_id": "steward-callback",
		"on_state_change": func(state ConnectionState) {
			mu.Lock()
			transitions = append(transitions, state)
			mu.Unlock()
		},
	}))
	require.NoError(t, client.Start(context.Background()))

	// Should have seen Connecting → Connected
	require.Eventually(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(transitions) >= 2
	}, 5*time.Second, 10*time.Millisecond)

	mu.Lock()
	assert.Equal(t, StateConnecting, transitions[0])
	assert.Equal(t, StateConnected, transitions[1])
	mu.Unlock()

	// Stop should produce Disconnected
	_ = client.Stop(context.Background())

	mu.Lock()
	lastState := transitions[len(transitions)-1]
	mu.Unlock()
	assert.Equal(t, StateDisconnected, lastState)
}

func TestReconnectStatsTracking(t *testing.T) {
	tc := newTestCA(t)
	reg := registry.NewRegistry()

	server := New(ModeServer)
	require.NoError(t, server.Initialize(context.Background(), map[string]interface{}{
		"mode":       "server",
		"addr":       "127.0.0.1:0",
		"tls_config": tc.serverTLSConfig(t),
		"registry":   reg,
	}))
	require.NoError(t, server.Start(context.Background()))
	listenAddr := server.listener.Addr().String()

	client := New(ModeClient)
	require.NoError(t, client.Initialize(context.Background(), map[string]interface{}{
		"mode":       "client",
		"addr":       listenAddr,
		"tls_config": tc.clientTLSConfig(t, "steward-stats-reconnect"),
		"steward_id": "steward-stats-reconnect",
	}))
	require.NoError(t, client.Start(context.Background()))
	t.Cleanup(func() { _ = client.Stop(context.Background()) })

	require.Eventually(t, func() bool {
		return client.getState() == StateConnected
	}, 5*time.Second, 10*time.Millisecond)

	// Kill server to trigger reconnection attempts
	forceStopServer(server)

	// Wait for at least one reconnect attempt
	require.Eventually(t, func() bool {
		return client.reconnectAttempts.Load() >= 1
	}, 10*time.Second, 50*time.Millisecond)

	// Verify stats include reconnect info
	stats, err := client.GetStats(context.Background())
	require.NoError(t, err)
	assert.Greater(t, stats.ProviderMetrics["reconnect_attempts"].(int64), int64(0))
	assert.NotNil(t, stats.ProviderMetrics["last_connected_at"])
	assert.NotNil(t, stats.ProviderMetrics["last_disconnected_at"])
	assert.NotEqual(t, "connected", stats.ProviderMetrics["connection_state"])

	// Restart server so cleanup reconnection stops
	_ = restartServerAndRepoint(t, client, tc, reg)

	// Wait for reconnection
	require.Eventually(t, func() bool {
		return client.getState() == StateConnected
	}, 30*time.Second, 100*time.Millisecond)
}

func TestRapidDisconnectReconnectCycles(t *testing.T) {
	tc := newTestCA(t)

	var serverCount atomic.Int32

	client := New(ModeClient)
	var listenAddr string

	// Start initial server
	reg := registry.NewRegistry()
	server := New(ModeServer)
	require.NoError(t, server.Initialize(context.Background(), map[string]interface{}{
		"mode":       "server",
		"addr":       "127.0.0.1:0",
		"tls_config": tc.serverTLSConfig(t),
		"registry":   reg,
	}))
	require.NoError(t, server.Start(context.Background()))
	listenAddr = server.listener.Addr().String()

	require.NoError(t, client.Initialize(context.Background(), map[string]interface{}{
		"mode":       "client",
		"addr":       listenAddr,
		"tls_config": tc.clientTLSConfig(t, "steward-rapid"),
		"steward_id": "steward-rapid",
	}))
	require.NoError(t, client.Start(context.Background()))
	t.Cleanup(func() { _ = client.Stop(context.Background()) })

	require.Eventually(t, func() bool {
		return client.getState() == StateConnected
	}, 5*time.Second, 10*time.Millisecond)

	// Rapid kill/restart cycles
	for i := 0; i < 3; i++ {
		forceStopServer(server)

		require.Eventually(t, func() bool {
			return client.getState() != StateConnected
		}, 5*time.Second, 10*time.Millisecond)

		// Restart server (new port, client addr updated automatically)
		server = restartServerAndRepoint(t, client, tc, reg)
		serverCount.Add(1)

		require.Eventually(t, func() bool {
			return client.getState() == StateConnected
		}, 30*time.Second, 100*time.Millisecond, "should reconnect after cycle %d", i)
	}

	// Should have exactly one registry entry (no duplicates).
	// Both conditions are checked atomically inside the closure to avoid a
	// TOCTOU window between two separate Eventually calls.
	require.Eventually(t, func() bool {
		_, ok := reg.Get("steward-rapid")
		return ok && reg.Count() == 1
	}, 5*time.Second, 10*time.Millisecond, "steward should be registered with no duplicates")
}
