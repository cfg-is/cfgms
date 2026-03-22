// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz

package grpc

import (
	"context"
	"crypto/tls"
	"fmt"
	"sync"
	"testing"
	"time"

	cfgcert "github.com/cfgis/cfgms/pkg/cert"
	"github.com/cfgis/cfgms/pkg/controlplane/interfaces"
	"github.com/cfgis/cfgms/pkg/controlplane/types"
	quictransport "github.com/cfgis/cfgms/pkg/transport/quic"
	"github.com/cfgis/cfgms/pkg/transport/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testEnv holds a matched server + client provider pair connected over real QUIC+mTLS.
type testEnv struct {
	server   *Provider
	client   *Provider
	registry registry.Registry
}

// newTestEnv creates a server and client provider connected over real QUIC+mTLS.
// The client certificate CN is used as the steward ID.
func newTestEnv(t *testing.T, stewardID string) *testEnv {
	t.Helper()

	serverTLS, clientTLS := newTestTLSConfigs(t, stewardID)
	reg := registry.NewRegistry()

	server := New(ModeServer)
	err := server.Initialize(context.Background(), map[string]interface{}{
		"mode":       "server",
		"addr":       "127.0.0.1:0",
		"tls_config": serverTLS,
		"registry":   reg,
	})
	require.NoError(t, err)

	// Start server on ephemeral port
	err = server.Start(context.Background())
	require.NoError(t, err)
	t.Cleanup(func() { _ = server.Stop(context.Background()) })

	// Get the actual listen address
	listenAddr := server.listener.Addr().String()

	client := New(ModeClient)
	err = client.Initialize(context.Background(), map[string]interface{}{
		"mode":       "client",
		"addr":       listenAddr,
		"tls_config": clientTLS,
		"steward_id": stewardID,
	})
	require.NoError(t, err)

	err = client.Start(context.Background())
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Stop(context.Background()) })

	// Wait for the steward to appear in the registry
	require.Eventually(t, func() bool {
		_, ok := reg.Get(stewardID)
		return ok
	}, 5*time.Second, 10*time.Millisecond, "steward should be registered")

	return &testEnv{server: server, client: client, registry: reg}
}

// testCA holds a test CA and its PEM-encoded certificate for reuse across
// multiple steward client configs in multi-steward tests.
type testCA struct {
	ca    *cfgcert.CA
	caPEM []byte
}

// newTestCA creates a fresh test CA.
func newTestCA(t *testing.T) *testCA {
	t.Helper()
	ca, err := cfgcert.NewCA(&cfgcert.CAConfig{
		Organization: "CFGMS Test",
		Country:      "US",
		ValidityDays: 1,
		KeySize:      2048,
	})
	require.NoError(t, err)
	require.NoError(t, ca.Initialize(nil))
	caPEM, err := ca.GetCACertificate()
	require.NoError(t, err)
	return &testCA{ca: ca, caPEM: caPEM}
}

// serverTLSConfig returns a server TLS config signed by this CA.
func (tc *testCA) serverTLSConfig(t *testing.T) *tls.Config {
	t.Helper()
	serverCert, err := tc.ca.GenerateServerCertificate(&cfgcert.ServerCertConfig{
		CommonName:   "localhost",
		DNSNames:     []string{"localhost"},
		ValidityDays: 1,
		KeySize:      2048,
	})
	require.NoError(t, err)

	cfg, err := cfgcert.CreateServerTLSConfig(
		serverCert.CertificatePEM, serverCert.PrivateKeyPEM,
		tc.caPEM, tls.VersionTLS13,
	)
	require.NoError(t, err)
	cfg.NextProtos = []string{quictransport.ALPNProtocol}
	return cfg
}

// clientTLSConfig returns a client TLS config with CN set to stewardID.
func (tc *testCA) clientTLSConfig(t *testing.T, stewardID string) *tls.Config {
	t.Helper()
	clientCert, err := tc.ca.GenerateClientCertificate(&cfgcert.ClientCertConfig{
		CommonName:   stewardID,
		ValidityDays: 1,
		KeySize:      2048,
	})
	require.NoError(t, err)

	cfg, err := cfgcert.CreateClientTLSConfig(
		clientCert.CertificatePEM, clientCert.PrivateKeyPEM,
		tc.caPEM, "localhost", tls.VersionTLS13,
	)
	require.NoError(t, err)
	cfg.NextProtos = []string{quictransport.ALPNProtocol}
	return cfg
}

// newTestTLSConfigs creates matched server and client TLS configs for testing.
// Convenience wrapper that creates a fresh CA per call (fine for single-steward tests).
func newTestTLSConfigs(t *testing.T, stewardID string) (serverTLS, clientTLS *tls.Config) {
	t.Helper()
	tc := newTestCA(t)
	return tc.serverTLSConfig(t), tc.clientTLSConfig(t, stewardID)
}

// --- Integration Tests ---

func TestControllerSendsCommand_StewardReceives(t *testing.T) {
	env := newTestEnv(t, "steward-cmd-test")

	received := make(chan *types.Command, 1)
	err := env.client.SubscribeCommands(context.Background(), "steward-cmd-test", func(ctx context.Context, cmd *types.Command) error {
		received <- cmd
		return nil
	})
	require.NoError(t, err)

	cmd := &types.Command{
		ID:        "cmd-001",
		Type:      types.CommandSyncConfig,
		StewardID: "steward-cmd-test",
		Timestamp: time.Now().Truncate(time.Microsecond),
		Priority:  3,
		Params:    map[string]interface{}{"version": "1.0"},
	}

	err = env.server.SendCommand(context.Background(), cmd)
	require.NoError(t, err)

	select {
	case got := <-received:
		assert.Equal(t, cmd.ID, got.ID)
		assert.Equal(t, cmd.Type, got.Type)
		assert.Equal(t, cmd.StewardID, got.StewardID)
		assert.Equal(t, cmd.Priority, got.Priority)
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for command")
	}
}

func TestStewardSendsEvent_ControllerReceives(t *testing.T) {
	env := newTestEnv(t, "steward-evt-test")

	received := make(chan *types.Event, 1)
	err := env.server.SubscribeEvents(context.Background(), nil, func(ctx context.Context, event *types.Event) error {
		received <- event
		return nil
	})
	require.NoError(t, err)

	event := &types.Event{
		ID:        "evt-001",
		Type:      types.EventConfigApplied,
		StewardID: "steward-evt-test",
		Timestamp: time.Now().Truncate(time.Microsecond),
		Severity:  "info",
		Details:   map[string]interface{}{"modules": "5"},
	}

	err = env.client.PublishEvent(context.Background(), event)
	require.NoError(t, err)

	select {
	case got := <-received:
		assert.Equal(t, event.ID, got.ID)
		assert.Equal(t, event.Type, got.Type)
		assert.Equal(t, event.StewardID, got.StewardID)
		assert.Equal(t, event.Severity, got.Severity)
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for event")
	}
}

func TestStewardSendsHeartbeat_ControllerReceives(t *testing.T) {
	env := newTestEnv(t, "steward-hb-test")

	received := make(chan *types.Heartbeat, 1)
	err := env.server.SubscribeHeartbeats(context.Background(), func(ctx context.Context, hb *types.Heartbeat) error {
		received <- hb
		return nil
	})
	require.NoError(t, err)

	hb := &types.Heartbeat{
		StewardID: "steward-hb-test",
		Status:    types.StatusHealthy,
		Timestamp: time.Now().Truncate(time.Microsecond),
		Version:   "2.0.0",
	}

	err = env.client.SendHeartbeat(context.Background(), hb)
	require.NoError(t, err)

	select {
	case got := <-received:
		assert.Equal(t, hb.StewardID, got.StewardID)
		assert.Equal(t, hb.Status, got.Status)
		assert.Equal(t, hb.Version, got.Version)
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for heartbeat")
	}
}

func TestWaitForResponse(t *testing.T) {
	env := newTestEnv(t, "steward-resp-test")

	// Subscribe to commands so the steward can respond
	err := env.client.SubscribeCommands(context.Background(), "steward-resp-test", func(ctx context.Context, cmd *types.Command) error {
		// Send response back
		return env.client.SendResponse(ctx, &types.Response{
			CommandID: cmd.ID,
			StewardID: "steward-resp-test",
			Success:   true,
			Message:   "done",
			Timestamp: time.Now(),
		})
	})
	require.NoError(t, err)

	// Start waiting for response in background
	var resp *types.Response
	var respErr error
	done := make(chan struct{})
	go func() {
		resp, respErr = env.server.WaitForResponse(context.Background(), "cmd-resp-001", 5*time.Second)
		close(done)
	}()

	// Wait for the pending response channel to be registered before sending
	require.Eventually(t, func() bool {
		env.server.responseMu.Lock()
		_, ok := env.server.pendingResponses["cmd-resp-001"]
		env.server.responseMu.Unlock()
		return ok
	}, 5*time.Second, time.Millisecond)

	err = env.server.SendCommand(context.Background(), &types.Command{
		ID:        "cmd-resp-001",
		Type:      types.CommandSyncConfig,
		StewardID: "steward-resp-test",
		Timestamp: time.Now(),
	})
	require.NoError(t, err)

	select {
	case <-done:
		require.NoError(t, respErr)
		assert.Equal(t, "cmd-resp-001", resp.CommandID)
		assert.True(t, resp.Success)
		assert.Equal(t, "done", resp.Message)
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for response")
	}
}

func TestWaitForResponse_Timeout(t *testing.T) {
	env := newTestEnv(t, "steward-timeout-test")

	_, err := env.server.WaitForResponse(context.Background(), "nonexistent-cmd", 100*time.Millisecond)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "timeout")
}

func TestEventFilter(t *testing.T) {
	env := newTestEnv(t, "steward-filter-test")

	received := make(chan *types.Event, 10)

	// Subscribe with filter: only config_applied events
	err := env.server.SubscribeEvents(context.Background(), &types.EventFilter{
		EventTypes: []types.EventType{types.EventConfigApplied},
	}, func(ctx context.Context, event *types.Event) error {
		received <- event
		return nil
	})
	require.NoError(t, err)

	// Send an event that matches the filter
	err = env.client.PublishEvent(context.Background(), &types.Event{
		ID:        "evt-match",
		Type:      types.EventConfigApplied,
		StewardID: "steward-filter-test",
		Timestamp: time.Now(),
		Severity:  "info",
	})
	require.NoError(t, err)

	// Send an event that does NOT match the filter
	err = env.client.PublishEvent(context.Background(), &types.Event{
		ID:        "evt-nomatch",
		Type:      types.EventError,
		StewardID: "steward-filter-test",
		Timestamp: time.Now(),
		Severity:  "error",
	})
	require.NoError(t, err)

	// Should receive only the matching event
	select {
	case got := <-received:
		assert.Equal(t, "evt-match", got.ID)
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for filtered event")
	}

	// Verify the non-matching event does not arrive
	require.Never(t, func() bool {
		return len(received) > 0
	}, 200*time.Millisecond, 20*time.Millisecond, "non-matching event should not have been delivered")
}

func TestFanOutCommand(t *testing.T) {
	// Shared CA so all certs are mutually trusted
	tc := newTestCA(t)
	reg := registry.NewRegistry()

	server := New(ModeServer)
	err := server.Initialize(context.Background(), map[string]interface{}{
		"mode":       "server",
		"addr":       "127.0.0.1:0",
		"tls_config": tc.serverTLSConfig(t),
		"registry":   reg,
	})
	require.NoError(t, err)
	require.NoError(t, server.Start(context.Background()))
	t.Cleanup(func() { _ = server.Stop(context.Background()) })

	listenAddr := server.listener.Addr().String()

	// Connect two stewards
	received := make(map[string]chan *types.Command)
	stewardIDs := []string{"steward-fan-1", "steward-fan-2"}

	for _, id := range stewardIDs {
		client := New(ModeClient)
		err := client.Initialize(context.Background(), map[string]interface{}{
			"mode":       "client",
			"addr":       listenAddr,
			"tls_config": tc.clientTLSConfig(t, id),
			"steward_id": id,
		})
		require.NoError(t, err)
		require.NoError(t, client.Start(context.Background()))
		t.Cleanup(func() { _ = client.Stop(context.Background()) })

		ch := make(chan *types.Command, 1)
		received[id] = ch
		id := id
		require.NoError(t, client.SubscribeCommands(context.Background(), id, func(ctx context.Context, cmd *types.Command) error {
			received[id] <- cmd
			return nil
		}))
	}

	// Wait for both stewards to register
	require.Eventually(t, func() bool { return reg.Count() == 2 }, 5*time.Second, 10*time.Millisecond)

	cmd := &types.Command{
		ID:        "cmd-fan",
		Type:      types.CommandSyncDNA,
		Timestamp: time.Now(),
	}

	result, err := server.FanOutCommand(context.Background(), cmd, stewardIDs)
	require.NoError(t, err)
	assert.Len(t, result.Succeeded, 2)
	assert.Empty(t, result.Failed)

	// Both stewards should receive the command
	for _, id := range stewardIDs {
		select {
		case got := <-received[id]:
			assert.Equal(t, "cmd-fan", got.ID)
		case <-time.After(5 * time.Second):
			t.Fatalf("steward %s did not receive fan-out command", id)
		}
	}
}

func TestFanOutCommand_PartialFailure(t *testing.T) {
	env := newTestEnv(t, "steward-fan-partial")

	cmd := &types.Command{
		ID:        "cmd-partial",
		Type:      types.CommandSyncConfig,
		Timestamp: time.Now(),
	}

	// Fan-out to one connected and one disconnected steward
	result, err := env.server.FanOutCommand(context.Background(), cmd, []string{
		"steward-fan-partial",
		"steward-not-connected",
	})
	require.NoError(t, err)
	assert.Contains(t, result.Succeeded, "steward-fan-partial")
	assert.Contains(t, result.Failed, "steward-not-connected")
}

func TestDisconnectCleansUpRegistry(t *testing.T) {
	serverTLS, clientTLS := newTestTLSConfigs(t, "steward-disconnect")
	reg := registry.NewRegistry()

	server := New(ModeServer)
	err := server.Initialize(context.Background(), map[string]interface{}{
		"mode":       "server",
		"addr":       "127.0.0.1:0",
		"tls_config": serverTLS,
		"registry":   reg,
	})
	require.NoError(t, err)
	require.NoError(t, server.Start(context.Background()))
	t.Cleanup(func() { _ = server.Stop(context.Background()) })

	listenAddr := server.listener.Addr().String()

	client := New(ModeClient)
	err = client.Initialize(context.Background(), map[string]interface{}{
		"mode":       "client",
		"addr":       listenAddr,
		"tls_config": clientTLS,
		"steward_id": "steward-disconnect",
	})
	require.NoError(t, err)
	require.NoError(t, client.Start(context.Background()))

	// Wait for registration
	require.Eventually(t, func() bool {
		_, ok := reg.Get("steward-disconnect")
		return ok
	}, 5*time.Second, 10*time.Millisecond)

	// Disconnect the client
	_ = client.Stop(context.Background())

	// Steward should be unregistered
	require.Eventually(t, func() bool {
		_, ok := reg.Get("steward-disconnect")
		return !ok
	}, 5*time.Second, 10*time.Millisecond, "steward should be unregistered after disconnect")

	// SendCommand to the disconnected steward should return an error
	err = server.SendCommand(context.Background(), &types.Command{
		ID:        "cmd-after-disconnect",
		Type:      types.CommandSyncConfig,
		StewardID: "steward-disconnect",
		Timestamp: time.Now(),
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not connected")
}

func TestMultipleConcurrentStewards(t *testing.T) {
	tc := newTestCA(t)
	reg := registry.NewRegistry()

	server := New(ModeServer)
	err := server.Initialize(context.Background(), map[string]interface{}{
		"mode":       "server",
		"addr":       "127.0.0.1:0",
		"tls_config": tc.serverTLSConfig(t),
		"registry":   reg,
	})
	require.NoError(t, err)
	require.NoError(t, server.Start(context.Background()))
	t.Cleanup(func() { _ = server.Stop(context.Background()) })

	listenAddr := server.listener.Addr().String()

	const numStewards = 5

	// Pre-generate client TLS configs (cert generation is not goroutine-safe with testing.T)
	clientConfigs := make(map[string]*tls.Config, numStewards)
	for i := 0; i < numStewards; i++ {
		id := fmt.Sprintf("steward-%d", i)
		clientConfigs[id] = tc.clientTLSConfig(t, id)
	}

	// Create and initialize all clients on the main goroutine (safe for t.Cleanup),
	// then connect them concurrently.
	clients := make([]*Provider, numStewards)
	for i := 0; i < numStewards; i++ {
		id := fmt.Sprintf("steward-%d", i)
		client := New(ModeClient)
		err := client.Initialize(context.Background(), map[string]interface{}{
			"mode":       "client",
			"addr":       listenAddr,
			"tls_config": clientConfigs[id],
			"steward_id": id,
		})
		require.NoError(t, err)
		clients[i] = client
		t.Cleanup(func() { _ = client.Stop(context.Background()) })
	}

	var wg sync.WaitGroup
	for i := 0; i < numStewards; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			if err := clients[idx].Start(context.Background()); err != nil {
				t.Errorf("steward-%d start failed: %v", idx, err)
			}
		}(i)
	}

	wg.Wait()

	// All stewards should be registered
	require.Eventually(t, func() bool {
		return reg.Count() == numStewards
	}, 10*time.Second, 50*time.Millisecond, "all %d stewards should be registered", numStewards)
}

func TestStatsTracking(t *testing.T) {
	env := newTestEnv(t, "steward-stats-test")

	// Subscribe handlers
	require.NoError(t, env.server.SubscribeEvents(context.Background(), nil, func(ctx context.Context, event *types.Event) error {
		return nil
	}))
	require.NoError(t, env.server.SubscribeHeartbeats(context.Background(), func(ctx context.Context, hb *types.Heartbeat) error {
		return nil
	}))
	require.NoError(t, env.client.SubscribeCommands(context.Background(), "steward-stats-test", func(ctx context.Context, cmd *types.Command) error {
		return nil
	}))

	now := time.Now()

	// Send one of each message type
	require.NoError(t, env.server.SendCommand(context.Background(), &types.Command{
		ID: "cmd-stats", Type: types.CommandSyncConfig, StewardID: "steward-stats-test", Timestamp: now,
	}))
	require.NoError(t, env.client.PublishEvent(context.Background(), &types.Event{
		ID: "evt-stats", Type: types.EventConfigApplied, StewardID: "steward-stats-test", Timestamp: now, Severity: "info",
	}))
	require.NoError(t, env.client.SendHeartbeat(context.Background(), &types.Heartbeat{
		StewardID: "steward-stats-test", Status: types.StatusHealthy, Timestamp: now,
	}))

	// Poll until all stats are populated (async dispatch via goroutines)
	require.Eventually(t, func() bool {
		return env.server.eventsReceived.Load() >= 1 &&
			env.server.heartbeatsReceived.Load() >= 1 &&
			env.client.commandsReceived.Load() >= 1
	}, 5*time.Second, 10*time.Millisecond)

	// Check server stats
	serverStats, err := env.server.GetStats(context.Background())
	require.NoError(t, err)
	assert.Equal(t, int64(1), serverStats.CommandsSent)
	assert.Equal(t, int64(1), serverStats.EventsReceived)
	assert.Equal(t, int64(1), serverStats.HeartbeatsReceived)
	assert.Equal(t, int64(1), serverStats.ConnectedStewards)
	assert.Equal(t, int64(2), serverStats.ActiveSubscriptions) // 1 event + 1 heartbeat
	assert.True(t, serverStats.Uptime > 0)

	// Check client stats
	clientStats, err := env.client.GetStats(context.Background())
	require.NoError(t, err)
	assert.Equal(t, int64(1), clientStats.EventsPublished)
	assert.Equal(t, int64(1), clientStats.HeartbeatsSent)
	assert.Equal(t, int64(1), clientStats.CommandsReceived)
}

func TestProviderRegistration(t *testing.T) {
	provider := interfaces.GetProvider("grpc")
	require.NotNil(t, provider)
	assert.Equal(t, "grpc", provider.Name())
}

func TestAvailable(t *testing.T) {
	p := New(ModeServer)
	ok, err := p.Available()
	assert.False(t, ok)
	assert.Error(t, err)

	p.addr = ":50051"
	p.tlsConfig = &tls.Config{}
	ok, err = p.Available()
	assert.True(t, ok)
	assert.NoError(t, err)
}

func TestModeValidation(t *testing.T) {
	// Server-only methods fail in client mode
	client := New(ModeClient)
	client.stewardID = "test"
	client.addr = "localhost:50051"
	client.tlsConfig = &tls.Config{}

	err := client.SendCommand(context.Background(), &types.Command{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "server mode")

	_, err = client.FanOutCommand(context.Background(), &types.Command{}, []string{"a"})
	assert.Error(t, err)

	err = client.SubscribeEvents(context.Background(), nil, nil)
	assert.Error(t, err)

	err = client.SubscribeHeartbeats(context.Background(), nil)
	assert.Error(t, err)

	_, err = client.WaitForResponse(context.Background(), "x", time.Second)
	assert.Error(t, err)

	// Client-only methods fail in server mode
	server := New(ModeServer)
	server.addr = ":50051"
	server.tlsConfig = &tls.Config{}

	err = server.SubscribeCommands(context.Background(), "x", nil)
	assert.Error(t, err)

	err = server.PublishEvent(context.Background(), &types.Event{})
	assert.Error(t, err)

	err = server.SendHeartbeat(context.Background(), &types.Heartbeat{})
	assert.Error(t, err)

	err = server.SendResponse(context.Background(), &types.Response{})
	assert.Error(t, err)
}
