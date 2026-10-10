// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package grpc

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	cfgcert "github.com/cfgis/cfgms/pkg/cert"
	"github.com/cfgis/cfgms/pkg/controlplane/interfaces"
	"github.com/cfgis/cfgms/pkg/controlplane/types"
	quictransport "github.com/cfgis/cfgms/pkg/transport/quic"
	"github.com/cfgis/cfgms/pkg/transport/registry"
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
	t.Cleanup(server.ForceStop)

	// Get the actual listen address
	listenAddr := server.ListenAddr()

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

	received := make(chan *types.SignedCommand, 1)
	err := env.client.SubscribeCommands(context.Background(), "steward-cmd-test", func(ctx context.Context, sc *types.SignedCommand) error {
		received <- sc
		return nil
	})
	require.NoError(t, err)

	sc := &types.SignedCommand{
		Command: types.Command{
			ID:        "cmd-001",
			Type:      types.CommandSyncConfig,
			StewardID: "steward-cmd-test",
			Timestamp: time.Now().Truncate(time.Microsecond),
			Params:    map[string]interface{}{"version": "1.0"},
		},
	}

	err = env.server.SendCommand(context.Background(), sc)
	require.NoError(t, err)

	select {
	case got := <-received:
		assert.Equal(t, sc.Command.ID, got.Command.ID)
		assert.Equal(t, sc.Command.Type, got.Command.Type)
		assert.Equal(t, sc.Command.StewardID, got.Command.StewardID)
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
	t.Cleanup(server.ForceStop)

	listenAddr := server.ListenAddr()

	// Connect two stewards
	received := make(map[string]chan *types.SignedCommand)
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

		ch := make(chan *types.SignedCommand, 1)
		received[id] = ch
		id := id
		cmdCh := ch // capture for closure to avoid concurrent map read
		require.NoError(t, client.SubscribeCommands(context.Background(), id, func(ctx context.Context, sc *types.SignedCommand) error {
			cmdCh <- sc
			return nil
		}))
	}

	// Wait for both stewards to register
	require.Eventually(t, func() bool { return reg.Count() == 2 }, 5*time.Second, 10*time.Millisecond)

	sc := &types.SignedCommand{
		Command: types.Command{
			ID:        "cmd-fan",
			Type:      types.CommandSyncDNA,
			Timestamp: time.Now(),
		},
	}

	result, err := server.FanOutCommand(context.Background(), sc, stewardIDs)
	require.NoError(t, err)
	assert.Len(t, result.Succeeded, 2)
	assert.Empty(t, result.Failed)

	// Both stewards should receive the command
	for _, id := range stewardIDs {
		select {
		case got := <-received[id]:
			assert.Equal(t, "cmd-fan", got.Command.ID)
		case <-time.After(5 * time.Second):
			t.Fatalf("steward %s did not receive fan-out command", id)
		}
	}
}

func TestFanOutCommand_PartialFailure(t *testing.T) {
	env := newTestEnv(t, "steward-fan-partial")

	sc := &types.SignedCommand{
		Command: types.Command{
			ID:        "cmd-partial",
			Type:      types.CommandSyncConfig,
			Timestamp: time.Now(),
		},
	}

	// Fan-out to one connected and one disconnected steward
	result, err := env.server.FanOutCommand(context.Background(), sc, []string{
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
	t.Cleanup(server.ForceStop)

	listenAddr := server.ListenAddr()

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
	err = server.SendCommand(context.Background(), &types.SignedCommand{
		Command: types.Command{
			ID:        "cmd-after-disconnect",
			Type:      types.CommandSyncConfig,
			StewardID: "steward-disconnect",
			Timestamp: time.Now(),
		},
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
	t.Cleanup(server.ForceStop)

	listenAddr := server.ListenAddr()

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
	require.NoError(t, env.client.SubscribeCommands(context.Background(), "steward-stats-test", func(ctx context.Context, sc *types.SignedCommand) error {
		return nil
	}))

	now := time.Now()

	// Send one of each message type
	require.NoError(t, env.server.SendCommand(context.Background(), &types.SignedCommand{
		Command: types.Command{
			ID: "cmd-stats", Type: types.CommandSyncConfig, StewardID: "steward-stats-test", Timestamp: now,
		},
	}))
	require.NoError(t, env.client.PublishEvent(context.Background(), &types.Event{
		ID: "evt-stats", Type: types.EventConfigApplied, StewardID: "steward-stats-test", Timestamp: now, Severity: "info",
	}))
	require.NoError(t, env.client.SendHeartbeat(context.Background(), &types.Heartbeat{
		StewardID: "steward-stats-test", Status: types.StatusHealthy, Timestamp: now,
	}))

	// Poll until all stats are populated (async dispatch via goroutines)
	require.Eventually(t, func() bool {
		sStats, err := env.server.GetStats(context.Background())
		if err != nil {
			return false
		}
		cStats, err := env.client.GetStats(context.Background())
		if err != nil {
			return false
		}
		return sStats.EventsReceived >= 1 &&
			sStats.HeartbeatsReceived >= 1 &&
			cStats.CommandsReceived >= 1
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

func TestModeValidation(t *testing.T) {
	// Server-only methods fail in client mode
	client := New(ModeClient)
	require.NoError(t, client.Initialize(context.Background(), map[string]interface{}{
		"mode":       "client",
		"addr":       "localhost:50051",
		"tls_config": &tls.Config{MinVersion: tls.VersionTLS13},
		"steward_id": "test",
	}))

	err := client.SendCommand(context.Background(), &types.SignedCommand{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "server mode")

	_, err = client.FanOutCommand(context.Background(), &types.SignedCommand{}, []string{"a"})
	assert.Error(t, err)

	err = client.SubscribeEvents(context.Background(), nil, nil)
	assert.Error(t, err)

	err = client.SubscribeHeartbeats(context.Background(), nil)
	assert.Error(t, err)

	// Client-only methods fail in server mode
	server := New(ModeServer)
	require.NoError(t, server.Initialize(context.Background(), map[string]interface{}{
		"mode":       "server",
		"addr":       ":50051",
		"tls_config": &tls.Config{MinVersion: tls.VersionTLS13},
	}))

	err = server.SubscribeCommands(context.Background(), "x", nil)
	assert.Error(t, err)

	err = server.PublishEvent(context.Background(), &types.Event{})
	assert.Error(t, err)

	err = server.SendHeartbeat(context.Background(), &types.Heartbeat{})
	assert.Error(t, err)

	err = server.SendResponse(context.Background(), &types.Response{})
	assert.Error(t, err)
}

// reserveUnusedUDPAddr binds an ephemeral UDP port and immediately releases
// it, returning an address string that nothing is listening on. Used to
// force a client's initial dial (see Provider.dialInitial) into a real,
// non-simulated connection failure instead of racing a real listener.
func reserveUnusedUDPAddr(t *testing.T) string {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	require.NoError(t, err)
	addr := conn.LocalAddr().String()
	require.NoError(t, conn.Close())
	return addr
}

// TestClientStart_RetriesInitialDialUntilServerIsReady is a regression test
// for Issue #3849: TestStewardSendsHeartbeat_ControllerReceives failed on the
// macOS merge-queue leg because the client's initial ControlChannel dial
// (dialAndOpenStream, called once from startClient) is a fail-fast gRPC call
// with no retry -- a single attempt that hits gRPC-go's own internal connect
// ceiling under CPU contention surfaced immediately as a hard failure, even
// though the server was listening moments later. This test targets the peer
// directly: the client starts dialing an address with nothing listening on
// it at all, and the server only binds that exact address afterward. Before
// the fix (Provider.dialInitial retrying until p.ctx is done), client.Start
// would already have failed by the time the server came up.
func TestClientStart_RetriesInitialDialUntilServerIsReady(t *testing.T) {
	serverTLS, clientTLS := newTestTLSConfigs(t, "steward-late-server-test")
	addr := reserveUnusedUDPAddr(t)

	client := New(ModeClient)
	require.NoError(t, client.Initialize(context.Background(), map[string]interface{}{
		"mode":       "client",
		"addr":       addr,
		"tls_config": clientTLS,
		"steward_id": "steward-late-server-test",
	}))

	startErr := make(chan error, 1)
	go func() { startErr <- client.Start(context.Background()) }()
	t.Cleanup(func() { _ = client.Stop(context.Background()) })

	// Give the client's first dial attempt(s) time to fail against the
	// not-yet-bound address before the server binds it.
	time.Sleep(100 * time.Millisecond)

	reg := registry.NewRegistry()
	server := New(ModeServer)
	require.NoError(t, server.Initialize(context.Background(), map[string]interface{}{
		"mode":       "server",
		"addr":       addr,
		"tls_config": serverTLS,
		"registry":   reg,
	}))
	require.NoError(t, server.Start(context.Background()))
	t.Cleanup(server.ForceStop)

	select {
	case err := <-startErr:
		require.NoError(t, err, "client.Start should retry the initial dial until the server becomes reachable")
	case <-time.After(10 * time.Second):
		t.Fatal("client.Start did not succeed after the server became reachable")
	}

	require.Eventually(t, func() bool {
		_, ok := reg.Get("steward-late-server-test")
		return ok
	}, 5*time.Second, 10*time.Millisecond, "steward should be registered")
}

// TestClientStop_DuringInitialDialDoesNotDeadlock is a regression test for
// the concurrency hazard introduced alongside Provider.dialInitial (Issue
// #3849): since the initial dial now retries until p.ctx is done instead of
// failing after one attempt, startClient must not hold p.mu across that
// retry -- otherwise a concurrent Stop() can never acquire p.mu to reach
// p.cancel(), which is the only thing that can end the retry, and the two
// calls deadlock permanently instead of just running slowly.
func TestClientStop_DuringInitialDialDoesNotDeadlock(t *testing.T) {
	_, clientTLS := newTestTLSConfigs(t, "steward-stop-during-dial-test")
	addr := reserveUnusedUDPAddr(t)

	client := New(ModeClient)
	require.NoError(t, client.Initialize(context.Background(), map[string]interface{}{
		"mode":       "client",
		"addr":       addr,
		"tls_config": clientTLS,
		"steward_id": "steward-stop-during-dial-test",
	}))

	startErr := make(chan error, 1)
	go func() { startErr <- client.Start(context.Background()) }()

	// Give Start time to acquire p.mu, set p.cancel, and enter the retry loop.
	time.Sleep(50 * time.Millisecond)

	stopErr := make(chan error, 1)
	go func() { stopErr <- client.Stop(context.Background()) }()

	select {
	case err := <-stopErr:
		assert.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("client.Stop did not return -- startClient may be holding p.mu across the initial dial retry, deadlocking Stop's p.cancel() call")
	}

	select {
	case err := <-startErr:
		require.Error(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("client.Start did not return after Stop cancelled its context")
	}
}

// startAdmissionServer starts a server provider with the given approval checker
// (nil admits every steward) and returns its listen address.
func startAdmissionServer(t *testing.T, serverTLS *tls.Config, checker StewardApprovalChecker) string {
	t.Helper()
	var opts []option
	if checker != nil {
		opts = append(opts, WithApprovalChecker(checker))
	}
	server := New(ModeServer, opts...)
	require.NoError(t, server.Initialize(context.Background(), map[string]interface{}{
		"mode":       "server",
		"addr":       "127.0.0.1:0",
		"tls_config": serverTLS,
		"registry":   registry.NewRegistry(),
	}))
	require.NoError(t, server.Start(context.Background()))
	t.Cleanup(server.ForceStop)
	return server.ListenAddr()
}

// newAdmissionClient returns an initialized client provider with admission_window set.
func newAdmissionClient(t *testing.T, addr string, clientTLS *tls.Config, stewardID string) *Provider {
	t.Helper()
	client := New(ModeClient)
	require.NoError(t, client.Initialize(context.Background(), map[string]interface{}{
		"mode":             "client",
		"addr":             addr,
		"tls_config":       clientTLS,
		"steward_id":       stewardID,
		"admission_window": 5 * time.Second,
	}))
	t.Cleanup(func() { _ = client.Stop(context.Background()) })
	return client
}

// startWithin runs client.Start and returns its error, failing the test if it
// does not return within limit.
func startWithin(t *testing.T, client *Provider, limit time.Duration) error {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- client.Start(context.Background()) }()
	select {
	case err := <-done:
		return err
	case <-time.After(limit):
		t.Fatalf("client.Start did not return within %s", limit)
		return nil
	}
}

// TestClientStart_AdmissionWindow_UnreachableKeepsRetrying guards Issue #4532: a
// controller that is merely unreachable is never reported as an identity
// rejection — the initial connect keeps retrying, so a steward reconnecting with
// a stored identity never falls back to registration because of an outage.
func TestClientStart_AdmissionWindow_UnreachableKeepsRetrying(t *testing.T) {
	_, clientTLS := newTestTLSConfigs(t, "steward-unreachable-test")
	client := newAdmissionClient(t, reserveUnusedUDPAddr(t), clientTLS, "steward-unreachable-test")

	done := make(chan error, 1)
	go func() { done <- client.Start(context.Background()) }()
	select {
	case err := <-done:
		t.Fatalf("Start returned while nothing was listening: %v", err)
	case <-time.After(8 * time.Second):
	}

	require.NoError(t, client.Stop(context.Background()))
	select {
	case err := <-done:
		require.Error(t, err)
		assert.NotErrorIs(t, err, interfaces.ErrIdentityRejected, "an unreachable controller is not a rejection")
	case <-time.After(10 * time.Second):
		t.Fatal("Start did not return after Stop")
	}
}

// TestClientStart_AdmissionWindow_ApprovalRefusedIsIdentityRejected guards Issue
// #4532: the controller refusing the control channel (unknown, deregistered or
// revoked steward) is reported as ErrIdentityRejected rather than retried.
func TestClientStart_AdmissionWindow_ApprovalRefusedIsIdentityRejected(t *testing.T) {
	serverTLS, clientTLS := newTestTLSConfigs(t, "steward-refused-test")
	addr := startAdmissionServer(t, serverTLS, rejectAll{})
	client := newAdmissionClient(t, addr, clientTLS, "steward-refused-test")

	err := startWithin(t, client, 20*time.Second)
	require.ErrorIs(t, err, interfaces.ErrIdentityRejected)
	assert.False(t, client.IsConnected())
}

// assertKeepsRetrying starts client and asserts Start is still retrying after
// wait, then that stopping it returns an error that is not an identity rejection.
func assertKeepsRetrying(t *testing.T, client *Provider, wait time.Duration) {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- client.Start(context.Background()) }()
	select {
	case err := <-done:
		t.Fatalf("Start returned instead of retrying: %v", err)
	case <-time.After(wait):
	}
	require.NoError(t, client.Stop(context.Background()))
	select {
	case err := <-done:
		require.Error(t, err)
		assert.NotErrorIs(t, err, interfaces.ErrIdentityRejected)
	case <-time.After(10 * time.Second):
		t.Fatal("Start did not return after Stop")
	}
}

// TestClientStart_AdmissionWindow_ClientCertRejectedAtTLSKeepsRetrying guards the
// #4533 review: the controller rejecting the client certificate during the TLS
// handshake is retried, not treated as an identity rejection. Go's TLS server
// sends the same bad_certificate alert for a valid certificate it judges not yet
// valid or expired under a skewed clock, so the alert alone must never send a
// healthy steward to registration.
func TestClientStart_AdmissionWindow_ClientCertRejectedAtTLSKeepsRetrying(t *testing.T) {
	controllerCA := newTestCA(t)
	otherCA := newTestCA(t)
	clientTLS := otherCA.clientTLSConfig(t, "steward-foreign-cert-test")
	// Trust the controller's server certificate so only the client certificate fails.
	clientTLS.RootCAs = controllerCA.clientTLSConfig(t, "trust-only").RootCAs
	addr := startAdmissionServer(t, controllerCA.serverTLSConfig(t), nil)

	assertKeepsRetrying(t, newAdmissionClient(t, addr, clientTLS, "steward-foreign-cert-test"), 6*time.Second)
}

// TestClientStart_AdmissionWindow_UntrustedServerCertKeepsRetrying guards the #4533
// review: a server certificate the stored CA does not trust is retried — a
// TLS-intercepting proxy produces exactly this, and it must not cost a healthy
// steward its registration token.
func TestClientStart_AdmissionWindow_UntrustedServerCertKeepsRetrying(t *testing.T) {
	controllerCA := newTestCA(t)
	storedCA := newTestCA(t)
	addr := startAdmissionServer(t, controllerCA.serverTLSConfig(t), nil)

	assertKeepsRetrying(t, newAdmissionClient(t, addr, storedCA.clientTLSConfig(t, "steward-moved-test"), "steward-moved-test"), 6*time.Second)
}

// TestClientStart_AdmissionWindow_AdmittedConnects verifies an admitted identity
// connects normally with admission_window set and the session stays up.
func TestClientStart_AdmissionWindow_AdmittedConnects(t *testing.T) {
	serverTLS, clientTLS := newTestTLSConfigs(t, "steward-admitted-test")
	addr := startAdmissionServer(t, serverTLS, approveAll{})
	client := newAdmissionClient(t, addr, clientTLS, "steward-admitted-test")

	require.NoError(t, startWithin(t, client, 30*time.Second))
	assert.True(t, client.IsConnected())
}

// TestClientStart_NoAdmissionWindow_RefusalIsRetried pins the default: without
// admission_window, a refused control channel is not surfaced by Start (the
// fresh-registration connect keeps its existing retry behaviour).
func TestClientStart_NoAdmissionWindow_RefusalIsRetried(t *testing.T) {
	serverTLS, clientTLS := newTestTLSConfigs(t, "steward-default-refused-test")
	addr := startAdmissionServer(t, serverTLS, rejectAll{})
	client := New(ModeClient)
	require.NoError(t, client.Initialize(context.Background(), map[string]interface{}{
		"mode":       "client",
		"addr":       addr,
		"tls_config": clientTLS,
		"steward_id": "steward-default-refused-test",
	}))
	t.Cleanup(func() { _ = client.Stop(context.Background()) })
	assert.NoError(t, startWithin(t, client, 30*time.Second))
}

func TestIsIdentityRejection(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"permission denied", status.Error(codes.PermissionDenied, "steward reconnect not approved"), true},
		{"unauthenticated", status.Error(codes.Unauthenticated, "no peer info"), true},
		{"unavailable approval service", status.Error(codes.Unavailable, "steward approval service unavailable"), false},
		{"connection timeout", status.Error(codes.Unavailable, "connection error: desc = \"transport: Error while dialing: timeout: no recent network activity\""), false},
		{"wrapped permission denied", fmt.Errorf("failed to open ControlChannel: %w", status.Error(codes.PermissionDenied, "steward reconnect not approved")), true},
		{"bad certificate alert", status.Error(codes.Unavailable, "connection error: desc = \"transport: CRYPTO_ERROR 0x12a (remote): tls: bad certificate\""), false},
		{"expired certificate alert (clock skew)", status.Error(codes.Unavailable, "connection error: desc = \"transport: CRYPTO_ERROR 0x12d (remote): tls: expired certificate\""), false},
		{"unknown authority (intercepting proxy)", errors.New("tls: failed to verify certificate: x509: certificate signed by unknown authority"), false},
		{"context deadline", context.DeadlineExceeded, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, isIdentityRejection(tc.err))
		})
	}
}

func TestStewardSendsResponse_ControllerSubscriberReceives(t *testing.T) {
	env := newTestEnv(t, "steward-resp-test")

	received := make(chan *types.Response, 1)
	err := env.server.SubscribeResponses(context.Background(), func(ctx context.Context, resp *types.Response) error {
		received <- resp
		return nil
	})
	require.NoError(t, err)

	// StewardID left empty: the server stamps it from the authenticated CN.
	err = env.client.SendResponse(context.Background(), &types.Response{
		CommandID: "cmd-rejected-1",
		Success:   false,
		Message:   "term_fenced",
		Timestamp: time.Now(),
		Details:   map[string]interface{}{"reason": "term_fenced", "retryable": true},
	})
	require.NoError(t, err)

	select {
	case got := <-received:
		assert.Equal(t, "cmd-rejected-1", got.CommandID)
		assert.Equal(t, "steward-resp-test", got.StewardID)
		assert.False(t, got.Success)
		assert.Equal(t, "term_fenced", got.Details["reason"])
		assert.Equal(t, true, got.Details["retryable"], "retryable must round-trip as a bool")
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for response")
	}

	assert.Error(t, env.client.SubscribeResponses(context.Background(), func(context.Context, *types.Response) error { return nil }))
	assert.Error(t, env.server.SendResponse(context.Background(), &types.Response{CommandID: "x"}))
}
