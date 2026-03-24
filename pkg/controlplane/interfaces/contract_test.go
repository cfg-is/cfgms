// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz

// Package interfaces_test contains transport-agnostic contract tests for the
// ControlPlaneProvider interface.
//
// These tests validate that any ControlPlaneProvider implementation exhibits
// correct behavioral contracts: command delivery, event pub/sub, heartbeat
// delivery, request-response, fan-out, isolation, and security guarantees.
//
// # Usage by Provider Implementors
//
// To validate a new provider implementation, call RunCPContractTests from the
// new provider's test package:
//
//	func TestMyProvider_ContractSuite(t *testing.T) {
//		interfaces.RunCPContractTests(t, myProviderFactory)
//	}
//
// where myProviderFactory creates and connects a server + client pair.
package interfaces_test

import (
	"context"
	"crypto/tls"
	"sync"
	"testing"
	"time"

	cfgcert "github.com/cfgis/cfgms/pkg/cert"
	cpinterfaces "github.com/cfgis/cfgms/pkg/controlplane/interfaces"
	cpgrpc "github.com/cfgis/cfgms/pkg/controlplane/providers/grpc"
	cptypes "github.com/cfgis/cfgms/pkg/controlplane/types"
	quictransport "github.com/cfgis/cfgms/pkg/transport/quic"
	"github.com/cfgis/cfgms/pkg/transport/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// cpContractStewardIDs are the fixed steward IDs used by the contract test suite.
// Factories must create clients for each of these IDs.
var cpContractStewardIDs = []string{"contract-steward-0", "contract-steward-1"}

// CPProviderFactory creates a server ControlPlaneProvider and one client per
// steward ID in cpContractStewardIDs. All providers are fully started and the
// clients are connected before the factory returns.
//
// The cleanup function stops all providers and releases resources.
type CPProviderFactory func(t *testing.T) (
	server cpinterfaces.ControlPlaneProvider,
	clients map[string]cpinterfaces.ControlPlaneProvider,
	cleanup func(),
)

// RunCPContractTests runs the full ControlPlaneProvider contract test suite
// using the provided factory. Each contract is a subtest for granular reporting.
func RunCPContractTests(t *testing.T, factory CPProviderFactory) {
	t.Helper()

	t.Run("CommandDelivery", func(t *testing.T) {
		testCPCommandDelivery(t, factory)
	})
	t.Run("EventPubSub", func(t *testing.T) {
		testCPEventPubSub(t, factory)
	})
	t.Run("HeartbeatDelivery", func(t *testing.T) {
		testCPHeartbeatDelivery(t, factory)
	})
	t.Run("FanOutCommand", func(t *testing.T) {
		testCPFanOutCommand(t, factory)
	})
	t.Run("FanOutPartialFailure", func(t *testing.T) {
		testCPFanOutPartialFailure(t, factory)
	})
	t.Run("RequestResponse", func(t *testing.T) {
		testCPRequestResponse(t, factory)
	})
	t.Run("ResponseTimeout", func(t *testing.T) {
		testCPResponseTimeout(t, factory)
	})
	t.Run("ResponseContextCancellation", func(t *testing.T) {
		testCPResponseContextCancellation(t, factory)
	})
	t.Run("EventFilteringByType", func(t *testing.T) {
		testCPEventFilteringByType(t, factory)
	})
	t.Run("MultipleEventHandlers", func(t *testing.T) {
		testCPMultipleEventHandlers(t, factory)
	})
	t.Run("MultipleHeartbeatHandlers", func(t *testing.T) {
		testCPMultipleHeartbeatHandlers(t, factory)
	})
	t.Run("MultiTenantIsolation", func(t *testing.T) {
		testCPMultiTenantIsolation(t, factory)
	})
	t.Run("DisconnectCleanup", func(t *testing.T) {
		testCPDisconnectCleanup(t, factory)
	})
	t.Run("StatsTracking", func(t *testing.T) {
		testCPStatsTracking(t, factory)
	})
	t.Run("SendDuringDisconnection", func(t *testing.T) {
		testCPSendDuringDisconnection(t, factory)
	})
	t.Run("MalformedMessageHandling", func(t *testing.T) {
		testCPMalformedMessageHandling(t, factory)
	})
}

// --- Contract Implementations ---

// testCPCommandDelivery verifies server sends a command to a specific steward
// and that steward receives it with fields intact.
func testCPCommandDelivery(t *testing.T, factory CPProviderFactory) {
	t.Helper()
	server, clients, cleanup := factory(t)
	defer cleanup()

	ctx := context.Background()
	client := clients["contract-steward-0"]

	received := make(chan *cptypes.Command, 1)
	require.NoError(t, client.SubscribeCommands(ctx, "contract-steward-0", func(_ context.Context, cmd *cptypes.Command) error {
		received <- cmd
		return nil
	}))

	cmd := &cptypes.Command{
		ID:        "contract-cmd-delivery",
		Type:      cptypes.CommandSyncConfig,
		StewardID: "contract-steward-0",
		Timestamp: time.Now().Truncate(time.Microsecond),
		Priority:  2,
		Params:    map[string]interface{}{"version": "1.0"},
	}
	require.NoError(t, server.SendCommand(ctx, cmd))

	select {
	case got := <-received:
		assert.Equal(t, cmd.ID, got.ID)
		assert.Equal(t, cmd.Type, got.Type)
		assert.Equal(t, cmd.StewardID, got.StewardID)
		assert.Equal(t, cmd.Priority, got.Priority)
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for command delivery")
	}
}

// testCPEventPubSub verifies steward publishes an event and server receives it
// with correct fields.
func testCPEventPubSub(t *testing.T, factory CPProviderFactory) {
	t.Helper()
	server, clients, cleanup := factory(t)
	defer cleanup()

	ctx := context.Background()
	client := clients["contract-steward-0"]

	received := make(chan *cptypes.Event, 1)
	require.NoError(t, server.SubscribeEvents(ctx, nil, func(_ context.Context, event *cptypes.Event) error {
		received <- event
		return nil
	}))

	event := &cptypes.Event{
		ID:        "contract-evt-pubsub",
		Type:      cptypes.EventConfigApplied,
		StewardID: "contract-steward-0",
		Timestamp: time.Now().Truncate(time.Microsecond),
		Severity:  "info",
		Details:   map[string]interface{}{"modules": "3"},
	}
	require.NoError(t, client.PublishEvent(ctx, event))

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

// testCPHeartbeatDelivery verifies steward sends a heartbeat and server receives it.
func testCPHeartbeatDelivery(t *testing.T, factory CPProviderFactory) {
	t.Helper()
	server, clients, cleanup := factory(t)
	defer cleanup()

	ctx := context.Background()
	client := clients["contract-steward-0"]

	received := make(chan *cptypes.Heartbeat, 1)
	require.NoError(t, server.SubscribeHeartbeats(ctx, func(_ context.Context, hb *cptypes.Heartbeat) error {
		received <- hb
		return nil
	}))

	hb := &cptypes.Heartbeat{
		StewardID: "contract-steward-0",
		Status:    cptypes.StatusHealthy,
		Timestamp: time.Now().Truncate(time.Microsecond),
		Version:   "1.0.0",
	}
	require.NoError(t, client.SendHeartbeat(ctx, hb))

	select {
	case got := <-received:
		assert.Equal(t, hb.StewardID, got.StewardID)
		assert.Equal(t, hb.Status, got.Status)
		assert.Equal(t, hb.Version, got.Version)
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for heartbeat")
	}
}

// testCPFanOutCommand verifies server sends a command to all N stewards and
// all receive it.
func testCPFanOutCommand(t *testing.T, factory CPProviderFactory) {
	t.Helper()
	server, clients, cleanup := factory(t)
	defer cleanup()

	ctx := context.Background()

	received := make(map[string]chan *cptypes.Command)
	for _, id := range cpContractStewardIDs {
		id := id
		ch := make(chan *cptypes.Command, 1)
		received[id] = ch
		require.NoError(t, clients[id].SubscribeCommands(ctx, id, func(_ context.Context, cmd *cptypes.Command) error {
			ch <- cmd
			return nil
		}))
	}

	cmd := &cptypes.Command{
		ID:        "contract-cmd-fanout",
		Type:      cptypes.CommandSyncDNA,
		Timestamp: time.Now(),
	}
	result, err := server.FanOutCommand(ctx, cmd, cpContractStewardIDs)
	require.NoError(t, err)
	assert.Len(t, result.Succeeded, len(cpContractStewardIDs))
	assert.Empty(t, result.Failed)

	for _, id := range cpContractStewardIDs {
		select {
		case got := <-received[id]:
			assert.Equal(t, cmd.ID, got.ID)
		case <-time.After(5 * time.Second):
			t.Fatalf("steward %s did not receive fan-out command", id)
		}
	}
}

// testCPFanOutPartialFailure verifies FanOutCommand reports correct results
// when some stewards are connected and some are not.
func testCPFanOutPartialFailure(t *testing.T, factory CPProviderFactory) {
	t.Helper()
	server, _, cleanup := factory(t)
	defer cleanup()

	ctx := context.Background()

	cmd := &cptypes.Command{
		ID:        "contract-cmd-partial",
		Type:      cptypes.CommandSyncConfig,
		Timestamp: time.Now(),
	}

	// Fan-out to one connected steward and one that never connected
	result, err := server.FanOutCommand(ctx, cmd, []string{
		"contract-steward-0",
		"steward-never-connected",
	})
	require.NoError(t, err)
	assert.Contains(t, result.Succeeded, "contract-steward-0")
	assert.Contains(t, result.Failed, "steward-never-connected")
}

// testCPRequestResponse verifies server sends a command, steward responds,
// and server receives the response via WaitForResponse.
func testCPRequestResponse(t *testing.T, factory CPProviderFactory) {
	t.Helper()
	server, clients, cleanup := factory(t)
	defer cleanup()

	ctx := context.Background()
	client := clients["contract-steward-0"]

	// Subscribe to commands so the client can respond
	require.NoError(t, client.SubscribeCommands(ctx, "contract-steward-0", func(ctx context.Context, cmd *cptypes.Command) error {
		return client.SendResponse(ctx, &cptypes.Response{
			CommandID: cmd.ID,
			StewardID: "contract-steward-0",
			Success:   true,
			Message:   "ack",
			Timestamp: time.Now(),
		})
	}))

	var resp *cptypes.Response
	var respErr error
	done := make(chan struct{})

	go func() {
		resp, respErr = server.WaitForResponse(ctx, "contract-cmd-resp", 10*time.Second)
		close(done)
	}()

	// Give WaitForResponse time to register its pending channel
	time.Sleep(50 * time.Millisecond)

	require.NoError(t, server.SendCommand(ctx, &cptypes.Command{
		ID:        "contract-cmd-resp",
		Type:      cptypes.CommandSyncConfig,
		StewardID: "contract-steward-0",
		Timestamp: time.Now(),
	}))

	select {
	case <-done:
		require.NoError(t, respErr)
		require.NotNil(t, resp)
		assert.Equal(t, "contract-cmd-resp", resp.CommandID)
		assert.True(t, resp.Success)
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for request-response")
	}
}

// testCPResponseTimeout verifies WaitForResponse returns an error when no
// response arrives within the timeout.
func testCPResponseTimeout(t *testing.T, factory CPProviderFactory) {
	t.Helper()
	server, _, cleanup := factory(t)
	defer cleanup()

	_, err := server.WaitForResponse(context.Background(), "nonexistent-cmd", 100*time.Millisecond)
	require.Error(t, err)
	// The error should mention timeout or context — implementation defined, just verify non-nil
	assert.NotEmpty(t, err.Error())
}

// testCPResponseContextCancellation verifies WaitForResponse respects context
// cancellation.
func testCPResponseContextCancellation(t *testing.T, factory CPProviderFactory) {
	t.Helper()
	server, _, cleanup := factory(t)
	defer cleanup()

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() {
		_, err := server.WaitForResponse(ctx, "contract-cmd-ctx-cancel", 30*time.Second)
		done <- err
	}()

	// Give WaitForResponse time to register its pending channel
	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		require.Error(t, err)
	case <-time.After(3 * time.Second):
		t.Fatal("WaitForResponse did not respect context cancellation")
	}
}

// testCPEventFilteringByType verifies the server only delivers events that
// match the subscribed event type filter.
func testCPEventFilteringByType(t *testing.T, factory CPProviderFactory) {
	t.Helper()
	server, clients, cleanup := factory(t)
	defer cleanup()

	ctx := context.Background()
	client := clients["contract-steward-0"]

	received := make(chan *cptypes.Event, 5)
	require.NoError(t, server.SubscribeEvents(ctx, &cptypes.EventFilter{
		EventTypes: []cptypes.EventType{cptypes.EventConfigApplied},
	}, func(_ context.Context, event *cptypes.Event) error {
		received <- event
		return nil
	}))

	// Publish a matching event
	require.NoError(t, client.PublishEvent(ctx, &cptypes.Event{
		ID:        "contract-evt-match",
		Type:      cptypes.EventConfigApplied,
		StewardID: "contract-steward-0",
		Timestamp: time.Now(),
		Severity:  "info",
	}))

	// Publish a non-matching event
	require.NoError(t, client.PublishEvent(ctx, &cptypes.Event{
		ID:        "contract-evt-nomatch",
		Type:      cptypes.EventError,
		StewardID: "contract-steward-0",
		Timestamp: time.Now(),
		Severity:  "error",
	}))

	// Should receive only the matching event
	select {
	case got := <-received:
		assert.Equal(t, "contract-evt-match", got.ID)
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for filtered event")
	}

	// The non-matching event must not arrive
	require.Never(t, func() bool { return len(received) > 0 },
		200*time.Millisecond, 20*time.Millisecond,
		"non-matching event should not be delivered")
}

// testCPMultipleEventHandlers verifies that multiple SubscribeEvents calls all
// receive the same event.
func testCPMultipleEventHandlers(t *testing.T, factory CPProviderFactory) {
	t.Helper()
	server, clients, cleanup := factory(t)
	defer cleanup()

	ctx := context.Background()
	client := clients["contract-steward-0"]

	const numHandlers = 3
	channels := make([]chan *cptypes.Event, numHandlers)
	for i := range channels {
		ch := make(chan *cptypes.Event, 1)
		channels[i] = ch
		require.NoError(t, server.SubscribeEvents(ctx, nil, func(_ context.Context, event *cptypes.Event) error {
			select {
			case ch <- event:
			default:
			}
			return nil
		}))
	}

	event := &cptypes.Event{
		ID:        "contract-evt-multi-handler",
		Type:      cptypes.EventTaskCompleted,
		StewardID: "contract-steward-0",
		Timestamp: time.Now(),
		Severity:  "info",
	}
	require.NoError(t, client.PublishEvent(ctx, event))

	for i, ch := range channels {
		select {
		case got := <-ch:
			assert.Equal(t, event.ID, got.ID, "handler %d should receive event", i)
		case <-time.After(5 * time.Second):
			t.Fatalf("handler %d did not receive event", i)
		}
	}
}

// testCPMultipleHeartbeatHandlers verifies that multiple SubscribeHeartbeats
// calls all receive the same heartbeat.
func testCPMultipleHeartbeatHandlers(t *testing.T, factory CPProviderFactory) {
	t.Helper()
	server, clients, cleanup := factory(t)
	defer cleanup()

	ctx := context.Background()
	client := clients["contract-steward-0"]

	const numHandlers = 3
	channels := make([]chan *cptypes.Heartbeat, numHandlers)
	for i := range channels {
		ch := make(chan *cptypes.Heartbeat, 1)
		channels[i] = ch
		require.NoError(t, server.SubscribeHeartbeats(ctx, func(_ context.Context, hb *cptypes.Heartbeat) error {
			select {
			case ch <- hb:
			default:
			}
			return nil
		}))
	}

	hb := &cptypes.Heartbeat{
		StewardID: "contract-steward-0",
		Status:    cptypes.StatusHealthy,
		Timestamp: time.Now(),
		Version:   "2.0.0",
	}
	require.NoError(t, client.SendHeartbeat(ctx, hb))

	for i, ch := range channels {
		select {
		case got := <-ch:
			assert.Equal(t, hb.StewardID, got.StewardID, "handler %d should receive heartbeat", i)
		case <-time.After(5 * time.Second):
			t.Fatalf("handler %d did not receive heartbeat", i)
		}
	}
}

// testCPMultiTenantIsolation verifies that a command sent to steward A is not
// delivered to steward B.
func testCPMultiTenantIsolation(t *testing.T, factory CPProviderFactory) {
	t.Helper()
	server, clients, cleanup := factory(t)
	defer cleanup()

	ctx := context.Background()

	receivedA := make(chan *cptypes.Command, 1)
	receivedB := make(chan *cptypes.Command, 1)

	require.NoError(t, clients["contract-steward-0"].SubscribeCommands(ctx, "contract-steward-0",
		func(_ context.Context, cmd *cptypes.Command) error {
			receivedA <- cmd
			return nil
		}))
	require.NoError(t, clients["contract-steward-1"].SubscribeCommands(ctx, "contract-steward-1",
		func(_ context.Context, cmd *cptypes.Command) error {
			receivedB <- cmd
			return nil
		}))

	// Send command only to steward-0
	require.NoError(t, server.SendCommand(ctx, &cptypes.Command{
		ID:        "contract-cmd-isolation",
		Type:      cptypes.CommandSyncConfig,
		StewardID: "contract-steward-0",
		Timestamp: time.Now(),
	}))

	// steward-0 must receive
	select {
	case got := <-receivedA:
		assert.Equal(t, "contract-cmd-isolation", got.ID)
	case <-time.After(5 * time.Second):
		t.Fatal("steward-0 did not receive its command")
	}

	// steward-1 must NOT receive
	require.Never(t, func() bool { return len(receivedB) > 0 },
		200*time.Millisecond, 20*time.Millisecond,
		"steward-1 should not receive command addressed to steward-0")
}

// testCPDisconnectCleanup verifies that after a client disconnects, the server
// correctly reflects the disconnection (SendCommand returns an error).
func testCPDisconnectCleanup(t *testing.T, factory CPProviderFactory) {
	t.Helper()
	server, clients, cleanup := factory(t)
	defer cleanup()

	ctx := context.Background()

	// Verify initial connectivity
	require.True(t, clients["contract-steward-0"].IsConnected())

	// Disconnect the client
	require.NoError(t, clients["contract-steward-0"].Stop(ctx))

	// Server should eventually reflect disconnection
	require.Eventually(t, func() bool {
		err := server.SendCommand(ctx, &cptypes.Command{
			ID:        "contract-cmd-after-disconnect",
			Type:      cptypes.CommandSyncConfig,
			StewardID: "contract-steward-0",
			Timestamp: time.Now(),
		})
		return err != nil
	}, 5*time.Second, 50*time.Millisecond,
		"server should report error sending to disconnected steward")
}

// testCPStatsTracking verifies that provider stats counters increment correctly
// after sending commands, events, and heartbeats.
func testCPStatsTracking(t *testing.T, factory CPProviderFactory) {
	t.Helper()
	server, clients, cleanup := factory(t)
	defer cleanup()

	ctx := context.Background()
	client := clients["contract-steward-0"]

	// Register handlers so dispatched messages are counted
	require.NoError(t, server.SubscribeEvents(ctx, nil, func(_ context.Context, _ *cptypes.Event) error { return nil }))
	require.NoError(t, server.SubscribeHeartbeats(ctx, func(_ context.Context, _ *cptypes.Heartbeat) error { return nil }))
	require.NoError(t, client.SubscribeCommands(ctx, "contract-steward-0", func(_ context.Context, _ *cptypes.Command) error { return nil }))

	now := time.Now()

	require.NoError(t, server.SendCommand(ctx, &cptypes.Command{
		ID:        "contract-cmd-stats",
		Type:      cptypes.CommandSyncConfig,
		StewardID: "contract-steward-0",
		Timestamp: now,
	}))
	require.NoError(t, client.PublishEvent(ctx, &cptypes.Event{
		ID:        "contract-evt-stats",
		Type:      cptypes.EventConfigApplied,
		StewardID: "contract-steward-0",
		Timestamp: now,
		Severity:  "info",
	}))
	require.NoError(t, client.SendHeartbeat(ctx, &cptypes.Heartbeat{
		StewardID: "contract-steward-0",
		Status:    cptypes.StatusHealthy,
		Timestamp: now,
	}))

	// Wait until stats are updated (async handler dispatch)
	require.Eventually(t, func() bool {
		sStats, err := server.GetStats(ctx)
		if err != nil {
			return false
		}
		cStats, err := client.GetStats(ctx)
		if err != nil {
			return false
		}
		return sStats.CommandsSent >= 1 &&
			sStats.EventsReceived >= 1 &&
			sStats.HeartbeatsReceived >= 1 &&
			cStats.CommandsReceived >= 1 &&
			cStats.EventsPublished >= 1 &&
			cStats.HeartbeatsSent >= 1
	}, 5*time.Second, 10*time.Millisecond, "stats counters should increment")

	serverStats, err := server.GetStats(ctx)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, serverStats.CommandsSent, int64(1))
	assert.GreaterOrEqual(t, serverStats.EventsReceived, int64(1))
	assert.GreaterOrEqual(t, serverStats.HeartbeatsReceived, int64(1))

	clientStats, err := client.GetStats(ctx)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, clientStats.CommandsReceived, int64(1))
	assert.GreaterOrEqual(t, clientStats.EventsPublished, int64(1))
	assert.GreaterOrEqual(t, clientStats.HeartbeatsSent, int64(1))
}

// testCPSendDuringDisconnection verifies that client-side send methods return
// errors when the client is not connected. The test stops the client cleanly
// and verifies sends fail immediately (rather than killing the server, which
// would require force-stop to avoid GracefulStop hanging on long-lived streams).
func testCPSendDuringDisconnection(t *testing.T, factory CPProviderFactory) {
	t.Helper()
	_, clients, cleanup := factory(t)
	defer cleanup()

	ctx := context.Background()
	client := clients["contract-steward-0"]

	// Stop the client to enter StateDisconnected
	require.NoError(t, client.Stop(ctx))

	// Client must not be connected after Stop
	assert.False(t, client.IsConnected(), "client should not be connected after Stop")

	// All send methods must return errors when disconnected
	err := client.PublishEvent(ctx, &cptypes.Event{
		ID:        "evt-during-disconnect",
		Type:      cptypes.EventError,
		StewardID: "contract-steward-0",
		Timestamp: time.Now(),
		Severity:  "error",
	})
	require.Error(t, err, "PublishEvent must fail when disconnected")

	err = client.SendHeartbeat(ctx, &cptypes.Heartbeat{
		StewardID: "contract-steward-0",
		Status:    cptypes.StatusDisconnected,
		Timestamp: time.Now(),
	})
	require.Error(t, err, "SendHeartbeat must fail when disconnected")

	err = client.SendResponse(ctx, &cptypes.Response{
		CommandID: "cmd-1",
		StewardID: "contract-steward-0",
		Timestamp: time.Now(),
	})
	require.Error(t, err, "SendResponse must fail when disconnected")
}

// testCPMalformedMessageHandling verifies the provider does not panic when
// receiving nil or zero-value messages.
func testCPMalformedMessageHandling(t *testing.T, factory CPProviderFactory) {
	t.Helper()
	server, clients, cleanup := factory(t)
	defer cleanup()

	ctx := context.Background()
	client := clients["contract-steward-0"]

	// nil messages — must not panic (may return error or no-op)
	assert.NotPanics(t, func() {
		_ = server.SendCommand(ctx, nil)
	}, "SendCommand with nil command must not panic")

	assert.NotPanics(t, func() {
		_ = client.PublishEvent(ctx, nil)
	}, "PublishEvent with nil event must not panic")

	assert.NotPanics(t, func() {
		_ = client.SendHeartbeat(ctx, nil)
	}, "SendHeartbeat with nil heartbeat must not panic")

	assert.NotPanics(t, func() {
		_ = client.SendResponse(ctx, nil)
	}, "SendResponse with nil response must not panic")
}

// =============================================================================
// gRPC Default Factory
// =============================================================================

// contractTestCA wraps a cfgcert.CA to build TLS configs for contract tests.
type cpContractTestCA struct {
	ca    *cfgcert.CA
	caPEM []byte
}

// newCPContractTestCA creates a fresh CA for use in contract tests.
func newCPContractTestCA(t *testing.T) *cpContractTestCA {
	t.Helper()
	ca, err := cfgcert.NewCA(&cfgcert.CAConfig{
		Organization: "CFGMS Contract Test",
		Country:      "US",
		ValidityDays: 1,
		KeySize:      2048,
	})
	require.NoError(t, err)
	require.NoError(t, ca.Initialize(nil))

	caPEM, err := ca.GetCACertificate()
	require.NoError(t, err)

	return &cpContractTestCA{ca: ca, caPEM: caPEM}
}

// serverTLSConfig returns a server TLS config signed by this CA.
func (tc *cpContractTestCA) serverTLSConfig(t *testing.T) *tls.Config {
	t.Helper()
	cert, err := tc.ca.GenerateServerCertificate(&cfgcert.ServerCertConfig{
		CommonName:   "localhost",
		DNSNames:     []string{"localhost"},
		ValidityDays: 1,
		KeySize:      2048,
	})
	require.NoError(t, err)

	cfg, err := cfgcert.CreateServerTLSConfig(
		cert.CertificatePEM, cert.PrivateKeyPEM,
		tc.caPEM, tls.VersionTLS13,
	)
	require.NoError(t, err)
	cfg.NextProtos = []string{quictransport.ALPNProtocol}
	return cfg
}

// clientTLSConfig returns a client TLS config with the given steward ID as CN.
func (tc *cpContractTestCA) clientTLSConfig(t *testing.T, stewardID string) *tls.Config {
	t.Helper()
	cert, err := tc.ca.GenerateClientCertificate(&cfgcert.ClientCertConfig{
		CommonName:   stewardID,
		ValidityDays: 1,
		KeySize:      2048,
	})
	require.NoError(t, err)

	cfg, err := cfgcert.CreateClientTLSConfig(
		cert.CertificatePEM, cert.PrivateKeyPEM,
		tc.caPEM, "localhost", tls.VersionTLS13,
	)
	require.NoError(t, err)
	cfg.NextProtos = []string{quictransport.ALPNProtocol}
	return cfg
}

// grpcCPFactory is the default CPProviderFactory for the contract test suite.
// It creates a gRPC-over-QUIC server and one client per steward ID in
// cpContractStewardIDs, all connected with real mTLS.
func grpcCPFactory(t *testing.T) (cpinterfaces.ControlPlaneProvider, map[string]cpinterfaces.ControlPlaneProvider, func()) {
	t.Helper()

	tc := newCPContractTestCA(t)
	reg := registry.NewRegistry()
	ctx := context.Background()

	// Start server
	server := cpgrpc.New(cpgrpc.ModeServer)
	require.NoError(t, server.Initialize(ctx, map[string]interface{}{
		"mode":       "server",
		"addr":       "127.0.0.1:0",
		"tls_config": tc.serverTLSConfig(t),
		"registry":   reg,
	}))
	require.NoError(t, server.Start(ctx))

	listenAddr := server.ListenAddr()
	require.NotEmpty(t, listenAddr, "server listen address must be set after Start")

	// Start clients
	clients := make(map[string]cpinterfaces.ControlPlaneProvider, len(cpContractStewardIDs))
	concreteClients := make([]*cpgrpc.Provider, 0, len(cpContractStewardIDs))

	for _, id := range cpContractStewardIDs {
		id := id
		client := cpgrpc.New(cpgrpc.ModeClient)
		require.NoError(t, client.Initialize(ctx, map[string]interface{}{
			"mode":       "client",
			"addr":       listenAddr,
			"tls_config": tc.clientTLSConfig(t, id),
			"steward_id": id,
		}))
		require.NoError(t, client.Start(ctx))
		clients[id] = client
		concreteClients = append(concreteClients, client)
	}

	// Wait for all stewards to appear in the registry
	require.Eventually(t, func() bool {
		return reg.Count() == len(cpContractStewardIDs)
	}, 10*time.Second, 10*time.Millisecond, "all stewards should register")

	cleanup := func() {
		// Stop clients first so their control streams are closed
		var wg sync.WaitGroup
		for _, c := range concreteClients {
			wg.Add(1)
			go func(p *cpgrpc.Provider) {
				defer wg.Done()
				_ = p.Stop(ctx)
			}(c)
		}
		wg.Wait()
		// Force-stop the server: GracefulStop() blocks indefinitely on
		// long-lived ControlChannel streams even after clients disconnect.
		server.ForceStop()
	}

	return server, clients, cleanup
}

// =============================================================================
// Top-level test: run full suite against gRPC provider
// =============================================================================

// TestCP_GRPCContractSuite runs all ControlPlaneProvider contract tests against
// the gRPC-over-QUIC provider implementation.
func TestCP_GRPCContractSuite(t *testing.T) {
	RunCPContractTests(t, grpcCPFactory)
}
