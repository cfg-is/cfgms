// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package grpc

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cfgis/cfgms/pkg/controlplane/types"
	"github.com/cfgis/cfgms/pkg/logging"
	pkgtesting "github.com/cfgis/cfgms/pkg/testing"
	quictransport "github.com/cfgis/cfgms/pkg/transport/quic"
	"github.com/cfgis/cfgms/pkg/transport/registry"
	quicgo "github.com/quic-go/quic-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
)

// TestControlPlaneProvider_Start_server_logsStarted verifies that a Provider in
// server mode with an injected logging.Logger emits at least one info log during
// Initialize + Start.
func TestControlPlaneProvider_Start_server_logsStarted(t *testing.T) {
	grpcServer := grpc.NewServer(grpc.Creds(quictransport.TransportCredentials()))
	mockLog := pkgtesting.NewMockLogger(true)

	p := New(ModeServer)
	require.NoError(t, p.Initialize(context.Background(), map[string]interface{}{
		"mode":        "server",
		"grpc_server": grpcServer,
		"logger":      mockLog,
	}))
	require.NoError(t, p.Start(context.Background()))
	defer func() { _ = p.Stop(context.Background()) }()

	assert.NotEmpty(t, mockLog.GetLogs("info"), "expected at least one info log when server starts")
}

// TestControlPlaneProvider_Registry_HonorsInjectedRegistry verifies that a
// server-mode provider uses the registry passed via the "registry" Initialize
// config key, and that a re-Initialize (as the controller performs in Start()
// to swap in the shared gRPC server) keeps that same instance when the key is
// supplied again. Regression guard for Issue #1572: the controller must be
// able to share one registry between the CP provider and the HTTP API server.
func TestControlPlaneProvider_Registry_HonorsInjectedRegistry(t *testing.T) {
	reg := registry.NewRegistry()

	p := New(ModeServer)
	require.NoError(t, p.Initialize(context.Background(), map[string]interface{}{
		"mode":        "server",
		"grpc_server": grpc.NewServer(grpc.Creds(quictransport.TransportCredentials())),
		"registry":    reg,
	}))
	assert.Same(t, reg, p.Registry(), "provider must use the injected registry")

	// Re-Initialize with the same registry key — mirrors controller Start().
	require.NoError(t, p.Initialize(context.Background(), map[string]interface{}{
		"mode":        "server",
		"grpc_server": grpc.NewServer(grpc.Creds(quictransport.TransportCredentials())),
		"registry":    reg,
	}))
	assert.Same(t, reg, p.Registry(), "re-Initialize with the registry key must preserve the instance")
}

// TestControlPlaneProvider_Registry_AutoCreatesWhenAbsent verifies that a
// server-mode provider auto-creates a registry when none is injected, so the
// ControlChannel handler always has somewhere to register connections.
func TestControlPlaneProvider_Registry_AutoCreatesWhenAbsent(t *testing.T) {
	p := New(ModeServer)
	require.NoError(t, p.Initialize(context.Background(), map[string]interface{}{
		"mode":        "server",
		"grpc_server": grpc.NewServer(grpc.Creds(quictransport.TransportCredentials())),
	}))
	assert.NotNil(t, p.Registry(), "provider must auto-create a registry when none is injected")
}

// TestControlPlaneProvider_reconnectLoop_logsWarning verifies that the reconnect loop
// emits a warn log when a reconnection attempt fails after the server goes away.
func TestControlPlaneProvider_reconnectLoop_logsWarning(t *testing.T) {
	tc := newTestCA(t)
	reg := registry.NewRegistry()
	const stewardID = "steward-reconnect-warn-test"

	server := New(ModeServer)
	require.NoError(t, server.Initialize(context.Background(), map[string]interface{}{
		"mode":       "server",
		"addr":       "127.0.0.1:0",
		"tls_config": tc.serverTLSConfig(t),
		"registry":   reg,
	}))
	require.NoError(t, server.Start(context.Background()))

	serverAddr := server.ListenAddr()
	mockLog := pkgtesting.NewMockLogger(true)

	client := New(ModeClient,
		withBackoff(&backoff{initial: 50 * time.Millisecond, max: 200 * time.Millisecond, multiplier: 2.0, jitter: 0.1}),
		withQUICConfig(&quicgo.Config{MaxIdleTimeout: 3 * time.Second, KeepAlivePeriod: 200 * time.Millisecond}),
	)
	require.NoError(t, client.Initialize(context.Background(), map[string]interface{}{
		"mode":       "client",
		"addr":       serverAddr,
		"tls_config": tc.clientTLSConfig(t, stewardID),
		"steward_id": stewardID,
		"logger":     mockLog,
	}))
	require.NoError(t, client.Start(context.Background()))
	t.Cleanup(func() { _ = client.Stop(context.Background()) })

	// Wait for the steward to appear in the registry before killing the server.
	require.Eventually(t, func() bool {
		_, ok := reg.Get(stewardID)
		return ok
	}, 5*time.Second, 10*time.Millisecond, "steward should be registered before server is killed")

	// Kill the server to trigger the reconnect loop on the client side.
	server.ForceStop()

	// The reconnect loop will fail to reconnect (server is gone) and emit a warn log.
	require.Eventually(t, func() bool {
		return len(mockLog.GetLogs("warn")) > 0
	}, 10*time.Second, 50*time.Millisecond, "expected at least one warn log from reconnect loop")
}

// verbatimLogger writes each Error call's message and key/value pairs verbatim
// (no quoting) so a raw control character splits the record across lines.
type verbatimLogger struct {
	logging.Logger
	mu      sync.Mutex
	records []string
}

func (l *verbatimLogger) Warn(msg string, kv ...interface{}) { l.Error(msg, kv...) }

func (l *verbatimLogger) Error(msg string, kv ...interface{}) {
	var sb strings.Builder
	sb.WriteString("msg=" + msg)
	for i := 0; i+1 < len(kv); i += 2 {
		fmt.Fprintf(&sb, " %v=%v", kv[i], kv[i+1])
	}
	l.mu.Lock()
	l.records = append(l.records, sb.String())
	l.mu.Unlock()
}

func (l *verbatimLogger) snapshot() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.records...)
}

// TestDispatchEvent_HandlerErrorLogNeutralizesControlCharacters verifies that a
// steward-supplied event ID and a handler error carrying a newline cannot
// split the "event handler error" log record (Issue #5079).
func TestDispatchEvent_HandlerErrorLogNeutralizesControlCharacters(t *testing.T) {
	vl := &verbatimLogger{Logger: logging.NewNoopLogger()}
	p := New(ModeServer)
	require.NoError(t, p.Initialize(context.Background(), map[string]interface{}{
		"mode":        "server",
		"grpc_server": grpc.NewServer(grpc.Creds(quictransport.TransportCredentials())),
		"logger":      vl,
	}))
	require.NoError(t, p.Start(context.Background()))
	defer func() { _ = p.Stop(context.Background()) }()

	require.NoError(t, p.SubscribeEvents(context.Background(), nil,
		func(context.Context, *types.Event) error {
			return errors.New("handler failed\nforged=1")
		}))

	p.dispatchEvent(&types.Event{ID: "evt\nforged=1"}, nil)

	require.Eventually(t, func() bool {
		for _, r := range vl.snapshot() {
			if strings.HasPrefix(r, "msg=event handler error") {
				return true
			}
		}
		return false
	}, 2*time.Second, 10*time.Millisecond)
	for _, r := range vl.snapshot() {
		if strings.HasPrefix(r, "msg=event handler error") {
			assert.NotContains(t, r, "\n")
			assert.NotContains(t, r, "\r")
		}
	}
}

func sendTestResponses(t *testing.T, c *Provider, stewardID string, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		require.NoError(t, c.SendResponse(context.Background(), &types.Response{
			CommandID: fmt.Sprintf("cmd-%d", i), StewardID: stewardID,
			Success: false, Timestamp: time.Now().Truncate(time.Microsecond),
		}))
	}
}

// TestControlChannel_Response_FloodDoesNotStallReceiveLoop: a blocked response
// handler holds at most maxInFlightResponsesPerStream responses; the rest are
// dropped and counted, and a following heartbeat is still dispatched.
func TestControlChannel_Response_FloodDoesNotStallReceiveLoop(t *testing.T) {
	t.Parallel()
	env := newAdmissionEnv(t)
	probe := newConcurrencyProbe()
	released := false
	releaseProbe := func() {
		if !released {
			released = true
			close(probe.release)
		}
	}
	t.Cleanup(releaseProbe)
	require.NoError(t, env.server.SubscribeResponses(context.Background(), func(context.Context, *types.Response) error {
		probe.enter()
		return nil
	}))
	beats := make(chan *types.Heartbeat, 4)
	require.NoError(t, env.server.SubscribeHeartbeats(context.Background(), func(_ context.Context, hb *types.Heartbeat) error {
		beats <- hb
		return nil
	}))

	const extra = 12
	sendTestResponses(t, env.clientA, "steward-adm-a", maxInFlightResponsesPerStream+extra)

	require.Eventually(t, func() bool { return env.stats(t).ResponsesDropped >= extra },
		5*time.Second, 10*time.Millisecond, "responses past the stream cap must be dropped")
	require.Eventually(t, func() bool { return probe.started.Load() >= maxInFlightResponsesPerStream },
		5*time.Second, 10*time.Millisecond)

	require.NoError(t, env.clientA.SendHeartbeat(context.Background(), testHeartbeat("steward-adm-a", admissionTenantA)))
	select {
	case got := <-beats:
		assert.Equal(t, "steward-adm-a", got.StewardID)
	case <-time.After(5 * time.Second):
		t.Fatal("receive loop stalled behind blocked response handlers")
	}
	assert.EqualValues(t, maxInFlightResponsesPerStream, probe.max.Load(), "concurrency must never exceed the stream cap")
	assert.EqualValues(t, extra, env.stats(t).ResponsesDropped)
	assert.EqualValues(t, maxInFlightResponsesPerStream+extra, env.stats(t).ResponsesReceived)
}

// TestControlChannel_Response_AdmittedDeliveredExactlyOnce: once the handler is
// released every admitted response was delivered once and all slots are free.
func TestControlChannel_Response_AdmittedDeliveredExactlyOnce(t *testing.T) {
	t.Parallel()
	env := newAdmissionEnv(t)
	probe := newConcurrencyProbe()
	var mu sync.Mutex
	seen := map[string]int{}
	require.NoError(t, env.server.SubscribeResponses(context.Background(), func(_ context.Context, r *types.Response) error {
		probe.enter()
		mu.Lock()
		seen[r.CommandID]++
		mu.Unlock()
		return nil
	}))

	sendTestResponses(t, env.clientA, "steward-adm-a", maxInFlightResponsesPerStream)
	require.Eventually(t, func() bool { return probe.cur.Load() == maxInFlightResponsesPerStream },
		5*time.Second, 10*time.Millisecond)
	close(probe.release)
	require.Eventually(t, func() bool { return probe.cur.Load() == 0 }, 5*time.Second, 10*time.Millisecond)
	require.Eventually(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(seen) == maxInFlightResponsesPerStream
	}, 5*time.Second, 10*time.Millisecond)

	mu.Lock()
	for id, n := range seen {
		assert.Equal(t, 1, n, "response %s must be delivered exactly once", id)
	}
	mu.Unlock()
	assert.EqualValues(t, 0, env.stats(t).ResponsesDropped)
	requireTenantSlotsFree(t, env.responseQueue, admissionTenantA, "response slots must be released after handlers return")
}

// TestControlChannel_Heartbeat_TamperAlarmAboutAnotherSteward_Rejected: a steward
// can raise a tamper alarm only about itself. A heartbeat that carries a tamper code
// but names another steward is rejected and counted, so nothing reaches the
// subscriber that would move that other steward to tampered (Issue #5652). A tamper
// heartbeat from the authenticated steward itself is delivered.
func TestControlChannel_Heartbeat_TamperAlarmAboutAnotherSteward_Rejected(t *testing.T) {
	t.Parallel()
	env := newMultiStewardEnv(t)

	dispatched := make(chan *types.Heartbeat, 5)
	require.NoError(t, env.server.SubscribeHeartbeats(context.Background(), func(_ context.Context, hb *types.Heartbeat) error {
		dispatched <- hb
		return nil
	}))
	tamper := []types.HealthReason{{Component: "integrity", Code: types.ReasonCodeTamperDataDir}}

	// steward-a's certificate, steward-b's ID.
	require.NoError(t, env.clientA.SendHeartbeat(context.Background(), &types.Heartbeat{
		StewardID: "steward-b",
		Status:    types.StatusError,
		Timestamp: time.Now().Truncate(time.Microsecond),
		Reasons:   tamper,
	}))
	require.Never(t, func() bool { return len(dispatched) > 0 },
		300*time.Millisecond, 20*time.Millisecond, "a tamper alarm naming another steward must not be dispatched")
	require.Eventually(t, func() bool {
		stats, err := env.server.GetStats(context.Background())
		return err == nil && stats.IdentityMismatches == 1
	}, 3*time.Second, 50*time.Millisecond, "the cross-steward alarm must be counted as an identity mismatch")

	// The same alarm about itself is delivered, bound to the authenticated ID.
	require.NoError(t, env.clientA.SendHeartbeat(context.Background(), &types.Heartbeat{
		StewardID: "steward-a",
		Status:    types.StatusError,
		Timestamp: time.Now().Truncate(time.Microsecond),
		Reasons:   tamper,
	}))
	select {
	case got := <-dispatched:
		assert.Equal(t, "steward-a", got.StewardID)
		require.Len(t, got.Reasons, 1)
		assert.True(t, types.IsTamperCode(got.Reasons[0].Code))
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for the steward's own tamper heartbeat")
	}
}
