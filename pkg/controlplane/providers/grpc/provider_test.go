// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package grpc

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	transportpb "github.com/cfgis/cfgms/api/proto/transport"
	"github.com/cfgis/cfgms/pkg/controlplane/types"
	"github.com/cfgis/cfgms/pkg/logging"
	pkgtesting "github.com/cfgis/cfgms/pkg/testing"
	quictransport "github.com/cfgis/cfgms/pkg/transport/quic"
	"github.com/cfgis/cfgms/pkg/transport/registry"
	quicgo "github.com/quic-go/quic-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/encoding/protowire"
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

// --- Capability declaration on the control channel ---

// capEvent is one call a capRecorder received.
type capEvent struct {
	kind         string // "reset" or "declare"
	connectionID string
	state        string
	profile      types.CapabilityProfile
}

// capRecorder is a CapabilityRecorder that records its calls in order. resetDelay
// holds the reset open, resetErr fails it, and declareGate (when set) holds every
// durable write until it is closed.
type capRecorder struct {
	mu          sync.Mutex
	events      []capEvent
	closed      []string
	resetDelay  time.Duration
	resetErr    error
	declareGate chan struct{}
	// inflight counts DeclareCapabilities calls that have not returned;
	// declareExits holds the ctx.Err() each call observed as it returned.
	inflight     atomic.Int32
	declareExits []error
}

func (r *capRecorder) ResetCapabilities(_ context.Context, conn *registry.StewardConnection) error {
	if r.resetDelay > 0 {
		time.Sleep(r.resetDelay)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.resetErr != nil {
		return r.resetErr
	}
	r.events = append(r.events, capEvent{kind: "reset", connectionID: conn.ConnectionID, state: types.CapabilityPending})
	return nil
}

func (r *capRecorder) DeclareCapabilities(ctx context.Context, conn *registry.StewardConnection, profile types.CapabilityProfile) (bool, error) {
	r.inflight.Add(1)
	defer func() {
		r.mu.Lock()
		r.declareExits = append(r.declareExits, ctx.Err())
		r.mu.Unlock()
		r.inflight.Add(-1)
	}()
	if r.declareGate != nil {
		select {
		case <-r.declareGate:
		case <-ctx.Done():
			return false, ctx.Err()
		}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, capEvent{kind: "declare", connectionID: conn.ConnectionID, state: profile.State, profile: profile})
	return true, nil
}

func (r *capRecorder) CapabilityConnectionClosed(conn *registry.StewardConnection) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closed = append(r.closed, conn.ConnectionID)
}

func (r *capRecorder) exits() []error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]error(nil), r.declareExits...)
}

func (r *capRecorder) snapshot() []capEvent {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]capEvent(nil), r.events...)
}

func (r *capRecorder) states() []string {
	var out []string
	for _, e := range r.snapshot() {
		out = append(out, e.kind+":"+e.state)
	}
	return out
}

// capEnv is a real in-process server and steward-side client over QUIC+mTLS.
type capEnv struct {
	server *Provider
	client *Provider
	reg    registry.Registry
	conn   *registry.StewardConnection
}

// newCapEnv starts a server with serverOpts and a client with clientOpts, and
// returns once the steward's connection is registered.
func newCapEnv(t *testing.T, stewardID string, serverOpts, clientOpts []option) *capEnv {
	t.Helper()
	serverTLS, clientTLS := newTestTLSConfigs(t, stewardID)
	reg := registry.NewRegistry()

	server := New(ModeServer, serverOpts...)
	require.NoError(t, server.Initialize(context.Background(), map[string]interface{}{
		"mode": "server", "addr": "127.0.0.1:0", "tls_config": serverTLS, "registry": reg,
	}))
	require.NoError(t, server.Start(context.Background()))
	t.Cleanup(server.ForceStop)

	client := New(ModeClient, clientOpts...)
	require.NoError(t, client.Initialize(context.Background(), map[string]interface{}{
		"mode": "client", "addr": server.ListenAddr(), "tls_config": clientTLS, "steward_id": stewardID,
	}))
	require.NoError(t, client.Start(context.Background()))
	t.Cleanup(func() { _ = client.Stop(context.Background()) })

	var conn *registry.StewardConnection
	require.Eventually(t, func() bool {
		c, ok := reg.Get(stewardID)
		conn = c
		return ok
	}, 5*time.Second, 10*time.Millisecond, "steward should be registered")
	return &capEnv{server: server, client: client, reg: reg, conn: conn}
}

func requireSettled(t *testing.T, conn *registry.StewardConnection) {
	t.Helper()
	select {
	case <-conn.CapabilitiesSettled():
	case <-time.After(10 * time.Second):
		t.Fatal("connection capabilities never settled")
	}
}

func TestCapabilitiesDeclaringStewardSettlesOnFirstMessage(t *testing.T) {
	t.Parallel()
	rec := &capRecorder{}
	local := LocalCapabilities("steward-cap-declare")
	// A long grace proves the signal was released by the declaration, not the timer.
	env := newCapEnv(t, "steward-cap-declare",
		[]option{WithCapabilityRecorder(rec), WithCapabilityGrace(time.Minute)},
		[]option{WithStewardCapabilities(local)})

	requireSettled(t, env.conn)
	snap := env.conn.CapabilitySnapshot()
	assert.Equal(t, registry.CapabilityDeclared, snap.State)
	assert.Equal(t, local.CommandTypes, snap.CommandTypes)
	assert.Equal(t, local.SigningPayloadVersions, snap.SigningPayloadVersions)
	assert.Contains(t, snap.SigningPayloadVersions, types.SigningPayloadV2)

	require.Eventually(t, func() bool { return len(rec.snapshot()) == 2 }, 5*time.Second, 10*time.Millisecond)
	assert.Equal(t, []string{"reset:pending", "declare:declared"}, rec.states())
	events := rec.snapshot()
	assert.NotEmpty(t, events[0].connectionID)
	assert.Equal(t, events[0].connectionID, events[1].connectionID, "every write carries the connection's ID")
	assert.Equal(t, env.conn.ConnectionID, events[0].connectionID)
}

func TestCapabilitiesSilentStewardSettlesAtFloorAfterGrace(t *testing.T) {
	t.Parallel()
	rec := &capRecorder{}
	start := time.Now()
	env := newCapEnv(t, "steward-cap-silent",
		[]option{WithCapabilityRecorder(rec), WithCapabilityGrace(300 * time.Millisecond)}, nil)

	select {
	case <-env.conn.CapabilitiesSettled():
		assert.GreaterOrEqual(t, time.Since(start), 250*time.Millisecond, "a silent steward waits out the grace")
	default:
		// Not settled yet: the grace is still running.
		assert.Equal(t, registry.CapabilityPending, env.conn.CapabilitySnapshot().State)
		requireSettled(t, env.conn)
	}

	floor := types.FloorProfile()
	snap := env.conn.CapabilitySnapshot()
	assert.Equal(t, registry.CapabilityFloor, snap.State)
	assert.Equal(t, floor.CommandTypes, snap.CommandTypes)
	assert.Equal(t, floor.SigningPayloadVersions, snap.SigningPayloadVersions)

	require.Eventually(t, func() bool { return len(rec.snapshot()) == 2 }, 5*time.Second, 10*time.Millisecond)
	assert.Equal(t, []string{"reset:pending", "declare:floor"}, rec.states())
}

func TestCapabilitiesLateDeclarationMovesFloorToDeclaredOnce(t *testing.T) {
	t.Parallel()
	rec := &capRecorder{}
	var lateMu sync.Mutex
	var late []string
	env := newCapEnv(t, "steward-cap-late",
		[]option{
			WithCapabilityRecorder(rec),
			WithCapabilityGrace(100 * time.Millisecond),
			WithOnLateCapabilities(func(_ context.Context, stewardID string) {
				lateMu.Lock()
				late = append(late, stewardID)
				lateMu.Unlock()
			}),
		}, nil)

	requireSettled(t, env.conn)
	require.Equal(t, registry.CapabilityFloor, env.conn.CapabilitySnapshot().State)

	local := LocalCapabilities("steward-cap-late")
	require.NoError(t, env.client.SendCapabilities(context.Background(), &local))
	require.Eventually(t, func() bool {
		return env.conn.CapabilitySnapshot().State == registry.CapabilityDeclared
	}, 5*time.Second, 10*time.Millisecond)
	assert.Equal(t, local.CommandTypes, env.conn.CapabilitySnapshot().CommandTypes)

	require.Eventually(t, func() bool {
		lateMu.Lock()
		defer lateMu.Unlock()
		return len(late) == 1
	}, 5*time.Second, 10*time.Millisecond, "late callback runs for the floor to declared move")

	// A second declaration on the same connection changes nothing and does not
	// call the callback again.
	other := types.StewardCapabilities{StewardID: "steward-cap-late", CommandTypes: []int32{1}, SigningPayloadVersions: []uint32{1}}
	require.NoError(t, env.client.SendCapabilities(context.Background(), &other))
	require.NoError(t, env.client.SendHeartbeat(context.Background(), &types.Heartbeat{StewardID: "steward-cap-late"}))
	time.Sleep(200 * time.Millisecond)

	lateMu.Lock()
	assert.Equal(t, []string{"steward-cap-late"}, late)
	lateMu.Unlock()
	assert.Equal(t, local.CommandTypes, env.conn.CapabilitySnapshot().CommandTypes, "the first declaration is final")

	require.Eventually(t, func() bool { return len(rec.snapshot()) == 3 }, 5*time.Second, 10*time.Millisecond)
	assert.Equal(t, []string{"reset:pending", "declare:floor", "declare:declared"}, rec.states())
}

func TestCapabilitiesResetCompletesBeforeReceiveLoopStarts(t *testing.T) {
	t.Parallel()
	// The reset takes long enough that the steward's first-message declaration is
	// already queued on the stream when it returns. The reset must not overwrite
	// the declaration, and no durable write may precede the reset.
	rec := &capRecorder{resetDelay: 400 * time.Millisecond}
	local := LocalCapabilities("steward-cap-order")
	env := newCapEnv(t, "steward-cap-order",
		[]option{WithCapabilityRecorder(rec), WithCapabilityGrace(time.Minute)},
		[]option{WithStewardCapabilities(local)})

	requireSettled(t, env.conn)
	assert.Equal(t, registry.CapabilityDeclared, env.conn.CapabilitySnapshot().State)
	require.Eventually(t, func() bool { return len(rec.snapshot()) == 2 }, 5*time.Second, 10*time.Millisecond)
	assert.Equal(t, []string{"reset:pending", "declare:declared"}, rec.states())
}

func TestCapabilitiesEveryReconnectResetsAndDeclaresAgain(t *testing.T) {
	t.Parallel()
	rec := &capRecorder{}
	local := LocalCapabilities("steward-cap-reconnect")
	env := newCapEnv(t, "steward-cap-reconnect",
		[]option{WithCapabilityRecorder(rec), WithCapabilityGrace(time.Minute)},
		[]option{WithStewardCapabilities(local)})
	requireSettled(t, env.conn)
	first := env.conn.ConnectionID

	require.NoError(t, env.client.Reconnect(context.Background()))
	require.Eventually(t, func() bool {
		c, ok := env.reg.Get("steward-cap-reconnect")
		return ok && c.ConnectionID != first
	}, 10*time.Second, 20*time.Millisecond, "a new connection registers")
	next, _ := env.reg.Get("steward-cap-reconnect")
	requireSettled(t, next)

	assert.NotEqual(t, first, next.ConnectionID)
	assert.Equal(t, registry.CapabilityDeclared, next.CapabilitySnapshot().State, "the reconnect declared again as its first message")
	require.Eventually(t, func() bool { return len(rec.snapshot()) >= 4 }, 5*time.Second, 10*time.Millisecond)
	events := rec.snapshot()
	assert.Equal(t, "reset", events[2].kind)
	assert.Equal(t, next.ConnectionID, events[2].connectionID)
}

func TestCapabilitiesFailedResetStaysPendingAndWritesNothingDurable(t *testing.T) {
	t.Parallel()
	rec := &capRecorder{resetErr: errors.New("store unavailable")}
	env := newCapEnv(t, "steward-cap-resetfail",
		[]option{WithCapabilityRecorder(rec), WithCapabilityGrace(time.Minute)}, nil)

	assert.True(t, env.conn.CapabilityDurableLost(), "the connection is marked: its record is not the stored one")
	assert.Equal(t, registry.CapabilityPending, env.conn.CapabilitySnapshot().State)
	select {
	case <-env.conn.CapabilitiesSettled():
		t.Fatal("a connection whose reset failed must stay pending, not settle")
	case <-time.After(200 * time.Millisecond):
	}

	// A declaration still moves the in-memory state (it came from the steward on
	// this connection) but nothing is written to the record of an older one.
	local := LocalCapabilities("steward-cap-resetfail")
	require.NoError(t, env.client.SendCapabilities(context.Background(), &local))
	requireSettled(t, env.conn)
	time.Sleep(200 * time.Millisecond)
	assert.Empty(t, rec.snapshot(), "no durable write after a failed reset")
}

func TestCapabilitiesReceiveLoopDoesNotBlockOnDurableWrite(t *testing.T) {
	t.Parallel()
	gate := make(chan struct{})
	rec := &capRecorder{declareGate: gate}
	local := LocalCapabilities("steward-cap-slow")
	env := newCapEnv(t, "steward-cap-slow",
		[]option{WithCapabilityRecorder(rec), WithCapabilityGrace(time.Minute)},
		[]option{WithStewardCapabilities(local)})

	got := make(chan *types.Heartbeat, 1)
	require.NoError(t, env.server.SubscribeHeartbeats(context.Background(), func(_ context.Context, hb *types.Heartbeat) error {
		got <- hb
		return nil
	}))

	requireSettled(t, env.conn)
	// The durable write is parked on the gate; the next message must still be read.
	require.NoError(t, env.client.SendHeartbeat(context.Background(), &types.Heartbeat{StewardID: "steward-cap-slow", Version: "after-declare"}))
	select {
	case hb := <-got:
		assert.Equal(t, "after-declare", hb.Version)
	case <-time.After(5 * time.Second):
		t.Fatal("the receive loop was blocked by the durable write")
	}
	assert.Equal(t, []string{"reset:pending"}, rec.states(), "the write has not completed")

	close(gate)
	require.Eventually(t, func() bool { return len(rec.snapshot()) == 2 }, 5*time.Second, 10*time.Millisecond)
}

func TestCapabilitiesMismatchedStewardIDRejected(t *testing.T) {
	t.Parallel()
	env := newCapEnv(t, "steward-cap-mismatch",
		[]option{WithCapabilityGrace(time.Minute)}, nil)

	forged := types.StewardCapabilities{StewardID: "someone-else", CommandTypes: []int32{1, 2}, SigningPayloadVersions: []uint32{1, 2}}
	require.NoError(t, env.client.SendCapabilities(context.Background(), &forged))

	require.Eventually(t, func() bool {
		stats, err := env.server.GetStats(context.Background())
		return err == nil && stats.IdentityMismatches == 1
	}, 5*time.Second, 10*time.Millisecond)
	assert.Equal(t, registry.CapabilityPending, env.conn.CapabilitySnapshot().State, "a forged declaration changes nothing")
}

func TestCapabilitiesUnknownAndOversizedListsAreIgnoredOrCapped(t *testing.T) {
	t.Parallel()
	t.Run("unknown enum numbers are dropped", func(t *testing.T) {
		t.Parallel()
		env := newCapEnv(t, "steward-cap-unknown", []option{WithCapabilityGrace(time.Minute)}, nil)
		caps := types.StewardCapabilities{CommandTypes: []int32{2, 1, 9999, -4, 0}, SigningPayloadVersions: []uint32{2, 1, 0}}
		require.NoError(t, env.client.SendCapabilities(context.Background(), &caps))
		requireSettled(t, env.conn)
		snap := env.conn.CapabilitySnapshot()
		assert.Equal(t, []int32{1, 2}, snap.CommandTypes)
		assert.Equal(t, []uint32{1, 2}, snap.SigningPayloadVersions)
	})

	t.Run("a declaration with nothing usable is ignored", func(t *testing.T) {
		t.Parallel()
		env := newCapEnv(t, "steward-cap-nothing", []option{WithCapabilityGrace(time.Minute)}, nil)
		caps := types.StewardCapabilities{CommandTypes: []int32{9999}, SigningPayloadVersions: []uint32{1}}
		require.NoError(t, env.client.SendCapabilities(context.Background(), &caps))
		// A usable one afterwards still settles the connection: the bad one did not.
		time.Sleep(200 * time.Millisecond)
		assert.Equal(t, registry.CapabilityPending, env.conn.CapabilitySnapshot().State)
		good := types.StewardCapabilities{CommandTypes: []int32{1}, SigningPayloadVersions: []uint32{1}}
		require.NoError(t, env.client.SendCapabilities(context.Background(), &good))
		requireSettled(t, env.conn)
		assert.Equal(t, []int32{1}, env.conn.CapabilitySnapshot().CommandTypes)
	})

	t.Run("oversized lists are capped", func(t *testing.T) {
		t.Parallel()
		env := newCapEnv(t, "steward-cap-oversized", []option{WithCapabilityGrace(time.Minute)}, nil)
		caps := types.StewardCapabilities{}
		for i := 1; i <= 3000; i++ {
			caps.CommandTypes = append(caps.CommandTypes, int32(i))
			caps.SigningPayloadVersions = append(caps.SigningPayloadVersions, uint32(i))
		}
		caps.CommandTypes = append(caps.CommandTypes, 1, 2, 3)
		require.NoError(t, env.client.SendCapabilities(context.Background(), &caps))
		requireSettled(t, env.conn)
		snap := env.conn.CapabilitySnapshot()
		assert.LessOrEqual(t, len(snap.CommandTypes), types.MaxDeclaredCommandTypes)
		assert.Len(t, snap.SigningPayloadVersions, types.MaxDeclaredSigningPayloadVersions)
		for _, n := range snap.CommandTypes {
			_, ok := transportpb.CommandType_name[n]
			assert.True(t, ok, "only enum numbers the build knows are kept, got %d", n)
		}
	})
}

// TestUnknownControlPayloadIgnored pins the rollback-safe behaviour of the
// controller's receive loop: a ControlMessage whose oneof member this build does
// not know (a newer steward's) decodes with no payload, is ignored, and leaves
// the stream open. A controller rolled back to a build without the capabilities
// member therefore tolerates a steward that sends it.
func TestUnknownControlPayloadIgnored(t *testing.T) {
	t.Parallel()
	const stewardID = "steward-unknown-payload"
	serverTLS, clientTLS := newTestTLSConfigs(t, stewardID)
	reg := registry.NewRegistry()
	server := New(ModeServer)
	require.NoError(t, server.Initialize(context.Background(), map[string]interface{}{
		"mode": "server", "addr": "127.0.0.1:0", "tls_config": serverTLS, "registry": reg,
	}))
	require.NoError(t, server.Start(context.Background()))
	t.Cleanup(server.ForceStop)

	heartbeats := make(chan *types.Heartbeat, 4)
	require.NoError(t, server.SubscribeHeartbeats(context.Background(), func(_ context.Context, hb *types.Heartbeat) error {
		heartbeats <- hb
		return nil
	}))

	stream := openStreamFrom(t, "127.0.0.1", server.ListenAddr(), clientTLS, nil)
	select {
	case <-heartbeats: // the opening heartbeat openStreamFrom sends
	case <-time.After(5 * time.Second):
		t.Fatal("opening heartbeat not received")
	}

	// A message carrying only a field number this build does not define.
	unknown := &transportpb.ControlMessage{}
	raw := protowire.AppendTag(nil, 99, protowire.BytesType)
	raw = protowire.AppendBytes(raw, []byte("from a newer steward"))
	unknown.ProtoReflect().SetUnknown(raw)
	require.NoError(t, stream.Send(unknown))
	require.NoError(t, stream.Send(&transportpb.ControlMessage{Payload: &transportpb.ControlMessage_Heartbeat{
		Heartbeat: &transportpb.Heartbeat{StewardId: stewardID, Version: "after-unknown"},
	}}))

	select {
	case hb := <-heartbeats:
		assert.Equal(t, "after-unknown", hb.Version, "a heartbeat after the unknown payload is still processed")
	case <-time.After(5 * time.Second):
		t.Fatal("stream was closed or stalled by an unknown payload")
	}
	_, ok := reg.Get(stewardID)
	assert.True(t, ok, "the steward stays registered")
}

// TestCapabilitiesShutdownDrainsParkedDurableWrite pins that Stop and ForceStop
// cancel an in-flight durable capability write and return only after it has
// exited, so a controller may close its store as soon as the call returns.
func TestCapabilitiesShutdownDrainsParkedDurableWrite(t *testing.T) {
	t.Parallel()
	shutdowns := map[string]func(t *testing.T, p *Provider){
		"Stop": func(t *testing.T, p *Provider) {
			require.NoError(t, p.Stop(context.Background()))
		},
		"ForceStop": func(_ *testing.T, p *Provider) { p.ForceStop() },
	}
	for name, shutdown := range shutdowns {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			stewardID := "steward-cap-drain-" + name
			// The gate is never closed: only cancellation can release the write.
			rec := &capRecorder{declareGate: make(chan struct{})}
			local := LocalCapabilities(stewardID)
			env := newCapEnv(t, stewardID,
				[]option{WithCapabilityRecorder(rec), WithCapabilityGrace(time.Minute)},
				[]option{WithStewardCapabilities(local)})

			require.Eventually(t, func() bool { return rec.inflight.Load() == 1 },
				5*time.Second, 5*time.Millisecond, "the durable write should be parked")

			shutdown(t, env.server)

			assert.Zero(t, rec.inflight.Load(), "the write goroutine must have exited when shutdown returns")
			exits := rec.exits()
			require.Len(t, exits, 1)
			assert.Error(t, exits[0], "the write must observe the provider's cancellation")
		})
	}
}

// TestCapabilitiesWriteRefusedAfterShutdown pins that no capability writer starts
// once shutdown has begun, that a refused submit leaves the writer reusable, and
// that a restarted provider accepts writers again.
func TestCapabilitiesWriteRefusedAfterShutdown(t *testing.T) {
	t.Parallel()
	p := New(ModeServer)
	w := &capabilityWriter{}
	ran := make(chan struct{}, 1)
	write := func(_ context.Context, _ types.CapabilityProfile) { ran <- struct{}{} }

	p.stopCapabilityWrites()
	assert.False(t, w.submit(p, types.FloorProfile(), write), "a write must be refused after shutdown begins")
	require.NoError(t, p.drainCapabilityWrites(context.Background()), "a refused write is not tracked")
	select {
	case <-ran:
		t.Fatal("a refused write must not run")
	default:
	}

	p.resumeCapabilityWrites()
	require.True(t, w.submit(p, types.FloorProfile(), write), "a restarted provider accepts writes again")
	require.NoError(t, p.drainCapabilityWrites(context.Background()))
	select {
	case <-ran:
	default:
		t.Fatal("the accepted write should have run before the drain returned")
	}
}

// TestCapabilitiesDrainBoundedByContext pins that the drain reports a writer that
// ignores cancellation instead of waiting for it forever.
func TestCapabilitiesDrainBoundedByContext(t *testing.T) {
	t.Parallel()
	p := New(ModeServer)
	w := &capabilityWriter{}
	release := make(chan struct{})
	started := make(chan struct{})
	require.True(t, w.submit(p, types.FloorProfile(), func(_ context.Context, _ types.CapabilityProfile) {
		close(started)
		<-release
	}))
	<-started

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	err := p.drainCapabilityWrites(ctx)
	require.Error(t, err)
	assert.ErrorIs(t, err, context.DeadlineExceeded)
	assert.Contains(t, err.Error(), "capability writes")

	close(release)
	require.NoError(t, p.drainCapabilityWrites(context.Background()))
}
