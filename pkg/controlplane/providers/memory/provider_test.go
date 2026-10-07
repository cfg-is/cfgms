// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package memory_test

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/controlplane/providers/memory"
	"github.com/cfgis/cfgms/pkg/controlplane/types"
)

// startServer returns a started server-mode provider on bus.
func startServer(t *testing.T, bus *memory.Bus) *memory.Provider {
	t.Helper()
	ctx := context.Background()
	server := memory.New(memory.ModeServer)
	require.NoError(t, server.Initialize(ctx, map[string]interface{}{"bus": bus}))
	require.NoError(t, server.Start(ctx))
	t.Cleanup(func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		require.NoError(t, server.Stop(stopCtx))
	})
	return server
}

// startClient returns a started client-mode provider for stewardID on bus.
func startClient(t *testing.T, bus *memory.Bus, stewardID string) *memory.Provider {
	t.Helper()
	ctx := context.Background()
	client := memory.New(memory.ModeClient)
	require.NoError(t, client.Initialize(ctx, map[string]interface{}{
		"bus":        bus,
		"steward_id": stewardID,
	}))
	require.NoError(t, client.Start(ctx))
	t.Cleanup(func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		require.NoError(t, client.Stop(stopCtx))
	})
	return client
}

func TestInitialize_RequiresBus(t *testing.T) {
	ctx := context.Background()

	server := memory.New(memory.ModeServer)
	err := server.Initialize(ctx, map[string]interface{}{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "bus")
}

func TestInitialize_ClientRequiresStewardID(t *testing.T) {
	ctx := context.Background()
	bus := memory.NewBus()

	client := memory.New(memory.ModeClient)
	err := client.Initialize(ctx, map[string]interface{}{"bus": bus})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "steward_id")
}

func TestInitialize_RejectsUnknownMode(t *testing.T) {
	ctx := context.Background()
	bus := memory.NewBus()

	p := memory.New(memory.Mode("relay"))
	err := p.Initialize(ctx, map[string]interface{}{"bus": bus})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid mode")
}

func TestStart_ClientRequiresListeningServer(t *testing.T) {
	ctx := context.Background()
	bus := memory.NewBus()

	client := memory.New(memory.ModeClient)
	require.NoError(t, client.Initialize(ctx, map[string]interface{}{
		"bus":        bus,
		"steward_id": "steward-1",
	}))

	err := client.Start(ctx)
	require.Error(t, err, "client must not connect when no server is listening")
	assert.False(t, client.IsConnected())
}

func TestStart_RejectsSecondServerOnBus(t *testing.T) {
	ctx := context.Background()
	bus := memory.NewBus()
	startServer(t, bus)

	second := memory.New(memory.ModeServer)
	require.NoError(t, second.Initialize(ctx, map[string]interface{}{"bus": bus}))
	require.Error(t, second.Start(ctx), "only one server may listen on a bus")
}

func TestStart_RejectsDuplicateStewardID(t *testing.T) {
	ctx := context.Background()
	bus := memory.NewBus()
	startServer(t, bus)
	startClient(t, bus, "steward-1")

	duplicate := memory.New(memory.ModeClient)
	require.NoError(t, duplicate.Initialize(ctx, map[string]interface{}{
		"bus":        bus,
		"steward_id": "steward-1",
	}))
	err := duplicate.Start(ctx)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "already connected")
}

func TestServerStop_DisconnectsClients(t *testing.T) {
	ctx := context.Background()
	bus := memory.NewBus()

	server := memory.New(memory.ModeServer)
	require.NoError(t, server.Initialize(ctx, map[string]interface{}{"bus": bus}))
	require.NoError(t, server.Start(ctx))

	client := startClient(t, bus, "steward-1")
	require.True(t, client.IsConnected())

	require.NoError(t, server.Stop(ctx))

	assert.False(t, client.IsConnected(), "client must observe the server going away")
	assert.Equal(t, 0, bus.ClientCount())

	require.Error(t, client.PublishEvent(ctx, &types.Event{
		ID:        "evt-after-server-stop",
		Type:      types.EventError,
		StewardID: "steward-1",
		Timestamp: time.Now(),
	}))
}

func TestStop_IsIdempotent(t *testing.T) {
	ctx := context.Background()
	bus := memory.NewBus()
	startServer(t, bus)

	client := memory.New(memory.ModeClient)
	require.NoError(t, client.Initialize(ctx, map[string]interface{}{
		"bus":        bus,
		"steward_id": "steward-1",
	}))
	require.NoError(t, client.Start(ctx))

	require.NoError(t, client.Stop(ctx))
	require.NoError(t, client.Stop(ctx), "second Stop must be a no-op")
}

func TestReconnect_RestoresClientDelivery(t *testing.T) {
	ctx := context.Background()
	bus := memory.NewBus()
	server := startServer(t, bus)
	client := startClient(t, bus, "steward-1")

	require.NoError(t, client.Stop(ctx))

	cmd := &types.SignedCommand{Command: types.Command{
		ID:        "cmd-while-disconnected",
		Type:      types.CommandSyncConfig,
		StewardID: "steward-1",
		Timestamp: time.Now(),
	}}
	require.Error(t, server.SendCommand(ctx, cmd), "disconnected steward must not be reachable")

	require.NoError(t, client.Reconnect(ctx))
	assert.True(t, client.IsConnected())

	received := make(chan *types.SignedCommand, 1)
	require.NoError(t, client.SubscribeCommands(ctx, "steward-1", func(_ context.Context, sc *types.SignedCommand) error {
		received <- sc
		return nil
	}))

	require.NoError(t, server.SendCommand(ctx, &types.SignedCommand{Command: types.Command{
		ID:        "cmd-after-reconnect",
		Type:      types.CommandSyncConfig,
		StewardID: "steward-1",
		Timestamp: time.Now(),
	}}))

	select {
	case got := <-received:
		assert.Equal(t, "cmd-after-reconnect", got.Command.ID)
	case <-time.After(5 * time.Second):
		t.Fatal("reconnected steward did not receive command")
	}
}

func TestReconnect_RejectedInServerMode(t *testing.T) {
	bus := memory.NewBus()
	server := startServer(t, bus)
	require.Error(t, server.Reconnect(context.Background()))
}

func TestSubscribeCommands_RejectsForeignStewardID(t *testing.T) {
	ctx := context.Background()
	bus := memory.NewBus()
	startServer(t, bus)
	client := startClient(t, bus, "steward-1")

	err := client.SubscribeCommands(ctx, "steward-2", func(context.Context, *types.SignedCommand) error {
		return nil
	})
	require.Error(t, err, "a steward must not subscribe to another steward's commands")
}

func TestModeGuards(t *testing.T) {
	ctx := context.Background()
	bus := memory.NewBus()
	server := startServer(t, bus)
	client := startClient(t, bus, "steward-1")

	require.Error(t, client.SendCommand(ctx, &types.SignedCommand{}))
	_, err := client.FanOutCommand(ctx, &types.SignedCommand{}, []string{"steward-1"})
	require.Error(t, err)
	require.Error(t, client.SubscribeEvents(ctx, nil, func(context.Context, *types.Event) error { return nil }))
	require.Error(t, client.SubscribeHeartbeats(ctx, func(context.Context, *types.Heartbeat) error { return nil }))

	require.Error(t, server.PublishEvent(ctx, &types.Event{ID: "e"}))
	require.Error(t, server.SendHeartbeat(ctx, &types.Heartbeat{StewardID: "steward-1"}))
	require.Error(t, server.SubscribeCommands(ctx, "steward-1", func(context.Context, *types.SignedCommand) error { return nil }))
}

func TestFanOutCommand_RejectsEmptyTargets(t *testing.T) {
	bus := memory.NewBus()
	server := startServer(t, bus)

	_, err := server.FanOutCommand(context.Background(), &types.SignedCommand{}, nil)
	require.Error(t, err)
}

func TestSendCommand_RequiresTargetStewardID(t *testing.T) {
	bus := memory.NewBus()
	server := startServer(t, bus)

	err := server.SendCommand(context.Background(), &types.SignedCommand{Command: types.Command{
		ID:        "cmd-no-target",
		Type:      types.CommandSyncConfig,
		Timestamp: time.Now(),
	}})
	require.Error(t, err, "an unaddressed command must not be broadcast")
}

func TestDeliveredMessagesAreCopies(t *testing.T) {
	ctx := context.Background()
	bus := memory.NewBus()
	server := startServer(t, bus)
	clientA := startClient(t, bus, "steward-a")
	clientB := startClient(t, bus, "steward-b")

	var wg sync.WaitGroup
	wg.Add(2)
	var mu sync.Mutex
	copies := make(map[string]*types.SignedCommand, 2)
	for _, c := range []*memory.Provider{clientA, clientB} {
		id := c.StewardID()
		require.NoError(t, c.SubscribeCommands(ctx, id, func(_ context.Context, sc *types.SignedCommand) error {
			// Each steward mutates its own copy; no other party may observe it.
			sc.Command.Params["mutated_by"] = id
			mu.Lock()
			copies[id] = sc
			mu.Unlock()
			wg.Done()
			return nil
		}))
	}

	original := &types.SignedCommand{Command: types.Command{
		ID:        "cmd-copy",
		Type:      types.CommandSyncConfig,
		Timestamp: time.Now(),
		Params:    map[string]interface{}{"version": "1.0"},
	}}
	result, err := server.FanOutCommand(ctx, original, []string{"steward-a", "steward-b"})
	require.NoError(t, err)
	require.Len(t, result.Succeeded, 2)

	wg.Wait()

	assert.Equal(t, map[string]interface{}{"version": "1.0"}, original.Command.Params,
		"handler mutations must not reach the sender's command")

	mu.Lock()
	defer mu.Unlock()
	require.Len(t, copies, 2)
	assert.Equal(t, "steward-a", copies["steward-a"].Command.Params["mutated_by"])
	assert.Equal(t, "steward-b", copies["steward-b"].Command.Params["mutated_by"])
	assert.Equal(t, original.Command.ID, copies["steward-a"].Command.ID)
}

func TestEventDetailsAreCopied(t *testing.T) {
	ctx := context.Background()
	bus := memory.NewBus()
	server := startServer(t, bus)
	client := startClient(t, bus, "steward-1")

	received := make(chan *types.Event, 1)
	require.NoError(t, server.SubscribeEvents(ctx, nil, func(_ context.Context, e *types.Event) error {
		e.Details["mutated"] = true
		received <- e
		return nil
	}))

	original := &types.Event{
		ID:        "evt-copy",
		Type:      types.EventConfigApplied,
		StewardID: "steward-1",
		Timestamp: time.Now(),
		Details:   map[string]interface{}{"modules": "3"},
	}
	require.NoError(t, client.PublishEvent(ctx, original))

	select {
	case got := <-received:
		assert.Equal(t, true, got.Details["mutated"])
	case <-time.After(5 * time.Second):
		t.Fatal("server did not receive event")
	}

	assert.Equal(t, map[string]interface{}{"modules": "3"}, original.Details,
		"handler mutations must not reach the publisher's event")
}

func TestGetStats_ReportsConnectedStewardsAndSubscriptions(t *testing.T) {
	ctx := context.Background()
	bus := memory.NewBus()
	server := startServer(t, bus)
	startClient(t, bus, "steward-1")
	startClient(t, bus, "steward-2")

	require.NoError(t, server.SubscribeEvents(ctx, nil, func(context.Context, *types.Event) error { return nil }))
	require.NoError(t, server.SubscribeHeartbeats(ctx, func(context.Context, *types.Heartbeat) error { return nil }))

	stats, err := server.GetStats(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(2), stats.ConnectedStewards)
	assert.Equal(t, int64(2), stats.ActiveSubscriptions)
	// Plumbing check only: confirms Uptime is wired to startTime, not a timing
	// assertion. assert.Positive is unreliable here because Windows timer
	// granularity (~15.6ms) can put Start and GetStats in the same tick,
	// producing an observed 0s even though the code is correct. See
	// TestGetStats_UptimeReflectsClock for a deterministic growth assertion.
	assert.GreaterOrEqual(t, stats.Uptime, time.Duration(0))
}

// TestGetStats_UptimeReflectsClock asserts Uptime growth exactly, using an
// injected clock instead of real elapsed wall-clock time. Asserting a real
// sleep interval would reintroduce the same clock-resolution flakiness this
// test is written to avoid; the injectable clock lets the boundary be exact.
func TestGetStats_UptimeReflectsClock(t *testing.T) {
	ctx := context.Background()
	bus := memory.NewBus()

	current := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	clock := func() time.Time { return current }

	server := memory.New(memory.ModeServer, memory.WithClock(clock))
	require.NoError(t, server.Initialize(ctx, map[string]interface{}{"bus": bus}))
	require.NoError(t, server.Start(ctx))
	t.Cleanup(func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		require.NoError(t, server.Stop(stopCtx))
	})

	current = current.Add(90 * time.Second)

	stats, err := server.GetStats(ctx)
	require.NoError(t, err)
	assert.Equal(t, 90*time.Second, stats.Uptime)
}

func TestGetStats_CountsDeliveryFailures(t *testing.T) {
	ctx := context.Background()
	bus := memory.NewBus()
	server := startServer(t, bus)

	require.Error(t, server.SendCommand(ctx, &types.SignedCommand{Command: types.Command{
		ID:        "cmd-nowhere",
		Type:      types.CommandSyncConfig,
		StewardID: "steward-absent",
		Timestamp: time.Now(),
	}}))

	stats, err := server.GetStats(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(1), stats.DeliveryFailures)
	assert.Equal(t, int64(0), stats.CommandsSent)
}

func TestName(t *testing.T) {
	assert.Equal(t, "memory", memory.New(memory.ModeServer).Name())
}

func TestConcurrentSendAndPublish(t *testing.T) {
	ctx := context.Background()
	bus := memory.NewBus()
	server := startServer(t, bus)
	client := startClient(t, bus, "steward-1")

	var commands, events atomic.Int64
	require.NoError(t, client.SubscribeCommands(ctx, "steward-1", func(context.Context, *types.SignedCommand) error {
		commands.Add(1)
		return nil
	}))
	require.NoError(t, server.SubscribeEvents(ctx, nil, func(context.Context, *types.Event) error {
		events.Add(1)
		return nil
	}))

	const n = 50
	var wg sync.WaitGroup
	wg.Add(2 * n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			assert.NoError(t, server.SendCommand(ctx, &types.SignedCommand{Command: types.Command{
				ID:        "cmd-concurrent",
				Type:      types.CommandSyncConfig,
				StewardID: "steward-1",
				Timestamp: time.Now(),
			}}))
		}()
		go func() {
			defer wg.Done()
			assert.NoError(t, client.PublishEvent(ctx, &types.Event{
				ID:        "evt-concurrent",
				Type:      types.EventConfigApplied,
				StewardID: "steward-1",
				Timestamp: time.Now(),
			}))
		}()
	}
	wg.Wait()

	require.Eventually(t, func() bool {
		return commands.Load() == n && events.Load() == n
	}, 5*time.Second, 10*time.Millisecond, "all concurrent messages should be delivered")
}
