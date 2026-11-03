// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package grpc

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/controlplane/types"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/transport/registry"
)

// panicHookRecorder records PanicHook calls.
type panicHookRecorder struct {
	mu         sync.Mutex
	components []string
	values     []interface{}
}

func (r *panicHookRecorder) hook(component string, recovered interface{}) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.components = append(r.components, component)
	r.values = append(r.values, recovered)
}

func (r *panicHookRecorder) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.components)
}

func panicTestCommand(id string) *types.SignedCommand {
	return &types.SignedCommand{Command: types.Command{
		ID: id, Type: types.CommandSyncConfig, StewardID: "steward-panic", Timestamp: time.Now(),
	}}
}

// A command handler that panics is recovered, the hook is called with
// command_handler, and the next command delivered over the real stream is still
// handled by the same receive loop.
func TestClientReceiveLoop_HandlerPanic_RecoveredAndNextCommandDelivered(t *testing.T) {
	t.Parallel()
	tc := newTestCA(t)
	server := New(ModeServer)
	require.NoError(t, server.Initialize(context.Background(), map[string]interface{}{
		"logger": logging.NewNoopLogger(), "mode": "server", "addr": "127.0.0.1:0",
		"tls_config": tc.serverTLSConfig(t), "registry": registry.NewRegistry(),
	}))
	require.NoError(t, server.Start(context.Background()))
	t.Cleanup(server.ForceStop)

	rec := &panicHookRecorder{}
	client := New(ModeClient, WithPanicHook(rec.hook))
	require.NoError(t, client.Initialize(context.Background(), map[string]interface{}{
		"mode": "client", "addr": server.ListenAddr(),
		"tls_config": tc.clientTLSConfig(t, "steward-panic"), "steward_id": "steward-panic",
	}))
	require.NoError(t, client.Start(context.Background()))
	t.Cleanup(func() { _ = client.Stop(context.Background()) })

	handled := make(chan string, 4)
	require.NoError(t, client.SubscribeCommands(context.Background(), "steward-panic",
		func(_ context.Context, sc *types.SignedCommand) error {
			if sc.Command.ID == "boom" {
				panic("handler exploded")
			}
			handled <- sc.Command.ID
			return nil
		}))

	require.Eventually(t, func() bool {
		return server.SendCommand(context.Background(), panicTestCommand("boom")) == nil
	}, 5*time.Second, 20*time.Millisecond)
	require.Eventually(t, func() bool { return rec.count() == 1 }, 5*time.Second, 10*time.Millisecond)

	require.NoError(t, server.SendCommand(context.Background(), panicTestCommand("after")))
	select {
	case id := <-handled:
		assert.Equal(t, "after", id)
	case <-time.After(5 * time.Second):
		t.Fatal("receive loop stopped after a handler panic: next command was not delivered")
	}
	rec.mu.Lock()
	defer rec.mu.Unlock()
	assert.Equal(t, []string{PanicComponentCommandHandler}, rec.components)
	assert.Equal(t, "handler exploded", rec.values[0])
}

// The Drain path (commands received before subscription) is guarded too: a
// panicking first command does not stop the backlog, the second is handled.
func TestSubscribeCommands_DrainPath_HandlerPanic_RecoveredAndNextRuns(t *testing.T) {
	t.Parallel()
	rec := &panicHookRecorder{}
	p := New(ModeClient, WithPanicHook(rec.hook))

	for _, id := range []string{"boom", "next"} {
		h, dropped := p.commands.Admit(panicTestCommand(id))
		require.Nil(t, h)
		require.False(t, dropped)
	}

	handled := make(chan string, 2)
	require.NoError(t, p.SubscribeCommands(context.Background(), "steward-panic",
		func(_ context.Context, sc *types.SignedCommand) error {
			if sc.Command.ID == "boom" {
				panic("drain exploded")
			}
			handled <- sc.Command.ID
			return nil
		}))

	select {
	case id := <-handled:
		assert.Equal(t, "next", id)
	case <-time.After(5 * time.Second):
		t.Fatal("Drain stopped after a handler panic")
	}
	assert.Equal(t, 1, rec.count())
}

// Without a hook a panic is still recovered.
func TestHandleCommand_PanicWithoutHook_Recovered(t *testing.T) {
	t.Parallel()
	p := New(ModeClient)
	assert.NotPanics(t, func() {
		p.handleCommand(func(context.Context, *types.SignedCommand) error { panic("x") }, panicTestCommand("c"))
	})
}
