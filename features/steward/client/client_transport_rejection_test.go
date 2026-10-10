// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package client

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/steward/commands"
	"github.com/cfgis/cfgms/pkg/controlplane/providers/memory"
	cpTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
)

const rejectionTestSteward = "steward-rejection-test"

// rejectionHarness is a real TransportClient wired to a real in-process
// control plane pair and a real commands.Handler.
type rejectionHarness struct {
	tc        *TransportClient
	handler   *commands.Handler
	responses chan *cpTypes.Response
}

func newRejectionHarness(t *testing.T) *rejectionHarness {
	t.Helper()
	ctx := context.Background()

	bus := memory.NewBus()
	server := memory.New(memory.ModeServer)
	require.NoError(t, server.Initialize(ctx, map[string]interface{}{"bus": bus}))
	require.NoError(t, server.Start(ctx))
	client := memory.New(memory.ModeClient)
	require.NoError(t, client.Initialize(ctx, map[string]interface{}{"bus": bus, "steward_id": rejectionTestSteward}))
	require.NoError(t, client.Start(ctx))
	t.Cleanup(func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = client.Stop(stopCtx)
		_ = server.Stop(stopCtx)
	})

	responses := make(chan *cpTypes.Response, 8)
	require.NoError(t, server.SubscribeResponses(ctx, func(_ context.Context, resp *cpTypes.Response) error {
		responses <- resp
		return nil
	}))

	handler, err := commands.New(&commands.Config{
		StewardID:      rejectionTestSteward,
		OnStatus:       func(context.Context, *cpTypes.Event) {},
		Logger:         newTestLogger(t),
		MaxParamsBytes: 64,
	})
	require.NoError(t, err)
	t.Cleanup(handler.Wait)

	tc := &TransportClient{
		logger:       newTestLogger(t),
		stewardID:    rejectionTestSteward,
		controlPlane: client,
	}
	return &rejectionHarness{tc: tc, handler: handler, responses: responses}
}

func rejectionCommand(id string) *cpTypes.SignedCommand {
	return &cpTypes.SignedCommand{Command: cpTypes.Command{
		ID:        id,
		Type:      cpTypes.CommandSyncConfig,
		StewardID: rejectionTestSteward,
		Timestamp: time.Now(),
	}}
}

func TestReceiveCommand_ReportsRejectionReason(t *testing.T) {
	tests := []struct {
		name      string
		reason    string
		retryable bool
		// build returns the command to receive after setup has run.
		setup    func(t *testing.T, h *rejectionHarness)
		build    func() *cpTypes.SignedCommand
		dispatch func(h *rejectionHarness) func(context.Context, *cpTypes.SignedCommand) error
	}{
		{
			name:      "term_fenced",
			reason:    "term_fenced",
			retryable: true,
			setup: func(t *testing.T, h *rejectionHarness) {
				c := rejectionCommand("seed")
				c.Command.Term = 5
				require.NoError(t, h.tc.checkTermFence(c))
			},
			build: func() *cpTypes.SignedCommand { return rejectionCommand("fenced") },
		},
		{
			name:   "unauthenticated",
			reason: "unauthenticated",
			build: func() *cpTypes.SignedCommand {
				c := rejectionCommand("unauth")
				c.Command.Type = cpTypes.CommandExecuteScript
				c.Command.Params = map[string]interface{}{"script_id": "lib-1"}
				return c
			},
		},
		{
			name:   "wrong_steward",
			reason: "wrong_steward",
			build: func() *cpTypes.SignedCommand {
				c := rejectionCommand("wrong")
				c.Command.StewardID = "someone-else"
				return c
			},
		},
		{
			name:   "stale_timestamp",
			reason: "stale_timestamp",
			build: func() *cpTypes.SignedCommand {
				c := rejectionCommand("stale")
				c.Command.Timestamp = time.Now().Add(-time.Hour)
				return c
			},
		},
		{
			name:   "duplicate_id",
			reason: "duplicate_id",
			setup: func(t *testing.T, h *rejectionHarness) {
				require.NoError(t, h.handler.HandleCommand(context.Background(), rejectionCommand("dup")))
			},
			build: func() *cpTypes.SignedCommand { return rejectionCommand("dup") },
		},
		{
			name:   "params_too_large",
			reason: "params_too_large",
			build: func() *cpTypes.SignedCommand {
				c := rejectionCommand("big")
				c.Command.Params = map[string]interface{}{"blob": string(make([]byte, 256))}
				return c
			},
		},
		{
			name:   "invalid_command",
			reason: "invalid_command",
			build:  func() *cpTypes.SignedCommand { return rejectionCommand("invalid") },
			dispatch: func(*rejectionHarness) func(context.Context, *cpTypes.SignedCommand) error {
				return func(context.Context, *cpTypes.SignedCommand) error { return errors.New("boom: secret detail") }
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newRejectionHarness(t)
			if tt.setup != nil {
				tt.setup(t, h)
			}
			dispatch := h.handler.HandleCommand
			if tt.dispatch != nil {
				dispatch = tt.dispatch(h)
			}
			sc := tt.build()

			err := h.tc.receiveCommand(context.Background(), sc, dispatch)
			require.Error(t, err, "the original error must still be returned")

			select {
			case resp := <-h.responses:
				assert.Equal(t, sc.Command.ID, resp.CommandID)
				assert.Equal(t, rejectionTestSteward, resp.StewardID)
				assert.False(t, resp.Success)
				assert.Equal(t, tt.reason, resp.Message)
				assert.Equal(t, tt.reason, resp.Details["reason"])
				assert.Equal(t, tt.retryable, resp.Details["retryable"])
				assert.NotContains(t, resp.Message, "secret detail", "the response carries the reason code only")
			case <-time.After(5 * time.Second):
				t.Fatal("timed out waiting for the rejection response")
			}

			select {
			case extra := <-h.responses:
				t.Fatalf("expected exactly one response, got a second for %q", extra.CommandID)
			case <-time.After(100 * time.Millisecond):
			}
		})
	}

	t.Run("accepted command sends no response", func(t *testing.T) {
		h := newRejectionHarness(t)
		require.NoError(t, h.tc.receiveCommand(context.Background(), rejectionCommand("ok"), h.handler.HandleCommand))

		select {
		case resp := <-h.responses:
			t.Fatalf("accepted command produced a response: %q", resp.Message)
		case <-time.After(200 * time.Millisecond):
		}
	})

	t.Run("empty command ID sends no response", func(t *testing.T) {
		h := newRejectionHarness(t)
		err := h.tc.receiveCommand(context.Background(), rejectionCommand(""), func(context.Context, *cpTypes.SignedCommand) error {
			return errors.New("rejected")
		})
		require.Error(t, err)

		select {
		case resp := <-h.responses:
			t.Fatalf("empty command ID produced a response: %q", resp.Message)
		case <-time.After(200 * time.Millisecond):
		}
	})
}
