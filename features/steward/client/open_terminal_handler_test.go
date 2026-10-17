// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package client exercises the CommandOpenTerminal handler registered in setupCommandHandler.
//
// Issue #2760: setupCommandHandler must call handler.RegisterOpenTerminalHandler()
// so a controller-sent open_terminal command is dispatched through the terminal
// bridge and produces EventCommandCompleted — not EventCommandFailed
// ("no handler for command type"). Without this wiring an open_terminal command
// dispatched by the controller silently fails.
package client

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/steward/execution"
	cpTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
)

// TestSetupCommandHandler_RegistersOpenTerminal verifies that the command handler
// built by setupCommandHandler dispatches CommandOpenTerminal through the
// production registration path rather than falling through to EventCommandFailed.
// A real TransportClient with an in-process eventCapture control plane is used —
// no mocks (Issue #2760).
//
// This guards against accidental removal of the RegisterOpenTerminalHandler call
// from setupCommandHandler, which would cause a controller-dispatched open_terminal
// command to silently produce EventCommandFailed with "no handler for command type".
func TestSetupCommandHandler_RegistersOpenTerminal(t *testing.T) {
	exec, err := execution.NewExecutor(&execution.ExecutorConfig{Logger: newTestLogger(t)})
	require.NoError(t, err)

	capture := newEventCapture()
	c := newMinimalClientWithCP(t, newTestSession(), exec, capture, "steward-open-term", "tenant-open-term")

	handler, err := c.setupCommandHandler(context.Background(), "steward-open-term")
	require.NoError(t, err)

	// No operator proof is attached: the command must reach the registered handler and
	// be refused with ErrUnauthenticatedCommand, not "no handler for command type".
	cmd := &cpTypes.SignedCommand{Command: cpTypes.Command{
		ID:        "cmd-open-term-1",
		Type:      cpTypes.CommandOpenTerminal,
		StewardID: "steward-open-term",
		TenantID:  "tenant-open-term",
		Timestamp: time.Now(),
		Params: map[string]interface{}{
			"session_id": "sess-2760-test",
			"shell":      "bash",
			"cols":       float64(80),
			"rows":       float64(24),
		},
	}}
	require.NoError(t, handler.HandleCommand(context.Background(), cmd))
	handler.Wait()

	events := drainEvents(capture.events)
	require.NotEmpty(t, events, "open_terminal dispatch must publish a status event")

	var failed *cpTypes.Event
	for _, evt := range events {
		require.NotEqualf(t, cpTypes.EventCommandCompleted, evt.Type, "an unproven open_terminal must not complete")
		if evt.Type == cpTypes.EventCommandFailed {
			failed = evt
		}
	}
	require.NotNil(t, failed, "open_terminal dispatch must publish EventCommandFailed")
	require.Equal(t, "cmd-open-term-1", failed.CommandID)
	require.Contains(t, fmt.Sprint(failed.Details), "unauthenticated")
	require.NotContains(t, fmt.Sprint(failed.Details), "no handler for command type")
}
