// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package client exercises the CommandReconnect handler registered in setupCommandHandler.
//
// Issue #1327: when the controller sends COMMAND_TYPE_RECONNECT, the steward must
// call controlPlane.Reconnect() to re-establish its ControlChannel against the new
// Raft leader.
package client

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/steward/execution"
	cpTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
)

// reconnectCapture embeds noopControlPlane and records each Reconnect() call
// by sending on a buffered channel — no mocking framework involved.
type reconnectCapture struct {
	noopControlPlane
	reconnected chan struct{}
}

func (r *reconnectCapture) Reconnect(_ context.Context) error {
	select {
	case r.reconnected <- struct{}{}:
	default:
	}
	return nil
}

// TestCommandReconnect_TriggersControlPlaneReconnect verifies that when the
// command handler receives a CommandReconnect, it calls controlPlane.Reconnect().
// Uses the same pattern as TestCommandSyncConfig_DNAUpdateCarriesConfigHash:
// a real TransportClient with an in-process provider — no mocks (Issue #1327).
func TestCommandReconnect_TriggersControlPlaneReconnect(t *testing.T) {
	exec, err := execution.NewExecutor(&execution.ExecutorConfig{Logger: newTestLogger(t)})
	require.NoError(t, err)

	capture := &reconnectCapture{reconnected: make(chan struct{}, 1)}

	c := newMinimalClientWithCP(t, newTestSession(), exec, capture, "steward-reconnect-test", "tenant-reconnect")

	handler, err := c.setupCommandHandler(context.Background(), "steward-reconnect-test")
	require.NoError(t, err)

	cmd := &cpTypes.SignedCommand{Command: cpTypes.Command{
		ID:        "cmd-reconnect-1",
		Type:      cpTypes.CommandReconnect,
		StewardID: "steward-reconnect-test",
		TenantID:  "tenant-reconnect",
		Timestamp: time.Now(),
	}}
	require.NoError(t, handler.HandleCommand(context.Background(), cmd))
	handler.Wait()

	select {
	case <-capture.reconnected:
		// Reconnect() was called — handler is wired correctly.
	case <-time.After(2 * time.Second):
		t.Fatal("controlPlane.Reconnect() was not called within 2s after CommandReconnect dispatch")
	}
}

// TestCommandReconnect_NilControlPlane verifies that the nil-guard in the
// CommandReconnect handler prevents a call to Reconnect() when controlPlane
// is nil. The handler must not panic and must not invoke Reconnect().
func TestCommandReconnect_NilControlPlane(t *testing.T) {
	exec, err := execution.NewExecutor(&execution.ExecutorConfig{Logger: newTestLogger(t)})
	require.NoError(t, err)

	// Start with a real reconnectCapture so we can observe whether Reconnect() is called.
	capture := &reconnectCapture{reconnected: make(chan struct{}, 1)}
	c := newMinimalClientWithCP(t, newTestSession(), exec, capture, "steward-nil-cp", "tenant-nil-cp")

	// Nil out the control plane to simulate the not-yet-connected state.
	c.mu.Lock()
	c.controlPlane = nil
	c.mu.Unlock()

	handler, err := c.setupCommandHandler(context.Background(), "steward-nil-cp")
	require.NoError(t, err)

	cmd := &cpTypes.SignedCommand{Command: cpTypes.Command{
		ID:        "cmd-reconnect-nil",
		Type:      cpTypes.CommandReconnect,
		StewardID: "steward-nil-cp",
		TenantID:  "tenant-nil-cp",
		Timestamp: time.Now(),
	}}
	// HandleCommand dispatches async; it returns nil after authentication passes.
	require.NoError(t, handler.HandleCommand(context.Background(), cmd))
	handler.Wait()

	// Reconnect() must NOT have been called — the nil guard prevents it.
	select {
	case <-capture.reconnected:
		t.Fatal("controlPlane.Reconnect() must not be called when controlPlane is nil")
	default:
		// Expected: nil guard prevented the reconnect call.
	}
}
