// SPDX-License-Identifier: Apache-2.0
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

// TestCommandReconnect_NilControlPlane verifies that the handler returns an error
// rather than panicking when controlPlane is nil at dispatch time.
func TestCommandReconnect_NilControlPlane(t *testing.T) {
	exec, err := execution.NewExecutor(&execution.ExecutorConfig{Logger: newTestLogger(t)})
	require.NoError(t, err)

	// Create client with no control plane set.
	c := &TransportClient{
		stewardID:        "steward-nil-cp",
		tenantID:         "tenant-nil-cp",
		heartbeatStop:    make(chan struct{}),
		convergenceStop:  make(chan struct{}),
		convergeInterval: 30 * time.Minute,
		logger:           newTestLogger(t),
	}
	c.mu.Lock()
	c.configExecutor = exec
	// controlPlane intentionally left nil
	c.dataPlaneSession = newTestSession()
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
	// HandleCommand must not panic — the handler returns an error internally
	// and executeCommand logs it without propagating to the caller.
	require.NoError(t, handler.HandleCommand(context.Background(), cmd))
	handler.Wait()
	// If we reach here without panic, the nil-guard test passes.
}
