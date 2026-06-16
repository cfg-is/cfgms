// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package grpc

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/cfgis/cfgms/pkg/controlplane/types"
	"github.com/cfgis/cfgms/pkg/transport/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// captureHook is a StewardOnConnectHook that records every stewardID it is called with.
type captureHook struct {
	mu        sync.Mutex
	called    []string
	returnErr error
}

func (h *captureHook) OnConnect(_ context.Context, stewardID string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.called = append(h.called, stewardID)
	return h.returnErr
}

func (h *captureHook) CalledWith() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]string, len(h.called))
	copy(out, h.called)
	return out
}

// newTestEnvWithOnConnectHook creates a server+client pair with the given hook injected.
func newTestEnvWithOnConnectHook(t *testing.T, stewardID string, hook StewardOnConnectHook) (*Provider, registry.Registry) {
	t.Helper()

	serverTLS, clientTLS := newTestTLSConfigs(t, stewardID)
	reg := registry.NewRegistry()

	server := New(ModeServer, WithOnConnectHook(hook))
	require.NoError(t, server.Initialize(context.Background(), map[string]interface{}{
		"mode":       "server",
		"addr":       "127.0.0.1:0",
		"tls_config": serverTLS,
		"registry":   reg,
	}))
	require.NoError(t, server.Start(context.Background()))
	t.Cleanup(server.ForceStop)

	client := New(ModeClient)
	require.NoError(t, client.Initialize(context.Background(), map[string]interface{}{
		"mode":       "client",
		"addr":       server.ListenAddr(),
		"tls_config": clientTLS,
		"steward_id": stewardID,
	}))
	require.NoError(t, client.Start(context.Background()))
	t.Cleanup(func() { _ = client.Stop(context.Background()) })

	require.Eventually(t, func() bool {
		_, ok := reg.Get(stewardID)
		return ok
	}, 5*time.Second, 10*time.Millisecond, "steward should be registered before proceeding")

	return server, reg
}

// TestOnConnectHookCalledOnConnect verifies that the hook is invoked with the
// correct stewardID after a steward successfully opens a ControlChannel.
func TestOnConnectHookCalledOnConnect(t *testing.T) {
	t.Parallel()
	const stewardID = "steward-hook-called"
	hook := &captureHook{}

	_, _ = newTestEnvWithOnConnectHook(t, stewardID, hook)

	require.Eventually(t, func() bool {
		called := hook.CalledWith()
		for _, id := range called {
			if id == stewardID {
				return true
			}
		}
		return false
	}, 5*time.Second, 10*time.Millisecond, "hook should be called with stewardID")
}

// TestOnConnectHookErrorDoesNotTearDownStream verifies that an error returned by
// the hook is logged but does not terminate the ControlChannel stream.
func TestOnConnectHookErrorDoesNotTearDownStream(t *testing.T) {
	t.Parallel()
	const stewardID = "steward-hook-error"
	hook := &captureHook{returnErr: errors.New("hook failure")}

	server, reg := newTestEnvWithOnConnectHook(t, stewardID, hook)

	// Steward should still be registered (stream is alive).
	require.Eventually(t, func() bool {
		_, ok := reg.Get(stewardID)
		return ok
	}, 5*time.Second, 10*time.Millisecond, "steward should remain registered after hook error")

	// Hook was still called despite returning an error.
	assert.Contains(t, hook.CalledWith(), stewardID, "hook should have been called")

	// Controller can still send commands on the live stream.
	sc := &types.SignedCommand{
		Command: types.Command{
			ID:        "post-hook-error-cmd",
			Type:      types.CommandSyncConfig,
			StewardID: stewardID,
		},
	}
	assert.NoError(t, server.SendCommand(context.Background(), sc), "stream should still accept commands after hook error")
}

// TestWithOnConnectHook_OptionSetsField verifies that WithOnConnectHook correctly
// wires the hook into the Provider struct field.
func TestWithOnConnectHook_OptionSetsField(t *testing.T) {
	t.Parallel()
	hook := &captureHook{}
	p := New(ModeServer, WithOnConnectHook(hook))
	assert.Equal(t, StewardOnConnectHook(hook), p.onConnectHook)
}

// TestOnConnectHookNotCalledWhenNil verifies that a nil hook is a no-op and the
// ControlChannel handler does not panic.
func TestOnConnectHookNotCalledWhenNil(t *testing.T) {
	t.Parallel()
	// newTestEnv creates a server with no hook (default nil).
	env := newTestEnv(t, "steward-no-hook")
	_, ok := env.registry.Get("steward-no-hook")
	assert.True(t, ok, "steward should be admitted when no hook is set")
}
