// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package grpc

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/controlplane/interfaces"
)

// startCallbackClient starts a client against server with the identity-rejected
// callback installed, returning the provider.
func startCallbackClient(t *testing.T, env *revocationEnv, addr, stewardID string, onRejected func(error)) (*Provider, string) {
	t.Helper()
	tlsCfg, serial := env.clientTLS(t, stewardID)
	client := New(ModeClient, WithOnIdentityRejected(onRejected))
	require.NoError(t, client.Initialize(context.Background(), map[string]interface{}{
		"mode": "client", "addr": addr, "tls_config": tlsCfg, "steward_id": stewardID,
	}))
	t.Cleanup(func() { _ = client.Stop(context.Background()) })
	require.NoError(t, client.Start(context.Background()))
	return client, serial
}

// A mid-session revocation fires the callback exactly once for the episode even
// though the reconnect loop keeps being refused.
func TestOnIdentityRejected_FiresOncePerEpisode(t *testing.T) {
	t.Parallel()
	env := newRevocationEnv(t)
	server, reg := env.startServer(t,
		WithRevocationChecker(env.mgr), WithRevocationRecheckInterval(50*time.Millisecond))

	var fired atomic.Int32
	causes := make(chan error, 8)
	_, serial := startCallbackClient(t, env, server.ListenAddr(), "steward-cb", func(cause error) {
		fired.Add(1)
		causes <- cause
	})
	require.Eventually(t, func() bool { _, ok := reg.Get("steward-cb"); return ok },
		5*time.Second, 10*time.Millisecond)
	assert.Zero(t, fired.Load(), "an admitted steward must not report a rejection")

	require.NoError(t, env.mgr.Revoke(serial))

	select {
	case cause := <-causes:
		require.Error(t, cause)
	case <-time.After(10 * time.Second):
		t.Fatal("callback did not fire after the serial was revoked")
	}

	// The reconnect loop retries against the refusing server; none of those
	// further refusals may re-fire the callback.
	require.Never(t, func() bool { return fired.Load() > 1 },
		4*time.Second, 50*time.Millisecond, "callback must not fire once per reconnect attempt")
}

// An explicit Reconnect (new credentials) starts a new episode, so a refusal of
// the new credentials is reported again.
func TestOnIdentityRejected_ReconnectStartsNewEpisode(t *testing.T) {
	t.Parallel()
	env := newRevocationEnv(t)
	server, reg := env.startServer(t,
		WithRevocationChecker(env.mgr), WithRevocationRecheckInterval(50*time.Millisecond))

	var fired atomic.Int32
	client, serial := startCallbackClient(t, env, server.ListenAddr(), "steward-cb2", func(error) { fired.Add(1) })
	require.Eventually(t, func() bool { _, ok := reg.Get("steward-cb2"); return ok },
		5*time.Second, 10*time.Millisecond)
	require.NoError(t, env.mgr.Revoke(serial))
	require.Eventually(t, func() bool { return fired.Load() == 1 }, 10*time.Second, 20*time.Millisecond)
	assert.True(t, client.IdentityRejectionActive())

	require.NoError(t, client.Reconnect(context.Background()))
	require.Eventually(t, func() bool { return fired.Load() == 2 }, 20*time.Second, 20*time.Millisecond,
		"a refusal after an explicit Reconnect is a new episode")
}

func TestOnIdentityRejected_NilCallbackIsSafe(t *testing.T) {
	t.Parallel()
	env := newRevocationEnv(t)
	server, _ := env.startServer(t,
		WithRevocationChecker(env.mgr), WithRevocationRecheckInterval(50*time.Millisecond))
	tlsCfg, serial := env.clientTLS(t, "steward-nocb")
	client, err := startRevocationClient(t, server.ListenAddr(), tlsCfg, "steward-nocb", 0)
	require.NoError(t, err)
	require.NoError(t, env.mgr.Revoke(serial))
	require.Eventually(t, client.IdentityRejectionActive, 10*time.Second, 20*time.Millisecond)
	assert.ErrorIs(t, client.rejectErr, interfaces.ErrIdentityRejected)
}
