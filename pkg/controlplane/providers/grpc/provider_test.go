// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz

package grpc

import (
	"context"
	"testing"
	"time"

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
