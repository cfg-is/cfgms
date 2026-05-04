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

	client := New(ModeClient)
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
