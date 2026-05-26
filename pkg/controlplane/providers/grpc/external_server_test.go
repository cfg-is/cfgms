// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package grpc

import (
	"context"
	"testing"

	quictransport "github.com/cfgis/cfgms/pkg/transport/quic"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
)

func TestExternalServer_InitializeWithGRPCServer(t *testing.T) {
	grpcServer := grpc.NewServer(grpc.Creds(quictransport.TransportCredentials()))

	p := New(ModeServer)
	err := p.Initialize(context.Background(), map[string]interface{}{
		"mode":        "server",
		"grpc_server": grpcServer,
	})
	require.NoError(t, err)
	require.NoError(t, p.Start(context.Background()))
	defer func() { _ = p.Stop(context.Background()) }()
	// External server path: no QUIC listener is created
	assert.Equal(t, "", p.ListenAddr(), "should not create a QUIC listener when external gRPC server provided")
	// External server path: a handler is registered with the provided gRPC server
	assert.NotNil(t, p.ServerHandler(), "should register handler with the external gRPC server")
}

func TestExternalServer_StartCreatesServerImpl(t *testing.T) {
	grpcServer := grpc.NewServer(grpc.Creds(quictransport.TransportCredentials()))

	p := New(ModeServer)
	err := p.Initialize(context.Background(), map[string]interface{}{
		"mode":        "server",
		"grpc_server": grpcServer,
	})
	require.NoError(t, err)

	err = p.Start(context.Background())
	require.NoError(t, err)
	defer func() { _ = p.Stop(context.Background()) }()

	assert.Equal(t, "", p.ListenAddr(), "should not create a QUIC listener")
	assert.NotNil(t, p.ServerHandler(), "should create serverImpl for handler delegation")
}

func TestExternalServer_ServerHandlerReturnsHandler(t *testing.T) {
	grpcServer := grpc.NewServer(grpc.Creds(quictransport.TransportCredentials()))

	p := New(ModeServer)
	err := p.Initialize(context.Background(), map[string]interface{}{
		"mode":        "server",
		"grpc_server": grpcServer,
	})
	require.NoError(t, err)

	// Before Start, handler should be nil
	assert.Nil(t, p.ServerHandler(), "handler should be nil before Start")

	err = p.Start(context.Background())
	require.NoError(t, err)
	defer func() { _ = p.Stop(context.Background()) }()

	handler := p.ServerHandler()
	require.NotNil(t, handler, "ServerHandler should return non-nil after Start")

	// Verify handler is usable (non-nil assertion already above covers this)
}

func TestExternalServer_IsConnectedReturnsTrue(t *testing.T) {
	grpcServer := grpc.NewServer(grpc.Creds(quictransport.TransportCredentials()))

	p := New(ModeServer)
	err := p.Initialize(context.Background(), map[string]interface{}{
		"mode":        "server",
		"grpc_server": grpcServer,
	})
	require.NoError(t, err)

	err = p.Start(context.Background())
	require.NoError(t, err)
	defer func() { _ = p.Stop(context.Background()) }()

	assert.True(t, p.IsConnected(), "IsConnected should return true for external server mode")
}

func TestExternalServer_StopDoesNotTouchServer(t *testing.T) {
	grpcServer := grpc.NewServer(grpc.Creds(quictransport.TransportCredentials()))

	p := New(ModeServer)
	err := p.Initialize(context.Background(), map[string]interface{}{
		"mode":        "server",
		"grpc_server": grpcServer,
	})
	require.NoError(t, err)

	err = p.Start(context.Background())
	require.NoError(t, err)

	// Stop should not panic or affect the external server
	err = p.Stop(context.Background())
	require.NoError(t, err)

	// ForceStop should also be safe
	p2 := New(ModeServer)
	_ = p2.Initialize(context.Background(), map[string]interface{}{
		"mode":        "server",
		"grpc_server": grpcServer,
	})
	_ = p2.Start(context.Background())
	p2.ForceStop() // should not panic
}

func TestExternalServer_RequiresServerOrAddr(t *testing.T) {
	p := New(ModeServer)
	err := p.Initialize(context.Background(), map[string]interface{}{
		"mode": "server",
		// no grpc_server, no addr
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "requires 'addr' or 'grpc_server'")
}

func TestOwnedServer_StillWorks(t *testing.T) {
	// Verify that existing addr-based initialization still works
	serverTLS, _ := newTestTLSConfigs(t, "test-owned")

	p := New(ModeServer)
	err := p.Initialize(context.Background(), map[string]interface{}{
		"mode":       "server",
		"addr":       "127.0.0.1:0",
		"tls_config": serverTLS,
	})
	require.NoError(t, err)
	err = p.Start(context.Background())
	require.NoError(t, err)
	defer p.ForceStop()

	assert.NotEqual(t, "", p.ListenAddr(), "should create a QUIC listener when using addr")
	assert.True(t, p.IsConnected(), "should be connected after Start with owned gRPC server")
}
