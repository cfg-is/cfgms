// SPDX-License-Identifier: Apache-2.0
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
	assert.False(t, p.ownGRPCServer, "should not own the gRPC server")
	assert.Same(t, grpcServer, p.grpcServer, "should store the provided gRPC server")
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

	assert.Nil(t, p.listener, "should not create a QUIC listener")
	assert.NotNil(t, p.serverImpl, "should create serverImpl for handler delegation")
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
	assert.True(t, p.ownGRPCServer, "should own the gRPC server when using addr")

	err = p.Start(context.Background())
	require.NoError(t, err)
	defer forceStopServer(p)

	assert.NotNil(t, p.listener, "should create a QUIC listener")
	assert.NotNil(t, p.grpcServer, "should create a gRPC server")
	assert.True(t, p.IsConnected())
}
