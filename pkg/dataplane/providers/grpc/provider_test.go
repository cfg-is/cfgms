// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package grpc

import (
	"bytes"
	"context"
	"crypto/tls"
	"net"
	"testing"

	transportpb "github.com/cfgis/cfgms/api/proto/transport"
	"github.com/cfgis/cfgms/pkg/dataplane/interfaces"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

// TestProvider_Registration verifies the provider registers itself as "grpc" via init().
func TestProvider_Registration(t *testing.T) {
	p := interfaces.GetProvider("grpc")
	require.NotNil(t, p, "grpc provider should be registered via init()")
	assert.Equal(t, "grpc", p.Name())
}

// TestProvider_Name verifies Name() returns "grpc".
func TestProvider_Name(t *testing.T) {
	p := New()
	assert.Equal(t, "grpc", p.Name())
}

// TestProvider_Description verifies Description() is non-empty.
func TestProvider_Description(t *testing.T) {
	p := New()
	assert.NotEmpty(t, p.Description())
}

// TestProvider_InitializeServer verifies server mode initialization with valid config.
func TestProvider_InitializeServer(t *testing.T) {
	p := New()
	err := p.Initialize(context.Background(), map[string]interface{}{
		"mode":        "server",
		"listen_addr": "127.0.0.1:0",
		"tls_config":  &tls.Config{MinVersion: tls.VersionTLS13}, //nolint:gosec // test config
	})
	require.NoError(t, err)
	assert.Equal(t, "server", p.mode)
	assert.Equal(t, "127.0.0.1:0", p.listenAddr)
}

// TestProvider_InitializeClient verifies client mode initialization with grpc_conn.
func TestProvider_InitializeClient(t *testing.T) {
	p := New()
	// Use a nil *grpc.ClientConn placeholder — the provider only checks for
	// key presence in Initialize; actual usage happens in Start/Connect.
	err := p.Initialize(context.Background(), map[string]interface{}{
		"mode":        "client",
		"server_addr": "127.0.0.1:4433",
		"tls_config":  &tls.Config{MinVersion: tls.VersionTLS13}, //nolint:gosec // test config
		"steward_id":  "steward-test",
	})
	require.NoError(t, err)
	assert.Equal(t, "client", p.mode)
	assert.Equal(t, "steward-test", p.stewardID)
}

// TestProvider_InitializeMissingMode verifies an error when mode is absent.
func TestProvider_InitializeMissingMode(t *testing.T) {
	p := New()
	err := p.Initialize(context.Background(), map[string]interface{}{
		"listen_addr": "127.0.0.1:0",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "mode")
}

// TestProvider_InitializeInvalidMode verifies an error for unknown mode strings.
func TestProvider_InitializeInvalidMode(t *testing.T) {
	p := New()
	err := p.Initialize(context.Background(), map[string]interface{}{
		"mode": "banana",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "mode")
}

// TestProvider_InitializeServerMissingAddr verifies an error when listen_addr is absent in server mode.
func TestProvider_InitializeServerMissingAddr(t *testing.T) {
	p := New()
	err := p.Initialize(context.Background(), map[string]interface{}{
		"mode":       "server",
		"tls_config": &tls.Config{MinVersion: tls.VersionTLS13}, //nolint:gosec // test config
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "listen_addr")
}

// TestProvider_InitializeClientMissingAddrAndConn verifies an error when neither
// server_addr nor grpc_conn is provided in client mode.
func TestProvider_InitializeClientMissingAddrAndConn(t *testing.T) {
	p := New()
	err := p.Initialize(context.Background(), map[string]interface{}{
		"mode":       "client",
		"tls_config": &tls.Config{MinVersion: tls.VersionTLS13}, //nolint:gosec // test config
		"steward_id": "steward-test",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "server_addr")
}

// TestProvider_Available_Uninitialized verifies Available returns false before init.
func TestProvider_Available_Uninitialized(t *testing.T) {
	p := New()
	ok, err := p.Available()
	assert.False(t, ok)
	require.Error(t, err)
}

// TestProvider_Available_Server verifies Available returns true after server init.
func TestProvider_Available(t *testing.T) {
	p := New()
	err := p.Initialize(context.Background(), map[string]interface{}{
		"mode":        "server",
		"listen_addr": "127.0.0.1:0",
		"tls_config":  &tls.Config{MinVersion: tls.VersionTLS13}, //nolint:gosec // test config
	})
	require.NoError(t, err)

	ok, err := p.Available()
	require.NoError(t, err)
	assert.True(t, ok)
}

// TestProvider_Stats verifies GetStats returns a correctly named stats struct.
func TestProvider_Stats(t *testing.T) {
	p := New()
	stats, err := p.GetStats(context.Background())
	require.NoError(t, err)
	require.NotNil(t, stats)
	assert.Equal(t, "grpc", stats.ProviderName)
	assert.Equal(t, 0, stats.ActiveSessions)
}

// TestProvider_StatsTracking verifies that AcceptConnection increments session counters.
func TestProvider_StatsTracking(t *testing.T) {
	p := New()
	err := p.Initialize(context.Background(), map[string]interface{}{
		"mode":        "server",
		"listen_addr": "127.0.0.1:0",
		"tls_config":  &tls.Config{MinVersion: tls.VersionTLS13}, //nolint:gosec // test config
	})
	require.NoError(t, err)

	// Manually mark as started and set up handler to avoid needing real QUIC
	p.started.Store(true)
	p.handler = newDataPlaneHandler()
	p.sessions = make(map[string]*Session)

	_, err = p.AcceptConnection(context.Background())
	require.NoError(t, err)

	stats, err := p.GetStats(context.Background())
	require.NoError(t, err)
	assert.Equal(t, int64(1), stats.TotalSessionsAccepted)
	assert.Equal(t, 1, stats.ActiveSessions)
}

// TestProvider_IsListening returns false before Start.
func TestProvider_IsListening(t *testing.T) {
	p := New()
	err := p.Initialize(context.Background(), map[string]interface{}{
		"mode":        "server",
		"listen_addr": "127.0.0.1:0",
		"tls_config":  &tls.Config{MinVersion: tls.VersionTLS13}, //nolint:gosec // test config
	})
	require.NoError(t, err)
	assert.False(t, p.IsListening(), "not listening before Start")
}

// TestProvider_IsConnected returns false before Start.
func TestProvider_IsConnected(t *testing.T) {
	p := New()
	err := p.Initialize(context.Background(), map[string]interface{}{
		"mode":        "client",
		"server_addr": "127.0.0.1:4433",
		"tls_config":  &tls.Config{MinVersion: tls.VersionTLS13}, //nolint:gosec // test config
		"steward_id":  "steward-test",
	})
	require.NoError(t, err)
	assert.False(t, p.IsConnected(), "not connected before Start")
}

// TestProvider_Handler_NilBeforeStart verifies Handler returns nil before Start.
func TestProvider_Handler_NilBeforeStart(t *testing.T) {
	p := New()
	err := p.Initialize(context.Background(), map[string]interface{}{
		"mode":        "server",
		"listen_addr": "127.0.0.1:0",
		"tls_config":  &tls.Config{MinVersion: tls.VersionTLS13}, //nolint:gosec // test config
	})
	require.NoError(t, err)
	assert.Nil(t, p.Handler(), "handler should be nil before Start")
}

// TestProvider_Handler_NonNilAfterStart verifies Handler returns non-nil after Start.
func TestProvider_Handler_NonNilAfterStart(t *testing.T) {
	p := New()
	err := p.Initialize(context.Background(), map[string]interface{}{
		"mode":        "server",
		"listen_addr": "127.0.0.1:0",
		"tls_config":  &tls.Config{MinVersion: tls.VersionTLS13}, //nolint:gosec // test config
	})
	require.NoError(t, err)

	// Manually mark as started and set up handler (avoids needing real QUIC)
	p.started.Store(true)
	p.handler = newDataPlaneHandler()

	handler := p.Handler()
	require.NotNil(t, handler, "Handler should return non-nil after Start")
}

// TestProvider_Handler_WithExternalServer verifies Handler works when using grpc_server config.
func TestProvider_Handler_WithExternalServer(t *testing.T) {
	p := New()
	err := p.Initialize(context.Background(), map[string]interface{}{
		"mode":        "server",
		"grpc_server": grpcNewServer(), // external server
	})
	require.NoError(t, err)
	assert.False(t, p.ownGRPCServer)

	// Manually start to create handler
	p.started.Store(true)
	p.handler = newDataPlaneHandler()

	handler := p.Handler()
	require.NotNil(t, handler)
}

func grpcNewServer() *grpc.Server {
	return grpc.NewServer()
}

// TestProvider_ServerOptions_Applied verifies that a gRPC server built with
// ServerOptions() actually rejects a message larger than 8 MB with
// codes.ResourceExhausted. Uses a plain TCP listener so no QUIC/mTLS is needed.
//
// The test would fail if maxRecvMsgSize were changed to a value > 9 MB because
// the 9 MB payload would no longer be rejected.
func TestProvider_ServerOptions_Applied(t *testing.T) {
	opts := ServerOptions()
	require.Len(t, opts, 5,
		"ServerOptions must return 5 options: MaxRecvMsgSize, MaxSendMsgSize, MaxConcurrentStreams, KeepaliveParams, KeepaliveEnforcementPolicy")

	// Start a real TCP gRPC server with the DoS limits applied.
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	srv := grpc.NewServer(opts...)
	transportpb.RegisterStewardTransportServer(srv, &dosLimitTestHandler{})
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.GracefulStop)

	conn, err := grpc.NewClient(lis.Addr().String(),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	client := transportpb.NewStewardTransportClient(conn)
	stream, err := client.SyncDNA(context.Background())
	require.NoError(t, err)

	// 9 MB is 1 MB over the 8 MB maxRecvMsgSize limit.
	sendErr := stream.Send(&transportpb.DNAChunk{
		StewardId: "dos-unit-test",
		Data:      bytes.Repeat([]byte("X"), 9*1024*1024),
	})
	if sendErr == nil {
		_, sendErr = stream.CloseAndRecv()
	}

	require.Error(t, sendErr, "server built with ServerOptions must reject messages > 8 MB")
	assert.Equal(t, codes.ResourceExhausted, status.Code(sendErr),
		"oversized message must yield codes.ResourceExhausted, got %v", sendErr)
}

// dosLimitTestHandler is a minimal StewardTransportServer that calls Recv()
// on the first SyncDNA message, triggering the gRPC MaxRecvMsgSize check.
// The handler returns the Recv error directly so gRPC propagates it to the client.
type dosLimitTestHandler struct {
	transportpb.UnimplementedStewardTransportServer
}

func (h *dosLimitTestHandler) SyncDNA(stream grpc.ClientStreamingServer[transportpb.DNAChunk, transportpb.DNASyncResponse]) error {
	_, err := stream.Recv()
	return err
}
