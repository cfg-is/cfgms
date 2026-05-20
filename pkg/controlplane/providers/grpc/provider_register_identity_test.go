// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz

package grpc

import (
	"context"
	"crypto/tls"
	"testing"

	commonpb "github.com/cfgis/cfgms/api/proto/common"
	controllerpb "github.com/cfgis/cfgms/api/proto/controller"
	transportpb "github.com/cfgis/cfgms/api/proto/transport"
	quictransport "github.com/cfgis/cfgms/pkg/transport/quic"
	"github.com/cfgis/cfgms/pkg/transport/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// dialAndRegister dials the server over QUIC+mTLS and invokes the Register RPC.
func dialAndRegister(t *testing.T, serverAddr string, clientTLS *tls.Config, req *controllerpb.RegisterRequest) (*controllerpb.RegisterResponse, error) {
	t.Helper()
	dialer := quictransport.NewDialer(clientTLS, nil)
	conn, err := grpc.NewClient(
		serverAddr,
		grpc.WithContextDialer(dialer),
		grpc.WithTransportCredentials(quictransport.TransportCredentials()),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	return transportpb.NewStewardTransportClient(conn).Register(context.Background(), req)
}

// TestRegister_NoPeerInfo_Unauthenticated verifies that Register() rejects a
// request when the gRPC context carries no peer/TLS info, returning
// codes.Unauthenticated.
func TestRegister_NoPeerInfo_Unauthenticated(t *testing.T) {
	t.Parallel()

	ts := &transportServer{provider: New(ModeServer)}
	req := &controllerpb.RegisterRequest{
		Version:     "1.0.0",
		Credentials: &commonpb.Credentials{ClientId: "steward-victim"},
	}

	_, err := ts.Register(context.Background(), req)
	require.Error(t, err)
	s, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Unauthenticated, s.Code())
}

// TestRegister_ImpersonationRejected is the impersonation regression test.
// A client whose mTLS cert CN is "steward-attacker" but who sends
// Credentials.ClientId="steward-victim" must register as "steward-attacker" —
// never as "steward-victim".
func TestRegister_ImpersonationRejected(t *testing.T) {
	t.Parallel()

	tc := newTestCA(t)
	reg := registry.NewRegistry()

	server := New(ModeServer)
	require.NoError(t, server.Initialize(context.Background(), map[string]interface{}{
		"mode":       "server",
		"addr":       "127.0.0.1:0",
		"tls_config": tc.serverTLSConfig(t),
		"registry":   reg,
	}))
	require.NoError(t, server.Start(context.Background()))
	t.Cleanup(server.ForceStop)

	// Client cert CN is "steward-attacker"; request claims to be "steward-victim".
	attackerTLS := tc.clientTLSConfig(t, "steward-attacker")
	resp, err := dialAndRegister(t, server.ListenAddr(), attackerTLS, &controllerpb.RegisterRequest{
		Version:     "1.0.0",
		Credentials: &commonpb.Credentials{ClientId: "steward-victim"},
	})

	require.NoError(t, err, "a valid mTLS cert should not be rejected")
	assert.Equal(t, "steward-attacker", resp.GetStewardId(),
		"identity must come from mTLS cert CN, not from caller-supplied Credentials.ClientId")
	assert.NotEqual(t, "steward-victim", resp.GetStewardId(),
		"impersonation must be blocked: result must never equal the forged ClientId")
}

// TestRegister_ValidCert_RegistersWithCNCertId verifies that a valid mTLS cert
// with CN "steward-abc" yields RegisterResponse.StewardId = "steward-abc".
func TestRegister_ValidCert_RegistersWithCNCertId(t *testing.T) {
	t.Parallel()

	tc := newTestCA(t)
	reg := registry.NewRegistry()

	server := New(ModeServer)
	require.NoError(t, server.Initialize(context.Background(), map[string]interface{}{
		"mode":       "server",
		"addr":       "127.0.0.1:0",
		"tls_config": tc.serverTLSConfig(t),
		"registry":   reg,
	}))
	require.NoError(t, server.Start(context.Background()))
	t.Cleanup(server.ForceStop)

	clientTLS := tc.clientTLSConfig(t, "steward-abc")
	resp, err := dialAndRegister(t, server.ListenAddr(), clientTLS, &controllerpb.RegisterRequest{
		Version: "1.0.0",
	})

	require.NoError(t, err)
	assert.Equal(t, "steward-abc", resp.GetStewardId())
	assert.Equal(t, commonpb.Status_OK, resp.GetStatus().GetCode())
}
