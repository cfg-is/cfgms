// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz

package grpc

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"testing"

	commonpb "github.com/cfgis/cfgms/api/proto/common"
	controllerpb "github.com/cfgis/cfgms/api/proto/controller"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

// newPeerCtxWithCN creates a context with peer info containing a real TLS certificate
// with the given CN, signed by the provided test CA.
func newPeerCtxWithCN(t *testing.T, tc *testCA, cn string) context.Context {
	t.Helper()
	clientTLS := tc.clientTLSConfig(t, cn)

	cert, err := x509.ParseCertificate(clientTLS.Certificates[0].Certificate[0])
	require.NoError(t, err)

	tlsState := tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{cert},
	}
	p := &peer.Peer{
		AuthInfo: credentials.TLSInfo{State: tlsState},
	}
	return peer.NewContext(context.Background(), p)
}

func TestRegister_MatchingCNAndClientId_Succeeds(t *testing.T) {
	tc := newTestCA(t)
	ctx := newPeerCtxWithCN(t, tc, "steward-match")

	s := &transportServer{provider: New(ModeServer)}

	resp, err := s.Register(ctx, &controllerpb.RegisterRequest{
		Version: "v0.1.0",
		Credentials: &commonpb.Credentials{
			ClientId: "steward-match",
		},
	})

	require.NoError(t, err)
	assert.Equal(t, "steward-match", resp.GetStewardId())
	assert.Equal(t, commonpb.Status_OK, resp.GetStatus().GetCode())
}

func TestRegister_MismatchedCNAndClientId_ReturnsPermissionDenied(t *testing.T) {
	tc := newTestCA(t)
	ctx := newPeerCtxWithCN(t, tc, "steward-real")

	s := &transportServer{provider: New(ModeServer)}

	_, err := s.Register(ctx, &controllerpb.RegisterRequest{
		Version: "v0.1.0",
		Credentials: &commonpb.Credentials{
			ClientId: "steward-imposter",
		},
	})

	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

func TestRegister_EmptyClientId_DerivesFromCN_Succeeds(t *testing.T) {
	tc := newTestCA(t)
	ctx := newPeerCtxWithCN(t, tc, "steward-cn-only")

	s := &transportServer{provider: New(ModeServer)}

	resp, err := s.Register(ctx, &controllerpb.RegisterRequest{
		Version: "v0.1.0",
	})

	require.NoError(t, err)
	assert.Equal(t, "steward-cn-only", resp.GetStewardId())
	assert.Equal(t, commonpb.Status_OK, resp.GetStatus().GetCode())
}

func TestRegister_NoPeerInfo_ReturnsUnauthenticated(t *testing.T) {
	s := &transportServer{provider: New(ModeServer)}

	_, err := s.Register(context.Background(), &controllerpb.RegisterRequest{
		Version: "v0.1.0",
		Credentials: &commonpb.Credentials{
			ClientId: "any-steward",
		},
	})

	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}

func TestRegister_PeerWithNoCertificates_ReturnsUnauthenticated(t *testing.T) {
	// Peer context present with TLSInfo but no client certificate presented.
	tlsState := tls.ConnectionState{} // PeerCertificates is nil/empty
	p := &peer.Peer{
		AuthInfo: credentials.TLSInfo{State: tlsState},
	}
	ctx := peer.NewContext(context.Background(), p)

	s := &transportServer{provider: New(ModeServer)}

	_, err := s.Register(ctx, &controllerpb.RegisterRequest{
		Version: "v0.1.0",
	})

	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}

func TestRegister_PeerWithEmptyCN_ReturnsUnauthenticated(t *testing.T) {
	// Peer context present with a certificate that has an empty Common Name.
	tc := newTestCA(t)
	clientTLS := tc.clientTLSConfig(t, "steward-valid")

	cert, err := x509.ParseCertificate(clientTLS.Certificates[0].Certificate[0])
	require.NoError(t, err)

	// Clear the CN to simulate a cert with no CN.
	cert.Subject.CommonName = ""

	tlsState := tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{cert},
	}
	p := &peer.Peer{
		AuthInfo: credentials.TLSInfo{State: tlsState},
	}
	ctx := peer.NewContext(context.Background(), p)

	s := &transportServer{provider: New(ModeServer)}

	_, err = s.Register(ctx, &controllerpb.RegisterRequest{
		Version: "v0.1.0",
	})

	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}
