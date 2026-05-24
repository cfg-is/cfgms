// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package grpc

import (
	"context"
	"crypto/tls"
	"fmt"
	"sync"
	"testing"
	"time"

	commonpb "github.com/cfgis/cfgms/api/proto/common"
	controllerpb "github.com/cfgis/cfgms/api/proto/controller"
	transportpb "github.com/cfgis/cfgms/api/proto/transport"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	quictransport "github.com/cfgis/cfgms/pkg/transport/quic"
	"github.com/cfgis/cfgms/pkg/transport/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// inMemoryTokenStore is a real in-memory RegistrationTokenStore for tests.
// It implements the full interface with proper save/retrieve semantics.
type inMemoryTokenStore struct {
	mu     sync.RWMutex
	tokens map[string]*business.RegistrationTokenData
}

func newInMemoryTokenStore() *inMemoryTokenStore {
	return &inMemoryTokenStore{tokens: make(map[string]*business.RegistrationTokenData)}
}

func (s *inMemoryTokenStore) SaveToken(_ context.Context, token *business.RegistrationTokenData) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tokens[token.Token] = token
	return nil
}

func (s *inMemoryTokenStore) GetToken(_ context.Context, tokenStr string) (*business.RegistrationTokenData, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	token, ok := s.tokens[tokenStr]
	if !ok {
		return nil, fmt.Errorf("token not found: %q", tokenStr)
	}
	return token, nil
}

func (s *inMemoryTokenStore) UpdateToken(_ context.Context, token *business.RegistrationTokenData) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tokens[token.Token] = token
	return nil
}

func (s *inMemoryTokenStore) DeleteToken(_ context.Context, tokenStr string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.tokens, tokenStr)
	return nil
}

func (s *inMemoryTokenStore) ListTokens(_ context.Context, filter *business.RegistrationTokenFilter) ([]*business.RegistrationTokenData, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var result []*business.RegistrationTokenData
	for _, t := range s.tokens {
		if filter != nil && filter.TenantID != "" && t.TenantID != filter.TenantID {
			continue
		}
		result = append(result, t)
	}
	return result, nil
}

func (s *inMemoryTokenStore) RotateToken(_ context.Context, tenantID, group string) (*business.RegistrationTokenData, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, t := range s.tokens {
		if t.TenantID == tenantID && t.Group == group && !t.Revoked {
			now := time.Now()
			t.Revoked = true
			t.RevokedAt = &now
		}
	}
	newTok := &business.RegistrationTokenData{
		Token:     fmt.Sprintf("rotated-%d", len(s.tokens)),
		TenantID:  tenantID,
		Group:     group,
		CreatedAt: time.Now(),
	}
	s.tokens[newTok.Token] = newTok
	return newTok, nil
}

func (s *inMemoryTokenStore) Initialize(_ context.Context) error { return nil }
func (s *inMemoryTokenStore) Close() error                       { return nil }

// compile-time assertion
var _ business.RegistrationTokenStore = (*inMemoryTokenStore)(nil)

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

// newServerWithTokenStore creates a server with a real in-memory RegistrationTokenStore injected.
func newServerWithTokenStore(t *testing.T, tc *testCA, ts business.RegistrationTokenStore) *Provider {
	t.Helper()
	reg := registry.NewRegistry()
	server := New(ModeServer)
	require.NoError(t, server.Initialize(context.Background(), map[string]interface{}{
		"mode":                     "server",
		"addr":                     "127.0.0.1:0",
		"tls_config":               tc.serverTLSConfig(t),
		"registry":                 reg,
		"registration_token_store": ts,
	}))
	require.NoError(t, server.Start(context.Background()))
	t.Cleanup(server.ForceStop)
	return server
}

// TestRegister_TenantMismatch_PermissionDenied verifies that when the registration
// token (creds.ClientId) maps to tenant X on the server but creds.TenantId claims
// tenant Y (Y≠X), Register() returns codes.PermissionDenied.
func TestRegister_TenantMismatch_PermissionDenied(t *testing.T) {
	t.Parallel()

	tc := newTestCA(t)
	ts := newInMemoryTokenStore()
	require.NoError(t, ts.SaveToken(context.Background(), &business.RegistrationTokenData{
		Token:    "token-tenant-x",
		TenantID: "tenant-x",
	}))

	server := newServerWithTokenStore(t, tc, ts)

	_, err := dialAndRegister(t, server.ListenAddr(), tc.clientTLSConfig(t, "steward-tenant-test"), &controllerpb.RegisterRequest{
		Version: "1.0.0",
		Credentials: &commonpb.Credentials{
			ClientId: "token-tenant-x", // server resolves this to tenant-x
			TenantId: "tenant-y",       // claimed tenant does not match
		},
	})

	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.PermissionDenied, st.Code(),
		"tenant mismatch: token maps to tenant-x but creds.TenantId claims tenant-y")
}

// TestRegister_EmptyTenantId_PermissionDenied verifies that an empty creds.TenantId
// is rejected with codes.PermissionDenied when a token store is wired in.
func TestRegister_EmptyTenantId_PermissionDenied(t *testing.T) {
	t.Parallel()

	tc := newTestCA(t)
	ts := newInMemoryTokenStore()
	require.NoError(t, ts.SaveToken(context.Background(), &business.RegistrationTokenData{
		Token:    "token-any",
		TenantID: "some-tenant",
	}))

	server := newServerWithTokenStore(t, tc, ts)

	_, err := dialAndRegister(t, server.ListenAddr(), tc.clientTLSConfig(t, "steward-empty-tenant"), &controllerpb.RegisterRequest{
		Version: "1.0.0",
		Credentials: &commonpb.Credentials{
			ClientId: "token-any",
			TenantId: "", // empty — must be rejected
		},
	})

	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.PermissionDenied, st.Code(), "empty creds.TenantId must be rejected")
}

// TestRegister_NoRegistrationToken_Rejected verifies that a registration with no token
// (empty creds.ClientId) or an invalid/unknown token is rejected and does NOT fall
// through to tenant "default".
func TestRegister_NoRegistrationToken_Rejected(t *testing.T) {
	t.Parallel()

	tc := newTestCA(t)
	ts := newInMemoryTokenStore()
	// No tokens seeded: any lookup will fail.

	server := newServerWithTokenStore(t, tc, ts)

	t.Run("no token in creds", func(t *testing.T) {
		_, err := dialAndRegister(t, server.ListenAddr(), tc.clientTLSConfig(t, "steward-no-token"), &controllerpb.RegisterRequest{
			Version: "1.0.0",
			Credentials: &commonpb.Credentials{
				TenantId: "some-tenant",
				ClientId: "", // no registration token
			},
		})
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.PermissionDenied, st.Code(),
			"registration without a token must be rejected, not silently accepted as tenant 'default'")
	})

	t.Run("invalid token not in store", func(t *testing.T) {
		_, err := dialAndRegister(t, server.ListenAddr(), tc.clientTLSConfig(t, "steward-bad-token"), &controllerpb.RegisterRequest{
			Version: "1.0.0",
			Credentials: &commonpb.Credentials{
				TenantId: "some-tenant",
				ClientId: "nonexistent-token-xyz",
			},
		})
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.PermissionDenied, st.Code(),
			"registration with an invalid token must be rejected, not silently accepted as tenant 'default'")
	})
}

// TestRegister_ValidTokenAndTenant_Succeeds verifies the happy-path through the
// tenant-binding gate: a valid mTLS cert + a token seeded in the store + a
// creds.TenantId that matches tokenData.TenantID → codes.OK with the mTLS CN
// as the returned StewardId.
func TestRegister_ValidTokenAndTenant_Succeeds(t *testing.T) {
	t.Parallel()

	tc := newTestCA(t)
	ts := newInMemoryTokenStore()
	require.NoError(t, ts.SaveToken(context.Background(), &business.RegistrationTokenData{
		Token:    "valid-token-abc",
		TenantID: "tenant-z",
	}))

	server := newServerWithTokenStore(t, tc, ts)

	resp, err := dialAndRegister(t, server.ListenAddr(), tc.clientTLSConfig(t, "steward-z"), &controllerpb.RegisterRequest{
		Version: "1.0.0",
		Credentials: &commonpb.Credentials{
			ClientId: "valid-token-abc",
			TenantId: "tenant-z",
		},
	})

	require.NoError(t, err, "valid token + matching tenant must be accepted")
	assert.Equal(t, "steward-z", resp.GetStewardId(),
		"StewardId must come from the mTLS cert CN, not from creds")
	assert.Equal(t, commonpb.Status_OK, resp.GetStatus().GetCode(),
		"response status must be OK")
}
