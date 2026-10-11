// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package auth

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func handshakePayload(t *testing.T, m365Tenant string, expiresAt time.Time) string {
	t.Helper()
	enc, err := EncodeHandshakeToken(&AccessToken{
		Token: "graph-token-value", TenantID: m365Tenant, TokenType: "Bearer", ExpiresAt: expiresAt, Scope: "s",
		RefreshToken: "must-not-travel",
	})
	require.NoError(t, err)
	return enc
}

func TestEncodeHandshakeToken_OnlyAllowedFields(t *testing.T) {
	enc := handshakePayload(t, "m365-tid", time.Now().Add(time.Hour))
	assert.NotContains(t, enc, "must-not-travel")
	assert.NotContains(t, enc, "refresh_token")
	assert.Contains(t, enc, `"tenant_id":"m365-tid"`)
	_, err := EncodeHandshakeToken(nil)
	assert.Error(t, err)
}

// [REQUIRED TEST] Issue #4891
func TestHandshakeTokenProvider_FailsClosed(t *testing.T) {
	ctx := context.Background()

	t.Run("happy path", func(t *testing.T) {
		p := NewHandshakeTokenProvider()
		require.NoError(t, p.Bind("client-1", handshakePayload(t, "m365-tid", time.Now().Add(time.Hour))))
		tok, err := p.GetAccessToken(ctx, "client-1")
		require.NoError(t, err)
		assert.Equal(t, "graph-token-value", tok.Token)
		assert.Equal(t, "m365-tid", tok.TenantID)
		assert.True(t, p.IsTokenValid(tok))
	})

	t.Run("other tenant", func(t *testing.T) {
		p := NewHandshakeTokenProvider()
		require.NoError(t, p.Bind("client-1", handshakePayload(t, "m365-tid", time.Now().Add(time.Hour))))
		_, err := p.GetAccessToken(ctx, "client-2")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "client-2")
		assert.NotContains(t, err.Error(), "graph-token-value")
	})

	t.Run("expired", func(t *testing.T) {
		p := NewHandshakeTokenProvider()
		require.NoError(t, p.Bind("client-1", handshakePayload(t, "m365-tid", time.Now().Add(-time.Hour))))
		_, err := p.GetAccessToken(ctx, "client-1")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "client-1")
		assert.Contains(t, err.Error(), "expired")
	})

	t.Run("no token delivered", func(t *testing.T) {
		p := NewHandshakeTokenProvider()
		require.NoError(t, p.Bind("client-1", ""))
		_, err := p.GetAccessToken(ctx, "client-1")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "client-1")
		assert.Contains(t, err.Error(), "No M365 credential was delivered")
	})

	t.Run("unbound", func(t *testing.T) {
		_, err := NewHandshakeTokenProvider().GetAccessToken(ctx, "client-1")
		require.Error(t, err)
	})

	t.Run("malformed credential", func(t *testing.T) {
		p := NewHandshakeTokenProvider()
		err := p.Bind("client-1", "{not json")
		require.Error(t, err)
		assert.NotContains(t, err.Error(), "not json")
	})

	t.Run("malformed repeat handshake keeps the delivered credential", func(t *testing.T) {
		p := NewHandshakeTokenProvider()
		require.NoError(t, p.Bind("client-1", handshakePayload(t, "m365-tid", time.Now().Add(time.Hour))))
		require.Error(t, p.Bind("client-1", "{broken"))
		tok, err := p.GetAccessToken(ctx, "client-1")
		require.NoError(t, err)
		assert.Equal(t, "graph-token-value", tok.Token)
	})

	t.Run("unsupported methods", func(t *testing.T) {
		p := NewHandshakeTokenProvider()
		_, err := p.GetDelegatedAccessToken(ctx, "client-1", &UserContext{})
		assert.ErrorContains(t, err, "not supported in a workflow module")
		_, err = p.RefreshToken(ctx, "r")
		assert.ErrorContains(t, err, "not supported in a workflow module")
		_, err = p.RefreshDelegatedToken(ctx, "r", &UserContext{})
		assert.ErrorContains(t, err, "not supported in a workflow module")
		assert.NoError(t, p.ValidatePermissions(ctx, &AccessToken{}, nil))
	})
}
