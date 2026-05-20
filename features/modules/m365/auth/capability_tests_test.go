// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package auth

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// buildTestJWT constructs a synthetic unsigned JWT for claim-extraction tests.
// The token follows the standard three-part header.payload.signature format with
// an empty signature, so no library validation is triggered.
func buildTestJWT(t *testing.T, claims map[string]interface{}) string {
	t.Helper()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	payloadJSON, err := json.Marshal(claims)
	require.NoError(t, err)
	payload := base64.RawURLEncoding.EncodeToString(payloadJSON)
	return header + "." + payload + "."
}

func newTestAuthFlow(t *testing.T) *InteractiveAuthFlow {
	t.Helper()
	return &InteractiveAuthFlow{
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}
}

func TestExtractUserContext(t *testing.T) {
	flow := newTestAuthFlow(t)

	t.Run("extracts all claims from valid JWT", func(t *testing.T) {
		token := buildTestJWT(t, map[string]interface{}{
			"oid":   "user-object-id-123",
			"upn":   "user@contoso.onmicrosoft.com",
			"tid":   "tenant-id-456",
			"roles": []string{"MSPAdmin", "DeviceManager"},
			"name":  "Test User",
		})

		ctx, err := flow.extractUserContext(token, "tenant-id-456")
		require.NoError(t, err)
		assert.Equal(t, "user-object-id-123", ctx.UserID)
		assert.Equal(t, "user@contoso.onmicrosoft.com", ctx.UserPrincipalName)
		assert.Equal(t, "Test User", ctx.DisplayName)
		assert.Equal(t, []string{"MSPAdmin", "DeviceManager"}, ctx.Roles)
		assert.False(t, ctx.LastAuthenticated.IsZero())
	})

	t.Run("returns error for empty token", func(t *testing.T) {
		_, err := flow.extractUserContext("", "tenant-id-456")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no ID token")
	})

	t.Run("returns error for malformed JWT with wrong part count", func(t *testing.T) {
		_, err := flow.extractUserContext("only.two", "tenant-id-456")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "malformed JWT")
	})

	t.Run("returns error for malformed JWT with too many parts", func(t *testing.T) {
		_, err := flow.extractUserContext("a.b.c.d.e", "tenant-id-456")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "malformed JWT")
	})

	t.Run("returns error for invalid base64 payload", func(t *testing.T) {
		_, err := flow.extractUserContext("header.!!!invalid!!!.signature", "tenant-id-456")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "malformed JWT")
	})

	t.Run("returns error for non-JSON payload", func(t *testing.T) {
		badPayload := base64.RawURLEncoding.EncodeToString([]byte("not-json"))
		token := "header." + badPayload + ".sig"
		_, err := flow.extractUserContext(token, "tenant-id-456")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "malformed JWT")
	})

	t.Run("returns error for missing oid claim", func(t *testing.T) {
		token := buildTestJWT(t, map[string]interface{}{
			"upn": "user@contoso.onmicrosoft.com",
			"tid": "tenant-id-456",
		})
		_, err := flow.extractUserContext(token, "tenant-id-456")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "oid")
	})

	t.Run("returns error for missing upn claim", func(t *testing.T) {
		token := buildTestJWT(t, map[string]interface{}{
			"oid": "user-object-id-123",
			"tid": "tenant-id-456",
		})
		_, err := flow.extractUserContext(token, "tenant-id-456")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "upn")
	})

	t.Run("returns error for missing tid claim", func(t *testing.T) {
		token := buildTestJWT(t, map[string]interface{}{
			"oid": "user-object-id-123",
			"upn": "user@contoso.onmicrosoft.com",
		})
		_, err := flow.extractUserContext(token, "tenant-id-456")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "tid")
	})

	t.Run("handles JWT with no roles claim", func(t *testing.T) {
		token := buildTestJWT(t, map[string]interface{}{
			"oid": "user-object-id-123",
			"upn": "user@contoso.onmicrosoft.com",
			"tid": "tenant-id-456",
		})
		ctx, err := flow.extractUserContext(token, "tenant-id-456")
		require.NoError(t, err)
		assert.Equal(t, "user-object-id-123", ctx.UserID)
		assert.Nil(t, ctx.Roles)
	})

	t.Run("returns error when tid does not match expected tenant", func(t *testing.T) {
		token := buildTestJWT(t, map[string]interface{}{
			"oid": "user-object-id-123",
			"upn": "user@contoso.onmicrosoft.com",
			"tid": "tenant-id-456",
		})
		_, err := flow.extractUserContext(token, "different-tenant-id")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "tid")
	})

	t.Run("accepts token when tenantID arg is empty", func(t *testing.T) {
		token := buildTestJWT(t, map[string]interface{}{
			"oid": "user-object-id-123",
			"upn": "user@contoso.onmicrosoft.com",
			"tid": "tenant-id-456",
		})
		ctx, err := flow.extractUserContext(token, "")
		require.NoError(t, err)
		assert.Equal(t, "user-object-id-123", ctx.UserID)
	})

	t.Run("handles JWT with empty roles array", func(t *testing.T) {
		token := buildTestJWT(t, map[string]interface{}{
			"oid":   "user-object-id-123",
			"upn":   "user@contoso.onmicrosoft.com",
			"tid":   "tenant-id-456",
			"roles": []string{},
		})
		ctx, err := flow.extractUserContext(token, "tenant-id-456")
		require.NoError(t, err)
		assert.Equal(t, "user-object-id-123", ctx.UserID)
		assert.Empty(t, ctx.Roles)
	})
}
