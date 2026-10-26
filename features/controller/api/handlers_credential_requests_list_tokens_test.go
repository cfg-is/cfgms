// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// listEnrolmentTokensAs issues GET /api/v1/enrolment-tokens with an API key.
func listEnrolmentTokensAs(t *testing.T, server *Server, apiKey string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("GET", "/api/v1/enrolment-tokens", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)
	return rec
}

func decodeEnrolmentTokenList(t *testing.T, rec *httptest.ResponseRecorder) []EnrolmentTokenResponse {
	t.Helper()
	var resp struct {
		Data []EnrolmentTokenResponse `json:"data"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	return resp.Data
}

// [REQUIRED TEST]
func TestListEnrolmentTokens_NeverReturnsSecret(t *testing.T) {
	server := setupTestServer(t)
	minted := mintTestEnrolmentToken(t, server, "test-tenant")
	require.NotEmpty(t, minted.Token)
	stored, err := server.getEnrolmentTokenByID(context.Background(), minted.ID)
	require.NoError(t, err)
	require.NotNil(t, stored)
	require.NotEmpty(t, stored.TokenHash)

	key := NewTestKey(t, server, []string{"enrolment-token:list"})
	rec := listEnrolmentTokensAs(t, server, key)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	body := rec.Body.String()
	assert.NotContains(t, body, minted.Token)
	assert.NotContains(t, body, stored.TokenHash)
	assert.NotContains(t, body, `"token":`)

	rows := decodeEnrolmentTokenList(t, rec)
	require.Len(t, rows, 1)
	assert.Equal(t, minted.ID, rows[0].ID)
	assert.Equal(t, minted.TokenPrefix, rows[0].TokenPrefix)
	assert.Equal(t, "test-tenant", rows[0].TenantID)
	assert.NotEmpty(t, rows[0].CreatedBy)
	assert.NotEmpty(t, rows[0].CreatedAt)
	assert.NotEmpty(t, rows[0].ExpiresAt)
	assert.Equal(t, enrolmentTokenStatusActive, rows[0].Status)
	assert.Nil(t, rows[0].SpentAt)
}

// [REQUIRED TEST]
func TestListEnrolmentTokens_TenantScoped(t *testing.T) {
	server := setupTestServer(t)
	mine := mintTestEnrolmentToken(t, server, "test-tenant")
	other := mintTestEnrolmentToken(t, server, "other-tenant")

	key := NewTestKey(t, server, []string{"enrolment-token:list"}) // scoped to test-tenant
	rec := listEnrolmentTokensAs(t, server, key)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var ids []string
	for _, r := range decodeEnrolmentTokenList(t, rec) {
		ids = append(ids, r.ID)
	}
	assert.Contains(t, ids, mine.ID)
	assert.NotContains(t, ids, other.ID)
}

// [REQUIRED TEST]
func TestListEnrolmentTokens_RequiresPermission(t *testing.T) {
	server := setupTestServer(t)
	mintTestEnrolmentToken(t, server, "test-tenant")

	key := NewTestKey(t, server, []string{"enrolment-token:mint"})
	rec := listEnrolmentTokensAs(t, server, key)
	assert.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
}

// [REQUIRED TEST]
func TestListEnrolmentTokens_StatusDerivation(t *testing.T) {
	now := time.Now()
	past := now.Add(-time.Minute)
	future := now.Add(time.Hour)

	cases := []struct {
		name string
		tok  enrolmentToken
		want string
	}{
		{"revoked wins over spent and expired", enrolmentToken{Revoked: true, SpentAt: &past, ExpiresAt: past}, "revoked"},
		{"spent wins over expired", enrolmentToken{SpentAt: &past, ExpiresAt: past}, "spent"},
		{"expired", enrolmentToken{ExpiresAt: past}, "expired"},
		{"active", enrolmentToken{ExpiresAt: future}, "active"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, enrolmentTokenStatus(&tc.tok, now))
		})
	}

	t.Run("through the route", func(t *testing.T) {
		server := setupTestServer(t)
		revoked := mintTestEnrolmentToken(t, server, "test-tenant")
		spent := mintTestEnrolmentToken(t, server, "test-tenant")
		active := mintTestEnrolmentToken(t, server, "test-tenant")

		tok, err := server.getEnrolmentTokenByID(context.Background(), revoked.ID)
		require.NoError(t, err)
		tok.Revoked = true
		rv := now
		tok.RevokedAt = &rv
		require.NoError(t, server.persistEnrolmentToken(context.Background(), tok))

		tok, err = server.getEnrolmentTokenByID(context.Background(), spent.ID)
		require.NoError(t, err)
		sp := now
		tok.SpentAt = &sp
		require.NoError(t, server.persistEnrolmentToken(context.Background(), tok))

		key := NewTestKey(t, server, []string{"enrolment-token:list"})
		rec := listEnrolmentTokensAs(t, server, key)
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		got := map[string]EnrolmentTokenResponse{}
		for _, r := range decodeEnrolmentTokenList(t, rec) {
			got[r.ID] = r
		}
		assert.Equal(t, "revoked", got[revoked.ID].Status)
		assert.Equal(t, "spent", got[spent.ID].Status)
		require.NotNil(t, got[spent.ID].SpentAt)
		assert.Equal(t, "active", got[active.ID].Status)
	})
}
