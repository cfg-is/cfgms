// SPDX-License-Identifier: Apache-2.0
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

	"github.com/cfgis/cfgms/features/controller/ctxkeys"
)

// callHandleListAPIKeys calls handleListAPIKeys directly with the given context tenant.
func callHandleListAPIKeys(server *Server, contextTenantID string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/api-keys", nil)
	if contextTenantID != "" {
		req = req.WithContext(context.WithValue(req.Context(), ctxkeys.TenantID, contextTenantID))
	}
	rec := httptest.NewRecorder()
	server.handleListAPIKeys(rec, req)
	return rec
}

// injectAPIKey directly inserts an APIKey into the server's in-memory cache (bypassing secret store)
// so tests can assert on tenant filtering without needing a full secret store round-trip.
func injectAPIKey(server *Server, key *APIKey) {
	server.mu.Lock()
	server.apiKeys[key.Key] = key
	server.mu.Unlock()
}

// TestHandleListAPIKeys_FiltersByAuthenticatedTenant verifies that a tenant only sees
// its own API keys and never another tenant's keys.
func TestHandleListAPIKeys_FiltersByAuthenticatedTenant(t *testing.T) {
	server := setupTestServer(t)

	now := time.Now().UTC()

	keyA := &APIKey{
		ID:          "key-a-id",
		Key:         "key-a-secret",
		Name:        "Tenant A Key",
		Permissions: []string{"steward:list"},
		CreatedAt:   now,
		TenantID:    "tenant-a",
	}
	keyB := &APIKey{
		ID:          "key-b-id",
		Key:         "key-b-secret",
		Name:        "Tenant B Key",
		Permissions: []string{"steward:list"},
		CreatedAt:   now,
		TenantID:    "tenant-b",
	}

	injectAPIKey(server, keyA)
	injectAPIKey(server, keyB)

	// Authenticated as tenant-a — must only see tenant-a's key.
	rec := callHandleListAPIKeys(server, "tenant-a")
	require.Equal(t, http.StatusOK, rec.Code)

	var resp APIResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))

	keys, ok := resp.Data.([]interface{})
	require.True(t, ok, "expected array in Data")

	require.Len(t, keys, 1, "tenant-a should only see one key")
	keyMap := keys[0].(map[string]interface{})
	assert.Equal(t, "key-a-id", keyMap["id"])
	assert.Equal(t, "tenant-a", keyMap["tenant_id"])
}

// TestHandleListAPIKeys_DoesNotExposeOtherTenantKeys verifies tenant-b's key is invisible
// to a request authenticated as tenant-a.
func TestHandleListAPIKeys_DoesNotExposeOtherTenantKeys(t *testing.T) {
	server := setupTestServer(t)

	now := time.Now().UTC()
	injectAPIKey(server, &APIKey{
		ID: "only-b-key", Key: "only-b-secret", Name: "B Key",
		Permissions: []string{}, CreatedAt: now, TenantID: "tenant-b",
	})

	rec := callHandleListAPIKeys(server, "tenant-a")
	require.Equal(t, http.StatusOK, rec.Code)

	var resp APIResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))

	keys, ok := resp.Data.([]interface{})
	require.True(t, ok)
	assert.Empty(t, keys, "tenant-a should see no keys when it has none")
}

// TestHandleListAPIKeys_NoContextTenant_Returns401 verifies that a missing context tenant
// results in HTTP 401.
func TestHandleListAPIKeys_NoContextTenant_Returns401(t *testing.T) {
	server := setupTestServer(t)
	rec := callHandleListAPIKeys(server, "")
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

// TestHandleListAPIKeys_RouterPath_FiltersByAuthenticatedTenant verifies tenant isolation
// through the full router and authentication middleware — not just direct handler invocation.
// This exercises the path where the auth middleware reads the API key, looks it up in
// s.apiKeys, sets ctxkeys.TenantID from key.TenantID, and the handler filters on that value.
func TestHandleListAPIKeys_RouterPath_FiltersByAuthenticatedTenant(t *testing.T) {
	server := setupTestServer(t)

	// Create an API key for tenant-a via generateEphemeralKey, which registers the key in
	// s.apiKeys with TenantID="tenant-a". The auth middleware uses this TenantID to populate
	// the context, which handleListAPIKeys then reads for filtering.
	tenantAKey := NewEphemeralTestKey(t, server, []string{"api-key:list"}, "tenant-a", 5*time.Minute)

	// Inject a second key belonging to tenant-b directly into the cache.
	injectAPIKey(server, &APIKey{
		ID:          "tenant-b-key-id",
		Key:         "tenant-b-key-secret",
		Name:        "Tenant B Key",
		Permissions: []string{},
		CreatedAt:   time.Now().UTC(),
		TenantID:    "tenant-b",
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/api-keys", nil)
	req.Header.Set("X-API-Key", tenantAKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)

	var resp APIResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))

	keys, ok := resp.Data.([]interface{})
	require.True(t, ok, "expected array in Data")

	for _, k := range keys {
		keyMap, ok := k.(map[string]interface{})
		require.True(t, ok)
		assert.Equal(t, "tenant-a", keyMap["tenant_id"],
			"router path must return only tenant-a keys when authenticated as tenant-a")
		assert.NotEqual(t, "tenant-b-key-id", keyMap["id"],
			"tenant-b key must not be visible through the router to tenant-a")
	}
}
