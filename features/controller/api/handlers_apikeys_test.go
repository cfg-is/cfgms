// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sort"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/ctxkeys"
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

// callHandleCreateAPIKey posts body to handleCreateAPIKey with the given context tenant.
func callHandleCreateAPIKey(server *Server, body []byte, contextTenantID string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/api-keys", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if contextTenantID != "" {
		req = req.WithContext(context.WithValue(req.Context(), ctxkeys.TenantID, contextTenantID))
	}
	rec := httptest.NewRecorder()
	server.handleCreateAPIKey(rec, req)
	return rec
}

// TestHandleCreateAPIKey_RejectsWildcard verifies that POST /api/v1/api-keys with
// permissions: ["*"] returns 400 INVALID_PERMISSION and does not persist the key (C1).
func TestHandleCreateAPIKey_RejectsWildcard(t *testing.T) {
	server := setupTestServer(t)

	body := []byte(`{"name":"test-key","permissions":["*"]}`)
	rec := callHandleCreateAPIKey(server, body, "default")

	assert.Equal(t, http.StatusBadRequest, rec.Code, "wildcard permission must be rejected")
	assert.Contains(t, rec.Body.String(), "INVALID_PERMISSION")

	// Secret store must be unchanged — key was not persisted.
	server.mu.RLock()
	defer server.mu.RUnlock()
	for _, key := range server.apiKeys {
		assert.NotEqual(t, "test-key", key.Name, "key with wildcard permission must not be stored")
	}
}

// TestHandleCreateAPIKey_RejectsUnknownPermission verifies that an unrecognized permission
// ID is rejected with 400 INVALID_PERMISSION (C1).
func TestHandleCreateAPIKey_RejectsUnknownPermission(t *testing.T) {
	server := setupTestServer(t)

	body := []byte(`{"name":"test-key","permissions":["does-not-exist:action"]}`)
	rec := callHandleCreateAPIKey(server, body, "default")

	assert.Equal(t, http.StatusBadRequest, rec.Code, "unknown permission must be rejected")
	assert.Contains(t, rec.Body.String(), "INVALID_PERMISSION")
}

// TestHandleCreateAPIKey_AcceptsKnownPermissions verifies that valid permission IDs are accepted.
func TestHandleCreateAPIKey_AcceptsKnownPermissions(t *testing.T) {
	server := setupTestServer(t)

	body := []byte(`{"name":"valid-key","permissions":["steward:read","api-key:list"]}`)
	rec := callHandleCreateAPIKey(server, body, "default")

	assert.Equal(t, http.StatusCreated, rec.Code, "known permissions must be accepted")
}

// TestHandleCreateAPIKey_RoleID_ConflictsWithPermissions verifies that supplying both
// role_id and permissions in the same request is rejected with 400 CONFLICTING_FIELDS.
func TestHandleCreateAPIKey_RoleID_ConflictsWithPermissions(t *testing.T) {
	server := setupTestServer(t)

	body := []byte(`{"name":"conflict-key","role_id":"agent.dev","permissions":["steward:read"]}`)
	rec := callHandleCreateAPIKey(server, body, "agent-test/1")

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "CONFLICTING_FIELDS")
}

// TestHandleCreateAPIKey_RoleID_UnknownRole verifies that an unrecognized role_id
// is rejected with 400 UNKNOWN_ROLE.
func TestHandleCreateAPIKey_RoleID_UnknownRole(t *testing.T) {
	server := setupTestServer(t)

	body := []byte(`{"name":"bad-role-key","role_id":"does-not-exist"}`)
	rec := callHandleCreateAPIKey(server, body, "agent-test/1")

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "UNKNOWN_ROLE")
}

// TestHandleCreateAPIKey_AgentDevRole_SetsCorrectPermissions verifies that role_id="agent.dev"
// resolves to exactly the agentDevAPIPermissions set and creates the key successfully.
func TestHandleCreateAPIKey_AgentDevRole_SetsCorrectPermissions(t *testing.T) {
	server := setupTestServer(t)

	body := []byte(`{"name":"agent-dev-key","role_id":"agent.dev","tenant_id":"agent-test/1"}`)
	rec := callHandleCreateAPIKey(server, body, "agent-test/1")

	require.Equal(t, http.StatusCreated, rec.Code, "agent.dev role_id must create key successfully")

	// Response is wrapped in APIResponse{Data: APIKeyCreateResult, Timestamp}.
	// Decode via the JSON map to avoid re-serializing the nested struct.
	var outer struct {
		Data map[string]interface{} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &outer))

	raw, ok := outer.Data["permissions"].([]interface{})
	require.True(t, ok, "permissions must be a JSON array in response data")

	got := make([]string, len(raw))
	for i, v := range raw {
		s, ok := v.(string)
		require.True(t, ok, "each permission must be a string")
		got[i] = s
	}
	want := make([]string, len(agentDevAPIPermissions))
	copy(want, agentDevAPIPermissions)
	sort.Strings(got)
	sort.Strings(want)
	assert.Equal(t, want, got, "agent.dev key must carry exactly the agentDevAPIPermissions set")
	assert.Equal(t, "agent-test/1", outer.Data["tenant_id"])
	assert.NotEmpty(t, outer.Data["key"], "plaintext key must be returned on creation")
}

// TestHandleDeleteAPIKey_SecretStoreFails_StillReturns200 covers the pre-existing error path
// at handlers_apikeys.go:300-304: a key injected only into memory (never persisted to the
// secret store) triggers a DeleteSecret failure, but the handler returns 200 because the
// in-memory entry is already removed.
func TestHandleDeleteAPIKey_SecretStoreFails_StillReturns200(t *testing.T) {
	server := setupTestServer(t)

	// Inject a key directly into memory, bypassing the secret store, so that
	// the subsequent DeleteSecret call returns "secret not found".
	key := &APIKey{
		ID:          "memory-only-key-id",
		Key:         "memory-only-key-secret",
		Name:        "Memory-Only Key",
		Permissions: []string{"steward:read"},
		CreatedAt:   time.Now().UTC(),
		TenantID:    "agent-test/1",
	}
	injectAPIKey(server, key)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/api-keys/memory-only-key-id", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "memory-only-key-id"})
	rec := httptest.NewRecorder()
	server.handleDeleteAPIKey(rec, req)

	// The handler must return 200: memory was cleared even though secret-store deletion failed.
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "deleted")

	// Confirm key is no longer in the in-memory cache.
	server.mu.RLock()
	defer server.mu.RUnlock()
	for _, k := range server.apiKeys {
		assert.NotEqual(t, "memory-only-key-id", k.ID, "key must be removed from memory even when secret store deletion fails")
	}
}
