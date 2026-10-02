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
	return callHandleCreateAPIKeyAsPrincipal(server, body, contextTenantID, &Principal{
		ID:            "test-caller",
		ImplicitAdmin: true,
		TenantID:      contextTenantID,
	})
}

// callHandleCreateAPIKeyAsPrincipal calls handleCreateAPIKey with the given caller
// principal and a matching TenantScope injected into the context, exactly as
// authenticationMiddleware would (Issue #4334). Passing a non-ImplicitAdmin
// principal with a limited Permissions set exercises the permission-escalation and
// tenant-containment checks the plain callHandleCreateAPIKey helper otherwise masks.
func callHandleCreateAPIKeyAsPrincipal(server *Server, body []byte, contextTenantID string, principal *Principal) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/api-keys", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if contextTenantID != "" {
		ctx := context.WithValue(req.Context(), ctxkeys.TenantID, contextTenantID)
		ctx = context.WithValue(ctx, ctxkeys.TenantScopeKey, ctxkeys.NewTenantScope(contextTenantID))
		ctx = context.WithValue(ctx, principalContextKey, principal)
		req = req.WithContext(ctx)
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
	// Issue #4334: the handler now enforces tenant containment before deleting —
	// an unscoped (root) caller here exercises the pre-existing secret-store-failure
	// path this test targets, independent of that new check.
	req = req.WithContext(context.WithValue(req.Context(), ctxkeys.TenantScopeKey, ctxkeys.NewRootScope()))
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

// TestHandleCreateAPIKey_CannotGrantPermissionCallerDoesNotHold is a [REQUIRED TEST]
// for Issue #4334: a caller holding only api-key:create cannot mint an API key
// carrying certificate:rotate — a permission it does not itself hold.
func TestHandleCreateAPIKey_CannotGrantPermissionCallerDoesNotHold(t *testing.T) {
	server := setupTestServer(t)

	limitedCaller := &Principal{
		ID:          "limited-caller",
		TenantID:    "tenant-a",
		Permissions: []string{"api-key:create"},
	}
	body := []byte(`{"name":"escalation-key","tenant_id":"tenant-a","permissions":["certificate:rotate"]}`)
	rec := callHandleCreateAPIKeyAsPrincipal(server, body, "tenant-a", limitedCaller)

	assert.Equal(t, http.StatusForbidden, rec.Code, "body: %s", rec.Body.String())
	assert.Contains(t, rec.Body.String(), "PERMISSION_ESCALATION")

	server.mu.RLock()
	defer server.mu.RUnlock()
	for _, k := range server.apiKeys {
		assert.NotEqual(t, "escalation-key", k.Name, "no key may be persisted when the caller lacks a requested permission")
	}
}

// TestHandleCreateAPIKey_CanGrantHeldPermission verifies the positive case: a caller
// holding the requested permission itself may grant it to a new key.
func TestHandleCreateAPIKey_CanGrantHeldPermission(t *testing.T) {
	server := setupTestServer(t)

	caller := &Principal{
		ID:          "holder-caller",
		TenantID:    "tenant-a",
		Permissions: []string{"api-key:create", "steward:read"},
	}
	body := []byte(`{"name":"held-perm-key","tenant_id":"tenant-a","permissions":["steward:read"]}`)
	rec := callHandleCreateAPIKeyAsPrincipal(server, body, "tenant-a", caller)

	assert.Equal(t, http.StatusCreated, rec.Code, "body: %s", rec.Body.String())
}

// TestHandleCreateAPIKey_TenantScope_SiblingTenant_Returns403 is the [REQUIRED TEST]
// for Issue #4334: a caller scoped to tenant-a cannot mint an API key for sibling
// tenant tenant-b.
func TestHandleCreateAPIKey_TenantScope_SiblingTenant_Returns403(t *testing.T) {
	server := setupTestServer(t)

	caller := &Principal{ID: "scoped-caller", TenantID: "tenant-a", ImplicitAdmin: true}
	body := []byte(`{"name":"cross-tenant-key","tenant_id":"tenant-b","permissions":["steward:read"]}`)
	rec := callHandleCreateAPIKeyAsPrincipal(server, body, "tenant-a", caller)

	assert.Equal(t, http.StatusForbidden, rec.Code, "body: %s", rec.Body.String())

	server.mu.RLock()
	defer server.mu.RUnlock()
	for _, k := range server.apiKeys {
		assert.NotEqual(t, "cross-tenant-key", k.Name, "no key may be persisted for a tenant outside the caller's own subtree")
	}
}

// TestHandleCreateAPIKey_TenantScope_CannotDefaultOutsideOwnSubtree is the
// [REQUIRED TEST] for Issue #4334 covering AC3: a tenant-scoped caller cannot mint a
// key that resolves to the catch-all "default" tenant outside its own subtree by
// simply omitting tenant_id — the equivalent, for API keys, of a tenant-scoped caller
// being unable to create a root-scoped account.
func TestHandleCreateAPIKey_TenantScope_CannotDefaultOutsideOwnSubtree(t *testing.T) {
	server := setupTestServer(t)

	caller := &Principal{ID: "scoped-caller", TenantID: "tenant-a", ImplicitAdmin: true}
	body := []byte(`{"name":"default-tenant-key","permissions":["steward:read"]}`)
	rec := callHandleCreateAPIKeyAsPrincipal(server, body, "tenant-a", caller)

	assert.Equal(t, http.StatusForbidden, rec.Code, "body: %s", rec.Body.String())
}

// TestHandleCreateAPIKey_UnsetScope_Returns403 verifies the fail-closed contract
// (Issue #4316): a request reaching the handler with no TenantScope ever established
// is refused, never treated as unrestricted root access.
func TestHandleCreateAPIKey_UnsetScope_Returns403(t *testing.T) {
	server := setupTestServer(t)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/api-keys",
		bytes.NewReader([]byte(`{"name":"unset-scope-key","permissions":["steward:read"]}`)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	server.handleCreateAPIKey(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code, "body: %s", rec.Body.String())
}

// TestHandleGetAPIKey_TenantScope_SiblingTenant_Returns404 is the [REQUIRED TEST] for
// Issue #4334: a caller scoped to tenant-a is refused (as not-found, not forbidden —
// existence must not be disclosed across tenants) when reading a key belonging to
// sibling tenant tenant-b.
func TestHandleGetAPIKey_TenantScope_SiblingTenant_Returns404(t *testing.T) {
	server := setupTestServer(t)
	injectAPIKey(server, &APIKey{
		ID:       "cross-tenant-get-id",
		Key:      "cross-tenant-get-secret",
		Name:     "Tenant B Key",
		TenantID: "tenant-b",
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/api-keys/cross-tenant-get-id", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "cross-tenant-get-id"})
	req = req.WithContext(context.WithValue(req.Context(), ctxkeys.TenantScopeKey, ctxkeys.NewTenantScope("tenant-a")))
	rec := httptest.NewRecorder()
	server.handleGetAPIKey(rec, req)

	assert.Equal(t, http.StatusNotFound, rec.Code, "body: %s", rec.Body.String())
}

// TestHandleGetAPIKey_TenantScope_OwnTenant_Succeeds verifies a caller scoped to
// tenant-a CAN read a key belonging to its own tenant.
func TestHandleGetAPIKey_TenantScope_OwnTenant_Succeeds(t *testing.T) {
	server := setupTestServer(t)
	injectAPIKey(server, &APIKey{
		ID:       "own-tenant-get-id",
		Key:      "own-tenant-get-secret",
		Name:     "Tenant A Key",
		TenantID: "tenant-a",
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/api-keys/own-tenant-get-id", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "own-tenant-get-id"})
	req = req.WithContext(context.WithValue(req.Context(), ctxkeys.TenantScopeKey, ctxkeys.NewTenantScope("tenant-a")))
	rec := httptest.NewRecorder()
	server.handleGetAPIKey(rec, req)

	require.Equal(t, http.StatusOK, rec.Code, "body: %s", rec.Body.String())
}

// TestHandleGetAPIKey_UnsetScope_Returns404 verifies the fail-closed contract (Issue
// #4316): a request reaching the handler with no TenantScope ever established is
// refused, never treated as unrestricted root access.
func TestHandleGetAPIKey_UnsetScope_Returns404(t *testing.T) {
	server := setupTestServer(t)
	injectAPIKey(server, &APIKey{
		ID:       "unset-scope-get-id",
		Key:      "unset-scope-get-secret",
		Name:     "Some Key",
		TenantID: "tenant-a",
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/api-keys/unset-scope-get-id", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "unset-scope-get-id"})
	rec := httptest.NewRecorder()
	server.handleGetAPIKey(rec, req)

	assert.Equal(t, http.StatusNotFound, rec.Code, "body: %s", rec.Body.String())
}

// TestHandleDeleteAPIKey_TenantScope_SiblingTenant_Returns404 is the [REQUIRED TEST]
// for Issue #4334: a caller scoped to tenant-a is refused (as not-found) when
// deleting a key belonging to sibling tenant tenant-b, and the key must survive.
func TestHandleDeleteAPIKey_TenantScope_SiblingTenant_Returns404(t *testing.T) {
	server := setupTestServer(t)
	injectAPIKey(server, &APIKey{
		ID:       "cross-tenant-delete-id",
		Key:      "cross-tenant-delete-secret",
		Name:     "Tenant B Key",
		TenantID: "tenant-b",
	})

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/api-keys/cross-tenant-delete-id", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "cross-tenant-delete-id"})
	req = req.WithContext(context.WithValue(req.Context(), ctxkeys.TenantScopeKey, ctxkeys.NewTenantScope("tenant-a")))
	rec := httptest.NewRecorder()
	server.handleDeleteAPIKey(rec, req)

	assert.Equal(t, http.StatusNotFound, rec.Code, "body: %s", rec.Body.String())

	server.mu.RLock()
	defer server.mu.RUnlock()
	_, stillExists := server.apiKeys["cross-tenant-delete-secret"]
	assert.True(t, stillExists, "a cross-tenant delete attempt must not remove the key")
}

// TestHandleDeleteAPIKey_SecretStoreFailure_LogsNoKeyOrHash proves a failed
// DeleteSecret never puts the API key or its SHA-256 hash in the log output.
func TestHandleDeleteAPIKey_SecretStoreFailure_LogsNoKeyOrHash(t *testing.T) {
	logger := &captureAllLogger{}
	server := setupTestServerWithLogger(t, logger)

	key := &APIKey{
		ID:          "log-leak-key-id",
		Key:         "log-leak-key-secret-value",
		Name:        "Log Leak Key",
		Permissions: []string{"steward:read"},
		CreatedAt:   time.Now().UTC(),
		TenantID:    "agent-test/1",
	}
	injectAPIKey(server, key)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/api-keys/log-leak-key-id", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "log-leak-key-id"})
	req = req.WithContext(context.WithValue(req.Context(), ctxkeys.TenantScopeKey, ctxkeys.NewRootScope()))
	rec := httptest.NewRecorder()
	server.handleDeleteAPIKey(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)

	out := logger.captured()
	assert.Contains(t, out, "Failed to delete API key from secret store")
	assert.NotContains(t, out, key.Key)
	assert.NotContains(t, out, hashAPIKey(key.Key))
}
