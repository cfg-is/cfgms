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

	"github.com/cfgis/cfgms/api/proto/common"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
	secretsif "github.com/cfgis/cfgms/pkg/secrets/interfaces"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
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
	server.keyCache[key.Key] = key
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
// s.keyCache, sets ctxkeys.TenantID from key.TenantID, and the handler filters on that value.
func TestHandleListAPIKeys_RouterPath_FiltersByAuthenticatedTenant(t *testing.T) {
	server := setupTestServer(t)

	// Create an API key for tenant-a via generateEphemeralKey, which registers the key in
	// s.keyCache with TenantID="tenant-a". The auth middleware uses this TenantID to populate
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
	for _, key := range server.keyCache {
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

// TestHandleDeleteAPIKey_LocalOnlyKey_Returns200 covers a key that exists only in this
// node's cache with no durable record (the env-gated test keys seeded in New): it is
// not in the secret store, so the handler removes the cache entry and returns 200
// (Issue #4574 moved store-backed keys to a store-first delete).
func TestHandleDeleteAPIKey_LocalOnlyKey_Returns200(t *testing.T) {
	server := setupTestServer(t)

	// Inject a key directly into memory, bypassing the secret store.
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
	// Issue #4334: the handler enforces tenant containment before deleting — a
	// root-scoped caller here exercises the local-only path independent of that check.
	ctx := context.WithValue(req.Context(), ctxkeys.TenantScopeKey, ctxkeys.NewRootScope())
	ctx = context.WithValue(ctx, principalContextKey, &Principal{ID: "root-admin", ImplicitAdmin: true})
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()
	server.handleDeleteAPIKey(rec, req)

	// The handler must return 200: the local-only entry was removed.
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "deleted")

	// Confirm key is no longer in the in-memory cache.
	server.mu.RLock()
	defer server.mu.RUnlock()
	for _, k := range server.keyCache {
		assert.NotEqual(t, "memory-only-key-id", k.ID, "local-only key must be removed from memory")
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
	for _, k := range server.keyCache {
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
	for _, k := range server.keyCache {
		assert.NotEqual(t, "cross-tenant-key", k.Name, "no key may be persisted for a tenant outside the caller's own subtree")
	}
}

// TestHandleCreateAPIKey_TenantScope_CannotDefaultOutsideOwnSubtree is the
// [REQUIRED TEST] for Issue #4334 covering AC3: a tenant-scoped caller cannot mint a
// key outside its own subtree by simply omitting tenant_id — the equivalent, for API
// keys, of a tenant-scoped caller being unable to create a root-scoped account.
// Since Issue #4665 (with #4543) an omitted tenant resolves to the caller's own
// tenant rather than a catch-all "default" tenant, so the key lands in tenant-a.
func TestHandleCreateAPIKey_TenantScope_CannotDefaultOutsideOwnSubtree(t *testing.T) {
	server := setupTestServer(t)

	caller := &Principal{ID: "scoped-caller", TenantID: "tenant-a", ImplicitAdmin: true}
	body := []byte(`{"name":"default-tenant-key","permissions":["steward:read"]}`)
	rec := callHandleCreateAPIKeyAsPrincipal(server, body, "tenant-a", caller)

	require.Equal(t, http.StatusCreated, rec.Code, "body: %s", rec.Body.String())
	var resp struct {
		Data struct {
			TenantID string `json:"tenant_id"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.Equal(t, "tenant-a", resp.Data.TenantID, "an omitted tenant must resolve to the caller's own tenant, never \"default\"")
}

// TestHandleCreateAPIKey_UnsetScope_Returns403 verifies the fail-closed contract
// (Issue #4316): a request reaching the handler with no TenantScope ever established
// is refused, never treated as unrestricted root access. The caller is an authenticated
// admin bound to a tenant, so the absent scope is the only reason for the refusal.
func TestHandleCreateAPIKey_UnsetScope_Returns403(t *testing.T) {
	server := setupTestServer(t)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/api-keys",
		bytes.NewReader([]byte(`{"name":"unset-scope-key","permissions":["steward:read"]}`)))
	req.Header.Set("Content-Type", "application/json")
	ctx := context.WithValue(req.Context(), ctxkeys.TenantID, "tenant-a")
	ctx = context.WithValue(ctx, principalContextKey, &Principal{ID: "unscoped-caller", TenantID: "tenant-a", ImplicitAdmin: true})
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()
	server.handleCreateAPIKey(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code, "body: %s", rec.Body.String())
	assert.Equal(t, "FORBIDDEN", errorCode(t, rec), "the refusal must come from the tenant-scope check")
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
	ctx := context.WithValue(req.Context(), ctxkeys.TenantScopeKey, ctxkeys.NewTenantScope("tenant-a"))
	ctx = context.WithValue(ctx, principalContextKey, &Principal{ID: "scoped-caller", TenantID: "tenant-a", ImplicitAdmin: true})
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()
	server.handleDeleteAPIKey(rec, req)

	assert.Equal(t, http.StatusNotFound, rec.Code, "body: %s", rec.Body.String())

	server.mu.RLock()
	defer server.mu.RUnlock()
	_, stillExists := server.keyCache["cross-tenant-delete-secret"]
	assert.True(t, stillExists, "a cross-tenant delete attempt must not remove the key")
}

// TestHandleDeleteAPIKey_SecretStoreFailure_LogsNoKeyOrHash proves a failed
// DeleteSecret never puts the API key or its SHA-256 hash in the log output.
func TestHandleDeleteAPIKey_SecretStoreFailure_LogsNoKeyOrHash(t *testing.T) {
	logger := &captureAllLogger{}
	server := setupTestServerWithLogger(t, logger)

	apiKey, keyID := mintStoreAPIKey(t, server, []string{"steward:read"}, "agent-test")
	server.secretStore = &errDeleteSecretStore{SecretStore: server.secretStore}

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/api-keys/"+keyID, nil)
	req = mux.SetURLVars(req, map[string]string{"id": keyID})
	ctx := context.WithValue(req.Context(), ctxkeys.TenantScopeKey, ctxkeys.NewRootScope())
	ctx = context.WithValue(ctx, principalContextKey, &Principal{ID: "root-admin", ImplicitAdmin: true})
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()
	server.handleDeleteAPIKey(rec, req)
	assert.Equal(t, http.StatusInternalServerError, rec.Code)

	out := logger.captured()
	assert.Contains(t, out, "Failed to delete API key from secret store")
	assert.NotContains(t, out, apiKey)
	assert.NotContains(t, out, hashAPIKey(apiKey))
}

// TestHandleCreateAPIKey_RecordsAuditEvent is a [REQUIRED TEST]: a successful creation
// writes one high-severity security audit entry naming the principal and key ID, and
// the entry holds neither the key secret nor its hash.
func TestHandleCreateAPIKey_RecordsAuditEvent(t *testing.T) {
	server := setupTestServer(t)

	rec := callHandleCreateAPIKey(server, []byte(`{"name":"audited-key","permissions":["steward:read"]}`), "audit-tenant-a")
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
	var resp struct {
		Data APIKeyCreateResult `json:"data"`
	}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	require.NotEmpty(t, resp.Data.Key)

	entries := auditEntriesByAction(t, server, "api_key_created")
	require.Len(t, entries, 1)
	e := entries[0]
	assert.Equal(t, business.AuditEventSecurityEvent, e.EventType)
	assert.Equal(t, business.AuditSeverityHigh, e.Severity)
	assert.Equal(t, "audit-tenant-a", e.TenantID)
	assert.Equal(t, "test-caller", e.UserID)
	assert.Equal(t, resp.Data.ID, e.ResourceID)
	assert.Equal(t, resp.Data.ID, e.Details["key_id"])
	raw, err := json.Marshal(e)
	require.NoError(t, err)
	assert.NotContains(t, string(raw), resp.Data.Key)
	assert.NotContains(t, string(raw), hashAPIKey(resp.Data.Key))
}

// TestHandleCreateAPIKey_Rejected_RecordsNoAuditEvent is a [REQUIRED TEST]: a rejected
// creation leaves no audit entry for the caller's tenant.
func TestHandleCreateAPIKey_Rejected_RecordsNoAuditEvent(t *testing.T) {
	server := setupTestServer(t)

	rec := callHandleCreateAPIKey(server, []byte(`{"name":"k","permissions":["does-not-exist:action"]}`), "audit-tenant-b")
	require.Equal(t, http.StatusBadRequest, rec.Code)

	require.NoError(t, server.auditManager.Flush(context.Background()))
	entries, err := server.auditManager.QueryEntries(context.Background(), &business.AuditFilter{TenantID: "audit-tenant-b"})
	require.NoError(t, err)
	assert.Empty(t, entries)
}

// TestHandleDeleteAPIKey_RecordsAuditEvent is a [REQUIRED TEST]: a deletion writes one
// audit entry naming the principal and key ID; a not-found deletion writes none.
func TestHandleDeleteAPIKey_RecordsAuditEvent(t *testing.T) {
	server := setupTestServer(t)

	createRec := callHandleCreateAPIKey(server, []byte(`{"name":"to-delete","permissions":["steward:read"]}`), "audit-tenant-c")
	require.Equal(t, http.StatusCreated, createRec.Code, createRec.Body.String())
	var created struct {
		Data APIKeyCreateResult `json:"data"`
	}
	require.NoError(t, json.NewDecoder(createRec.Body).Decode(&created))

	deleteAs := func(id string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodDelete, "/api/v1/api-keys/"+id, nil)
		req = mux.SetURLVars(req, map[string]string{"id": id})
		ctx := context.WithValue(req.Context(), ctxkeys.TenantScopeKey, ctxkeys.NewTenantScope("audit-tenant-c"))
		ctx = context.WithValue(ctx, principalContextKey, &Principal{ID: "deleter", TenantID: "audit-tenant-c", ImplicitAdmin: true})
		rec := httptest.NewRecorder()
		server.handleDeleteAPIKey(rec, req.WithContext(ctx))
		return rec
	}

	require.Equal(t, http.StatusNotFound, deleteAs("no-such-key").Code)
	assert.Empty(t, auditEntriesByAction(t, server, "api_key_deleted"))

	require.Equal(t, http.StatusOK, deleteAs(created.Data.ID).Code)
	entries := auditEntriesByAction(t, server, "api_key_deleted")
	require.Len(t, entries, 1)
	e := entries[0]
	assert.Equal(t, business.AuditEventSecurityEvent, e.EventType)
	assert.Equal(t, business.AuditSeverityHigh, e.Severity)
	assert.Equal(t, "audit-tenant-c", e.TenantID)
	assert.Equal(t, "deleter", e.UserID)
	assert.Equal(t, created.Data.ID, e.ResourceID)
	raw, err := json.Marshal(e)
	require.NoError(t, err)
	assert.NotContains(t, string(raw), created.Data.Key)
	assert.NotContains(t, string(raw), hashAPIKey(created.Data.Key))
}

// apiKeyRecordsFor lists every API-key record the secret store holds for tenantID,
// with the filter handleListAPIKeys uses.
func apiKeyRecordsFor(t *testing.T, server *Server, tenantID string) []*secretsif.SecretMetadata {
	t.Helper()
	records, err := server.secretStore.ListSecrets(context.Background(), &secretsif.SecretFilter{
		TenantID: tenantID,
		Metadata: map[string]string{
			secretsif.MetadataKeySecretType: string(secretsif.SecretTypeAPIKey),
		},
	})
	require.NoError(t, err)
	return records
}

// apiKeyRecordByID returns the stored record of the key with keyID in tenantID, or
// nil when the store holds none.
func apiKeyRecordByID(t *testing.T, server *Server, tenantID, keyID string) *secretsif.SecretMetadata {
	t.Helper()
	for _, rec := range apiKeyRecordsFor(t, server, tenantID) {
		if rec.Metadata["id"] == keyID {
			return rec
		}
	}
	return nil
}

// decodeCreatedAPIKey decodes a handleCreateAPIKey success response.
func decodeCreatedAPIKey(t *testing.T, rec *httptest.ResponseRecorder) APIKeyCreateResult {
	t.Helper()
	var resp struct {
		Data APIKeyCreateResult `json:"data"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp), rec.Body.String())
	require.NotEmpty(t, resp.Data.ID)
	return resp.Data
}

// keyCacheLen reports how many entries the server's API-key cache holds.
func keyCacheLen(server *Server) int {
	server.mu.RLock()
	defer server.mu.RUnlock()
	return len(server.keyCache)
}

// TestHandleCreateAPIKey_RecordNamesActingPrincipal: the secret-store record of a
// minted key names the principal that minted it as its creator.
func TestHandleCreateAPIKey_RecordNamesActingPrincipal(t *testing.T) {
	server := setupTestServer(t)

	caller := &Principal{ID: "operator-7", TenantID: "tenant-a", ImplicitAdmin: true}
	rec := callHandleCreateAPIKeyAsPrincipal(server, []byte(`{"name":"actor-key","permissions":["steward:read"]}`), "tenant-a", caller)
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
	created := decodeCreatedAPIKey(t, rec)

	stored := apiKeyRecordByID(t, server, "tenant-a", created.ID)
	require.NotNil(t, stored, "the minted key has a durable record")
	assert.Equal(t, "operator-7", stored.CreatedBy)
}

// TestRecordAPIKeyRoleAssignment_NamesActingPrincipal: the role assignment that binds a
// minted API key to its role names the principal that minted the key as its assigner.
// The actor is not an argument: recordAPIKeyRoleAssignment reads it from the mint
// result, which carries the same ActorID that TestHandleCreateAPIKey_RecordNamesActingPrincipal
// proves the handler takes from the request's principal. The key's RBAC subject is
// created here first, because the RBAC manager stores an assignment only for a subject
// it knows.
func TestRecordAPIKeyRoleAssignment_NamesActingPrincipal(t *testing.T) {
	server := setupTestServer(t)
	ctx := context.Background()

	const tenantID = "agent-test/1"
	expiresAt := time.Now().UTC().Add(time.Hour)
	minted, err := server.mintAPIKey(ctx, apiKeyMintSpec{
		Name:        "role-bound-key",
		Permissions: agentDevAPIPermissions,
		TenantID:    tenantID,
		ExpiresAt:   &expiresAt,
		ActorID:     "operator-7",
	})
	require.NoError(t, err)
	keyID := minted.apiKey.ID
	require.NoError(t, server.rbacManager.CreateSubject(ctx, &common.Subject{
		Id: keyID, Type: common.SubjectType_SUBJECT_TYPE_API_CLIENT, DisplayName: minted.apiKey.Name, TenantId: tenantID, IsActive: true,
	}))

	server.recordAPIKeyRoleAssignment(ctx, minted, "")
	none, err := server.rbacManager.GetSubjectAssignments(ctx, keyID, tenantID)
	require.NoError(t, err)
	assert.Empty(t, none, "no role requested, no assignment")

	server.recordAPIKeyRoleAssignment(ctx, minted, "agent.dev")
	assignments, err := server.rbacManager.GetSubjectAssignments(ctx, keyID, tenantID)
	require.NoError(t, err)
	require.Len(t, assignments, 1, "the key must be bound to its role by one stored assignment")
	a := assignments[0]
	assert.Equal(t, keyID, a.SubjectId)
	assert.Equal(t, "agent.dev", a.RoleId)
	assert.Equal(t, tenantID, a.TenantId)
	assert.Equal(t, "operator-7", a.AssignedBy)

	// The assigner is the same principal the key's own record names.
	stored := apiKeyRecordByID(t, server, tenantID, keyID)
	require.NotNil(t, stored)
	assert.Equal(t, stored.CreatedBy, a.AssignedBy)
}

// TestHandleCreateAPIKey_NoActor_Returns401AndWritesNothing: with no principal, or a
// principal with an empty ID, key creation is refused with 401 and nothing is cached,
// stored, assigned or audited. The request is otherwise complete: the same request from
// an authenticated principal succeeds.
func TestHandleCreateAPIKey_NoActor_Returns401AndWritesNothing(t *testing.T) {
	server := setupTestServer(t)
	const tenantID = "tenant-a"

	post := func(p *Principal, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/api-keys", bytes.NewReader([]byte(body)))
		req.Header.Set("Content-Type", "application/json")
		ctx := context.WithValue(req.Context(), ctxkeys.TenantID, tenantID)
		ctx = context.WithValue(ctx, ctxkeys.TenantScopeKey, ctxkeys.NewTenantScope(tenantID))
		rec := httptest.NewRecorder()
		server.handleCreateAPIKey(rec, req.WithContext(withActor(ctx, p)))
		return rec
	}

	cacheBefore := keyCacheLen(server)
	for _, tc := range noActorCases(tenantID) {
		t.Run(tc.name, func(t *testing.T) {
			// With no principal at all the caller holds no permission, so the body
			// asks for none (a role_id would grant agent.dev's); the empty-ID
			// principal is an implicit admin and asks for the role binding too.
			body := `{"name":"no-actor-key","tenant_id":"` + tenantID + `"}`
			if tc.principal != nil {
				body = `{"name":"no-actor-key","role_id":"agent.dev","tenant_id":"` + tenantID + `"}`
			}
			assertAuthenticationRequired(t, post(tc.principal, body))

			assert.Empty(t, apiKeyRecordsFor(t, server, tenantID), "no API-key record may be stored")
			assert.Equal(t, cacheBefore, keyCacheLen(server), "the key cache must be unchanged")
			assignments, err := server.rbacManager.ListAssignments(context.Background(), "", "", tenantID)
			require.NoError(t, err)
			assert.Empty(t, assignments, "no role assignment may be stored")
			assert.Empty(t, auditEntriesByAction(t, server, "api_key_created"))
		})
	}

	operator := &Principal{ID: "operator-7", TenantID: tenantID, ImplicitAdmin: true}
	rec := post(operator, `{"name":"no-actor-key","role_id":"agent.dev","tenant_id":"`+tenantID+`"}`)
	require.Equal(t, http.StatusCreated, rec.Code, "the same request from an authenticated principal succeeds: %s", rec.Body.String())
}

// TestHandleDeleteAPIKey_NoActor_Returns401AndKeyRemains: with no principal, or a
// principal with an empty ID, a delete is refused with 401 before anything is looked
// up or removed: the record stays in the store, the key stays cached and still
// resolves, and no deletion is audited. The same request from an authenticated
// principal deletes the key.
func TestHandleDeleteAPIKey_NoActor_Returns401AndKeyRemains(t *testing.T) {
	server := setupTestServer(t)
	const tenantID = "tenant-a"
	apiKey, keyID := mintStoreAPIKey(t, server, []string{"steward:read"}, tenantID)

	del := func(p *Principal) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodDelete, "/api/v1/api-keys/"+keyID, nil)
		req = mux.SetURLVars(req, map[string]string{"id": keyID})
		ctx := context.WithValue(req.Context(), ctxkeys.TenantID, tenantID)
		ctx = context.WithValue(ctx, ctxkeys.TenantScopeKey, ctxkeys.NewTenantScope(tenantID))
		rec := httptest.NewRecorder()
		server.handleDeleteAPIKey(rec, req.WithContext(withActor(ctx, p)))
		return rec
	}

	for _, tc := range noActorCases(tenantID) {
		t.Run(tc.name, func(t *testing.T) {
			assertAuthenticationRequired(t, del(tc.principal))

			stored, err := server.readAPIKeyRecord(context.Background(), tenantID, hashAPIKey(apiKey))
			require.NoError(t, err)
			assert.NotNil(t, stored, "the key's record must remain in the store")
			assert.True(t, isCached(server, apiKey), "the key must remain cached")
			loaded, err := server.loadKeyEntryFromStore(context.Background(), apiKey)
			require.NoError(t, err, "the key must still resolve from the store")
			assert.Equal(t, keyID, loaded.ID)
			assert.Empty(t, auditEntriesByAction(t, server, "api_key_deleted"))
		})
	}

	rec := del(&Principal{ID: "operator-7", TenantID: tenantID, ImplicitAdmin: true})
	require.Equal(t, http.StatusOK, rec.Code, "the same request from an authenticated principal deletes: %s", rec.Body.String())
	entries := auditEntriesByAction(t, server, "api_key_deleted")
	require.Len(t, entries, 1)
	assert.Equal(t, "operator-7", entries[0].UserID)
}

// TestMintAPIKey_EmptyActor_RefusedBeforeAnythingIsStored: mintAPIKey refuses a spec
// with no actor before generating, caching or storing anything, and the refusal maps
// to 401 AUTHENTICATION_REQUIRED.
func TestMintAPIKey_EmptyActor_RefusedBeforeAnythingIsStored(t *testing.T) {
	server := setupTestServer(t)
	const tenantID = "tenant-a"
	expires := time.Now().Add(time.Hour)

	cacheBefore := keyCacheLen(server)
	minted, err := server.mintAPIKey(context.Background(), apiKeyMintSpec{
		Name:        "no-actor-mint",
		Permissions: []string{"steward:read"},
		TenantID:    tenantID,
		ExpiresAt:   &expires,
	})
	require.ErrorIs(t, err, errMintAPIKeyNoActor)
	assert.Nil(t, minted)
	assert.Equal(t, cacheBefore, keyCacheLen(server), "the key cache must be unchanged")
	assert.Empty(t, apiKeyRecordsFor(t, server, tenantID), "no API-key record may be stored")

	rec := httptest.NewRecorder()
	server.writeMintAPIKeyError(rec, err)
	assertAuthenticationRequired(t, rec)
}
