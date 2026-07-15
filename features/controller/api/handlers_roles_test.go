// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	stewardtypes "github.com/cfgis/cfgms/features/config/stewardtypes"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
	pkgtesting "github.com/cfgis/cfgms/pkg/testing"
)

// setupRoleConfigServer creates a test server wired with a role config store.
func setupRoleConfigServer(t *testing.T) *Server {
	t.Helper()
	server := setupTestServer(t)
	sm := pkgtesting.SetupTestStorage(t)
	server.SetRoleConfigStore(sm.GetConfigStore())
	return server
}

// minimalFragment returns a StewardConfig fragment with no required fields set
// (role configs are partial configs — no steward ID needed).
func minimalFragment() stewardtypes.StewardConfig {
	return stewardtypes.StewardConfig{}
}

// validRolePayload returns a JSON body for POST /api/v1/roles.
func validRolePayload(name, sel string) []byte {
	b, _ := json.Marshal(createRoleConfigRequest{
		Name:     name,
		Selector: sel,
		Fragment: minimalFragment(),
	})
	return b
}

// TestHandleCreateRoleConfig_HappyPath verifies POST /api/v1/roles stores and returns
// a role config, and GET /api/v1/roles/{name} returns the same config.
func TestHandleCreateRoleConfig_HappyPath(t *testing.T) {
	server := setupRoleConfigServer(t)
	apiKey := NewEphemeralTestKey(t, server, []string{"role:write", "role:read"}, "test-tenant", 5*time.Minute)

	body := validRolePayload("github-runners", "os:windows tag:github-runner")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/roles", bytes.NewReader(body))
	req.Header.Set("X-API-Key", apiKey)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusCreated, rec.Code, "unexpected body: %s", rec.Body.String())

	var createResp APIResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &createResp))
	created, ok := createResp.Data.(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "github-runners", created["name"])
	assert.Equal(t, "os:windows tag:github-runner", created["selector"])

	// GET returns the same role config.
	req2 := httptest.NewRequest(http.MethodGet, "/api/v1/roles/github-runners", nil)
	req2.Header.Set("X-API-Key", apiKey)
	rec2 := httptest.NewRecorder()
	server.router.ServeHTTP(rec2, req2)

	require.Equal(t, http.StatusOK, rec2.Code, "unexpected body: %s", rec2.Body.String())

	var getResp APIResponse
	require.NoError(t, json.Unmarshal(rec2.Body.Bytes(), &getResp))
	got, ok := getResp.Data.(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "github-runners", got["name"])
	assert.Equal(t, "os:windows tag:github-runner", got["selector"])
}

// TestHandleCreateRoleConfig_InvalidSelector verifies that an unparseable selector
// returns 400 BAD_REQUEST.
func TestHandleCreateRoleConfig_InvalidSelector(t *testing.T) {
	server := setupRoleConfigServer(t)
	apiKey := NewEphemeralTestKey(t, server, []string{"role:write"}, "test-tenant", 5*time.Minute)

	body, _ := json.Marshal(createRoleConfigRequest{
		Name:     "bad-role",
		Selector: "unknownkey:value",
		Fragment: minimalFragment(),
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/roles", bytes.NewReader(body))
	req.Header.Set("X-API-Key", apiKey)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	var errResp ErrorResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &errResp))
	require.NotNil(t, errResp.Error)
	assert.Equal(t, "INVALID_SELECTOR", errResp.Error.Code)
}

// TestHandleCreateRoleConfig_EmptySelector verifies that an empty selector returns 400.
func TestHandleCreateRoleConfig_EmptySelector(t *testing.T) {
	server := setupRoleConfigServer(t)
	apiKey := NewEphemeralTestKey(t, server, []string{"role:write"}, "test-tenant", 5*time.Minute)

	body, _ := json.Marshal(createRoleConfigRequest{
		Name:     "bad-role",
		Selector: "",
		Fragment: minimalFragment(),
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/roles", bytes.NewReader(body))
	req.Header.Set("X-API-Key", apiKey)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

// TestHandleListRoleConfigs_ReturnsTenantRoles verifies GET /api/v1/roles lists only
// the roles belonging to the authenticated tenant.
func TestHandleListRoleConfigs_ReturnsTenantRoles(t *testing.T) {
	server := setupRoleConfigServer(t)
	apiKey := NewEphemeralTestKey(t, server, []string{"role:write", "role:read"}, "test-tenant", 5*time.Minute)

	for _, name := range []string{"role-alpha", "role-beta"} {
		body := validRolePayload(name, "all")
		req := httptest.NewRequest(http.MethodPost, "/api/v1/roles", bytes.NewReader(body))
		req.Header.Set("X-API-Key", apiKey)
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		server.router.ServeHTTP(rec, req)
		require.Equal(t, http.StatusCreated, rec.Code, "seed %s: %s", name, rec.Body.String())
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/roles", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var listResp APIResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &listResp))
	items, ok := listResp.Data.([]interface{})
	require.True(t, ok, "expected array in Data")
	assert.Len(t, items, 2)

	names := make([]string, 0, len(items))
	for _, item := range items {
		m, ok := item.(map[string]interface{})
		require.True(t, ok)
		names = append(names, m["name"].(string))
	}
	assert.ElementsMatch(t, []string{"role-alpha", "role-beta"}, names)
}

// TestHandleDeleteRoleConfig_RemovesRole verifies DELETE /api/v1/roles/{name} removes
// the role and subsequent GET returns 404.
func TestHandleDeleteRoleConfig_RemovesRole(t *testing.T) {
	server := setupRoleConfigServer(t)
	apiKey := NewEphemeralTestKey(t, server, []string{"role:write", "role:read"}, "test-tenant", 5*time.Minute)

	// Create role.
	body := validRolePayload("to-delete", "all")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/roles", bytes.NewReader(body))
	req.Header.Set("X-API-Key", apiKey)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)
	require.Equal(t, http.StatusCreated, rec.Code)

	// Delete role.
	req2 := httptest.NewRequest(http.MethodDelete, "/api/v1/roles/to-delete", nil)
	req2.Header.Set("X-API-Key", apiKey)
	rec2 := httptest.NewRecorder()
	server.router.ServeHTTP(rec2, req2)
	require.Equal(t, http.StatusOK, rec2.Code, rec2.Body.String())

	// GET now returns 404.
	req3 := httptest.NewRequest(http.MethodGet, "/api/v1/roles/to-delete", nil)
	req3.Header.Set("X-API-Key", apiKey)
	rec3 := httptest.NewRecorder()
	server.router.ServeHTTP(rec3, req3)
	assert.Equal(t, http.StatusNotFound, rec3.Code)
}

// TestHandleDeleteRoleConfig_NotFound verifies DELETE for a non-existent role returns 404.
func TestHandleDeleteRoleConfig_NotFound(t *testing.T) {
	server := setupRoleConfigServer(t)
	apiKey := NewEphemeralTestKey(t, server, []string{"role:write"}, "test-tenant", 5*time.Minute)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/roles/nonexistent", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

// TestHandleRoleConfig_TenantScoping verifies that a caller scoped to tenant-a cannot
// create or delete roles under tenant-b.
func TestHandleRoleConfig_TenantScoping(t *testing.T) {
	server := setupRoleConfigServer(t)

	// Create API key for tenant-a.
	keyA := NewEphemeralTestKey(t, server, []string{"role:write", "role:read"}, "tenant-a", 5*time.Minute)

	// Seed a role for tenant-b by injecting context directly (bypass middleware).
	ctx := context.WithValue(context.Background(), principalContextKey, &Principal{
		ID:       "admin",
		TenantID: "",
	})
	ctx = context.WithValue(ctx, ctxkeys.TenantID, "tenant-b")

	body := validRolePayload("tenant-b-role", "all")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/roles", bytes.NewReader(body))
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()
	server.handleCreateRoleConfig(rec, req)
	require.Equal(t, http.StatusCreated, rec.Code, "seed tenant-b role: %s", rec.Body.String())

	// A tenant-a caller cannot reach tenant-b's role. A tenant-scoped caller is
	// PINNED to its own tenant (#2548): roleTenantFromRequest ignores any request-
	// supplied tenant and uses the principal's tenant, so this delete operates in
	// tenant-a — where tenant-b-role does not exist — and returns 404. Even with a
	// mismatching tenant context injected (which the middleware never produces —
	// it sets the context tenant FROM the principal), the caller can neither act
	// on nor learn of another tenant's role. This is stronger isolation than the
	// prior 403: it discloses nothing about tenant-b's contents.
	ctxA := context.WithValue(context.Background(), principalContextKey, &Principal{
		ID:       "caller-a",
		TenantID: "tenant-a",
	})
	ctxA = context.WithValue(ctxA, ctxkeys.TenantID, "tenant-b")

	req2 := httptest.NewRequest(http.MethodDelete, "/api/v1/roles/tenant-b-role", nil)
	// Direct handler call: set the {name} path var the router would normally supply.
	req2 = mux.SetURLVars(req2.WithContext(ctxA), map[string]string{"name": "tenant-b-role"})
	rec2 := httptest.NewRecorder()
	server.handleDeleteRoleConfig(rec2, req2)
	assert.Equal(t, http.StatusNotFound, rec2.Code,
		"scoped caller is pinned to its own tenant; tenant-b-role is not found there")

	// GET via tenant-a API key returns 404 (not 200) because tenant-a has no roles.
	req3 := httptest.NewRequest(http.MethodGet, "/api/v1/roles/tenant-b-role", nil)
	req3.Header.Set("X-API-Key", keyA)
	rec3 := httptest.NewRecorder()
	server.router.ServeHTTP(rec3, req3)
	assert.Equal(t, http.StatusNotFound, rec3.Code)
}

// TestHandleRoleConfig_ServiceUnavailable verifies 503 when no role config store is wired.
func TestHandleRoleConfig_ServiceUnavailable(t *testing.T) {
	server := setupTestServer(t) // no roleConfigStore wired
	apiKey := NewTestKey(t, server, []string{"role:read"})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/roles", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
}

// TestHandleCreateRoleConfig_InvalidName verifies that invalid characters in the role
// name return 400.
func TestHandleCreateRoleConfig_InvalidName(t *testing.T) {
	server := setupRoleConfigServer(t)
	apiKey := NewEphemeralTestKey(t, server, []string{"role:write"}, "test-tenant", 5*time.Minute)

	for _, bad := range []string{"", "has space", "slash/name", "null\x00byte"} {
		body, _ := json.Marshal(createRoleConfigRequest{
			Name:     bad,
			Selector: "all",
			Fragment: minimalFragment(),
		})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/roles", bytes.NewReader(body))
		req.Header.Set("X-API-Key", apiKey)
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		server.router.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusBadRequest, rec.Code, "expected 400 for name=%q", bad)
	}
}

// TestHandleCreateRoleConfig_WithFragment verifies a role with a populated StewardConfig
// fragment round-trips correctly.
func TestHandleCreateRoleConfig_WithFragment(t *testing.T) {
	server := setupRoleConfigServer(t)
	apiKey := NewEphemeralTestKey(t, server, []string{"role:write", "role:read"}, "test-tenant", 5*time.Minute)

	fragment := stewardtypes.StewardConfig{
		Steward: stewardtypes.StewardSettings{
			Logging: stewardtypes.LoggingConfig{Level: "debug"},
		},
	}
	body, _ := json.Marshal(createRoleConfigRequest{
		Name:     "debug-role",
		Selector: "tag:debug",
		Fragment: fragment,
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/roles", bytes.NewReader(body))
	req.Header.Set("X-API-Key", apiKey)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())

	// GET and verify the fragment logging level is preserved.
	req2 := httptest.NewRequest(http.MethodGet, "/api/v1/roles/debug-role", nil)
	req2.Header.Set("X-API-Key", apiKey)
	rec2 := httptest.NewRecorder()
	server.router.ServeHTTP(rec2, req2)
	require.Equal(t, http.StatusOK, rec2.Code)

	var getResp APIResponse
	require.NoError(t, json.Unmarshal(rec2.Body.Bytes(), &getResp))
	got, ok := getResp.Data.(map[string]interface{})
	require.True(t, ok)

	frag, ok := got["fragment"].(map[string]interface{})
	require.True(t, ok, "expected fragment object")
	steward, ok := frag["steward"].(map[string]interface{})
	require.True(t, ok)
	logging, ok := steward["logging"].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "debug", fmt.Sprintf("%v", logging["level"]))
}

// TestHandleRoleConfig_RootAdminTenantTargeting is the regression guard for the
// #2548 authoring fix: role configs are stored per tenant, so a global/root admin
// (empty principal tenant) must select the target tenant via ?tenant=. Without it
// the store call fails "tenant ID is required"; the handler must reject that as a
// 400 up front, and honor ?tenant= (with cross-tenant isolation) when present.
func TestHandleRoleConfig_RootAdminTenantTargeting(t *testing.T) {
	server := setupRoleConfigServer(t)
	// A root/global admin (as minted by the mTLS admin bundle) carries no tenant.
	// The API-key auth path cannot represent this (it requires a tenant), so drive
	// the handlers directly with a root Principal in context — the tenant-
	// resolution logic under test lives in the handler, not the middleware.
	rootPrincipal := &Principal{ID: "root-admin"}
	withRoot := func(req *http.Request) *http.Request {
		return req.WithContext(context.WithValue(req.Context(), principalContextKey, rootPrincipal))
	}

	post := func(url string) *httptest.ResponseRecorder {
		req := withRoot(httptest.NewRequest(http.MethodPost, url,
			bytes.NewReader(validRolePayload("hyperv-host", "os:windows tag:hyperv-host"))))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		server.handleCreateRoleConfig(rec, req)
		return rec
	}
	list := func(url string) *httptest.ResponseRecorder {
		req := withRoot(httptest.NewRequest(http.MethodGet, url, nil))
		rec := httptest.NewRecorder()
		server.handleListRoleConfigs(rec, req)
		return rec
	}

	// Without ?tenant= → 400 (a root admin cannot author into an empty tenant).
	recNoTenant := post("/api/v1/roles")
	require.Equal(t, http.StatusBadRequest, recNoTenant.Code,
		"root admin without ?tenant= must be rejected; body: %s", recNoTenant.Body.String())

	// With ?tenant=infra-x → 201, stored under that tenant.
	recCreate := post("/api/v1/roles?tenant=infra-x")
	require.Equal(t, http.StatusCreated, recCreate.Code,
		"root admin with ?tenant= must succeed; body: %s", recCreate.Body.String())

	// Listing the same tenant returns it; a different tenant does not (isolation).
	recSame := list("/api/v1/roles?tenant=infra-x")
	require.Equal(t, http.StatusOK, recSame.Code)
	assert.Contains(t, recSame.Body.String(), "hyperv-host",
		"role must be listed under the tenant it was authored in")

	recOther := list("/api/v1/roles?tenant=other-tenant")
	require.Equal(t, http.StatusOK, recOther.Code)
	assert.NotContains(t, recOther.Body.String(), "hyperv-host",
		"role must not leak across tenants")

	// A root admin omitting ?tenant= must be rejected 400 on GET/LIST/DELETE too —
	// NOT reach the store with an empty tenant (which 500s on get/delete and, worse,
	// lists across ALL tenants on the default flatfile backend).
	recListNoTenant := list("/api/v1/roles")
	assert.Equal(t, http.StatusBadRequest, recListNoTenant.Code,
		"root admin LIST without ?tenant= must be 400, not a cross-tenant listing; body: %s", recListNoTenant.Body.String())

	getNoTenant := withRoot(httptest.NewRequest(http.MethodGet, "/api/v1/roles/hyperv-host", nil))
	getNoTenant = mux.SetURLVars(getNoTenant, map[string]string{"name": "hyperv-host"})
	recGet := httptest.NewRecorder()
	server.handleGetRoleConfig(recGet, getNoTenant)
	assert.Equal(t, http.StatusBadRequest, recGet.Code,
		"root admin GET without ?tenant= must be 400, not 500; body: %s", recGet.Body.String())

	delNoTenant := withRoot(httptest.NewRequest(http.MethodDelete, "/api/v1/roles/hyperv-host", nil))
	delNoTenant = mux.SetURLVars(delNoTenant, map[string]string{"name": "hyperv-host"})
	recDel := httptest.NewRecorder()
	server.handleDeleteRoleConfig(recDel, delNoTenant)
	assert.Equal(t, http.StatusBadRequest, recDel.Code,
		"root admin DELETE without ?tenant= must be 400, not 500; body: %s", recDel.Body.String())
}
