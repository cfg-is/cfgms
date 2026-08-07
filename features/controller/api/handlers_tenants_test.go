// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/tenant"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
	"github.com/cfgis/cfgms/pkg/session"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	pkgtesting "github.com/cfgis/cfgms/pkg/testing"
)

// tenantIDsFromListResponse extracts the slice of tenant IDs from a list-endpoint response body.
func tenantIDsFromListResponse(t *testing.T, body []byte) []string {
	t.Helper()
	var resp APIResponse
	require.NoError(t, json.Unmarshal(body, &resp))
	items, ok := resp.Data.([]interface{})
	require.True(t, ok, "response data must be a JSON array")
	ids := make([]string, 0, len(items))
	for _, item := range items {
		m, ok := item.(map[string]interface{})
		require.True(t, ok, "each list item must be a JSON object")
		if id, ok := m["id"].(string); ok {
			ids = append(ids, id)
		}
	}
	return ids
}

func TestHandleCreateTenant_ExplicitID(t *testing.T) {
	server := setupTestServer(t)

	body, _ := json.Marshal(map[string]string{"id": "team-root"})
	req := makeAdminRequest(t, http.MethodPost, "/api/v1/tenants", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	server.router.ServeHTTP(w, req)

	require.Equal(t, http.StatusCreated, w.Code, "expected 201 on successful tenant creation")

	var resp APIResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))

	data, ok := resp.Data.(map[string]interface{})
	require.True(t, ok, "response data must be a map")
	assert.Equal(t, "team-root", data["id"], "stored ID must match the requested explicit ID exactly")
}

func TestHandleCreateTenant_DuplicateID(t *testing.T) {
	server := setupTestServer(t)

	// Create the tenant once
	ctx := context.Background()
	_, err := server.tenantManager.CreateTenant(ctx, &tenant.TenantRequest{ID: "dup-tenant"})
	require.NoError(t, err)

	// Attempt to create with the same ID — must return 409
	body, _ := json.Marshal(map[string]string{"id": "dup-tenant"})
	req := makeAdminRequest(t, http.MethodPost, "/api/v1/tenants", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	server.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusConflict, w.Code, "duplicate tenant ID must return 409")
}

func TestHandleCreateTenant_InvalidBody(t *testing.T) {
	server := setupTestServer(t)

	req := makeAdminRequest(t, http.MethodPost, "/api/v1/tenants", bytes.NewBufferString("not-json"))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	server.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestHandleCreateTenant_InvalidExplicitID(t *testing.T) {
	server := setupTestServer(t)

	body, _ := json.Marshal(map[string]string{"id": "Team_Root"})
	req := makeAdminRequest(t, http.MethodPost, "/api/v1/tenants", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	server.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code, "non-K8s-compatible ID must be rejected")
}

func TestHandleCreateTenant_MissingPermission(t *testing.T) {
	server := setupTestServer(t)
	apiKey := NewTestKey(t, server, []string{"steward:read"})

	body, _ := json.Marshal(map[string]string{"id": "no-perm-tenant"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/tenants", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", apiKey)
	w := httptest.NewRecorder()

	server.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestHandleGetTenant_Exists(t *testing.T) {
	server := setupTestServer(t)

	// Use an unscoped admin request so the caller can read any tenant.
	ctx := context.Background()
	td, err := server.tenantManager.CreateTenant(ctx, &tenant.TenantRequest{ID: "readable-tenant"})
	require.NoError(t, err)

	req := makeAdminRequest(t, http.MethodGet, fmt.Sprintf("/api/v1/tenants/%s", td.ID), nil)
	w := httptest.NewRecorder()

	server.router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)

	var resp APIResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	data, ok := resp.Data.(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "readable-tenant", data["id"])
}

func TestHandleGetTenant_NotFound(t *testing.T) {
	server := setupTestServer(t)
	apiKey := NewEphemeralTestKey(t, server, []string{"tenant:read"}, "nonexistent-tenant", 5*time.Minute)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/tenants/nonexistent-tenant", nil)
	req.Header.Set("X-API-Key", apiKey)
	w := httptest.NewRecorder()

	server.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestHandleGetTenant_MissingPermission(t *testing.T) {
	server := setupTestServer(t)
	apiKey := NewTestKey(t, server, []string{"steward:read"})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/tenants/some-tenant", nil)
	req.Header.Set("X-API-Key", apiKey)
	w := httptest.NewRecorder()

	server.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestHandleSuspendTenant_Success(t *testing.T) {
	server := setupTestServer(t)
	apiKey := NewEphemeralTestKey(t, server, []string{"tenant:manage"}, "suspendable-tenant", 5*time.Minute)

	ctx := context.Background()
	_, err := server.tenantManager.CreateTenant(ctx, &tenant.TenantRequest{ID: "suspendable-tenant"})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/tenants/suspendable-tenant/suspend", nil)
	req.Header.Set("X-API-Key", apiKey)
	w := httptest.NewRecorder()

	server.router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code, "suspend must return 200")

	var resp APIResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	data, ok := resp.Data.(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "suspendable-tenant", data["id"])
	assert.Equal(t, string(business.TenantStatusSuspended), data["status"])

	// Verify status persisted to storage
	td, err := server.tenantManager.GetTenant(ctx, "suspendable-tenant")
	require.NoError(t, err)
	assert.Equal(t, business.TenantStatusSuspended, td.Status)
}

func TestHandleSuspendTenant_NotFound(t *testing.T) {
	server := setupTestServer(t)
	apiKey := NewEphemeralTestKey(t, server, []string{"tenant:manage"}, "nonexistent-tenant", 5*time.Minute)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/tenants/nonexistent-tenant/suspend", nil)
	req.Header.Set("X-API-Key", apiKey)
	w := httptest.NewRecorder()

	server.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestHandleSuspendTenant_MissingPermission(t *testing.T) {
	server := setupTestServer(t)
	apiKey := NewTestKey(t, server, []string{"tenant:read"})

	ctx := context.Background()
	_, err := server.tenantManager.CreateTenant(ctx, &tenant.TenantRequest{ID: "perm-check-tenant"})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/tenants/perm-check-tenant/suspend", nil)
	req.Header.Set("X-API-Key", apiKey)
	w := httptest.NewRecorder()

	server.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
}

// TestHandleGetTenant_ResponseShape verifies the full shape of the tenant JSON response.
func TestHandleGetTenant_ResponseShape(t *testing.T) {
	server := setupTestServer(t)

	ctx := context.Background()
	td, err := server.tenantManager.CreateTenant(ctx, &tenant.TenantRequest{
		ID:          "shape-tenant",
		Description: "test description",
	})
	require.NoError(t, err)

	// Unscoped admin reads any tenant.
	req := makeAdminRequest(t, http.MethodGet, "/api/v1/tenants/shape-tenant", nil)
	w := httptest.NewRecorder()

	server.router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)

	var resp APIResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	data, ok := resp.Data.(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, td.ID, data["id"])
	assert.Equal(t, string(business.TenantStatusActive), data["status"])
	assert.NotEmpty(t, data["created_at"])
}

// TestHandleGetTenant_CrossTenant_Returns404 verifies that a caller scoped to one
// tenant receives 404 (not 403) when requesting a tenant outside its subtree, so the
// response is indistinguishable from a nonexistent ID (Issue #3147, AC: REQUIRED TEST).
func TestHandleGetTenant_CrossTenant_Returns404(t *testing.T) {
	server := setupTestServer(t)

	// Create two sibling tenants — the caller is scoped to client-1, not client-2.
	ctx := context.Background()
	_, err := server.tenantManager.CreateTenant(ctx, &tenant.TenantRequest{ID: "client-2"})
	require.NoError(t, err)

	// Caller scoped to client-1.
	callerKey := NewEphemeralTestKey(t, server, []string{"tenant:read"}, "client-1", 5*time.Minute)

	// Request the existing client-2 record — must be 404 (existence must not be disclosed).
	req := httptest.NewRequest(http.MethodGet, "/api/v1/tenants/client-2", nil)
	req.Header.Set("X-API-Key", callerKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	// Compare with a genuinely nonexistent tenant to ensure the responses are identical.
	reqNonexistent := httptest.NewRequest(http.MethodGet, "/api/v1/tenants/does-not-exist", nil)
	reqNonexistent.Header.Set("X-API-Key", callerKey)
	recNonexistent := httptest.NewRecorder()
	server.router.ServeHTTP(recNonexistent, reqNonexistent)

	assert.Equal(t, http.StatusNotFound, rec.Code, "cross-tenant get must return 404, not 403")
	assert.Equal(t, recNonexistent.Code, rec.Code, "status must match nonexistent-ID response")

	var errResp, errRespNonexistent ErrorResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&errResp))
	require.NoError(t, json.NewDecoder(recNonexistent.Body).Decode(&errRespNonexistent))
	assert.Equal(t, "TENANT_NOT_FOUND", errResp.Error.Code)
	assert.Equal(t, errRespNonexistent.Error.Code, errResp.Error.Code,
		"error code must match nonexistent-ID response")
	assert.Equal(t, errRespNonexistent.Error.Message, errResp.Error.Message,
		"error message must match nonexistent-ID response")
}

// TestHandleGetTenant_SameTenant_Returns200 verifies that a caller scoped to a tenant
// can read that tenant's own record (Issue #3147).
func TestHandleGetTenant_SameTenant_Returns200(t *testing.T) {
	server := setupTestServer(t)

	ctx := context.Background()
	_, err := server.tenantManager.CreateTenant(ctx, &tenant.TenantRequest{ID: "msp-a"})
	require.NoError(t, err)

	callerKey := NewEphemeralTestKey(t, server, []string{"tenant:read"}, "msp-a", 5*time.Minute)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/tenants/msp-a", nil)
	req.Header.Set("X-API-Key", callerKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var resp APIResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	data, ok := resp.Data.(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "msp-a", data["id"])
}

// TestHandleGetTenant_UnscopedAdmin_CanReadAnyTenant verifies that a principal with an
// empty caller tenant (unscoped mTLS admin) can read any tenant record (Issue #3147).
func TestHandleGetTenant_UnscopedAdmin_CanReadAnyTenant(t *testing.T) {
	server := setupTestServer(t)

	ctx := context.Background()
	_, err := server.tenantManager.CreateTenant(ctx, &tenant.TenantRequest{ID: "any-tenant"})
	require.NoError(t, err)

	req := makeAdminRequest(t, http.MethodGet, "/api/v1/tenants/any-tenant", nil)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var resp APIResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	data, ok := resp.Data.(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "any-tenant", data["id"])
}

// TestHandleGetTenant_SiblingPrefix_Returns404 verifies that "client-1" cannot read
// "client-10" — a bare HasPrefix check without the "/" separator would allow this
// incorrectly (Issue #3147).
func TestHandleGetTenant_SiblingPrefix_Returns404(t *testing.T) {
	server := setupTestServer(t)

	ctx := context.Background()
	_, err := server.tenantManager.CreateTenant(ctx, &tenant.TenantRequest{ID: "client-10"})
	require.NoError(t, err)

	// "client-1" scoped caller tries to read "client-10".
	callerKey := NewEphemeralTestKey(t, server, []string{"tenant:read"}, "client-1", 5*time.Minute)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/tenants/client-10", nil)
	req.Header.Set("X-API-Key", callerKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNotFound, rec.Code,
		"sibling-prefix tenant must return 404 (client-1 must not match client-10)")
	var errResp ErrorResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&errResp))
	assert.Equal(t, "TENANT_NOT_FOUND", errResp.Error.Code)
}

// --- handleListTenants tests ---

// TestHandleListTenants_UnscopedAdmin_ReturnsAll verifies that an unscoped mTLS admin
// (callerTenant == "") receives all tenants in the list response.
func TestHandleListTenants_UnscopedAdmin_ReturnsAll(t *testing.T) {
	server := setupTestServer(t)

	ctx := context.Background()
	_, err := server.tenantManager.CreateTenant(ctx, &tenant.TenantRequest{ID: "list-alpha"})
	require.NoError(t, err)
	_, err = server.tenantManager.CreateTenant(ctx, &tenant.TenantRequest{ID: "list-beta"})
	require.NoError(t, err)

	req := makeAdminRequest(t, http.MethodGet, "/api/v1/tenants", nil)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	ids := tenantIDsFromListResponse(t, rec.Body.Bytes())
	assert.Contains(t, ids, "list-alpha")
	assert.Contains(t, ids, "list-beta")
}

// TestHandleListTenants_ScopedCaller_FiltersToOwnTenant verifies that a caller scoped
// to a specific tenant only sees their own tenant ID in the list (not others).
func TestHandleListTenants_ScopedCaller_FiltersToOwnTenant(t *testing.T) {
	server := setupTestServer(t)

	ctx := context.Background()
	_, err := server.tenantManager.CreateTenant(ctx, &tenant.TenantRequest{ID: "scoped-mine"})
	require.NoError(t, err)
	_, err = server.tenantManager.CreateTenant(ctx, &tenant.TenantRequest{ID: "scoped-other"})
	require.NoError(t, err)

	callerKey := NewEphemeralTestKey(t, server, []string{"tenant:list"}, "scoped-mine", 5*time.Minute)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/tenants", nil)
	req.Header.Set("X-API-Key", callerKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	ids := tenantIDsFromListResponse(t, rec.Body.Bytes())
	assert.Contains(t, ids, "scoped-mine", "caller must see their own tenant")
	assert.NotContains(t, ids, "scoped-other", "caller must not see an unrelated tenant")
}

// TestHandleListTenants_ClientScopedCallerCannotSeeSibling is a REQUIRED test (Issue #3125
// AC: "a caller scoped to client-1 calling GET /tenants never sees a sibling tenant
// (client-2) or an ancestor-only tenant outside their subtree").
func TestHandleListTenants_ClientScopedCallerCannotSeeSibling(t *testing.T) {
	server := setupTestServer(t)

	ctx := context.Background()
	_, err := server.tenantManager.CreateTenant(ctx, &tenant.TenantRequest{ID: "list-client-1"})
	require.NoError(t, err)
	_, err = server.tenantManager.CreateTenant(ctx, &tenant.TenantRequest{ID: "list-client-2"})
	require.NoError(t, err)

	callerKey := NewEphemeralTestKey(t, server, []string{"tenant:list"}, "list-client-1", 5*time.Minute)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/tenants", nil)
	req.Header.Set("X-API-Key", callerKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	ids := tenantIDsFromListResponse(t, rec.Body.Bytes())
	assert.Contains(t, ids, "list-client-1", "caller must see their own tenant")
	assert.NotContains(t, ids, "list-client-2",
		"sibling tenant list-client-2 must not be visible to list-client-1 scoped caller")
}

// TestHandleListTenants_UnrelatedFlatTenant_NotVisible covers the same fixture shape
// Issue #3125's original ADR-025 AC used ("root" caller, "msp-a" target) but names what
// it actually verifies: a caller scoped to one flat, unrelated tenant ID does not see
// another flat tenant that happens to share no ParentID ancestry with it. This passes
// under isCallerAuthorizedForTenant's IsTenantAncestor check because "root" is not an
// ancestor of "msp-a" in the store — the same result plain sibling-exclusion produces,
// and NOT a stand-in for ADR-025 Decision 1's root<->MSP boundary check.
//
// ADR-025 Decision 1 (a root-scoped caller is walled off from an MSP subtree it *is*
// the ancestor of, absent an active grant/break-glass session) is intentionally not
// covered by this test: Amendment 1's A1.3 (distinguishing a genuinely root-scoped
// caller from an unscoped superadmin — both present as callerTenant == "" today) is an
// open design question the ADR explicitly leaves to a follow-on decision, and the
// grant/break-glass override has no store-backed state yet. See
// isCallerAuthorizedForTenant's doc comment and the follow-up tracked in #3228.
func TestHandleListTenants_UnrelatedFlatTenant_NotVisible(t *testing.T) {
	server := setupTestServer(t)

	ctx := context.Background()
	_, err := server.tenantManager.CreateTenant(ctx, &tenant.TenantRequest{ID: "root"})
	require.NoError(t, err)
	_, err = server.tenantManager.CreateTenant(ctx, &tenant.TenantRequest{ID: "msp-a"})
	require.NoError(t, err)

	callerKey := NewEphemeralTestKey(t, server, []string{"tenant:list"}, "root", 5*time.Minute)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/tenants", nil)
	req.Header.Set("X-API-Key", callerKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	ids := tenantIDsFromListResponse(t, rec.Body.Bytes())
	assert.Contains(t, ids, "root", "root-scoped caller must see the root tenant itself")
	assert.NotContains(t, ids, "msp-a",
		"a flat tenant ID with no ParentID ancestry relationship to the caller must not be visible")
}

// TestHandleListTenants_ScopedCaller_SeesOwnDescendant is a regression test for the
// functional break the acceptance review found in isWithinTenantScope's dead prefix
// branch: real tenant hierarchy is carried by ParentID, not by tenant-ID string
// concatenation, so an MSP admin scoped to "msp-a" could not see its own child tenant
// "client-1" (ParentID: "msp-a") through GET /api/v1/tenants. isCallerAuthorizedForTenant
// fixes this via IsTenantAncestor, which walks the real ParentID chain.
func TestHandleListTenants_ScopedCaller_SeesOwnDescendant(t *testing.T) {
	server := setupTestServer(t)

	ctx := context.Background()
	_, err := server.tenantManager.CreateTenant(ctx, &tenant.TenantRequest{ID: "desc-msp-a"})
	require.NoError(t, err)
	_, err = server.tenantManager.CreateTenant(ctx, &tenant.TenantRequest{
		ID:       "desc-client-1",
		ParentID: "desc-msp-a",
	})
	require.NoError(t, err)
	_, err = server.tenantManager.CreateTenant(ctx, &tenant.TenantRequest{ID: "desc-unrelated"})
	require.NoError(t, err)

	callerKey := NewEphemeralTestKey(t, server, []string{"tenant:list"}, "desc-msp-a", 5*time.Minute)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/tenants", nil)
	req.Header.Set("X-API-Key", callerKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	ids := tenantIDsFromListResponse(t, rec.Body.Bytes())
	assert.Contains(t, ids, "desc-msp-a", "caller must see its own tenant")
	assert.Contains(t, ids, "desc-client-1",
		"caller must see its real child tenant via ParentID ancestry, not tenant-ID prefix matching")
	assert.NotContains(t, ids, "desc-unrelated", "caller must not see an unrelated tenant")
}

// TestHandleListTenants_MissingPermission verifies that a caller without tenant:list
// receives 403 Forbidden.
func TestHandleListTenants_MissingPermission(t *testing.T) {
	server := setupTestServer(t)
	callerKey := NewTestKey(t, server, []string{"steward:read"})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/tenants", nil)
	req.Header.Set("X-API-Key", callerKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code)
}

// TestHandleListTenants_StorageFailure_Returns500 covers handleListTenants' storage-failure
// branch, the one path the scope-filtering and permission tests above never reach.
//
// The failure is produced by the genuine sqlite tenant store rather than a substitute
// store: the handler passes r.Context() straight through to ListTenants, and the provider
// issues the query with QueryContext, so a cancelled request context makes the driver fail
// for real. That is also a fault this endpoint sees in production — a client disconnecting
// or a request deadline elapsing mid-query.
//
// The handler is invoked directly because the failure has to originate inside
// ListTenants; routing a cancelled-context request would abort in the authentication
// middleware's own store lookups first and never reach the handler.
func TestHandleListTenants_StorageFailure_Returns500(t *testing.T) {
	capLog := &errorCapturingLogger{}
	server := setupTestServerWithLogger(t, capLog)

	// A tenant the caller is authorized to see, so an empty result cannot be mistaken
	// for a correct response: on the success path this ID is returned.
	_, err := server.tenantManager.CreateTenant(context.Background(), &tenant.TenantRequest{
		ID: "list-failure-visible",
	})
	require.NoError(t, err)

	listAsUnscopedAdmin := func(ctx context.Context) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/tenants", nil)
		req = req.WithContext(context.WithValue(ctx, ctxkeys.TenantID, ""))
		rec := httptest.NewRecorder()
		server.handleListTenants(rec, req)
		return rec
	}

	// Precondition: with a healthy store the same call succeeds and returns the tenant.
	// Without this the 500 below could come from a handler that never works at all.
	healthy := listAsUnscopedAdmin(context.Background())
	require.Equal(t, http.StatusOK, healthy.Code, "precondition: the healthy path must return 200")
	require.Contains(t, tenantIDsFromListResponse(t, healthy.Body.Bytes()), "list-failure-visible")

	failedCtx, cancel := context.WithCancel(context.Background())
	cancel()
	rec := listAsUnscopedAdmin(failedCtx)

	require.Equal(t, http.StatusInternalServerError, rec.Code,
		"a store failure must be reported as 500, never as an empty success list")

	var errResp ErrorResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&errResp))
	assert.Equal(t, "LIST_FAILED", errResp.Error.Code)
	assert.Equal(t, "failed to list tenants", errResp.Error.Message,
		"the client must receive a generic message, not backend driver text")
	assert.NotContains(t, errResp.Error.Message, "list-failure-visible",
		"a failed list must not disclose any tenant ID")

	// The detail the client is denied must still reach the operator, sanitized like
	// every other caller-influenced log value in this file.
	loggedErr, ok := capLog.kvValue("error").(string)
	require.True(t, ok, "the store failure must be logged as a sanitized string under 'error'")
	assert.Contains(t, loggedErr, "context canceled",
		"the operator must get the underlying store fault")
	assert.NotContains(t, loggedErr, "\n", "log values must not carry newlines")
	assert.NotContains(t, loggedErr, "\r", "log values must not carry carriage returns")
}

// --- handleUpdateTenant tests ---

// TestHandleUpdateTenant_Success verifies that PUT /api/v1/tenants/{id} updates the
// tenant's name and description and returns the updated record.
func TestHandleUpdateTenant_Success(t *testing.T) {
	server := setupTestServer(t)

	ctx := context.Background()
	_, err := server.tenantManager.CreateTenant(ctx, &tenant.TenantRequest{
		ID:          "update-me",
		Description: "original",
	})
	require.NoError(t, err)

	body, _ := json.Marshal(map[string]string{
		"name":        "update-me",
		"description": "updated",
	})
	req := makeAdminRequest(t, http.MethodPut, "/api/v1/tenants/update-me", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var resp APIResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	data, ok := resp.Data.(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "update-me", data["id"])
	assert.Equal(t, "updated", data["description"])
}

// TestHandleUpdateTenant_NotFound verifies that updating a non-existent tenant returns 404.
//
// The handler classifies the miss with errors.Is against business.ErrTenantDoesNotExist.
// No storage provider's message contains the literal "tenant not found" any more, so a
// regression to substring classification fails this test rather than silently returning
// 500 for a missing tenant while an out-of-scope tenant still returns 404 — a status
// split that would disclose the existence of tenants outside the caller's subtree.
func TestHandleUpdateTenant_NotFound(t *testing.T) {
	server := setupTestServer(t)

	body, _ := json.Marshal(map[string]string{"name": "whatever"})
	req := makeAdminRequest(t, http.MethodPut, "/api/v1/tenants/does-not-exist", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNotFound, rec.Code)
	var errResp ErrorResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&errResp))
	assert.Equal(t, "TENANT_NOT_FOUND", errResp.Error.Code)
}

// TestHandleUpdateTenant_InvalidBody verifies that a malformed request body returns 400.
func TestHandleUpdateTenant_InvalidBody(t *testing.T) {
	server := setupTestServer(t)

	ctx := context.Background()
	_, err := server.tenantManager.CreateTenant(ctx, &tenant.TenantRequest{ID: "update-badbody"})
	require.NoError(t, err)

	req := makeAdminRequest(t, http.MethodPut, "/api/v1/tenants/update-badbody", bytes.NewBufferString("not-json"))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

// TestHandleUpdateTenant_MissingPermission verifies that a caller without tenant:update
// receives 403 Forbidden.
func TestHandleUpdateTenant_MissingPermission(t *testing.T) {
	server := setupTestServer(t)
	callerKey := NewTestKey(t, server, []string{"steward:read"})

	body, _ := json.Marshal(map[string]string{"name": "whatever"})
	req := httptest.NewRequest(http.MethodPut, "/api/v1/tenants/any-tenant", bytes.NewReader(body))
	req.Header.Set("X-API-Key", callerKey)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code)
}

// putTenantAsScopedCaller invokes handleUpdateTenant for a caller scoped to callerTenant
// and returns the recorder.
//
// The handler is called directly rather than through the router because
// requirePermission's tenant-isolation middleware denies a non-global scoped principal
// before the handler runs. The handler's own isCallerAuthorizedForTenant guard is the last line
// of defence for a principal that legitimately clears that middleware — GlobalScope=true
// carrying a TenantID, the "strongly-authenticated but tenant-scoped" shape the Principal
// doc comment requires to stay confined. That shape is exercised end-to-end through the
// router in TestHandleUpdateTenant_ScopedStrongSession_CrossTenantReturns404; these
// direct-call tests pin the guard's decision table without a session per case.
func putTenantAsScopedCaller(t *testing.T, server *Server, callerTenant, targetID string, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPut, "/api/v1/tenants/"+targetID, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	// Inject mux path variables (not populated when calling the handler directly).
	req = mux.SetURLVars(req, map[string]string{"id": targetID})
	req = req.WithContext(context.WithValue(req.Context(), ctxkeys.TenantID, callerTenant))

	rec := httptest.NewRecorder()
	server.handleUpdateTenant(rec, req)
	return rec
}

// TestHandleUpdateTenant_CrossTenant_Returns404 verifies that a caller scoped to one
// tenant receives 404 (not 403) when attempting to PUT a tenant outside its subtree,
// byte-identical to the response for an ID that does not exist at all — so the reply
// cannot be used to enumerate tenants in other scopes. It also verifies the target
// tenant is left untouched.
func TestHandleUpdateTenant_CrossTenant_Returns404(t *testing.T) {
	server := setupTestServer(t)

	ctx := context.Background()
	// Target exists but belongs to a different scope ("cross-target").
	_, err := server.tenantManager.CreateTenant(ctx, &tenant.TenantRequest{
		ID:          "cross-target",
		Description: "original",
	})
	require.NoError(t, err)

	body, _ := json.Marshal(map[string]string{
		"name":        "cross-target",
		"description": "hijacked",
	})

	// Caller scoped to "cross-owner" — a different subtree from the target.
	rec := putTenantAsScopedCaller(t, server, "cross-owner", "cross-target", body)
	// Same caller, an ID that does not exist at all.
	recNonexistent := putTenantAsScopedCaller(t, server, "cross-owner", "does-not-exist", body)

	require.Equal(t, http.StatusNotFound, rec.Code,
		"cross-tenant update must return 404, not 403, to prevent existence disclosure")
	assert.Equal(t, recNonexistent.Code, rec.Code, "status must match nonexistent-ID response")

	var errResp, errRespNonexistent ErrorResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&errResp))
	require.NoError(t, json.NewDecoder(recNonexistent.Body).Decode(&errRespNonexistent))
	assert.Equal(t, "TENANT_NOT_FOUND", errResp.Error.Code)
	assert.Equal(t, errRespNonexistent.Error.Code, errResp.Error.Code,
		"error code must match nonexistent-ID response")
	assert.Equal(t, errRespNonexistent.Error.Message, errResp.Error.Message,
		"error message must match nonexistent-ID response")

	// The refused write must not have been applied.
	unchanged, err := server.tenantManager.GetTenant(ctx, "cross-target")
	require.NoError(t, err)
	assert.Equal(t, "original", unchanged.Description,
		"a refused cross-tenant update must not mutate the target tenant")
}

// TestHandleUpdateTenant_SiblingPrefix_Returns404 verifies that "client-1" cannot update
// "client-10" — a bare HasPrefix check without the "/" separator would allow this
// incorrectly, exactly as TestHandleGetTenant_SiblingPrefix_Returns404 pins for reads.
func TestHandleUpdateTenant_SiblingPrefix_Returns404(t *testing.T) {
	server := setupTestServer(t)

	ctx := context.Background()
	_, err := server.tenantManager.CreateTenant(ctx, &tenant.TenantRequest{
		ID:          "client-10",
		Description: "original",
	})
	require.NoError(t, err)

	body, _ := json.Marshal(map[string]string{
		"name":        "client-10",
		"description": "hijacked",
	})
	rec := putTenantAsScopedCaller(t, server, "client-1", "client-10", body)

	require.Equal(t, http.StatusNotFound, rec.Code,
		"sibling-prefix tenant must return 404 (client-1 must not match client-10)")
	var errResp ErrorResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&errResp))
	assert.Equal(t, "TENANT_NOT_FOUND", errResp.Error.Code)

	unchanged, err := server.tenantManager.GetTenant(ctx, "client-10")
	require.NoError(t, err)
	assert.Equal(t, "original", unchanged.Description,
		"a refused sibling-prefix update must not mutate the target tenant")
}

// TestHandleUpdateTenant_OwnTenant_Allowed is the positive half of the scope guard:
// a scoped caller may update its own tenant. Without this, a guard that refused every
// scoped caller would still pass the 404 tests above.
//
// Only the self case (resourceTenant == callerTenant, which IsTenantAncestor reports
// true for since a tenant's own path always includes itself) is exercised here.
// Genuine descendant access via IsTenantAncestor is covered separately by
// TestHandleListTenants_ScopedCaller_SeesOwnDescendant.
func TestHandleUpdateTenant_OwnTenant_Allowed(t *testing.T) {
	server := setupTestServer(t)
	ctx := context.Background()

	_, err := server.tenantManager.CreateTenant(ctx, &tenant.TenantRequest{
		ID:          "msp-a",
		Description: "original",
	})
	require.NoError(t, err)

	body, _ := json.Marshal(map[string]string{
		"name":        "renamed",
		"description": "updated",
	})
	rec := putTenantAsScopedCaller(t, server, "msp-a", "msp-a", body)

	require.Equal(t, http.StatusOK, rec.Code,
		"caller scoped to msp-a must be allowed to update its own tenant")

	updated, err := server.tenantManager.GetTenant(ctx, "msp-a")
	require.NoError(t, err)
	assert.Equal(t, "updated", updated.Description, "the in-scope update must be applied")
}

// TestHandleUpdateTenant_ScopedStrongSession_CrossTenantReturns404 exercises the scope
// guard end-to-end through the router with a real credential.
//
// The principal is a cfg-CLI Bearer session issued for tenant "client-1" and elevated to
// AssuranceStrong (ADR-021 Amendment 2). That principal clears every earlier layer —
// tenant:update is granted, AssuranceStrong satisfies permissionAssurance, and
// GlobalScope=true means requirePermission's tenant-isolation check does not fire — so
// handleUpdateTenant's own isCallerAuthorizedForTenant guard is the only thing standing
// between it and another MSP client's tenant record.
func TestHandleUpdateTenant_ScopedStrongSession_CrossTenantReturns404(t *testing.T) {
	server, sessionMgr, _ := setupTestServerWithSession(t)
	ctx := context.Background()

	// A tenant that exists but sits outside the caller's subtree.
	_, err := server.tenantManager.CreateTenant(ctx, &tenant.TenantRequest{
		ID:          "client-2",
		Description: "original",
	})
	require.NoError(t, err)

	sess, _, err := sessionMgr.Issue(ctx, "msp-operator", "cfg-cli", "client-1")
	require.NoError(t, err)
	// httptest requests carry RemoteAddr 192.0.2.1:1234; binding the elevation to that
	// IP keeps the session at AssuranceStrong through the device-continuity check.
	elevated, token, err := sessionMgr.Elevate(ctx, sess.ID, []byte("test-credential-id"), "192.0.2.1")
	require.NoError(t, err)
	require.Equal(t, session.AssuranceStrong, elevated.Assurance,
		"precondition: the caller must clear the AssuranceStrong gate on tenant:update")

	body, _ := json.Marshal(map[string]string{
		"name":        "client-2",
		"description": "hijacked",
	})
	req := httptest.NewRequest(http.MethodPut, "/api/v1/tenants/client-2", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusNotFound, rec.Code,
		"a tenant-scoped strong-assurance caller must get 404 for a tenant outside its subtree")
	var errResp ErrorResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&errResp))
	assert.Equal(t, "TENANT_NOT_FOUND", errResp.Error.Code)

	unchanged, err := server.tenantManager.GetTenant(ctx, "client-2")
	require.NoError(t, err)
	assert.Equal(t, "original", unchanged.Description,
		"the cross-tenant update must not have been applied")
}

// TestHandleUpdateTenant_ValidationFailure_Returns400WithDetail verifies the one class
// of UpdateTenant failure whose text is returned to the caller: a rejection of the data
// they submitted. The message must be specific enough to correct the request.
func TestHandleUpdateTenant_ValidationFailure_Returns400WithDetail(t *testing.T) {
	server := setupTestServer(t)

	ctx := context.Background()
	_, err := server.tenantManager.CreateTenant(ctx, &tenant.TenantRequest{ID: "validate-me"})
	require.NoError(t, err)

	// A name containing a space fails Manager.validateTenantRequest's name regex.
	body, _ := json.Marshal(map[string]string{"name": "not a valid name"})
	req := makeAdminRequest(t, http.MethodPut, "/api/v1/tenants/validate-me", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusBadRequest, rec.Code, "a rejected payload is a client error")
	var errResp ErrorResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&errResp))
	assert.Equal(t, "VALIDATION_FAILED", errResp.Error.Code)
	assert.Contains(t, errResp.Error.Message, "validation failed",
		"the caller must be told which rule rejected their input")
}

// TestIsTenantInputRejection_OnlyEchoesCallerSuppliedRejections pins the allowlist that
// decides whether an UpdateTenant error's text reaches the HTTP client.
//
// The backend-fault strings below are the literal shapes produced by
// features/tenant/manager.go and pkg/storage/providers/database/tenant_store.go. Each
// carries controller internals — driver text naming the cfgms_tenants schema, the
// database host:port, Go type names. A tenant-scoped API key holding tenant:update is a
// downstream MSP-client principal, so returning any of them would leak controller
// internals across a tenant boundary. They must classify as server faults (generic 500).
func TestIsTenantInputRejection_OnlyEchoesCallerSuppliedRejections(t *testing.T) {
	callerRejections := []string{
		"validation failed: tenant name must contain only alphanumeric characters, hyphens, and underscores",
		"validation failed: tenant description must be 255 characters or less",
		"invalid config source metadata: config_source_url is required",
		"config source validation failed: mount point /etc/cfgms is not writable",
	}
	for _, msg := range callerRejections {
		assert.True(t, isTenantInputRejection(errors.New(msg)),
			"caller-actionable rejection must be returned verbatim: %q", msg)
	}

	backendFaults := []string{
		`failed to update tenant: pq: duplicate key value violates unique constraint "cfgms_tenants_pkey"`,
		"failed to update tenant: dial tcp 10.0.0.5:5432: connect: connection refused",
		"failed to marshal metadata: json: unsupported type: chan int",
		"tenant not found",
		"unexpected EOF",
	}
	for _, msg := range backendFaults {
		assert.False(t, isTenantInputRejection(errors.New(msg)),
			"backend fault text must never reach the client: %q", msg)
	}

	assert.False(t, isTenantInputRejection(nil), "a nil error is not a rejection")
}

// echoingUpdateTenantStore is a real tenant.Store (not a mock): every method except
// UpdateTenant runs against the wrapped durable store, so GetTenant, the scope check and
// tenant creation all exercise the genuine sqlite provider. UpdateTenant reproduces the
// one behaviour that matters here — a storage driver rejecting a write with a message that
// quotes the value the caller submitted. Postgres does this routinely (unique-constraint
// and value-length violations both echo the offending column value), which is how untrusted
// request-body bytes reach the controller's log line.
type echoingUpdateTenantStore struct {
	tenant.Store
}

func (s *echoingUpdateTenantStore) UpdateTenant(_ context.Context, td *business.TenantData) error {
	return fmt.Errorf("pq: value too long for type character varying (64), Key (description) is %q", td.Description)
}

// TestHandleUpdateTenant_BackendError_LogValueSanitized pins the go/log-injection fix at
// handlers_tenants.go: the "error" value logged when UpdateTenant fails must be passed
// through logging.SanitizeLogValue, exactly like the adjacent "tenant_id" field.
//
// The taint path is real: Manager.UpdateTenant wraps the store error as
// "failed to update tenant: %w", the store's text can quote the caller's Name/Description,
// and that class is deliberately excluded from isTenantInputRejection so it falls through
// to the Error log. Without sanitization a request body carrying CR/LF forges whole log
// lines in the controller log.
func TestHandleUpdateTenant_BackendError_LogValueSanitized(t *testing.T) {
	// The payload passes the request-validation middleware's safe_text charset — whose
	// regexp allows \s, and therefore CR and LF — so this is reachable over the wire by
	// any caller holding tenant:update, not a hypothetical.
	const forgedDescription = "evil\r\nERROR Tenant suspended by admin: forged log line"

	t.Run("control characters stripped from logged error", func(t *testing.T) {
		capLog := &errorCapturingLogger{}
		server := setupTestServerWithLogger(t, capLog)
		server.tenantManager = tenant.NewManager(
			&echoingUpdateTenantStore{Store: tenant.NewStorageAdapter(pkgtesting.SetupTestStorage(t).GetTenantStore())},
			server.rbacManager,
		)

		ctx := context.Background()
		_, err := server.tenantManager.CreateTenant(ctx, &tenant.TenantRequest{ID: "log-injection-target"})
		require.NoError(t, err)

		// The name must clear Manager.validateTenantRequest so the failure lands on the
		// store write; the injected control characters ride in on the description instead.
		body, err := json.Marshal(map[string]string{
			"name":        "log-injection-target",
			"description": forgedDescription,
		})
		require.NoError(t, err)
		req := makeAdminRequest(t, http.MethodPut, "/api/v1/tenants/log-injection-target", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		server.router.ServeHTTP(rec, req)

		require.Equal(t, http.StatusInternalServerError, rec.Code,
			"a store write failure is a backend fault, not a caller-actionable rejection")

		logged := capLog.kvValue("error")
		require.NotNil(t, logged, "the backend fault must be logged under the 'error' key")
		loggedStr, ok := logged.(string)
		require.True(t, ok, "the sanitized error must be logged as a string, not a raw error value")
		assert.NotContains(t, loggedStr, "\n", "CR/LF from the request body must not reach the log")
		assert.NotContains(t, loggedStr, "\r", "CR/LF from the request body must not reach the log")
		assert.Contains(t, loggedStr, "value too long for type",
			"sanitization must preserve the diagnostic text operators need")
		assert.NotContains(t, loggedStr, "ERROR Tenant suspended by admin: forged log line\n",
			"the forged entry must not survive as a standalone log line")
	})

	t.Run("clean backend error text preserved", func(t *testing.T) {
		capLog := &errorCapturingLogger{}
		server := setupTestServerWithLogger(t, capLog)
		server.tenantManager = tenant.NewManager(
			&echoingUpdateTenantStore{Store: tenant.NewStorageAdapter(pkgtesting.SetupTestStorage(t).GetTenantStore())},
			server.rbacManager,
		)

		ctx := context.Background()
		_, err := server.tenantManager.CreateTenant(ctx, &tenant.TenantRequest{ID: "log-clean-target"})
		require.NoError(t, err)

		body, err := json.Marshal(map[string]string{
			"name":        "log-clean-target",
			"description": "ordinary description",
		})
		require.NoError(t, err)
		req := makeAdminRequest(t, http.MethodPut, "/api/v1/tenants/log-clean-target", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		server.router.ServeHTTP(rec, req)

		require.Equal(t, http.StatusInternalServerError, rec.Code)

		loggedStr, ok := capLog.kvValue("error").(string)
		require.True(t, ok, "the sanitized error must be logged as a string")
		assert.Contains(t, loggedStr, "failed to update tenant",
			"a control-character-free backend error must survive sanitization unchanged")
	})
}

// TestHandleUpdateTenant_ParentIDIgnored is a REQUIRED test (Issue #3125 AC: "Attempting
// to change parent_id via update is rejected or silently ignored, covered by a test").
// Manager.UpdateTenant explicitly skips ParentID updates ("ParentID cannot be changed
// after creation to maintain hierarchy integrity"), so the handler inherits this contract.
func TestHandleUpdateTenant_ParentIDIgnored(t *testing.T) {
	server := setupTestServer(t)

	ctx := context.Background()
	_, err := server.tenantManager.CreateTenant(ctx, &tenant.TenantRequest{
		ID:       "parent-stable",
		ParentID: "parent-a",
	})
	require.NoError(t, err)

	// Submit an update that attempts to change the parent_id.
	body, _ := json.Marshal(map[string]string{
		"name":      "parent-stable",
		"parent_id": "parent-b",
	})
	req := makeAdminRequest(t, http.MethodPut, "/api/v1/tenants/parent-stable", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)

	// Verify the parent_id is unchanged.
	updated, err := server.tenantManager.GetTenant(ctx, "parent-stable")
	require.NoError(t, err)
	assert.Equal(t, "parent-a", updated.ParentID,
		"ParentID must remain unchanged after update; the manager silently ignores parent_id in update requests")
}

// TestHandleUpdateTenant_ForeignCredentialRef_Returns400 covers the write-content
// half of tenant isolation on PUT /api/v1/tenants/{id}.
//
// isCallerAuthorizedForTenant constrains *which* tenant row a scoped principal may
// mutate; it says nothing about the metadata written into it. config_source_credential
// is a secret-store key in "<tenant_id>/<secret_key>" form, and the mount-point
// validator and the configrouting git store fetch it and present the value as HTTP
// Basic auth to the host in config_source_url — a host the same request body chooses,
// and one the SSRF guard permits whenever it is a public HTTPS name. So an in-scope
// PUT naming another tenant's credential is a cross-tenant credential read, and the
// request must be rejected outright rather than persisted.
func TestHandleUpdateTenant_ForeignCredentialRef_Returns400(t *testing.T) {
	server := setupTestServer(t)
	ctx := context.Background()

	_, err := server.tenantManager.CreateTenant(ctx, &tenant.TenantRequest{ID: "victim-msp"})
	require.NoError(t, err)
	_, err = server.tenantManager.CreateTenant(ctx, &tenant.TenantRequest{ID: "client-msp"})
	require.NoError(t, err)

	body, _ := json.Marshal(map[string]interface{}{
		"name": "client-msp",
		"metadata": map[string]string{
			"config_source_type":       "git",
			"config_source_url":        "https://attacker.example/r.git",
			"config_source_credential": "victim-msp/git-token",
		},
	})
	rec := putTenantAsScopedCaller(t, server, "client-msp", "client-msp", body)

	require.Equal(t, http.StatusBadRequest, rec.Code,
		"a tenant-scoped caller must not be able to store another tenant's credential reference")
	var errResp ErrorResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&errResp))
	assert.Equal(t, "VALIDATION_FAILED", errResp.Error.Code)

	stored, err := server.tenantManager.GetTenant(ctx, "client-msp")
	require.NoError(t, err)
	assert.Empty(t, stored.Metadata["config_source_credential"],
		"the rejected credential reference must not be persisted")
	assert.Empty(t, stored.Metadata["config_source_url"],
		"no part of the rejected config source may be persisted")
}

// TestHandleUpdateTenant_OwnCredentialRef_Returns200 is the companion to the test
// above: the legitimate case — a tenant naming a secret in its own namespace — must
// still be accepted, so the isolation check cannot be satisfied by rejecting all
// credential references.
func TestHandleUpdateTenant_OwnCredentialRef_Returns200(t *testing.T) {
	server := setupTestServer(t)
	ctx := context.Background()

	_, err := server.tenantManager.CreateTenant(ctx, &tenant.TenantRequest{ID: "self-msp"})
	require.NoError(t, err)

	body, _ := json.Marshal(map[string]interface{}{
		"name": "self-msp",
		"metadata": map[string]string{
			"config_source_type":       "git",
			"config_source_url":        "https://git.example.com/configs.git",
			"config_source_credential": "self-msp/git-token",
		},
	})
	rec := putTenantAsScopedCaller(t, server, "self-msp", "self-msp", body)

	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	stored, err := server.tenantManager.GetTenant(ctx, "self-msp")
	require.NoError(t, err)
	assert.Equal(t, "self-msp/git-token", stored.Metadata["config_source_credential"])
}
