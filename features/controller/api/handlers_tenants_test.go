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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/tenant"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

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
	apiKey := NewTestKey(t, server, []string{"tenant:read"})

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
	apiKey := NewTestKey(t, server, []string{"tenant:manage"})

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
	apiKey := NewTestKey(t, server, []string{"tenant:manage"})

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
