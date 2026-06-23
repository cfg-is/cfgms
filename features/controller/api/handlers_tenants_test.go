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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/tenant"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

func TestHandleCreateTenant_ExplicitID(t *testing.T) {
	server := setupTestServer(t)
	apiKey := NewTestKey(t, server, []string{"tenant:create"})

	body, _ := json.Marshal(map[string]string{"id": "team-root"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/tenants", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", apiKey)
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
	apiKey := NewTestKey(t, server, []string{"tenant:create"})

	// Create the tenant once
	ctx := context.Background()
	_, err := server.tenantManager.CreateTenant(ctx, &tenant.TenantRequest{ID: "dup-tenant"})
	require.NoError(t, err)

	// Attempt to create with the same ID — must return 409
	body, _ := json.Marshal(map[string]string{"id": "dup-tenant"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/tenants", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", apiKey)
	w := httptest.NewRecorder()

	server.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusConflict, w.Code, "duplicate tenant ID must return 409")
}

func TestHandleCreateTenant_InvalidBody(t *testing.T) {
	server := setupTestServer(t)
	apiKey := NewTestKey(t, server, []string{"tenant:create"})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/tenants", bytes.NewBufferString("not-json"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", apiKey)
	w := httptest.NewRecorder()

	server.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestHandleCreateTenant_InvalidExplicitID(t *testing.T) {
	server := setupTestServer(t)
	apiKey := NewTestKey(t, server, []string{"tenant:create"})

	body, _ := json.Marshal(map[string]string{"id": "Team_Root"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/tenants", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", apiKey)
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
	apiKey := NewTestKey(t, server, []string{"tenant:read"})

	// Create a tenant to retrieve
	ctx := context.Background()
	td, err := server.tenantManager.CreateTenant(ctx, &tenant.TenantRequest{ID: "readable-tenant"})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/v1/tenants/%s", td.ID), nil)
	req.Header.Set("X-API-Key", apiKey)
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
	apiKey := NewTestKey(t, server, []string{"tenant:read"})

	ctx := context.Background()
	td, err := server.tenantManager.CreateTenant(ctx, &tenant.TenantRequest{
		ID:          "shape-tenant",
		Description: "test description",
	})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/tenants/shape-tenant", nil)
	req.Header.Set("X-API-Key", apiKey)
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
