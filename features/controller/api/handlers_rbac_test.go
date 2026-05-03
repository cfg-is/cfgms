// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/api/proto/common"
	controller "github.com/cfgis/cfgms/api/proto/controller"
	"github.com/cfgis/cfgms/features/rbac"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
)

// createRoleForTenant creates a role for a specific tenant via the RBAC service.
func createRoleForTenant(t *testing.T, server *Server, tenantID, roleID, roleName string) {
	t.Helper()
	// M-AUTH-2: CreateRole requires justification in context
	ctx := rbac.WithSensitiveOperationJustification(context.Background(), "test: role setup for RBAC handler test")
	_, err := server.rbacService.CreateRole(ctx, &controller.CreateRoleRequest{
		Role: &common.Role{
			Id:          roleID,
			Name:        roleName,
			Description: "test role for " + tenantID,
			TenantId:    tenantID,
		},
	})
	require.NoError(t, err)
}

// callHandleListRoles calls handleListRoles directly with the given context tenant,
// bypassing the router/middleware so we can inject context values explicitly.
func callHandleListRoles(server *Server, contextTenantID, queryTenantID string) *httptest.ResponseRecorder {
	url := "/api/v1/rbac/roles"
	if queryTenantID != "" {
		url += "?tenant_id=" + queryTenantID
	}
	req := httptest.NewRequest(http.MethodGet, url, nil)
	if contextTenantID != "" {
		req = req.WithContext(context.WithValue(req.Context(), ctxkeys.TenantID, contextTenantID))
	}
	rec := httptest.NewRecorder()
	server.handleListRoles(rec, req)
	return rec
}

// roleIDsFromResponse extracts the "id" field from each role in the API response data.
func roleIDsFromResponse(t *testing.T, resp APIResponse) []string {
	t.Helper()
	roles, ok := resp.Data.([]interface{})
	require.True(t, ok, "expected array in Data")
	ids := make([]string, 0, len(roles))
	for _, r := range roles {
		roleMap, ok := r.(map[string]interface{})
		require.True(t, ok)
		if id, ok := roleMap["id"].(string); ok {
			ids = append(ids, id)
		}
	}
	return ids
}

// TestHandleListRoles_IgnoresQueryParamTenantID verifies that a tenant_id query param
// cannot be used to access another tenant's roles (tenant scoping must come from context).
func TestHandleListRoles_IgnoresQueryParamTenantID(t *testing.T) {
	server := setupTestServer(t)

	// Create roles for two different tenants.
	createRoleForTenant(t, server, "tenant-a", "tenant-a.role1", "Tenant A Role")
	createRoleForTenant(t, server, "tenant-b", "tenant-b.role1", "Tenant B Role")

	// Authenticated as tenant-a, but supplying ?tenant_id=tenant-b in the query string.
	// The handler must ignore the query param and use the context tenant.
	rec := callHandleListRoles(server, "tenant-a", "tenant-b")

	require.Equal(t, http.StatusOK, rec.Code)
	var resp APIResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))

	ids := roleIDsFromResponse(t, resp)

	// tenant-a's role must be present.
	assert.Contains(t, ids, "tenant-a.role1",
		"tenant-a role must appear when authenticated as tenant-a")

	// tenant-b's role must not appear even though ?tenant_id=tenant-b was supplied.
	assert.NotContains(t, ids, "tenant-b.role1",
		"tenant-b role must not be visible to tenant-a; query param must be ignored")
}

// TestHandleListRoles_ReturnsOnlyOwnTenantRoles verifies that a tenant only sees its own roles.
func TestHandleListRoles_ReturnsOnlyOwnTenantRoles(t *testing.T) {
	server := setupTestServer(t)

	createRoleForTenant(t, server, "tenant-a", "tenant-a.admin", "Tenant A Admin")
	createRoleForTenant(t, server, "tenant-b", "tenant-b.admin", "Tenant B Admin")

	rec := callHandleListRoles(server, "tenant-a", "")
	require.Equal(t, http.StatusOK, rec.Code)

	var resp APIResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))

	ids := roleIDsFromResponse(t, resp)
	assert.Contains(t, ids, "tenant-a.admin", "tenant-a's own role must be present")
	assert.NotContains(t, ids, "tenant-b.admin", "tenant-b role must not appear in tenant-a response")
}

// TestHandleListRoles_NoContextTenant_Returns401 verifies that a missing context tenant
// (unauthenticated path) results in HTTP 401 rather than forwarding an empty tenant ID.
func TestHandleListRoles_NoContextTenant_Returns401(t *testing.T) {
	server := setupTestServer(t)

	// No tenant in context simulates an unauthenticated/misconfigured request.
	rec := callHandleListRoles(server, "", "")
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

// TestServer_RBACSubjectRoutesDeregistered confirms that all 10 RBAC subject, assignment,
// and permission-check routes are removed from the router. An unregistered route in
// gorilla/mux returns 404 before any auth middleware fires; a registered-but-unimplemented
// route would instead return 401 (auth) or 501 (stub handler).
func TestServer_RBACSubjectRoutesDeregistered(t *testing.T) {
	server := setupTestServer(t)

	routes := []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/api/v1/rbac/subjects"},
		{http.MethodPost, "/api/v1/rbac/subjects"},
		{http.MethodGet, "/api/v1/rbac/subjects/test-id"},
		{http.MethodPut, "/api/v1/rbac/subjects/test-id"},
		{http.MethodDelete, "/api/v1/rbac/subjects/test-id"},
		{http.MethodGet, "/api/v1/rbac/subjects/test-id/roles"},
		{http.MethodPost, "/api/v1/rbac/subjects/test-id/roles"},
		{http.MethodDelete, "/api/v1/rbac/subjects/test-id/roles/role-id"},
		{http.MethodGet, "/api/v1/rbac/subjects/test-id/permissions"},
		{http.MethodPost, "/api/v1/rbac/check"},
	}

	for _, tt := range routes {
		t.Run(tt.method+" "+tt.path, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, nil)
			rec := httptest.NewRecorder()
			server.router.ServeHTTP(rec, req)
			assert.Equal(t, http.StatusNotFound, rec.Code,
				"route %s %s must be deregistered (404 expected, route was still registered)",
				tt.method, tt.path)
			assert.NotEqual(t, http.StatusNotImplemented, rec.Code,
				"route %s %s must not return 501 (stub handlers must be deleted)",
				tt.method, tt.path)
		})
	}
}
