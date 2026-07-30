// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
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

// callHandleGetRole calls handleGetRole directly, bypassing the router/middleware,
// injecting the caller tenant and role ID via context and mux vars respectively.
func callHandleGetRole(server *Server, callerTenantID, roleID string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/rbac/roles/"+roleID, nil)
	if callerTenantID != "" {
		req = req.WithContext(context.WithValue(req.Context(), ctxkeys.TenantID, callerTenantID))
	}
	req = mux.SetURLVars(req, map[string]string{"id": roleID})
	rec := httptest.NewRecorder()
	server.handleGetRole(rec, req)
	return rec
}

// callHandleUpdateRole calls handleUpdateRole directly, bypassing the router/middleware.
func callHandleUpdateRole(server *Server, callerTenantID, roleID string, body []byte) *httptest.ResponseRecorder {
	ctx := rbac.WithSensitiveOperationJustification(context.Background(), "test: update role")
	if callerTenantID != "" {
		ctx = context.WithValue(ctx, ctxkeys.TenantID, callerTenantID)
	}
	req := httptest.NewRequest(http.MethodPut, "/api/v1/rbac/roles/"+roleID, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(ctx)
	req = mux.SetURLVars(req, map[string]string{"id": roleID})
	rec := httptest.NewRecorder()
	server.handleUpdateRole(rec, req)
	return rec
}

// callHandleDeleteRole calls handleDeleteRole directly, bypassing the router/middleware.
func callHandleDeleteRole(server *Server, callerTenantID, roleID string) *httptest.ResponseRecorder {
	ctx := rbac.WithSensitiveOperationJustification(context.Background(), "test: delete role")
	if callerTenantID != "" {
		ctx = context.WithValue(ctx, ctxkeys.TenantID, callerTenantID)
	}
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/rbac/roles/"+roleID, nil)
	req = req.WithContext(ctx)
	req = mux.SetURLVars(req, map[string]string{"id": roleID})
	rec := httptest.NewRecorder()
	server.handleDeleteRole(rec, req)
	return rec
}

// callHandleCreateRole calls handleCreateRole directly, bypassing the router/middleware.
func callHandleCreateRole(server *Server, callerTenantID string, body []byte) *httptest.ResponseRecorder {
	ctx := rbac.WithSensitiveOperationJustification(context.Background(), "test: create role")
	if callerTenantID != "" {
		ctx = context.WithValue(ctx, ctxkeys.TenantID, callerTenantID)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/rbac/roles", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()
	server.handleCreateRole(rec, req)
	return rec
}

// TestHandleGetRole_CrossTenantBlocked verifies that a caller scoped to client-1 gets 404
// when attempting to GET a role belonging to client-2 (Issue #3140).
func TestHandleGetRole_CrossTenantBlocked(t *testing.T) {
	server := setupTestServer(t)
	createRoleForTenant(t, server, "client-2", "client-2.role-a", "Client Two Role")

	rec := callHandleGetRole(server, "client-1", "client-2.role-a")

	assert.Equal(t, http.StatusNotFound, rec.Code,
		"cross-tenant GET must return 404 to avoid disclosing role existence")
}

// TestHandleGetRole_SameTenantAllowed verifies that a caller scoped to client-1 can
// GET a role in their own tenant.
func TestHandleGetRole_SameTenantAllowed(t *testing.T) {
	server := setupTestServer(t)
	createRoleForTenant(t, server, "client-1", "client-1.role-a", "Client One Role")

	rec := callHandleGetRole(server, "client-1", "client-1.role-a")

	assert.Equal(t, http.StatusOK, rec.Code)
}

// TestHandleGetRole_SubtenantAllowed verifies that a caller scoped to client-1 can
// GET a role belonging to a child tenant (client-1/sub) within their subtree.
func TestHandleGetRole_SubtenantAllowed(t *testing.T) {
	server := setupTestServer(t)
	createRoleForTenant(t, server, "client-1/sub", "client-1.sub.role", "Sub Role")

	rec := callHandleGetRole(server, "client-1", "client-1.sub.role")

	assert.Equal(t, http.StatusOK, rec.Code)
}

// TestHandleGetRole_NoCallerTenant_Unrestricted verifies that a request with no
// caller tenant (admin mTLS path — empty TenantID) is not restricted by scope.
func TestHandleGetRole_NoCallerTenant_Unrestricted(t *testing.T) {
	server := setupTestServer(t)
	createRoleForTenant(t, server, "some-tenant", "some-tenant.role", "Some Role")

	rec := callHandleGetRole(server, "", "some-tenant.role")

	assert.Equal(t, http.StatusOK, rec.Code)
}

// TestHandleUpdateRole_CrossTenantBlocked verifies that a caller scoped to client-1
// gets 404 when attempting to UPDATE a role belonging to client-2, and the role is
// left unmodified (Issue #3140).
func TestHandleUpdateRole_CrossTenantBlocked(t *testing.T) {
	server := setupTestServer(t)
	createRoleForTenant(t, server, "client-2", "client-2.role-b", "Original Name")

	body, err := json.Marshal(RoleInfo{Name: "Modified Name", TenantID: "client-2"})
	require.NoError(t, err)
	rec := callHandleUpdateRole(server, "client-1", "client-2.role-b", body)

	assert.Equal(t, http.StatusNotFound, rec.Code,
		"cross-tenant UPDATE must return 404 to avoid disclosing role existence")

	// The role must be left unmodified.
	getResp, err := server.rbacService.GetRole(context.Background(), &controller.GetRoleRequest{
		RoleId: "client-2.role-b",
	})
	require.NoError(t, err)
	assert.Equal(t, "Original Name", getResp.Role.Name, "role must not be modified on cross-tenant 404")
}

// TestHandleUpdateRole_CrossTenantBodyLie verifies that supplying the caller's own tenant
// in the update body does not bypass the scope check — the check uses the role's stored
// tenant, not the client-supplied TenantId (Issue #3140).
func TestHandleUpdateRole_CrossTenantBodyLie(t *testing.T) {
	server := setupTestServer(t)
	createRoleForTenant(t, server, "client-2", "client-2.role-c", "Original Name")

	// Claim the role belongs to client-1 to try to bypass scope check.
	body, err := json.Marshal(RoleInfo{Name: "Bypassed", TenantID: "client-1"})
	require.NoError(t, err)
	rec := callHandleUpdateRole(server, "client-1", "client-2.role-c", body)

	assert.Equal(t, http.StatusNotFound, rec.Code,
		"scope check must use the stored tenant, not the body's TenantId")

	getResp, err := server.rbacService.GetRole(context.Background(), &controller.GetRoleRequest{
		RoleId: "client-2.role-c",
	})
	require.NoError(t, err)
	assert.Equal(t, "Original Name", getResp.Role.Name, "role must not be modified on body-lie 404")
}

// TestHandleUpdateRole_SameTenantAllowed verifies that a caller can update a role in
// their own tenant.
func TestHandleUpdateRole_SameTenantAllowed(t *testing.T) {
	server := setupTestServer(t)
	createRoleForTenant(t, server, "client-1", "client-1.role-update", "Before Update")

	body, err := json.Marshal(RoleInfo{Name: "After Update", TenantID: "client-1"})
	require.NoError(t, err)
	rec := callHandleUpdateRole(server, "client-1", "client-1.role-update", body)

	assert.Equal(t, http.StatusOK, rec.Code)
}

// TestHandleDeleteRole_CrossTenantBlocked verifies that a caller scoped to client-1
// gets 404 when attempting to DELETE a role belonging to client-2, and the role is
// left intact (Issue #3140).
func TestHandleDeleteRole_CrossTenantBlocked(t *testing.T) {
	server := setupTestServer(t)
	createRoleForTenant(t, server, "client-2", "client-2.role-del", "Delete Target")

	rec := callHandleDeleteRole(server, "client-1", "client-2.role-del")

	assert.Equal(t, http.StatusNotFound, rec.Code,
		"cross-tenant DELETE must return 404 to avoid disclosing role existence")

	// The role must still exist.
	getResp, err := server.rbacService.GetRole(context.Background(), &controller.GetRoleRequest{
		RoleId: "client-2.role-del",
	})
	require.NoError(t, err)
	assert.NotNil(t, getResp.Role, "role must remain intact after cross-tenant delete attempt")
}

// TestHandleDeleteRole_SameTenantAllowed verifies that a caller can delete a role in
// their own tenant.
func TestHandleDeleteRole_SameTenantAllowed(t *testing.T) {
	server := setupTestServer(t)
	createRoleForTenant(t, server, "client-1", "client-1.role-del", "To Delete")

	rec := callHandleDeleteRole(server, "client-1", "client-1.role-del")

	assert.Equal(t, http.StatusOK, rec.Code)
}

// TestHandleCreateRole_CrossTenantBlocked verifies that a caller scoped to client-1
// gets 400 when the request body specifies tenant_id "client-2", and no role is
// created (Issue #3140). 400 (not 404) because there is no existing resource to avoid
// disclosing.
func TestHandleCreateRole_CrossTenantBlocked(t *testing.T) {
	server := setupTestServer(t)

	body, err := json.Marshal(RoleInfo{ID: "injected.role", Name: "Injected Role", TenantID: "client-2"})
	require.NoError(t, err)
	rec := callHandleCreateRole(server, "client-1", body)

	assert.Equal(t, http.StatusBadRequest, rec.Code,
		"cross-tenant POST must return 400")

	// The specific role ID must not have been created (scope check fires before CreateRole).
	_, err = server.rbacService.GetRole(context.Background(),
		&controller.GetRoleRequest{RoleId: "injected.role"})
	assert.Error(t, err, "role must not exist after cross-tenant create was rejected")
}

// TestHandleCreateRole_SameTenantAllowed verifies that a caller can create a role in
// their own tenant.
func TestHandleCreateRole_SameTenantAllowed(t *testing.T) {
	server := setupTestServer(t)

	body, err := json.Marshal(RoleInfo{ID: "client-1.new-role", Name: "My Role", TenantID: "client-1"})
	require.NoError(t, err)
	rec := callHandleCreateRole(server, "client-1", body)

	assert.Equal(t, http.StatusCreated, rec.Code)
}

// TestHandleCreateRole_SubtenantAllowed verifies that a caller can create a role in
// a child tenant within their subtree.
func TestHandleCreateRole_SubtenantAllowed(t *testing.T) {
	server := setupTestServer(t)

	body, err := json.Marshal(RoleInfo{ID: "client-1.sub.role", Name: "Sub Role", TenantID: "client-1/sub"})
	require.NoError(t, err)
	rec := callHandleCreateRole(server, "client-1", body)

	assert.Equal(t, http.StatusCreated, rec.Code)
}

// TestHandleCreateRole_NoCallerTenant_Unrestricted verifies that a request with no
// caller tenant (admin mTLS path) is not restricted by scope.
func TestHandleCreateRole_NoCallerTenant_Unrestricted(t *testing.T) {
	server := setupTestServer(t)

	body, err := json.Marshal(RoleInfo{ID: "any-tenant.admin-role", Name: "Admin Role", TenantID: "any-tenant"})
	require.NoError(t, err)
	rec := callHandleCreateRole(server, "", body)

	assert.Equal(t, http.StatusCreated, rec.Code)
}

// roleFromResponse decodes the RoleInfo carried in the "data" field of an API response.
func roleFromResponse(t *testing.T, rec *httptest.ResponseRecorder) RoleInfo {
	t.Helper()
	var resp struct {
		Data RoleInfo `json:"data"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	return resp.Data
}

// errorCodeFromResponse decodes the machine-readable error code from an API error response.
func errorCodeFromResponse(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var resp ErrorResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	require.NotNil(t, resp.Error, "error response must carry an error object")
	return resp.Error.Code
}

// TestHandleCreateRole_IgnoresClientSuppliedID verifies that the role ID is assigned
// server-side. Role IDs are a global primary key with no tenant binding, so honouring a
// client-supplied ID would let a caller reserve IDs in another tenant's naming space
// (Issue #3140).
func TestHandleCreateRole_IgnoresClientSuppliedID(t *testing.T) {
	server := setupTestServer(t)

	body, err := json.Marshal(RoleInfo{ID: "client-2.squatted", Name: "My Role", TenantID: "client-1"})
	require.NoError(t, err)
	rec := callHandleCreateRole(server, "client-1", body)

	require.Equal(t, http.StatusCreated, rec.Code)

	created := roleFromResponse(t, rec)
	assert.NotEqual(t, "client-2.squatted", created.ID,
		"client-supplied id must be ignored; the server assigns the role ID")
	assert.NotEmpty(t, created.ID, "server must assign a non-empty role ID")
	assert.Equal(t, "client-1", created.TenantID)

	// The client-supplied ID must not have been consumed in the global ID namespace.
	_, err = server.rbacService.GetRole(context.Background(),
		&controller.GetRoleRequest{RoleId: "client-2.squatted"})
	assert.Error(t, err, "client-supplied id must not be stored")

	// The server-assigned ID resolves to the created role.
	stored, err := server.rbacService.GetRole(context.Background(),
		&controller.GetRoleRequest{RoleId: created.ID})
	require.NoError(t, err)
	assert.Equal(t, "client-1", stored.Role.TenantId)
	assert.Equal(t, "My Role", stored.Role.Name)
}

// TestHandleCreateRole_NoCrossTenantExistenceOracle verifies that reusing an ID that
// already exists in another tenant neither fails nor perturbs the existing role. A
// duplicate-ID rejection would be an existence oracle that defeats the 404-instead-of-403
// concealment on the read/update/delete paths (Issue #3140).
func TestHandleCreateRole_NoCrossTenantExistenceOracle(t *testing.T) {
	server := setupTestServer(t)
	createRoleForTenant(t, server, "client-2", "client-2.reserved", "Client Two Role")

	body, err := json.Marshal(RoleInfo{ID: "client-2.reserved", Name: "Probe Role", TenantID: "client-1"})
	require.NoError(t, err)
	rec := callHandleCreateRole(server, "client-1", body)

	assert.Equal(t, http.StatusCreated, rec.Code,
		"colliding with another tenant's role ID must not produce a distinguishable failure")

	created := roleFromResponse(t, rec)
	assert.NotEqual(t, "client-2.reserved", created.ID)

	// client-2's role must be untouched.
	stored, err := server.rbacService.GetRole(context.Background(),
		&controller.GetRoleRequest{RoleId: "client-2.reserved"})
	require.NoError(t, err)
	assert.Equal(t, "Client Two Role", stored.Role.Name, "existing role must not be overwritten")
	assert.Equal(t, "client-2", stored.Role.TenantId, "existing role must keep its tenant")
}

// TestHandleUpdateRole_DestinationTenantRejected verifies that a caller who legitimately
// owns a role cannot relocate it into another tenant by supplying a different tenant_id
// in the update body (Issue #3140). The source-tenant check alone does not cover this.
func TestHandleUpdateRole_DestinationTenantRejected(t *testing.T) {
	server := setupTestServer(t)
	createRoleForTenant(t, server, "client-1", "client-1.role-move", "Original Name")

	body, err := json.Marshal(RoleInfo{
		Name:        "Relocated",
		TenantID:    "client-2",
		Permissions: []string{"rbac.manage"},
	})
	require.NoError(t, err)
	rec := callHandleUpdateRole(server, "client-1", "client-1.role-move", body)

	assert.Equal(t, http.StatusBadRequest, rec.Code,
		"relocating a role into another tenant must be rejected")
	assert.Equal(t, "TENANT_IMMUTABLE", errorCodeFromResponse(t, rec))

	stored, err := server.rbacService.GetRole(context.Background(),
		&controller.GetRoleRequest{RoleId: "client-1.role-move"})
	require.NoError(t, err)
	assert.Equal(t, "client-1", stored.Role.TenantId, "role must remain in its original tenant")
	assert.Equal(t, "Original Name", stored.Role.Name, "role must not be modified on rejection")
}

// TestHandleUpdateRole_AdminCannotRelocateTenant verifies that the destination-tenant
// check also applies on the admin mTLS path (no caller tenant), where the source scope
// check is intentionally skipped (Issue #3140).
func TestHandleUpdateRole_AdminCannotRelocateTenant(t *testing.T) {
	server := setupTestServer(t)
	createRoleForTenant(t, server, "client-1", "client-1.role-admin-move", "Original Name")

	body, err := json.Marshal(RoleInfo{Name: "Relocated", TenantID: "client-2"})
	require.NoError(t, err)
	rec := callHandleUpdateRole(server, "", "client-1.role-admin-move", body)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Equal(t, "TENANT_IMMUTABLE", errorCodeFromResponse(t, rec))

	stored, err := server.rbacService.GetRole(context.Background(),
		&controller.GetRoleRequest{RoleId: "client-1.role-admin-move"})
	require.NoError(t, err)
	assert.Equal(t, "client-1", stored.Role.TenantId)
}

// TestHandleUpdateRole_OmittedTenantPreservesStoredTenant verifies that an update body
// without a tenant_id does not blank the role's tenant, which would orphan it from every
// ListRoles result (Issue #3140).
func TestHandleUpdateRole_OmittedTenantPreservesStoredTenant(t *testing.T) {
	server := setupTestServer(t)
	createRoleForTenant(t, server, "client-1", "client-1.role-partial", "Before Update")

	body, err := json.Marshal(map[string]interface{}{"name": "After Update"})
	require.NoError(t, err)
	rec := callHandleUpdateRole(server, "client-1", "client-1.role-partial", body)

	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "client-1", roleFromResponse(t, rec).TenantID,
		"response must report the preserved tenant")

	stored, err := server.rbacService.GetRole(context.Background(),
		&controller.GetRoleRequest{RoleId: "client-1.role-partial"})
	require.NoError(t, err)
	assert.Equal(t, "client-1", stored.Role.TenantId, "omitted tenant_id must not blank the stored tenant")
	assert.Equal(t, "After Update", stored.Role.Name)

	// The role must still be listed for its tenant.
	listRec := callHandleListRoles(server, "client-1", "")
	require.Equal(t, http.StatusOK, listRec.Code)
	var listResp APIResponse
	require.NoError(t, json.Unmarshal(listRec.Body.Bytes(), &listResp))
	assert.Contains(t, roleIDsFromResponse(t, listResp), "client-1.role-partial")
}

// callHandleListPermissions calls handleListPermissions directly, bypassing the
// router/middleware, with an optional resource_type query filter.
func callHandleListPermissions(server *Server, resourceType string) *httptest.ResponseRecorder {
	url := "/api/v1/rbac/permissions"
	if resourceType != "" {
		url += "?resource_type=" + resourceType
	}
	req := httptest.NewRequest(http.MethodGet, url, nil)
	rec := httptest.NewRecorder()
	server.handleListPermissions(rec, req)
	return rec
}

// callHandleGetPermission calls handleGetPermission directly, bypassing the
// router/middleware. When setVar is false the {id} mux var is absent, which is how the
// handler observes a missing path variable.
func callHandleGetPermission(server *Server, permissionID string, setVar bool) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/rbac/permissions/"+permissionID, nil)
	if setVar {
		req = mux.SetURLVars(req, map[string]string{"id": permissionID})
	}
	rec := httptest.NewRecorder()
	server.handleGetPermission(rec, req)
	return rec
}

// permissionsFromResponse decodes the permission list carried in an API response.
func permissionsFromResponse(t *testing.T, rec *httptest.ResponseRecorder) []PermissionInfo {
	t.Helper()
	var resp struct {
		Data []PermissionInfo `json:"data"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	return resp.Data
}

// permissionFromResponse decodes a single permission carried in an API response.
func permissionFromResponse(t *testing.T, rec *httptest.ResponseRecorder) PermissionInfo {
	t.Helper()
	var resp struct {
		Data PermissionInfo `json:"data"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	return resp.Data
}

// TestHandleListPermissions_NilService_Returns503 verifies the guard for a controller
// started without an RBAC service.
func TestHandleListPermissions_NilService_Returns503(t *testing.T) {
	server := setupTestServer(t)
	server.rbacService = nil

	rec := callHandleListPermissions(server, "")

	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
	assert.Equal(t, "SERVICE_UNAVAILABLE", errorCodeFromResponse(t, rec))
}

// TestHandleListPermissions_ReturnsAllPermissions verifies the unfiltered list returns
// the default permission catalogue loaded at RBAC initialization.
func TestHandleListPermissions_ReturnsAllPermissions(t *testing.T) {
	server := setupTestServer(t)

	rec := callHandleListPermissions(server, "")

	require.Equal(t, http.StatusOK, rec.Code)
	perms := permissionsFromResponse(t, rec)
	require.NotEmpty(t, perms, "default permissions must be returned")

	byID := make(map[string]PermissionInfo, len(perms))
	for _, p := range perms {
		byID[p.ID] = p
	}
	require.Contains(t, byID, "steward.read")
	require.Contains(t, byID, "config.read", "unfiltered list must span resource types")
	assert.Equal(t, "steward", byID["steward.read"].ResourceType)
	assert.Equal(t, []string{"read"}, byID["steward.read"].Actions)
}

// TestHandleListPermissions_ResourceTypeFilter verifies the resource_type query parameter
// is applied to the listing.
func TestHandleListPermissions_ResourceTypeFilter(t *testing.T) {
	server := setupTestServer(t)

	all := permissionsFromResponse(t, callHandleListPermissions(server, ""))

	rec := callHandleListPermissions(server, "steward")
	require.Equal(t, http.StatusOK, rec.Code)
	filtered := permissionsFromResponse(t, rec)

	require.NotEmpty(t, filtered)
	assert.Less(t, len(filtered), len(all), "filter must narrow the result set")

	ids := make([]string, 0, len(filtered))
	for _, p := range filtered {
		assert.Equal(t, "steward", p.ResourceType,
			"permission %q must not appear under resource_type=steward", p.ID)
		ids = append(ids, p.ID)
	}
	assert.Contains(t, ids, "steward.read")
	assert.NotContains(t, ids, "config.read")
}

// TestHandleGetPermission_NilService_Returns503 verifies the guard for a controller
// started without an RBAC service.
func TestHandleGetPermission_NilService_Returns503(t *testing.T) {
	server := setupTestServer(t)
	server.rbacService = nil

	rec := callHandleGetPermission(server, "steward.read", true)

	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
	assert.Equal(t, "SERVICE_UNAVAILABLE", errorCodeFromResponse(t, rec))
}

// TestHandleGetPermission_MissingID_Returns400 verifies that an absent path variable is
// reported as a client error rather than being forwarded to the service.
func TestHandleGetPermission_MissingID_Returns400(t *testing.T) {
	server := setupTestServer(t)

	rec := callHandleGetPermission(server, "", false)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Equal(t, "MISSING_PERMISSION_ID", errorCodeFromResponse(t, rec))
}

// TestHandleGetPermission_UnknownID_Returns404 verifies the not-found path.
func TestHandleGetPermission_UnknownID_Returns404(t *testing.T) {
	server := setupTestServer(t)

	rec := callHandleGetPermission(server, "does.not.exist", true)

	assert.Equal(t, http.StatusNotFound, rec.Code)
	assert.Equal(t, "PERMISSION_NOT_FOUND", errorCodeFromResponse(t, rec))
	assert.NotContains(t, rec.Body.String(), "not found: permission",
		"internal error detail must not be disclosed to the client")
}

// TestHandleGetPermission_Success verifies a known default permission is returned with
// all fields mapped onto the API representation.
func TestHandleGetPermission_Success(t *testing.T) {
	server := setupTestServer(t)

	rec := callHandleGetPermission(server, "steward.read", true)

	require.Equal(t, http.StatusOK, rec.Code)
	perm := permissionFromResponse(t, rec)
	assert.Equal(t, "steward.read", perm.ID)
	assert.Equal(t, "Read Steward", perm.Name)
	assert.Equal(t, "steward", perm.ResourceType)
	assert.Equal(t, []string{"read"}, perm.Actions)
	assert.NotEmpty(t, perm.Description)
}

// Role-handler guard and failure-path coverage.
//
// The 500 cases below are driven by omitting the X-Justification header. That header
// is the only channel through which a REST client supplies a justification for a
// sensitive RBAC operation (M-AUTH-2), and the real rbac.Manager rejects unjustified
// create/update/delete role operations. The failure therefore originates in the real
// RBAC component stack — no wrapper, substitute, or synthetic error is involved.

// unjustifiedRoleRequest builds a role request that carries no X-Justification header
// and no justification in its context: the exact state of a REST client that omits the
// header. roleID, when non-empty, is installed as the {id} mux var.
func unjustifiedRoleRequest(method, target, callerTenantID, roleID string, body []byte) *http.Request {
	var req *http.Request
	if body == nil {
		req = httptest.NewRequest(method, target, nil)
	} else {
		req = httptest.NewRequest(method, target, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
	}
	if callerTenantID != "" {
		req = req.WithContext(context.WithValue(req.Context(), ctxkeys.TenantID, callerTenantID))
	}
	if roleID != "" {
		req = mux.SetURLVars(req, map[string]string{"id": roleID})
	}
	return req
}

// TestHandleRoles_NilService_Returns503 verifies the guard on every role handler for a
// controller started without an RBAC backend.
func TestHandleRoles_NilService_Returns503(t *testing.T) {
	body, err := json.Marshal(RoleInfo{Name: "Any Role", TenantID: "client-1"})
	require.NoError(t, err)

	cases := []struct {
		name string
		call func(*Server) *httptest.ResponseRecorder
	}{
		{"list", func(s *Server) *httptest.ResponseRecorder { return callHandleListRoles(s, "client-1", "") }},
		{"create", func(s *Server) *httptest.ResponseRecorder { return callHandleCreateRole(s, "client-1", body) }},
		{"get", func(s *Server) *httptest.ResponseRecorder { return callHandleGetRole(s, "client-1", "client-1.role") }},
		{"update", func(s *Server) *httptest.ResponseRecorder {
			return callHandleUpdateRole(s, "client-1", "client-1.role", body)
		}},
		{"delete", func(s *Server) *httptest.ResponseRecorder {
			return callHandleDeleteRole(s, "client-1", "client-1.role")
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server := setupTestServer(t)
			server.rbacService = nil

			rec := tc.call(server)

			assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
			assert.Equal(t, "SERVICE_UNAVAILABLE", errorCodeFromResponse(t, rec))
		})
	}
}

// TestHandleCreateRole_InvalidJSON_Returns400 verifies that a malformed body is rejected
// before the request reaches the RBAC service.
func TestHandleCreateRole_InvalidJSON_Returns400(t *testing.T) {
	server := setupTestServer(t)

	rec := callHandleCreateRole(server, "client-1", []byte(`{"name": "Broken"`))

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Equal(t, "INVALID_JSON", errorCodeFromResponse(t, rec))
}

// TestHandleCreateRole_MissingName_Returns400 verifies the required-field check on name.
func TestHandleCreateRole_MissingName_Returns400(t *testing.T) {
	server := setupTestServer(t)

	body, err := json.Marshal(RoleInfo{TenantID: "client-1"})
	require.NoError(t, err)
	rec := callHandleCreateRole(server, "client-1", body)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Equal(t, "MISSING_NAME", errorCodeFromResponse(t, rec))
}

// TestHandleGetRole_MissingID_Returns400 verifies that an absent {id} path variable is
// reported as a client error rather than being forwarded to the service.
func TestHandleGetRole_MissingID_Returns400(t *testing.T) {
	server := setupTestServer(t)

	rec := httptest.NewRecorder()
	server.handleGetRole(rec, unjustifiedRoleRequest(http.MethodGet, "/api/v1/rbac/roles/", "client-1", "", nil))

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Equal(t, "MISSING_ROLE_ID", errorCodeFromResponse(t, rec))
}

// TestHandleUpdateRole_MissingID_Returns400 verifies the same guard on the update path.
func TestHandleUpdateRole_MissingID_Returns400(t *testing.T) {
	server := setupTestServer(t)

	body, err := json.Marshal(RoleInfo{Name: "Any Role"})
	require.NoError(t, err)
	rec := httptest.NewRecorder()
	server.handleUpdateRole(rec, unjustifiedRoleRequest(http.MethodPut, "/api/v1/rbac/roles/", "client-1", "", body))

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Equal(t, "MISSING_ROLE_ID", errorCodeFromResponse(t, rec))
}

// TestHandleUpdateRole_InvalidJSON_Returns400 verifies that a malformed update body is
// rejected before the existing role is fetched or modified.
func TestHandleUpdateRole_InvalidJSON_Returns400(t *testing.T) {
	server := setupTestServer(t)
	createRoleForTenant(t, server, "client-1", "client-1.role-badjson", "Original Name")

	rec := callHandleUpdateRole(server, "client-1", "client-1.role-badjson", []byte(`{"name": `))

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Equal(t, "INVALID_JSON", errorCodeFromResponse(t, rec))

	stored, err := server.rbacService.GetRole(context.Background(),
		&controller.GetRoleRequest{RoleId: "client-1.role-badjson"})
	require.NoError(t, err)
	assert.Equal(t, "Original Name", stored.Role.Name, "role must not be modified on a malformed body")
}

// TestHandleCreateRole_ServiceFailure_Returns500 verifies that a create rejected by the
// RBAC manager is reported as 500 without leaking the underlying error text, and that no
// role is left behind.
func TestHandleCreateRole_ServiceFailure_Returns500(t *testing.T) {
	server := setupTestServer(t)

	body, err := json.Marshal(RoleInfo{Name: "Unjustified Role", TenantID: "client-1"})
	require.NoError(t, err)
	rec := httptest.NewRecorder()
	server.handleCreateRole(rec, unjustifiedRoleRequest(http.MethodPost, "/api/v1/rbac/roles", "client-1", "", body))

	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.Equal(t, "INTERNAL_ERROR", errorCodeFromResponse(t, rec))
	assert.NotContains(t, rec.Body.String(), "justification",
		"internal error detail must not be disclosed to the client")

	listed, err := server.rbacService.ListRoles(context.Background(),
		&controller.ListRolesRequest{TenantId: "client-1"})
	require.NoError(t, err)
	for _, role := range listed.Roles {
		assert.NotEqual(t, "Unjustified Role", role.Name, "rejected create must not persist a role")
	}
}

// TestHandleUpdateRole_ServiceFailure_Returns500 verifies that an update rejected by the
// RBAC manager is reported as 500 and leaves the stored role untouched.
func TestHandleUpdateRole_ServiceFailure_Returns500(t *testing.T) {
	server := setupTestServer(t)
	createRoleForTenant(t, server, "client-1", "client-1.role-unjustified", "Original Name")

	body, err := json.Marshal(RoleInfo{Name: "Renamed", TenantID: "client-1"})
	require.NoError(t, err)
	rec := httptest.NewRecorder()
	server.handleUpdateRole(rec, unjustifiedRoleRequest(http.MethodPut,
		"/api/v1/rbac/roles/client-1.role-unjustified", "client-1", "client-1.role-unjustified", body))

	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.Equal(t, "INTERNAL_ERROR", errorCodeFromResponse(t, rec))
	assert.NotContains(t, rec.Body.String(), "justification",
		"internal error detail must not be disclosed to the client")

	stored, err := server.rbacService.GetRole(context.Background(),
		&controller.GetRoleRequest{RoleId: "client-1.role-unjustified"})
	require.NoError(t, err)
	assert.Equal(t, "Original Name", stored.Role.Name, "role must not be modified when the update is rejected")
}

// TestHandleDeleteRole_ServiceFailure_Returns500 verifies that a delete rejected by the
// RBAC manager is reported as 500 and leaves the role in place.
func TestHandleDeleteRole_ServiceFailure_Returns500(t *testing.T) {
	server := setupTestServer(t)
	createRoleForTenant(t, server, "client-1", "client-1.role-nodelete", "Keep Me")

	rec := httptest.NewRecorder()
	server.handleDeleteRole(rec, unjustifiedRoleRequest(http.MethodDelete,
		"/api/v1/rbac/roles/client-1.role-nodelete", "client-1", "client-1.role-nodelete", nil))

	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.Equal(t, "INTERNAL_ERROR", errorCodeFromResponse(t, rec))
	assert.NotContains(t, rec.Body.String(), "justification",
		"internal error detail must not be disclosed to the client")

	stored, err := server.rbacService.GetRole(context.Background(),
		&controller.GetRoleRequest{RoleId: "client-1.role-nodelete"})
	require.NoError(t, err)
	assert.Equal(t, "Keep Me", stored.Role.Name, "role must survive a rejected delete")
}

// TestHandleDeleteRole_JustificationHeaderAccepted verifies the X-Justification header
// path that the handler uses to satisfy the M-AUTH-2 requirement, complementing the
// rejection case above.
func TestHandleDeleteRole_JustificationHeaderAccepted(t *testing.T) {
	server := setupTestServer(t)
	createRoleForTenant(t, server, "client-1", "client-1.role-hdr", "Delete Me")

	req := unjustifiedRoleRequest(http.MethodDelete,
		"/api/v1/rbac/roles/client-1.role-hdr", "client-1", "client-1.role-hdr", nil)
	req.Header.Set("X-Justification", "test: delete role via header justification")
	rec := httptest.NewRecorder()
	server.handleDeleteRole(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)

	_, err := server.rbacService.GetRole(context.Background(),
		&controller.GetRoleRequest{RoleId: "client-1.role-hdr"})
	assert.Error(t, err, "role must be gone after a justified delete")
}
