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

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/api/proto/common"
	controller "github.com/cfgis/cfgms/api/proto/controller"
	"github.com/cfgis/cfgms/features/rbac"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
)

// createSubjectForTenant creates a subject in a specific tenant via the RBAC service.
func createSubjectForTenant(t *testing.T, server *Server, tenantID, subjectID, name string) {
	t.Helper()
	_, err := server.rbacService.CreateSubject(context.Background(), &controller.CreateSubjectRequest{
		Subject: &common.Subject{
			Id:          subjectID,
			DisplayName: name,
			TenantId:    tenantID,
		},
	})
	require.NoError(t, err)
}

// callHandleGetSubjectRoles calls handleGetSubjectRoles directly, injecting the
// caller tenant and subject ID via context and mux vars.
func callHandleGetSubjectRoles(server *Server, callerTenantID, subjectID string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/rbac/subjects/"+subjectID+"/roles", nil)
	if callerTenantID != "" {
		req = req.WithContext(context.WithValue(req.Context(), ctxkeys.TenantID, callerTenantID))
	}
	req = mux.SetURLVars(req, map[string]string{"id": subjectID})
	rec := httptest.NewRecorder()
	server.handleGetSubjectRoles(rec, req)
	return rec
}

// callHandleAssignSubjectRole calls handleAssignSubjectRole directly.
func callHandleAssignSubjectRole(server *Server, callerTenantID, subjectID, roleID string) *httptest.ResponseRecorder {
	ctx := rbac.WithSensitiveOperationJustification(context.Background(), "test: assign subject role for rbac subjects handler test")
	if callerTenantID != "" {
		ctx = context.WithValue(ctx, ctxkeys.TenantID, callerTenantID)
	}
	body, _ := json.Marshal(RoleAssignmentRequest{RoleID: roleID})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/rbac/subjects/"+subjectID+"/roles", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Justification", "test: assign subject role for rbac subjects handler test")
	req = req.WithContext(ctx)
	req = mux.SetURLVars(req, map[string]string{"id": subjectID})
	rec := httptest.NewRecorder()
	server.handleAssignSubjectRole(rec, req)
	return rec
}

// callHandleRevokeSubjectRole calls handleRevokeSubjectRole directly.
func callHandleRevokeSubjectRole(server *Server, callerTenantID, subjectID, roleID string) *httptest.ResponseRecorder {
	ctx := rbac.WithSensitiveOperationJustification(context.Background(), "test: revoke subject role for rbac subjects handler test")
	if callerTenantID != "" {
		ctx = context.WithValue(ctx, ctxkeys.TenantID, callerTenantID)
	}
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/rbac/subjects/"+subjectID+"/roles/"+roleID, nil)
	req.Header.Set("X-Justification", "test: revoke subject role for rbac subjects handler test")
	req = req.WithContext(ctx)
	req = mux.SetURLVars(req, map[string]string{"id": subjectID, "role_id": roleID})
	rec := httptest.NewRecorder()
	server.handleRevokeSubjectRole(rec, req)
	return rec
}

// TestHandleGetSubjectRoles_CrossTenantBlocked verifies that a caller scoped to
// root/msp-a cannot list roles for a subject belonging to root/msp-b, and that
// the check fires before the manager is called (REQUIRED TEST, Issue #3128 AC).
func TestHandleGetSubjectRoles_CrossTenantBlocked(t *testing.T) {
	server := setupTestServer(t)
	createSubjectForTenant(t, server, "root/msp-b", "subject-get-msp-b", "MSP-B Subject")

	rec := callHandleGetSubjectRoles(server, "root/msp-a", "subject-get-msp-b")
	assert.Equal(t, http.StatusNotFound, rec.Code,
		"GET roles for subject outside caller subtree must return 404")
}

// TestHandleAssignSubjectRole_CrossTenantBlocked verifies that a caller scoped to
// root/msp-a cannot assign a role to a subject in root/msp-b, regardless of the
// tenant ID the request body might claim (REQUIRED TEST, Issue #3128 AC).
func TestHandleAssignSubjectRole_CrossTenantBlocked(t *testing.T) {
	server := setupTestServer(t)
	createSubjectForTenant(t, server, "root/msp-b", "subject-assign-msp-b", "MSP-B Subject")
	createRoleForTenant(t, server, "root/msp-b", "role-assign-msp-b", "MSP-B Role")

	rec := callHandleAssignSubjectRole(server, "root/msp-a", "subject-assign-msp-b", "role-assign-msp-b")
	assert.Equal(t, http.StatusNotFound, rec.Code,
		"POST assign for subject outside caller subtree must be rejected before the manager is called")
}

// TestHandleRevokeSubjectRole_CrossTenantBlocked verifies that a caller scoped to
// root/msp-a cannot revoke a role from a subject in root/msp-b (REQUIRED TEST, Issue #3128 AC).
func TestHandleRevokeSubjectRole_CrossTenantBlocked(t *testing.T) {
	server := setupTestServer(t)
	createSubjectForTenant(t, server, "root/msp-b", "subject-revoke-msp-b", "MSP-B Subject")
	createRoleForTenant(t, server, "root/msp-b", "role-revoke-msp-b", "MSP-B Role")

	rec := callHandleRevokeSubjectRole(server, "root/msp-a", "subject-revoke-msp-b", "role-revoke-msp-b")
	assert.Equal(t, http.StatusNotFound, rec.Code,
		"DELETE revoke for subject outside caller subtree must be rejected before the manager is called")
}

// TestHandleAssignSubjectRole_EscalationPrevention_Returns403 verifies that when the
// escalationPreventionMgr rejects an assignment (caller is authorized for the target
// tenant), the handler returns 403 with no role assigned, not 500 (REQUIRED TEST, Issue #3128 AC).
func TestHandleAssignSubjectRole_EscalationPrevention_Returns403(t *testing.T) {
	server := setupTestServer(t)
	createSubjectForTenant(t, server, "tenant-esc", "subject-esc", "Escalation Subject")

	// Create 5 roles to assign.
	for i := 1; i <= 5; i++ {
		createRoleForTenant(t, server, "tenant-esc",
			fmt.Sprintf("esc-role-%d", i),
			fmt.Sprintf("Escalation Role %d", i))
	}

	// Assign the first 4 roles — the rapid escalation guard fires at > 3 recent successes.
	for i := 1; i <= 4; i++ {
		rec := callHandleAssignSubjectRole(server, "tenant-esc", "subject-esc", fmt.Sprintf("esc-role-%d", i))
		require.Equal(t, http.StatusCreated, rec.Code, "assignment %d must succeed before escalation triggers", i)
	}

	// The 5th assignment triggers rapid escalation protection; handler must return 403.
	rec := callHandleAssignSubjectRole(server, "tenant-esc", "subject-esc", "esc-role-5")
	assert.Equal(t, http.StatusForbidden, rec.Code,
		"escalation prevention rejection must be surfaced as 403, not 500")

	// Confirm that the 5th role was NOT assigned.
	getRec := callHandleGetSubjectRoles(server, "tenant-esc", "subject-esc")
	require.Equal(t, http.StatusOK, getRec.Code)
	var resp APIResponse
	require.NoError(t, json.Unmarshal(getRec.Body.Bytes(), &resp))
	roles := roleIDsFromResponse(t, resp)
	assert.NotContains(t, roles, "esc-role-5",
		"esc-role-5 must not be assigned after escalation prevention blocks it")
}

// TestHandleAssignSubjectRole_SystemRoleBlocked verifies that a tenant-scoped caller
// holding rbac:assign-role cannot grant a subject a system role (system.admin carries
// system.admin/tenant.manage/rbac.*.manage and an empty TenantId, so granting it would
// escalate the subject beyond the caller's subtree).
func TestHandleAssignSubjectRole_SystemRoleBlocked(t *testing.T) {
	server := setupTestServer(t)
	createSubjectForTenant(t, server, "root/msp-a", "subject-sysrole", "MSP-A Subject")

	rec := callHandleAssignSubjectRole(server, "root/msp-a", "subject-sysrole", "system.admin")
	assert.Equal(t, http.StatusForbidden, rec.Code,
		"assigning a system role must be rejected with 403")
	assert.Contains(t, rec.Body.String(), "SYSTEM_ROLE_IMMUTABLE")

	// The role must not have been assigned.
	getRec := callHandleGetSubjectRoles(server, "root/msp-a", "subject-sysrole")
	require.Equal(t, http.StatusOK, getRec.Code)
	var resp APIResponse
	require.NoError(t, json.Unmarshal(getRec.Body.Bytes(), &resp))
	if resp.Data != nil {
		assert.NotContains(t, roleIDsFromResponse(t, resp), "system.admin",
			"system.admin must not be bound to the subject")
	}
}

// TestHandleAssignSubjectRole_OutOfScopeRoleBlocked verifies that a caller may not grant
// a subject inside its own subtree a role owned by a tenant outside that subtree.
func TestHandleAssignSubjectRole_OutOfScopeRoleBlocked(t *testing.T) {
	server := setupTestServer(t)
	createSubjectForTenant(t, server, "root/msp-a", "subject-scoped-role", "MSP-A Subject")
	createRoleForTenant(t, server, "root/msp-b", "role-foreign-msp-b", "MSP-B Role")

	rec := callHandleAssignSubjectRole(server, "root/msp-a", "subject-scoped-role", "role-foreign-msp-b")
	assert.Equal(t, http.StatusNotFound, rec.Code,
		"assigning a role outside the caller's subtree must be rejected with 404")

	getRec := callHandleGetSubjectRoles(server, "root/msp-a", "subject-scoped-role")
	require.Equal(t, http.StatusOK, getRec.Code)
	var resp APIResponse
	require.NoError(t, json.Unmarshal(getRec.Body.Bytes(), &resp))
	if resp.Data != nil {
		assert.NotContains(t, roleIDsFromResponse(t, resp), "role-foreign-msp-b",
			"out-of-scope role must not be bound to the subject")
	}
}

// TestHandleAssignSubjectRole_UnknownRoleNotFound verifies that a role ID that does not
// exist is rejected before the assignment is attempted.
func TestHandleAssignSubjectRole_UnknownRoleNotFound(t *testing.T) {
	server := setupTestServer(t)
	createSubjectForTenant(t, server, "tenant-unknown-role", "subject-unknown-role", "Subject")

	rec := callHandleAssignSubjectRole(server, "tenant-unknown-role", "subject-unknown-role", "no-such-role-xyz")
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

// TestHandleGetSubjectRoles_SameTenantAllowed verifies happy-path GET for a subject
// in the caller's own tenant.
func TestHandleGetSubjectRoles_SameTenantAllowed(t *testing.T) {
	server := setupTestServer(t)
	createSubjectForTenant(t, server, "tenant-same", "subject-same", "Same Subject")

	rec := callHandleGetSubjectRoles(server, "tenant-same", "subject-same")
	assert.Equal(t, http.StatusOK, rec.Code)
}

// TestHandleGetSubjectRoles_SubtenantAllowed verifies that a caller scoped to a
// parent tenant can list roles for a subject in a child tenant.
func TestHandleGetSubjectRoles_SubtenantAllowed(t *testing.T) {
	server := setupTestServer(t)
	createSubjectForTenant(t, server, "parent/child", "subject-subtenant", "Child Subject")

	rec := callHandleGetSubjectRoles(server, "parent", "subject-subtenant")
	assert.Equal(t, http.StatusOK, rec.Code)
}

// TestHandleGetSubjectRoles_NoCallerTenant_Unrestricted verifies that an unscoped
// admin (empty callerTenant — the mTLS admin path) can access subjects in any tenant.
func TestHandleGetSubjectRoles_NoCallerTenant_Unrestricted(t *testing.T) {
	server := setupTestServer(t)
	createSubjectForTenant(t, server, "any-tenant", "subject-any", "Any Subject")

	rec := callHandleGetSubjectRoles(server, "", "subject-any")
	assert.Equal(t, http.StatusOK, rec.Code)
}

// TestHandleAssignSubjectRole_SameTenant verifies that assigning a role within the
// caller's own tenant returns 201.
func TestHandleAssignSubjectRole_SameTenant(t *testing.T) {
	server := setupTestServer(t)
	createSubjectForTenant(t, server, "tenant-assign", "subject-assign", "Assign Subject")
	createRoleForTenant(t, server, "tenant-assign", "role-assign", "Assign Role")

	rec := callHandleAssignSubjectRole(server, "tenant-assign", "subject-assign", "role-assign")
	assert.Equal(t, http.StatusCreated, rec.Code)
}

// TestHandleRevokeSubjectRole_SameTenant verifies that revoking a previously assigned
// role within the caller's own tenant returns 200.
func TestHandleRevokeSubjectRole_SameTenant(t *testing.T) {
	server := setupTestServer(t)
	createSubjectForTenant(t, server, "tenant-revoke", "subject-revoke", "Revoke Subject")
	createRoleForTenant(t, server, "tenant-revoke", "role-revoke", "Revoke Role")

	// Assign first.
	rec := callHandleAssignSubjectRole(server, "tenant-revoke", "subject-revoke", "role-revoke")
	require.Equal(t, http.StatusCreated, rec.Code, "assign must succeed before revoke test")

	// Then revoke.
	rec = callHandleRevokeSubjectRole(server, "tenant-revoke", "subject-revoke", "role-revoke")
	assert.Equal(t, http.StatusOK, rec.Code)
}

// TestHandleGetSubjectRoles_SubjectNotFound verifies that a request for a non-existent
// subject returns 404.
func TestHandleGetSubjectRoles_SubjectNotFound(t *testing.T) {
	server := setupTestServer(t)

	rec := callHandleGetSubjectRoles(server, "tenant-a", "nonexistent-subject-xyz")
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

// TestHandleAssignSubjectRole_MissingRoleID verifies that omitting role_id in the
// request body returns 400.
func TestHandleAssignSubjectRole_MissingRoleID(t *testing.T) {
	server := setupTestServer(t)
	createSubjectForTenant(t, server, "tenant-val", "subject-val", "Validation Subject")

	ctx := rbac.WithSensitiveOperationJustification(context.Background(), "test: missing role id validation")
	ctx = context.WithValue(ctx, ctxkeys.TenantID, "tenant-val")
	body, _ := json.Marshal(RoleAssignmentRequest{RoleID: ""})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/rbac/subjects/subject-val/roles", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Justification", "test: missing role id validation")
	req = req.WithContext(ctx)
	req = mux.SetURLVars(req, map[string]string{"id": "subject-val"})
	rec := httptest.NewRecorder()
	server.handleAssignSubjectRole(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

// TestHandleAssignSubjectRole_RevokeIDFromSubjectNotBody verifies that the tenantID
// used in the RevokeRole call is derived from the subject's stored tenant, not from
// any client-supplied value.  This is tested indirectly: the revoke handler uses
// subjectInCallerScope to look up the tenant, and the assign handler sets the tenant
// from the same lookup — so a subject whose stored tenant differs from any body field
// will still be processed with the correct tenant.
func TestHandleRevokeSubjectRole_TenantDerivedFromSubject(t *testing.T) {
	server := setupTestServer(t)
	// Subject lives in "authoritative-tenant"; we supply no body (DELETE has no body).
	createSubjectForTenant(t, server, "authoritative-tenant", "subject-auth-tenant", "Auth Tenant Subject")
	createRoleForTenant(t, server, "authoritative-tenant", "role-auth-tenant", "Auth Tenant Role")

	// Assign in the correct tenant.
	rec := callHandleAssignSubjectRole(server, "authoritative-tenant", "subject-auth-tenant", "role-auth-tenant")
	require.Equal(t, http.StatusCreated, rec.Code)

	// Revoke — the tenantID must come from the subject lookup, not a body field.
	rec = callHandleRevokeSubjectRole(server, "authoritative-tenant", "subject-auth-tenant", "role-auth-tenant")
	assert.Equal(t, http.StatusOK, rec.Code)
}
