// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"

	"github.com/cfgis/cfgms/api/proto/common"
	controller "github.com/cfgis/cfgms/api/proto/controller"
	"github.com/cfgis/cfgms/features/rbac"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
	"github.com/cfgis/cfgms/pkg/logging"
)

// handleListPermissions handles GET /api/v1/rbac/permissions
func (s *Server) handleListPermissions(w http.ResponseWriter, r *http.Request) {
	if s.rbacService == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable, "RBAC service not available", "SERVICE_UNAVAILABLE")
		return
	}

	// Get resource_type filter from query params
	resourceType := r.URL.Query().Get("resource_type")

	// Create gRPC request
	req := &controller.ListPermissionsRequest{
		ResourceType: resourceType,
	}

	// Call gRPC service
	resp, err := s.rbacService.ListPermissions(r.Context(), req)
	if err != nil {
		s.logger.Error("Failed to list permissions", "error", err)
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to list permissions", "INTERNAL_ERROR")
		return
	}

	// Convert to API response
	var permissions []PermissionInfo
	for _, perm := range resp.Permissions {
		permissions = append(permissions, PermissionInfo{
			ID:           perm.Id,
			Name:         perm.Name,
			Description:  perm.Description,
			ResourceType: perm.ResourceType,
			Actions:      perm.Actions,
		})
	}

	s.writeSuccessResponse(w, permissions)
}

// handleGetPermission handles GET /api/v1/rbac/permissions/{id}
func (s *Server) handleGetPermission(w http.ResponseWriter, r *http.Request) {
	if s.rbacService == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable, "RBAC service not available", "SERVICE_UNAVAILABLE")
		return
	}

	vars := mux.Vars(r)
	permissionID := vars["id"]

	if permissionID == "" {
		s.writeErrorResponse(w, http.StatusBadRequest, "Permission ID is required", "MISSING_PERMISSION_ID")
		return
	}

	// Create gRPC request
	req := &controller.GetPermissionRequest{
		PermissionId: permissionID,
	}

	// Call gRPC service
	resp, err := s.rbacService.GetPermission(r.Context(), req)
	if err != nil {
		s.logger.Error("Failed to get permission", "permission_id", logging.SanitizeLogValue(permissionID), "error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusNotFound, "Permission not found", "PERMISSION_NOT_FOUND")
		return
	}

	// Convert to API response
	permission := PermissionInfo{
		ID:           resp.Permission.Id,
		Name:         resp.Permission.Name,
		Description:  resp.Permission.Description,
		ResourceType: resp.Permission.ResourceType,
		Actions:      resp.Permission.Actions,
	}

	s.writeSuccessResponse(w, permission)
}

// handleListRoles handles GET /api/v1/rbac/roles
func (s *Server) handleListRoles(w http.ResponseWriter, r *http.Request) {
	if s.rbacService == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable, "RBAC service not available", "SERVICE_UNAVAILABLE")
		return
	}

	tenantID, _ := r.Context().Value(ctxkeys.TenantID).(string)
	if tenantID == "" {
		s.writeErrorResponse(w, http.StatusUnauthorized, "Authentication required", "AUTHENTICATION_REQUIRED")
		return
	}

	// Create gRPC request
	req := &controller.ListRolesRequest{
		TenantId: tenantID,
	}

	// Call gRPC service
	resp, err := s.rbacService.ListRoles(r.Context(), req)
	if err != nil {
		s.logger.Error("Failed to list roles", "error", err)
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to list roles", "INTERNAL_ERROR")
		return
	}

	// Convert to API response
	var roles []RoleInfo
	for _, role := range resp.Roles {
		roles = append(roles, RoleInfo{
			ID:          role.Id,
			Name:        role.Name,
			Description: role.Description,
			Permissions: role.PermissionIds, // Use permission_ids
			TenantID:    role.TenantId,
			CreatedAt:   time.Unix(role.CreatedAt, 0),
			UpdatedAt:   time.Unix(role.UpdatedAt, 0),
		})
	}

	s.writeSuccessResponse(w, roles)
}

// handleCreateRole handles POST /api/v1/rbac/roles
func (s *Server) handleCreateRole(w http.ResponseWriter, r *http.Request) {
	if s.rbacService == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable, "RBAC service not available", "SERVICE_UNAVAILABLE")
		return
	}

	// Parse request body
	var roleInfo RoleInfo
	if err := json.NewDecoder(r.Body).Decode(&roleInfo); err != nil {
		s.writeErrorResponse(w, http.StatusBadRequest, "Invalid JSON body", "INVALID_JSON")
		return
	}

	// Validate required fields
	if roleInfo.Name == "" {
		s.writeErrorResponse(w, http.StatusBadRequest, "Role name is required", "MISSING_NAME")
		return
	}

	// Validate that the request body's TenantId is within the caller's subtree.
	// 400 (not 404): there is no existing resource whose existence to conceal.
	callerTenant, _ := r.Context().Value(ctxkeys.TenantID).(string)
	if callerTenant != "" && !isWithinTenantScope(callerTenant, roleInfo.TenantID) {
		s.logger.Info("Cross-tenant role create refused",
			"requested_tenant", logging.SanitizeLogValue(roleInfo.TenantID),
			"caller_tenant", logging.SanitizeLogValue(callerTenant))
		s.writeErrorResponse(w, http.StatusBadRequest, "TenantId is outside caller's scope", "TENANT_SCOPE_VIOLATION")
		return
	}

	// Role IDs are a global primary key with no tenant binding, so a client-chosen ID
	// leaks and reserves state across tenant boundaries: a duplicate-ID rejection tells
	// the caller that ID exists in *some* tenant (an existence oracle that defeats the
	// 404-instead-of-403 concealment on the read/update/delete paths), and a caller can
	// squat IDs inside another tenant's naming space to permanently deny them. The REST
	// contract assigns IDs server-side, so any client-supplied "id" is ignored.
	roleID := uuid.New().String()

	// Create gRPC request
	req := &controller.CreateRoleRequest{
		Role: &common.Role{
			Id:            roleID,
			Name:          roleInfo.Name,
			Description:   roleInfo.Description,
			PermissionIds: roleInfo.Permissions, // Use permission_ids
			TenantId:      roleInfo.TenantID,
		},
	}

	// M-AUTH-2: Inject justification from X-Justification HTTP header when present.
	ctx := r.Context()
	if justification := r.Header.Get("X-Justification"); justification != "" {
		ctx = rbac.WithSensitiveOperationJustification(ctx, justification)
	}

	// Call gRPC service
	resp, err := s.rbacService.CreateRole(ctx, req)
	if err != nil {
		s.logger.Error("Failed to create role", "name", logging.SanitizeLogValue(roleInfo.Name), "error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to create role", "INTERNAL_ERROR")
		return
	}

	// Convert to API response
	createdRole := RoleInfo{
		ID:          resp.Role.Id,
		Name:        resp.Role.Name,
		Description: resp.Role.Description,
		Permissions: resp.Role.PermissionIds, // Use permission_ids
		TenantID:    resp.Role.TenantId,
		CreatedAt:   time.Unix(resp.Role.CreatedAt, 0),
		UpdatedAt:   time.Unix(resp.Role.UpdatedAt, 0),
	}

	s.writeResponse(w, http.StatusCreated, createdRole)
}

// handleGetRole handles GET /api/v1/rbac/roles/{id}
func (s *Server) handleGetRole(w http.ResponseWriter, r *http.Request) {
	if s.rbacService == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable, "RBAC service not available", "SERVICE_UNAVAILABLE")
		return
	}

	vars := mux.Vars(r)
	roleID := vars["id"]

	if roleID == "" {
		s.writeErrorResponse(w, http.StatusBadRequest, "Role ID is required", "MISSING_ROLE_ID")
		return
	}

	// Create gRPC request
	req := &controller.GetRoleRequest{
		RoleId: roleID,
	}

	// Call gRPC service
	resp, err := s.rbacService.GetRole(r.Context(), req)
	if err != nil {
		s.logger.Error("Failed to get role", "role_id", logging.SanitizeLogValue(roleID), "error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusNotFound, "Role not found", "ROLE_NOT_FOUND")
		return
	}

	// Cross-tenant scope check: empty callerTenant means admin mTLS (no restriction).
	// 404 instead of 403 to avoid disclosing role existence across tenant boundaries.
	callerTenant, _ := r.Context().Value(ctxkeys.TenantID).(string)
	if callerTenant != "" && !isWithinTenantScope(callerTenant, resp.Role.TenantId) {
		s.logger.Info("Cross-tenant role get refused",
			"role_tenant", logging.SanitizeLogValue(resp.Role.TenantId),
			"caller_tenant", logging.SanitizeLogValue(callerTenant))
		s.writeErrorResponse(w, http.StatusNotFound, "Role not found", "ROLE_NOT_FOUND")
		return
	}

	// Convert to API response
	role := RoleInfo{
		ID:          resp.Role.Id,
		Name:        resp.Role.Name,
		Description: resp.Role.Description,
		Permissions: resp.Role.PermissionIds, // Use permission_ids
		TenantID:    resp.Role.TenantId,
		CreatedAt:   time.Unix(resp.Role.CreatedAt, 0),
		UpdatedAt:   time.Unix(resp.Role.UpdatedAt, 0),
	}

	s.writeSuccessResponse(w, role)
}

// handleUpdateRole handles PUT /api/v1/rbac/roles/{id}
func (s *Server) handleUpdateRole(w http.ResponseWriter, r *http.Request) {
	if s.rbacService == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable, "RBAC service not available", "SERVICE_UNAVAILABLE")
		return
	}

	vars := mux.Vars(r)
	roleID := vars["id"]

	if roleID == "" {
		s.writeErrorResponse(w, http.StatusBadRequest, "Role ID is required", "MISSING_ROLE_ID")
		return
	}

	// Parse request body
	var roleInfo RoleInfo
	if err := json.NewDecoder(r.Body).Decode(&roleInfo); err != nil {
		s.writeErrorResponse(w, http.StatusBadRequest, "Invalid JSON body", "INVALID_JSON")
		return
	}

	// Set the ID from URL
	roleInfo.ID = roleID

	// Fetch the existing role to get its actual stored tenant for the scope check.
	// The check MUST use the stored tenant, not the request body's TenantId, to prevent
	// a caller from bypassing the check by lying about the tenant in the update payload.
	existing, err := s.rbacService.GetRole(r.Context(), &controller.GetRoleRequest{RoleId: roleID})
	if err != nil {
		s.logger.Error("Failed to get role", "role_id", logging.SanitizeLogValue(roleID), "error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusNotFound, "Role not found", "ROLE_NOT_FOUND")
		return
	}

	// Cross-tenant scope check: empty callerTenant means admin mTLS (no restriction).
	// 404 instead of 403 to avoid disclosing role existence across tenant boundaries.
	callerTenant, _ := r.Context().Value(ctxkeys.TenantID).(string)
	if callerTenant != "" && !isWithinTenantScope(callerTenant, existing.Role.TenantId) {
		s.logger.Info("Cross-tenant role update refused",
			"role_tenant", logging.SanitizeLogValue(existing.Role.TenantId),
			"caller_tenant", logging.SanitizeLogValue(callerTenant))
		s.writeErrorResponse(w, http.StatusNotFound, "Role not found", "ROLE_NOT_FOUND")
		return
	}

	// A role's tenant is immutable through update. Every layer below this handler
	// (manager, memory store, SQLite upsert) overwrites the stored tenant with the
	// request value, so honouring the body's TenantId would relocate the role — with
	// caller-chosen permission IDs — into another tenant's namespace, and an omitted
	// TenantId would blank it out of every ListRoles result. Reject an explicit
	// relocation attempt; otherwise carry the stored tenant forward.
	if roleInfo.TenantID != "" && roleInfo.TenantID != existing.Role.TenantId {
		s.logger.Info("Role tenant relocation refused",
			"role_tenant", logging.SanitizeLogValue(existing.Role.TenantId),
			"requested_tenant", logging.SanitizeLogValue(roleInfo.TenantID))
		s.writeErrorResponse(w, http.StatusBadRequest, "TenantId cannot be changed", "TENANT_IMMUTABLE")
		return
	}

	// Create gRPC request
	req := &controller.UpdateRoleRequest{
		Role: &common.Role{
			Id:            roleID,
			Name:          roleInfo.Name,
			Description:   roleInfo.Description,
			PermissionIds: roleInfo.Permissions, // Use permission_ids
			TenantId:      existing.Role.TenantId,
		},
	}

	// M-AUTH-2: Inject justification from X-Justification HTTP header when present.
	ctx := r.Context()
	if justification := r.Header.Get("X-Justification"); justification != "" {
		ctx = rbac.WithSensitiveOperationJustification(ctx, justification)
	}

	// Call gRPC service
	resp, err := s.rbacService.UpdateRole(ctx, req)
	if err != nil {
		s.logger.Error("Failed to update role", "role_id", logging.SanitizeLogValue(roleID), "error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to update role", "INTERNAL_ERROR")
		return
	}

	// Convert to API response
	updatedRole := RoleInfo{
		ID:          resp.Role.Id,
		Name:        resp.Role.Name,
		Description: resp.Role.Description,
		Permissions: resp.Role.PermissionIds, // Use permission_ids
		TenantID:    resp.Role.TenantId,
		CreatedAt:   time.Unix(resp.Role.CreatedAt, 0),
		UpdatedAt:   time.Unix(resp.Role.UpdatedAt, 0),
	}

	s.writeSuccessResponse(w, updatedRole)
}

// handleDeleteRole handles DELETE /api/v1/rbac/roles/{id}
func (s *Server) handleDeleteRole(w http.ResponseWriter, r *http.Request) {
	if s.rbacService == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable, "RBAC service not available", "SERVICE_UNAVAILABLE")
		return
	}

	vars := mux.Vars(r)
	roleID := vars["id"]

	if roleID == "" {
		s.writeErrorResponse(w, http.StatusBadRequest, "Role ID is required", "MISSING_ROLE_ID")
		return
	}

	// Fetch the role to obtain its tenant for the scope check. This fetch is always
	// required regardless of whether an audit manager is present (authorization must
	// not depend on an audit-log side effect being active).
	existing, err := s.rbacService.GetRole(r.Context(), &controller.GetRoleRequest{RoleId: roleID})
	if err != nil {
		s.logger.Error("Failed to get role for deletion", "role_id", logging.SanitizeLogValue(roleID), "error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusNotFound, "Role not found", "ROLE_NOT_FOUND")
		return
	}

	// Cross-tenant scope check: empty callerTenant means admin mTLS (no restriction).
	// 404 instead of 403 to avoid disclosing role existence across tenant boundaries.
	callerTenant, _ := r.Context().Value(ctxkeys.TenantID).(string)
	if callerTenant != "" && !isWithinTenantScope(callerTenant, existing.Role.TenantId) {
		s.logger.Info("Cross-tenant role delete refused",
			"role_tenant", logging.SanitizeLogValue(existing.Role.TenantId),
			"caller_tenant", logging.SanitizeLogValue(callerTenant))
		s.writeErrorResponse(w, http.StatusNotFound, "Role not found", "ROLE_NOT_FOUND")
		return
	}

	// Create gRPC request
	req := &controller.DeleteRoleRequest{
		RoleId: roleID,
	}

	// M-AUTH-2: Inject justification from X-Justification HTTP header when present.
	ctx := r.Context()
	if justification := r.Header.Get("X-Justification"); justification != "" {
		ctx = rbac.WithSensitiveOperationJustification(ctx, justification)
	}

	// Call gRPC service. RBACService.DeleteRole signals failure exclusively through
	// its error return; DeleteRoleResponse.Success is set to true on every non-error
	// path (features/controller/service/rbac_service.go). A `!resp.Success` branch
	// here would therefore be unreachable, so the error return is the only outcome
	// this handler distinguishes.
	if _, err := s.rbacService.DeleteRole(ctx, req); err != nil {
		s.logger.Error("Failed to delete role", "role_id", logging.SanitizeLogValue(roleID), "error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to delete role", "INTERNAL_ERROR")
		return
	}

	s.writeSuccessResponse(w, map[string]interface{}{
		"id":      roleID,
		"deleted": true,
	})
}
