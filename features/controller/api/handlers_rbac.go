// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"

	"github.com/cfgis/cfgms/api/proto/common"
	controller "github.com/cfgis/cfgms/api/proto/controller"
	"github.com/cfgis/cfgms/features/rbac"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
	"github.com/cfgis/cfgms/pkg/logging"
)

// isWithinTenantScope is defined in middleware.go and shared across RBAC and
// tenant handlers.

// Role field bounds enforced at the API boundary. Role names and descriptions are
// operator-supplied free text that is rendered in the web UI and written to audit
// events, so both are length-bounded and rejected when they carry control
// characters (log/audit-record injection).
const (
	maxRoleNameLength        = 128
	maxRoleDescriptionLength = 512
)

// Role validation errors. Each message is caller-facing and discloses nothing
// about controller internals.
var (
	errRoleNameRequired       = errors.New("role name is required")
	errRoleNameTooLong        = fmt.Errorf("role name must be at most %d characters", maxRoleNameLength)
	errRoleDescriptionTooLong = fmt.Errorf("role description must be at most %d characters", maxRoleDescriptionLength)
	errRoleControlCharacters  = errors.New("role name and description must not contain control characters")
)

// validateRoleFields validates operator-supplied role fields and returns the
// trimmed name and description. The error message is safe to return to the caller.
func validateRoleFields(name, description string) (string, string, error) {
	trimmedName := strings.TrimSpace(name)
	trimmedDescription := strings.TrimSpace(description)
	if trimmedName == "" {
		return "", "", errRoleNameRequired
	}
	if len(trimmedName) > maxRoleNameLength {
		return "", "", errRoleNameTooLong
	}
	if len(trimmedDescription) > maxRoleDescriptionLength {
		return "", "", errRoleDescriptionTooLong
	}
	if strings.ContainsFunc(trimmedName, isControlRune) || strings.ContainsFunc(trimmedDescription, isControlRune) {
		return "", "", errRoleControlCharacters
	}
	return trimmedName, trimmedDescription, nil
}

// isControlRune reports whether r is a C0/C1 control character.
func isControlRune(r rune) bool {
	return r < 0x20 || (r >= 0x7F && r <= 0x9F)
}

// roleReadableByTenant reports whether callerTenant may read role. The rule matches
// the visibility ListRoles applies (own-subtree roles plus system roles), extended
// with subtree scope and the unscoped ("") admin mTLS path, so a role can never be
// fetched by ID that the same caller cannot see in the list.
func roleReadableByTenant(role *common.Role, callerTenant string) bool {
	return role != nil && (role.IsSystemRole || callerTenant == "" || isWithinTenantScope(callerTenant, role.TenantId))
}

// loadRoleForWrite loads roleID and confirms callerTenant may act on it, writing the
// HTTP error response and returning false when it does not.
//
// A role outside callerTenant's subtree is reported as 404: confirming its existence
// to a caller outside that subtree is itself a disclosure. System roles are 403 —
// they are visible to every tenant but owned by none, so no tenant operator may
// edit or delete them (the store rejects system-role deletion as well).
func (s *Server) loadRoleForWrite(w http.ResponseWriter, r *http.Request, roleID, callerTenant, action string) (*common.Role, bool) {
	resp, err := s.rbacService.GetRole(r.Context(), &controller.GetRoleRequest{RoleId: roleID})
	if err != nil || resp.Role == nil {
		errText := ""
		if err != nil {
			errText = err.Error()
		}
		s.logger.Error("Failed to get role", "role_id", logging.SanitizeLogValue(roleID),
			"action", action, "error", logging.SanitizeLogValue(errText))
		s.writeErrorResponse(w, http.StatusNotFound, "Role not found", "ROLE_NOT_FOUND")
		return nil, false
	}

	if resp.Role.IsSystemRole {
		s.writeErrorResponse(w, http.StatusForbidden, "System roles cannot be "+action, "SYSTEM_ROLE_IMMUTABLE")
		return nil, false
	}

	if callerTenant != "" && !isWithinTenantScope(callerTenant, resp.Role.TenantId) {
		s.logger.Warn("Blocked cross-tenant role write",
			"role_id", logging.SanitizeLogValue(roleID),
			"caller_tenant", logging.SanitizeLogValue(callerTenant),
			"action", action)
		s.writeErrorResponse(w, http.StatusNotFound, "Role not found", "ROLE_NOT_FOUND")
		return nil, false
	}

	return resp.Role, true
}

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

	// Validate operator-supplied fields
	name, description, err := validateRoleFields(roleInfo.Name, roleInfo.Description)
	if err != nil {
		s.writeErrorResponse(w, http.StatusBadRequest, err.Error(), "INVALID_ROLE")
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
			Name:          name,
			Description:   description,
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

	// Tenant scoping: a role outside the caller's subtree must not be readable by ID
	// unless it is a system role (visible to every tenant, matching ListRoles).
	// Reported as 404 so the response does not confirm that the role exists.
	callerTenant, _ := r.Context().Value(ctxkeys.TenantID).(string)
	if !roleReadableByTenant(resp.Role, callerTenant) {
		s.logger.Warn("Blocked cross-tenant role read",
			"role_id", logging.SanitizeLogValue(roleID),
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

	name, description, err := validateRoleFields(roleInfo.Name, roleInfo.Description)
	if err != nil {
		s.writeErrorResponse(w, http.StatusBadRequest, err.Error(), "INVALID_ROLE")
		return
	}

	// Tenant scoping: the role must exist inside the caller's subtree (or the caller
	// is an unscoped admin) and must not be a system role before any field is written.
	callerTenant, _ := r.Context().Value(ctxkeys.TenantID).(string)
	existing, ok := s.loadRoleForWrite(w, r, roleID, callerTenant, "modified")
	if !ok {
		return
	}

	// A role's tenant is immutable through update. Every layer below this handler
	// (manager, memory store, SQLite upsert) overwrites the stored tenant with the
	// request value, so honouring the body's TenantId would relocate the role — with
	// caller-chosen permission IDs — into another tenant's namespace, and an omitted
	// TenantId would blank it out of every ListRoles result. Reject an explicit
	// relocation attempt; otherwise carry the stored tenant forward.
	if roleInfo.TenantID != "" && roleInfo.TenantID != existing.TenantId {
		s.logger.Info("Role tenant relocation refused",
			"role_tenant", logging.SanitizeLogValue(existing.TenantId),
			"requested_tenant", logging.SanitizeLogValue(roleInfo.TenantID))
		s.writeErrorResponse(w, http.StatusBadRequest, "TenantId cannot be changed", "TENANT_IMMUTABLE")
		return
	}

	// UpdateRole is a whole-record replacement, so every field the API does not
	// expose is carried over from the stored role: tenant scope, system-role status,
	// hierarchy links and creation time would otherwise be silently cleared.
	req := &controller.UpdateRoleRequest{
		Role: &common.Role{
			Id:              roleID,
			Name:            name,
			Description:     description,
			PermissionIds:   roleInfo.Permissions, // Use permission_ids
			TenantId:        existing.TenantId,
			IsSystemRole:    existing.IsSystemRole,
			ParentRoleId:    existing.ParentRoleId,
			ChildRoleIds:    existing.ChildRoleIds,
			InheritanceType: existing.InheritanceType,
			CreatedAt:       existing.CreatedAt,
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

	// Tenant scoping: only a role inside the caller's subtree (or an unscoped admin)
	// may be deleted, and system roles may never be deleted.
	callerTenant, _ := r.Context().Value(ctxkeys.TenantID).(string)
	if _, ok := s.loadRoleForWrite(w, r, roleID, callerTenant, "deleted"); !ok {
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
