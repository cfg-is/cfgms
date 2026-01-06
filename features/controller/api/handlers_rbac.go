// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 CFGMS Contributors
package api

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/gorilla/mux"

	"github.com/cfgis/cfgms/api/proto/common"
	controller "github.com/cfgis/cfgms/api/proto/controller"
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
	resp, err := s.rbacService.ListPermissions(context.Background(), req)
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
	resp, err := s.rbacService.GetPermission(context.Background(), req)
	if err != nil {
		s.logger.Error("Failed to get permission", "permission_id", permissionID, "error", err)
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

	// Get tenant_id filter from query params
	tenantID := r.URL.Query().Get("tenant_id")

	// Create gRPC request
	req := &controller.ListRolesRequest{
		TenantId: tenantID,
	}

	// Call gRPC service
	resp, err := s.rbacService.ListRoles(context.Background(), req)
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

	// Create gRPC request
	req := &controller.CreateRoleRequest{
		Role: &common.Role{
			Name:          roleInfo.Name,
			Description:   roleInfo.Description,
			PermissionIds: roleInfo.Permissions, // Use permission_ids
			TenantId:      roleInfo.TenantID,
		},
	}

	// Call gRPC service
	resp, err := s.rbacService.CreateRole(context.Background(), req)
	if err != nil {
		s.logger.Error("Failed to create role", "name", roleInfo.Name, "error", err)
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
	resp, err := s.rbacService.GetRole(context.Background(), req)
	if err != nil {
		s.logger.Error("Failed to get role", "role_id", roleID, "error", err)
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

	// Create gRPC request
	req := &controller.UpdateRoleRequest{
		Role: &common.Role{
			Id:            roleID,
			Name:          roleInfo.Name,
			Description:   roleInfo.Description,
			PermissionIds: roleInfo.Permissions, // Use permission_ids
			TenantId:      roleInfo.TenantID,
		},
	}

	// Call gRPC service
	resp, err := s.rbacService.UpdateRole(context.Background(), req)
	if err != nil {
		s.logger.Error("Failed to update role", "role_id", roleID, "error", err)
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

	// Create gRPC request
	req := &controller.DeleteRoleRequest{
		RoleId: roleID,
	}

	// Call gRPC service
	resp, err := s.rbacService.DeleteRole(context.Background(), req)
	if err != nil {
		s.logger.Error("Failed to delete role", "role_id", roleID, "error", err)
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to delete role", "INTERNAL_ERROR")
		return
	}

	if !resp.Success {
		s.writeErrorResponse(w, http.StatusBadRequest, "Failed to delete role", "DELETE_FAILED")
		return
	}

	s.writeSuccessResponse(w, map[string]interface{}{
		"id":      roleID,
		"deleted": true,
	})
}

// Placeholder handlers for other RBAC endpoints
// TODO: Implement these when needed

func (s *Server) handleListSubjects(w http.ResponseWriter, r *http.Request) {
	s.writeErrorResponse(w, http.StatusNotImplemented, "Subjects management not yet implemented", "NOT_IMPLEMENTED")
}

func (s *Server) handleCreateSubject(w http.ResponseWriter, r *http.Request) {
	s.writeErrorResponse(w, http.StatusNotImplemented, "Subjects management not yet implemented", "NOT_IMPLEMENTED")
}

func (s *Server) handleGetSubject(w http.ResponseWriter, r *http.Request) {
	s.writeErrorResponse(w, http.StatusNotImplemented, "Subjects management not yet implemented", "NOT_IMPLEMENTED")
}

func (s *Server) handleUpdateSubject(w http.ResponseWriter, r *http.Request) {
	s.writeErrorResponse(w, http.StatusNotImplemented, "Subjects management not yet implemented", "NOT_IMPLEMENTED")
}

func (s *Server) handleDeleteSubject(w http.ResponseWriter, r *http.Request) {
	s.writeErrorResponse(w, http.StatusNotImplemented, "Subjects management not yet implemented", "NOT_IMPLEMENTED")
}

func (s *Server) handleGetSubjectRoles(w http.ResponseWriter, r *http.Request) {
	s.writeErrorResponse(w, http.StatusNotImplemented, "Role assignments not yet implemented", "NOT_IMPLEMENTED")
}

func (s *Server) handleAssignRole(w http.ResponseWriter, r *http.Request) {
	s.writeErrorResponse(w, http.StatusNotImplemented, "Role assignments not yet implemented", "NOT_IMPLEMENTED")
}

func (s *Server) handleRevokeRole(w http.ResponseWriter, r *http.Request) {
	s.writeErrorResponse(w, http.StatusNotImplemented, "Role assignments not yet implemented", "NOT_IMPLEMENTED")
}

func (s *Server) handleGetSubjectPermissions(w http.ResponseWriter, r *http.Request) {
	s.writeErrorResponse(w, http.StatusNotImplemented, "Permission queries not yet implemented", "NOT_IMPLEMENTED")
}

func (s *Server) handleCheckPermission(w http.ResponseWriter, r *http.Request) {
	s.writeErrorResponse(w, http.StatusNotImplemented, "Permission checking not yet implemented", "NOT_IMPLEMENTED")
}
