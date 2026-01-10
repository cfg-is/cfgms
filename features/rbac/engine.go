// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package rbac

import (
	"context"
	"fmt"
	"strings"

	"github.com/cfgis/cfgms/api/proto/common"
)

// AuthEngine implements the AuthorizationEngine interface
type AuthEngine struct {
	permissionStore PermissionStore
	roleStore       RoleStore
	subjectStore    SubjectStore
	assignmentStore RoleAssignmentStore
}

// NewAuthEngine creates a new authorization engine
func NewAuthEngine(
	permissionStore PermissionStore,
	roleStore RoleStore,
	subjectStore SubjectStore,
	assignmentStore RoleAssignmentStore,
) *AuthEngine {
	return &AuthEngine{
		permissionStore: permissionStore,
		roleStore:       roleStore,
		subjectStore:    subjectStore,
		assignmentStore: assignmentStore,
	}
}

// CheckPermission checks if a subject has a specific permission
func (e *AuthEngine) CheckPermission(ctx context.Context, request *common.AccessRequest) (*common.AccessResponse, error) {
	// Get subject
	subject, err := e.subjectStore.GetSubject(ctx, request.SubjectId)
	if err != nil {
		return &common.AccessResponse{
			Granted: false,
			Reason:  fmt.Sprintf("Subject not found: %v", err),
		}, nil
	}

	// Check if subject is active
	if !subject.IsActive {
		return &common.AccessResponse{
			Granted: false,
			Reason:  "Subject is inactive",
		}, nil
	}

	// Get subject's roles in the tenant context
	roles, err := e.subjectStore.GetSubjectRoles(ctx, request.SubjectId, request.TenantId)
	if err != nil {
		return &common.AccessResponse{
			Granted: false,
			Reason:  fmt.Sprintf("Failed to get subject roles: %v", err),
		}, nil
	}

	var appliedRoles []string
	var appliedPermissions []string

	// Check each role for the required permission
	for _, role := range roles {
		appliedRoles = append(appliedRoles, role.Name)

		// Get role permissions
		permissions, err := e.roleStore.GetRolePermissions(ctx, role.Id)
		if err != nil {
			continue // Skip this role on error
		}

		// Check if any permission matches the request
		for _, perm := range permissions {
			if e.permissionMatches(perm, request.PermissionId) {
				appliedPermissions = append(appliedPermissions, perm.Name)
				return &common.AccessResponse{
					Granted:            true,
					Reason:             fmt.Sprintf("Access granted via role '%s' with permission '%s'", role.Name, perm.Name),
					AppliedRoles:       appliedRoles,
					AppliedPermissions: appliedPermissions,
				}, nil
			}
		}
	}

	return &common.AccessResponse{
		Granted: false,
		Reason:  fmt.Sprintf("No role grants permission '%s' for tenant '%s'", request.PermissionId, request.TenantId),
	}, nil
}

// GetSubjectPermissions retrieves all permissions for a subject in a tenant context
func (e *AuthEngine) GetSubjectPermissions(ctx context.Context, subjectID, tenantID string) ([]*common.Permission, error) {
	// Get subject's roles
	roles, err := e.subjectStore.GetSubjectRoles(ctx, subjectID, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to get subject roles: %w", err)
	}

	// Collect all permissions from all roles (deduplicating)
	permissionMap := make(map[string]*common.Permission)

	for _, role := range roles {
		permissions, err := e.roleStore.GetRolePermissions(ctx, role.Id)
		if err != nil {
			continue // Skip this role on error
		}

		for _, perm := range permissions {
			permissionMap[perm.Id] = perm
		}
	}

	// Convert map to slice
	var permissions []*common.Permission
	for _, perm := range permissionMap {
		permissions = append(permissions, perm)
	}

	return permissions, nil
}

// ValidateAccess performs comprehensive access validation with context
func (e *AuthEngine) ValidateAccess(ctx context.Context, authContext *common.AuthorizationContext, requiredPermission string) (*common.AccessResponse, error) {
	request := &common.AccessRequest{
		SubjectId:    authContext.SubjectId,
		PermissionId: requiredPermission,
		TenantId:     authContext.TenantId,
		Context:      authContext.Environment,
	}

	// Add resource attributes to context if available
	if authContext.ResourceAttributes != nil {
		if request.Context == nil {
			request.Context = make(map[string]string)
		}
		for k, v := range authContext.ResourceAttributes {
			request.Context["resource."+k] = v
		}
	}

	return e.CheckPermission(ctx, request)
}

// permissionMatches checks if a permission matches the requested permission ID
// Supports exact matches and wildcard patterns
func (e *AuthEngine) permissionMatches(permission *common.Permission, requestedPermission string) bool {
	// Exact match
	if permission.Id == requestedPermission {
		return true
	}

	// Wildcard pattern matching (simple implementation)
	// For example: "steward.*" matches "steward.register", "steward.heartbeat", etc.
	if strings.HasSuffix(permission.Id, ".*") {
		prefix := strings.TrimSuffix(permission.Id, ".*")
		return strings.HasPrefix(requestedPermission, prefix+".")
	}

	// System admin has access to everything
	if permission.Id == "system.admin" {
		return true
	}

	return false
}

// GetEffectivePermissions gets all effective permissions for a subject considering role hierarchy
func (e *AuthEngine) GetEffectivePermissions(ctx context.Context, subjectID, tenantID string) ([]*common.Permission, error) {
	return e.GetSubjectPermissions(ctx, subjectID, tenantID)
}

// Verify that AuthEngine implements the AuthorizationEngine interface
var _ AuthorizationEngine = (*AuthEngine)(nil)
