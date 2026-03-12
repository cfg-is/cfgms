// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package database

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/cfgis/cfgms/api/proto/common"
)

// Query operations

// GetSubjectRoles implements RBACStore.GetSubjectRoles
func (s *DatabaseRBACStore) GetSubjectRoles(ctx context.Context, subjectID, tenantID string) ([]*common.Role, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	query := `
		SELECT r.id, r.name, r.description, r.permission_ids, r.is_system_role, r.tenant_id, r.parent_role_id, r.inheritance_type
		FROM rbac_roles r
		INNER JOIN rbac_role_assignments ra ON r.id = ra.role_id
		WHERE ra.subject_id = $1 AND ra.tenant_id = $2
		  AND (ra.expires_at IS NULL OR ra.expires_at > NOW())
		ORDER BY r.is_system_role DESC, r.name
	`

	rows, err := s.db.QueryContext(ctx, query, subjectID, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to get subject roles: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var roles []*common.Role

	for rows.Next() {
		role := &common.Role{}
		var permissionIDsJSON []byte
		var parentRoleID sql.NullString
		var inheritanceType sql.NullInt32

		err := rows.Scan(
			&role.Id,
			&role.Name,
			&role.Description,
			&permissionIDsJSON,
			&role.IsSystemRole,
			&role.TenantId,
			&parentRoleID,
			&inheritanceType,
		)

		if err != nil {
			return nil, fmt.Errorf("failed to scan role: %w", err)
		}

		// Deserialize permission IDs from JSON
		if err := json.Unmarshal(permissionIDsJSON, &role.PermissionIds); err != nil {
			return nil, fmt.Errorf("failed to deserialize permission IDs: %w", err)
		}

		// Handle nullable fields
		if parentRoleID.Valid {
			role.ParentRoleId = parentRoleID.String
		}
		if inheritanceType.Valid {
			role.InheritanceType = common.RoleInheritanceType(inheritanceType.Int32)
		}

		roles = append(roles, role)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating subject roles: %w", err)
	}

	return roles, nil
}

// GetRolePermissions implements RBACStore.GetRolePermissions
func (s *DatabaseRBACStore) GetRolePermissions(ctx context.Context, roleID string) ([]*common.Permission, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	// First get the role to find its permission IDs
	role, err := s.GetRole(ctx, roleID)
	if err != nil {
		return nil, fmt.Errorf("failed to get role: %w", err)
	}

	if len(role.PermissionIds) == 0 {
		return []*common.Permission{}, nil
	}

	// Build query with IN clause for permission IDs
	placeholders := make([]string, len(role.PermissionIds))
	args := make([]interface{}, len(role.PermissionIds))

	for i, permissionID := range role.PermissionIds {
		placeholders[i] = fmt.Sprintf("$%d", i+1)
		args[i] = permissionID
	}

	// #nosec G201 - Using parameterized query with dynamic IN clause - placeholders are $1, $2, etc.
	query := fmt.Sprintf(`
		SELECT id, name, description, resource_type, actions
		FROM rbac_permissions
		WHERE id IN (%s)
		ORDER BY resource_type, name
	`, strings.Join(placeholders, ","))

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to get role permissions: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var permissions []*common.Permission

	for rows.Next() {
		permission := &common.Permission{}
		var actionsJSON []byte

		err := rows.Scan(
			&permission.Id,
			&permission.Name,
			&permission.Description,
			&permission.ResourceType,
			&actionsJSON,
		)

		if err != nil {
			return nil, fmt.Errorf("failed to scan permission: %w", err)
		}

		// Deserialize actions from JSON
		if err := json.Unmarshal(actionsJSON, &permission.Actions); err != nil {
			return nil, fmt.Errorf("failed to deserialize actions: %w", err)
		}

		permissions = append(permissions, permission)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating role permissions: %w", err)
	}

	return permissions, nil
}

// GetSubjectAssignments implements RBACStore.GetSubjectAssignments
func (s *DatabaseRBACStore) GetSubjectAssignments(ctx context.Context, subjectID, tenantID string) ([]*common.RoleAssignment, error) {
	return s.ListRoleAssignments(ctx, subjectID, "", tenantID)
}
