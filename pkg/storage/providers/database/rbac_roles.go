// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package database

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	"github.com/cfgis/cfgms/api/proto/common"
)

// Role management

// StoreRole implements RBACStore.StoreRole
func (s *DatabaseRBACStore) StoreRole(ctx context.Context, role *common.Role) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	// H-TENANT-1: Validate tenant access before storing role (security audit finding)
	if err := s.validateTenantAccess(ctx, role.TenantId, role.IsSystemRole); err != nil {
		return err
	}

	// Begin transaction
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// Serialize permission IDs array to JSON
	permissionIDsJSON, err := json.Marshal(role.PermissionIds)
	if err != nil {
		return fmt.Errorf("failed to serialize permission IDs: %w", err)
	}

	query := `
		INSERT INTO rbac_roles (id, name, description, permission_ids, is_system_role, tenant_id, parent_role_id, inheritance_type)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		ON CONFLICT (id) DO UPDATE SET
			name = EXCLUDED.name,
			description = EXCLUDED.description,
			permission_ids = EXCLUDED.permission_ids,
			is_system_role = EXCLUDED.is_system_role,
			tenant_id = EXCLUDED.tenant_id,
			parent_role_id = EXCLUDED.parent_role_id,
			inheritance_type = EXCLUDED.inheritance_type,
			updated_at = NOW()
	`

	_, err = tx.ExecContext(ctx, query,
		role.Id,
		role.Name,
		role.Description,
		permissionIDsJSON,
		role.IsSystemRole,
		role.TenantId,
		role.ParentRoleId,
		int32(role.InheritanceType),
	)

	if err != nil {
		return fmt.Errorf("failed to store role: %w", err)
	}

	// Commit transaction
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

// GetRole implements RBACStore.GetRole
func (s *DatabaseRBACStore) GetRole(ctx context.Context, id string) (*common.Role, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	query := `
		SELECT id, name, description, permission_ids, is_system_role, tenant_id, parent_role_id, inheritance_type
		FROM rbac_roles
		WHERE id = $1
	`

	row := s.db.QueryRowContext(ctx, query, id)

	role := &common.Role{}
	var permissionIDsJSON []byte
	var parentRoleID sql.NullString
	var inheritanceType sql.NullInt32

	err := row.Scan(
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
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("role not found: %s", id)
		}
		return nil, fmt.Errorf("failed to get role: %w", err)
	}

	// H-TENANT-1: Validate tenant access before returning role (security audit finding)
	if err := s.validateTenantAccess(ctx, role.TenantId, role.IsSystemRole); err != nil {
		return nil, err
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

	return role, nil
}

// ListRoles implements RBACStore.ListRoles
func (s *DatabaseRBACStore) ListRoles(ctx context.Context, tenantID string) ([]*common.Role, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	var query string
	var args []interface{}

	if tenantID == "" {
		query = `
			SELECT id, name, description, permission_ids, is_system_role, tenant_id, parent_role_id, inheritance_type
			FROM rbac_roles
			ORDER BY is_system_role DESC, tenant_id, name
		`
	} else {
		query = `
			SELECT id, name, description, permission_ids, is_system_role, tenant_id, parent_role_id, inheritance_type
			FROM rbac_roles
			WHERE tenant_id = $1 OR is_system_role = true
			ORDER BY is_system_role DESC, name
		`
		args = []interface{}{tenantID}
	}

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to list roles: %w", err)
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
		return nil, fmt.Errorf("error iterating roles: %w", err)
	}

	return roles, nil
}

// UpdateRole implements RBACStore.UpdateRole
func (s *DatabaseRBACStore) UpdateRole(ctx context.Context, role *common.Role) error {
	// Same implementation as StoreRole due to ON CONFLICT DO UPDATE
	return s.StoreRole(ctx, role)
}

// DeleteRole implements RBACStore.DeleteRole
func (s *DatabaseRBACStore) DeleteRole(ctx context.Context, id string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	// H-TENANT-1: Fetch role first to validate tenant access (security audit finding)
	_, err := s.GetRole(ctx, id)
	if err != nil {
		return err
	}

	// Tenant validation already performed in GetRole
	// Proceed with deletion

	// Begin transaction
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	query := `DELETE FROM rbac_roles WHERE id = $1`

	result, err := tx.ExecContext(ctx, query, id)
	if err != nil {
		return fmt.Errorf("failed to delete role: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("role not found: %s", id)
	}

	// Commit transaction
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

